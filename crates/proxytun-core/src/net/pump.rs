//! The end of every relayed connection: copy its bytes both ways, counting
//! them, then close both sides (a reset after an abort) and log how it ended.
//! Shared by `relay::route` and the binary's host-port forwarding.

use anyhow::Result;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{copy_bidirectional_with_sizes, AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// Bytes relayed so far, all connections together: `up` from the program
/// towards its targets, `down` back.
#[derive(Default)]
pub struct Traffic {
    pub up: AtomicU64,
    pub down: AtomicU64,
}

/// Bytes one connection moved each way.
#[derive(Debug, Default, PartialEq, Eq)]
struct Transfer {
    up: u64,
    down: u64,
}

/// The line every relayed connection ends with: how long it lived, how long
/// reaching its proxy (or the target itself) took, through what, the bytes
/// each way, and how it ended. Enough to tell a slow proxy from a slow
/// transfer, at the default log level.
fn log_closed(start: Instant, dial: Duration, via: &str, moved: &Transfer, r: &Result<()>) {
    let (ms, dial_ms) = (start.elapsed().as_millis() as u64, dial.as_millis() as u64);
    let (up, down) = (moved.up, moved.down);
    match r {
        Ok(()) => tracing::info!(ms, dial_ms, via = %via, up, down, "closed"),
        Err(e) => tracing::info!(ms, dial_ms, via = %via, up, down, "closed: {e:#}"),
    }
}

/// The end of every relayed connection, once its way out (`via`) is dialed
/// or failed to be: copy both ways, then log how it ended. An abort reaches
/// each side as one, a reset: a transfer cut off, or a target that could not
/// be reached, must not look like a complete (or empty) one ending in a FIN.
/// `start` is when the connection came in, `dial` how long dialing took.
pub async fn finish(
    mut inbound: TcpStream,
    out: Result<TcpStream>,
    traffic: &Traffic,
    start: Instant,
    dial: Duration,
    via: &str,
) -> Result<()> {
    let (moved, r) = match out {
        Ok(mut out) => {
            let (moved, r) = pump(&mut inbound, &mut out, traffic).await;
            // The copy broke midway: with a zero linger, closing `out` (it drops at the end
            // of this arm) sends an RST instead of a FIN, so the target sees an abort.
            if r.is_err() {
                let _ = out.set_zero_linger();
            }
            (moved, r)
        }
        Err(e) => (Transfer::default(), Err(e)),
    };
    // Dial failed or the copy broke: the program's side is reset too when `inbound` drops,
    // so it never sees a clean end.
    if r.is_err() {
        let _ = inbound.set_zero_linger();
    }
    log_closed(start, dial, via, &moved, &r);
    r
}

/// Copy both ways until both sides are done, and say how many bytes went
/// each way (`up` = read from `a`), also when it ended in an error. A plain
/// copy, not splice(2): for connections that came in through the TUN device
/// it measured about a third faster (the TUN thread is the bottleneck either
/// way, and splice only adds to it). See docs/DESIGN.md.
async fn pump(a: &mut TcpStream, b: &mut TcpStream, traffic: &Traffic) -> (Transfer, Result<()>) {
    // No Nagle on either leg: a relay must pass small writes on at once.
    a.set_nodelay(true).ok();
    b.set_nodelay(true).ok();
    // Counted in wrappers as bytes pass: the copy's own counts are lost when it fails.
    let mut a = Counted {
        s: a,
        n: 0,
        total: &traffic.up,
    };
    let mut b = Counted {
        s: b,
        n: 0,
        total: &traffic.down,
    };
    // Each direction runs until its reader hits EOF, then shuts down the other side's
    // writing half (a FIN); the first error ends both directions.
    // 64 KiB buffers: the 8 KiB default costs throughput on fast links.
    let r = copy_bidirectional_with_sizes(&mut a, &mut b, 64 * 1024, 64 * 1024).await;
    (Transfer { up: a.n, down: b.n }, r.map(|_| ()).map_err(Into::into))
}

/// One side of a relayed connection, counting the bytes read from it (in `n`,
/// and in the shared `total` as they pass, so long transfers show up in the
/// stats before they end).
struct Counted<'a> {
    s: &'a mut TcpStream,
    n: u64,
    total: &'a AtomicU64,
}

impl AsyncRead for Counted<'_> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        // Count only what this read appended to `buf`.
        let before = buf.filled().len();
        let r = Pin::new(&mut *self.s).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = r {
            let k = (buf.filled().len() - before) as u64;
            self.n += k;
            self.total.fetch_add(k, Ordering::Relaxed);
        }
        r
    }
}

// Writes pass straight through: every byte was already counted when read from its source.
impl AsyncWrite for Counted<'_> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.s).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.s).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.s).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let c = TcpStream::connect(l.local_addr().unwrap()).await.unwrap();
        let (s, _) = l.accept().await.unwrap();
        (c, s)
    }

    type Pumped = tokio::task::JoinHandle<(Transfer, Result<()>, Arc<Traffic>)>;

    /// client <-> [a  pump  b] <-> server
    async fn pumped() -> (TcpStream, TcpStream, Pumped) {
        let (client, mut a) = tcp_pair().await;
        let (mut b, server) = tcp_pair().await;
        let traffic = Arc::new(Traffic::default());
        let h = tokio::spawn(async move {
            let (moved, r) = pump(&mut a, &mut b, &traffic).await;
            (moved, r, traffic)
        });
        (client, server, h)
    }

    #[tokio::test]
    async fn pump_turns_off_nagle_on_both_sides() {
        // Host port forwarding hands pump an outbound socket nobody else
        // configured: small writes (a prompt, a keystroke) must not wait for
        // more data on either leg.
        let (client, mut a) = tcp_pair().await;
        let (mut b, server) = tcp_pair().await;
        drop((client, server));
        let _ = pump(&mut a, &mut b, &Traffic::default()).await;
        assert!(a.nodelay().unwrap(), "inbound");
        assert!(b.nodelay().unwrap(), "outbound");
    }

    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i.wrapping_mul(31) % 251) as u8).collect()
    }

    #[tokio::test]
    async fn pump_moves_a_large_payload_intact_in_both_directions() {
        let (mut client, mut server, h) = pumped().await;
        let up = pattern(16 << 20);
        let down = pattern(9 << 20);
        let (up2, down2) = (up.clone(), down.clone());
        let srv = tokio::spawn(async move {
            let mut got = vec![0u8; up2.len()];
            server.read_exact(&mut got).await.unwrap();
            assert!(got == up2, "client->server bytes differ");
            server.write_all(&down2).await.unwrap();
            server.shutdown().await.unwrap();
        });
        client.write_all(&up).await.unwrap();
        client.shutdown().await.unwrap();
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.unwrap();
        assert!(got == down, "server->client bytes differ");
        srv.await.unwrap();
        let (moved, r, traffic) = h.await.unwrap();
        r.unwrap();
        let (up, down) = (up.len() as u64, down.len() as u64);
        assert_eq!(moved, Transfer { up, down });
        assert_eq!(
            (traffic.up.load(Ordering::Relaxed), traffic.down.load(Ordering::Relaxed)),
            (up, down),
            "the shared totals follow"
        );
    }

    #[tokio::test]
    async fn pump_keeps_the_other_direction_open_after_a_half_close() {
        let (mut client, mut server, h) = pumped().await;
        client.write_all(b"request").await.unwrap();
        client.shutdown().await.unwrap(); // client is done sending
        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap(); // sees EOF after the data
        assert_eq!(got, b"request");
        server.write_all(b"late reply").await.unwrap(); // reverse path still works
        server.shutdown().await.unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"late reply");
        let (moved, r, _) = h.await.unwrap();
        r.unwrap();
        assert_eq!(moved, Transfer { up: 7, down: 10 });
    }

    #[tokio::test]
    async fn a_reset_peer_ends_the_pump_instead_of_hanging() {
        use std::os::fd::AsRawFd;
        let (mut client, mut server, h) = pumped().await;
        // Some bytes get through first: they must still be counted.
        client.write_all(&[7; 1000]).await.unwrap();
        let mut first = [0u8; 1000];
        server.read_exact(&mut first).await.unwrap();
        // Abortive close of the client: RST instead of FIN.
        let abortive = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        unsafe {
            libc::setsockopt(
                client.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                &abortive as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::linger>() as u32,
            );
        }
        drop(client);
        let mut buf = [0u8; 8];
        let _ = server.read(&mut buf).await;
        let r = tokio::time::timeout(Duration::from_secs(5), h).await;
        let (moved, r, _) = r.expect("the pump must end after a reset").unwrap();
        assert!(r.is_err(), "a reset is an error");
        assert_eq!(moved.up, 1000, "bytes moved before the error are counted");
    }
}
