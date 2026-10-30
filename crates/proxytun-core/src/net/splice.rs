//! Zero-copy bidirectional relay using splice(2) through a pipe per direction.
//!
//! Compared with a read()/write() loop this keeps the payload inside the kernel
//! (page references move socket -> pipe -> socket), which is what lets the extra
//! loopback hop cost little when the link is fast. Falls back to the plain
//! copy loop if the kernel refuses splice for these sockets.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use tokio::io::Interest;
use tokio::net::TcpStream;

/// Pipes keep the system default size (64 KiB). Measured: 64 KiB, 256 KiB and
/// 1 MiB pipes give the same throughput, while bigger pipes eat the per-user
/// pipe budget (fs.pipe-user-pages-soft, 64 MiB by default) - at 1 MiB, 32
/// relayed connections exhausted it and the kernel then shrank every new pipe
/// of the user, the program's own included.
const F_GETPIPE_SZ: libc::c_int = 1032;

/// Below this the user is over the pipe budget and the kernel handed out a
/// tiny pipe; a plain copy loop is better then.
const MIN_PIPE: usize = 16 * 1024;

struct Pipe {
    r: OwnedFd,
    w: OwnedFd,
    cap: usize,
}

impl Pipe {
    fn new() -> io::Result<Pipe> {
        let mut fds = [0 as RawFd; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let (r, w) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        let got = unsafe { libc::fcntl(w.as_raw_fd(), F_GETPIPE_SZ) };
        let cap = if got > 0 { got as usize } else { 64 * 1024 };
        if cap < MIN_PIPE {
            return Err(io::ErrorKind::Unsupported.into());
        }
        Ok(Pipe { r, w, cap })
    }
}

fn splice(from: RawFd, to: RawFd, len: usize) -> io::Result<usize> {
    let n = unsafe {
        libc::splice(
            from,
            std::ptr::null_mut(),
            to,
            std::ptr::null_mut(),
            len,
            libc::SPLICE_F_NONBLOCK | libc::SPLICE_F_MOVE,
        )
    };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

/// Move everything from `src` to `dst` until EOF, then half-close `dst`.
async fn one_way(src: &TcpStream, dst: &TcpStream, pipe: &Pipe) -> io::Result<u64> {
    let (sfd, dfd) = (src.as_raw_fd(), dst.as_raw_fd());
    let mut total = 0u64;
    loop {
        src.readable().await?;
        let n = match src.try_io(Interest::READABLE, || splice(sfd, pipe.w.as_raw_fd(), pipe.cap)) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            // Nothing moved yet and the kernel refuses splice here: let the
            // caller fall back to a plain copy loop.
            Err(e) if total == 0 && matches!(e.raw_os_error(), Some(libc::EINVAL) | Some(libc::ENOSYS)) => {
                return Err(io::ErrorKind::Unsupported.into())
            }
            Err(e) => return Err(e),
        };
        let mut left = n;
        while left > 0 {
            dst.writable().await?;
            match dst.try_io(Interest::WRITABLE, || splice(pipe.r.as_raw_fd(), dfd, left)) {
                Ok(m) => left -= m,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
        total += n as u64;
    }
    unsafe { libc::shutdown(dfd, libc::SHUT_WR) };
    Ok(total)
}

/// Relay both directions until both sides are done. Returns (a->b, b->a) bytes.
pub async fn splice_bidirectional(a: &TcpStream, b: &TcpStream) -> io::Result<(u64, u64)> {
    // No pipe (fd limit, pipe budget): let the caller copy in user space instead
    // of failing the connection.
    let unsupported = |_| io::Error::from(io::ErrorKind::Unsupported);
    let (p1, p2) = (Pipe::new().map_err(unsupported)?, Pipe::new().map_err(unsupported)?);
    // try_join: if either direction fails (RST, EPIPE) stop both at once.
    // Waiting for the other direction would hang on a peer that never closes.
    tokio::try_join!(one_way(a, b, &p1), one_way(b, a, &p2))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let c = TcpStream::connect(l.local_addr().unwrap()).await.unwrap();
        let (s, _) = l.accept().await.unwrap();
        (c, s)
    }

    /// client <-> [a  relay  b] <-> server
    async fn relayed() -> (TcpStream, TcpStream, tokio::task::JoinHandle<io::Result<(u64, u64)>>) {
        let (client, a) = pair().await;
        let (b, server) = pair().await;
        let h = tokio::spawn(async move { splice_bidirectional(&a, &b).await });
        (client, server, h)
    }

    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i.wrapping_mul(31) % 251) as u8).collect()
    }

    #[tokio::test]
    async fn moves_a_large_payload_intact_in_both_directions() {
        let (mut client, mut server, h) = relayed().await;
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
        let (ab, ba) = h.await.unwrap().unwrap();
        assert_eq!((ab, ba), (up.len() as u64, down.len() as u64));
    }

    #[tokio::test]
    async fn half_close_keeps_the_other_direction_open() {
        let (mut client, mut server, h) = relayed().await;
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
        assert_eq!(h.await.unwrap().unwrap(), (7, 10));
    }

    #[tokio::test]
    async fn empty_connection_closes_cleanly() {
        let (mut client, mut server, h) = relayed().await;
        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
        let mut b = Vec::new();
        client.read_to_end(&mut b).await.unwrap();
        server.read_to_end(&mut b).await.unwrap();
        assert_eq!(h.await.unwrap().unwrap(), (0, 0));
    }

    #[tokio::test]
    async fn many_small_writes_arrive_in_order() {
        let (mut client, mut server, _h) = relayed().await;
        let writer = tokio::spawn(async move {
            for i in 0..2000u32 {
                client.write_all(&i.to_be_bytes()).await.unwrap();
            }
            client.shutdown().await.unwrap();
        });
        let mut all = Vec::new();
        server.read_to_end(&mut all).await.unwrap();
        writer.await.unwrap();
        assert_eq!(all.len(), 8000);
        for (i, c) in all.chunks(4).enumerate() {
            assert_eq!(u32::from_be_bytes(c.try_into().unwrap()), i as u32);
        }
    }

    #[tokio::test]
    async fn a_reset_peer_ends_the_relay_with_an_error_not_a_hang() {
        let (client, mut server, h) = relayed().await;
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
        let r = tokio::time::timeout(std::time::Duration::from_secs(5), h).await;
        assert!(r.is_ok(), "relay must terminate after a reset");
    }

    #[test]
    fn pipes_keep_the_default_size_and_stay_cheap() {
        let p = Pipe::new().unwrap();
        assert!(p.cap >= MIN_PIPE);
        assert!(
            p.cap <= 64 * 1024,
            "no enlarged pipes: they exhaust the per-user pipe budget"
        );
    }
}
