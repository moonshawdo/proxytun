//! After the accept: the relay's accept loop for captured connections, the
//! relay slots every accept loop (captured and host ports) takes from, and
//! what a captured connection becomes: its table entry looked up, its fake IP
//! mapped back to a domain, and the connection handed to `relay::route` (or,
//! on port 53, to the fake-ip DNS).

use crate::state::{count, Shared};
use anyhow::{anyhow, bail, Result};
use proxytun_core::net::dns;
use proxytun_core::net::fakeip::{FakeGuard, FakePool};
use proxytun_core::net::relay::{self, Pending};
use proxytun_core::throttle;
use proxytun_core::types::Target;
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tracing::{field, Instrument, Span};

/// The next connection on `listener` that may be relayed, with its slot.
/// accept failing (out of fds) fails again at once while connections wait:
/// reported now and then, retried after a pause. A connection over
/// `MAX_RELAYS` is reset, and the next one taken. (Its table entry ends when
/// the reset passes the TUN device; should the reset be lost there, it is
/// still waiting to be accepted, and `nat::QUEUED` resets the program.)
pub async fn accept_with_slot(
    listener: &TcpListener,
    sh: &Shared,
    what: &str,
) -> (tokio::net::TcpStream, SocketAddr, tokio::sync::OwnedSemaphorePermit) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                if sh.accept_failed_logged.due() {
                    tracing::warn!(
                        "{what} accept: {e} (repeats within {}s not logged)",
                        throttle::EVERY.as_secs()
                    );
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
                continue;
            }
        };
        match sh.relay_slots.clone().try_acquire_owned() {
            Ok(slot) => return (stream, peer, slot),
            Err(_) => refuse_busy(sh, stream),
        }
    }
}

/// A connection over `MAX_RELAYS`: reset at once, so the program fails fast
/// instead of waiting on a connection nobody serves.
fn refuse_busy(sh: &Shared, stream: tokio::net::TcpStream) {
    count(&sh.stats.relays_refused, 1);
    if sh.relays_refused_logged.due() {
        tracing::warn!(
            "as many connections as may be relayed at once are being relayed (see the open-file limit \
             at startup): refusing new ones (relays_refused; repeats within {}s not logged)",
            throttle::EVERY.as_secs()
        );
    }
    let _ = stream.set_zero_linger();
}

/// Accept captured connections and relay each one.
pub async fn run_relay(listener: TcpListener, sh: Arc<Shared>) {
    loop {
        let (stream, peer, slot) = accept_with_slot(&listener, &sh, "relay").await;
        let id = sh.next_conn_id();
        // Every line about this connection names it. Error level: present
        // whenever anything is logged, so a proxy failing at warn names it too.
        let span = tracing::error_span!("conn", id, target = field::Empty);
        let sh = sh.clone();
        tokio::spawn(
            async move {
                let _slot = slot;
                if let Err(e) = relay_one(&sh, stream, peer).await {
                    tracing::debug!("relay conn error: {e:#}");
                }
            }
            .instrument(span),
        );
    }
}

/// A connection being relayed, captured or host-port: counted in
/// `connections` and `active` when made, and out of `active` again however
/// the relay ends, its table entry (`nat`, for a captured one) marked closed
/// first.
pub struct Relaying<'a> {
    sh: &'a Shared,
    nat: Option<SocketAddrV4>,
}

impl<'a> Relaying<'a> {
    pub fn new(sh: &'a Shared, nat: Option<SocketAddrV4>) -> Relaying<'a> {
        sh.stats.connections.fetch_add(1, Ordering::Relaxed);
        sh.stats.active.fetch_add(1, Ordering::Relaxed);
        Relaying { sh, nat }
    }
}

impl Drop for Relaying<'_> {
    fn drop(&mut self) {
        if let Some(nat) = self.nat {
            self.sh.nat().close(nat, Instant::now());
        }
        self.sh.stats.active.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn relay_one(sh: &Shared, stream: tokio::net::TcpStream, peer: SocketAddr) -> Result<()> {
    let SocketAddr::V4(peer) = peer else {
        bail!("not a captured connection: {peer}");
    };
    if !sh.nat().is_nat(*peer.ip()) {
        bail!("not a captured connection: {peer}");
    }
    let dst = sh
        .nat()
        .accept(peer)
        .ok_or_else(|| anyhow!("no address-rewriting entry for {peer}"))?;
    let _relaying = Relaying::new(sh, Some(peer));
    tracing::trace!(nat = %peer, %dst, "accepted");

    if dst.port() == 53 {
        // DNS over TCP, to whatever server the program chose.
        Span::current().record("target", field::display(dst));
        tracing::info!("dns over tcp");
        let start = Instant::now();
        dns::serve_tcp(stream, &sh.pool, sh.upstream_dns, &sh.dns).await;
        tracing::info!(ms = start.elapsed().as_millis() as u64, "closed");
        return Ok(());
    }
    let (target, guard) = to_target(dst, &sh.pool);
    // `route` logs how the connection ended, errors included.
    let _ = relay::route(&sh.live(), &sh.traffic, stream, Pending { target, guard }).await;
    Ok(())
}

/// Map a fake IP back to its domain (pinning the mapping for the connection's
/// lifetime); anything else stays a literal IP, and a fake IP the pool never
/// handed out goes to the proxy as one, which fails it. A program that kept
/// an answer past `REUSE_AFTER` (twice its TTL) may find the address
/// recycled, naming another domain by then.
fn to_target(dst: SocketAddrV4, pool: &FakePool) -> (Target, Option<FakeGuard>) {
    match pool.acquire(*dst.ip()) {
        Some((domain, guard)) => (Target::Domain(domain, dst.port()), Some(guard)),
        None => (Target::V4(*dst.ip(), dst.port()), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::tests::sa;
    use crate::state::tests::shared;
    use std::sync::Mutex;
    use tokio::net::{TcpSocket, TcpStream};

    async fn relay_from(l: &TcpListener, sh: &Shared, from: SocketAddrV4) -> (TcpStream, Result<()>) {
        let sock = TcpSocket::new_v4().unwrap();
        sock.set_reuseaddr(true).unwrap();
        sock.bind(SocketAddr::V4(from)).unwrap();
        let client = sock.connect(l.local_addr().unwrap()).await.unwrap();
        let (s, peer) = l.accept().await.unwrap();
        // The client hangs up at once: a DNS-over-TCP relay then ends cleanly.
        let mut client = client;
        tokio::io::AsyncWriteExt::shutdown(&mut client).await.unwrap();
        (client, relay_one(sh, s, peer).await)
    }

    #[tokio::test]
    async fn only_rewritten_connections_are_relayed_and_their_entry_closes_after() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let SocketAddr::V4(listen) = l.local_addr().unwrap() else {
            unreachable!()
        };
        let sh = shared(listen);

        // Not from NAT_IP: something in the namespace dialed the listener itself.
        let (_c, r) = relay_from(&l, &sh, sa("127.0.0.1:0")).await;
        assert!(r.unwrap_err().to_string().contains("not a captured connection"));

        // From NAT_IP on a port the TUN loop never handed out.
        let (_c, r) = relay_from(&l, &sh, sa("127.0.0.2:0")).await;
        assert!(r.unwrap_err().to_string().contains("no address-rewriting entry"));

        // A real entry (a DNS-over-TCP connection) is relayed, then closed.
        let nat = sh
            .nat()
            .outbound(sa("198.19.255.1:5555"), sa("9.9.9.9:53"), Some(1), Instant::now())
            .unwrap();
        let (_c, r) = relay_from(&l, &sh, nat).await;
        r.unwrap();
        assert_eq!(sh.nat().accept(nat), None, "closed once the relay is done");
        assert_eq!(sh.stats.connections.load(Ordering::Relaxed), 1);
        assert_eq!(sh.stats.active.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn over_the_relay_cap_a_connection_is_reset_at_once() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let SocketAddr::V4(listen) = l.local_addr().unwrap() else {
            unreachable!()
        };
        let mut sh = shared(listen);
        sh.relay_slots = Arc::new(tokio::sync::Semaphore::new(1));
        let sh = Arc::new(sh);
        tokio::spawn(run_relay(l, sh.clone()));
        let connect = |nat: SocketAddrV4| {
            let sock = TcpSocket::new_v4().unwrap();
            sock.set_reuseaddr(true).unwrap();
            sock.bind(SocketAddr::V4(nat)).unwrap();
            sock.connect(SocketAddr::V4(listen))
        };
        let entry = |program: &str| {
            sh.nat()
                .outbound(sa(program), sa("9.9.9.9:53"), Some(1), Instant::now())
                .unwrap()
        };
        // One connection (DNS over TCP, held open) takes the only slot.
        let first = entry("198.19.255.1:5001");
        let _held = connect(first).await.unwrap();
        while sh.stats.active.load(Ordering::Relaxed) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // The next one is reset, not left waiting, and its entry ends.
        let second = entry("198.19.255.1:5002");
        let mut c = connect(second).await.unwrap();
        let mut b = [0u8; 1];
        let r = tokio::time::timeout(Duration::from_secs(2), tokio::io::AsyncReadExt::read(&mut c, &mut b))
            .await
            .expect("answered at once");
        assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::ConnectionReset);
        assert_eq!(sh.stats.relays_refused.load(Ordering::Relaxed), 1);
        // Its entry is left to the TUN thread, which sees the reset go by:
        // ended here, a lost reset would leave the program waiting forever
        // instead of reset after `nat::QUEUED`.
        assert_eq!(sh.nat().accept(second), Some(sa("9.9.9.9:53")));
    }

    /// What is logged on this thread (the test's, which runs every task of a
    /// current-thread runtime) until the guard is dropped. Messages only, no
    /// targets: this module's own name is `accept`.
    fn logged() -> (Arc<Mutex<Vec<u8>>>, tracing::subscriber::DefaultGuard) {
        struct Lines(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Lines {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let lines = Arc::new(Mutex::new(Vec::new()));
        let to = lines.clone();
        let sub = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_target(false)
            .with_writer(move || Lines(to.clone()))
            .finish();
        (lines, tracing::subscriber::set_default(sub))
    }

    fn count_in(lines: &Mutex<Vec<u8>>, what: &str) -> usize {
        String::from_utf8_lossy(&lines.lock().unwrap()).matches(what).count()
    }

    #[tokio::test]
    async fn refusals_are_reported_once_for_all_accept_loops_together() {
        let (lines, _log) = logged();
        let relay = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let host_port = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (to_relay, to_host_port) = (relay.local_addr().unwrap(), host_port.local_addr().unwrap());
        let SocketAddr::V4(listen) = to_relay else {
            unreachable!()
        };
        let mut sh = shared(listen);
        sh.relay_slots = Arc::new(tokio::sync::Semaphore::new(0));
        let sh = Arc::new(sh);
        tokio::spawn(run_relay(relay, sh.clone()));
        tokio::spawn(crate::hostports::serve(host_port, to_host_port, sh.clone()));
        // One connection over the cap on each loop: two refused, within the
        // same 10 s.
        let _a = TcpStream::connect(to_relay).await.unwrap();
        let _b = TcpStream::connect(to_host_port).await.unwrap();
        while sh.stats.relays_refused.load(Ordering::Relaxed) < 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            count_in(&lines, "refusing new ones"),
            1,
            "one line, whichever loop refused"
        );
    }

    #[tokio::test]
    async fn accept_failures_are_reported_once_for_all_accept_loops_together() {
        use std::os::fd::{FromRawFd, IntoRawFd};
        let (lines, _log) = logged();
        // Bound but not listening: every accept fails at once (EINVAL), as
        // one out of fds would.
        let failing = || {
            let s = TcpSocket::new_v4().unwrap();
            s.bind(sa("127.0.0.1:0").into()).unwrap();
            TcpListener::from_std(unsafe { std::net::TcpListener::from_raw_fd(s.into_raw_fd()) }).unwrap()
        };
        let sh = Arc::new(shared(sa("127.0.0.1:9")));
        tokio::spawn(run_relay(failing(), sh.clone()));
        tokio::spawn(crate::hostports::serve(failing(), sa("127.0.0.1:9").into(), sh.clone()));
        // Each loop fails several times over (retrying every 20 ms).
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(count_in(&lines, "accept:"), 1, "one line, whichever loop failed");
    }
}
