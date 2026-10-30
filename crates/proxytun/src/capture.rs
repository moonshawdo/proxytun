//! Serving the namespace: the TUN packet loop and the relay's accept loop.
//!
//! Every packet the program's kernel routes out of the namespace arrives on
//! the TUN device:
//!   * TCP is rewritten through the `Nat` table onto our listener, so the
//!     namespace's kernel terminates it and the relay gets a plain socket;
//!     the listener's replies are rewritten back;
//!   * UDP to port 53, whatever the address, is answered by the fake-ip DNS;
//!   * other UDP gets ICMP port unreachable (QUIC falls back to TCP);
//!   * everything else (ICMP, IPv6, fragments) is dropped.

use crate::nat::Nat;
use crate::netns::Addrs;
use crate::packet::{self, Packet, PROTO_TCP, PROTO_UDP};
use anyhow::{anyhow, bail, Result};
use proxytun_core::net::dns::{self, Transport};
use proxytun_core::net::fakeip::{FakeGuard, FakePool};
use proxytun_core::net::relay::{self, Live};
use proxytun_core::types::{Pending, Target};
use std::net::{SocketAddr, SocketAddrV4};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::{Duration, Instant};
use tokio::io::unix::AsyncFd;
use tokio::net::TcpListener;
use tracing::{field, Instrument, Span};

#[derive(Default)]
pub struct Stats {
    pub connections: AtomicU64,
    pub active: AtomicU64,
    pub dns_queries: AtomicU64,
    pub udp_refused: AtomicU64,
    pub dropped: AtomicU64,
}

/// State shared by the packet loop, the relay and the signal handlers.
pub struct Shared {
    pub addrs: Addrs,
    /// The listener captured TCP is rewritten to.
    pub listen: SocketAddrV4,
    pub nat: Mutex<Nat>,
    pub pool: FakePool,
    pub upstream_dns: SocketAddr,
    /// Rules and proxies, swapped on SIGHUP.
    pub live: RwLock<Arc<Live>>,
    pub stats: Stats,
    /// Last connection id handed out (TUN-captured and host-port alike).
    pub last_id: AtomicU64,
}

impl Shared {
    pub fn next_conn_id(&self) -> u64 {
        self.last_id.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn live(&self) -> Arc<Live> {
        self.live.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn nat(&self) -> MutexGuard<'_, Nat> {
        // A poisoned lock only means a panic mid-update of plain maps.
        self.nat.lock().unwrap_or_else(|e| e.into_inner())
    }
}

// ------------------------------------------------------------ packet loop --

/// Read packets from the TUN device until it fails.
pub async fn run_tun(tun: OwnedFd, sh: Arc<Shared>) -> Result<()> {
    set_nonblocking(&tun)?;
    // SAFETY: the OwnedFd stays open, and is the same fd, for as long as the
    // AsyncFd owns it.
    let tun = Arc::new(unsafe { AsyncFd::register(tun) }?);
    let mut buf = vec![0u8; 65536];
    loop {
        let mut ready = tun.readable().await?;
        // SAFETY: read into our own buffer.
        let n = unsafe { libc::read(tun.as_raw_fd(), buf.as_mut_ptr() as *mut _, buf.len()) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::WouldBlock {
                ready.clear_ready();
                continue;
            }
            bail!("reading the TUN device: {e}");
        }
        on_packet(&tun, &sh, &mut buf[..n as usize]);
    }
}

fn set_nonblocking(fd: &OwnedFd) -> Result<()> {
    // SAFETY: plain fcntl on an fd we own.
    unsafe {
        let fl = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL);
        if fl < 0 || libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, fl | libc::O_NONBLOCK) < 0 {
            bail!("fcntl O_NONBLOCK: {}", std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn on_packet(tun: &Arc<AsyncFd<OwnedFd>>, sh: &Arc<Shared>, pkt: &mut [u8]) {
    let Some(p) = packet::parse(pkt) else {
        sh.stats.dropped.fetch_add(1, Ordering::Relaxed);
        return;
    };
    match p.proto {
        PROTO_TCP => on_tcp(tun, sh, pkt, &p),
        PROTO_UDP if p.dst.port() == 53 => on_dns(tun, sh, pkt, &p),
        PROTO_UDP => {
            sh.stats.udp_refused.fetch_add(1, Ordering::Relaxed);
            tracing::trace!(src = %p.src, dst = %p.dst, "udp refused");
            write_packet(tun, &packet::build_port_unreachable(pkt, &p));
        }
        _ => {
            sh.stats.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn on_tcp(tun: &AsyncFd<OwnedFd>, sh: &Shared, pkt: &mut [u8], p: &Packet) {
    let rewritten = if p.src == sh.listen && *p.dst.ip() == sh.addrs.nat {
        // The listener answering: back to the program, from where it dialed.
        sh.nat().inbound(p.dst.port())
    } else {
        let port = sh.nat().outbound(p.src, p.dst, p.is_syn(), Instant::now());
        if p.is_syn() {
            match port {
                Some(port) => tracing::trace!(src = %p.src, dst = %p.dst, nat_port = port, "syn"),
                None => tracing::error!(src = %p.src, dst = %p.dst, "address-rewriting table full, dropping a SYN"),
            }
        }
        port.map(|port| (SocketAddrV4::new(sh.addrs.nat, port), sh.listen))
    };
    match rewritten {
        Some((src, dst)) => {
            packet::rewrite_tcp(pkt, p, src, dst);
            write_packet(tun, &pkt[..p.len]);
        }
        None => {
            sh.stats.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn on_dns(tun: &Arc<AsyncFd<OwnedFd>>, sh: &Arc<Shared>, pkt: &[u8], p: &Packet) {
    sh.stats.dns_queries.fetch_add(1, Ordering::Relaxed);
    let query = packet::udp_payload(pkt, p).to_vec();
    let (client, server) = (p.src, p.dst);
    let (tun, sh) = (tun.clone(), sh.clone());
    // Forwarded queries can take seconds; never hold up the packet loop.
    tokio::spawn(async move {
        let Some(resp) = dns::respond(&query, &sh.pool, sh.upstream_dns, Transport::Udp).await else {
            return;
        };
        // From the address the program asked, so its resolver accepts it.
        if let Some(b) = packet::build_udp(server, client, &resp) {
            write_packet(&tun, &b);
        }
    });
}

/// Hand a packet to the namespace's kernel. A TUN write never blocks; if the
/// kernel refuses one (out of memory) the sender retransmits, as on a real
/// link.
fn write_packet(tun: &AsyncFd<OwnedFd>, b: &[u8]) {
    // SAFETY: plain write of our own buffer.
    let n = unsafe { libc::write(tun.as_raw_fd(), b.as_ptr() as *const _, b.len()) };
    if n < 0 {
        tracing::debug!("writing to the TUN device: {}", std::io::Error::last_os_error());
    }
}

// ------------------------------------------------------------------ relay --

/// Accept captured connections and relay each one.
pub async fn run_relay(listener: TcpListener, sh: Arc<Shared>) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("relay accept: {e}");
                tokio::time::sleep(Duration::from_millis(20)).await;
                continue;
            }
        };
        let id = sh.next_conn_id();
        // Every line about this connection names it. Error level: present
        // whenever anything is logged, so a proxy failing at warn names it too.
        let span = tracing::error_span!("conn", id, target = field::Empty);
        let sh = sh.clone();
        tokio::spawn(
            async move {
                if let Err(e) = relay_one(&sh, stream, peer).await {
                    tracing::debug!("relay conn error: {e:#}");
                }
            }
            .instrument(span),
        );
    }
}

/// Marks the connection's table entry closed (and the connection inactive)
/// however the relay ends.
struct Closing<'a> {
    sh: &'a Shared,
    port: u16,
}

impl Drop for Closing<'_> {
    fn drop(&mut self) {
        self.sh.nat().close(self.port, Instant::now());
        self.sh.stats.active.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn relay_one(sh: &Shared, stream: tokio::net::TcpStream, peer: SocketAddr) -> Result<()> {
    let SocketAddr::V4(peer) = peer else {
        bail!("not a captured connection: {peer}");
    };
    if *peer.ip() != sh.addrs.nat {
        bail!("not a captured connection: {peer}");
    }
    let dst = sh
        .nat()
        .accept(peer.port())
        .ok_or_else(|| anyhow!("no address-rewriting entry for {peer}"))?;
    sh.stats.connections.fetch_add(1, Ordering::Relaxed);
    sh.stats.active.fetch_add(1, Ordering::Relaxed);
    let _closing = Closing { sh, port: peer.port() };
    tracing::trace!(nat_port = peer.port(), %dst, "accepted");

    if dst.port() == 53 {
        // DNS over TCP, to whatever server the program chose.
        Span::current().record("target", field::display(dst));
        tracing::info!("dns over tcp");
        dns::serve_tcp(stream, &sh.pool, sh.upstream_dns).await;
        return Ok(());
    }
    let (target, guard) = to_target(dst, &sh.pool);
    relay::route(&sh.live(), stream, Pending { target, guard }).await
}

/// Map a fake IP back to its domain (pinning the mapping for the connection's
/// lifetime); anything else stays a literal IP. A stale fake IP, recycled
/// since the program resolved it, stays an IP and the proxy fails it.
fn to_target(dst: SocketAddrV4, pool: &FakePool) -> (Target, Option<FakeGuard>) {
    match pool.acquire(*dst.ip()) {
        Some((domain, guard)) => (Target::Domain(domain, dst.port()), Some(guard)),
        None => (Target::V4(*dst.ip(), dst.port()), None),
    }
}

/// Drop table entries whose connection is long gone.
pub async fn run_sweeper(sh: Arc<Shared>) {
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    loop {
        tick.tick().await;
        let n = sh.nat().sweep(Instant::now());
        if n > 0 {
            tracing::debug!(expired = n, "swept address-rewriting entries");
        }
    }
}

pub fn log_stats(sh: &Shared) {
    let s = &sh.stats;
    tracing::info!(
        fake_ips = sh.pool.len(),
        nat_entries = sh.nat().len(),
        connections = s.connections.load(Ordering::Relaxed),
        active = s.active.load(Ordering::Relaxed),
        dns_queries = s.dns_queries.load(Ordering::Relaxed),
        udp_refused = s.udp_refused.load(Ordering::Relaxed),
        dropped_packets = s.dropped.load(Ordering::Relaxed),
        "stats"
    );
    for n in &sh.live().registry.nodes {
        let s = n.stats();
        tracing::info!(
            proxy = %s.name, healthy = s.healthy, active = s.active,
            latency_ms = s.latency_us as f64 / 1000.0, ok = s.ok_total, failed = s.fail_total,
            "proxy stats"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::tests::sa;
    use proxytun_core::config::Config;
    use std::net::Ipv4Addr;
    use tokio::net::{TcpSocket, TcpStream};

    /// NAT_IP is 127.0.0.2 here, so a test can play the rewritten client.
    fn shared(listen: SocketAddrV4) -> Shared {
        let cfg = Config::parse("[proxy]\ntype=\"socks5\"\naddr=\"127.0.0.1:1\"\n").unwrap();
        Shared {
            addrs: Addrs {
                tun: Ipv4Addr::LOCALHOST,
                nat: Ipv4Addr::new(127, 0, 0, 2),
                dns: Ipv4Addr::new(127, 0, 0, 53),
            },
            listen,
            nat: Mutex::new(Nat::default()),
            pool: FakePool::new("198.18.0.0/15".parse().unwrap()),
            upstream_dns: "127.0.0.1:9".parse().unwrap(),
            live: RwLock::new(Arc::new(relay::build_live(&cfg).unwrap())),
            stats: Stats::default(),
            last_id: AtomicU64::new(0),
        }
    }

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
        let port = sh
            .nat()
            .outbound(sa("198.19.255.1:5555"), sa("9.9.9.9:53"), true, Instant::now())
            .unwrap();
        let (_c, r) = relay_from(&l, &sh, SocketAddrV4::new(sh.addrs.nat, port)).await;
        r.unwrap();
        assert_eq!(sh.nat().accept(port), None, "closed once the relay is done");
        assert_eq!(sh.stats.connections.load(Ordering::Relaxed), 1);
        assert_eq!(sh.stats.active.load(Ordering::Relaxed), 0);
    }
}
