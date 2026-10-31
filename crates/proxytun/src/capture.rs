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
use proxytun_core::net::dns::{self, DnsStats, Transport};
use proxytun_core::net::fakeip::{FakeGuard, FakePool};
use proxytun_core::net::relay::{self, Live, Traffic};
use proxytun_core::types::{Pending, Target};
use std::net::{SocketAddr, SocketAddrV4};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::runtime::Handle;
use tracing::{field, Instrument, Span};

/// Counters for SIGUSR1. Packet counts are for the TUN device; drops are
/// split by reason, since each points at a different problem.
#[derive(Default)]
pub struct Stats {
    pub connections: AtomicU64,
    pub active: AtomicU64,
    pub udp_refused: AtomicU64,
    pub tun_packets_in: AtomicU64,
    pub tun_bytes_in: AtomicU64,
    pub tun_packets_out: AtomicU64,
    pub tun_bytes_out: AtomicU64,
    /// Not IPv4, a fragment, or malformed.
    pub drop_unparsed: AtomicU64,
    /// IPv4 but neither TCP nor UDP (ICMP...).
    pub drop_other_proto: AtomicU64,
    /// TCP for no known connection (a stray packet after the entry expired).
    pub drop_no_flow: AtomicU64,
    /// A SYN that found the address-rewriting table full.
    pub drop_table_full: AtomicU64,
}

/// The counters `log_stats` turns into rates.
#[derive(Clone, Copy)]
pub struct Snapshot {
    at: Instant,
    connections: u64,
    tun_packets_in: u64,
    tun_bytes_in: u64,
    up: u64,
    down: u64,
}

/// Per-second rates between two snapshots (MB = 10^6 bytes).
#[derive(Debug, PartialEq)]
pub struct Rates {
    seconds: f64,
    connections: f64,
    tun_packets_in: f64,
    tun_mb_in: f64,
    up_mb: f64,
    down_mb: f64,
}

impl Snapshot {
    fn rates_since(&self, prev: &Snapshot) -> Rates {
        let seconds = self.at.duration_since(prev.at).as_secs_f64().max(1e-3);
        let per_s = |a: u64, b: u64| a.saturating_sub(b) as f64 / seconds;
        Rates {
            seconds,
            connections: per_s(self.connections, prev.connections),
            tun_packets_in: per_s(self.tun_packets_in, prev.tun_packets_in),
            tun_mb_in: per_s(self.tun_bytes_in, prev.tun_bytes_in) / 1e6,
            up_mb: per_s(self.up, prev.up) / 1e6,
            down_mb: per_s(self.down, prev.down) / 1e6,
        }
    }

    pub fn zero() -> Self {
        Snapshot {
            at: Instant::now(),
            connections: 0,
            tun_packets_in: 0,
            tun_bytes_in: 0,
            up: 0,
            down: 0,
        }
    }
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
    pub dns: DnsStats,
    pub traffic: Traffic,
    /// Counters at the previous `log_stats`, for rates.
    pub last_stats: Mutex<Snapshot>,
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

fn count(c: &AtomicU64, n: usize) {
    c.fetch_add(n as u64, Ordering::Relaxed);
}

// ------------------------------------------------------------ packet loop --

/// Read packets from the TUN device until it fails. Runs on its own thread
/// (named "tun", easy to find in `top -H`): the namespace's TCP processing
/// happens in our writes, so this is where the CPU goes. `rt` runs the DNS
/// lookups, which may take seconds.
pub fn run_tun(tun: OwnedFd, sh: Arc<Shared>, rt: Handle) -> Result<()> {
    let tun = Arc::new(tun);
    let mut buf = vec![0u8; 65536];
    loop {
        // SAFETY: read into our own buffer from a blocking fd.
        let n = unsafe { libc::read(tun.as_raw_fd(), buf.as_mut_ptr() as *mut _, buf.len()) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            bail!("reading the TUN device: {e}");
        }
        on_packet(&tun, &sh, &rt, &mut buf[..n as usize]);
    }
}

fn on_packet(tun: &Arc<OwnedFd>, sh: &Arc<Shared>, rt: &Handle, pkt: &mut [u8]) {
    count(&sh.stats.tun_packets_in, 1);
    count(&sh.stats.tun_bytes_in, pkt.len());
    let Some(p) = packet::parse(pkt) else {
        count(&sh.stats.drop_unparsed, 1);
        return;
    };
    match p.proto {
        PROTO_TCP => on_tcp(tun, sh, pkt, &p),
        PROTO_UDP if p.dst.port() == 53 => on_dns(tun, sh, rt, pkt, &p),
        PROTO_UDP => {
            count(&sh.stats.udp_refused, 1);
            tracing::trace!(src = %p.src, dst = %p.dst, "udp refused");
            write_packet(tun, sh, &packet::build_port_unreachable(pkt, &p));
        }
        _ => count(&sh.stats.drop_other_proto, 1),
    }
}

fn on_tcp(tun: &OwnedFd, sh: &Shared, pkt: &mut [u8], p: &Packet) {
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
            write_packet(tun, sh, &pkt[..p.len]);
        }
        None if p.is_syn() => count(&sh.stats.drop_table_full, 1),
        None => {
            count(&sh.stats.drop_no_flow, 1);
            tracing::trace!(src = %p.src, dst = %p.dst, flags = p.flags, "tcp for no known connection, dropped");
        }
    }
}

fn on_dns(tun: &Arc<OwnedFd>, sh: &Arc<Shared>, rt: &Handle, pkt: &[u8], p: &Packet) {
    let query = packet::udp_payload(pkt, p).to_vec();
    let (client, server) = (p.src, p.dst);
    let (tun, sh) = (tun.clone(), sh.clone());
    // Forwarded queries can take seconds; never hold up the packet loop.
    rt.spawn(async move {
        let Some(resp) = dns::respond(&query, &sh.pool, sh.upstream_dns, Transport::Udp, &sh.dns).await else {
            return;
        };
        // From the address the program asked, so its resolver accepts it.
        if let Some(b) = packet::build_udp(server, client, &resp) {
            write_packet(&tun, &sh, &b);
        }
    });
}

/// Hand a packet to the namespace's kernel. A TUN write never blocks; if the
/// kernel refuses one (out of memory) the sender retransmits, as on a real
/// link.
fn write_packet(tun: &OwnedFd, sh: &Shared, b: &[u8]) {
    // SAFETY: plain write of our own buffer.
    let n = unsafe { libc::write(tun.as_raw_fd(), b.as_ptr() as *const _, b.len()) };
    if n < 0 {
        tracing::debug!("writing to the TUN device: {}", std::io::Error::last_os_error());
        return;
    }
    count(&sh.stats.tun_packets_out, 1);
    count(&sh.stats.tun_bytes_out, b.len());
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

/// SIGUSR1: totals since start, then rates since the previous dump (or since
/// start), for telling where the time goes without outside tools.
pub fn log_stats(sh: &Shared) {
    let (s, d) = (&sh.stats, &sh.dns);
    let n = |c: &AtomicU64| c.load(Ordering::Relaxed);
    let now = Snapshot {
        at: Instant::now(),
        connections: n(&s.connections),
        tun_packets_in: n(&s.tun_packets_in),
        tun_bytes_in: n(&s.tun_bytes_in),
        up: n(&sh.traffic.up),
        down: n(&sh.traffic.down),
    };
    tracing::info!(
        fake_ips = sh.pool.len(),
        nat_entries = sh.nat().len(),
        connections = now.connections,
        active = n(&s.active),
        relayed_up = now.up,
        relayed_down = now.down,
        dns_queries = n(&d.queries),
        dns_forwarded = n(&d.forwarded),
        dns_forward_failed = n(&d.forward_failed),
        udp_refused = n(&s.udp_refused),
        tun_packets_in = now.tun_packets_in,
        tun_bytes_in = now.tun_bytes_in,
        tun_packets_out = n(&s.tun_packets_out),
        tun_bytes_out = n(&s.tun_bytes_out),
        dropped_unparsed = n(&s.drop_unparsed),
        dropped_other_proto = n(&s.drop_other_proto),
        dropped_no_flow = n(&s.drop_no_flow),
        dropped_table_full = n(&s.drop_table_full),
        "stats"
    );
    let prev = std::mem::replace(&mut *sh.last_stats.lock().unwrap_or_else(|e| e.into_inner()), now);
    let r = now.rates_since(&prev);
    tracing::info!(
        seconds = %format!("{:.1}", r.seconds),
        connections_per_s = %format!("{:.1}", r.connections),
        tun_packets_in_per_s = %format!("{:.0}", r.tun_packets_in),
        tun_mb_in_per_s = %format!("{:.2}", r.tun_mb_in),
        up_mb_per_s = %format!("{:.2}", r.up_mb),
        down_mb_per_s = %format!("{:.2}", r.down_mb),
        "rates since the previous stats"
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
            dns: DnsStats::default(),
            traffic: Traffic::default(),
            last_stats: Mutex::new(Snapshot::zero()),
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

    /// A pipe stands in for the TUN device: what we write comes out of the
    /// returned file.
    fn fake_tun() -> (Arc<OwnedFd>, std::fs::File) {
        use std::os::fd::FromRawFd;
        let mut fds = [0; 2];
        assert_eq!(
            unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
            0
        );
        unsafe {
            (
                Arc::new(OwnedFd::from_raw_fd(fds[1])),
                std::fs::File::from_raw_fd(fds[0]),
            )
        }
    }

    #[tokio::test]
    async fn every_packet_is_counted_and_every_drop_has_its_reason() {
        use crate::packet::tests::tcp;
        use crate::packet::{TCP_ACK, TCP_SYN};
        use std::io::Read;
        let listen = sa("127.0.0.1:4000");
        let sh = Arc::new(shared(listen));
        let (tun, mut out) = fake_tun();
        let rt = Handle::current();
        let n = |c: &AtomicU64| c.load(Ordering::Relaxed);

        let mut v6 = tcp(sa("1.1.1.1:1"), sa("2.2.2.2:2"), TCP_SYN, b"");
        v6[0] = 0x60;
        let mut icmp = tcp(sa("1.1.1.1:1"), sa("2.2.2.2:2"), TCP_SYN, b"");
        icmp[9] = packet::PROTO_ICMP;
        let mut stray = tcp(sa("198.19.255.1:40000"), sa("198.18.0.9:443"), TCP_ACK, b"x");
        let mut syn = tcp(sa("198.19.255.1:40000"), sa("198.18.0.9:443"), TCP_SYN, b"");
        let mut quic = packet::build_udp(sa("198.19.255.1:5000"), sa("1.2.3.4:443"), b"quic").unwrap();
        let mut sizes = 0;
        for pkt in [&mut v6, &mut icmp, &mut stray, &mut syn, &mut quic] {
            sizes += pkt.len();
            on_packet(&tun, &sh, &rt, pkt);
        }
        // Fill the table: the next SYN has nowhere to go.
        {
            let mut nat = sh.nat();
            for i in 0..crate::nat::PORTS.len() {
                let src = SocketAddrV4::new([10, 0, (i >> 8) as u8, i as u8].into(), 1);
                nat.outbound(src, sa("1.1.1.1:80"), true, Instant::now());
            }
        }
        let mut late = tcp(sa("198.19.255.1:40001"), sa("198.18.0.9:443"), TCP_SYN, b"");
        sizes += late.len();
        on_packet(&tun, &sh, &rt, &mut late);

        let s = &sh.stats;
        assert_eq!((n(&s.tun_packets_in), n(&s.tun_bytes_in)), (6, sizes as u64));
        assert_eq!(
            (
                n(&s.drop_unparsed),
                n(&s.drop_other_proto),
                n(&s.drop_no_flow),
                n(&s.drop_table_full),
                n(&s.udp_refused)
            ),
            (1, 1, 1, 1, 1),
            "IPv6, ICMP, a stray ACK, a SYN into a full table, a QUIC datagram"
        );
        // Out: the rewritten SYN, then the ICMP refusal of the datagram.
        let mut written = vec![0u8; 4096];
        let got = out.read(&mut written).unwrap();
        assert_eq!(n(&s.tun_packets_out), 2);
        assert_eq!(n(&s.tun_bytes_out), got as u64);
        let first = packet::parse(&written[..got]).unwrap();
        assert_eq!(
            (first.dst, *first.src.ip()),
            (listen, sh.addrs.nat),
            "the SYN was rewritten to the listener"
        );
    }

    #[test]
    fn rates_are_deltas_over_the_time_between_two_dumps() {
        let t0 = Instant::now();
        let prev = Snapshot {
            at: t0,
            connections: 10,
            tun_packets_in: 1000,
            tun_bytes_in: 5_000_000,
            up: 1_000_000,
            down: 2_000_000,
        };
        let now = Snapshot {
            at: t0 + Duration::from_secs(2),
            connections: 30,
            tun_packets_in: 101_000,
            tun_bytes_in: 205_000_000,
            up: 3_000_000,
            down: 202_000_000,
        };
        assert_eq!(
            now.rates_since(&prev),
            Rates {
                seconds: 2.0,
                connections: 10.0,
                tun_packets_in: 50_000.0,
                tun_mb_in: 100.0,
                up_mb: 1.0,
                down_mb: 100.0
            }
        );
    }
}
