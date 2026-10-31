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
use crate::packet::{self, Packet, PROTO_TCP, PROTO_UDP, TCP_ACK, TCP_RST, TCP_SYN};
use anyhow::{anyhow, bail, Result};
use proxytun_core::net::dns::{self, DnsStats, Transport};
use proxytun_core::net::fakeip::{FakeGuard, FakePool};
use proxytun_core::net::relay::{self, Live, Traffic};
use proxytun_core::throttle;
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
    /// Connections reset because `MAX_RELAYS` were being relayed already.
    pub relays_refused: AtomicU64,
}

/// At most this many connections are relayed at once (captured and host-port
/// alike): each holds two 64 KiB buffers, and the fd limit no longer stops
/// them short of the address-rewriting table. 1 GiB of buffers at most.
pub const MAX_RELAYS: usize = 8192;

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
    /// When the full address-rewriting table was last reported.
    pub table_full_logged: Mutex<Option<Instant>>,
    /// One per connection being relayed, `MAX_RELAYS` in all.
    pub relay_slots: Arc<tokio::sync::Semaphore>,
}

/// When an accept loop last reported trouble.
#[derive(Default)]
pub struct AcceptLog {
    failed: Option<Instant>,
    busy: Option<Instant>,
}

/// The next connection on `listener` that may be relayed, with its slot.
/// accept failing (out of fds) fails again at once while connections wait:
/// reported now and then, retried after a pause. A connection over
/// `MAX_RELAYS` is reset, after `refused` cleans up after it, and the next
/// one taken.
pub async fn accept_with_slot(
    listener: &TcpListener,
    sh: &Shared,
    what: &str,
    log: &mut AcceptLog,
    refused: impl Fn(SocketAddr),
) -> (tokio::net::TcpStream, SocketAddr, tokio::sync::OwnedSemaphorePermit) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                if throttle::due(&mut log.failed, Instant::now(), throttle::EVERY) {
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
            Err(_) => {
                refused(peer);
                refuse_busy(sh, stream, &mut log.busy);
            }
        }
    }
}

/// A connection over `MAX_RELAYS`: reset at once, so the program fails fast
/// instead of waiting on a connection nobody serves.
fn refuse_busy(sh: &Shared, stream: tokio::net::TcpStream, warned: &mut Option<Instant>) {
    count(&sh.stats.relays_refused, 1);
    if throttle::due(warned, Instant::now(), throttle::EVERY) {
        tracing::warn!(
            "{MAX_RELAYS} connections are being relayed: refusing new ones (relays_refused; repeats \
             within {}s not logged)",
            throttle::EVERY.as_secs()
        );
    }
    let _ = stream.set_zero_linger();
}

/// Report a full address-rewriting table now and then: every retried SYN
/// lands there, on the TUN thread (`dropped_table_full` counts them all).
fn table_full_due(sh: &Shared) -> bool {
    let mut last = sh.table_full_logged.lock().unwrap_or_else(|e| e.into_inner());
    throttle::due(&mut last, Instant::now(), throttle::EVERY)
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
pub fn run_tun(tun: Arc<OwnedFd>, sh: Arc<Shared>, rt: Handle) -> Result<()> {
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
    let rst = p.flags & TCP_RST != 0;
    let rewritten = if p.src == sh.listen {
        // The listener answering: back to the program, from where it dialed.
        let mut nat = sh.nat();
        let syn_ack = (p.flags & (TCP_SYN | TCP_ACK) == TCP_SYN | TCP_ACK).then(|| packet::tcp_seq(pkt, p));
        // Only these change an entry's state: no second lookup per data packet.
        if syn_ack.is_some() || rst {
            nat.listener_sent(p.dst, syn_ack, rst, Instant::now());
        }
        nat.inbound(p.dst)
    } else {
        let mut table = sh.nat();
        let nat = table.outbound(p.src, p.dst, p.is_syn(), Instant::now());
        if rst {
            table.program_reset(p.src, p.dst, Instant::now());
        }
        drop(table);
        if p.is_syn() {
            match nat {
                Some(nat) => tracing::trace!(src = %p.src, dst = %p.dst, %nat, "syn"),
                None => {
                    // Refused at once: the program gets ECONNREFUSED now
                    // rather than retrying its SYN for two minutes.
                    let ack = packet::tcp_seq(pkt, p).wrapping_add(1);
                    write_packet(tun, sh, &packet::build_tcp_reset(p.dst, p.src, 0, Some(ack)));
                    if table_full_due(sh) {
                        tracing::error!(
                            src = %p.src, dst = %p.dst,
                            "address-rewriting table full, refusing new connections (see \
                             dropped_table_full; reported every {}s)",
                            throttle::EVERY.as_secs()
                        );
                    }
                }
            }
        }
        nat.map(|nat| (nat, sh.listen))
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
    let mut log = AcceptLog::default();
    loop {
        let (stream, peer, slot) = accept_with_slot(&listener, &sh, "relay", &mut log, |peer| {
            // Refused: its entry ends here too, or it would wait for an
            // accept forever.
            if let SocketAddr::V4(p) = peer {
                let mut nat = sh.nat();
                if nat.accept(p).is_some() {
                    nat.close(p, Instant::now());
                }
            }
        })
        .await;
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

/// Marks the connection's table entry closed (and the connection inactive)
/// however the relay ends.
struct Closing<'a> {
    sh: &'a Shared,
    nat: SocketAddrV4,
}

impl Drop for Closing<'_> {
    fn drop(&mut self) {
        self.sh.nat().close(self.nat, Instant::now());
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
    sh.stats.connections.fetch_add(1, Ordering::Relaxed);
    sh.stats.active.fetch_add(1, Ordering::Relaxed);
    let _closing = Closing { sh, nat: peer };
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
/// lifetime); anything else stays a literal IP. A stale fake IP, recycled
/// since the program resolved it, stays an IP and the proxy fails it.
fn to_target(dst: SocketAddrV4, pool: &FakePool) -> (Target, Option<FakeGuard>) {
    match pool.acquire(*dst.ip()) {
        Some((domain, guard)) => (Target::Domain(domain, dst.port()), Some(guard)),
        None => (Target::V4(*dst.ip(), dst.port()), None),
    }
}

/// Drop table entries whose connection is long gone.
pub async fn run_sweeper(tun: Arc<OwnedFd>, sh: Arc<Shared>) {
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    loop {
        tick.tick().await;
        sweep(&tun, &sh, Instant::now());
    }
}

/// Expire address-rewriting entries, and reset the programs left holding a
/// connection that was never accepted.
fn sweep(tun: &OwnedFd, sh: &Shared, now: Instant) {
    let (n, resets) = {
        let mut nat = sh.nat();
        (nat.sweep(now), nat.take_resets())
    };
    if n > 0 {
        tracing::debug!(expired = n, reset = resets.len(), "swept address-rewriting entries");
    }
    for r in resets {
        tracing::debug!(program = %r.to, dst = %r.from, "never accepted: resetting the program's connection");
        write_packet(tun, sh, &packet::build_tcp_reset(r.from, r.to, r.seq, None));
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
    // Read first: a lock taken inside the macro is held while the line is
    // written, and a stalled stderr (Ctrl+S, a paused pager) would stall the
    // TUN thread with it.
    let (fake_ips, nat_entries) = (sh.pool.len(), sh.nat().len());
    tracing::info!(
        fake_ips,
        nat_entries,
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
        relays_refused = n(&s.relays_refused),
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

    /// The (one) NAT address here, so a test can play the rewritten client.
    const NAT: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

    fn shared(listen: SocketAddrV4) -> Shared {
        let cfg = Config::parse("[proxy]\ntype=\"socks5\"\naddr=\"127.0.0.1:1\"\n").unwrap();
        Shared {
            listen,
            nat: Mutex::new(Nat::new(NAT, 1)),
            pool: FakePool::new("198.18.0.0/15".parse().unwrap()),
            upstream_dns: "127.0.0.1:9".parse().unwrap(),
            live: RwLock::new(Arc::new(relay::build_live(&cfg).unwrap())),
            stats: Stats::default(),
            dns: DnsStats::default(),
            traffic: Traffic::default(),
            last_stats: Mutex::new(Snapshot::zero()),
            last_id: AtomicU64::new(0),
            table_full_logged: Mutex::new(None),
            relay_slots: Arc::new(tokio::sync::Semaphore::new(MAX_RELAYS)),
        }
    }

    #[test]
    fn a_connection_the_listener_answered_outlives_a_stalled_accept() {
        let sh = shared("127.0.0.1:9".parse().unwrap());
        let (tun, _other) = std::os::unix::net::UnixDatagram::pair().unwrap();
        let tun = OwnedFd::from(tun);
        let (program, dst) = (
            crate::packet::tests::sa("198.19.255.1:40000"),
            crate::packet::tests::sa("198.18.0.5:443"),
        );
        let mut syn = crate::packet::tests::tcp(program, dst, TCP_SYN, b"");
        let p = packet::parse(&syn).unwrap();
        on_tcp(&tun, &sh, &mut syn, &p);
        let nat = sh.nat().outbound(program, dst, false, Instant::now()).unwrap();
        // The listener's SYN-ACK: the handshake completes in the kernel.
        let mut syn_ack = crate::packet::tests::tcp(sh.listen, nat, TCP_SYN | TCP_ACK, b"");
        let p = packet::parse(&syn_ack).unwrap();
        on_tcp(&tun, &sh, &mut syn_ack, &p);
        // accept stalls for a while (out of fds): the entry must still be
        // there for the relay to find.
        sh.nat().sweep(Instant::now() + crate::nat::QUEUED / 2);
        assert_eq!(sh.nat().accept(nat), Some(dst));

        // Another, never accepted: once its time is up, the program is reset
        // through the TUN device, at the sequence number it expects.
        use std::io::Read;
        let (tun, mut out) = fake_tun();
        let other = crate::packet::tests::sa("198.19.255.1:40001");
        let mut syn = crate::packet::tests::tcp(other, dst, TCP_SYN, b"");
        let p = packet::parse(&syn).unwrap();
        on_tcp(&tun, &sh, &mut syn, &p);
        let nat = sh.nat().outbound(other, dst, false, Instant::now()).unwrap();
        let mut syn_ack = crate::packet::tests::tcp(sh.listen, nat, TCP_SYN | TCP_ACK, b"");
        let p = packet::parse(&syn_ack).unwrap();
        on_tcp(&tun, &sh, &mut syn_ack, &p);
        let mut written = vec![0u8; 4096];
        let got = out.read(&mut written).unwrap(); // the rewritten SYN and SYN-ACK
        assert_eq!(got, syn.len() + syn_ack.len());
        sweep(&tun, &sh, Instant::now() + crate::nat::QUEUED);
        let got = out.read(&mut written).unwrap();
        let r = packet::parse(&written[..got]).unwrap();
        assert!(crate::packet::tests::checksums_ok(&written[..got]));
        assert_eq!((r.src, r.dst, r.flags), (dst, other, TCP_RST));
        // The test SYN-ACK's sequence number is 0x01020304.
        assert_eq!(packet::tcp_seq(&written[..got], &r), 0x0102_0305);

        // A third, reset by the program before accept (it gave up): over.
        let third = crate::packet::tests::sa("198.19.255.1:40002");
        let mut syn = crate::packet::tests::tcp(third, dst, TCP_SYN, b"");
        let p = packet::parse(&syn).unwrap();
        on_tcp(&tun, &sh, &mut syn, &p);
        let nat = sh.nat().outbound(third, dst, false, Instant::now()).unwrap();
        let mut rst = crate::packet::tests::tcp(third, dst, TCP_RST, b"");
        let p = packet::parse(&rst).unwrap();
        on_tcp(&tun, &sh, &mut rst, &p);
        assert_eq!(sh.nat().accept(nat), None, "the program's reset ended it");
    }

    #[test]
    fn stats_are_written_without_holding_the_address_table() {
        let sh = Arc::new(shared("127.0.0.1:9".parse().unwrap()));
        let free = Arc::new(Mutex::new(Vec::new()));
        let (sh2, free2) = (sh.clone(), free.clone());
        // Whenever a line is written, could the TUN thread take the table?
        let sub = tracing_subscriber::fmt()
            .with_writer(move || {
                free2.lock().unwrap().push(sh2.nat.try_lock().is_ok());
                std::io::sink()
            })
            .finish();
        tracing::subscriber::with_default(sub, || log_stats(&sh));
        let free = free.lock().unwrap();
        assert!(!free.is_empty() && free.iter().all(|&f| f), "{free:?}");
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
        let nat = sh
            .nat()
            .outbound(sa("198.19.255.1:5555"), sa("9.9.9.9:53"), true, Instant::now())
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
                .outbound(sa(program), sa("9.9.9.9:53"), true, Instant::now())
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
        assert_eq!(sh.nat().accept(second), None, "its entry is closed");
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
        // Out: the rewritten SYN, the ICMP refusal of the datagram, and the
        // reset refusing the SYN that found the table full.
        let mut written = vec![0u8; 4096];
        let got = out.read(&mut written).unwrap();
        assert_eq!(n(&s.tun_packets_out), 3);
        assert_eq!(n(&s.tun_bytes_out), got as u64);
        let first = packet::parse(&written[..got]).unwrap();
        assert_eq!(
            (first.dst, *first.src.ip()),
            (listen, NAT),
            "the SYN was rewritten to the listener"
        );
        let second = packet::parse(&written[first.len..got]).unwrap();
        let reset_at = first.len + second.len;
        let reset = &written[reset_at..got];
        let r = packet::parse(reset).unwrap();
        assert!(crate::packet::tests::checksums_ok(reset));
        assert_eq!(
            (r.src, r.dst, r.flags),
            (sa("198.18.0.9:443"), sa("198.19.255.1:40001"), TCP_RST | TCP_ACK),
            "from where the program dialed, refusing its SYN"
        );
        assert_eq!(packet::tcp_seq(reset, &r), 0);
        let late_seq = u32::from_be_bytes(late[24..28].try_into().unwrap());
        assert_eq!(
            u32::from_be_bytes(reset[28..32].try_into().unwrap()),
            late_seq + 1,
            "it acknowledges the SYN"
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
