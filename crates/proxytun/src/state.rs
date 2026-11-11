//! What the TUN loop, the accept loops and the signal handlers share: the
//! address-rewriting table, the fake-ip pool, the rules, the counters (and
//! their SIGUSR1 dump) and the relay slots.

use crate::nat::Nat;
use proxytun_core::live::Live;
use proxytun_core::net::dns::DnsStats;
use proxytun_core::net::fakeip::FakePool;
use proxytun_core::net::pump::Traffic;
use proxytun_core::throttle::Throttle;
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::Instant;

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
    /// DNS queries being answered now, and those dropped because
    /// `MAX_DNS_IN_FLIGHT` were.
    pub dns_in_flight: AtomicU64,
    pub drop_dns_busy: AtomicU64,
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
        // At least a millisecond: two dumps at the same instant would divide by zero.
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
    /// Last connection id handed out (TUN-captured and host-port alike).
    pub last_id: AtomicU64,
    /// The full address-rewriting table, reported once in a while.
    pub(crate) table_full_logged: Throttle,
    /// accept failing, reported once in a while for all accept loops
    /// (captured and host ports) together.
    pub(crate) accept_failed_logged: Throttle,
    /// Connections refused over `MAX_RELAYS`, likewise.
    pub(crate) relays_refused_logged: Throttle,
    /// One per connection being relayed, `MAX_RELAYS` at most (fewer when the
    /// open-file limit is low: `app::relay_capacity`).
    pub relay_slots: Arc<tokio::sync::Semaphore>,
}

impl Shared {
    /// `relays` connections may be relayed at once.
    pub fn new(
        listen: SocketAddrV4,
        nat: Nat,
        pool: FakePool,
        upstream_dns: SocketAddr,
        live: Arc<Live>,
        relays: usize,
    ) -> Shared {
        Shared {
            listen,
            nat: Mutex::new(nat),
            pool,
            upstream_dns,
            live: RwLock::new(live),
            stats: Stats::default(),
            dns: DnsStats::default(),
            traffic: Traffic::default(),
            last_id: AtomicU64::new(0),
            table_full_logged: Throttle::new(),
            accept_failed_logged: Throttle::new(),
            relays_refused_logged: Throttle::new(),
            relay_slots: Arc::new(tokio::sync::Semaphore::new(relays)),
        }
    }

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

pub(crate) fn count(c: &AtomicU64, n: usize) {
    c.fetch_add(n as u64, Ordering::Relaxed);
}

/// SIGUSR1: totals since start, then rates since `prev`, the previous dump
/// (or start), for telling where the time goes without outside tools.
pub fn log_stats(sh: &Shared, prev: &mut Snapshot) {
    let (s, d) = (&sh.stats, &sh.dns);
    let n = |c: &AtomicU64| c.load(Ordering::Relaxed);
    // The counters that also get a rate; the rest are shown as totals only.
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
        dropped_dns_busy = n(&s.drop_dns_busy),
        "stats"
    );
    // This dump becomes the base of the next one's rates.
    let prev = std::mem::replace(prev, now);
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
pub(crate) mod tests {
    use super::*;
    use proxytun_core::config::Config;
    use proxytun_core::live::build_live;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    /// The (one) NAT address here, so a test can play the rewritten client.
    pub(crate) const NAT: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

    pub(crate) fn shared(listen: SocketAddrV4) -> Shared {
        let cfg = Config::parse("[proxy]\ntype=\"socks5\"\naddr=\"127.0.0.1:1\"\n").unwrap();
        Shared::new(
            listen,
            Nat::new(NAT, 1),
            FakePool::with_reserved_tail("198.18.0.0/15".parse().unwrap(), 0),
            "127.0.0.1:9".parse().unwrap(),
            Arc::new(build_live(&cfg).unwrap()),
            MAX_RELAYS,
        )
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
        tracing::subscriber::with_default(sub, || log_stats(&sh, &mut Snapshot::zero()));
        let free = free.lock().unwrap();
        assert!(!free.is_empty() && free.iter().all(|&f| f), "{free:?}");
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
