//! Fake-IP pool: allocates a synthetic IP per domain and lets the interceptor
//! map a synthetic IP back to its domain. This is what lets us preserve the
//! hostname all the way to the proxy.
//!
//! Lifecycle: addresses are handed out sequentially; once the range is used up,
//! the least-recently-used mapping that has no live connection is recycled,
//! but only once `REUSE_AFTER` (the TTL of our answers) has passed since it
//! was last handed out or used: until then the program may still connect to
//! it from its cache, and must not reach another name that way. Every lookup
//! refreshes recency, and `acquire` pins a mapping while a connection that was
//! resolved through it is alive (so a busy long-lived connection can never
//! have its domain pulled out from under it); pinned mappings leave the
//! recycling order until released. With nothing recyclable the pool reports
//! `PoolFull` instead of overwriting.

use ipnet::Ipv4Net;
use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// How long a mapping stays out of reach of recycling after its last use:
/// the TTL our DNS answers carry.
pub const REUSE_AFTER: Duration = Duration::from_secs(super::dns::FAKE_TTL as u64);

#[derive(Debug, PartialEq, Eq)]
pub struct PoolFull;

#[derive(Clone)]
pub struct FakePool(Arc<Mutex<Inner>>);

struct Entry {
    domain: String,
    tick: u64,
    /// When it was last handed out or used.
    used: Instant,
    active: u32,
}

struct Inner {
    base: u32,
    /// Number of usable host offsets: 1..=usable (offset 0 and the last
    /// address of the range are skipped).
    usable: u32,
    /// Next never-used offset; `> usable` means the range has been exhausted.
    next_free: u32,
    clock: u64,
    entries: HashMap<u32, Entry>,
    by_domain: HashMap<String, u32>,
    /// tick -> offset, oldest first; unpinned entries only.
    lru: BTreeMap<u64, u32>,
}

/// Pins one fake-ip mapping while a connection that used it is alive.
pub struct FakeGuard {
    pool: FakePool,
    off: u32,
}

impl std::fmt::Debug for FakeGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FakeGuard(+{})", self.off)
    }
}

impl Drop for FakeGuard {
    fn drop(&mut self) {
        let mut g = self.pool.lock();
        if let Some(e) = g.entries.get_mut(&self.off) {
            e.active = e.active.saturating_sub(1);
            if e.active == 0 {
                // Recyclable again, as the most recently used.
                g.touch(self.off, Instant::now());
            }
        }
    }
}

impl Inner {
    fn touch(&mut self, off: u32, now: Instant) {
        self.clock += 1;
        let tick = self.clock;
        if let Some(e) = self.entries.get_mut(&off) {
            self.lru.remove(&e.tick);
            e.tick = tick;
            e.used = now;
            if e.active == 0 {
                self.lru.insert(tick, off);
            }
        }
    }

    fn ip(&self, off: u32) -> Ipv4Addr {
        Ipv4Addr::from(self.base + off)
    }

    fn off_of(&self, ip: Ipv4Addr) -> Option<u32> {
        let v: u32 = ip.into();
        let off = v.checked_sub(self.base)?;
        (off >= 1 && off <= self.usable).then_some(off)
    }
}

impl FakePool {
    pub fn new(net: Ipv4Net) -> Self {
        Self::with_reserved_tail(net, 0)
    }

    /// A pool over `net` that never hands out its last `reserved` addresses
    /// (proxytun keeps the top /24 of the range for its own addresses).
    pub fn with_reserved_tail(net: Ipv4Net, reserved: u32) -> Self {
        let span = 1u64 << (32 - net.prefix_len() as u32);
        // Offsets 1..=span-2-reserved are usable (skip the network address,
        // and the broadcast address or the address below the reserved block).
        let usable = span.saturating_sub(2 + reserved as u64).min(u32::MAX as u64) as u32;
        FakePool(Arc::new(Mutex::new(Inner {
            base: net.network().into(),
            usable,
            next_free: 1,
            clock: 0,
            entries: HashMap::new(),
            by_domain: HashMap::new(),
            lru: BTreeMap::new(),
        })))
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // A poisoned lock only means another thread panicked mid-update of
        // plain maps; keep serving rather than cascading the panic.
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Allocate (or reuse) a fake IP for a domain. Names are case-insensitive.
    pub fn alloc(&self, domain: &str) -> Result<Ipv4Addr, PoolFull> {
        self.alloc_at(domain, Instant::now())
    }

    pub(crate) fn alloc_at(&self, domain: &str, now: Instant) -> Result<Ipv4Addr, PoolFull> {
        let domain = domain.to_ascii_lowercase();
        let mut g = self.lock();
        if let Some(&off) = g.by_domain.get(&domain) {
            g.touch(off, now);
            return Ok(g.ip(off));
        }

        let off = if g.next_free <= g.usable {
            let o = g.next_free;
            g.next_free += 1;
            o
        } else {
            // Recycle the oldest mapping no live connection is using, if no
            // program can still hold it from our answer.
            let (&tick, &victim) = g.lru.iter().next().ok_or(PoolFull)?;
            if now.saturating_duration_since(g.entries[&victim].used) < REUSE_AFTER {
                return Err(PoolFull);
            }
            g.lru.remove(&tick);
            let old = g.entries.remove(&victim).expect("lru entry exists");
            g.by_domain.remove(&old.domain);
            victim
        };

        g.entries.insert(
            off,
            Entry {
                domain: domain.clone(),
                tick: 0,
                used: now,
                active: 0,
            },
        );
        g.by_domain.insert(domain, off);
        g.touch(off, now);
        Ok(g.ip(off))
    }

    /// Reverse: is this IP one of ours, and if so which domain? Refreshes recency.
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<String> {
        let mut g = self.lock();
        let off = g.off_of(ip)?;
        let domain = g.entries.get(&off)?.domain.clone();
        g.touch(off, Instant::now());
        Some(domain)
    }

    /// Like `lookup`, but also pins the mapping until the guard is dropped.
    pub fn acquire(&self, ip: Ipv4Addr) -> Option<(String, FakeGuard)> {
        let mut g = self.lock();
        let off = g.off_of(ip)?;
        let e = g.entries.get_mut(&off)?;
        e.active += 1;
        let domain = e.domain.clone();
        g.touch(off, Instant::now()); // pinned: out of the recycling order
        drop(g);
        Some((
            domain,
            FakeGuard {
                pool: self.clone(),
                off,
            },
        ))
    }

    /// Does this IP fall inside the fake-ip range at all?
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let g = self.lock();
        let v: u32 = ip.into();
        v >= g.base && v - g.base <= g.usable + 1
    }

    pub fn len(&self) -> usize {
        self.lock().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(cidr: &str) -> FakePool {
        FakePool::new(cidr.parse().unwrap())
    }

    #[test]
    fn alloc_is_stable_and_case_insensitive() {
        let p = pool("198.18.0.0/15");
        let a = p.alloc("Example.COM").unwrap();
        assert_eq!(p.alloc("example.com").unwrap(), a);
        assert_eq!(p.lookup(a).as_deref(), Some("example.com"));
        assert!(p.contains(a));
    }

    #[test]
    fn distinct_domains_get_distinct_ips_inside_range() {
        let p = pool("198.18.0.0/15");
        let a = p.alloc("a.com").unwrap();
        let b = p.alloc("b.com").unwrap();
        assert_ne!(a, b);
        let net: Ipv4Net = "198.18.0.0/15".parse().unwrap();
        assert!(net.contains(&a) && net.contains(&b));
        // Network address itself is never handed out.
        assert_ne!(a, Ipv4Addr::new(198, 18, 0, 0));
    }

    #[test]
    fn lookup_of_foreign_or_unallocated_ip_is_none() {
        let p = pool("198.18.0.0/15");
        assert_eq!(p.lookup(Ipv4Addr::new(8, 8, 8, 8)), None);
        assert_eq!(p.lookup(Ipv4Addr::new(198, 18, 5, 5)), None);
        assert!(!p.contains(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn tiny_range_recycles_least_recently_used() {
        // /30 => 2 usable addresses.
        let p = pool("10.0.0.0/30");
        let t = Instant::now();
        let a = p.alloc_at("a.com", t).unwrap();
        let b = p.alloc_at("b.com", t).unwrap();
        // Touch a so b is the LRU victim.
        assert_eq!(p.lookup(a).as_deref(), Some("a.com"));
        let c = p.alloc_at("c.com", t + 2 * REUSE_AFTER).unwrap();
        assert_eq!(c, b, "oldest mapping's address is recycled");
        assert_eq!(p.lookup(c).as_deref(), Some("c.com"));
        assert_eq!(p.lookup(a).as_deref(), Some("a.com"));
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn pinned_entries_are_never_recycled() {
        let p = pool("10.0.0.0/30");
        let a = p.alloc("a.com").unwrap();
        let b = p.alloc("b.com").unwrap();
        let (_, ga) = p.acquire(a).unwrap();
        let (_, gb) = p.acquire(b).unwrap();
        let later = Instant::now() + 2 * REUSE_AFTER;
        assert_eq!(p.alloc_at("c.com", later), Err(PoolFull));
        // Releasing one pin frees exactly that slot.
        drop(ga);
        let c = p.alloc_at("c.com", later + 2 * REUSE_AFTER).unwrap();
        assert_eq!(c, a);
        drop(gb);
    }

    #[test]
    fn an_address_a_program_may_still_have_cached_goes_to_no_other_name() {
        let p = pool("10.0.0.0/30");
        let t = Instant::now();
        let a = p.alloc_at("a.com", t).unwrap();
        p.alloc_at("b.com", t).unwrap();
        // Within the TTL of our answer, a.com's address may still be in the
        // program's cache: handing it to c.com would send that traffic there.
        assert_eq!(p.alloc_at("c.com", t + REUSE_AFTER / 2), Err(PoolFull));
        // Asked again meanwhile: the clock restarts.
        p.alloc_at("a.com", t + REUSE_AFTER / 2).unwrap();
        assert_ne!(p.alloc_at("c.com", t + REUSE_AFTER).unwrap(), a, "b.com's time is up");
        assert_eq!(p.alloc_at("d.com", t + REUSE_AFTER).unwrap_err(), PoolFull);
        assert_eq!(p.alloc_at("d.com", t + 2 * REUSE_AFTER).unwrap(), a);
    }

    #[test]
    fn recycling_does_not_walk_past_pinned_entries() {
        let p = pool("10.0.0.0/22");
        let t = Instant::now();
        let ips: Vec<Ipv4Addr> = (0..1022)
            .map(|i| p.alloc_at(&format!("d{i}.test"), t).unwrap())
            .collect();
        // The oldest half pinned by live connections; they are out of the way.
        let guards: Vec<FakeGuard> = ips[..511].iter().map(|&ip| p.acquire(ip).unwrap().1).collect();
        assert_eq!(p.lock().lru.len(), 511);
        assert_eq!(p.alloc_at("new.test", t + REUSE_AFTER).unwrap(), ips[511]);
        drop(guards);
        assert_eq!(p.lock().lru.len(), 1022, "released: recyclable again");
    }

    #[test]
    fn acquire_unknown_ip_is_none() {
        let p = pool("198.18.0.0/15");
        assert!(p.acquire(Ipv4Addr::new(198, 18, 1, 1)).is_none());
    }

    #[test]
    fn range_boundaries_are_not_allocatable() {
        let p = pool("10.0.0.0/30");
        // 10.0.0.0 (network) and 10.0.0.3 (broadcast) are not usable.
        assert_eq!(p.lookup(Ipv4Addr::new(10, 0, 0, 0)), None);
        assert_eq!(p.lookup(Ipv4Addr::new(10, 0, 0, 3)), None);
        let a = p.alloc("a.com").unwrap();
        let b = p.alloc("b.com").unwrap();
        let mut got = [a, b];
        got.sort();
        assert_eq!(got, [Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)]);
    }

    #[test]
    fn concurrent_alloc_is_consistent() {
        let p = pool("198.18.0.0/15");
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let p = p.clone();
                std::thread::spawn(move || {
                    (0..200)
                        .map(|i| {
                            let name = format!("h{}.com", i % 50);
                            let ip = p.alloc(&name).unwrap();
                            (name, ip)
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let mut seen: HashMap<String, Ipv4Addr> = HashMap::new();
        for h in handles {
            for (name, ip) in h.join().unwrap() {
                let e = seen.entry(name.clone()).or_insert(ip);
                assert_eq!(*e, ip, "{name} must map to one ip");
            }
        }
        assert_eq!(p.len(), 50);
    }

    #[test]
    fn a_reserved_tail_is_never_handed_out() {
        let p = FakePool::with_reserved_tail("10.0.0.0/22".parse().unwrap(), 256);
        let ips: Vec<Ipv4Addr> = (0..766).map(|i| p.alloc(&format!("d{i}.test")).unwrap()).collect();
        assert_eq!(ips[0], Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(*ips.last().unwrap(), Ipv4Addr::new(10, 0, 2, 254));
        // Full: the next name recycles the oldest instead of entering 10.0.3.0/24.
        assert_eq!(p.alloc_at("one.more", Instant::now() + REUSE_AFTER).unwrap(), ips[0]);
        assert_eq!(p.len(), 766);
        assert_eq!(p.lookup(Ipv4Addr::new(10, 0, 3, 1)), None);
    }
}
