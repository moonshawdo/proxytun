//! Fake-IP pool: allocates a synthetic IP per domain and lets the interceptor
//! map a synthetic IP back to its domain. This is what lets us preserve the
//! hostname all the way to the proxy.
//!
//! Lifecycle: addresses are handed out sequentially; once the range is used up,
//! the least-recently-used mapping that has no live connection is recycled.
//! Every lookup refreshes recency, and `acquire` pins a mapping while a
//! connection that was resolved through it is alive (so a busy long-lived
//! connection can never have its domain pulled out from under it). If every
//! entry is pinned the pool reports `PoolFull` instead of overwriting.

use ipnet::Ipv4Net;
use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Debug, PartialEq, Eq)]
pub struct PoolFull;

#[derive(Clone)]
pub struct FakePool(Arc<Mutex<Inner>>);

struct Entry {
    domain: String,
    tick: u64,
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
    /// tick -> offset, oldest first.
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
        }
    }
}

impl Inner {
    fn touch(&mut self, off: u32) {
        self.clock += 1;
        let now = self.clock;
        if let Some(e) = self.entries.get_mut(&off) {
            self.lru.remove(&e.tick);
            e.tick = now;
            self.lru.insert(now, off);
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
        let domain = domain.to_ascii_lowercase();
        let mut g = self.lock();
        if let Some(&off) = g.by_domain.get(&domain) {
            g.touch(off);
            return Ok(g.ip(off));
        }

        let off = if g.next_free <= g.usable {
            let o = g.next_free;
            g.next_free += 1;
            o
        } else {
            // Recycle the oldest mapping that no live connection is using.
            let victim = g
                .lru
                .iter()
                .map(|(_, &off)| off)
                .find(|off| g.entries[off].active == 0)
                .ok_or(PoolFull)?;
            let old = g.entries.remove(&victim).expect("lru entry exists");
            g.lru.remove(&old.tick);
            g.by_domain.remove(&old.domain);
            victim
        };

        g.entries.insert(
            off,
            Entry {
                domain: domain.clone(),
                tick: 0,
                active: 0,
            },
        );
        g.by_domain.insert(domain, off);
        g.touch(off);
        Ok(g.ip(off))
    }

    /// Reverse: is this IP one of ours, and if so which domain? Refreshes recency.
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<String> {
        let mut g = self.lock();
        let off = g.off_of(ip)?;
        let domain = g.entries.get(&off)?.domain.clone();
        g.touch(off);
        Some(domain)
    }

    /// Like `lookup`, but also pins the mapping until the guard is dropped.
    pub fn acquire(&self, ip: Ipv4Addr) -> Option<(String, FakeGuard)> {
        let mut g = self.lock();
        let off = g.off_of(ip)?;
        let e = g.entries.get_mut(&off)?;
        e.active += 1;
        let domain = e.domain.clone();
        g.touch(off);
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
        let a = p.alloc("a.com").unwrap();
        let b = p.alloc("b.com").unwrap();
        // Touch a so b is the LRU victim.
        assert_eq!(p.lookup(a).as_deref(), Some("a.com"));
        let c = p.alloc("c.com").unwrap();
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
        assert_eq!(p.alloc("c.com"), Err(PoolFull));
        // Releasing one pin frees exactly that slot.
        drop(ga);
        let c = p.alloc("c.com").unwrap();
        assert_eq!(c, a);
        drop(gb);
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
        assert_eq!(p.alloc("one.more").unwrap(), ips[0]);
        assert_eq!(p.len(), 766);
        assert_eq!(p.lookup(Ipv4Addr::new(10, 0, 3, 1)), None);
    }
}
