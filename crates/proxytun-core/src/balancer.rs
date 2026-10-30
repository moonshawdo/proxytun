//! Upstream proxy nodes, groups and load-balancing strategies.
//!
//! Selection is lock-free and O(members): it only reads atomics. A `Node`
//! tracks its own health (passive: dial results; active: the health prober),
//! live connection count and an EWMA of handshake latency.

use crate::config::{Config, ProxyCfg, Strategy};
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub struct Node {
    pub name: String,
    pub cfg: ProxyCfg,
    pub addr: SocketAddr,
    pub weight: u32,
    active: AtomicUsize,
    /// EWMA of connect+handshake latency in microseconds; 0 = never measured.
    latency_us: AtomicU64,
    fails: AtomicU32,
    healthy: AtomicBool,
    ok_total: AtomicU64,
    fail_total: AtomicU64,
}

/// Keeps a node's live-connection count accurate for `least-conn`.
pub struct ConnGuard(Arc<Node>);

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeStats {
    pub name: String,
    pub healthy: bool,
    pub active: usize,
    pub latency_us: u64,
    pub ok_total: u64,
    pub fail_total: u64,
}

impl Node {
    pub fn new(cfg: ProxyCfg) -> Result<Arc<Node>> {
        let addr = cfg.socket_addr()?;
        Ok(Arc::new(Node {
            name: cfg.name.clone(),
            weight: cfg.weight.max(1),
            addr,
            cfg,
            active: AtomicUsize::new(0),
            latency_us: AtomicU64::new(0),
            fails: AtomicU32::new(0),
            healthy: AtomicBool::new(true),
            ok_total: AtomicU64::new(0),
            fail_total: AtomicU64::new(0),
        }))
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }
    pub fn active(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }
    pub fn latency_us(&self) -> u64 {
        self.latency_us.load(Ordering::Relaxed)
    }

    pub fn acquire(self: &Arc<Self>) -> ConnGuard {
        self.active.fetch_add(1, Ordering::Relaxed);
        ConnGuard(self.clone())
    }

    /// A health probe succeeded: clear the failure streak, revive, and fold the
    /// round trip to the proxy into the latency EWMA (alpha = 0.3).
    pub fn record_success(&self, rtt: Duration) {
        let sample = (rtt.as_micros() as u64).max(1);
        let old = self.latency_us.load(Ordering::Relaxed);
        let new = if old == 0 { sample } else { (old * 7 + sample * 3) / 10 };
        self.latency_us.store(new.max(1), Ordering::Relaxed);
        self.fails.store(0, Ordering::Relaxed);
        self.healthy.store(true, Ordering::Relaxed);
        self.ok_total.fetch_add(1, Ordering::Relaxed);
    }

    /// A real connection went through this node: it is alive. No latency
    /// sample (the round trip also contains the proxy reaching the target).
    pub fn record_ok(&self) {
        self.fails.store(0, Ordering::Relaxed);
        self.healthy.store(true, Ordering::Relaxed);
        self.ok_total.fetch_add(1, Ordering::Relaxed);
    }

    /// A handshake/probe failed; after `threshold` in a row the node is down.
    pub fn record_failure(&self, threshold: u32) {
        let n = self.fails.fetch_add(1, Ordering::Relaxed) + 1;
        self.fail_total.fetch_add(1, Ordering::Relaxed);
        if n >= threshold.max(1) {
            self.healthy.store(false, Ordering::Relaxed);
        }
    }

    pub fn stats(&self) -> NodeStats {
        NodeStats {
            name: self.name.clone(),
            healthy: self.is_healthy(),
            active: self.active(),
            latency_us: self.latency_us(),
            ok_total: self.ok_total.load(Ordering::Relaxed),
            fail_total: self.fail_total.load(Ordering::Relaxed),
        }
    }
}

pub struct Group {
    pub name: String,
    pub strategy: Strategy,
    pub nodes: Vec<Arc<Node>>,
    rr: AtomicUsize,
    rng: AtomicU64,
    /// Node indices repeated by weight, for weighted-round-robin.
    schedule: Vec<usize>,
}

impl Group {
    pub fn new(name: &str, strategy: Strategy, nodes: Vec<Arc<Node>>) -> Group {
        // Interleave rather than repeat in blocks so weight 2/1 yields a,b,a
        // style spreading instead of a,a,b bursts.
        let max_w = nodes.iter().map(|n| n.weight).max().unwrap_or(1);
        let mut schedule = Vec::new();
        for round in 0..max_w {
            for (i, n) in nodes.iter().enumerate() {
                if round < n.weight {
                    schedule.push(i);
                }
            }
        }
        Group {
            name: name.to_string(),
            strategy,
            nodes,
            rr: AtomicUsize::new(0),
            rng: AtomicU64::new(0x9E37_79B9_7F4A_7C15),
            schedule,
        }
    }

    fn next_rr(&self) -> usize {
        self.rr.fetch_add(1, Ordering::Relaxed)
    }

    fn next_rand(&self) -> u64 {
        // splitmix64 over an atomic counter: cheap, lock-free, good enough
        // for spreading load (not for anything security related).
        let mut z = self.rng.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Pick a member index. `key` feeds the `hash` strategy; `exclude` lists
    /// members that already failed for this connection. Returns None when no
    /// healthy candidate is left (the caller then fails closed).
    pub fn select(&self, key: &str, exclude: &[usize]) -> Option<usize> {
        let cands: Vec<usize> = (0..self.nodes.len())
            .filter(|i| self.nodes[*i].is_healthy() && !exclude.contains(i))
            .collect();
        if cands.is_empty() {
            return None;
        }
        let pick = match self.strategy {
            Strategy::RoundRobin => cands[self.next_rr() % cands.len()],
            Strategy::Random => cands[(self.next_rand() % cands.len() as u64) as usize],
            Strategy::LeastConn => {
                // Take ONE snapshot of the counts: they change under us as other
                // connections open and close, and deriving the minimum and the
                // set of ties from separate reads can leave the tie set empty.
                let snap: Vec<(usize, usize)> = cands.iter().map(|&i| (i, self.nodes[i].active())).collect();
                let min = snap.iter().map(|&(_, a)| a).min().expect("cands is non-empty");
                let ties: Vec<usize> = snap.iter().filter(|&&(_, a)| a == min).map(|&(i, _)| i).collect();
                ties[self.next_rr() % ties.len()]
            }
            Strategy::LeastLatency => {
                let best = cands
                    .iter()
                    .copied()
                    .filter(|&i| self.nodes[i].latency_us() > 0)
                    .min_by_key(|&i| self.nodes[i].latency_us());
                match best {
                    Some(i) => i,
                    // Nothing measured yet: spread until probes report in.
                    None => cands[self.next_rr() % cands.len()],
                }
            }
            Strategy::WeightedRoundRobin => {
                let start = self.next_rr();
                let n = self.schedule.len();
                (0..n)
                    .map(|k| self.schedule[(start + k) % n])
                    .find(|i| cands.contains(i))
                    .unwrap_or(cands[0])
            }
            Strategy::Hash => {
                // Rendezvous hashing: stable per key, and when a member drops
                // out only the keys that were on it move.
                cands
                    .iter()
                    .copied()
                    .max_by_key(|&i| fnv1a(key, &self.nodes[i].name))
                    .unwrap()
            }
        };
        Some(pick)
    }
}

fn fnv1a(key: &str, salt: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in key.bytes().chain(std::iter::once(0xff)).chain(salt.bytes()) {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// All nodes and groups of one config generation.
pub struct Registry {
    pub nodes: Vec<Arc<Node>>,
    pub groups: HashMap<String, Arc<Group>>,
}

impl Registry {
    pub fn build(cfg: &Config) -> Result<Registry> {
        let mut by_name: HashMap<String, Arc<Node>> = HashMap::new();
        let mut nodes = Vec::new();
        for p in &cfg.proxies {
            let n = Node::new(p.clone())?;
            by_name.insert(n.name.clone(), n.clone());
            nodes.push(n);
        }
        let mut groups = HashMap::new();
        for g in &cfg.groups {
            let members = g
                .members
                .iter()
                .map(|m| by_name.get(m).cloned().ok_or_else(|| anyhow!("unknown proxy {m}")))
                .collect::<Result<Vec<_>>>()?;
            groups.insert(g.name.clone(), Arc::new(Group::new(&g.name, g.strategy, members)));
        }
        Ok(Registry { nodes, groups })
    }

    pub fn group(&self, name: &str) -> Option<&Arc<Group>> {
        self.groups.get(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProxyKind;

    fn node(name: &str, weight: u32) -> Arc<Node> {
        Node::new(ProxyCfg {
            name: name.into(),
            kind: ProxyKind::Socks5,
            addr: "127.0.0.1:1".into(),
            username: None,
            password: None,
            weight,
        })
        .unwrap()
    }

    fn group(strategy: Strategy, names: &[(&str, u32)]) -> Group {
        Group::new("g", strategy, names.iter().map(|(n, w)| node(n, *w)).collect())
    }

    fn picks(g: &Group, n: usize) -> Vec<usize> {
        (0..n).map(|_| g.select("k", &[]).unwrap()).collect()
    }

    #[test]
    fn round_robin_cycles_evenly() {
        let g = group(Strategy::RoundRobin, &[("a", 1), ("b", 1), ("c", 1)]);
        assert_eq!(picks(&g, 6), vec![0, 1, 2, 0, 1, 2]);
    }

    #[test]
    fn round_robin_skips_unhealthy_and_excluded() {
        let g = group(Strategy::RoundRobin, &[("a", 1), ("b", 1), ("c", 1)]);
        g.nodes[1].record_failure(1);
        for _ in 0..10 {
            let p = g.select("k", &[2]).unwrap();
            assert_eq!(p, 0);
        }
    }

    #[test]
    fn all_down_or_excluded_returns_none() {
        let g = group(Strategy::RoundRobin, &[("a", 1), ("b", 1)]);
        assert_eq!(g.select("k", &[0, 1]), None);
        g.nodes[0].record_failure(1);
        g.nodes[1].record_failure(1);
        assert_eq!(g.select("k", &[]), None, "fail closed when everything is down");
    }

    #[test]
    fn random_stays_in_candidates_and_uses_all() {
        let g = group(Strategy::Random, &[("a", 1), ("b", 1), ("c", 1)]);
        g.nodes[2].record_failure(1);
        let mut seen = [0usize; 3];
        for _ in 0..400 {
            seen[g.select("k", &[]).unwrap()] += 1;
        }
        assert_eq!(seen[2], 0, "unhealthy node never chosen");
        assert!(
            seen[0] > 100 && seen[1] > 100,
            "both healthy nodes get traffic: {seen:?}"
        );
    }

    #[test]
    fn least_conn_prefers_idle_node_and_tracks_guards() {
        let g = group(Strategy::LeastConn, &[("a", 1), ("b", 1)]);
        let _g1 = g.nodes[0].acquire();
        let _g2 = g.nodes[0].acquire();
        let g3 = g.nodes[1].acquire();
        // a has 2, b has 1 -> b
        assert_eq!(g.select("k", &[]), Some(1));
        drop(g3);
        // b has 0 -> still b
        assert_eq!(g.select("k", &[]), Some(1));
        assert_eq!(g.nodes[0].active(), 2);
        drop(_g1);
        drop(_g2);
        assert_eq!(g.nodes[0].active(), 0, "guard drop releases the count");
    }

    #[test]
    fn least_conn_ties_rotate() {
        let g = group(Strategy::LeastConn, &[("a", 1), ("b", 1)]);
        let p = picks(&g, 4);
        assert!(
            p.contains(&0) && p.contains(&1),
            "ties must not always pick the first: {p:?}"
        );
    }

    #[test]
    fn least_latency_picks_fastest_measured() {
        let g = group(Strategy::LeastLatency, &[("slow", 1), ("fast", 1), ("unknown", 1)]);
        g.nodes[0].record_success(Duration::from_millis(80));
        g.nodes[1].record_success(Duration::from_millis(5));
        for _ in 0..5 {
            assert_eq!(g.select("k", &[]), Some(1));
        }
        // If the fast one dies, the next best measured node wins.
        g.nodes[1].record_failure(1);
        assert_eq!(g.select("k", &[]), Some(0));
    }

    #[test]
    fn least_latency_with_no_samples_spreads() {
        let g = group(Strategy::LeastLatency, &[("a", 1), ("b", 1)]);
        let p = picks(&g, 4);
        assert!(p.contains(&0) && p.contains(&1));
    }

    #[test]
    fn weighted_round_robin_respects_weights() {
        let g = group(Strategy::WeightedRoundRobin, &[("a", 3), ("b", 1)]);
        let p = picks(&g, 400);
        let a = p.iter().filter(|&&i| i == 0).count();
        let b = p.iter().filter(|&&i| i == 1).count();
        assert_eq!((a, b), (300, 100));
    }

    #[test]
    fn weighted_skips_down_nodes() {
        let g = group(Strategy::WeightedRoundRobin, &[("a", 3), ("b", 1)]);
        g.nodes[0].record_failure(1);
        assert!(picks(&g, 10).iter().all(|&i| i == 1));
    }

    #[test]
    fn hash_is_sticky_per_key_and_spreads_keys() {
        let g = group(Strategy::Hash, &[("a", 1), ("b", 1), ("c", 1)]);
        let first = g.select("example.com", &[]).unwrap();
        for _ in 0..20 {
            assert_eq!(g.select("example.com", &[]), Some(first));
        }
        let distinct: std::collections::HashSet<_> = (0..100)
            .map(|i| g.select(&format!("host{i}.test"), &[]).unwrap())
            .collect();
        assert!(distinct.len() >= 2, "keys should spread over members");
    }

    #[test]
    fn hash_is_stable_when_an_unrelated_member_goes_down() {
        let g = group(Strategy::Hash, &[("a", 1), ("b", 1), ("c", 1)]);
        let keys: Vec<String> = (0..60).map(|i| format!("h{i}.test")).collect();
        let before: Vec<usize> = keys.iter().map(|k| g.select(k, &[]).unwrap()).collect();
        g.nodes[1].record_failure(1);
        for (k, b) in keys.iter().zip(&before) {
            let after = g.select(k, &[]).unwrap();
            if *b != 1 {
                assert_eq!(after, *b, "key {k} must not move when its node is healthy");
            } else {
                assert_ne!(after, 1);
            }
        }
    }

    #[test]
    fn failure_threshold_and_recovery() {
        let n = node("a", 1);
        n.record_failure(3);
        n.record_failure(3);
        assert!(n.is_healthy(), "below threshold stays healthy");
        n.record_failure(3);
        assert!(!n.is_healthy());
        n.record_success(Duration::from_millis(1));
        assert!(n.is_healthy(), "a success revives the node");
        // Success also resets the streak.
        n.record_failure(3);
        n.record_failure(3);
        assert!(n.is_healthy());
        let s = n.stats();
        assert_eq!((s.ok_total, s.fail_total), (1, 5));
    }

    #[test]
    fn latency_ewma_smooths() {
        let n = node("a", 1);
        n.record_success(Duration::from_micros(1000));
        assert_eq!(n.latency_us(), 1000, "first sample taken as is");
        n.record_success(Duration::from_micros(2000));
        assert_eq!(n.latency_us(), 1300, "0.7*1000 + 0.3*2000");
    }

    #[test]
    fn registry_builds_groups_from_config() {
        let cfg = Config::parse(
            r#"
            [[proxies]]
            name = "a"
            type = "socks5"
            addr = "127.0.0.1:1"
            [[proxies]]
            name = "b"
            type = "http"
            addr = "127.0.0.1:2"
            [[groups]]
            name = "default"
            strategy = "least-conn"
            members = ["a", "b"]
            "#,
        )
        .unwrap();
        let r = Registry::build(&cfg).unwrap();
        assert_eq!(r.nodes.len(), 2);
        let g = r.group("default").unwrap();
        assert_eq!(g.strategy, Strategy::LeastConn);
        assert!(Arc::ptr_eq(&g.nodes[0], &r.nodes[0]), "groups share node objects");
        assert!(r.group("nope").is_none());
    }

    #[test]
    fn least_conn_survives_concurrent_connection_churn() {
        // Counts change while select() runs; this used to panic with a modulo
        // by zero when the set of "least busy" nodes came out empty.
        let g = Arc::new(group(Strategy::LeastConn, &[("a", 1), ("b", 1), ("c", 1)]));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut hs = vec![];
        for _ in 0..8 {
            let (g, stop) = (g.clone(), stop.clone());
            hs.push(std::thread::spawn(move || {
                let mut held = Vec::new();
                let mut i = 0usize;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    if let Some(k) = g.select("k", &[]) {
                        held.push(g.nodes[k].acquire());
                    }
                    // release in bursts so counts swing up and down
                    if i.is_multiple_of(7) {
                        held.clear();
                    }
                    i += 1;
                }
            }));
        }
        std::thread::sleep(std::time::Duration::from_millis(400));
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for h in hs {
            h.join().expect("select must never panic under churn");
        }
    }
}
