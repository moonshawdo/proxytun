//! Address-rewriting table for TCP. A program connection `src -> dst` read
//! from the TUN device is rewritten to `NAT_IP:port -> listener`, so the
//! kernel's own TCP stack terminates it on our listener; the listener's
//! replies to `NAT_IP:port` are rewritten back to `dst -> src`. The relay finds
//! the original destination by the accepted connection's peer port.
//!
//! Lifecycle of an entry:
//!   * created by the program's SYN;
//!   * `accept`ed by the relay (an entry that is never accepted is dropped
//!     after `EMBRYONIC`: SYN lost, program gave up);
//!   * `close`d when the relay is done with it, then kept for `LINGER` so the
//!     last FIN/ACKs of both kernels still get through. A new SYN on the same
//!     flow during that time gets a fresh entry: it is a new connection.
//!
//! Live connections never expire, however long they stay idle.

use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::time::{Duration, Instant};

/// How long a closed entry keeps translating stray packets. Longer than the
/// 60 s TIME_WAIT of either kernel, so a port is never reused while the
/// listener side may still hold the old connection.
pub const LINGER: Duration = Duration::from_secs(75);
/// How long a SYN may wait for the relay to accept its connection.
pub const EMBRYONIC: Duration = Duration::from_secs(60);
/// Ports handed out on NAT_IP: one per concurrent (or lingering) connection.
pub const PORTS: std::ops::RangeInclusive<u16> = 1024..=65535;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Embryonic(Instant),
    Accepted,
    Closed(Instant),
}

#[derive(Debug)]
struct Entry {
    src: SocketAddrV4,
    dst: SocketAddrV4,
    state: State,
}

pub struct Nat {
    by_flow: HashMap<(SocketAddrV4, SocketAddrV4), u16>,
    by_port: HashMap<u16, Entry>,
    next: u16,
}

impl Default for Nat {
    fn default() -> Self {
        Nat {
            by_flow: HashMap::new(),
            by_port: HashMap::new(),
            next: *PORTS.start(),
        }
    }
}

impl Nat {
    /// A packet the program sent on flow `src -> dst`: the NAT port to send it
    /// from, or `None` to drop it (not a SYN and no entry, or table full).
    pub fn outbound(&mut self, src: SocketAddrV4, dst: SocketAddrV4, syn: bool, now: Instant) -> Option<u16> {
        if let Some(&port) = self.by_flow.get(&(src, dst)) {
            let closed = matches!(self.by_port[&port].state, State::Closed(_));
            if !(syn && closed) {
                return Some(port);
            }
            self.remove(port);
        }
        if !syn {
            return None;
        }
        let port = self.free_port()?;
        self.by_flow.insert((src, dst), port);
        self.by_port.insert(
            port,
            Entry {
                src,
                dst,
                state: State::Embryonic(now),
            },
        );
        Some(port)
    }

    /// A packet the listener sent to `NAT_IP:port`: the `(src, dst)` to give it
    /// so it reaches the program from the address it dialed.
    pub fn inbound(&self, port: u16) -> Option<(SocketAddrV4, SocketAddrV4)> {
        self.by_port.get(&port).map(|e| (e.dst, e.src))
    }

    /// The relay accepted the connection from `NAT_IP:port`: where was the
    /// program going? `None` for an unknown or already closed entry.
    pub fn accept(&mut self, port: u16) -> Option<SocketAddrV4> {
        let e = self.by_port.get_mut(&port)?;
        if matches!(e.state, State::Closed(_)) {
            return None;
        }
        e.state = State::Accepted;
        Some(e.dst)
    }

    /// The relay is done with the connection from `NAT_IP:port`.
    pub fn close(&mut self, port: u16, now: Instant) {
        if let Some(e) = self.by_port.get_mut(&port) {
            e.state = State::Closed(now);
        }
    }

    /// Drop closed entries past `LINGER` and unaccepted ones past `EMBRYONIC`.
    /// Returns how many went.
    pub fn sweep(&mut self, now: Instant) -> usize {
        let stale: Vec<u16> = self
            .by_port
            .iter()
            .filter(|(_, e)| match e.state {
                State::Embryonic(t) => now.saturating_duration_since(t) >= EMBRYONIC,
                State::Closed(t) => now.saturating_duration_since(t) >= LINGER,
                State::Accepted => false,
            })
            .map(|(&p, _)| p)
            .collect();
        for &p in &stale {
            self.remove(p);
        }
        stale.len()
    }

    pub fn len(&self) -> usize {
        self.by_port.len()
    }

    fn remove(&mut self, port: u16) {
        if let Some(e) = self.by_port.remove(&port) {
            self.by_flow.remove(&(e.src, e.dst));
        }
    }

    /// Round-robin over the range, so a just-closed port is the last to be
    /// reused.
    fn free_port(&mut self) -> Option<u16> {
        let span = PORTS.len();
        for _ in 0..span {
            let p = self.next;
            self.next = if p == *PORTS.end() { *PORTS.start() } else { p + 1 };
            if !self.by_port.contains_key(&p) {
                return Some(p);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::tests::sa;

    fn flow() -> (SocketAddrV4, SocketAddrV4) {
        (sa("198.19.255.1:40000"), sa("198.18.0.5:443"))
    }

    #[test]
    fn a_connection_goes_out_and_its_replies_come_back() {
        let mut n = Nat::default();
        let t = Instant::now();
        let (src, dst) = flow();
        assert_eq!(n.outbound(src, dst, false, t), None, "no entry without a SYN");
        let port = n.outbound(src, dst, true, t).unwrap();
        assert_eq!(
            n.outbound(src, dst, true, t),
            Some(port),
            "a retransmitted SYN keeps its port"
        );
        assert_eq!(n.outbound(src, dst, false, t), Some(port));
        assert_eq!(
            n.inbound(port),
            Some((dst, src)),
            "replies come from where the program dialed"
        );
        assert_eq!(n.accept(port), Some(dst));
        assert_eq!(n.inbound(port + 1), None);
        assert_eq!(n.accept(port + 1), None, "a connection with no entry is not ours");
    }

    #[test]
    fn a_closed_entry_lingers_then_goes_and_a_new_syn_starts_over() {
        let mut n = Nat::default();
        let t = Instant::now();
        let (src, dst) = flow();
        let port = n.outbound(src, dst, true, t).unwrap();
        n.accept(port);
        n.close(port, t);
        assert_eq!(n.accept(port), None, "closed: not accepted again");
        assert_eq!(
            n.outbound(src, dst, false, t),
            Some(port),
            "late FIN/ACKs still translated"
        );
        assert_eq!(n.inbound(port), Some((dst, src)));
        assert_eq!(n.sweep(t + LINGER - Duration::from_secs(1)), 0);
        assert_eq!(n.sweep(t + LINGER), 1);
        assert_eq!((n.outbound(src, dst, false, t), n.inbound(port)), (None, None));

        // The program reuses the same 4-tuple for a new connection while the
        // old entry lingers: a fresh port, not the closed one.
        let p1 = n.outbound(src, dst, true, t).unwrap();
        n.accept(p1);
        n.close(p1, t);
        let p2 = n.outbound(src, dst, true, t).unwrap();
        assert_ne!(p1, p2);
        assert_eq!(n.accept(p2), Some(dst));
        assert_eq!(n.len(), 1, "the closed entry was replaced");
    }

    #[test]
    fn unaccepted_entries_expire_but_live_ones_never_do() {
        let mut n = Nat::default();
        let t = Instant::now();
        let embryo = n.outbound(sa("198.19.255.1:1"), sa("1.1.1.1:80"), true, t).unwrap();
        let live = n.outbound(sa("198.19.255.1:2"), sa("1.1.1.1:80"), true, t).unwrap();
        n.accept(live);
        assert_eq!(n.sweep(t + EMBRYONIC), 1);
        assert_eq!(n.inbound(embryo), None);
        assert_eq!(
            n.sweep(t + Duration::from_secs(86_400)),
            0,
            "an idle live connection stays"
        );
        assert!(n.inbound(live).is_some());
    }

    #[test]
    fn ports_rotate_and_a_full_table_refuses_new_connections() {
        let mut n = Nat::default();
        let t = Instant::now();
        let dst = sa("1.1.1.1:80");
        let total = PORTS.len();
        let mut seen = std::collections::HashSet::new();
        for i in 0..total {
            let src = SocketAddrV4::new([198, 19, (i >> 16) as u8, (i >> 8) as u8].into(), i as u16);
            let port = n.outbound(src, dst, true, t).unwrap();
            n.accept(port); // live connections: the sweep below must not free them
            assert!(seen.insert(port), "port handed out twice");
        }
        assert_eq!(n.outbound(sa("9.9.9.9:9"), dst, true, t), None, "full");
        // Free one: it is the next one out.
        let some = *seen.iter().next().unwrap();
        n.close(some, t);
        n.sweep(t + LINGER);
        assert_eq!(n.outbound(sa("9.9.9.9:9"), dst, true, t), Some(some));
    }
}
