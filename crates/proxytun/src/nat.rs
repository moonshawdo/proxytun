//! Address-rewriting table for TCP. A program connection `src -> dst` read
//! from the TUN device is rewritten to `NAT_IP:port -> listener`, so the
//! kernel's own TCP stack terminates it on our listener; the listener's
//! replies to `NAT_IP:port` are rewritten back to `dst -> src`. The relay finds
//! the original destination by the accepted connection's peer port.
//!
//! Lifecycle of an entry:
//!   * created by the program's SYN;
//!   * answered by the listener (its SYN-ACK): the connection now waits in
//!     the accept queue, however long accept takes (out of fds, say); a
//!     reset from the listener before then ends it;
//!   * `accept`ed by the relay (an entry the listener never answered is
//!     dropped after `EMBRYONIC`: SYN lost, program gave up);
//!   * `close`d when the relay is done with it, then kept for `LINGER` so the
//!     last FIN/ACKs of both kernels still get through. A new SYN on the same
//!     flow during that time gets a fresh entry: it is a new connection.
//!
//! Live connections never expire, however long they stay idle.

use std::collections::{HashMap, VecDeque};
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
    /// Answered by the listener, waiting to be accepted: dropping it would
    /// leave the program a connection nobody ever closes.
    Queued,
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
    /// Unused ports, oldest freed first: a just-closed port is the last to be
    /// reused, and finding one costs the same however full the table is (it
    /// runs on the TUN thread, under the lock).
    free: VecDeque<u16>,
}

impl Default for Nat {
    fn default() -> Self {
        Nat {
            by_flow: HashMap::new(),
            by_port: HashMap::new(),
            free: PORTS.collect(),
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
        let port = self.free.pop_front()?;
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

    /// The listener sent a packet with these flags to `NAT_IP:port`.
    pub fn listener_sent(&mut self, port: u16, syn_ack: bool, rst: bool, now: Instant) {
        let Some(e) = self.by_port.get_mut(&port) else { return };
        e.state = match e.state {
            State::Embryonic(_) | State::Queued if rst => State::Closed(now),
            State::Embryonic(_) if syn_ack => State::Queued,
            s => s,
        };
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
                State::Queued | State::Accepted => false,
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
            self.free.push_back(port);
        }
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
    fn a_connection_the_listener_answered_waits_for_accept_however_long() {
        let mut n = Nat::default();
        let t = Instant::now();
        let (src, dst) = flow();
        let port = n.outbound(src, dst, true, t).unwrap();
        n.listener_sent(port, true, false, t);
        // accept failing for minutes (no fd left): the program's side is
        // established, so the entry must stay for the relay to find.
        n.sweep(t + 10 * EMBRYONIC);
        assert_eq!(n.accept(port), Some(dst));

        // Reset by the listener before accept (it gave up on the handshake):
        // ended, and gone after LINGER.
        let other = sa("198.19.255.1:40001");
        let port = n.outbound(other, dst, true, t).unwrap();
        n.listener_sent(port, true, false, t);
        n.listener_sent(port, false, true, t);
        assert_eq!(n.accept(port), None);
        n.sweep(t + LINGER);
        assert_eq!(n.inbound(port), None);
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

    #[test]
    fn a_nearly_full_table_still_hands_out_ports_at_once() {
        let mut n = Nat::default();
        let t = Instant::now();
        let dst = sa("1.1.1.1:80");
        for i in 0..PORTS.len() - 1 {
            let src = SocketAddrV4::new([198, 19, (i >> 16) as u8, (i >> 8) as u8].into(), i as u16);
            let port = n.outbound(src, dst, true, t).unwrap();
            n.accept(port);
        }
        // One port left, reused by a flow that keeps reconnecting: each SYN
        // is on the TUN thread, holding the table, so it must not scan the
        // whole range for the one free port.
        let (src, start) = (sa("9.9.9.9:9"), Instant::now());
        for _ in 0..2000 {
            let port = n.outbound(src, dst, true, t).unwrap();
            n.close(port, t);
        }
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "took {:?}",
            start.elapsed()
        );
    }
}
