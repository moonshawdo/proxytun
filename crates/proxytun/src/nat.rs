//! Address-rewriting table for TCP. A program connection `src -> dst` read
//! from the TUN device is rewritten to `nat -> listener`, a NAT address and
//! port of ours, so the kernel's own TCP stack terminates it on our listener;
//! the listener's replies to `nat` are rewritten back to `dst -> src`. The
//! relay finds the original destination by the accepted connection's peer.
//!
//! Capacity: `NAT_ADDRS` addresses (the first is `Addrs::nat`) times `PORTS`.
//! A closed connection keeps its NAT address and port for `LINGER`, so this
//! also bounds the rate of new connections: about 13 700 a second, sustained.
//!
//! Lifecycle of an entry:
//!   * created by the program's SYN; a SYN on the same flow with another
//!     initial sequence number is a new connection, with an entry of its
//!     own: the old one goes on as before, for its relay and late packets;
//!   * answered by the listener (its SYN-ACK): the connection now waits in
//!     the accept queue, for `QUEUED` at most (accept stalled, out of fds;
//!     or the listener's kernel dropped it unannounced, its accept queue
//!     full): then the program, whose side is established, gets a reset
//!     rather than a connection nobody will ever serve or close, and the
//!     entry is closed (the listener may still hold the connection). A
//!     reset from either side before then ends it;
//!   * `accept`ed by the relay (an entry the listener never answered is
//!     dropped after `EMBRYONIC`: SYN lost, program gave up);
//!   * `close`d when the relay is done with it, then kept for `LINGER` so the
//!     last FIN/ACKs of both kernels still get through. A new SYN on the same
//!     flow during that time gets a fresh entry: it is a new connection.
//!
//! Live connections never expire, however long they stay idle.

use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

/// How long a closed entry keeps translating stray packets. Longer than the
/// 60 s TIME_WAIT of either kernel, so a NAT port is never reused while the
/// listener side may still hold the old connection.
pub const LINGER: Duration = Duration::from_secs(75);
/// How long a SYN may wait for the listener to answer it.
pub const EMBRYONIC: Duration = Duration::from_secs(60);
/// How long a connection the listener answered may wait to be accepted.
pub const QUEUED: Duration = Duration::from_secs(30);
/// Ports handed out on each NAT address.
pub const PORTS: std::ops::RangeInclusive<u16> = 1024..=65535;
/// NAT addresses, from `Addrs::nat` on: about a million entries in all (some
/// 200-280 MB when full).
pub const NAT_ADDRS: u8 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Embryonic(Instant),
    /// Answered by the listener, waiting to be accepted. `server_next`: the
    /// sequence number the program expects next from it, which a reset must
    /// carry to be taken.
    Queued {
        since: Instant,
        server_next: u32,
    },
    Accepted,
    Closed(Instant),
}

#[derive(Debug)]
struct Entry {
    src: SocketAddrV4,
    dst: SocketAddrV4,
    /// The program's initial sequence number: a SYN with another one opens
    /// a new connection.
    isn: u32,
    state: State,
}

/// A NAT address and port, packed: address index << 16 | port.
type Key = u32;

/// A reset to send the program: from `from` (where it dialed) to `to`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reset {
    pub from: SocketAddrV4,
    pub to: SocketAddrV4,
    pub seq: u32,
}

pub struct Nat {
    first: u32,
    addrs: u32,
    by_flow: HashMap<(SocketAddrV4, SocketAddrV4), Key>,
    by_key: HashMap<Key, Entry>,
    /// How many keys were ever handed out: those never used come first (see
    /// `take_key`), with no list of a million unused keys kept for them.
    fresh: u32,
    /// Keys given back, oldest first: a just-closed one is the last to be
    /// reused, and finding one costs the same however full the table is (it
    /// runs on the TUN thread, under the lock).
    free: VecDeque<Key>,
    /// Entries to look at when they may have expired, in deadline order (each
    /// kind has one fixed timeout): a sweep costs what expires, not what the
    /// table holds, which at a million entries would stall the TUN thread.
    embryonic: VecDeque<(Instant, Key)>,
    queued: VecDeque<(Instant, Key)>,
    closed: VecDeque<(Instant, Key)>,
    /// Resets due to programs, for `take_resets`.
    resets: Vec<Reset>,
}

impl Nat {
    /// A table over `addrs` NAT addresses from `first` on.
    pub fn new(first: Ipv4Addr, addrs: u8) -> Self {
        Nat {
            first: first.into(),
            addrs: addrs as u32,
            by_flow: HashMap::new(),
            by_key: HashMap::new(),
            fresh: 0,
            free: VecDeque::new(),
            embryonic: VecDeque::new(),
            queued: VecDeque::new(),
            closed: VecDeque::new(),
            resets: Vec::new(),
        }
    }

    fn addr(&self, key: Key) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::from(self.first + (key >> 16)), key as u16)
    }

    fn key(&self, nat: SocketAddrV4) -> Option<Key> {
        let i = u32::from(*nat.ip()).checked_sub(self.first)?;
        (i < self.addrs).then_some(i << 16 | nat.port() as u32)
    }

    /// Is `ip` one of our NAT addresses?
    pub fn is_nat(&self, ip: Ipv4Addr) -> bool {
        self.key(SocketAddrV4::new(ip, 0)).is_some()
    }

    /// A packet the program sent on flow `src -> dst` (`syn`: the sequence
    /// number of a SYN): the NAT address and port to send it from, or `None`
    /// to drop it (not a SYN and no entry, or table full).
    pub fn outbound(
        &mut self,
        src: SocketAddrV4,
        dst: SocketAddrV4,
        syn: Option<u32>,
        now: Instant,
    ) -> Option<SocketAddrV4> {
        if let Some(&key) = self.by_flow.get(&(src, dst)) {
            let e = &self.by_key[&key];
            let new = syn.is_some_and(|isn| isn != e.isn || matches!(e.state, State::Closed(_)));
            if !new {
                return Some(self.addr(key)); // a retransmitted SYN too
            }
            // A new connection on the same flow: a fresh key. The old entry
            // goes on for its relay, if any, and its late packets; reused at
            // once, the listener could still hold the old connection on it,
            // and the old relay's close would end the new one.
            self.by_flow.remove(&(src, dst));
        }
        let isn = syn?;
        let key = self.take_key()?;
        self.by_flow.insert((src, dst), key);
        self.by_key.insert(
            key,
            Entry {
                src,
                dst,
                isn,
                state: State::Embryonic(now),
            },
        );
        self.embryonic.push_back((now + EMBRYONIC, key));
        Some(self.addr(key))
    }

    /// A packet the listener sent to `nat`: the `(src, dst)` to give it so it
    /// reaches the program from the address it dialed.
    pub fn inbound(&self, nat: SocketAddrV4) -> Option<(SocketAddrV4, SocketAddrV4)> {
        self.by_key.get(&self.key(nat)?).map(|e| (e.dst, e.src))
    }

    /// The listener sent `nat` a SYN-ACK (its sequence number) or a reset.
    pub fn listener_sent(&mut self, nat: SocketAddrV4, syn_ack: Option<u32>, rst: bool, now: Instant) {
        let Some(key) = self.key(nat) else { return };
        let Some(e) = self.by_key.get_mut(&key) else { return };
        match (e.state, syn_ack) {
            (State::Embryonic(_) | State::Queued { .. }, _) if rst => {
                e.state = State::Closed(now);
                self.closed.push_back((now + LINGER, key));
            }
            (State::Embryonic(_), Some(seq)) => {
                e.state = State::Queued {
                    since: now,
                    server_next: seq.wrapping_add(1),
                };
                self.queued.push_back((now + QUEUED, key));
            }
            _ => {}
        }
    }

    /// The program reset its flow `src -> dst`. Before accept the listener's
    /// kernel drops such a half-made connection silently, so only this says
    /// it is gone.
    pub fn program_reset(&mut self, src: SocketAddrV4, dst: SocketAddrV4, now: Instant) {
        let Some(&key) = self.by_flow.get(&(src, dst)) else {
            return;
        };
        let e = self.by_key.get_mut(&key).expect("flows map to entries");
        if matches!(e.state, State::Embryonic(_) | State::Queued { .. }) {
            e.state = State::Closed(now);
            self.closed.push_back((now + LINGER, key));
        }
    }

    /// Resets the last sweeps owe programs, to write to the TUN device.
    pub fn take_resets(&mut self) -> Vec<Reset> {
        std::mem::take(&mut self.resets)
    }

    /// The relay accepted the connection from `nat`: where was the program
    /// going? `None` for an unknown or already closed entry.
    pub fn accept(&mut self, nat: SocketAddrV4) -> Option<SocketAddrV4> {
        let e = self.by_key.get_mut(&self.key(nat)?)?;
        if matches!(e.state, State::Closed(_)) {
            return None;
        }
        e.state = State::Accepted;
        Some(e.dst)
    }

    /// The relay is done with the connection from `nat`.
    pub fn close(&mut self, nat: SocketAddrV4, now: Instant) {
        let Some(key) = self.key(nat) else { return };
        if let Some(e) = self.by_key.get_mut(&key) {
            e.state = State::Closed(now);
            self.closed.push_back((now + LINGER, key));
        }
    }

    /// `sweep_some` with no limit.
    #[cfg(test)]
    pub fn sweep(&mut self, now: Instant) -> usize {
        self.sweep_some(now, usize::MAX).0
    }

    /// Drop entries past their time: unanswered ones after `EMBRYONIC`,
    /// closed ones after `LINGER`. Unaccepted ones are closed after `QUEUED`,
    /// owing the program a reset (see `take_resets`) if it still uses the
    /// flow. Looks at `budget` due items at most: the TUN thread waits for
    /// the table meanwhile, and a million expiring at once would stall it
    /// for a quarter of a second. Returns how many entries went, and whether
    /// everything due by `now` was looked at.
    pub fn sweep_some(&mut self, now: Instant, budget: usize) -> (usize, bool) {
        let up = |since: Instant, limit: Duration| now.saturating_duration_since(since) >= limit;
        let (mut gone, mut left) = (0, budget);
        for key in due(&mut self.embryonic, now, &mut left) {
            if matches!(self.state(key), Some(State::Embryonic(t)) if up(t, EMBRYONIC)) {
                self.remove(key);
                gone += 1;
            }
        }
        for key in due(&mut self.queued, now, &mut left) {
            if let Some(State::Queued { since, server_next }) = self.state(key) {
                if up(since, QUEUED) {
                    let e = self.by_key.get_mut(&key).expect("state found it");
                    if self.by_flow.get(&(e.src, e.dst)) == Some(&key) {
                        self.resets.push(Reset {
                            from: e.dst,
                            to: e.src,
                            seq: server_next,
                        });
                    }
                    e.state = State::Closed(now);
                    self.closed.push_back((now + LINGER, key));
                }
            }
        }
        // Closed again later (a second close): its own, later item ends it.
        for key in due(&mut self.closed, now, &mut left) {
            if matches!(self.state(key), Some(State::Closed(t)) if up(t, LINGER)) {
                self.remove(key);
                gone += 1;
            }
        }
        let rest = [&self.embryonic, &self.queued, &self.closed];
        (gone, rest.iter().all(|q| q.front().is_none_or(|&(t, _)| t > now)))
    }

    /// A key never used yet, else the one given back longest ago. Never-used
    /// keys go address after address for each port: consecutive connections
    /// use all addresses, not one until it runs out.
    fn take_key(&mut self) -> Option<Key> {
        if self.fresh < self.addrs * PORTS.len() as u32 {
            let (n, addrs) = (self.fresh, self.addrs);
            self.fresh += 1;
            return Some((n % addrs) << 16 | (*PORTS.start() as u32 + n / addrs));
        }
        self.free.pop_front()
    }

    fn state(&self, key: Key) -> Option<State> {
        self.by_key.get(&key).map(|e| e.state)
    }

    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    fn remove(&mut self, key: Key) {
        if let Some(e) = self.by_key.remove(&key) {
            // The flow may have moved on to a newer key since.
            if self.by_flow.get(&(e.src, e.dst)) == Some(&key) {
                self.by_flow.remove(&(e.src, e.dst));
            }
            self.free.push_back(key);
        }
    }
}

/// The keys of `queue` due by `now`, `left` at most (counted down), taken
/// off it. An item only ends an entry still in the state it was queued for
/// with its time up: one replaced or moved on since is left alone.
fn due(queue: &mut VecDeque<(Instant, Key)>, now: Instant, left: &mut usize) -> Vec<Key> {
    let mut keys = Vec::new();
    while let Some(&(t, key)) = queue.front() {
        if t > now || *left == 0 {
            break;
        }
        queue.pop_front();
        keys.push(key);
        *left -= 1;
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::tests::sa;

    fn flow() -> (SocketAddrV4, SocketAddrV4) {
        (sa("198.19.255.1:40000"), sa("198.18.0.5:443"))
    }

    const FIRST: Ipv4Addr = Ipv4Addr::new(198, 19, 255, 2);

    /// One NAT address: a table that fills in a test.
    fn one() -> Nat {
        Nat::new(FIRST, 1)
    }

    fn next(a: SocketAddrV4) -> SocketAddrV4 {
        SocketAddrV4::new(*a.ip(), a.port() + 1)
    }

    /// A distinct program-side address per `i`.
    fn program(i: usize) -> SocketAddrV4 {
        SocketAddrV4::new([198, 19, (i >> 16) as u8, (i >> 8) as u8].into(), i as u16)
    }

    #[test]
    fn a_connection_goes_out_and_its_replies_come_back() {
        let mut n = one();
        let t = Instant::now();
        let (src, dst) = flow();
        assert_eq!(n.outbound(src, dst, None, t), None, "no entry without a SYN");
        let port = n.outbound(src, dst, Some(1), t).unwrap();
        assert_eq!(
            n.outbound(src, dst, Some(1), t),
            Some(port),
            "a retransmitted SYN keeps its port"
        );
        assert_eq!(n.outbound(src, dst, None, t), Some(port));
        assert_eq!(
            n.inbound(port),
            Some((dst, src)),
            "replies come from where the program dialed"
        );
        assert_eq!(n.accept(port), Some(dst));
        assert_eq!(n.inbound(next(port)), None);
        assert_eq!(n.accept(next(port)), None, "a connection with no entry is not ours");
        assert_eq!(n.inbound(sa("10.0.0.1:1")), None, "not a NAT address at all");
    }

    #[test]
    fn a_closed_entry_lingers_then_goes_and_a_new_syn_starts_over() {
        let mut n = one();
        let t = Instant::now();
        let (src, dst) = flow();
        let port = n.outbound(src, dst, Some(1), t).unwrap();
        n.accept(port);
        n.close(port, t);
        assert_eq!(n.accept(port), None, "closed: not accepted again");
        assert_eq!(
            n.outbound(src, dst, None, t),
            Some(port),
            "late FIN/ACKs still translated"
        );
        assert_eq!(n.inbound(port), Some((dst, src)));
        assert_eq!(n.sweep(t + LINGER - Duration::from_secs(1)), 0);
        assert_eq!(n.sweep(t + LINGER), 1);
        assert_eq!((n.outbound(src, dst, None, t), n.inbound(port)), (None, None));

        // The program reuses the same 4-tuple for a new connection while the
        // old entry lingers: a fresh port, not the closed one, which lingers
        // on for its own late packets (the listener may still hold it).
        let p1 = n.outbound(src, dst, Some(1), t).unwrap();
        n.accept(p1);
        n.close(p1, t);
        let p2 = n.outbound(src, dst, Some(1), t).unwrap();
        assert_ne!(p1, p2);
        assert_eq!(n.accept(p2), Some(dst));
        assert_eq!(n.len(), 2);
        assert_eq!(n.inbound(p1), Some((dst, src)), "still translated");
        assert_eq!(n.sweep(t + LINGER), 1);
        assert_eq!(n.inbound(p1), None);
        let p3 = n.outbound(sa("198.19.255.1:40009"), dst, Some(1), t).unwrap();
        assert_ne!(p3, p1, "a just-freed port is the last to be reused");
        assert_eq!(n.outbound(src, dst, None, t), Some(p2), "the flow is the new one's");
    }

    #[test]
    fn a_connection_the_listener_answered_waits_a_while_then_the_program_is_reset() {
        let mut n = one();
        let t = Instant::now();
        let (src, dst) = flow();
        let nat = n.outbound(src, dst, Some(1), t).unwrap();
        n.listener_sent(nat, Some(5000), false, t);
        // accept stalls for a while (no fd left): the entry waits for it.
        assert_eq!(n.sweep(t + QUEUED - Duration::from_secs(1)), 0);
        assert_eq!(n.accept(nat), Some(dst));

        // Never accepted (accept stalled for good, or the listener's kernel
        // dropped it unannounced): after QUEUED it goes, and the program,
        // established on its side, is owed a reset it will take.
        let other = sa("198.19.255.1:40001");
        let nat = n.outbound(other, dst, Some(1), t).unwrap();
        n.listener_sent(nat, Some(u32::MAX), false, t);
        assert_eq!(n.sweep(t + QUEUED - Duration::from_secs(1)), 0, "not yet");
        assert!(n.take_resets().is_empty());
        n.sweep(t + QUEUED);
        assert_eq!(
            n.take_resets(),
            [Reset {
                from: dst,
                to: other,
                seq: 0
            }],
            "from where it dialed, at the SYN-ACK's sequence number + 1"
        );
        // The listener may still hold the connection: its port lingers,
        // never accepted any more.
        assert_eq!(n.accept(nat), None);
        assert_eq!(n.inbound(nat), Some((dst, other)));
        assert_eq!(n.sweep(t + QUEUED + LINGER), 1);
        assert_eq!(n.inbound(nat), None);

        // Reset by the listener before accept (it gave up on the handshake):
        // ended, and gone after LINGER, owing nothing.
        let third = sa("198.19.255.1:40002");
        let nat = n.outbound(third, dst, Some(1), t).unwrap();
        n.listener_sent(nat, Some(1), false, t);
        n.listener_sent(nat, None, true, t);
        assert_eq!(n.accept(nat), None);
        n.sweep(t + LINGER);
        assert_eq!(n.inbound(nat), None);
        assert!(n.take_resets().is_empty());
    }

    #[test]
    fn a_new_connection_on_a_busy_flow_never_shares_the_old_ones_entry() {
        // A program bound to a fixed port aborts and redials the same
        // destination while the old relay still dials out.
        let mut n = one();
        let t = Instant::now();
        let (src, dst) = flow();
        let old = n.outbound(src, dst, Some(100), t).unwrap();
        assert_eq!(n.outbound(src, dst, Some(100), t), Some(old), "the same SYN again");
        n.listener_sent(old, Some(1), false, t);
        assert_eq!(n.accept(old), Some(dst));
        let new = n.outbound(src, dst, Some(900), t).unwrap();
        assert_ne!(new, old, "another initial sequence number: another connection");
        assert_eq!(n.outbound(src, dst, None, t), Some(new), "the flow is the new one's");
        assert_eq!(n.accept(new), Some(dst));
        // The old relay finishing ends its own entry only.
        n.close(old, t);
        assert_eq!(n.sweep(t + LINGER), 1);
        assert_eq!(n.inbound(new), Some((dst, src)));
        assert_eq!(n.sweep(t + 10 * LINGER), 0, "the new one lives on");

        // Same while the old one waits to be accepted: when it times out, the
        // program, on its new connection by then, is owed nothing.
        let mut n = one();
        let old = n.outbound(src, dst, Some(100), t).unwrap();
        n.listener_sent(old, Some(1), false, t);
        let new = n.outbound(src, dst, Some(900), t).unwrap();
        assert_ne!(new, old);
        n.sweep(t + QUEUED);
        assert!(n.take_resets().is_empty());
        assert_eq!(n.accept(new), Some(dst));
    }

    #[test]
    fn a_program_that_resets_a_waiting_connection_ends_it() {
        // Closed before the handshake was done (a connect timeout, a killed
        // program): the listener's kernel drops the half-made connection
        // without a word, so the program's reset is all there is to go by.
        let mut n = one();
        let t = Instant::now();
        let (src, dst) = flow();
        let nat = n.outbound(src, dst, Some(1), t).unwrap();
        n.listener_sent(nat, Some(1), false, t);
        n.program_reset(src, dst, t);
        assert_eq!(n.accept(nat), None);
        assert_eq!(n.sweep(t + LINGER), 1);
        assert!(n.take_resets().is_empty(), "it knows already");
        // A live connection is the relay's to end.
        let nat = n.outbound(src, dst, Some(1), t).unwrap();
        n.accept(nat);
        n.program_reset(src, dst, t);
        assert_eq!(n.inbound(nat), Some((dst, src)));
        assert_eq!(n.sweep(t + 10 * LINGER), 0);
    }

    #[test]
    fn unaccepted_entries_expire_but_live_ones_never_do() {
        let mut n = one();
        let t = Instant::now();
        let embryo = n.outbound(sa("198.19.255.1:1"), sa("1.1.1.1:80"), Some(1), t).unwrap();
        let live = n.outbound(sa("198.19.255.1:2"), sa("1.1.1.1:80"), Some(1), t).unwrap();
        n.accept(live);
        assert_eq!(n.sweep(t + EMBRYONIC - Duration::from_secs(1)), 0, "not yet");
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
        let mut n = one();
        let t = Instant::now();
        let dst = sa("1.1.1.1:80");
        let total = PORTS.len();
        let mut seen = std::collections::HashSet::new();
        for i in 0..total {
            let port = n.outbound(program(i), dst, Some(1), t).unwrap();
            n.accept(port); // live connections: the sweep below must not free them
            assert!(seen.insert(port), "port handed out twice");
        }
        assert_eq!(n.outbound(sa("9.9.9.9:9"), dst, Some(1), t), None, "full");
        // Free one: it is the next one out.
        let some = *seen.iter().next().unwrap();
        n.close(some, t);
        n.sweep(t + LINGER);
        assert_eq!(n.outbound(sa("9.9.9.9:9"), dst, Some(1), t), Some(some));
    }

    #[test]
    fn a_nearly_full_table_still_hands_out_ports_at_once() {
        let mut n = one();
        let t = Instant::now();
        let dst = sa("1.1.1.1:80");
        for i in 0..PORTS.len() - 1 {
            let port = n.outbound(program(i), dst, Some(1), t).unwrap();
            n.accept(port);
        }
        // One port left, reused by a flow that keeps reconnecting (each time
        // after the old connection's LINGER): each SYN is on the TUN thread,
        // holding the table, so it must not scan the whole range for the one
        // free port.
        let (src, start) = (sa("9.9.9.9:9"), Instant::now());
        for i in 0..2000 {
            let at = t + i * LINGER;
            let nat = n.outbound(src, dst, Some(1), at).unwrap();
            n.close(nat, at);
            n.sweep(at + LINGER);
        }
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn every_nat_address_adds_a_full_set_of_ports() {
        let mut n = Nat::new(FIRST, 2);
        let t = Instant::now();
        let dst = sa("1.1.1.1:80");
        // Taken in turn, so every address is in use from the start.
        let (a, b) = (
            n.outbound(program(0), dst, Some(1), t).unwrap(),
            n.outbound(program(1), dst, Some(1), t).unwrap(),
        );
        assert_ne!(a.ip(), b.ip());
        let mut n = Nat::new(FIRST, 2);
        let mut seen = std::collections::HashSet::new();
        for i in 0..2 * PORTS.len() {
            let nat = n.outbound(program(i), dst, Some(1), t).unwrap();
            assert!(seen.insert(nat), "{nat} handed out twice");
            assert!(n.is_nat(*nat.ip()));
        }
        let ips: std::collections::HashSet<Ipv4Addr> = seen.iter().map(|a| *a.ip()).collect();
        assert_eq!(ips.len(), 2, "both addresses in use");
        assert_eq!(n.outbound(sa("9.9.9.9:9"), dst, Some(1), t), None, "full");
        assert!(!n.is_nat(Ipv4Addr::new(198, 19, 255, 4)), "past the last NAT address");
    }

    #[test]
    fn a_sweep_costs_what_expires_not_what_the_table_holds() {
        let mut n = Nat::new(FIRST, 2);
        let t = Instant::now();
        let dst = sa("1.1.1.1:80");
        for i in 0..2 * PORTS.len() {
            let nat = n.outbound(program(i), dst, Some(1), t).unwrap();
            n.accept(nat); // live: never expires
        }
        n.sweep(t + EMBRYONIC); // the creations' own checks, once
                                // Every 5 s on the TUN thread, holding the table: walking 129 000
                                // entries each time would stall every packet meanwhile.
        let start = Instant::now();
        for k in 0..100 {
            assert_eq!(n.sweep(t + EMBRYONIC + Duration::from_secs(k)), 0);
        }
        assert!(
            start.elapsed() < Duration::from_millis(50),
            "took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn a_sweep_takes_what_is_due_a_batch_at_a_time() {
        let mut n = one();
        let t = Instant::now();
        let dst = sa("1.1.1.1:80");
        for i in 0..10 {
            n.outbound(program(i), dst, Some(1), t).unwrap();
        }
        // Ten unanswered SYNs expire together: four at a time.
        assert_eq!(n.sweep_some(t + EMBRYONIC, 4), (4, false));
        assert_eq!(n.sweep_some(t + EMBRYONIC, 4), (4, false));
        assert_eq!(n.sweep_some(t + EMBRYONIC, 4), (2, true));
        assert_eq!(n.len(), 0);
        assert_eq!(n.sweep_some(t + EMBRYONIC, 4), (0, true), "nothing left");
    }

    #[test]
    fn a_new_table_keeps_no_list_of_unused_ports() {
        // A million keys at hand, none of them listed up front.
        let n = Nat::new(FIRST, NAT_ADDRS);
        assert!(n.free.capacity() < 1024, "{}", n.free.capacity());
    }
}
