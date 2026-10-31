//! Serving the namespace: the TUN packet loop and the sweeper of the
//! address-rewriting table.
//!
//! Every packet the program's kernel routes out of the namespace arrives on
//! the TUN device:
//!   * TCP is rewritten through the `Nat` table onto our listener, so the
//!     namespace's kernel terminates it and the relay gets a plain socket;
//!     the listener's replies are rewritten back;
//!   * UDP to port 53, whatever the address, is answered by the fake-ip DNS;
//!   * other UDP gets ICMP port unreachable (QUIC falls back to TCP);
//!   * everything else (ICMP, IPv6, fragments) is dropped.

use crate::packet::{self, Packet, PROTO_TCP, PROTO_UDP, TCP_ACK, TCP_RST, TCP_SYN};
use crate::state::{count, Shared};
use anyhow::{bail, Result};
use proxytun_core::net::dns::{self, Transport};
use proxytun_core::throttle;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::runtime::Handle;

/// At most this many DNS queries are answered at once; more are dropped,
/// and the resolver asks again. Each is a task holding a copy of the query:
/// a flood faster than the runtime answers (a resolver retrying in a loop,
/// a DNS tunnel) would otherwise pile them up without bound (on two cores,
/// 500 MB within 15 s).
pub const MAX_DNS_IN_FLIGHT: u64 = 1024;

/// One DNS query counted in `Stats::dns_in_flight`, until dropped: made
/// where it is counted, so it is counted out however its task ends (or
/// never runs).
struct Answering(Arc<Shared>);

impl Drop for Answering {
    fn drop(&mut self) {
        self.0.stats.dns_in_flight.fetch_sub(1, Ordering::Relaxed);
    }
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

/// A TCP packet: from the listener back to the program, or from the program
/// onto the listener. One hold of the table either way.
fn on_tcp(tun: &OwnedFd, sh: &Shared, pkt: &mut [u8], p: &Packet) {
    if p.src == sh.listen {
        from_listener(tun, sh, pkt, p);
    } else {
        from_program(tun, sh, pkt, p);
    }
}

/// The listener answering: back to the program, from where it dialed.
fn from_listener(tun: &OwnedFd, sh: &Shared, pkt: &mut [u8], p: &Packet) {
    let rst = p.flags & TCP_RST != 0;
    let back = {
        let mut nat = sh.nat();
        let syn_ack = (p.flags & (TCP_SYN | TCP_ACK) == TCP_SYN | TCP_ACK).then(|| packet::tcp_seq(pkt, p));
        // Only these change an entry's state: no second lookup per data packet.
        if syn_ack.is_some() || rst {
            nat.listener_sent(p.dst, syn_ack, rst, Instant::now());
        }
        nat.inbound(p.dst)
    };
    match back {
        Some((src, dst)) => {
            packet::rewrite_tcp(pkt, p, src, dst);
            write_packet(tun, sh, &pkt[..p.len]);
        }
        // Late, its entry gone: dropped, the listener left unanswered.
        None => {
            count(&sh.stats.drop_no_flow, 1);
            tracing::trace!(src = %p.src, dst = %p.dst, flags = p.flags, "tcp for no known connection, dropped");
        }
    }
}

/// The program sending: onto the listener, from the NAT address and port of
/// its entry. Its SYN makes the entry, its reset ends one not yet accepted.
/// With no entry it is answered as by a host without such a connection: a
/// SYN that found the table full gets ECONNREFUSED now rather than retrying
/// for two minutes; anything else (its connection ended here long ago)
/// ECONNRESET rather than retransmitting for a quarter of an hour.
fn from_program(tun: &OwnedFd, sh: &Shared, pkt: &mut [u8], p: &Packet) {
    let syn = p.is_syn().then(|| packet::tcp_seq(pkt, p));
    let nat = {
        let mut table = sh.nat();
        let nat = table.outbound(p.src, p.dst, syn, Instant::now());
        if p.flags & TCP_RST != 0 {
            table.program_reset(p.src, p.dst, Instant::now());
        }
        nat
    };
    match (nat, syn) {
        (Some(nat), _) => {
            if syn.is_some() {
                tracing::trace!(src = %p.src, dst = %p.dst, %nat, "syn");
            }
            packet::rewrite_tcp(pkt, p, nat, sh.listen);
            write_packet(tun, sh, &pkt[..p.len]);
        }
        (None, Some(_)) => {
            // Every retried SYN lands here (`dropped_table_full` counts them
            // all).
            if sh.table_full_logged.due() {
                tracing::error!(
                    src = %p.src, dst = %p.dst,
                    "address-rewriting table full, refusing new connections (see \
                     dropped_table_full; reported every {}s)",
                    throttle::EVERY.as_secs()
                );
            }
            if let Some(r) = packet::reset_answering(pkt, p) {
                write_packet(tun, sh, &r);
            }
            count(&sh.stats.drop_table_full, 1);
        }
        (None, None) => {
            if let Some(r) = packet::reset_answering(pkt, p) {
                write_packet(tun, sh, &r);
            }
            count(&sh.stats.drop_no_flow, 1);
            tracing::trace!(src = %p.src, dst = %p.dst, flags = p.flags, "tcp for no known connection, dropped");
        }
    }
}

fn on_dns(tun: &Arc<OwnedFd>, sh: &Arc<Shared>, rt: &Handle, pkt: &[u8], p: &Packet) {
    let counted = sh.stats.dns_in_flight.fetch_add(1, Ordering::Relaxed);
    let answering = Answering(sh.clone());
    if counted >= MAX_DNS_IN_FLIGHT {
        count(&sh.stats.drop_dns_busy, 1);
        return;
    }
    let query = packet::udp_payload(pkt, p).to_vec();
    let (client, server) = (p.src, p.dst);
    let (tun, sh) = (tun.clone(), sh.clone());
    // Forwarded queries can take seconds; never hold up the packet loop.
    rt.spawn(async move {
        let _answering = answering;
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

// ---------------------------------------------------------------- sweeper --

/// Drop table entries whose connection is long gone. Every second: what
/// expires comes in small bites (see `sweep`).
pub async fn run_sweeper(tun: Arc<OwnedFd>, sh: Arc<Shared>) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tick.tick().await;
        sweep(&tun, &sh, Instant::now()).await;
    }
}

/// Due address-rewriting entries looked at per hold of the table, which the
/// TUN thread needs for every TCP packet: about a millisecond's work.
const SWEEP_BATCH: usize = 4096;

/// Expire address-rewriting entries, and reset the programs left holding a
/// connection that was never accepted: `SWEEP_BATCH` at a time, letting the
/// TUN thread have the table in between.
async fn sweep(tun: &OwnedFd, sh: &Shared, now: Instant) {
    loop {
        let (n, done, resets) = {
            let mut nat = sh.nat();
            let (n, done) = nat.sweep_some(now, SWEEP_BATCH);
            (n, done, nat.take_resets())
        };
        if n > 0 {
            tracing::debug!(expired = n, reset = resets.len(), "swept address-rewriting entries");
        }
        for r in resets {
            tracing::debug!(program = %r.to, dst = %r.from, "never accepted: resetting the program's connection");
            write_packet(tun, sh, &packet::build_tcp_reset(r.from, r.to, r.seq, None));
        }
        if done {
            return;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::tests::sa;
    use crate::state::tests::{shared, NAT};
    use std::net::SocketAddrV4;
    use std::sync::atomic::AtomicU64;

    #[tokio::test]
    async fn a_connection_the_listener_answered_outlives_a_stalled_accept() {
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
        let nat = sh.nat().outbound(program, dst, None, Instant::now()).unwrap();
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
        let nat = sh.nat().outbound(other, dst, None, Instant::now()).unwrap();
        let mut syn_ack = crate::packet::tests::tcp(sh.listen, nat, TCP_SYN | TCP_ACK, b"");
        let p = packet::parse(&syn_ack).unwrap();
        on_tcp(&tun, &sh, &mut syn_ack, &p);
        let mut written = vec![0u8; 4096];
        let got = out.read(&mut written).unwrap(); // the rewritten SYN and SYN-ACK
        assert_eq!(got, syn.len() + syn_ack.len());
        sweep(&tun, &sh, Instant::now() + crate::nat::QUEUED).await;
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
        let nat = sh.nat().outbound(third, dst, None, Instant::now()).unwrap();
        let mut rst = crate::packet::tests::tcp(third, dst, TCP_RST, b"");
        let p = packet::parse(&rst).unwrap();
        on_tcp(&tun, &sh, &mut rst, &p);
        assert_eq!(sh.nat().accept(nat), None, "the program's reset ended it");

        // A fourth, reset by the listener before accept (its queue was full):
        // over too, or the entry would wait out its timeout for nothing.
        let fourth = crate::packet::tests::sa("198.19.255.1:40003");
        let mut syn = crate::packet::tests::tcp(fourth, dst, TCP_SYN, b"");
        let p = packet::parse(&syn).unwrap();
        on_tcp(&tun, &sh, &mut syn, &p);
        let nat = sh.nat().outbound(fourth, dst, None, Instant::now()).unwrap();
        let mut rst = crate::packet::tests::tcp(sh.listen, nat, TCP_RST, b"");
        let p = packet::parse(&rst).unwrap();
        on_tcp(&tun, &sh, &mut rst, &p);
        assert_eq!(sh.nat().accept(nat), None, "the listener's reset ended it");
    }

    #[tokio::test]
    async fn a_dns_flood_is_dropped_beyond_what_is_being_answered() {
        use std::io::Read;
        let sh = Arc::new(shared(sa("127.0.0.1:4000")));
        let (tun, mut out) = fake_tun();
        let rt = Handle::current();
        // An A query for example.com, from the program to our DNS address.
        let mut q = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        let mut pkt = packet::build_udp(sa("198.19.255.1:5353"), sa("198.19.255.53:53"), &q).unwrap();
        // As many being answered as may be: the next is dropped at once,
        // no task, no copy of it kept.
        sh.stats.dns_in_flight.store(MAX_DNS_IN_FLIGHT, Ordering::Relaxed);
        on_packet(&tun, &sh, &rt, &mut pkt);
        assert_eq!(sh.stats.drop_dns_busy.load(Ordering::Relaxed), 1);
        assert_eq!(sh.stats.dns_in_flight.load(Ordering::Relaxed), MAX_DNS_IN_FLIGHT);
        // With room again, it is answered, and leaves the count when done.
        sh.stats.dns_in_flight.store(0, Ordering::Relaxed);
        on_packet(&tun, &sh, &rt, &mut pkt);
        let mut buf = [0u8; 512];
        let deadline = Instant::now() + Duration::from_secs(5);
        let n = loop {
            match out.read(&mut buf) {
                Ok(n) if n > 0 => break n,
                _ => {
                    assert!(Instant::now() < deadline, "no answer");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        };
        assert_eq!(packet::parse(&buf[..n]).unwrap().dst, sa("198.19.255.1:5353"));
        while sh.stats.dns_in_flight.load(Ordering::Relaxed) != 0 {
            assert!(Instant::now() < deadline, "still counted as in flight");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
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
        stray[28..32].copy_from_slice(&0x0a0b_0c0du32.to_be_bytes()); // what it acknowledges
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
                nat.outbound(src, sa("1.1.1.1:80"), Some(1), Instant::now());
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
        // Out: the reset answering the stray ACK, the rewritten SYN, the ICMP
        // refusal of the datagram, and the reset refusing the SYN that found
        // the table full.
        let mut written = vec![0u8; 4096];
        let got = out.read(&mut written).unwrap();
        assert_eq!(n(&s.tun_packets_out), 4);
        assert_eq!(n(&s.tun_bytes_out), got as u64);
        let stray_reset = packet::parse(&written[..got]).unwrap();
        assert_eq!(
            (stray_reset.src, stray_reset.dst, stray_reset.flags),
            (sa("198.18.0.9:443"), sa("198.19.255.1:40000"), TCP_RST),
            "a segment of no connection is reset, not left to be retransmitted"
        );
        assert_eq!(packet::tcp_seq(&written[..got], &stray_reset), 0x0a0b_0c0d);
        let at = stray_reset.len;
        let first = packet::parse(&written[at..got]).unwrap();
        assert_eq!(
            (first.dst, *first.src.ip()),
            (listen, NAT),
            "the SYN was rewritten to the listener"
        );
        let second = packet::parse(&written[at + first.len..got]).unwrap();
        let reset_at = at + first.len + second.len;
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
}
