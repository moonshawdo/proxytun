//! IPv4 packets as read from and written to the TUN device: parse the headers
//! we route on, rewrite addresses/ports with checksum fix-ups, and build the
//! few packets proxytun originates (DNS replies, ICMP port unreachable).
//! Pure functions over byte slices.

use std::net::{Ipv4Addr, SocketAddrV4};

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;

const TTL: u8 = 64;

/// The parts of an IPv4 TCP/UDP packet that routing looks at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet {
    pub proto: u8,
    /// Address and port (0 for protocols without ports).
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
    /// IP header length in bytes.
    pub ihl: usize,
    /// Total length from the IP header (never more than the buffer).
    pub len: usize,
    /// TCP flags, 0 for anything else.
    pub flags: u8,
}

impl Packet {
    /// A SYN that opens a connection (not the SYN-ACK of the other side).
    pub fn is_syn(&self) -> bool {
        self.proto == PROTO_TCP && self.flags & (TCP_SYN | TCP_ACK) == TCP_SYN
    }
}

/// Parse an IPv4 packet. `None` for anything we do not route: other IP
/// versions, malformed or truncated headers, and fragments (the kernel sends
/// TCP with DF set, and a DNS query never needs fragmenting at our MTU).
pub fn parse(buf: &[u8]) -> Option<Packet> {
    if buf.len() < 20 || buf[0] >> 4 != 4 {
        return None;
    }
    let ihl = (buf[0] & 0x0f) as usize * 4;
    let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if ihl < 20 || len < ihl || len > buf.len() {
        return None;
    }
    let frag = u16::from_be_bytes([buf[6], buf[7]]);
    if frag & 0x3fff != 0 {
        return None; // MF set or a non-zero offset
    }
    let proto = buf[9];
    let src_ip = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    let dst_ip = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
    let l4 = &buf[ihl..len];
    let (sport, dport, flags) = match proto {
        PROTO_TCP if l4.len() >= 20 => (port(l4, 0), port(l4, 2), l4[13]),
        PROTO_UDP if l4.len() >= 8 => (port(l4, 0), port(l4, 2), 0),
        PROTO_TCP | PROTO_UDP => return None,
        _ => (0, 0, 0),
    };
    Some(Packet {
        proto,
        src: SocketAddrV4::new(src_ip, sport),
        dst: SocketAddrV4::new(dst_ip, dport),
        ihl,
        len,
        flags,
    })
}

fn port(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

/// The UDP payload of a packet `parse` accepted as UDP.
pub fn udp_payload<'a>(buf: &'a [u8], p: &Packet) -> &'a [u8] {
    &buf[p.ihl + 8..p.len]
}

/// Give a TCP packet new source and destination address/port, in place. The
/// IP checksum is recomputed; the TCP checksum is updated incrementally
/// (RFC 1624) for the changed pseudo-header and port fields, so the payload is
/// never re-read.
pub fn rewrite_tcp(buf: &mut [u8], p: &Packet, src: SocketAddrV4, dst: SocketAddrV4) {
    debug_assert_eq!(p.proto, PROTO_TCP);
    let mut old = [0u8; 12];
    old[..8].copy_from_slice(&buf[12..20]);
    old[8..12].copy_from_slice(&buf[p.ihl..p.ihl + 4]);

    buf[12..16].copy_from_slice(&src.ip().octets());
    buf[16..20].copy_from_slice(&dst.ip().octets());
    buf[p.ihl..p.ihl + 2].copy_from_slice(&src.port().to_be_bytes());
    buf[p.ihl + 2..p.ihl + 4].copy_from_slice(&dst.port().to_be_bytes());

    let mut new = [0u8; 12];
    new[..8].copy_from_slice(&buf[12..20]);
    new[8..12].copy_from_slice(&buf[p.ihl..p.ihl + 4]);

    let at = p.ihl + 16;
    let sum = u16::from_be_bytes([buf[at], buf[at + 1]]);
    buf[at..at + 2].copy_from_slice(&update_checksum(sum, &old, &new).to_be_bytes());
    set_ip_checksum(buf, p.ihl);
}

/// RFC 1624 eqn. 3: HC' = ~(~HC + ~m + m'), over every 16-bit word that
/// changed from `old` to `new` (both of even length).
fn update_checksum(sum: u16, old: &[u8], new: &[u8]) -> u16 {
    let mut acc = u32::from(!sum);
    for (o, n) in old.as_chunks::<2>().0.iter().zip(new.as_chunks::<2>().0) {
        acc += u32::from(!u16::from_be_bytes(*o));
        acc += u32::from(u16::from_be_bytes(*n));
    }
    !fold(acc)
}

fn fold(mut acc: u32) -> u16 {
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    acc as u16
}

/// One's-complement sum of `data` added to `acc` (not yet folded or negated).
fn sum_words(data: &[u8], mut acc: u32) -> u32 {
    let (words, rest) = data.as_chunks::<2>();
    for w in words {
        acc += u32::from(u16::from_be_bytes(*w));
    }
    if let [last] = rest {
        acc += u32::from(u16::from_be_bytes([*last, 0]));
    }
    acc
}

fn set_ip_checksum(buf: &mut [u8], ihl: usize) {
    buf[10..12].copy_from_slice(&[0, 0]);
    let c = !fold(sum_words(&buf[..ihl], 0));
    buf[10..12].copy_from_slice(&c.to_be_bytes());
}

/// Checksum of a TCP/UDP segment with its IPv4 pseudo-header.
fn l4_checksum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, segment: &[u8]) -> u16 {
    let mut acc = sum_words(&src.octets(), 0);
    acc = sum_words(&dst.octets(), acc);
    acc += u32::from(proto);
    acc += segment.len() as u32;
    !fold(sum_words(segment, acc))
}

fn ip_header(buf: &mut [u8], total: usize, proto: u8, src: Ipv4Addr, dst: Ipv4Addr) {
    buf[0] = 0x45;
    buf[1] = 0;
    buf[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    buf[4..6].copy_from_slice(&[0, 0]); // id: DF is set, so it is never used
    buf[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    buf[8] = TTL;
    buf[9] = proto;
    buf[12..16].copy_from_slice(&src.octets());
    buf[16..20].copy_from_slice(&dst.octets());
    set_ip_checksum(buf, 20);
}

/// A UDP datagram from `src` to `dst`. `None` if the payload cannot fit in
/// one IPv4 packet.
pub fn build_udp(src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8]) -> Option<Vec<u8>> {
    let total = 28 + payload.len();
    if total > u16::MAX as usize {
        return None;
    }
    let mut buf = vec![0u8; total];
    ip_header(&mut buf, total, PROTO_UDP, *src.ip(), *dst.ip());
    let udp = &mut buf[20..];
    udp[0..2].copy_from_slice(&src.port().to_be_bytes());
    udp[2..4].copy_from_slice(&dst.port().to_be_bytes());
    udp[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    udp[8..].copy_from_slice(payload);
    let c = match l4_checksum(*src.ip(), *dst.ip(), PROTO_UDP, udp) {
        0 => 0xffff, // 0 means "no checksum" in UDP
        c => c,
    };
    udp[6..8].copy_from_slice(&c.to_be_bytes());
    Some(buf)
}

/// ICMP "port unreachable" answering `orig`, sent as if from its destination:
/// the kernel matches the quoted header to the program's socket and fails it
/// with ECONNREFUSED. Quotes the IP header and the first 8 payload bytes
/// (RFC 792), which hold the UDP ports.
pub fn build_port_unreachable(orig: &[u8], p: &Packet) -> Vec<u8> {
    let quoted = &orig[..(p.ihl + 8).min(p.len)];
    let total = 20 + 8 + quoted.len();
    let mut buf = vec![0u8; total];
    ip_header(&mut buf, total, PROTO_ICMP, *p.dst.ip(), *p.src.ip());
    let icmp = &mut buf[20..];
    icmp[0] = 3; // destination unreachable
    icmp[1] = 3; // port unreachable
    icmp[8..].copy_from_slice(quoted);
    let c = !fold(sum_words(icmp, 0));
    icmp[2..4].copy_from_slice(&c.to_be_bytes());
    buf
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const TCP_FIN: u8 = 0x01;

    pub(crate) fn sa(s: &str) -> SocketAddrV4 {
        s.parse().unwrap()
    }

    /// A TCP segment with the given flags and payload and valid checksums,
    /// the way the kernel hands one to the TUN device.
    pub(crate) fn tcp(src: SocketAddrV4, dst: SocketAddrV4, flags: u8, payload: &[u8]) -> Vec<u8> {
        let total = 20 + 20 + payload.len();
        let mut b = vec![0u8; total];
        ip_header(&mut b, total, PROTO_TCP, *src.ip(), *dst.ip());
        let t = &mut b[20..];
        t[0..2].copy_from_slice(&src.port().to_be_bytes());
        t[2..4].copy_from_slice(&dst.port().to_be_bytes());
        t[4..8].copy_from_slice(&0x0102_0304u32.to_be_bytes()); // seq
        t[12] = 5 << 4; // data offset
        t[13] = flags;
        t[14..16].copy_from_slice(&65535u16.to_be_bytes());
        t[20..].copy_from_slice(payload);
        let c = l4_checksum(*src.ip(), *dst.ip(), PROTO_TCP, t);
        t[16..18].copy_from_slice(&c.to_be_bytes());
        b
    }

    /// Does the whole packet verify, the way a receiving kernel checks it?
    pub(crate) fn checksums_ok(b: &[u8]) -> bool {
        let p = parse(b).expect("parses");
        let ip_ok = fold(sum_words(&b[..p.ihl], 0)) == 0xffff;
        let seg = &b[p.ihl..p.len];
        let l4_ok = match p.proto {
            PROTO_TCP | PROTO_UDP => {
                let mut acc = sum_words(&p.src.ip().octets(), 0);
                acc = sum_words(&p.dst.ip().octets(), acc);
                acc += u32::from(p.proto) + seg.len() as u32;
                fold(sum_words(seg, acc)) == 0xffff
            }
            _ => fold(sum_words(seg, 0)) == 0xffff,
        };
        ip_ok && l4_ok
    }

    #[test]
    fn parses_tcp_and_udp_headers() {
        let b = tcp(sa("198.19.255.1:40000"), sa("198.18.0.5:443"), TCP_SYN, b"");
        let p = parse(&b).unwrap();
        assert_eq!(
            (p.proto, p.src, p.dst, p.ihl, p.len),
            (PROTO_TCP, sa("198.19.255.1:40000"), sa("198.18.0.5:443"), 20, 40)
        );
        assert!(p.is_syn());
        let synack = parse(&tcp(p.dst, p.src, TCP_SYN | TCP_ACK, b"")).unwrap();
        assert!(!synack.is_syn(), "a SYN-ACK does not open a connection");

        let u = build_udp(sa("198.19.255.1:5353"), sa("8.8.8.8:53"), b"query").unwrap();
        let p = parse(&u).unwrap();
        assert_eq!((p.proto, p.dst.port(), p.flags), (PROTO_UDP, 53, 0));
        assert_eq!(udp_payload(&u, &p), b"query");
        assert!(checksums_ok(&u));
    }

    #[test]
    fn rejects_what_we_do_not_route() {
        let good = tcp(sa("1.1.1.1:1"), sa("2.2.2.2:2"), TCP_ACK, b"data");
        assert!(parse(&good).is_some());
        assert!(parse(&good[..19]).is_none(), "short header");
        assert!(parse(&good[..30]).is_none(), "total length beyond the buffer");
        let mut v6 = good.clone();
        v6[0] = 0x60;
        assert!(parse(&v6).is_none(), "IPv6");
        let mut frag = good.clone();
        frag[6] |= 0x20; // MF
        assert!(parse(&frag).is_none(), "first fragment");
        let mut frag = good.clone();
        frag[7] = 1; // offset 8
        assert!(parse(&frag).is_none(), "later fragment");
        let mut short_tcp = good.clone();
        short_tcp[2..4].copy_from_slice(&30u16.to_be_bytes());
        assert!(parse(&short_tcp).is_none(), "TCP header cut short");
        // A trailing pad beyond the IP total length is ignored, not an error.
        let mut padded = good.clone();
        padded.extend_from_slice(&[0; 6]);
        assert_eq!(parse(&padded).unwrap().len, good.len());
    }

    #[test]
    fn rewriting_keeps_every_checksum_valid() {
        // Odd and even payload lengths, and addresses whose words carry when
        // summed: the incremental update must equal a full recomputation.
        for payload in [&b""[..], b"x", b"hello world!", &[0xff; 1001]] {
            for (s, d, ns, nd) in [
                (
                    "198.19.255.1:40000",
                    "198.18.0.5:443",
                    "198.19.255.2:1024",
                    "198.19.255.1:33333",
                ),
                (
                    "198.19.255.1:65535",
                    "255.255.255.254:65535",
                    "0.0.0.1:1",
                    "198.19.255.1:1",
                ),
                ("10.0.0.1:1", "93.184.216.34:80", "255.255.255.255:65535", "1.2.3.4:0"),
            ] {
                let mut b = tcp(sa(s), sa(d), TCP_ACK | TCP_FIN, payload);
                let p = parse(&b).unwrap();
                rewrite_tcp(&mut b, &p, sa(ns), sa(nd));
                let q = parse(&b).unwrap();
                assert_eq!((q.src, q.dst), (sa(ns), sa(nd)));
                assert!(
                    checksums_ok(&b),
                    "{s}->{d} rewritten to {ns}->{nd}, payload {}",
                    payload.len()
                );
                assert_eq!(&b[40..], payload, "payload untouched");
            }
        }
    }

    #[test]
    fn port_unreachable_quotes_the_datagram_and_comes_from_its_destination() {
        let u = build_udp(sa("198.19.255.1:51000"), sa("1.2.3.4:443"), &[7; 1200]).unwrap();
        let p = parse(&u).unwrap();
        let icmp = build_port_unreachable(&u, &p);
        let q = parse(&icmp).unwrap();
        assert_eq!(
            (q.proto, *q.src.ip(), *q.dst.ip()),
            (PROTO_ICMP, *p.dst.ip(), *p.src.ip())
        );
        assert_eq!((icmp[20], icmp[21]), (3, 3));
        assert_eq!(&icmp[28..], &u[..28], "IP header + 8 bytes (the UDP ports)");
        assert!(checksums_ok(&icmp));
    }

    #[test]
    fn oversized_udp_payload_is_refused() {
        assert!(build_udp(sa("1.1.1.1:53"), sa("2.2.2.2:1"), &vec![0; 65507]).is_some());
        assert!(build_udp(sa("1.1.1.1:53"), sa("2.2.2.2:1"), &vec![0; 65508]).is_none());
    }
}
