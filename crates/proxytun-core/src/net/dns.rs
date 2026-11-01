//! Fake-ip DNS answers, plus forwarding of everything we do not answer.
//!
//! - A queries    -> allocate a fake IP, answer with a 60s TTL.
//! - AAAA, HTTPS (65) and SVCB (64) queries -> answer NOERROR/empty to push the program back to IPv4
//!   (so our fake-ip-over-v4 path is used).
//! - localhost    -> 127.0.0.1, never a fake IP.
//! - everything else (MX/TXT/PTR/non-IN class...) -> forward to the real
//!   upstream so the program keeps working.
//! - pool exhausted -> SERVFAIL (fail closed; never reuse a pinned mapping).
//!
//! There is no listening server here: queries arrive as captured packets
//! (UDP, see `respond`) or captured connections to port 53 (TCP, `serve_tcp`).

use crate::net::fakeip::{FakePool, FAKE_TTL};
use anyhow::{anyhow, ensure, Context, Result};
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{rdata, DNSClass, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;

/// What the DNS side has done, for the stats, and how much it may do at once.
pub struct DnsStats {
    pub queries: AtomicU64,
    /// Queries sent to the upstream resolver and answered by it.
    pub forwarded: AtomicU64,
    /// Queries the upstream resolver did not answer (in time).
    pub forward_failed: AtomicU64,
    /// Forwards in flight: each holds a socket and a buffer for up to
    /// `FORWARD_TIMEOUT`, and a program retrying lookups against a silent
    /// upstream must not pile them up without bound.
    pub upstream_slots: tokio::sync::Semaphore,
}

/// At most this many queries are forwarded at once; more are dropped (the
/// program's resolver retries).
pub const MAX_FORWARDS: usize = 256;

impl Default for DnsStats {
    fn default() -> Self {
        DnsStats {
            queries: AtomicU64::new(0),
            forwarded: AtomicU64::new(0),
            forward_failed: AtomicU64::new(0),
            upstream_slots: tokio::sync::Semaphore::new(MAX_FORWARDS),
        }
    }
}

/// What to do with a query after local processing.
#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    /// A complete wire-format reply.
    Reply(Vec<u8>),
    /// Not ours to answer; relay verbatim to the upstream resolver.
    Forward,
}

/// Pure query handling: no sockets, fully unit-testable. `None` = unparseable
/// input that should be dropped silently.
pub fn answer(raw: &[u8], pool: &FakePool) -> Option<Answer> {
    let req = Message::from_bytes(raw).ok()?;
    if req.message_type() != MessageType::Query {
        return None;
    }
    let q = req.queries().first()?.clone();
    if q.query_class() != DNSClass::IN {
        return Some(Answer::Forward);
    }
    let name = q.name().clone();

    match q.query_type() {
        // The root has no address; a fake one would name nothing a proxy can
        // be asked for.
        RecordType::A if name.is_root() => reply(base_response(&req, ResponseCode::NoError)),
        RecordType::A => {
            // ASCII (punycode, "xn--...") form: that is what proxies, rules and
            // the TLS SNI use. to_utf8() would decode IDNs and send UTF-8 bytes
            // onward. Built for A queries only: escaping a long binary name
            // costs, and a flood of other queries needs none of it.
            let domain = name.to_ascii();
            let domain = domain.trim_end_matches('.').to_ascii_lowercase();
            let ip = if domain == "localhost" || domain.ends_with(".localhost") {
                Ipv4Addr::LOCALHOST
            } else {
                match pool.alloc(&domain) {
                    Ok(ip) => {
                        tracing::debug!(%domain, %ip, "dns: A -> fake ip");
                        ip
                    }
                    Err(_) => {
                        // Once in a while: resolvers retry, at query rate.
                        static LOGGED: crate::throttle::Throttle = crate::throttle::Throttle::new();
                        if LOGGED.due() {
                            tracing::error!(
                                %domain,
                                "fake-ip pool exhausted, answering SERVFAIL (repeats within {}s not logged)",
                                crate::throttle::EVERY.as_secs()
                            );
                        }
                        return reply(base_response(&req, ResponseCode::ServFail));
                    }
                }
            };
            let mut resp = base_response(&req, ResponseCode::NoError);
            resp.add_answer(Record::from_rdata(name, FAKE_TTL, RData::A(rdata::A(ip))));
            reply(resp)
        }
        // Empty NOERROR -> the program falls back to the A record (our fake v4).
        // HTTPS/SVCB (types 65/64) get the same treatment (mihomo's
        // `disable-qtype-65`): their answers carry real IP hints and ECH keys
        // that would let a browser skip the fake IP, and forwarding them
        // upstream would leak the lookup outside the proxy.
        RecordType::AAAA | RecordType::HTTPS | RecordType::SVCB => {
            tracing::debug!(domain = %name, qtype = %q.query_type(), "dns: answered empty");
            reply(base_response(&req, ResponseCode::NoError))
        }
        _ => {
            tracing::debug!(domain = %name, qtype = %q.query_type(), "dns: forwarding upstream");
            Some(Answer::Forward)
        }
    }
}

fn reply(msg: Message) -> Option<Answer> {
    msg.to_bytes().ok().map(Answer::Reply)
}

fn base_response(req: &Message, code: ResponseCode) -> Message {
    let mut resp = Message::new();
    resp.set_id(req.id());
    resp.set_message_type(MessageType::Response);
    resp.set_op_code(req.op_code());
    resp.set_recursion_desired(req.recursion_desired());
    resp.set_recursion_available(true);
    resp.set_response_code(code);
    for q in req.queries() {
        resp.add_query(q.clone());
    }
    resp
}

/// How long a DNS-over-TCP client may stay silent mid-query or between queries.
pub const TCP_IDLE: Duration = Duration::from_secs(5);

/// Serve DNS over one TCP connection: 2-byte length prefix, possibly several
/// queries. Returns when the client closes, misbehaves, or stays silent (or
/// stops reading its answers) for `TCP_IDLE`.
pub async fn serve_tcp<S>(mut stream: S, pool: &FakePool, upstream: SocketAddr, stats: &DnsStats)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Every read and write has a deadline: a client that sends a length and
    // then nothing, or never reads, must not keep the task forever.
    loop {
        let mut lenbuf = [0u8; 2];
        let read = tokio::time::timeout(TCP_IDLE, stream.read_exact(&mut lenbuf)).await;
        if !matches!(read, Ok(Ok(_))) {
            return;
        }
        let mut q = vec![0u8; u16::from_be_bytes(lenbuf) as usize];
        if !matches!(
            tokio::time::timeout(TCP_IDLE, stream.read_exact(&mut q)).await,
            Ok(Ok(_))
        ) {
            return;
        }
        let Some(resp) = respond(&q, pool, upstream, Transport::Tcp, stats).await else {
            return;
        };
        if !matches!(
            tokio::time::timeout(TCP_IDLE, stream.write_all(&tcp_framed(&resp))).await,
            Ok(Ok(()))
        ) {
            return;
        }
    }
}

/// A message as DNS over TCP sends it: a 2-byte length, then the message, in
/// one write.
fn tcp_framed(msg: &[u8]) -> Vec<u8> {
    let mut out = (msg.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(msg);
    out
}

/// How the query reached us; forwarded queries go upstream the same way, so a
/// TCP client (usually retrying a truncated UDP answer) gets a full TCP answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

/// Answer one query: locally when we can, else by forwarding it upstream over
/// the same transport. `None` = drop it (unparseable, or no upstream answer).
pub async fn respond(
    raw: &[u8],
    pool: &FakePool,
    upstream: SocketAddr,
    via: Transport,
    stats: &DnsStats,
) -> Option<Vec<u8>> {
    stats.queries.fetch_add(1, Ordering::Relaxed);
    match answer(raw, pool)? {
        Answer::Reply(r) => Some(r),
        Answer::Forward => {
            let Ok(_slot) = stats.upstream_slots.try_acquire() else {
                tracing::debug!(%upstream, "dns: {MAX_FORWARDS} queries already forwarded and waiting, dropping one");
                return None;
            };
            let t0 = Instant::now();
            let r = match via {
                Transport::Udp => forward_udp(raw, upstream).await,
                Transport::Tcp => forward_tcp(raw, upstream).await,
            };
            let ms = t0.elapsed().as_millis() as u64;
            match r {
                Ok(r) => {
                    stats.forwarded.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(%upstream, ?via, ms, "dns: upstream answered");
                    Some(r)
                }
                // Our own shortage (no fd for a socket): not the upstream's
                // doing, and no reason to doubt upstream_dns.
                Err(e) if crate::errno::is_local_shortage(&e) => {
                    tracing::debug!(%upstream, ?via, "dns: cannot forward for lack of local resources: {e:#}");
                    None
                }
                Err(e) => {
                    if stats.forward_failed.fetch_add(1, Ordering::Relaxed) == 0 {
                        tracing::warn!(
                            %upstream, ?via, ms,
                            "dns: the upstream resolver did not answer ({e:#}); MX/TXT/PTR and other non-A \
                             lookups fail (check upstream_dns). Later failures are logged at debug"
                        );
                    } else {
                        tracing::debug!(%upstream, ?via, ms, "dns: upstream did not answer: {e:#}");
                    }
                    None
                }
            }
        }
    }
}

const FORWARD_TIMEOUT: Duration = Duration::from_secs(3);

/// Is `resp` the answer to `query`? Same transaction ID, a response, and the
/// same question section. Anything else is a stray or forged packet.
///
/// Only the header and the question are looked at, never the rest: a reply we
/// cannot fully parse (a truncated TC=1 reply cut mid-record) must still reach
/// the client, or it never learns to retry over TCP. An error reply (FORMERR,
/// NOTIMP, REFUSED, ...) may carry no question; one is accepted on the ID
/// alone, since forging it can only fail a lookup, not poison it.
pub fn is_reply_to(query: &[u8], resp: &[u8]) -> bool {
    if query.len() < 12 || resp.len() < 12 || query[..2] != resp[..2] || resp[2] & 0x80 == 0 {
        return false;
    }
    let qdcount = |m: &[u8]| u16::from_be_bytes([m[4], m[5]]);
    if qdcount(resp) == 0 {
        return resp[3] & 0x0f != 0; // RCODE
    }
    qdcount(resp) == qdcount(query) && same_questions(query, resp, qdcount(query))
}

/// Compare the question sections (from offset 12) of two messages. Names
/// compare case-insensitively: resolvers may randomise the case of a query
/// (DNS 0x20) and servers echo it, but not all do. A question is the first
/// thing in a message, so it never holds a compression pointer.
fn same_questions(q: &[u8], r: &[u8], count: u16) -> bool {
    let mut i = 12;
    for _ in 0..count {
        loop {
            let (Some(&len), Some(&rlen)) = (q.get(i), r.get(i)) else {
                return false;
            };
            if len != rlen || len & 0xC0 != 0 {
                return false;
            }
            i += 1;
            if len == 0 {
                break;
            }
            let end = i + len as usize;
            let (Some(a), Some(b)) = (q.get(i..end), r.get(i..end)) else {
                return false;
            };
            if !a.eq_ignore_ascii_case(b) {
                return false;
            }
            i = end;
        }
        // QTYPE and QCLASS
        let (a, b) = (q.get(i..i + 4), r.get(i..i + 4));
        if a.is_none() || a != b {
            return false;
        }
        i += 4;
    }
    true
}

/// Forward over UDP. The socket is CONNECTED to the upstream, so the kernel
/// drops datagrams from any other address (another local user, or a blind
/// spoofer, aiming at our ephemeral port), and the reply must also match the
/// query's ID and question.
async fn forward_udp(raw: &[u8], upstream: SocketAddr) -> Result<Vec<u8>> {
    let bind = if upstream.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = UdpSocket::bind(bind).await.context("open a socket")?;
    sock.connect(upstream).await.context("connect")?;
    sock.send(raw).await.context("send")?;
    let deadline = tokio::time::Instant::now() + FORWARD_TIMEOUT;
    // Room for the largest datagram, not zero-filled: recv_buf writes into the
    // spare capacity.
    let mut buf = Vec::with_capacity(65535);
    loop {
        buf.clear();
        tokio::time::timeout_at(deadline, sock.recv_buf(&mut buf))
            .await
            .map_err(|_| anyhow!("no answer within {}s", FORWARD_TIMEOUT.as_secs()))?
            .context("receive")?;
        if is_reply_to(raw, &buf) {
            return Ok(buf);
        }
        tracing::debug!(%upstream, "dns: ignoring a datagram that does not answer our query");
    }
}

/// Forward over TCP (2-byte length prefix), with the same reply check.
async fn forward_tcp(raw: &[u8], upstream: SocketAddr) -> Result<Vec<u8>> {
    let work = async {
        let mut s = tokio::net::TcpStream::connect(upstream).await.context("connect")?;
        s.write_all(&tcp_framed(raw)).await.context("send")?;
        let mut l = [0u8; 2];
        s.read_exact(&mut l).await.context("receive")?;
        let mut body = vec![0u8; u16::from_be_bytes(l) as usize];
        s.read_exact(&mut body).await.context("receive")?;
        ensure!(is_reply_to(raw, &body), "not an answer to the query");
        Ok(body)
    };
    tokio::time::timeout(FORWARD_TIMEOUT, work)
        .await
        .map_err(|_| anyhow!("no answer within {}s", FORWARD_TIMEOUT.as_secs()))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{OpCode, Query};
    use hickory_proto::rr::Name;
    use std::str::FromStr;
    use tokio::net::TcpListener;

    fn pool() -> FakePool {
        FakePool::new("198.18.0.0/15".parse().unwrap())
    }

    fn query(name: &str, ty: RecordType, class: DNSClass) -> Vec<u8> {
        let mut m = Message::new();
        m.set_id(0xBEEF);
        m.set_message_type(MessageType::Query);
        m.set_op_code(OpCode::Query);
        m.set_recursion_desired(true);
        let mut q = Query::query(Name::from_str(name).unwrap(), ty);
        q.set_query_class(class);
        m.add_query(q);
        m.to_bytes().unwrap()
    }

    fn parse(a: Answer) -> Message {
        match a {
            Answer::Reply(b) => Message::from_bytes(&b).unwrap(),
            Answer::Forward => panic!("expected a local reply"),
        }
    }

    fn a_ips(m: &Message) -> Vec<Ipv4Addr> {
        m.answers()
            .iter()
            .filter_map(|r| match r.data() {
                Some(RData::A(a)) => Some(a.0),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_query_gets_fake_ip_and_is_remembered() {
        let p = pool();
        let m = parse(answer(&query("Example.com.", RecordType::A, DNSClass::IN), &p).unwrap());
        assert_eq!(m.id(), 0xBEEF);
        assert_eq!(m.response_code(), ResponseCode::NoError);
        let ips = a_ips(&m);
        assert_eq!(ips.len(), 1);
        assert!(p.contains(ips[0]));
        assert_eq!(p.lookup(ips[0]).as_deref(), Some("example.com"));
        assert_eq!(m.answers()[0].ttl(), FAKE_TTL);
        assert_eq!(m.queries().len(), 1, "question is echoed");

        // Same name again -> same address.
        let m2 = parse(answer(&query("example.com.", RecordType::A, DNSClass::IN), &p).unwrap());
        assert_eq!(a_ips(&m2), ips);
    }

    #[test]
    fn aaaa_is_empty_noerror() {
        let p = pool();
        let m = parse(answer(&query("example.com.", RecordType::AAAA, DNSClass::IN), &p).unwrap());
        assert_eq!(m.response_code(), ResponseCode::NoError);
        assert!(m.answers().is_empty());
        assert!(p.is_empty(), "AAAA must not consume fake ips");
    }

    #[test]
    fn localhost_is_never_faked() {
        let p = pool();
        for n in ["localhost.", "foo.localhost."] {
            let m = parse(answer(&query(n, RecordType::A, DNSClass::IN), &p).unwrap());
            assert_eq!(a_ips(&m), vec![Ipv4Addr::LOCALHOST]);
        }
        assert!(p.is_empty());
    }

    #[test]
    fn https_and_svcb_records_are_answered_empty_not_forwarded() {
        let p = pool();
        for ty in [RecordType::HTTPS, RecordType::SVCB] {
            let m = parse(answer(&query("example.com.", ty, DNSClass::IN), &p).unwrap());
            assert_eq!(m.response_code(), ResponseCode::NoError, "{ty:?}");
            assert!(
                m.answers().is_empty(),
                "{ty:?}: no ECH keys or IP hints may reach the program"
            );
        }
        assert!(p.is_empty());
    }

    #[test]
    fn other_types_and_classes_are_forwarded() {
        let p = pool();
        for ty in [RecordType::MX, RecordType::TXT, RecordType::PTR, RecordType::SRV] {
            assert_eq!(
                answer(&query("example.com.", ty, DNSClass::IN), &p),
                Some(Answer::Forward)
            );
        }
        assert_eq!(
            answer(&query("version.bind.", RecordType::A, DNSClass::CH), &p),
            Some(Answer::Forward)
        );
    }

    #[test]
    fn exhausted_pool_answers_servfail() {
        let p = FakePool::new("10.0.0.0/30".parse().unwrap());
        let pins: Vec<_> = ["a.com.", "b.com."]
            .iter()
            .map(|n| {
                let m = parse(answer(&query(n, RecordType::A, DNSClass::IN), &p).unwrap());
                p.acquire(a_ips(&m)[0]).unwrap()
            })
            .collect();
        let m = parse(answer(&query("c.com.", RecordType::A, DNSClass::IN), &p).unwrap());
        assert_eq!(m.response_code(), ResponseCode::ServFail);
        assert!(a_ips(&m).is_empty());
        drop(pins);
    }

    #[test]
    fn garbage_and_non_queries_are_dropped() {
        let p = pool();
        assert_eq!(answer(&[], &p), None);
        assert_eq!(answer(&[1, 2, 3], &p), None);
        assert_eq!(answer(&[0xff; 64], &p), None);
        // A response packet is not a query.
        let mut m = Message::new();
        m.set_message_type(MessageType::Response);
        m.add_query(Query::query(Name::from_str("a.com.").unwrap(), RecordType::A));
        assert_eq!(answer(&m.to_bytes().unwrap(), &p), None);
        // A query with no question section.
        let mut m = Message::new();
        m.set_message_type(MessageType::Query);
        assert_eq!(answer(&m.to_bytes().unwrap(), &p), None);
    }

    /// A TCP DNS endpoint the way proxytun runs one: every captured
    /// connection to port 53 is served by `serve_tcp` in its own task.
    async fn tcp_dns(p: FakePool) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (s, _) = l.accept().await.unwrap();
                let p = p.clone();
                tokio::spawn(
                    async move { serve_tcp(s, &p, "127.0.0.1:9".parse().unwrap(), &DnsStats::default()).await },
                );
            }
        });
        addr
    }

    #[tokio::test]
    async fn udp_and_tcp_queries_share_one_pool() {
        let p = pool();
        let addr = tcp_dns(p.clone()).await;
        let q = query("served.example.", RecordType::A, DNSClass::IN);

        let udp = respond(
            &q,
            &p,
            "127.0.0.1:9".parse().unwrap(),
            Transport::Udp,
            &DnsStats::default(),
        )
        .await
        .unwrap();
        let udp_ip = a_ips(&Message::from_bytes(&udp).unwrap())[0];

        let mut t = tokio::net::TcpStream::connect(addr).await.unwrap();
        t.write_all(&(q.len() as u16).to_be_bytes()).await.unwrap();
        t.write_all(&q).await.unwrap();
        let mut l = [0u8; 2];
        t.read_exact(&mut l).await.unwrap();
        let mut body = vec![0u8; u16::from_be_bytes(l) as usize];
        t.read_exact(&mut body).await.unwrap();
        let tcp_ip = a_ips(&Message::from_bytes(&body).unwrap())[0];
        assert_eq!(udp_ip, tcp_ip);

        // A second pipelined query on the same TCP connection works too.
        let q2 = query("second.example.", RecordType::A, DNSClass::IN);
        t.write_all(&(q2.len() as u16).to_be_bytes()).await.unwrap();
        t.write_all(&q2).await.unwrap();
        t.read_exact(&mut l).await.unwrap();
        let mut body = vec![0u8; u16::from_be_bytes(l) as usize];
        t.read_exact(&mut body).await.unwrap();
        assert_ne!(a_ips(&Message::from_bytes(&body).unwrap())[0], udp_ip);
    }

    /// Turn a query into a plausible response (QR bit set) without changing it otherwise.
    fn as_response(q: &[u8]) -> Vec<u8> {
        let mut r = q.to_vec();
        r[2] |= 0x80;
        r
    }

    #[test]
    fn the_root_gets_no_fake_address() {
        let p = pool();
        let Answer::Reply(r) = answer(&query(".", RecordType::A, DNSClass::IN), &p).unwrap() else {
            panic!("answered locally");
        };
        let m = Message::from_bytes(&r).unwrap();
        assert_eq!(m.response_code(), ResponseCode::NoError);
        assert!(m.answers().is_empty());
        assert!(p.is_empty(), "nothing allocated");
    }

    #[tokio::test]
    async fn forwards_in_flight_are_capped() {
        // An upstream that never answers: every forward waits out its timeout
        // holding a socket. Past the cap, queries are dropped at once.
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let silent_addr = silent.local_addr().unwrap();
        let stats = std::sync::Arc::new(DnsStats::default());
        let q = std::sync::Arc::new(query("example.com.", RecordType::MX, DNSClass::IN));
        let pool = pool();
        let tasks: Vec<_> = (0..MAX_FORWARDS + 5)
            .map(|_| {
                let (stats, q, pool) = (stats.clone(), q.clone(), pool.clone());
                tokio::spawn(async move { respond(&q, &pool, silent_addr, Transport::Udp, &stats).await })
            })
            .collect();
        for t in tasks {
            assert!(t.await.unwrap().is_none());
        }
        // Those that went upstream timed out; the rest never went.
        assert_eq!(stats.forward_failed.load(Ordering::Relaxed), MAX_FORWARDS as u64);
        assert_eq!(stats.queries.load(Ordering::Relaxed), MAX_FORWARDS as u64 + 5);
        drop(silent);
    }

    #[tokio::test]
    async fn forwarding_reaches_upstream_and_times_out_quietly() {
        let up = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, from) = up.recv_from(&mut buf).await.unwrap();
            up.send_to(&as_response(&buf[..n]), from).await.unwrap();
        });
        let q = query("example.com.", RecordType::TXT, DNSClass::IN);
        let stats = DnsStats::default();
        let got = respond(&q, &pool(), up_addr, Transport::Udp, &stats).await.unwrap();
        assert_eq!(got, as_response(&q));

        // Nothing listening: the answer is None, not a hang or a panic.
        let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        let t0 = std::time::Instant::now();
        assert!(respond(&q, &pool(), dead_addr, Transport::Udp, &stats).await.is_none());
        assert!(t0.elapsed() < Duration::from_secs(5));

        // A local answer is a query too, but not a forward.
        respond(
            &query("a.example.", RecordType::A, DNSClass::IN),
            &pool(),
            dead_addr,
            Transport::Udp,
            &stats,
        )
        .await
        .unwrap();
        let n = |c: &AtomicU64| c.load(Ordering::Relaxed);
        assert_eq!(
            (n(&stats.queries), n(&stats.forwarded), n(&stats.forward_failed)),
            (3, 1, 1)
        );
    }

    #[test]
    fn reply_matching_rules() {
        let q = query("example.com.", RecordType::TXT, DNSClass::IN);
        assert!(is_reply_to(&q, &as_response(&q)));
        assert!(!is_reply_to(&q, &q), "a query is not a reply");
        let mut wrong_id = as_response(&q);
        wrong_id[0] ^= 0xff;
        assert!(!is_reply_to(&q, &wrong_id), "transaction id must match");
        let other = as_response(&query("other.com.", RecordType::TXT, DNSClass::IN));
        assert!(!is_reply_to(&q, &other), "question must match");
        assert!(!is_reply_to(&q, &[1, 2, 3]));
        let other_type = as_response(&query("example.com.", RecordType::A, DNSClass::IN));
        assert!(!is_reply_to(&q, &other_type), "QTYPE must match");
    }

    #[test]
    fn replies_we_cannot_parse_still_reach_the_client() {
        let q = query("big.example.", RecordType::TXT, DNSClass::IN);
        // TC=1 and ANCOUNT=1, but the record is cut off after 3 bytes.
        let mut tc = as_response(&q);
        tc[2] |= 0x02;
        tc[7] = 1;
        tc.extend_from_slice(&[0xc0, 0x0c, 0x00]);
        assert!(Message::from_bytes(&tc).is_err(), "not parseable as a whole");
        assert!(is_reply_to(&q, &tc), "the client needs the TC bit to retry over TCP");

        // Error reply without a question section: accepted on the ID.
        let mut formerr = tc[..12].to_vec();
        formerr[2] = 0x80;
        formerr[3] = 0x01; // RCODE = FORMERR
        formerr[4..12].fill(0);
        assert!(is_reply_to(&q, &formerr));
        let mut noerror = formerr.clone();
        noerror[3] = 0;
        assert!(!is_reply_to(&q, &noerror), "a NOERROR answer must echo the question");
    }

    #[test]
    fn question_names_compare_case_insensitively() {
        // DNS 0x20: the resolver randomised the case, the server lowercased it.
        let q = query("ExAmPlE.CoM.", RecordType::A, DNSClass::IN);
        let r = as_response(&query("example.com.", RecordType::A, DNSClass::IN));
        assert!(is_reply_to(&q, &r));
    }

    #[tokio::test]
    async fn forged_and_mismatched_upstream_replies_are_ignored() {
        // The upstream first sends two bogus answers, then the real one.
        let up = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, from) = up.recv_from(&mut buf).await.unwrap();
            let q = buf[..n].to_vec();
            let mut bad_id = as_response(&q);
            bad_id[1] ^= 0x55;
            up.send_to(&bad_id, from).await.unwrap();
            up.send_to(
                &as_response(&query("forged.example.", RecordType::TXT, DNSClass::IN)),
                from,
            )
            .await
            .unwrap();
            up.send_to(&as_response(&q), from).await.unwrap();
        });
        let q = query("real.example.", RecordType::TXT, DNSClass::IN);
        assert_eq!(forward_udp(&q, up_addr).await.unwrap(), as_response(&q));
    }

    #[tokio::test]
    async fn a_third_party_cannot_answer_for_the_upstream() {
        // The real upstream never answers; an attacker that knows nothing but
        // our source port floods it with otherwise perfect answers.
        let up = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up.local_addr().unwrap();
        let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, victim) = up.recv_from(&mut buf).await.unwrap();
            let forged = as_response(&buf[..n]);
            for _ in 0..20 {
                let _ = attacker.send_to(&forged, victim).await;
            }
            std::future::pending::<()>().await;
        });
        let q = query("victim.example.", RecordType::TXT, DNSClass::IN);
        assert!(
            forward_udp(&q, up_addr).await.is_err(),
            "datagrams from a non-upstream address are dropped"
        );
    }

    #[tokio::test]
    async fn tcp_queries_are_forwarded_over_tcp() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut len = [0u8; 2];
            s.read_exact(&mut len).await.unwrap();
            let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
            s.read_exact(&mut q).await.unwrap();
            let r = as_response(&q);
            s.write_all(&(r.len() as u16).to_be_bytes()).await.unwrap();
            s.write_all(&r).await.unwrap();
        });
        let q = query("big.example.", RecordType::TXT, DNSClass::IN);
        assert_eq!(
            respond(&q, &pool(), up_addr, Transport::Tcp, &DnsStats::default())
                .await
                .unwrap(),
            as_response(&q)
        );
    }

    #[test]
    fn internationalised_names_stay_in_punycode() {
        let p = pool();
        let m = parse(answer(&query("xn--mnchen-3ya.de.", RecordType::A, DNSClass::IN), &p).unwrap());
        let ip = a_ips(&m)[0];
        assert_eq!(
            p.lookup(ip).as_deref(),
            Some("xn--mnchen-3ya.de"),
            "never the decoded UTF-8 form"
        );
        // Mixed case punycode is still one name.
        let m2 = parse(answer(&query("XN--MNCHEN-3YA.DE.", RecordType::A, DNSClass::IN), &p).unwrap());
        assert_eq!(a_ips(&m2), vec![ip]);
    }

    #[tokio::test]
    async fn a_client_that_never_reads_its_answers_is_dropped_after_the_idle_deadline() {
        // A pipe with room for a query or two, not for the answers piling up.
        let (mut client, server) = tokio::io::duplex(256);
        let serving = tokio::spawn(async move {
            serve_tcp(server, &pool(), "127.0.0.1:9".parse().unwrap(), &DnsStats::default()).await
        });
        let ask = tcp_framed(&query("ok.example.", RecordType::A, DNSClass::IN));
        tokio::spawn(async move { while client.write_all(&ask).await.is_ok() {} });
        let ended = tokio::time::timeout(TCP_IDLE + Duration::from_secs(2), serving).await;
        assert!(
            ended.is_ok(),
            "a client that never reads must not keep the task forever"
        );
    }

    #[tokio::test]
    async fn a_stalled_tcp_client_does_not_block_others() {
        let addr = tcp_dns(pool()).await;
        // Says "a 300-byte query follows" and then goes quiet.
        let mut stalled = tokio::net::TcpStream::connect(addr).await.unwrap();
        stalled.write_all(&300u16.to_be_bytes()).await.unwrap();
        stalled.write_all(&[0u8; 10]).await.unwrap();
        // Meanwhile a normal client is served at once.
        let q = query("ok.example.", RecordType::A, DNSClass::IN);
        let mut t = tokio::net::TcpStream::connect(addr).await.unwrap();
        t.write_all(&(q.len() as u16).to_be_bytes()).await.unwrap();
        t.write_all(&q).await.unwrap();
        let mut l = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(2), t.read_exact(&mut l))
            .await
            .unwrap()
            .unwrap();
        // And the stalled one is dropped after the idle deadline, not kept forever.
        let mut b = [0u8; 1];
        let closed = tokio::time::timeout(TCP_IDLE + Duration::from_secs(2), stalled.read(&mut b)).await;
        assert!(
            matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
            "server must close a stalled client"
        );
    }
}
