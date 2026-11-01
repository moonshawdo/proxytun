//! Outbound dialers. Both SOCKS5 and HTTP CONNECT preserve the *domain*:
//! SOCKS5 via ATYP=0x03 (domain), HTTP via `CONNECT host:port`. This is the
//! whole point: the proxy (Clash/sing-box) receives the hostname and can do
//! domain-based routing, instead of the pre-resolved IP that graftcp leaks.
//!
//! The protocols themselves live in `socks5` and `http`. Here a node is
//! dialed (connect, handshake, each phase on its own clock), and a group
//! fails over, blaming each failure on whoever caused it (`Blame`).

mod http;
mod socks5;

use self::http::http_handshake;
use self::socks5::{socks5_connect_request, socks5_creds, socks5_greet, socks5_request};
use crate::balancer::{ConnGuard, Group, Node};
use crate::config::{ProxyCfg, ProxyKind};
use crate::errno::{is_errno, is_local_shortage};
use crate::types::Target;
use anyhow::{anyhow, Context, Result};
use std::future::Future;
use std::time::Duration;
use tokio::net::TcpStream;

/// The proxy answered properly but did not connect to the destination (a SOCKS5
/// reply code or HTTP CONNECT status saying so), or got no answer from it in
/// time, or the destination cannot be asked for at all. The proxy is up and
/// speaking the protocol, so this never counts against its health.
/// `about_target`: the answer is surely about the destination (refused,
/// unreachable), and another member would only repeat it. Otherwise (SOCKS5
/// "general failure" or "not allowed by ruleset", HTTP 403/500/503: the
/// proxy's own upstream or its own rules may be what failed) another member
/// is tried.
/// `answered`: the proxy said so. When it said nothing (the destination
/// never answered it) or was never asked, its health is left as it was.
#[derive(Debug)]
struct TargetRefused {
    msg: String,
    about_target: bool,
    answered: bool,
}

impl std::fmt::Display for TargetRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for TargetRefused {}

/// What a health probe asks of a connected proxy: its own part of a real
/// connection's handshake, before any destination is named. SOCKS5: the
/// greeting, authentication included. HTTP: nothing (it answers a CONNECT
/// only once the destination has).
pub(crate) async fn greet(s: &mut TcpStream, cfg: &ProxyCfg) -> Result<()> {
    match cfg.kind {
        ProxyKind::Socks5 => {
            let creds = socks5_creds(cfg.username.as_deref(), cfg.password.as_deref())?;
            socks5_greet(s, creds).await
        }
        ProxyKind::Http => Ok(()),
    }
}

// ---------------------------------------------------------------- dialing --

/// Connect to one node and finish the proxy handshake for `t`. Only what is
/// the proxy's own doing counts against it: reaching it, and its greeting.
/// Proxies answer a connect request once the destination has (squid, ssh -D,
/// dante), so a request left unanswered is about the destination.
async fn dial_node(
    node: &Node,
    t: &Target,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> Result<TcpStream> {
    let user = node.cfg.username.as_deref();
    let pass = node.cfg.password.as_deref();
    match node.cfg.kind {
        ProxyKind::Socks5 => {
            // A destination no proxy can be asked for (an empty or overlong
            // name): found out before connecting, and nobody's fault.
            let creds = socks5_creds(user, pass)?;
            let req = socks5_connect_request(t).map_err(|e| TargetRefused {
                msg: format!("{e:#}"),
                about_target: true,
                answered: false,
            })?;
            let mut s = connect(node, connect_timeout).await?;
            // Each phase its own time: a slow greeting is the proxy's, and must
            // not shorten the wait for the destination.
            tokio::time::timeout(handshake_timeout, socks5_greet(&mut s, creds))
                .await
                .map_err(|_| anyhow!("socks5 greeting of proxy {} timed out", node.name))??;
            wait_for_target(node, t, handshake_timeout, socks5_request(&mut s, &req)).await?;
            Ok(s)
        }
        ProxyKind::Http => {
            let mut s = connect(node, connect_timeout).await?;
            wait_for_target(node, t, handshake_timeout, http_handshake(&mut s, t, user, pass)).await?;
            Ok(s)
        }
    }
}

/// The TCP connection to the proxy itself.
async fn connect(node: &Node, timeout: Duration) -> Result<TcpStream> {
    let s = tokio::time::timeout(timeout, TcpStream::connect(node.addr))
        .await
        .map_err(|_| anyhow!("connect to proxy {} timed out", node.name))?
        .with_context(|| format!("connect to proxy {} ({})", node.name, node.addr))?;
    s.set_nodelay(true).ok();
    Ok(s)
}

/// The part of a handshake the proxy answers only once the destination has:
/// no answer in time means the destination gave the proxy none.
async fn wait_for_target(
    node: &Node,
    t: &Target,
    within: Duration,
    step: impl Future<Output = Result<()>>,
) -> Result<()> {
    tokio::time::timeout(within, step).await.map_err(|_| TargetRefused {
        msg: format!("proxy {} got no answer from {t:?} within {within:?}", node.name),
        about_target: true,
        answered: false,
    })?
}

/// Whose doing a failed dial was, which decides what happens next: one class
/// per outcome in docs/architecture/operations.md 7.2. `answered`: the proxy
/// replied, so it is up, and that counts as a success.
#[derive(Debug, PartialEq, Eq)]
enum Blame {
    /// The destination's (refused, unreachable, silent, or not one a proxy
    /// can be asked for): another member would only repeat it.
    Target { answered: bool },
    /// Unclear, or this proxy's own rules or upstream, or a proxy that hung
    /// up on the request: another member may get through.
    Unclear { answered: bool },
    /// No local port left towards this proxy: another may still have plenty.
    LocalPorts,
    /// Short of fds, buffers or memory: every proxy would fail the same way.
    LocalShortage,
    /// The proxy's own failure: unreachable, greeting or authentication
    /// failed, a feature it lacks, a broken reply.
    Proxy,
}

fn blame(e: &anyhow::Error) -> Blame {
    if let Some(r) = e.downcast_ref::<TargetRefused>() {
        return if r.about_target {
            Blame::Target { answered: r.answered }
        } else {
            Blame::Unclear { answered: r.answered }
        };
    }
    // Out of local ports is a local shortage too: asked first.
    if is_errno(e, libc::EADDRNOTAVAIL) {
        Blame::LocalPorts
    } else if is_local_shortage(e) {
        Blame::LocalShortage
    } else {
        Blame::Proxy
    }
}

/// Pick a node from `group`, dial through it, and on failure try other members
/// (at most `retries` more). Only handshake failures are retried: no
/// application byte has been sent yet, so a retry is always safe.
pub(crate) async fn dial_group(
    group: &Group,
    t: &Target,
    retries: u32,
    fail_threshold: u32,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> Result<(TcpStream, ConnGuard, String)> {
    let key = t.host_key();
    let mut tried: Vec<usize> = Vec::new();
    let mut last_err = anyhow!("group '{}': no healthy proxy available", group.name);
    for _ in 0..=retries {
        let Some(i) = group.select(&key, &tried) else { break };
        tried.push(i);
        let node = &group.nodes[i];
        let e = match dial_node(node, t, connect_timeout, handshake_timeout).await {
            Ok(s) => {
                // Health only: this round trip includes the proxy reaching the
                // destination, so it is not a sample of the proxy hop latency
                // (that comes from the health prober).
                node.record_ok();
                return Ok((s, node.acquire(), node.name.clone()));
            }
            Err(e) => e,
        };
        match blame(&e) {
            Blame::Target { answered } => {
                if answered {
                    node.record_ok();
                }
                tracing::debug!(proxy = %node.name, "destination refused by the proxy: {e:#}");
                return Err(e);
            }
            Blame::Unclear { answered } => {
                if answered {
                    node.record_ok();
                }
                tracing::debug!(proxy = %node.name, "proxy could not connect, trying another: {e:#}");
            }
            // Local ports run out per destination: another proxy may still
            // have plenty. Nobody's fault either way.
            Blame::LocalPorts => {
                tracing::warn!(proxy = %node.name, "no local port left towards this proxy, trying another: {e:#}");
            }
            Blame::LocalShortage => {
                // Once in a while: out of fds, every connection fails so.
                static LOGGED: crate::throttle::Throttle = crate::throttle::Throttle::new();
                if LOGGED.due() {
                    tracing::warn!(
                        proxy = %node.name,
                        "dial failed for lack of local resources: {e:#} (repeats within {}s not logged)",
                        crate::throttle::EVERY.as_secs()
                    );
                }
                return Err(e);
            }
            Blame::Proxy => {
                node.record_failure(fail_threshold);
                tracing::warn!(proxy = %node.name, "dial failed: {e:#}");
            }
        }
        // On to another member.
        last_err = e;
    }
    Err(last_err)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The default `connect_timeout_ms` and `handshake_timeout_ms`.
    const CT: Duration = Duration::from_secs(10);
    const HT: Duration = Duration::from_secs(10);

    /// A listener whose accept queue is full: the kernel drops further SYNs,
    /// so a connect to it hangs, as to a stuck service or a host that never
    /// answers. All three are kept for as long as that should last.
    pub(crate) fn black_hole() -> (std::net::TcpListener, std::net::TcpStream, std::net::SocketAddr) {
        use std::os::fd::AsRawFd;
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        // SAFETY: plain syscall; on a listening socket it only resizes the
        // backlog, here to the one connection queued next.
        assert_eq!(unsafe { libc::listen(l.as_raw_fd(), 0) }, 0);
        let addr = l.local_addr().unwrap();
        let queued = std::net::TcpStream::connect(addr).unwrap();
        // Queued for accept, not just under way: from now on SYNs are dropped.
        let mut p = libc::pollfd {
            fd: l.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: plain syscall on a local pollfd.
        assert_eq!(unsafe { libc::poll(&mut p, 1, 5000) }, 1, "the queued connection");
        (l, queued, addr)
    }

    pub(super) fn dom(d: &str, p: u16) -> Target {
        Target::Domain(d.into(), p)
    }

    // ------------------------------------------------- failure accounting --

    use crate::balancer::Node;
    use crate::config::{ProxyCfg, Strategy};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::net::TcpListener;

    #[derive(Clone, Copy)]
    enum Reply {
        Socks(u8),
        Http(&'static str),
        /// Greets, then never answers the connect request (the destination
        /// is a black hole).
        SocksUnanswered,
        /// Greets, takes the connect request and hangs up, as `ssh -D` does
        /// when the destination cannot be reached.
        SocksHangsUp,
        /// Takes the CONNECT, never answers it.
        HttpUnanswered,
        /// Accepts the TCP connection, never greets.
        Mute,
        /// Greets after 8 s, then gets through 3 s after the request.
        SlowGreeting,
    }

    /// A proxy that always gives the same answer; counts connections.
    async fn scripted_proxy(reply: Reply) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let h2 = hits.clone();
        tokio::spawn(async move {
            loop {
                let (mut c, _) = l.accept().await.unwrap();
                h2.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    match reply {
                        Reply::Socks(rep) => {
                            let mut g = [0u8; 3];
                            c.read_exact(&mut g).await.ok();
                            c.write_all(&[5, 0]).await.ok();
                            let mut h = [0u8; 5];
                            c.read_exact(&mut h).await.ok();
                            let mut rest = vec![0u8; h[4] as usize + 2];
                            c.read_exact(&mut rest).await.ok();
                            c.write_all(&[5, rep, 0, 1, 0, 0, 0, 0, 0, 0]).await.ok();
                        }
                        Reply::Http(status) => {
                            let mut buf = Vec::new();
                            let mut b = [0u8; 1];
                            while !buf.ends_with(b"\r\n\r\n") && c.read_exact(&mut b).await.is_ok() {
                                buf.push(b[0]);
                            }
                            c.write_all(format!("HTTP/1.1 {status}\r\n\r\n").as_bytes()).await.ok();
                        }
                        Reply::SocksUnanswered => {
                            let mut g = [0u8; 3];
                            c.read_exact(&mut g).await.ok();
                            c.write_all(&[5, 0]).await.ok();
                            // Hold on, silent, until the client gives up.
                            let mut sink = [0u8; 64];
                            while c.read(&mut sink).await.is_ok_and(|n| n > 0) {}
                        }
                        Reply::SocksHangsUp => {
                            let mut g = [0u8; 3];
                            c.read_exact(&mut g).await.ok();
                            c.write_all(&[5, 0]).await.ok();
                            let mut h = [0u8; 5];
                            c.read_exact(&mut h).await.ok();
                            let mut rest = vec![0u8; h[4] as usize + 2];
                            c.read_exact(&mut rest).await.ok();
                            return;
                        }
                        Reply::SlowGreeting => {
                            let mut g = [0u8; 3];
                            c.read_exact(&mut g).await.ok();
                            tokio::time::sleep(Duration::from_secs(8)).await;
                            c.write_all(&[5, 0]).await.ok();
                            let mut h = [0u8; 5];
                            c.read_exact(&mut h).await.ok();
                            let mut rest = vec![0u8; h[4] as usize + 2];
                            c.read_exact(&mut rest).await.ok();
                            tokio::time::sleep(Duration::from_secs(3)).await;
                            c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.ok();
                        }
                        Reply::HttpUnanswered | Reply::Mute => {
                            let mut sink = [0u8; 64];
                            while c.read(&mut sink).await.is_ok_and(|n| n > 0) {}
                        }
                    }
                    let mut sink = [0u8; 64];
                    let _ = c.read(&mut sink).await;
                });
            }
        });
        (addr, hits)
    }

    fn node_at(name: &str, addr: std::net::SocketAddr, kind: ProxyKind) -> Arc<Node> {
        Node::new(ProxyCfg {
            name: name.into(),
            kind,
            addr: addr.to_string(),
            username: None,
            password: None,
            weight: 1,
        })
        .unwrap()
    }

    #[tokio::test]
    async fn a_destination_refused_by_the_proxy_is_not_a_proxy_failure() {
        for (reply, kind) in [
            (Reply::Socks(0x04), ProxyKind::Socks5), // host unreachable
            (Reply::Socks(0x05), ProxyKind::Socks5), // connection refused
            (Reply::Socks(0x06), ProxyKind::Socks5), // TTL expired
            (Reply::Http("502 Bad Gateway"), ProxyKind::Http),
            (Reply::Http("504 Gateway Timeout"), ProxyKind::Http),
        ] {
            let (a, hits_a) = scripted_proxy(reply).await;
            let (b, hits_b) = scripted_proxy(reply).await;
            let g = Group::new(
                "g",
                Strategy::RoundRobin,
                vec![node_at("a", a, kind), node_at("b", b, kind)],
            )
            .unwrap();
            for _ in 0..5 {
                assert!(dial_group(&g, &dom("dead.example", 443), 2, 3, CT, HT).await.is_err());
            }
            assert!(g.nodes.iter().all(|n| n.is_healthy()), "nodes must stay UP");
            assert_eq!(g.nodes[0].stats().fail_total + g.nodes[1].stats().fail_total, 0);
            assert_eq!(
                hits_a.load(Ordering::SeqCst) + hits_b.load(Ordering::SeqCst),
                5,
                "one attempt per connection: retrying elsewhere would get the same answer"
            );
        }
    }

    #[tokio::test]
    async fn a_destination_that_never_answers_is_not_a_proxy_failure() {
        // squid, ssh -D, dante answer the connect request only once the
        // destination has: a black hole leaves the request unanswered. That is
        // no reason to doubt the proxy, nor to make every member wait it out.
        let cases = [
            (Reply::SocksUnanswered, ProxyKind::Socks5),
            (Reply::HttpUnanswered, ProxyKind::Http),
        ]
        .map(|(reply, kind)| async move {
            let (a, hits_a) = scripted_proxy(reply).await;
            let (b, hits_b) = scripted_proxy(reply).await;
            let g = Group::new(
                "g",
                Strategy::RoundRobin,
                vec![node_at("a", a, kind), node_at("b", b, kind)],
            )
            .unwrap();
            let e = dial_group(&g, &dom("black.hole", 443), 2, 1, CT, HT)
                .await
                .err()
                .expect("must fail");
            assert!(
                e.downcast_ref::<TargetRefused>().is_some_and(|r| r.about_target),
                "{e:#}"
            );
            assert!(g.nodes.iter().all(|n| n.is_healthy()), "{kind:?}: nodes must stay UP");
            // Nor up on its account: it never said the destination was fine.
            assert!(
                g.nodes.iter().all(|n| n.stats().ok_total == 0),
                "{kind:?}: no success recorded"
            );
            assert_eq!(
                hits_a.load(Ordering::SeqCst) + hits_b.load(Ordering::SeqCst),
                1,
                "{kind:?}"
            );
        });
        // A proxy that does not even greet is at fault.
        let mute = async {
            let (m, _) = scripted_proxy(Reply::Mute).await;
            let g = Group::new("g", Strategy::RoundRobin, vec![node_at("m", m, ProxyKind::Socks5)]).unwrap();
            assert!(dial_group(&g, &dom("x.example", 443), 0, 1, CT, HT).await.is_err());
            assert!(!g.nodes[0].is_healthy(), "a silent proxy is marked down");
        };
        let [socks, http] = cases;
        tokio::join!(socks, http, mute);
    }

    #[tokio::test]
    async fn a_proxy_that_hangs_up_on_a_request_is_neither_blamed_nor_the_last_word() {
        // ssh -D hangs up on a destination it cannot reach: three in a row
        // used to take it down (V2 fixed that), and another member, another
        // server, may reach it. Neither health is touched by the hang-up.
        let (a, a_hits) = scripted_proxy(Reply::SocksHangsUp).await;
        let (b, b_hits) = scripted_proxy(Reply::Socks(0)).await;
        let g = Group::new(
            "g",
            Strategy::RoundRobin,
            vec![node_at("a", a, ProxyKind::Socks5), node_at("b", b, ProxyKind::Socks5)],
        )
        .unwrap();
        for _ in 0..6 {
            dial_group(&g, &dom("x.example", 443), 2, 1, CT, HT).await.unwrap();
        }
        assert!(g.nodes[0].is_healthy(), "hanging up is not a broken proxy");
        assert_eq!(g.nodes[0].stats().ok_total, 0, "nor a success it reported");
        assert!(a_hits.load(Ordering::SeqCst) > 0, "a was asked");
        assert_eq!(b_hits.load(Ordering::SeqCst), 6, "and b got every one");
        // All members hang up: it fails, still blaming none.
        let (c, _) = scripted_proxy(Reply::SocksHangsUp).await;
        let g = Group::new("g", Strategy::RoundRobin, vec![node_at("c", c, ProxyKind::Socks5)]).unwrap();
        for _ in 0..3 {
            assert!(dial_group(&g, &dom("x.example", 443), 2, 1, CT, HT).await.is_err());
        }
        assert!(g.nodes[0].is_healthy());
    }

    #[tokio::test]
    async fn a_destination_no_proxy_can_be_asked_for_costs_no_connection() {
        let (a, hits) = scripted_proxy(Reply::Socks(0)).await;
        let g = Group::new("g", Strategy::RoundRobin, vec![node_at("a", a, ProxyKind::Socks5)]).unwrap();
        for d in ["", &"x".repeat(256)] {
            let e = dial_group(&g, &dom(d, 80), 2, 1, CT, HT)
                .await
                .err()
                .expect("must fail");
            assert!(
                e.downcast_ref::<TargetRefused>().is_some_and(|r| r.about_target),
                "{e:#}"
            );
        }
        assert!(g.nodes[0].is_healthy());
        assert_eq!(g.nodes[0].stats().ok_total, 0, "nor counted a success");
        assert_eq!(hits.load(Ordering::SeqCst), 0, "found out before connecting");
    }

    #[tokio::test]
    async fn a_slow_greeting_does_not_shorten_the_wait_for_the_destination() {
        // 8 s to greet, then 3 s for the destination: 11 s in all, more than
        // one handshake timeout (the default 10 s), but each phase is within
        // its own.
        let (a, _) = scripted_proxy(Reply::SlowGreeting).await;
        let g = Group::new("g", Strategy::RoundRobin, vec![node_at("a", a, ProxyKind::Socks5)]).unwrap();
        assert!(dial_group(&g, &dom("slow.example", 443), 0, 1, CT, HT).await.is_ok());
    }

    #[tokio::test]
    async fn proxy_side_failures_count_and_fail_over() {
        // 407: this proxy entry's credentials are wrong -> try the next member.
        let (bad, _) = scripted_proxy(Reply::Http("407 Proxy Authentication Required")).await;
        let (good, good_hits) = scripted_proxy(Reply::Http("200 Connection established")).await;
        let g = Group::new(
            "g",
            Strategy::RoundRobin,
            vec![
                node_at("bad", bad, ProxyKind::Http),
                node_at("good", good, ProxyKind::Http),
            ],
        )
        .unwrap();
        for _ in 0..3 {
            dial_group(&g, &dom("ok.example", 443), 2, 3, CT, HT).await.unwrap();
        }
        assert!(!g.nodes[0].is_healthy(), "repeated 407 marks the entry down");
        assert_eq!(good_hits.load(Ordering::SeqCst), 3);

        // Nothing listening: also a proxy failure.
        let dead = crate::testutil::refused();
        let n = node_at("dead", dead.addr, ProxyKind::Socks5);
        let g = Group::new("g", Strategy::RoundRobin, vec![n]).unwrap();
        assert!(dial_group(&g, &dom("x.example", 443), 0, 1, CT, HT).await.is_err());
        assert!(!g.nodes[0].is_healthy());
    }

    #[tokio::test]
    async fn an_unclear_refusal_tries_another_member_without_blaming_the_proxy() {
        // "General failure" / 503: perhaps the destination, perhaps the proxy's
        // own upstream is down. "Not allowed" / 403: this proxy's own rules,
        // which another's may not share. Another member may well get through,
        // but the proxy answered properly, so its health is not touched.
        for (reply, kind) in [
            (Reply::Socks(0x01), ProxyKind::Socks5),
            (Reply::Socks(0x02), ProxyKind::Socks5),
            (Reply::Http("403 Forbidden"), ProxyKind::Http),
            (Reply::Http("503 Service Unavailable"), ProxyKind::Http),
            (Reply::Http("500 Internal Server Error"), ProxyKind::Http),
        ] {
            let ok = match kind {
                ProxyKind::Socks5 => Reply::Socks(0),
                ProxyKind::Http => Reply::Http("200 Connection established"),
            };
            let (a, a_hits) = scripted_proxy(reply).await;
            let (b, _) = scripted_proxy(ok).await;
            let g = Group::new(
                "g",
                Strategy::RoundRobin,
                vec![node_at("a", a, kind), node_at("b", b, kind)],
            )
            .unwrap();
            for _ in 0..6 {
                dial_group(&g, &dom("x.example", 443), 2, 1, CT, HT)
                    .await
                    .expect("fails over to the member that gets through");
            }
            assert!(a_hits.load(Ordering::SeqCst) >= 3, "a was tried");
            assert!(g.nodes.iter().all(|n| n.is_healthy()), "fail_threshold 1, still UP");
            assert_eq!(g.nodes[0].stats().fail_total, 0);
        }
    }

    #[tokio::test]
    async fn a_proxy_lacking_a_feature_is_a_proxy_failure() {
        // e.g. an IP-only SOCKS5 proxy answering ATYP=domain with 0x08, or an
        // HTTP proxy without CONNECT: this entry cannot serve the request.
        for (reply, kind) in [
            (Reply::Socks(0x07), ProxyKind::Socks5),
            (Reply::Socks(0x08), ProxyKind::Socks5),
            (Reply::Http("405 Method Not Allowed"), ProxyKind::Http),
        ] {
            let ok = match kind {
                ProxyKind::Socks5 => Reply::Socks(0),
                ProxyKind::Http => Reply::Http("200 Connection established"),
            };
            let (a, _) = scripted_proxy(reply).await;
            let (b, b_hits) = scripted_proxy(ok).await;
            let g = Group::new(
                "g",
                Strategy::RoundRobin,
                vec![node_at("a", a, kind), node_at("b", b, kind)],
            )
            .unwrap();
            for _ in 0..3 {
                dial_group(&g, &dom("x.example", 443), 2, 1, CT, HT).await.unwrap();
            }
            assert!(!g.nodes[0].is_healthy(), "marked down");
            assert_eq!(b_hits.load(Ordering::SeqCst), 3);
        }
    }

    #[tokio::test]
    async fn a_proxy_that_never_accepts_is_given_up_after_the_connect_timeout_and_blamed() {
        let (_l, _queued, hole) = black_hole();
        let g = Group::new("g", Strategy::RoundRobin, vec![node_at("h", hole, ProxyKind::Socks5)]).unwrap();
        let start = std::time::Instant::now();
        let e = dial_group(&g, &dom("x.example", 443), 0, 1, Duration::from_millis(200), HT)
            .await
            .err()
            .expect("must fail");
        let took = start.elapsed();
        assert!(
            took < Duration::from_secs(3),
            "the configured 200 ms, not the default 10 s: {took:?}"
        );
        assert!(format!("{e:#}").contains("connect to proxy h timed out"), "{e:#}");
        assert!(!g.nodes[0].is_healthy(), "a proxy that never accepts is failing");
    }

    #[tokio::test]
    async fn each_handshake_step_ends_at_the_handshake_timeout_and_is_blamed_rightly() {
        let short = Duration::from_millis(200);
        // (proxy, kind, what the error says, whether the proxy is to blame)
        let cases = [
            (
                Reply::Mute,
                ProxyKind::Socks5,
                "socks5 greeting of proxy p timed out",
                true,
            ),
            (Reply::SocksUnanswered, ProxyKind::Socks5, "got no answer from", false),
            (Reply::HttpUnanswered, ProxyKind::Http, "got no answer from", false),
        ];
        for (reply, kind, says, blamed) in cases {
            let (a, _) = scripted_proxy(reply).await;
            let g = Group::new("g", Strategy::RoundRobin, vec![node_at("p", a, kind)]).unwrap();
            let start = std::time::Instant::now();
            let e = dial_group(&g, &dom("x.example", 443), 0, 1, CT, short)
                .await
                .err()
                .expect("must fail");
            let took = start.elapsed();
            assert!(
                took < Duration::from_secs(3),
                "{says}: the configured 200 ms, not 10 s: {took:?}"
            );
            assert!(format!("{e:#}").contains(says), "{e:#}");
            assert_eq!(!g.nodes[0].is_healthy(), blamed, "{says}");
        }
    }

    #[tokio::test]
    async fn successful_connections_do_not_feed_the_latency_estimate() {
        let (a, _) = scripted_proxy(Reply::Socks(0)).await;
        let g = Group::new("g", Strategy::RoundRobin, vec![node_at("a", a, ProxyKind::Socks5)]).unwrap();
        dial_group(&g, &dom("x.example", 443), 0, 3, CT, HT).await.unwrap();
        assert_eq!(g.nodes[0].latency_us(), 0, "only health probes measure the proxy hop");
        assert_eq!(g.nodes[0].stats().ok_total, 1);
    }

    #[tokio::test]
    async fn the_hash_strategy_sends_each_host_where_its_name_points() {
        let (a, _) = scripted_proxy(Reply::Socks(0)).await;
        let (b, _) = scripted_proxy(Reply::Socks(0)).await;
        let g = Group::new(
            "g",
            Strategy::Hash,
            vec![node_at("a", a, ProxyKind::Socks5), node_at("b", b, ProxyKind::Socks5)],
        )
        .unwrap();
        for i in 0..8 {
            let host = format!("h{i}.example");
            let want = &g.nodes[g.select(&host, &[]).unwrap()].name;
            for port in [80, 443] {
                let (_, _, via) = dial_group(&g, &dom(&host, port), 0, 1, CT, HT).await.unwrap();
                assert_eq!(&via, want, "{host}:{port}");
            }
        }
    }

    #[test]
    fn out_of_local_ports_is_told_apart_from_other_local_shortages() {
        // Both are no proxy's fault, but ports run out per destination: only
        // then is another member worth a try.
        let io = |n| anyhow::Error::new(std::io::Error::from_raw_os_error(n)).context("connect to proxy");
        assert_eq!(blame(&io(libc::EADDRNOTAVAIL)), Blame::LocalPorts);
        assert_eq!(blame(&io(libc::EMFILE)), Blame::LocalShortage);
        assert_eq!(blame(&io(libc::ECONNREFUSED)), Blame::Proxy);
    }
}
