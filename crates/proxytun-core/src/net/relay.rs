//! TCP relay. The capture side accepts the program's connection and works out
//! where it was going (`Pending`); `route` does the rest: sniff a hostname if
//! the target is a bare IP, run the rule engine, then copy bytes to a proxy
//! group / straight out / nowhere.

use crate::balancer::Registry;
use crate::config::{env_proxies, Config};
use crate::policy::Policy;
use crate::proxy;
use crate::sniff::{self, Sniffed};
use crate::types::{Decision, Dest, Pending, Target};
use anyhow::{anyhow, Result};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{copy_bidirectional_with_sizes, AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tracing::{field, Span};

/// Hostname sniffing for connections to a literal IP.
#[derive(Debug, Clone)]
pub struct SniffCfg {
    pub enabled: bool,
    pub ports: Vec<u16>,
    /// Lower-cased domain suffixes that are never the real destination
    /// (the "public name" a real ECH connection shows).
    pub skip: Vec<String>,
    pub timeout: Duration,
    /// Dial the sniffed name (true) or only route by it and dial the IP (false).
    pub override_destination: bool,
}

impl Default for SniffCfg {
    fn default() -> Self {
        SniffCfg {
            enabled: true,
            ports: vec![80, 443, 8443],
            skip: vec!["cloudflare-ech.com".into()],
            timeout: Duration::from_millis(300),
            override_destination: true,
        }
    }
}

impl SniffCfg {
    fn skips(&self, name: &str) -> bool {
        self.skip.iter().any(|s| name == s || name.ends_with(&format!(".{s}")))
    }
}

/// Everything a connection handler needs; swapped atomically on SIGHUP.
pub struct Live {
    pub policy: Policy,
    pub registry: Registry,
    pub retries: u32,
    pub fail_threshold: u32,
    pub sniff: SniffCfg,
}

/// Build the per-connection state from a config. The program's own
/// `*_proxy` variables are read from our environment, which it inherits.
pub fn build_live(cfg: &Config) -> Result<Live> {
    let env = env_proxies(std::env::vars());
    Ok(Live {
        policy: Policy::new(cfg, env)?,
        registry: Registry::build(cfg)?,
        retries: cfg.retries,
        fail_threshold: cfg.health.fail_threshold,
        sniff: SniffCfg {
            enabled: cfg.sniff,
            ports: cfg.sniff_ports.clone(),
            skip: cfg
                .sniff_skip_domains
                .iter()
                .map(|d| d.trim_start_matches('.').to_ascii_lowercase())
                .collect(),
            timeout: Duration::from_millis(cfg.sniff_timeout_ms),
            override_destination: cfg.sniff_override_destination,
        },
    })
}

/// Bytes relayed so far, all connections together: `up` from the program
/// towards its targets, `down` back.
#[derive(Default)]
pub struct Traffic {
    pub up: AtomicU64,
    pub down: AtomicU64,
}

/// Bytes one connection moved each way.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Transfer {
    pub up: u64,
    pub down: u64,
}

/// The line every relayed connection ends with: how long it lived, how long
/// reaching its proxy (or the target itself) took, through what, the bytes
/// each way, and how it ended. Enough to tell a slow proxy from a slow
/// transfer, at the default log level.
pub fn log_closed(start: Instant, dial: Duration, via: &str, moved: &Transfer, r: &Result<()>) {
    let (ms, dial_ms) = (start.elapsed().as_millis() as u64, dial.as_millis() as u64);
    let (up, down) = (moved.up, moved.down);
    match r {
        Ok(()) => tracing::info!(ms, dial_ms, via = %via, up, down, "closed"),
        Err(e) => tracing::info!(ms, dial_ms, via = %via, up, down, "closed: {e:#}"),
    }
}

/// Carry one accepted connection to its target and log how it ended.
/// Records `target` on the caller's span, which names the connection in
/// every log line.
pub async fn route(live: &Live, traffic: &Traffic, mut inbound: TcpStream, pending: Pending) -> Result<()> {
    let start = Instant::now();
    let Pending { target, guard } = pending;
    // localnet and the program's own proxies: straight out, untouched.
    let passthrough = match target {
        Target::V4(ip, port) => live.policy.is_passthrough(&Dest::V4(ip, port)),
        Target::V6(ip, port) => live.policy.is_passthrough(&Dest::V6(ip, port)),
        Target::Domain(..) => false,
    };
    // `target` is what we connect to, `rule_target` what the rules look at.
    let (mut target, mut rule_target) = (target.clone(), target);
    if !passthrough {
        if let Some(domain) = maybe_sniff(&inbound, &target, &live.sniff, &live.policy).await {
            tracing::debug!(ip = ?target, %domain, "recovered hostname from the first bytes");
            rule_target = Target::Domain(domain, target.port());
            if live.sniff.override_destination {
                target = rule_target.clone();
            }
        }
    }
    Span::current().record("target", field::debug(&target));
    let decision = if passthrough {
        tracing::info!(decision = ?Decision::Direct, "routing (localnet)");
        Decision::Direct
    } else {
        let d = live.policy.decide(&rule_target);
        tracing::info!(decision = ?d, "routing");
        d
    };
    // Pin the fake-ip mapping for as long as this connection lives.
    let _pin = guard;

    let dial_start = Instant::now();
    let dialed = match decision {
        Decision::Block => {
            tracing::info!(ms = start.elapsed().as_millis() as u64, "closed: blocked by a rule");
            return Ok(());
        }
        Decision::Direct => dial_direct(&target).await.map(|s| (s, None, "direct".to_string())),
        Decision::Proxy { group } => match live.registry.group(&group) {
            Some(g) => proxy::dial_group(g, &target, live.retries, live.fail_threshold)
                .await
                .map(|(s, conn, node)| (s, Some(conn), node)),
            None => Err(anyhow!("rule names unknown group '{group}'")),
        },
    };
    let dial = dial_start.elapsed();
    let (via, moved, r) = match dialed {
        // `_conn` counts the connection as active on its proxy while it lasts.
        Ok((mut out, _conn, via)) => {
            out.set_nodelay(true).ok();
            let (moved, r) = pump(&mut inbound, &mut out, traffic).await;
            (via, moved, r)
        }
        Err(e) => ("-".to_string(), Transfer::default(), Err(e)),
    };
    log_closed(start, dial, &via, &moved, &r);
    r
}

/// For a literal-IP target on a sniff port, peek (without consuming) the
/// client's first bytes and try to read a hostname out of them. Any failure or
/// timeout keeps the literal IP, so the worst case is a short extra wait.
async fn maybe_sniff(inbound: &TcpStream, target: &Target, cfg: &SniffCfg, policy: &Policy) -> Option<String> {
    let ip = match target {
        Target::Domain(..) => return None,
        Target::V4(ip, _) => std::net::IpAddr::V4(*ip),
        Target::V6(ip, _) => std::net::IpAddr::V6(*ip),
    };
    if !cfg.enabled || !cfg.ports.contains(&target.port()) {
        return None;
    }
    // The address was chosen on purpose (a LAN host, /etc/hosts), or the
    // user wrote an ip-cidr rule for it: the payload's hostname must not win.
    if crate::policy::is_local_scope(ip) || policy.has_ip_rule_for(target) {
        return None;
    }
    let deadline = tokio::time::Instant::now() + cfg.timeout;
    let mut buf = vec![0u8; sniff::MAX_PEEK];
    loop {
        let n = tokio::time::timeout_at(deadline, inbound.peek(&mut buf))
            .await
            .ok()?
            .ok()?;
        if n == 0 {
            return None;
        }
        match sniff::sniff(&buf[..n]) {
            Sniffed::Domain(d) if cfg.skips(&d) => {
                tracing::debug!(?target, name = %d, "sniff: name is on the skip list (ECH public name), keeping the IP");
                return None;
            }
            Sniffed::Domain(d) => return Some(d),
            Sniffed::No => {
                tracing::debug!(?target, bytes = n, head = %hex(&buf[..n.min(16)]), "sniff: no hostname, keeping the IP");
                return None;
            }
            Sniffed::NeedMore if n == buf.len() => return None,
            Sniffed::NeedMore => {
                // peek() returns at once while unread data sits in the buffer;
                // wait a moment for the rest instead of spinning.
                if tokio::time::Instant::now() + Duration::from_millis(2) >= deadline {
                    return None;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Copy both ways until both sides are done, and say how many bytes went
/// each way (`up` = read from `a`), also when it ended in an error. A plain
/// copy, not splice(2): for connections that came in through the TUN device
/// it measured 20-30% faster (the TUN thread is the bottleneck either way, and
/// splice only adds to it). See docs/DESIGN.md.
pub async fn pump(a: &mut TcpStream, b: &mut TcpStream, traffic: &Traffic) -> (Transfer, Result<()>) {
    a.set_nodelay(true).ok();
    let mut a = Counted {
        s: a,
        n: 0,
        total: &traffic.up,
    };
    let mut b = Counted {
        s: b,
        n: 0,
        total: &traffic.down,
    };
    // 64 KiB buffers: the 8 KiB default costs throughput on fast links.
    let r = copy_bidirectional_with_sizes(&mut a, &mut b, 64 * 1024, 64 * 1024).await;
    (Transfer { up: a.n, down: b.n }, r.map(|_| ()).map_err(Into::into))
}

/// One side of a relayed connection, counting the bytes read from it (in `n`,
/// and in the shared `total` as they pass, so long transfers show up in the
/// stats before they end).
struct Counted<'a> {
    s: &'a mut TcpStream,
    n: u64,
    total: &'a AtomicU64,
}

impl AsyncRead for Counted<'_> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut *self.s).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = r {
            let k = (buf.filled().len() - before) as u64;
            self.n += k;
            self.total.fetch_add(k, Ordering::Relaxed);
        }
        r
    }
}

impl AsyncWrite for Counted<'_> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.s).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.s).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.s).poll_shutdown(cx)
    }
}

/// Direct connect. For a domain we must resolve it ourselves now, because the
/// program was handed a *fake* IP; the real one was never resolved on its side.
async fn dial_direct(t: &Target) -> Result<TcpStream> {
    let fut = async {
        match t {
            Target::Domain(d, p) => TcpStream::connect((d.as_str(), *p)).await,
            Target::V4(ip, p) => TcpStream::connect((*ip, *p)).await,
            Target::V6(ip, p) => TcpStream::connect((*ip, *p)).await,
        }
    };
    Ok(tokio::time::timeout(proxy::CONNECT_TIMEOUT, fut)
        .await
        .map_err(|_| anyhow!("direct connect to {t:?} timed out"))??)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{env_proxies, Config};
    use crate::types::Pending;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A tiny SOCKS5 server that records the requested target then echoes.
    async fn echo_socks5() -> (SocketAddr, Arc<std::sync::Mutex<Vec<String>>>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let s2 = seen.clone();
        tokio::spawn(async move {
            loop {
                let (mut c, _) = l.accept().await.unwrap();
                let seen = s2.clone();
                tokio::spawn(async move {
                    let mut g = [0u8; 3];
                    c.read_exact(&mut g).await.unwrap();
                    c.write_all(&[5, 0]).await.unwrap();
                    let mut h = [0u8; 4];
                    c.read_exact(&mut h).await.unwrap();
                    let host = match h[3] {
                        3 => {
                            let mut l = [0u8; 1];
                            c.read_exact(&mut l).await.unwrap();
                            let mut d = vec![0u8; l[0] as usize];
                            c.read_exact(&mut d).await.unwrap();
                            format!("domain:{}", String::from_utf8(d).unwrap())
                        }
                        1 => {
                            let mut d = [0u8; 4];
                            c.read_exact(&mut d).await.unwrap();
                            format!("ip:{}", Ipv4Addr::from(d))
                        }
                        _ => "other".into(),
                    };
                    let mut p = [0u8; 2];
                    c.read_exact(&mut p).await.unwrap();
                    seen.lock().unwrap().push(format!("{host}:{}", u16::from_be_bytes(p)));
                    c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
                    let mut buf = [0u8; 1024];
                    loop {
                        let n = c.read(&mut buf).await.unwrap_or(0);
                        if n == 0 || c.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        (addr, seen)
    }

    fn mk_live(proxy: SocketAddr, rules: &str) -> Arc<Live> {
        mk_live_sniff(proxy, rules, SniffCfg::default())
    }

    fn mk_live_sniff(proxy: SocketAddr, rules: &str, sniff: SniffCfg) -> Arc<Live> {
        let cfg = Config::parse(&format!("[proxy]\ntype=\"socks5\"\naddr=\"{proxy}\"\n{rules}")).unwrap();
        Arc::new(Live {
            policy: Policy::new(&cfg, env_proxies(std::iter::empty())).unwrap(),
            registry: Registry::build(&cfg).unwrap(),
            retries: 2,
            fail_threshold: 3,
            sniff,
        })
    }

    /// A client connection that the relay carries to `p`'s target, the way the
    /// capture side hands one over after accepting it.
    async fn relay_pending(live: &Arc<Live>, p: Pending) -> TcpStream {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let live = live.clone();
        tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let _ = route(&live, &Traffic::default(), s, p).await;
        });
        TcpStream::connect(addr).await.unwrap()
    }

    fn pending(t: Target) -> Pending {
        Pending { target: t, guard: None }
    }

    #[tokio::test]
    async fn domain_target_reaches_the_proxy_as_a_domain() {
        let (proxy, seen) = echo_socks5().await;
        let live = mk_live(proxy, "");
        let pend = pending(Target::Domain("example.com".into(), 443));

        let mut c = relay_pending(&live, pend).await;
        c.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        c.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping", "bytes flow through the proxy");
        assert_eq!(seen.lock().unwrap().as_slice(), ["domain:example.com:443"]);
    }

    #[tokio::test]
    async fn literal_ip_target_is_sent_as_ip() {
        let (proxy, seen) = echo_socks5().await;
        let live = mk_live(proxy, "");
        let pend = pending(Target::V4(Ipv4Addr::new(93, 184, 216, 34), 80));
        let mut c = relay_pending(&live, pend).await;
        c.write_all(b"x").await.unwrap();
        let mut b = [0u8; 1];
        c.read_exact(&mut b).await.unwrap();
        assert_eq!(seen.lock().unwrap().as_slice(), ["ip:93.184.216.34:80"]);
    }

    #[tokio::test]
    async fn block_rule_closes_without_touching_the_proxy() {
        let (proxy, seen) = echo_socks5().await;
        let live = mk_live(
            proxy,
            "[[rules]]\nmatch=\"domain-suffix\"\nvalue=\"bad.test\"\naction=\"block\"",
        );
        let pend = pending(Target::Domain("x.bad.test".into(), 80));
        let mut c = relay_pending(&live, pend).await;
        let mut b = [0u8; 1];
        assert_eq!(c.read(&mut b).await.unwrap_or(0), 0, "connection is closed");
        assert!(seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn direct_rule_connects_without_the_proxy() {
        let (proxy, seen) = echo_socks5().await;
        // A real local server standing in for the Internet host.
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_port = origin.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = origin.accept().await.unwrap();
            s.write_all(b"hello from origin").await.unwrap();
        });
        let live = mk_live(
            proxy,
            "[[rules]]\nmatch=\"domain\"\nvalue=\"localhost\"\naction=\"direct\"",
        );
        let pend = pending(Target::Domain("localhost".into(), origin_port));
        let mut c = relay_pending(&live, pend).await;
        let mut got = Vec::new();
        c.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"hello from origin");
        assert!(seen.lock().unwrap().is_empty(), "direct must bypass the proxy");
    }

    #[tokio::test]
    async fn localnet_targets_go_direct_whatever_the_rules_say() {
        let (proxy, seen) = echo_socks5().await;
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_port = origin.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = origin.accept().await.unwrap();
            s.write_all(b"hello from the lan").await.unwrap();
        });
        // localnet covers the origin; the rules would proxy everything.
        let cfg = Config::parse(&format!(
            "localnet = [\"127.0.0.0/8\"]\n[proxy]\ntype=\"socks5\"\naddr=\"{proxy}\"\n\
             [[rules]]\nmatch=\"final\"\naction=\"proxy\""
        ))
        .unwrap();
        let live = Arc::new(build_live(&cfg).unwrap());
        let mut c = relay_pending(&live, pending(Target::V4(Ipv4Addr::LOCALHOST, origin_port))).await;
        let mut got = Vec::new();
        // The echoing proxy would never close: bound the wait so a regression
        // fails instead of hanging.
        let read = tokio::time::timeout(Duration::from_secs(5), c.read_to_end(&mut got)).await;
        assert!(
            read.is_ok(),
            "no reply from the origin; got {:?}",
            String::from_utf8_lossy(&got)
        );
        assert_eq!(got, b"hello from the lan");
        assert!(seen.lock().unwrap().is_empty(), "localnet never reaches the proxy");
    }

    #[tokio::test]
    async fn proxy_down_fails_closed() {
        // Nothing listens on this proxy address.
        let dead = crate::testutil::refused();
        let live = mk_live(dead.addr, "");
        let pend = pending(Target::Domain("example.com".into(), 443));
        let mut c = relay_pending(&live, pend).await;
        let mut b = [0u8; 1];
        assert_eq!(c.read(&mut b).await.unwrap_or(0), 0, "closed, never silently direct");
    }

    #[tokio::test]
    async fn failover_to_second_proxy_member() {
        let (good, seen) = echo_socks5().await;
        let dead = crate::testutil::refused();
        let dead_addr = dead.addr;
        let cfg = Config::parse(&format!(
            r#"
            [[proxies]]
            name = "dead"
            type = "socks5"
            addr = "{dead_addr}"
            [[proxies]]
            name = "good"
            type = "socks5"
            addr = "{good}"
            [[groups]]
            name = "default"
            strategy = "round-robin"
            members = ["dead", "good"]
            "#
        ))
        .unwrap();
        let live = Arc::new(Live {
            policy: Policy::new(&cfg, env_proxies(std::iter::empty())).unwrap(),
            registry: Registry::build(&cfg).unwrap(),
            retries: 2,
            fail_threshold: 3,
            sniff: SniffCfg::default(),
        });
        for _ in 0..4 {
            let pend = pending(Target::Domain("example.com".into(), 443));
            let mut c = relay_pending(&live, pend).await;
            c.write_all(b"z").await.unwrap();
            let mut b = [0u8; 1];
            c.read_exact(&mut b).await.unwrap();
        }
        assert_eq!(
            seen.lock().unwrap().len(),
            4,
            "every connection ends up on the good proxy"
        );
    }

    #[tokio::test]
    async fn fake_ip_pin_is_held_for_the_connection_lifetime() {
        use crate::net::fakeip::FakePool;
        let (proxy, _) = echo_socks5().await;
        let live = mk_live(proxy, "");
        let pool = FakePool::new("10.9.0.0/30".parse().unwrap());
        let a = pool.alloc("a.test").unwrap();
        let b = pool.alloc("b.test").unwrap();
        let (dom, guard) = pool.acquire(a).unwrap();
        let pend = Pending {
            target: Target::Domain(dom, 80),
            guard: Some(guard),
        };
        let mut c = relay_pending(&live, pend).await;
        c.write_all(b"1").await.unwrap();
        let mut buf = [0u8; 1];
        c.read_exact(&mut buf).await.unwrap();
        // While the connection is open `a` is pinned: churn through the other
        // slot as hard as we like, `a` must keep its mapping.
        assert_eq!(pool.alloc("c.test").unwrap(), b);
        for i in 0..5 {
            pool.alloc(&format!("churn{i}.test")).unwrap();
        }
        assert_eq!(pool.lookup(a).as_deref(), Some("a.test"));
        drop(c);
        tokio::time::sleep(Duration::from_millis(300)).await;
        // Pin released: `a` is now the oldest entry and gets recycled.
        pool.alloc("after1.test").unwrap();
        pool.alloc("after2.test").unwrap();
        assert_ne!(pool.lookup(a).as_deref(), Some("a.test"));
    }

    // ------------------------------------------------------------ sniffing --

    fn sniff_cfg(ports: &[u16], ms: u64) -> SniffCfg {
        SniffCfg {
            enabled: true,
            ports: ports.to_vec(),
            skip: vec!["cloudflare-ech.com".into()],
            timeout: Duration::from_millis(ms),
            override_destination: true,
        }
    }

    async fn wait_seen(seen: &Arc<std::sync::Mutex<Vec<String>>>, n: usize) -> Vec<String> {
        for _ in 0..200 {
            if seen.lock().unwrap().len() >= n {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        seen.lock().unwrap().clone()
    }

    #[tokio::test]
    async fn literal_ip_with_a_tls_hello_is_sent_to_the_proxy_as_the_sni_domain() {
        let (proxy, seen) = echo_socks5().await;
        let live = mk_live(proxy, "");
        let pend = pending(Target::V4(Ipv4Addr::new(93, 184, 216, 34), 443));

        let hello = sniff::tests::client_hello(Some("Sniffed.Example.com"), &[]);
        let mut c = relay_pending(&live, pend).await;
        c.write_all(&hello).await.unwrap();
        let mut echoed = vec![0u8; hello.len()];
        c.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, hello, "peeking must not consume the ClientHello");
        assert_eq!(seen.lock().unwrap().as_slice(), ["domain:sniffed.example.com:443"]);
    }

    #[tokio::test]
    async fn sniffed_domain_is_subject_to_the_rules() {
        let (proxy, seen) = echo_socks5().await;
        let live = mk_live(
            proxy,
            "[[rules]]\nmatch=\"domain-suffix\"\nvalue=\"blocked.test\"\naction=\"block\"",
        );
        let pend = pending(Target::V4(Ipv4Addr::new(9, 9, 9, 9), 443));
        let mut c = relay_pending(&live, pend).await;
        c.write_all(&sniff::tests::client_hello(Some("x.blocked.test"), &[]))
            .await
            .unwrap();
        let mut b = [0u8; 1];
        assert_eq!(
            c.read(&mut b).await.unwrap_or(0),
            0,
            "domain rule applies after sniffing"
        );
        assert!(seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn silent_client_falls_back_to_the_ip_after_the_timeout() {
        let (proxy, seen) = echo_socks5().await;
        let live = mk_live_sniff(proxy, "", sniff_cfg(&[443], 120));
        let pend = pending(Target::V4(Ipv4Addr::new(5, 6, 7, 8), 443));
        let t0 = std::time::Instant::now();
        let _c = relay_pending(&live, pend).await; // sends nothing
        let got = wait_seen(&seen, 1).await;
        assert_eq!(got, ["ip:5.6.7.8:443"]);
        assert!(t0.elapsed() >= Duration::from_millis(100), "waited for the first bytes");
        assert!(t0.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn ech_public_names_and_non_tls_traffic_keep_the_literal_ip() {
        let (proxy, seen) = echo_socks5().await;
        let live = mk_live(proxy, "");
        for (i, payload) in [
            sniff::tests::client_hello(Some("cloudflare-ech.com"), &[(0xfe0d, vec![1, 2, 3])]),
            b"\x00\x01 definitely not tls or http".to_vec(),
        ]
        .into_iter()
        .enumerate()
        {
            let pend = pending(Target::V4(Ipv4Addr::new(1, 1, 1, i as u8 + 1), 443));
            let mut c = relay_pending(&live, pend).await;
            c.write_all(&payload).await.unwrap();
        }
        let mut got = wait_seen(&seen, 2).await;
        got.sort();
        assert_eq!(got, ["ip:1.1.1.1:443", "ip:1.1.1.2:443"]);
    }

    #[tokio::test]
    async fn only_sniff_ports_are_delayed_and_domain_targets_are_never_sniffed() {
        let (proxy, seen) = echo_socks5().await;
        let live = mk_live_sniff(proxy, "", sniff_cfg(&[443], 2000));

        // Port 80 is not a sniff port: dialed at once even though the client is silent.
        let pend = pending(Target::V4(Ipv4Addr::new(2, 2, 2, 2), 80));
        let t0 = std::time::Instant::now();
        let _c1 = relay_pending(&live, pend).await;
        let got = wait_seen(&seen, 1).await;
        assert_eq!(got, ["ip:2.2.2.2:80"]);
        assert!(
            t0.elapsed() < Duration::from_millis(1000),
            "no sniff delay on other ports"
        );

        // A domain target keeps its domain whatever the client sends.
        let pend = pending(Target::Domain("real.test".into(), 443));
        let mut c2 = relay_pending(&live, pend).await;
        c2.write_all(&sniff::tests::client_hello(Some("other.test"), &[]))
            .await
            .unwrap();
        let got = wait_seen(&seen, 2).await;
        assert_eq!(got[1], "domain:real.test:443");
    }

    #[tokio::test]
    async fn http_host_is_sniffed_on_configured_ports_and_disabling_turns_it_off() {
        let (proxy, seen) = echo_socks5().await;
        let live = mk_live_sniff(proxy, "", sniff_cfg(&[80], 500));
        let pend = pending(Target::V4(Ipv4Addr::new(3, 3, 3, 3), 80));
        let mut c = relay_pending(&live, pend).await;
        c.write_all(b"GET / HTTP/1.1\r\nHost: Web.Example.org\r\n\r\n")
            .await
            .unwrap();
        assert_eq!(wait_seen(&seen, 1).await, ["domain:web.example.org:80"]);

        let off = SniffCfg {
            enabled: false,
            ports: vec![80],
            skip: vec![],
            timeout: Duration::from_millis(500),
            override_destination: true,
        };
        let live = mk_live_sniff(proxy, "", off);
        let pend = pending(Target::V4(Ipv4Addr::new(4, 4, 4, 4), 80));
        let mut c = relay_pending(&live, pend).await;
        c.write_all(b"GET / HTTP/1.1\r\nHost: web.example.org\r\n\r\n")
            .await
            .unwrap();
        assert_eq!(wait_seen(&seen, 2).await[1], "ip:4.4.4.4:80");
    }

    #[tokio::test]
    async fn a_hello_arriving_in_pieces_is_still_sniffed() {
        let (proxy, seen) = echo_socks5().await;
        let live = mk_live_sniff(proxy, "", sniff_cfg(&[443], 1000));
        let pend = pending(Target::V4(Ipv4Addr::new(6, 6, 6, 6), 443));
        let hello = sniff::tests::client_hello(Some("pieces.example.com"), &[]);
        let mut c = relay_pending(&live, pend).await;
        c.set_nodelay(true).unwrap();
        let (a, b) = hello.split_at(hello.len() / 2);
        c.write_all(a).await.unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
        c.write_all(b).await.unwrap();
        assert_eq!(wait_seen(&seen, 1).await, ["domain:pieces.example.com:443"]);
    }

    #[tokio::test]
    async fn grease_ech_hello_still_yields_the_real_host() {
        // Chrome adds an ECH extension to every ClientHello; the SNI is real.
        let (proxy, seen) = echo_socks5().await;
        let live = mk_live(proxy, "");
        let pend = pending(Target::V4(Ipv4Addr::new(172, 66, 147, 243), 443));
        let mut c = relay_pending(&live, pend).await;
        c.write_all(&sniff::tests::client_hello(
            Some("example.com"),
            &[(0xfe0d, vec![0; 40])],
        ))
        .await
        .unwrap();
        assert_eq!(wait_seen(&seen, 1).await, ["domain:example.com:443"]);
    }

    #[test]
    fn skip_list_matches_the_name_and_its_subdomains_only() {
        let c = SniffCfg::default();
        assert!(c.skips("cloudflare-ech.com"));
        assert!(c.skips("x.cloudflare-ech.com"));
        assert!(!c.skips("notcloudflare-ech.com"));
        assert!(!c.skips("cloudflare.com"));
    }

    #[tokio::test]
    async fn a_lan_address_keeps_its_ip_even_with_a_hostname_in_the_payload() {
        // /etc/hosts: nas.lan -> 192.168.1.10; the program's TLS says nas.lan.
        let (proxy, seen) = echo_socks5().await;
        let live = mk_live(proxy, "");
        let pend = pending(Target::V4(Ipv4Addr::new(192, 168, 1, 10), 443));
        let mut c = relay_pending(&live, pend).await;
        c.write_all(&sniff::tests::client_hello(Some("nas.lan"), &[]))
            .await
            .unwrap();
        assert_eq!(wait_seen(&seen, 1).await, ["ip:192.168.1.10:443"]);
    }

    #[tokio::test]
    async fn an_ip_cidr_rule_for_the_address_beats_the_sniffed_name() {
        let (proxy, seen) = echo_socks5().await;
        let live = mk_live(
            proxy,
            "[[rules]]\nmatch=\"ip-cidr\"\nvalue=\"9.9.9.0/24\"\naction=\"block\"",
        );
        let pend = pending(Target::V4(Ipv4Addr::new(9, 9, 9, 9), 443));
        let mut c = relay_pending(&live, pend).await;
        c.write_all(&sniff::tests::client_hello(Some("allowed.example"), &[]))
            .await
            .unwrap();
        let mut b = [0u8; 1];
        assert_eq!(c.read(&mut b).await.unwrap_or(0), 0, "the ip-cidr block rule applies");
        assert!(seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn without_override_the_name_picks_the_rule_but_the_ip_is_dialed() {
        let (proxy, seen) = echo_socks5().await;
        let mut cfg = sniff_cfg(&[443], 500);
        cfg.override_destination = false;
        let live = mk_live_sniff(
            proxy,
            "[[rules]]\nmatch=\"domain-suffix\"\nvalue=\"blocked.test\"\naction=\"block\"",
            cfg,
        );
        // Routed by the sniffed name...
        let pend = pending(Target::V4(Ipv4Addr::new(5, 5, 5, 5), 443));
        let mut c = relay_pending(&live, pend).await;
        c.write_all(&sniff::tests::client_hello(Some("x.blocked.test"), &[]))
            .await
            .unwrap();
        let mut b = [0u8; 1];
        assert_eq!(c.read(&mut b).await.unwrap_or(0), 0, "domain rule still applies");
        // ...but an allowed one reaches the proxy as the original IP.
        let pend = pending(Target::V4(Ipv4Addr::new(5, 5, 5, 6), 443));
        let mut c = relay_pending(&live, pend).await;
        c.write_all(&sniff::tests::client_hello(Some("ok.example"), &[]))
            .await
            .unwrap();
        assert_eq!(wait_seen(&seen, 1).await, ["ip:5.5.5.6:443"]);
    }

    // ------------------------------------------------------------ pump --

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let c = TcpStream::connect(l.local_addr().unwrap()).await.unwrap();
        let (s, _) = l.accept().await.unwrap();
        (c, s)
    }

    type Pumped = tokio::task::JoinHandle<(Transfer, Result<()>, Arc<Traffic>)>;

    /// client <-> [a  pump  b] <-> server
    async fn pumped() -> (TcpStream, TcpStream, Pumped) {
        let (client, mut a) = tcp_pair().await;
        let (mut b, server) = tcp_pair().await;
        let traffic = Arc::new(Traffic::default());
        let h = tokio::spawn(async move {
            let (moved, r) = pump(&mut a, &mut b, &traffic).await;
            (moved, r, traffic)
        });
        (client, server, h)
    }

    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i.wrapping_mul(31) % 251) as u8).collect()
    }

    #[tokio::test]
    async fn pump_moves_a_large_payload_intact_in_both_directions() {
        let (mut client, mut server, h) = pumped().await;
        let up = pattern(16 << 20);
        let down = pattern(9 << 20);
        let (up2, down2) = (up.clone(), down.clone());
        let srv = tokio::spawn(async move {
            let mut got = vec![0u8; up2.len()];
            server.read_exact(&mut got).await.unwrap();
            assert!(got == up2, "client->server bytes differ");
            server.write_all(&down2).await.unwrap();
            server.shutdown().await.unwrap();
        });
        client.write_all(&up).await.unwrap();
        client.shutdown().await.unwrap();
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.unwrap();
        assert!(got == down, "server->client bytes differ");
        srv.await.unwrap();
        let (moved, r, traffic) = h.await.unwrap();
        r.unwrap();
        let (up, down) = (up.len() as u64, down.len() as u64);
        assert_eq!(moved, Transfer { up, down });
        assert_eq!(
            (traffic.up.load(Ordering::Relaxed), traffic.down.load(Ordering::Relaxed)),
            (up, down),
            "the shared totals follow"
        );
    }

    #[tokio::test]
    async fn pump_keeps_the_other_direction_open_after_a_half_close() {
        let (mut client, mut server, h) = pumped().await;
        client.write_all(b"request").await.unwrap();
        client.shutdown().await.unwrap(); // client is done sending
        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap(); // sees EOF after the data
        assert_eq!(got, b"request");
        server.write_all(b"late reply").await.unwrap(); // reverse path still works
        server.shutdown().await.unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"late reply");
        let (moved, r, _) = h.await.unwrap();
        r.unwrap();
        assert_eq!(moved, Transfer { up: 7, down: 10 });
    }

    #[tokio::test]
    async fn a_reset_peer_ends_the_pump_instead_of_hanging() {
        use std::os::fd::AsRawFd;
        let (mut client, mut server, h) = pumped().await;
        // Some bytes get through first: they must still be counted.
        client.write_all(&[7; 1000]).await.unwrap();
        let mut first = [0u8; 1000];
        server.read_exact(&mut first).await.unwrap();
        // Abortive close of the client: RST instead of FIN.
        let abortive = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        unsafe {
            libc::setsockopt(
                client.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                &abortive as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::linger>() as u32,
            );
        }
        drop(client);
        let mut buf = [0u8; 8];
        let _ = server.read(&mut buf).await;
        let r = tokio::time::timeout(Duration::from_secs(5), h).await;
        let (moved, r, _) = r.expect("the pump must end after a reset").unwrap();
        assert!(r.is_err(), "a reset is an error");
        assert_eq!(moved.up, 1000, "bytes moved before the error are counted");
    }
}
