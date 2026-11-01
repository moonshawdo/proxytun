//! TCP relay. The capture side accepts the program's connection and works out
//! where it was going (`Pending`); `route` does the rest: sniff a hostname if
//! the target is a bare IP, run the rule engine, then copy bytes to a proxy
//! group / straight out / nowhere.

use crate::live::{Live, SniffCfg};
use crate::net::fakeip::FakeGuard;
use crate::net::pump::{finish, Traffic};
use crate::policy::Policy;
use crate::proxy;
use crate::sniff::{self, Sniffed};
use crate::types::{Decision, Target};
use anyhow::{anyhow, Result};
use std::io;
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tracing::{field, Span};

/// One captured connection handed to the relay: where the program meant to go.
pub struct Pending {
    pub target: Target,
    /// Keeps the fake-ip mapping pinned (un-evictable) while the connection lives.
    pub guard: Option<FakeGuard>,
}

/// Carry one accepted connection to its target and log how it ended.
/// Records `target` on the caller's span, which names the connection in
/// every log line.
pub async fn route(live: &Live, traffic: &Traffic, inbound: TcpStream, pending: Pending) -> Result<()> {
    let start = Instant::now();
    let Pending { target, guard } = pending;
    // localnet and the program's own proxies: straight out, untouched.
    let passthrough = match target {
        Target::V4(ip, port) => live.policy.is_passthrough(ip, port),
        Target::Domain(..) => false,
    };
    // A name sniffed from a literal IP's first bytes (a domain target is
    // never sniffed, so never copied).
    let mut sniffed = None;
    if !passthrough {
        if let Some(domain) = maybe_sniff(&inbound, &target, &live.sniff, &live.policy).await {
            tracing::debug!(ip = ?target, %domain, "recovered hostname from the first bytes");
            sniffed = Some(Target::Domain(domain, target.port()));
        }
    }
    // `target` is what we connect to, `rule_target` what the rules look at.
    let rule_target = sniffed.as_ref().unwrap_or(&target);
    let target = if live.sniff.override_destination {
        rule_target
    } else {
        &target
    };
    Span::current().record("target", field::debug(target));
    let decision = if passthrough {
        tracing::info!(decision = ?Decision::Direct, "routing (localnet)");
        Decision::Direct
    } else {
        let d = live.policy.decide(rule_target);
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
        Decision::Direct => dial_direct(target, live.connect_timeout)
            .await
            .map(|s| (s, None, "direct".to_string())),
        Decision::Proxy { group } => match live.registry.group(&group) {
            Some(g) => proxy::dial_group(g, target, live.retries, live.fail_threshold, live.connect_timeout)
                .await
                .map(|(s, conn, node)| (s, Some(conn), node)),
            None => Err(anyhow!("rule names unknown group '{group}'")),
        },
    };
    let dial = dial_start.elapsed();
    // `_conn` counts the connection as active on its proxy while it lasts.
    let (out, _conn, via) = match dialed {
        Ok((out, conn, via)) => {
            out.set_nodelay(true).ok();
            keepalive(&out);
            (Ok(out), conn, via)
        }
        Err(e) => (Err(e), None, "-".to_string()),
    };
    finish(inbound, out, traffic, start, dial, &via).await
}

/// Notice a dead path to the proxy or target, which nothing else would: the
/// program's own keepalives are answered by our listener, right next to it.
/// Idle, the first probe goes after 60 s, then every 15 s; four unanswered,
/// the connection fails, and the relay with it, resetting the program. No
/// TCP_USER_TIMEOUT: it would also end a transfer whose receiver merely
/// stops reading for a while (a zero window); data that cannot get through
/// a dead path ends the connection after the kernel's own retries.
fn keepalive(s: &TcpStream) {
    let fd = s.as_raw_fd();
    for (level, opt, v) in [
        (libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1),
        (libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, 60),
        (libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, 15),
        (libc::IPPROTO_TCP, libc::TCP_KEEPCNT, 4),
    ] {
        let v: libc::c_int = v;
        // SAFETY: an int option on a socket we own.
        unsafe {
            libc::setsockopt(
                fd,
                level,
                opt,
                &v as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
    }
}

/// For a literal-IP target on a sniff port, peek (without consuming) the
/// client's first bytes and try to read a hostname out of them. Any failure or
/// timeout keeps the literal IP, so the worst case is a short extra wait.
async fn maybe_sniff(inbound: &TcpStream, target: &Target, cfg: &SniffCfg, policy: &Policy) -> Option<String> {
    let ip = match target {
        Target::Domain(..) => return None,
        Target::V4(ip, _) => *ip,
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

/// Host-name lookups for direct rules run on blocking threads (getaddrinfo,
/// seconds on a slow resolver): at most this many at once, fewer than the
/// runtime's 64 blocking threads. So a lookup never waits in that pool's
/// queue, where one given up at its timeout would still run later and hold
/// up those behind it; past the limit a connection fails at once instead.
pub const MAX_LOOKUPS: usize = 32;
static LOOKUPS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(MAX_LOOKUPS);

async fn lookup(
    slots: &'static tokio::sync::Semaphore,
    host: &str,
    port: u16,
) -> io::Result<Vec<std::net::SocketAddr>> {
    let Ok(slot) = slots.try_acquire() else {
        static WARNED: crate::throttle::Throttle = crate::throttle::Throttle::new();
        if WARNED.due() {
            tracing::warn!(
                "{MAX_LOOKUPS} host name lookups for direct rules under way (a slow resolver?): failing \
                 new direct connections to names (repeats within {}s not logged)",
                crate::throttle::EVERY.as_secs()
            );
        }
        return Err(io::Error::other(format!(
            "{MAX_LOOKUPS} host name lookups already under way"
        )));
    };
    let host = host.to_owned();
    tokio::task::spawn_blocking(move || {
        let _slot = slot; // held until getaddrinfo is done, however long
        std::net::ToSocketAddrs::to_socket_addrs(&(host.as_str(), port)).map(Iterator::collect)
    })
    .await
    .map_err(io::Error::other)?
}

/// Direct connect. For a domain we must resolve it ourselves now, because the
/// program was handed a *fake* IP; the real one was never resolved on its side.
async fn dial_direct(t: &Target, timeout: Duration) -> Result<TcpStream> {
    let fut = async {
        match t {
            Target::Domain(d, p) => TcpStream::connect(&lookup(&LOOKUPS, d, *p).await?[..]).await,
            Target::V4(ip, p) => TcpStream::connect((*ip, *p)).await,
        }
    };
    Ok(tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| anyhow!("direct connect to {t:?} timed out"))??)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::live::build_live;
    use crate::policy::EnvProxies;
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
        Arc::new(live_for(proxy, rules))
    }

    fn mk_live_sniff(proxy: SocketAddr, rules: &str, sniff: SniffCfg) -> Arc<Live> {
        Arc::new(Live {
            sniff,
            ..live_for(proxy, rules)
        })
    }

    /// One SOCKS5 proxy at `proxy`, `rules`, and the defaults for the rest.
    fn live_for(proxy: SocketAddr, rules: &str) -> Live {
        let cfg = Config::parse(&format!("[proxy]\ntype=\"socks5\"\naddr=\"{proxy}\"\n{rules}")).unwrap();
        Live::new(&cfg, EnvProxies::default()).unwrap()
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
    async fn a_direct_destination_that_never_answers_is_reset_after_the_connect_timeout() {
        let (proxy, seen) = echo_socks5().await;
        let (_l, _queued, hole) = crate::proxy::tests::black_hole();
        let cfg = Config::parse(&format!(
            "connect_timeout_ms = 200\n[proxy]\ntype=\"socks5\"\naddr=\"{proxy}\"\n\
             [[rules]]\nmatch=\"ip-cidr\"\nvalue=\"{}/32\"\naction=\"direct\"",
            hole.ip()
        ))
        .unwrap();
        let live = Arc::new(Live::new(&cfg, EnvProxies::default()).unwrap());
        let SocketAddr::V4(hole) = hole else { unreachable!() };
        let mut c = relay_pending(&live, pending(Target::V4(*hole.ip(), hole.port()))).await;
        let r = tokio::time::timeout(Duration::from_secs(3), c.read(&mut [0u8; 1])).await;
        let r = r.expect("given up after the configured 200 ms, not the default 10 s");
        assert_eq!(r.map_err(|e| e.kind()), Err(std::io::ErrorKind::ConnectionReset));
        assert!(seen.lock().unwrap().is_empty(), "no fallback to the proxy");
    }

    #[tokio::test]
    async fn a_proxy_that_never_accepts_resets_the_program_after_the_connect_timeout() {
        let (_l, _queued, hole) = crate::proxy::tests::black_hole();
        let cfg = Config::parse(&format!(
            "connect_timeout_ms = 200\n[proxy]\ntype=\"socks5\"\naddr=\"{hole}\"\n"
        ))
        .unwrap();
        let live = Arc::new(Live::new(&cfg, EnvProxies::default()).unwrap());
        let mut c = relay_pending(&live, pending(Target::Domain("x.example".into(), 443))).await;
        let r = tokio::time::timeout(Duration::from_secs(3), c.read(&mut [0u8; 1])).await;
        let r = r.expect("given up after the configured 200 ms, not the default 10 s");
        assert_eq!(r.map_err(|e| e.kind()), Err(std::io::ErrorKind::ConnectionReset));
    }

    #[tokio::test]
    async fn the_connect_timeout_bounds_the_dial_only_never_an_idle_connection() {
        let (proxy, _) = echo_socks5().await;
        // An echoing origin for the direct route.
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let SocketAddr::V4(at) = origin.local_addr().unwrap() else {
            unreachable!()
        };
        tokio::spawn(async move {
            let (mut s, _) = origin.accept().await.unwrap();
            let (mut r, mut w) = s.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });
        let cfg = Config::parse(&format!(
            "connect_timeout_ms = 200\n[proxy]\ntype=\"socks5\"\naddr=\"{proxy}\"\n\
             [[rules]]\nmatch=\"ip-cidr\"\nvalue=\"{}/32\"\naction=\"direct\"",
            at.ip()
        ))
        .unwrap();
        let live = Arc::new(Live::new(&cfg, EnvProxies::default()).unwrap());
        let via_proxy = relay_pending(&live, pending(Target::Domain("x.example".into(), 443))).await;
        let direct = relay_pending(&live, pending(Target::V4(*at.ip(), at.port()))).await;
        for (what, mut c) in [("proxied", via_proxy), ("direct", direct)] {
            c.write_all(b"before").await.unwrap();
            let mut b = [0u8; 6];
            c.read_exact(&mut b).await.unwrap();
            // Idle for five times the connect timeout, then talk again.
            tokio::time::sleep(Duration::from_secs(1)).await;
            c.write_all(b"after!").await.unwrap();
            tokio::time::timeout(Duration::from_secs(3), c.read_exact(&mut b))
                .await
                .unwrap_or_else(|_| panic!("{what}: no echo after idling"))
                .unwrap_or_else(|e| panic!("{what}: ended while idle: {e}"));
            assert_eq!(&b, b"after!", "{what}");
        }
    }

    #[tokio::test]
    async fn proxy_down_fails_closed() {
        // Nothing listens on this proxy address. The target is one a direct
        // dial would reach, and say so: it must not be dialed.
        let dead = crate::testutil::refused();
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = origin.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = origin.accept().await {
                let _ = s.write_all(b"reached directly").await;
            }
        });
        let live = mk_live(dead.addr, "");
        let pend = pending(Target::Domain("localhost".into(), port));
        let mut c = relay_pending(&live, pend).await;
        let mut got = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), c.read_to_end(&mut got)).await;
        assert!(
            got.is_empty(),
            "never silently direct: {:?}",
            String::from_utf8_lossy(&got)
        );
    }

    #[tokio::test]
    async fn an_abort_reaches_the_other_side_as_a_reset_not_an_end() {
        let (proxy, _) = echo_socks5().await;
        let direct = "[[rules]]\nmatch=\"domain\"\nvalue=\"localhost\"\naction=\"direct\"";
        let reset = |r: std::io::Result<usize>| r.map_err(|e| e.kind());
        // Nothing to reach: the program learns so, it does not see an empty
        // reply.
        let live = mk_live(crate::testutil::refused().addr, "");
        let mut c = relay_pending(&live, pending(Target::Domain("example.com".into(), 443))).await;
        let mut b = [0u8; 16];
        assert_eq!(reset(c.read(&mut b).await), Err(std::io::ErrorKind::ConnectionReset));

        // The target cuts the transfer off: the program gets what came, then
        // the reset, not a clean end that passes for a complete download.
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = origin.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = origin.accept().await.unwrap();
            s.write_all(b"part").await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            s.set_zero_linger().unwrap();
        });
        let live = mk_live(proxy, direct);
        let mut c = relay_pending(&live, pending(Target::Domain("localhost".into(), port))).await;
        let mut got = [0u8; 4];
        c.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"part");
        assert_eq!(reset(c.read(&mut b).await), Err(std::io::ErrorKind::ConnectionReset));

        // The program aborts an upload: the target must not take it for a
        // finished one.
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = origin.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut s, _) = origin.accept().await.unwrap();
            let mut buf = Vec::new();
            let _ = tx.send(s.read_to_end(&mut buf).await.map_err(|e| e.kind()));
        });
        let mut c = relay_pending(&live, pending(Target::Domain("localhost".into(), port))).await;
        c.write_all(b"half an upload").await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        c.set_zero_linger().unwrap();
        drop(c);
        let seen = tokio::time::timeout(Duration::from_secs(5), rx).await.unwrap().unwrap();
        assert_eq!(seen, Err(std::io::ErrorKind::ConnectionReset));
    }

    #[tokio::test]
    async fn keepalive_probes_idle_paths_and_never_times_out_a_slow_reader() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let s = TcpStream::connect(l.local_addr().unwrap()).await.unwrap();
        keepalive(&s);
        let get = |level, opt| {
            let mut v: libc::c_int = -1;
            let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            unsafe { libc::getsockopt(s.as_raw_fd(), level, opt, &mut v as *mut _ as *mut _, &mut len) };
            v
        };
        assert_eq!(get(libc::SOL_SOCKET, libc::SO_KEEPALIVE), 1);
        assert_eq!(get(libc::IPPROTO_TCP, libc::TCP_KEEPIDLE), 60);
        // A receiver that stops reading for minutes (a zero window) is not
        // a dead path: no user timeout may end the transfer.
        assert_eq!(get(libc::IPPROTO_TCP, libc::TCP_USER_TIMEOUT), 0);
    }

    #[tokio::test]
    async fn the_way_out_is_probed_while_idle() {
        let (proxy, _) = echo_socks5().await;
        let live = mk_live(proxy, "");
        let mut c = relay_pending(&live, pending(Target::Domain("example.com".into(), 443))).await;
        c.write_all(b"x").await.unwrap();
        c.read_exact(&mut [0u8; 1]).await.unwrap();
        // Our connection to the proxy, idle now: its keepalive timer runs
        // ("tr" 2 in /proc/net/tcp).
        let SocketAddr::V4(p) = proxy else { unreachable!() };
        let rem = format!("{:08X}:{:04X}", u32::from_le_bytes(p.ip().octets()), p.port());
        let tcp = std::fs::read_to_string("/proc/net/tcp").unwrap();
        let ours: Vec<&str> = tcp
            .lines()
            .map(str::split_whitespace)
            .filter_map(|mut f| {
                let (_, _, r, st, _, tr) = (f.next()?, f.next()?, f.next()?, f.next()?, f.next()?, f.next()?);
                (r == rem && st == "01").then_some(tr)
            })
            .collect();
        assert_eq!(ours.len(), 1, "{tcp}");
        assert!(ours[0].starts_with("02:"), "no keepalive timer: {}", ours[0]);
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
        let live = Arc::new(Live::new(&cfg, EnvProxies::default()).unwrap());
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
        use crate::net::fakeip::{FakePool, REUSE_AFTER};
        let (proxy, _) = echo_socks5().await;
        let live = mk_live(proxy, "");
        let pool = FakePool::new("10.9.0.0/30".parse().unwrap());
        // Time is driven by hand: a slot is recycled only once its last use
        // is REUSE_AFTER old.
        let t = std::time::Instant::now();
        let at = |n: u32| t + n * REUSE_AFTER;
        let a = pool.alloc_at("a.test", at(0)).unwrap();
        let b = pool.alloc_at("b.test", at(0)).unwrap();
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
        assert_eq!(pool.alloc_at("c.test", at(2)).unwrap(), b);
        for i in 0..5 {
            pool.alloc_at(&format!("churn{i}.test"), at(4 + 2 * i)).unwrap();
        }
        assert_eq!(pool.lookup(a).as_deref(), Some("a.test"));
        drop(c);
        tokio::time::sleep(Duration::from_millis(300)).await;
        // Pin released (and used just now): once that use is old enough, `a`
        // is the oldest entry and gets recycled.
        pool.alloc_at("after1.test", at(20)).unwrap();
        pool.alloc_at("after2.test", at(22)).unwrap();
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

    #[tokio::test]
    async fn direct_lookups_beyond_the_limit_fail_at_once() {
        let slots: &'static tokio::sync::Semaphore = Box::leak(Box::new(tokio::sync::Semaphore::new(1)));
        let addrs = lookup(slots, "localhost", 80).await.unwrap();
        assert!(addrs.iter().any(|a| a.ip().is_loopback()), "{addrs:?}");
        // The only slot taken (a lookup still waiting on a slow resolver).
        let _busy = slots.try_acquire().unwrap();
        let t0 = Instant::now();
        let e = lookup(slots, "localhost", 80).await.unwrap_err();
        assert!(e.to_string().contains("lookups already under way"), "{e}");
        assert!(t0.elapsed() < Duration::from_millis(100), "not queued");
    }
}
