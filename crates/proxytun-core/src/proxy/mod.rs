//! Outbound dialers. Both SOCKS5 and HTTP CONNECT preserve the *domain*:
//! SOCKS5 via ATYP=0x03 (domain), HTTP via `CONNECT host:port`. This is the
//! whole point: the proxy (Clash/sing-box) receives the hostname and can do
//! domain-based routing, instead of the pre-resolved IP that graftcp leaks.
//!
//! The handshakes are generic over any `AsyncRead + AsyncWrite` stream so they
//! can be unit-tested against an in-memory pipe.

use crate::balancer::{ConnGuard, Group, Node};
use crate::config::ProxyKind;
use crate::errno::{is_errno, is_local_shortage};
use crate::types::Target;
use anyhow::{anyhow, bail, Context, Result};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

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
pub struct TargetRefused {
    pub msg: String,
    pub about_target: bool,
    pub answered: bool,
}

impl std::fmt::Display for TargetRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for TargetRefused {}
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------- SOCKS5 --

pub fn socks5_greeting(with_auth: bool) -> Vec<u8> {
    if with_auth {
        vec![0x05, 0x02, 0x00, 0x02]
    } else {
        vec![0x05, 0x01, 0x00]
    }
}

pub fn socks5_auth_request(user: &str, pass: &str) -> Result<Vec<u8>> {
    if user.len() > 255 || pass.len() > 255 {
        bail!("socks5: username/password longer than 255 bytes");
    }
    let mut v = vec![0x01u8, user.len() as u8];
    v.extend_from_slice(user.as_bytes());
    v.push(pass.len() as u8);
    v.extend_from_slice(pass.as_bytes());
    Ok(v)
}

pub fn socks5_connect_request(t: &Target) -> Result<Vec<u8>> {
    let mut req = vec![0x05, 0x01, 0x00];
    match t {
        Target::Domain(d, p) => {
            if d.is_empty() || d.len() > 255 {
                bail!("socks5: domain length {} not in 1..=255", d.len());
            }
            req.push(0x03);
            req.push(d.len() as u8);
            req.extend_from_slice(d.as_bytes());
            req.extend_from_slice(&p.to_be_bytes());
        }
        Target::V4(ip, p) => {
            req.push(0x01);
            req.extend_from_slice(&ip.octets());
            req.extend_from_slice(&p.to_be_bytes());
        }
    }
    Ok(req)
}

fn socks5_rep_name(rep: u8) -> &'static str {
    match rep {
        0x01 => "general failure",
        0x02 => "not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "ttl expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown",
    }
}

#[cfg(test)]
pub async fn socks5_handshake<S>(s: &mut S, t: &Target, user: Option<&str>, pass: Option<&str>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Build everything that can fail before touching the wire.
    let creds = socks5_creds(user, pass)?;
    let req = socks5_connect_request(t)?;
    socks5_greet(s, creds).await?;
    socks5_request(s, &req).await
}

pub(crate) fn socks5_creds(user: Option<&str>, pass: Option<&str>) -> Result<Option<Vec<u8>>> {
    user.map(|u| socks5_auth_request(u, pass.unwrap_or(""))).transpose()
}

/// Greeting and authentication: the proxy's own part of the handshake.
pub(crate) async fn socks5_greet<S>(s: &mut S, creds: Option<Vec<u8>>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    s.write_all(&socks5_greeting(creds.is_some())).await?;
    let mut sel = [0u8; 2];
    s.read_exact(&mut sel).await.context("socks5: method selection")?;
    if sel[0] != 0x05 {
        bail!("socks5: bad version {:#x} in method selection", sel[0]);
    }
    match sel[1] {
        0x00 => {}
        0x02 => {
            let auth = creds.ok_or_else(|| anyhow!("socks5: proxy demands auth but none configured"))?;
            s.write_all(&auth).await?;
            let mut ar = [0u8; 2];
            s.read_exact(&mut ar).await.context("socks5: auth reply")?;
            if ar[1] != 0x00 {
                bail!("socks5: auth rejected");
            }
        }
        0xff => bail!("socks5: no acceptable auth method"),
        m => bail!("socks5: unexpected method {m:#x}"),
    }
    Ok(())
}

/// The connect request and its reply, which the proxy sends only once the
/// destination has answered (or not).
async fn socks5_request<S>(s: &mut S, req: &[u8]) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    s.write_all(req).await?;

    // reply: VER REP RSV ATYP BND.ADDR BND.PORT
    let mut head = [0u8; 4];
    if let Err(e) = s.read_exact(&mut head).await {
        use std::io::ErrorKind::{ConnectionAborted, ConnectionReset, UnexpectedEof};
        // Hung up instead of replying: what `ssh -D` does when it cannot
        // reach the destination, which another member (another server) may
        // well reach. Not the proxy's failure (it greeted us properly), nor a
        // success it reported: health untouched, and the next member tried
        // at once.
        if matches!(e.kind(), UnexpectedEof | ConnectionReset | ConnectionAborted) {
            return Err(TargetRefused {
                msg: format!("socks5: the proxy hung up instead of replying to the connect request ({e})"),
                about_target: false,
                answered: false,
            }
            .into());
        }
        return Err(anyhow::Error::new(e).context("socks5: connect reply"));
    }
    if head[0] != 0x05 {
        bail!("socks5: bad version {:#x} in reply", head[0]);
    }
    if head[1] != 0x00 {
        let msg = format!(
            "socks5: connect failed: {} (rep={:#x})",
            socks5_rep_name(head[1]),
            head[1]
        );
        return match head[1] {
            // Network/host unreachable, refused, TTL expired.
            0x03..=0x06 => Err(TargetRefused {
                msg,
                about_target: true,
                answered: true,
            }
            .into()),
            // Command / address type not supported: this proxy cannot do it.
            0x07 | 0x08 => Err(anyhow!(msg)),
            // General failure, not allowed by this proxy's rules (another's
            // may differ), unknown codes.
            _ => Err(TargetRefused {
                msg,
                about_target: false,
                answered: true,
            }
            .into()),
        };
    }
    let bnd = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            l[0] as usize
        }
        a => bail!("socks5: bad bound-address type {a:#x}"),
    };
    let mut drain = vec![0u8; bnd + 2];
    s.read_exact(&mut drain).await?;
    Ok(())
}

// ------------------------------------------------------------------ HTTP --

pub fn http_connect_request(t: &Target, user: Option<&str>, pass: Option<&str>) -> String {
    let hostport = match t {
        Target::Domain(d, p) => format!("{d}:{p}"),
        Target::V4(ip, p) => format!("{ip}:{p}"),
    };
    let mut req = format!("CONNECT {hostport} HTTP/1.1\r\nHost: {hostport}\r\n");
    if let Some(u) = user {
        let token = base64_encode(format!("{u}:{}", pass.unwrap_or("")).as_bytes());
        req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    req.push_str("Proxy-Connection: Keep-Alive\r\n\r\n");
    req
}

pub async fn http_handshake<S>(s: &mut S, t: &Target, user: Option<&str>, pass: Option<&str>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    s.write_all(http_connect_request(t, user, pass).as_bytes()).await?;

    // Read byte-by-byte up to the blank line so no tunnelled byte is consumed.
    let mut buf = Vec::with_capacity(256);
    let mut b = [0u8; 1];
    loop {
        if s.read(&mut b).await? == 0 {
            bail!("http connect: eof before end of headers");
        }
        buf.push(b[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8192 {
            bail!("http connect: response header too large");
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let status_line = head.lines().next().unwrap_or("");
    match status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
    {
        Some(200) => Ok(()),
        // Wrong or missing credentials, or no CONNECT support: a problem with
        // this proxy entry.
        Some(405 | 407) => bail!("http connect failed: {status_line}"),
        // The proxy failed to reach / timed out on the destination.
        Some(502 | 504) => Err(TargetRefused {
            msg: format!("http connect failed: {status_line}"),
            about_target: true,
            answered: true,
        }
        .into()),
        // 403 (this proxy's rules; another's may differ), 500, 503, ...:
        // maybe the destination, maybe the proxy itself.
        Some(_) => Err(TargetRefused {
            msg: format!("http connect failed: {status_line}"),
            about_target: false,
            answered: true,
        }
        .into()),
        None => bail!("http connect: malformed status line {status_line:?}"),
    }
}

/// Tiny base64 (no external dep) for Proxy-Authorization.
pub fn base64_encode(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            T[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

// ---------------------------------------------------------------- dialing --

/// Connect to one node and finish the proxy handshake for `t`. Only what is
/// the proxy's own doing counts against it: reaching it, and its greeting.
/// Proxies answer a connect request once the destination has (squid, ssh -D,
/// dante), so a request left unanswered is about the destination.
pub async fn dial_node(node: &Node, t: &Target) -> Result<TcpStream> {
    let user = node.cfg.username.as_deref();
    let pass = node.cfg.password.as_deref();
    // A destination no proxy can be asked for (an empty or overlong name):
    // found out before connecting, and nobody's fault.
    let socks = match node.cfg.kind {
        ProxyKind::Socks5 => Some((
            socks5_creds(user, pass)?,
            socks5_connect_request(t).map_err(|e| TargetRefused {
                msg: format!("{e:#}"),
                about_target: true,
                answered: false,
            })?,
        )),
        ProxyKind::Http => None,
    };
    let mut s = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(node.addr))
        .await
        .map_err(|_| anyhow!("connect to proxy {} timed out", node.name))?
        .with_context(|| format!("connect to proxy {} ({})", node.name, node.addr))?;
    s.set_nodelay(true).ok();
    let unanswered = || -> anyhow::Error {
        TargetRefused {
            msg: format!(
                "proxy {} got no answer from {t:?} within {}s",
                node.name,
                HANDSHAKE_TIMEOUT.as_secs()
            ),
            about_target: true,
            answered: false,
        }
        .into()
    };
    match socks {
        Some((creds, req)) => {
            // Each phase its own time: a slow greeting is the proxy's, and must
            // not shorten the wait for the destination.
            tokio::time::timeout(HANDSHAKE_TIMEOUT, socks5_greet(&mut s, creds))
                .await
                .map_err(|_| anyhow!("socks5 greeting of proxy {} timed out", node.name))??;
            tokio::time::timeout(HANDSHAKE_TIMEOUT, socks5_request(&mut s, &req))
                .await
                .map_err(|_| unanswered())??;
        }
        None => tokio::time::timeout(HANDSHAKE_TIMEOUT, http_handshake(&mut s, t, user, pass))
            .await
            .map_err(|_| unanswered())??,
    }
    Ok(s)
}

/// Pick a node from `group`, dial through it, and on failure try other members
/// (at most `retries` more). Only handshake failures are retried: no
/// application byte has been sent yet, so a retry is always safe.
pub async fn dial_group(
    group: &Group,
    t: &Target,
    retries: u32,
    fail_threshold: u32,
) -> Result<(TcpStream, ConnGuard, String)> {
    let key = t.host_key();
    let mut tried: Vec<usize> = Vec::new();
    let mut last_err = anyhow!("group '{}': no healthy proxy available", group.name);
    for _ in 0..=retries {
        let Some(i) = group.select(&key, &tried) else { break };
        tried.push(i);
        let node = &group.nodes[i];
        match dial_node(node, t).await {
            Ok(s) => {
                // Health only: this round trip includes the proxy reaching the
                // destination, so it is not a sample of the proxy hop latency
                // (that comes from the health prober).
                node.record_ok();
                return Ok((s, node.acquire(), node.name.clone()));
            }
            Err(e) if e.downcast_ref::<TargetRefused>().is_some() => {
                if e.downcast_ref::<TargetRefused>().is_some_and(|r| r.answered) {
                    node.record_ok();
                }
                if e.downcast_ref::<TargetRefused>().is_some_and(|r| r.about_target) {
                    tracing::debug!(proxy = %node.name, "destination refused by the proxy: {e:#}");
                    return Err(e);
                }
                tracing::debug!(proxy = %node.name, "proxy could not connect, trying another: {e:#}");
                last_err = e;
            }
            // Local ports run out per destination: another proxy may still
            // have plenty. Nobody's fault either way.
            Err(e) if is_errno(&e, libc::EADDRNOTAVAIL) => {
                tracing::warn!(proxy = %node.name, "no local port left towards this proxy, trying another: {e:#}");
                last_err = e;
            }
            Err(e) if is_local_shortage(&e) => {
                // Once in a while: out of fds, every connection fails so.
                static LOGGED: std::sync::Mutex<Option<std::time::Instant>> = std::sync::Mutex::new(None);
                let mut last = LOGGED.lock().unwrap_or_else(|e| e.into_inner());
                if crate::throttle::due(&mut last, std::time::Instant::now(), crate::throttle::EVERY) {
                    tracing::warn!(
                        proxy = %node.name,
                        "dial failed for lack of local resources: {e:#} (repeats within {}s not logged)",
                        crate::throttle::EVERY.as_secs()
                    );
                }
                return Err(e);
            }
            Err(e) => {
                node.record_failure(fail_threshold);
                tracing::warn!(proxy = %node.name, "dial failed: {e:#}");
                last_err = e;
            }
        }
    }
    Err(last_err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::io::duplex;

    fn dom(d: &str, p: u16) -> Target {
        Target::Domain(d.into(), p)
    }

    #[test]
    fn socks5_domain_request_uses_atyp_3() {
        let r = socks5_connect_request(&dom("example.com", 443)).unwrap();
        let mut want = vec![0x05, 0x01, 0x00, 0x03, 11];
        want.extend_from_slice(b"example.com");
        want.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(r, want, "the domain, not an IP, goes on the wire");
    }

    #[test]
    fn socks5_ip_requests() {
        let r = socks5_connect_request(&Target::V4(Ipv4Addr::new(1, 2, 3, 4), 80)).unwrap();
        assert_eq!(r, vec![5, 1, 0, 1, 1, 2, 3, 4, 0, 80]);
    }

    #[test]
    fn socks5_domain_length_limits() {
        assert!(socks5_connect_request(&dom(&"a".repeat(255), 1)).is_ok());
        assert!(socks5_connect_request(&dom(&"a".repeat(256), 1)).is_err());
        assert!(socks5_connect_request(&dom("", 1)).is_err());
    }

    #[test]
    fn socks5_auth_bytes_and_limits() {
        assert_eq!(socks5_auth_request("u", "pw").unwrap(), vec![1, 1, b'u', 2, b'p', b'w']);
        assert_eq!(socks5_auth_request("", "").unwrap(), vec![1, 0, 0]);
        assert!(socks5_auth_request(&"x".repeat(256), "p").is_err());
        assert!(socks5_auth_request("u", &"x".repeat(256)).is_err());
        assert_eq!(socks5_greeting(false), vec![5, 1, 0]);
        assert_eq!(socks5_greeting(true), vec![5, 2, 0, 2]);
    }

    /// Minimal scripted SOCKS5 server on the other end of a duplex pipe.
    async fn fake_socks5(
        mut s: tokio::io::DuplexStream,
        method: u8,
        auth_ok: bool,
        rep: u8,
        bnd_atyp: u8,
    ) -> (Vec<u8>, Vec<u8>) {
        let mut greet = [0u8; 3];
        s.read_exact(&mut greet).await.ok();
        // read the rest of the greeting when auth methods are offered
        if greet[1] == 2 {
            let mut extra = [0u8; 1];
            s.read_exact(&mut extra).await.ok();
        }
        s.write_all(&[0x05, method]).await.unwrap();
        let mut auth_seen = Vec::new();
        if method == 0x02 {
            let mut hdr = [0u8; 2];
            s.read_exact(&mut hdr).await.unwrap();
            let mut u = vec![0u8; hdr[1] as usize];
            s.read_exact(&mut u).await.unwrap();
            let mut pl = [0u8; 1];
            s.read_exact(&mut pl).await.unwrap();
            let mut p = vec![0u8; pl[0] as usize];
            s.read_exact(&mut p).await.unwrap();
            auth_seen = [hdr.to_vec(), u, pl.to_vec(), p].concat();
            s.write_all(&[1, if auth_ok { 0 } else { 1 }]).await.unwrap();
            if !auth_ok {
                return (auth_seen, vec![]);
            }
        }
        if method == 0xff {
            return (auth_seen, vec![]);
        }
        let mut head = [0u8; 4];
        s.read_exact(&mut head).await.unwrap();
        let mut req = head.to_vec();
        let rest = match head[3] {
            1 => 4 + 2,
            4 => 16 + 2,
            _ => {
                let mut l = [0u8; 1];
                s.read_exact(&mut l).await.unwrap();
                req.push(l[0]);
                l[0] as usize + 2
            }
        };
        let mut tail = vec![0u8; rest];
        s.read_exact(&mut tail).await.unwrap();
        req.extend(tail);
        let mut reply = vec![5, rep, 0, bnd_atyp];
        match bnd_atyp {
            1 => reply.extend_from_slice(&[0, 0, 0, 0, 0, 0]),
            4 => reply.extend_from_slice(&[0u8; 18]),
            _ => {
                reply.push(3);
                reply.extend_from_slice(b"abc");
                reply.extend_from_slice(&[0, 0]);
            }
        }
        s.write_all(&reply).await.unwrap();
        (auth_seen, req)
    }

    #[tokio::test]
    async fn socks5_handshake_no_auth_ok() {
        let (mut c, srv) = duplex(1024);
        let t = dom("example.com", 443);
        let server = tokio::spawn(fake_socks5(srv, 0x00, true, 0, 1));
        socks5_handshake(&mut c, &t, None, None).await.unwrap();
        let (_, req) = server.await.unwrap();
        assert_eq!(req, socks5_connect_request(&t).unwrap());
    }

    #[tokio::test]
    async fn socks5_handshake_with_auth_and_domain_bound_addr() {
        let (mut c, srv) = duplex(1024);
        let server = tokio::spawn(fake_socks5(srv, 0x02, true, 0, 3));
        socks5_handshake(&mut c, &dom("a.b", 1), Some("bob"), Some("pw"))
            .await
            .unwrap();
        let (auth, _) = server.await.unwrap();
        assert_eq!(auth, socks5_auth_request("bob", "pw").unwrap());
    }

    #[tokio::test]
    async fn socks5_handshake_ipv6_bound_addr() {
        let (mut c, srv) = duplex(1024);
        let server = tokio::spawn(fake_socks5(srv, 0x00, true, 0, 4));
        socks5_handshake(&mut c, &dom("x.y", 1), None, None).await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_handshake_errors() {
        // auth rejected
        let (mut c, srv) = duplex(1024);
        let h = tokio::spawn(fake_socks5(srv, 0x02, false, 0, 1));
        let e = socks5_handshake(&mut c, &dom("a.b", 1), Some("u"), Some("p"))
            .await
            .unwrap_err();
        assert!(e.to_string().contains("auth rejected"), "{e:#}");
        h.await.unwrap();

        // no acceptable method
        let (mut c, srv) = duplex(1024);
        let h = tokio::spawn(fake_socks5(srv, 0xff, true, 0, 1));
        let e = socks5_handshake(&mut c, &dom("a.b", 1), None, None).await.unwrap_err();
        assert!(e.to_string().contains("no acceptable"), "{e:#}");
        h.await.unwrap();

        // proxy wants auth but we have none
        let (mut c, srv) = duplex(1024);
        let h = tokio::spawn(fake_socks5(srv, 0x02, true, 0, 1));
        let e = socks5_handshake(&mut c, &dom("a.b", 1), None, None).await.unwrap_err();
        assert!(e.to_string().contains("demands auth"), "{e:#}");
        drop(c);
        let _ = h.await;

        // connect refused by the proxy
        let (mut c, srv) = duplex(1024);
        let h = tokio::spawn(fake_socks5(srv, 0x00, true, 0x05, 1));
        let e = socks5_handshake(&mut c, &dom("a.b", 1), None, None).await.unwrap_err();
        assert!(e.to_string().contains("connection refused"), "{e:#}");
        h.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_handshake_truncated_reply_is_an_error() {
        let (mut c, mut srv) = duplex(1024);
        tokio::spawn(async move {
            let mut b = [0u8; 3];
            srv.read_exact(&mut b).await.ok();
            srv.write_all(&[5]).await.ok(); // only half of the method reply
            drop(srv);
        });
        assert!(socks5_handshake(&mut c, &dom("a.b", 1), None, None).await.is_err());
    }

    #[test]
    fn http_connect_request_shapes() {
        let r = http_connect_request(&dom("example.com", 443), None, None);
        assert!(r.starts_with("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n"));
        assert!(r.ends_with("\r\n\r\n"));
        assert!(!r.contains("Proxy-Authorization"));

        let r = http_connect_request(&dom("a.b", 1), Some("Aladdin"), Some("open sesame"));
        assert!(
            r.contains("Proxy-Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\n"),
            "{r}"
        );
    }

    #[test]
    fn base64_rfc4648_vectors() {
        for (i, o) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(i.as_bytes()), o);
        }
    }

    async fn http_server(mut s: tokio::io::DuplexStream, reply: &'static [u8]) -> String {
        let mut got = Vec::new();
        let mut b = [0u8; 1];
        while !got.ends_with(b"\r\n\r\n") {
            s.read_exact(&mut b).await.unwrap();
            got.push(b[0]);
        }
        s.write_all(reply).await.unwrap();
        s.write_all(b"TUNNELED").await.unwrap();
        String::from_utf8(got).unwrap()
    }

    #[tokio::test]
    async fn http_handshake_ok_does_not_swallow_tunnel_bytes() {
        let (mut c, srv) = duplex(1024);
        let h = tokio::spawn(http_server(srv, b"HTTP/1.1 200 Connection established\r\nX: y\r\n\r\n"));
        http_handshake(&mut c, &dom("example.com", 443), None, None)
            .await
            .unwrap();
        let mut rest = [0u8; 8];
        c.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"TUNNELED");
        assert!(h.await.unwrap().starts_with("CONNECT example.com:443"));
    }

    #[tokio::test]
    async fn http_handshake_rejects_non_200_and_truncation() {
        let (mut c, srv) = duplex(1024);
        let h = tokio::spawn(http_server(srv, b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"));
        let e = http_handshake(&mut c, &dom("a.b", 1), None, None).await.unwrap_err();
        assert!(e.to_string().contains("407"), "{e:#}");
        h.await.unwrap();

        let (mut c, mut srv) = duplex(1024);
        tokio::spawn(async move {
            srv.write_all(b"HTTP/1.1 200 OK\r\n").await.ok();
            drop(srv);
        });
        assert!(http_handshake(&mut c, &dom("a.b", 1), None, None).await.is_err());
    }

    #[tokio::test]
    async fn http_handshake_caps_header_size() {
        let (mut c, mut srv) = duplex(64 * 1024);
        tokio::spawn(async move {
            srv.write_all(&vec![b'a'; 20_000]).await.ok();
            std::future::pending::<()>().await;
        });
        let e = http_handshake(&mut c, &dom("a.b", 1), None, None).await.unwrap_err();
        assert!(e.to_string().contains("too large"), "{e:#}");
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
                assert!(dial_group(&g, &dom("dead.example", 443), 2, 3).await.is_err());
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
            let e = dial_group(&g, &dom("black.hole", 443), 2, 1)
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
            assert!(dial_group(&g, &dom("x.example", 443), 0, 1).await.is_err());
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
            dial_group(&g, &dom("x.example", 443), 2, 1).await.unwrap();
        }
        assert!(g.nodes[0].is_healthy(), "hanging up is not a broken proxy");
        assert_eq!(g.nodes[0].stats().ok_total, 0, "nor a success it reported");
        assert!(a_hits.load(Ordering::SeqCst) > 0, "a was asked");
        assert_eq!(b_hits.load(Ordering::SeqCst), 6, "and b got every one");
        // All members hang up: it fails, still blaming none.
        let (c, _) = scripted_proxy(Reply::SocksHangsUp).await;
        let g = Group::new("g", Strategy::RoundRobin, vec![node_at("c", c, ProxyKind::Socks5)]).unwrap();
        for _ in 0..3 {
            assert!(dial_group(&g, &dom("x.example", 443), 2, 1).await.is_err());
        }
        assert!(g.nodes[0].is_healthy());
    }

    #[tokio::test]
    async fn a_destination_no_proxy_can_be_asked_for_costs_no_connection() {
        let (a, hits) = scripted_proxy(Reply::Socks(0)).await;
        let g = Group::new("g", Strategy::RoundRobin, vec![node_at("a", a, ProxyKind::Socks5)]).unwrap();
        for d in ["", &"x".repeat(256)] {
            let e = dial_group(&g, &dom(d, 80), 2, 1).await.err().expect("must fail");
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
        // one HANDSHAKE_TIMEOUT, but each phase is within its own.
        let (a, _) = scripted_proxy(Reply::SlowGreeting).await;
        let g = Group::new("g", Strategy::RoundRobin, vec![node_at("a", a, ProxyKind::Socks5)]).unwrap();
        assert!(dial_group(&g, &dom("slow.example", 443), 0, 1).await.is_ok());
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
            dial_group(&g, &dom("ok.example", 443), 2, 3).await.unwrap();
        }
        assert!(!g.nodes[0].is_healthy(), "repeated 407 marks the entry down");
        assert_eq!(good_hits.load(Ordering::SeqCst), 3);

        // Nothing listening: also a proxy failure.
        let dead = crate::testutil::refused();
        let n = node_at("dead", dead.addr, ProxyKind::Socks5);
        let g = Group::new("g", Strategy::RoundRobin, vec![n]).unwrap();
        assert!(dial_group(&g, &dom("x.example", 443), 0, 1).await.is_err());
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
                dial_group(&g, &dom("x.example", 443), 2, 1)
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
                dial_group(&g, &dom("x.example", 443), 2, 1).await.unwrap();
            }
            assert!(!g.nodes[0].is_healthy(), "marked down");
            assert_eq!(b_hits.load(Ordering::SeqCst), 3);
        }
    }

    #[tokio::test]
    async fn successful_connections_do_not_feed_the_latency_estimate() {
        let (a, _) = scripted_proxy(Reply::Socks(0)).await;
        let g = Group::new("g", Strategy::RoundRobin, vec![node_at("a", a, ProxyKind::Socks5)]).unwrap();
        dial_group(&g, &dom("x.example", 443), 0, 3).await.unwrap();
        assert_eq!(g.nodes[0].latency_us(), 0, "only health probes measure the proxy hop");
        assert_eq!(g.nodes[0].stats().ok_total, 1);
    }
}
