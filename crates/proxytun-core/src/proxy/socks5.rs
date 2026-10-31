//! SOCKS5 (RFC 1928, username/password auth per RFC 1929). The domain goes to
//! the proxy as ATYP=0x03. The handshake is split where the blame for a
//! failure changes hands: `socks5_greet` is the proxy's own part,
//! `socks5_request` is answered only once the destination has.
//!
//! Generic over any `AsyncRead + AsyncWrite` stream so it can be unit-tested
//! against an in-memory pipe.

use super::TargetRefused;
use crate::types::Target;
use anyhow::{anyhow, bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

fn socks5_greeting(with_auth: bool) -> &'static [u8] {
    if with_auth {
        &[0x05, 0x02, 0x00, 0x02]
    } else {
        &[0x05, 0x01, 0x00]
    }
}

fn socks5_auth_request(user: &str, pass: &str) -> Result<Vec<u8>> {
    if user.len() > 255 || pass.len() > 255 {
        bail!("socks5: username/password longer than 255 bytes");
    }
    let mut v = vec![0x01u8, user.len() as u8];
    v.extend_from_slice(user.as_bytes());
    v.push(pass.len() as u8);
    v.extend_from_slice(pass.as_bytes());
    Ok(v)
}

pub(super) fn socks5_connect_request(t: &Target) -> Result<Vec<u8>> {
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
async fn socks5_handshake<S>(s: &mut S, t: &Target, user: Option<&str>, pass: Option<&str>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Build everything that can fail before touching the wire.
    let creds = socks5_creds(user, pass)?;
    let req = socks5_connect_request(t)?;
    socks5_greet(s, creds).await?;
    socks5_request(s, &req).await
}

pub(super) fn socks5_creds(user: Option<&str>, pass: Option<&str>) -> Result<Option<Vec<u8>>> {
    user.map(|u| socks5_auth_request(u, pass.unwrap_or(""))).transpose()
}

/// Greeting and authentication: the proxy's own part of the handshake.
pub(super) async fn socks5_greet<S>(s: &mut S, creds: Option<Vec<u8>>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    s.write_all(socks5_greeting(creds.is_some())).await?;
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
pub(super) async fn socks5_request<S>(s: &mut S, req: &[u8]) -> Result<()>
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::tests::dom;
    use std::net::Ipv4Addr;
    use tokio::io::duplex;

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
}
