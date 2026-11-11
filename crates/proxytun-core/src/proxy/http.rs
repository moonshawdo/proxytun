//! HTTP CONNECT: `CONNECT host:port`, so the proxy gets the domain, with
//! Basic auth when a username is set. A proxy answers only once the
//! destination has, so the whole handshake waits on the destination.
//!
//! Generic over any `AsyncRead + AsyncWrite` stream so it can be unit-tested
//! against an in-memory pipe.

use super::TargetRefused;
use crate::types::Target;
use anyhow::{bail, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

fn http_connect_request(t: &Target, user: Option<&str>, pass: Option<&str>) -> String {
    let hostport = match t {
        Target::Domain(d, p) => format!("{d}:{p}"),
        Target::V4(ip, p) => format!("{ip}:{p}"),
    };
    // CONNECT takes host:port (the authority form) as its target; Host repeats it, as
    // HTTP/1.1 requires a Host header in every request.
    let mut req = format!("CONNECT {hostport} HTTP/1.1\r\nHost: {hostport}\r\n");
    // Basic auth: base64 of "user:password".
    if let Some(u) = user {
        let token = base64_encode(format!("{u}:{}", pass.unwrap_or("")).as_bytes());
        req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    req.push_str("Proxy-Connection: Keep-Alive\r\n\r\n");
    req
}

pub(super) async fn http_handshake<S>(s: &mut S, t: &Target, user: Option<&str>, pass: Option<&str>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    s.write_all(http_connect_request(t, user, pass).as_bytes()).await?;

    // Read byte-by-byte up to the blank line so no tunnelled byte is consumed.
    let mut buf = Vec::with_capacity(256);
    let mut b = [0u8; 1];
    loop {
        // A hang-up before the header is complete counts against the proxy, unlike a
        // SOCKS5 proxy hanging up on the connect request (see `socks5_request`).
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
    // Only the status line counts ("HTTP/1.1 <code> <reason>"): its second word is the
    // status code. The header fields after it are ignored.
    let head = String::from_utf8_lossy(&buf);
    let status_line = head.lines().next().unwrap_or("");
    match status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
    {
        // Any 2xx: the tunnel is up (RFC 9110 9.3.6), most proxies say 200.
        Some(200..=299) => Ok(()),
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
fn base64_encode(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    // Every 3 input bytes become 4 characters of 6 bits each. A last chunk of 1 or 2 bytes
    // is zero-filled, and the characters made only of that filler are written as '='.
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        // The chunk as one 24-bit number, cut below into four 6-bit indices into `T`.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::tests::dom;
    use tokio::io::duplex;

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
    async fn http_handshake_takes_any_2xx_as_the_tunnel() {
        // RFC 9110 9.3.6: any 2xx answer to CONNECT means the tunnel is up.
        for reply in [&b"HTTP/1.1 201 Created\r\n\r\n"[..], b"HTTP/1.0 299 Fine\r\n\r\n"] {
            let (mut c, srv) = duplex(1024);
            let h = tokio::spawn(http_server(srv, reply));
            http_handshake(&mut c, &dom("example.com", 443), None, None)
                .await
                .unwrap();
            let mut rest = [0u8; 8];
            c.read_exact(&mut rest).await.unwrap();
            assert_eq!(&rest, b"TUNNELED");
            h.await.unwrap();
        }
        // Not 2xx: no tunnel, whatever the reason phrase says.
        let (mut c, srv) = duplex(1024);
        tokio::spawn(http_server(srv, b"HTTP/1.1 300 Connection established\r\n\r\n"));
        assert!(http_handshake(&mut c, &dom("a.b", 1), None, None).await.is_err());
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
}
