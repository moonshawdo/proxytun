//! Recover a hostname from the first bytes a client sends (TLS SNI or HTTP
//! Host). Used when the program connected to a literal IP, which happens when
//! it resolved the name some way that bypassed our DNS (Chrome's DoH, a
//! hard-coded address, an HTTPS-record IP hint). mihomo calls this "sniffer"
//! with `parse-pure-ip`.
//!
//! Pure functions over a byte slice: the relay peeks the socket (without
//! consuming) and asks `sniff` what it sees.
//!
//! ECH: a ClientHello carrying the ECH extension is still sniffed. Chrome sends
//! an ECH extension on every hello as GREASE, and GREASE cannot be told apart
//! from a real one by structure; in the GREASE case the SNI is the true host.
//! A real ECH hello shows only the provider's public name (cloudflare-ech.com),
//! which the relay's skip list (`sniff_skip_domains`) filters out.

use std::net::IpAddr;

#[derive(Debug, PartialEq, Eq)]
pub enum Sniffed {
    /// A usable hostname (lower-cased).
    Domain(String),
    /// Looks like TLS/HTTP but the message is not complete yet.
    NeedMore,
    /// Not TLS/HTTP, or no usable hostname in it: keep the literal IP.
    No,
}

/// Longest ClientHello we are willing to wait for (a TLS record is at most 16 KiB).
pub const MAX_PEEK: usize = 16 * 1024 + 5;

pub fn sniff(buf: &[u8]) -> Sniffed {
    if buf.is_empty() {
        return Sniffed::NeedMore;
    }
    // The first byte tells the protocol: 0x16 is a TLS handshake record, and these letters
    // start the HTTP methods in `METHODS`.
    match buf[0] {
        0x16 => sniff_tls(buf),
        b'G' | b'P' | b'H' | b'D' | b'O' | b'C' | b'T' => sniff_http(buf),
        _ => Sniffed::No,
    }
}

/// Bounds-checked reader; any overrun makes the whole parse `No`.
struct Rd<'a>(&'a [u8]);

impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
}

const EXT_SERVER_NAME: u16 = 0;
#[cfg(test)]
const EXT_ECH: u16 = 0xfe0d;

fn sniff_tls(buf: &[u8]) -> Sniffed {
    // Record header: type(1)=22, version(2) major 3, length(2).
    if buf.len() < 5 {
        return Sniffed::NeedMore;
    }
    if buf[1] != 3 {
        return Sniffed::No;
    }
    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    // A plaintext record carries 1 to 2^14 bytes; any other length is not TLS.
    if rec_len == 0 || rec_len > 16 * 1024 {
        return Sniffed::No;
    }
    // Wait for the whole first record: its payload must hold the ClientHello.
    if buf.len() < 5 + rec_len {
        return Sniffed::NeedMore;
    }
    match parse_client_hello(&buf[5..5 + rec_len]) {
        Some(name) => Sniffed::Domain(name),
        None => Sniffed::No,
    }
}

fn parse_client_hello(rec: &[u8]) -> Option<String> {
    let mut r = Rd(rec);
    // Handshake header: msg_type (1 = ClientHello) and a 3-byte body length.
    if r.u8()? != 0x01 {
        return None; // not a ClientHello
    }
    let len = r
        .take(3)
        .map(|b| ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize)?;
    let mut h = Rd(r.take(len)?); // a hello fragmented over several records fails here
    h.take(2 + 32)?; // legacy_version + random

    // Skip the session id, cipher suites and compression methods: each is length-prefixed
    // (1, 2 and 1 bytes) and they all come before the extensions.
    let sid = h.u8()? as usize;
    h.take(sid)?;
    let cs = h.u16()? as usize;
    h.take(cs)?;
    let comp = h.u8()? as usize;
    h.take(comp)?;
    let ext_len = h.u16()? as usize;
    let mut exts = Rd(h.take(ext_len)?);

    // Walk the extensions (2-byte type, 2-byte length, body) and keep the first server_name.
    let mut name = None;
    while !exts.0.is_empty() {
        let ty = exts.u16()?;
        let l = exts.u16()? as usize;
        let body = exts.take(l)?;
        match ty {
            EXT_SERVER_NAME if name.is_none() => {
                // server_name body: a length-prefixed list of (name_type, 2-byte length, name);
                // name_type 0 is a DNS host name, the only type defined.
                let mut e = Rd(body);
                let list_len = e.u16()? as usize;
                let mut list = Rd(e.take(list_len)?);
                while !list.0.is_empty() {
                    let nt = list.u8()?;
                    let nl = list.u16()? as usize;
                    let n = list.take(nl)?;
                    if nt == 0 {
                        name = valid_host(std::str::from_utf8(n).ok()?);
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    name
}

const METHODS: [&[u8]; 9] = [
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"CONNECT ",
    b"TRACE ",
    b"PATCH ",
];

fn sniff_http(buf: &[u8]) -> Sniffed {
    // A request starts with one of `METHODS`; a few bytes that are a prefix of one may
    // still become one.
    let method_ok = METHODS.iter().any(|m| buf.starts_with(m));
    let could_be = METHODS.iter().any(|m| m.starts_with(&buf[..buf.len().min(m.len())]));
    if !method_ok {
        return if could_be { Sniffed::NeedMore } else { Sniffed::No };
    }
    // The header block ends at the first empty line; stop waiting for it after 8 KiB.
    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return if buf.len() < 8192 {
            Sniffed::NeedMore
        } else {
            Sniffed::No
        };
    };
    let Ok(head) = std::str::from_utf8(&buf[..end]) else {
        return Sniffed::No;
    };
    // Skip the request line; the first header named Host (any case) decides.
    for line in head.split("\r\n").skip(1) {
        let Some((k, v)) = line.split_once(':') else { continue };
        if k.eq_ignore_ascii_case("host") {
            let v = v.trim();
            // strip an optional :port (a bare IPv6 literal is not a hostname anyway)
            let host = if v.starts_with('[') {
                v
            } else {
                v.rsplit_once(':').map_or(v, |(h, _)| h)
            };
            return valid_host(host).map_or(Sniffed::No, Sniffed::Domain);
        }
    }
    Sniffed::No
}

/// Accept only plausible DNS names; reject IP literals, trailing dots, junk.
fn valid_host(s: &str) -> Option<String> {
    // 253 bytes is the longest a DNS name can be in dotted form without the root dot.
    if s.is_empty() || s.len() > 253 || s.starts_with('.') || s.ends_with('.') {
        return None;
    }
    if s.parse::<IpAddr>().is_ok() {
        return None;
    }
    // Host name characters (letters, digits, '-', '.'), plus '_', which some real names use.
    if !s
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'.' || c == b'_')
    {
        return None;
    }
    // Every label 1 to 63 bytes (the DNS limit); an empty one means two dots in a row.
    if s.split('.').any(|l| l.is_empty() || l.len() > 63) {
        return None;
    }
    Some(s.to_ascii_lowercase())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Build a TLS record holding a ClientHello with the given extensions.
    pub(crate) fn client_hello(sni: Option<&str>, extra_ext: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut exts: Vec<u8> = Vec::new();
        let mut add = |ty: u16, body: Vec<u8>| {
            exts.extend_from_slice(&ty.to_be_bytes());
            exts.extend_from_slice(&(body.len() as u16).to_be_bytes());
            exts.extend_from_slice(&body);
        };
        // an unrelated extension first, as real clients do (supported_groups)
        add(10, vec![0, 4, 0, 29, 0, 23]);
        if let Some(n) = sni {
            let mut b = vec![];
            let name = n.as_bytes();
            b.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
            b.push(0);
            b.extend_from_slice(&(name.len() as u16).to_be_bytes());
            b.extend_from_slice(name);
            add(EXT_SERVER_NAME, b);
        }
        for (t, b) in extra_ext {
            add(*t, b.clone());
        }
        let mut body = vec![3, 3];
        body.extend_from_slice(&[7u8; 32]); // random
        body.push(32);
        body.extend_from_slice(&[9u8; 32]); // session id
        body.extend_from_slice(&[0, 4, 0x13, 0x01, 0x13, 0x02]); // cipher suites
        body.extend_from_slice(&[1, 0]); // compression
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        let mut hs = vec![
            0x01,
            (body.len() >> 16) as u8,
            (body.len() >> 8) as u8,
            body.len() as u8,
        ];
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 3, 1];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn extracts_sni_from_a_client_hello() {
        let h = client_hello(Some("WWW.Example.com"), &[]);
        assert_eq!(sniff(&h), Sniffed::Domain("www.example.com".into()));
    }

    #[test]
    fn partial_hello_needs_more_and_never_panics() {
        let h = client_hello(Some("example.com"), &[]);
        assert_eq!(sniff(&h[..3]), Sniffed::NeedMore);
        assert_eq!(sniff(&h[..5]), Sniffed::NeedMore);
        assert_eq!(sniff(&h[..h.len() - 1]), Sniffed::NeedMore);
        // Every truncation is either NeedMore or a clean answer, never a panic.
        for i in 0..h.len() {
            let _ = sniff(&h[..i]);
        }
        assert_eq!(sniff(&[]), Sniffed::NeedMore);
    }

    #[test]
    fn hello_without_sni_is_no() {
        assert_eq!(sniff(&client_hello(None, &[])), Sniffed::No);
    }

    #[test]
    fn ech_extension_does_not_stop_sniffing() {
        // Chrome puts an ECH extension (GREASE) on every ClientHello; the SNI
        // is then the real host. Filtering real ECH public names is the
        // relay's job (sniff_skip_domains).
        let h = client_hello(Some("www.example.com"), &[(EXT_ECH, vec![0, 1, 2, 3])]);
        assert_eq!(sniff(&h), Sniffed::Domain("www.example.com".into()));
        let h = client_hello(Some("cloudflare-ech.com"), &[(EXT_ECH, vec![0, 1, 2, 3])]);
        assert_eq!(sniff(&h), Sniffed::Domain("cloudflare-ech.com".into()));
    }

    #[test]
    fn rejects_invalid_names() {
        for bad in [
            "",
            ".",
            "a..b",
            "-.",
            "exa mple.com",
            "1.2.3.4",
            "::1",
            "trailing.dot.",
            "ünï.com",
        ] {
            assert_eq!(sniff(&client_hello(Some(bad), &[])), Sniffed::No, "{bad:?}");
        }
        let long = format!("{}.com", "a".repeat(64));
        assert_eq!(sniff(&client_hello(Some(&long), &[])), Sniffed::No, "label > 63");
        assert!(matches!(
            sniff(&client_hello(Some("a_b-c.example"), &[])),
            Sniffed::Domain(_)
        ));
    }

    #[test]
    fn corrupt_records_are_no() {
        let mut h = client_hello(Some("example.com"), &[]);
        h[1] = 2; // SSL 2.x style major version
        assert_eq!(sniff(&h), Sniffed::No);
        let mut h = client_hello(Some("example.com"), &[]);
        h[3] = 0;
        h[4] = 0; // zero length record
        assert_eq!(sniff(&h), Sniffed::No);
        let mut h = client_hello(Some("example.com"), &[]);
        h[5] = 0x02; // ServerHello, not ClientHello
        assert_eq!(sniff(&h), Sniffed::No);
        let mut h = client_hello(Some("example.com"), &[]);
        h[3] = 0xff;
        h[4] = 0xff; // absurd record length
        assert_eq!(sniff(&h), Sniffed::No);
        // random garbage
        assert_eq!(sniff(&[0x16, 3, 1, 0, 5, 1, 0, 0, 1, 0]), Sniffed::No);
    }

    #[test]
    fn http_host_header() {
        let r = b"GET /x?y=1 HTTP/1.1\r\nUser-Agent: t\r\nHOST: Example.org:8080\r\nAccept: */*\r\n\r\n";
        assert_eq!(sniff(r), Sniffed::Domain("example.org".into()));
        let r = b"POST / HTTP/1.1\r\nHost: api.example.org\r\n\r\nbody";
        assert_eq!(sniff(r), Sniffed::Domain("api.example.org".into()));
    }

    #[test]
    fn http_edge_cases() {
        // header block not finished yet
        assert_eq!(sniff(b"GET / HTTP/1.1\r\nHost: exa"), Sniffed::NeedMore);
        // method prefix only
        assert_eq!(sniff(b"GE"), Sniffed::NeedMore);
        // no Host header
        assert_eq!(sniff(b"GET / HTTP/1.0\r\nAccept: x\r\n\r\n"), Sniffed::No);
        // Host is an IP literal: nothing to recover
        assert_eq!(sniff(b"GET / HTTP/1.1\r\nHost: 10.0.0.1:80\r\n\r\n"), Sniffed::No);
        assert_eq!(sniff(b"GET / HTTP/1.1\r\nHost: [::1]:80\r\n\r\n"), Sniffed::No);
        // looks like a method letter but is something else
        assert_eq!(sniff(b"GOPHER"), Sniffed::No);
        assert_eq!(sniff(b"\x00\x01\x02"), Sniffed::No);
        // oversized header block without a terminator gives up
        let mut big = b"GET / HTTP/1.1\r\n".to_vec();
        big.extend(std::iter::repeat_n(b'a', 9000));
        assert_eq!(sniff(&big), Sniffed::No);
    }
}
