//! A proxy given as a URL (`--proxy` / `PROXYTUN_PROXY`): parsed into the one
//! proxy that replaces the config's, its credentials kept out of messages.

use super::{Config, GroupCfg, ProxyCfg, ProxyKind, Strategy, DEFAULT_GROUP};
use anyhow::{bail, Context, Result};

impl Config {
    /// Replace all proxies with a single one given as a URL
    /// (`--proxy` / `PROXYTUN_PROXY`).
    pub fn override_proxy(&mut self, url: &str) -> Result<()> {
        let p = parse_proxy_url(url)?;
        self.proxies = vec![ProxyCfg {
            name: DEFAULT_GROUP.into(),
            ..p
        }];
        self.groups = vec![GroupCfg {
            name: DEFAULT_GROUP.into(),
            strategy: Strategy::RoundRobin,
            members: vec![DEFAULT_GROUP.into()],
        }];
        self.proxy = None;
        // Every proxy is the given one now, the groups' included: so are
        // the rules that named a group.
        let mut renamed: Vec<String> = Vec::new();
        for r in &mut self.rules {
            if let Some(g) = r.group.take() {
                if g != DEFAULT_GROUP && !renamed.contains(&g) {
                    renamed.push(g);
                }
            }
        }
        if !renamed.is_empty() {
            tracing::warn!(
                "--proxy / $PROXYTUN_PROXY replaces every proxy: rules for group(s) {} use it too",
                renamed.join(", ")
            );
        }
        // The config was loaded unchecked (it may come from no file, or name no proxy):
        // the whole of it is checked only now, the URL's address included.
        self.validate()
    }
}

/// Does a proxy URL carry `user:pass@` credentials?
pub fn url_has_credentials(url: &str) -> bool {
    url.split_once("://")
        .map_or(url, |(_, rest)| rest)
        .trim_end_matches('/')
        .contains('@')
}

/// The URL with any `user:pass@` part replaced by `***@`, for messages.
fn redact_url(url: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (Some(s), r),
        None => (None, url),
    };
    // Up to the last `@`, as `parse_proxy_url` splits it: whatever it would take
    // as credentials is hidden, an unescaped `@` in the password included.
    let rest = match rest.rsplit_once('@') {
        Some((_, host)) => format!("***@{host}"),
        None => rest.to_string(),
    };
    match scheme {
        Some(s) => format!("{s}://{rest}"),
        None => rest,
    }
}

/// Decode `%XX` escapes in URL userinfo (RFC 3986), so passwords containing
/// `@`, `:` or `/` can be written as `%40`, `%3A`, `%2F`.
fn percent_decode(s: &str) -> Result<String> {
    // Decode into bytes: one character may be escaped as several `%XX` (its UTF-8
    // bytes), so the result is checked as UTF-8 only at the end.
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            // Two hex digits must follow; `get` is None past the end of the string or
            // when the two bytes cut a multi-byte character.
            let hex = s
                .get(i + 1..i + 3)
                .filter(|h| h.len() == 2 && h.bytes().all(|c| c.is_ascii_hexdigit()));
            let v = hex.and_then(|h| u8::from_str_radix(h, 16).ok());
            match v {
                Some(v) => {
                    out.push(v);
                    i += 3;
                    continue;
                }
                None => bail!("bad percent-escape in proxy url credentials"),
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8(out).context("proxy url credentials are not valid UTF-8")
}

/// Parse `socks5://[user:pass@]host:port` or `http://[user:pass@]host:port`.
/// Error messages never contain the credentials.
fn parse_proxy_url(url: &str) -> Result<ProxyCfg> {
    let (scheme, rest) = url
        .split_once("://")
        .with_context(|| format!("proxy url {:?} needs a scheme (socks5:// or http://)", redact_url(url)))?;
    // socks5h ("the proxy resolves names") is plain socks5 here: proxytun never
    // resolves a name for a SOCKS5 proxy, it sends the name itself (ATYP 3).
    let kind = match scheme.to_ascii_lowercase().as_str() {
        "socks5" | "socks5h" => ProxyKind::Socks5,
        "http" => ProxyKind::Http,
        other => bail!("unsupported proxy scheme {other:?}"),
    };
    let rest = rest.trim_end_matches('/');
    // The credentials end at the last `@`: an unescaped `@` in the password stays in it.
    let (userinfo, hostport) = match rest.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, rest),
    };
    // The first `:` ends the username, so a password may hold more (`bob:s3:cret`);
    // a username alone gets an empty password.
    let (username, password) = match userinfo {
        Some(u) => match u.split_once(':') {
            Some((a, b)) => (Some(percent_decode(a)?), Some(percent_decode(b)?)),
            None => (Some(percent_decode(u)?), Some(String::new())),
        },
        None => (None, None),
    };
    // Name and address are left to `override_proxy`: it names the proxy `default`,
    // and its `validate` requires an ip:port.
    Ok(ProxyCfg {
        name: String::new(),
        kind,
        addr: hostport.to_string(),
        username,
        password,
        weight: 1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::MINIMAL;

    #[test]
    fn proxy_url_variants() {
        let p = parse_proxy_url("socks5://127.0.0.1:1080").unwrap();
        assert_eq!(
            (p.kind, p.addr.as_str(), p.username),
            (ProxyKind::Socks5, "127.0.0.1:1080", None)
        );

        let p = parse_proxy_url("http://bob:s3:cret@10.0.0.1:8080/").unwrap();
        assert_eq!(p.kind, ProxyKind::Http);
        assert_eq!(p.addr, "10.0.0.1:8080");
        assert_eq!(p.username.as_deref(), Some("bob"));
        assert_eq!(p.password.as_deref(), Some("s3:cret"));

        assert!(parse_proxy_url("127.0.0.1:1080").is_err(), "scheme required");
        assert!(parse_proxy_url("ftp://x:1").is_err());
    }

    #[test]
    fn proxy_passwords_never_reach_debug_output_or_errors() {
        let p = parse_proxy_url("socks5://alice:s3cret@127.0.0.1:1080").unwrap();
        let dbg = format!("{p:?}");
        assert!(!dbg.contains("s3cret"), "{dbg}");
        assert!(dbg.contains("alice") && dbg.contains("***"));
        // Whole-config Debug goes through the same impl.
        let c = Config::parse("[proxy]\ntype=\"socks5\"\naddr=\"1.1.1.1:1\"\nusername=\"u\"\npassword=\"hunter2\"")
            .unwrap();
        assert!(!format!("{c:?}").contains("hunter2"));
        // A malformed URL is reported without its credentials.
        let e = format!("{:#}", parse_proxy_url("alice:s3cret@127.0.0.1:1080").unwrap_err());
        assert!(!e.contains("s3cret"), "{e}");
        assert_eq!(redact_url("http://u:p@h:1/"), "http://***@h:1/");
        assert_eq!(redact_url("socks5://h:1"), "socks5://h:1");
    }

    #[test]
    fn percent_escaped_credentials_are_decoded() {
        let p = parse_proxy_url("http://bob:p%40ss%3Aw%2Fd@10.0.0.1:8080").unwrap();
        assert_eq!(p.username.as_deref(), Some("bob"));
        assert_eq!(p.password.as_deref(), Some("p@ss:w/d"));
        assert!(parse_proxy_url("http://bob:bad%zz@10.0.0.1:8080").is_err());
        assert!(parse_proxy_url("http://bob:trail%4@10.0.0.1:8080").is_err());
        // Exactly two hex digits: a sign is no digit, though Rust's radix parser takes one.
        assert!(parse_proxy_url("http://bob:sign%+A@10.0.0.1:8080").is_err());
        assert!(parse_proxy_url("http://bob:sign%-A@10.0.0.1:8080").is_err());
    }

    #[test]
    fn credentials_in_proxy_urls_are_detected() {
        assert!(url_has_credentials("socks5://user:pw@127.0.0.1:1080"));
        assert!(url_has_credentials("http://u@host:8080/"));
        assert!(!url_has_credentials("socks5://127.0.0.1:1080"));
        assert!(!url_has_credentials("http://host:8080/"));
        assert!(!url_has_credentials(""));
    }

    #[test]
    fn an_override_needs_no_proxy_in_the_file_and_serves_every_group() {
        // Rules only, the proxy from --proxy: fine.
        let rules = "[[rules]]\nmatch=\"domain-suffix\"\nvalue=\"corp.example\"\naction=\"direct\"\n";
        assert!(Config::parse(rules).is_err(), "no proxy at all");
        let mut c = Config::parse_unchecked(rules).unwrap();
        c.override_proxy("socks5://127.0.0.1:1080").unwrap();
        // Rules sending traffic to other groups: the override serves them.
        let groups = format!(
            "{MINIMAL}[[proxies]]\nname=\"hk1\"\ntype=\"socks5\"\naddr=\"10.0.0.9:1080\"\n\
             [[groups]]\nname=\"hk\"\nmembers=[\"hk1\"]\n\
             [[rules]]\nmatch=\"domain-suffix\"\nvalue=\"hk.example\"\naction=\"proxy\"\ngroup=\"hk\"\n"
        );
        let mut c = Config::parse_unchecked(&groups).unwrap();
        c.override_proxy("http://10.1.1.1:3128").unwrap();
        assert_eq!(c.rules[0].group, None, "the default group, the only one");
        assert_eq!(c.proxies.len(), 1);
    }

    #[test]
    fn override_proxy_replaces_everything() {
        let mut c = Config::parse(MINIMAL).unwrap();
        c.override_proxy("http://10.1.1.1:3128").unwrap();
        assert_eq!(c.proxies.len(), 1);
        assert_eq!(c.proxies[0].kind, ProxyKind::Http);
        assert_eq!(c.groups.len(), 1);
        assert!(c.override_proxy("socks5://not-an-addr").is_err());
    }
}
