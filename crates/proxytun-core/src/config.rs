//! Config file parsing and validation.
//!
//! A config describes: the upstream proxies and how they are grouped for load
//! balancing, the routing rules, and a handful of behaviour switches. The
//! legacy single `[proxy]` table is still accepted and becomes a one-member
//! group named `default`.

use anyhow::{bail, Context, Result};
use ipnet::{IpNet, Ipv4Net};
use serde::Deserialize;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

pub const DEFAULT_GROUP: &str = "default";

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// Legacy single upstream proxy. Equivalent to one `[[proxies]]` entry
    /// named "default" in a group named "default".
    #[serde(default)]
    pub proxy: Option<ProxyCfg>,

    #[serde(default)]
    pub proxies: Vec<ProxyCfg>,

    #[serde(default)]
    pub groups: Vec<GroupCfg>,

    /// fake-ip CIDR pool. Default 198.18.0.0/15.
    #[serde(default = "default_fakeip")]
    pub fake_ip_range: String,

    /// Upstream DNS for the queries we do not fake (MX/TXT/PTR/...), as
    /// "ip:port". Contacted directly, not through the proxy. Unset: the host's
    /// own resolver (see `upstream_dns_addr`). (Domains routed `direct` are
    /// resolved by the system resolver, not by this server.)
    #[serde(default)]
    pub upstream_dns: Option<String>,

    /// Destinations reached directly, never through rules or the proxy. Like
    /// proxychains' localnet. Default empty: in the namespace 127.0.0.0/8 is
    /// the namespace's own loopback and never reaches proxytun at all.
    #[serde(default)]
    pub localnet: Vec<String>,

    /// How many other group members to try when a proxy handshake fails.
    #[serde(default = "default_retries")]
    pub retries: u32,

    /// Recover the hostname of connections to a literal IP by peeking the first
    /// bytes (TLS SNI / HTTP Host). Catches programs that bypass our DNS
    /// (Chrome's DoH, hard-coded IPs). Default true.
    #[serde(default = "yes")]
    pub sniff: bool,

    /// Destination ports worth sniffing. Others are never delayed.
    #[serde(default = "default_sniff_ports")]
    pub sniff_ports: Vec<u16>,

    /// Sniffed names that are not the real destination: ECH "public names".
    /// A real ECH ClientHello shows only the provider's public name, so a match
    /// here means "keep the literal IP". Domain-suffix matching.
    #[serde(default = "default_sniff_skip")]
    pub sniff_skip_domains: Vec<String>,

    /// Send the sniffed hostname to the proxy (true), or use it only to choose
    /// the rule and still send the original IP (false). Default true, so the
    /// proxy can route by name.
    #[serde(default = "yes")]
    pub sniff_override_destination: bool,

    /// How long to wait for the client's first bytes before giving up and
    /// keeping the literal IP.
    #[serde(default = "default_sniff_timeout")]
    pub sniff_timeout_ms: u64,

    /// Forward the host's loopback TCP listeners, as found at start-up, into
    /// the namespace's own loopback (which is otherwise empty). Default true.
    #[serde(default = "yes")]
    pub host_ports_forward: bool,

    /// Ports never forwarded: the program wants to listen on them itself.
    #[serde(default)]
    pub host_ports_exclude: Vec<u16>,

    /// The program's own connections to one of the [[proxies]] (same ip and
    /// port: its own proxy setting, `curl -x`) go direct instead of through
    /// the proxy a second time. Other ports of that host follow the rules.
    /// Default true.
    #[serde(default = "yes")]
    pub direct_to_proxies: bool,

    #[serde(default)]
    pub health: HealthCfg,

    #[serde(default)]
    pub rules: Vec<RuleCfg>,

    /// Keys in the file that no field takes (typos, or proxyhook keys that mean
    /// nothing here), e.g. `verify_peer_uid` or `proxies.0.usrname`. Not an
    /// error: the caller warns about them.
    #[serde(skip)]
    pub ignored_keys: Vec<String>,
}

/// The first nameserver of a resolv.conf that we can dial (IPv6 link-local
/// ones with a `%zone` are skipped).
pub fn first_nameserver(resolv: &str) -> Option<SocketAddr> {
    resolv.lines().find_map(|l| {
        let mut f = l.split_whitespace();
        (f.next()? == "nameserver").then_some(())?;
        let ip: std::net::IpAddr = f.next()?.parse().ok()?;
        Some(SocketAddr::new(ip, 53))
    })
}

/// `proxies.0.usrname`: the key as written in the file. serde_ignored's own
/// Display also shows the `Option`/newtype layers serde walks through (`?`).
fn key_path(path: &serde_ignored::Path) -> String {
    use serde_ignored::Path;
    match path {
        Path::Root => String::new(),
        Path::Seq { parent, index } => join(key_path(parent), &index.to_string()),
        Path::Map { parent, key } => join(key_path(parent), key),
        Path::Some { parent } | Path::NewtypeStruct { parent } | Path::NewtypeVariant { parent } => key_path(parent),
    }
}

fn join(parent: String, key: &str) -> String {
    if parent.is_empty() {
        key.to_owned()
    } else {
        format!("{parent}.{key}")
    }
}

fn default_fakeip() -> String {
    "198.18.0.0/15".into()
}
fn default_sniff_ports() -> Vec<u16> {
    vec![80, 443, 8443]
}
fn default_sniff_skip() -> Vec<String> {
    vec!["cloudflare-ech.com".into()]
}
fn default_sniff_timeout() -> u64 {
    300
}
fn default_retries() -> u32 {
    2
}
fn yes() -> bool {
    true
}
fn one() -> u32 {
    1
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyKind {
    Socks5,
    Http,
}

/// `Debug` is written by hand below so that `{:?}` of a config (in a log line
/// or an error) can never print the password.
#[derive(Deserialize, Clone)]
pub struct ProxyCfg {
    /// Unique name, referenced by groups. Optional for the legacy `[proxy]`.
    #[serde(default)]
    pub name: String,
    #[serde(rename = "type")]
    pub kind: ProxyKind,
    pub addr: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    /// Used by weighted-round-robin.
    #[serde(default = "one")]
    pub weight: u32,
}

impl std::fmt::Debug for ProxyCfg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyCfg")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("addr", &self.addr)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "***"))
            .field("weight", &self.weight)
            .finish()
    }
}

/// Largest accepted `weight`: weighted-round-robin builds a schedule with one
/// slot per unit of weight, so an absurd value would allocate gigabytes.
pub const MAX_WEIGHT: u32 = 1000;

impl ProxyCfg {
    pub fn socket_addr(&self) -> Result<SocketAddr> {
        self.addr
            .parse()
            .with_context(|| format!("proxy '{}': bad addr {:?} (want ip:port)", self.name, self.addr))
    }
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Strategy {
    #[default]
    RoundRobin,
    Random,
    LeastConn,
    LeastLatency,
    WeightedRoundRobin,
    Hash,
}

#[derive(Debug, Deserialize, Clone)]
pub struct GroupCfg {
    pub name: String,
    #[serde(default)]
    pub strategy: Strategy,
    pub members: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HealthCfg {
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_fail_threshold")]
    pub fail_threshold: u32,
    #[serde(default = "default_probe_timeout")]
    pub timeout_ms: u64,
}

fn default_interval() -> u64 {
    10
}
fn default_fail_threshold() -> u32 {
    3
}
fn default_probe_timeout() -> u64 {
    3000
}

impl Default for HealthCfg {
    fn default() -> Self {
        HealthCfg {
            interval_secs: default_interval(),
            fail_threshold: default_fail_threshold(),
            timeout_ms: default_probe_timeout(),
        }
    }
}

/// One routing rule, e.g.
///   { match = "domain-suffix", value = "google.com", action = "proxy" }
///   { match = "ip-cidr",       value = "192.168.0.0/16", action = "direct" }
///   { match = "final",         action = "proxy", group = "hk" }
#[derive(Debug, Deserialize, Clone)]
pub struct RuleCfg {
    #[serde(rename = "match")]
    pub kind: RuleKind,
    #[serde(default)]
    pub value: String,
    pub action: Action,
    /// Proxy group for `action = "proxy"`; defaults to "default".
    #[serde(default)]
    pub group: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RuleKind {
    DomainSuffix,
    DomainKeyword,
    Domain,
    IpCidr,
    Final,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    Proxy,
    Direct,
    Block,
}

impl Config {
    /// A warning when the file holds a proxy password but other users can read it.
    pub fn permission_warning(&self, path: &Path) -> Option<String> {
        use std::os::unix::fs::PermissionsExt;
        let has_secret = self
            .proxies
            .iter()
            .any(|p| p.password.as_deref().is_some_and(|pw| !pw.is_empty()));
        let mode = std::fs::metadata(path).ok()?.permissions().mode();
        (has_secret && mode & 0o077 != 0).then(|| {
            format!(
                "{} contains a proxy password but is readable by group/others (mode {:o}); run: chmod 600 {}",
                path.display(),
                mode & 0o777,
                path.display()
            )
        })
    }

    pub fn load(path: &Path) -> Result<Self> {
        let cfg = Self::load_unchecked(path)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// `load` without `validate`: for a config about to get its proxies from
    /// `override_proxy`, which validates.
    pub fn load_unchecked(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading config {}", path.display()))?;
        Self::parse_unchecked(&text)
    }

    /// Parse, normalise legacy forms and validate.
    pub fn parse(text: &str) -> Result<Self> {
        let cfg = Self::parse_unchecked(text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// `parse` without `validate` (see `load_unchecked`).
    pub fn parse_unchecked(text: &str) -> Result<Self> {
        let mut ignored = Vec::new();
        let de = toml::Deserializer::new(text);
        let mut cfg: Config =
            serde_ignored::deserialize(de, |path| ignored.push(key_path(&path))).context("parsing config toml")?;
        cfg.ignored_keys = ignored;
        cfg.normalise();
        Ok(cfg)
    }

    fn normalise(&mut self) {
        if let Some(mut p) = self.proxy.take() {
            if self.proxies.is_empty() {
                if p.name.is_empty() {
                    p.name = DEFAULT_GROUP.into();
                }
                self.proxies.push(p);
            }
        }
        if self.groups.is_empty() && !self.proxies.is_empty() {
            self.groups.push(GroupCfg {
                name: DEFAULT_GROUP.into(),
                strategy: Strategy::RoundRobin,
                members: self.proxies.iter().map(|p| p.name.clone()).collect(),
            });
        }
        for r in &mut self.rules {
            if r.kind == RuleKind::DomainSuffix {
                r.value = r
                    .value
                    .trim_start_matches("*.")
                    .trim_start_matches('.')
                    .to_ascii_lowercase();
            } else if matches!(r.kind, RuleKind::Domain | RuleKind::DomainKeyword) {
                r.value = r.value.to_ascii_lowercase();
            }
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.proxies.is_empty() {
            bail!("no upstream proxy configured (add [[proxies]] or [proxy])");
        }
        let mut names = HashSet::new();
        for p in &self.proxies {
            if p.name.is_empty() {
                bail!("every [[proxies]] entry needs a name");
            }
            if !names.insert(p.name.as_str()) {
                bail!("duplicate proxy name '{}'", p.name);
            }
            if p.weight == 0 || p.weight > MAX_WEIGHT {
                bail!("proxy '{}': weight must be between 1 and {MAX_WEIGHT}", p.name);
            }
            p.socket_addr()?;
            if p.username.as_deref().is_some_and(|u| u.len() > 255)
                || p.password.as_deref().is_some_and(|u| u.len() > 255)
            {
                bail!("proxy '{}': username/password longer than 255 bytes", p.name);
            }
        }

        let mut gnames = HashSet::new();
        for g in &self.groups {
            if !gnames.insert(g.name.as_str()) {
                bail!("duplicate group name '{}'", g.name);
            }
            if g.members.is_empty() {
                bail!("group '{}' has no members", g.name);
            }
            for m in &g.members {
                if !names.contains(m.as_str()) {
                    bail!("group '{}': unknown proxy '{}'", g.name, m);
                }
            }
        }
        if !gnames.contains(DEFAULT_GROUP) {
            bail!("no group named '{DEFAULT_GROUP}' (rules without `group` use it)");
        }

        let h = &self.health;
        if h.interval_secs == 0 || h.interval_secs > 3600 {
            bail!("health.interval_secs must be between 1 and 3600");
        }
        if h.fail_threshold == 0 || h.fail_threshold > 100 {
            bail!("health.fail_threshold must be between 1 and 100");
        }
        // A tiny probe timeout would mark every proxy DOWN and fail every connection.
        if h.timeout_ms < 100 || h.timeout_ms > 60_000 {
            bail!("health.timeout_ms must be between 100 and 60000");
        }
        if self.sniff_timeout_ms == 0 || self.sniff_timeout_ms > 10_000 {
            bail!("sniff_timeout_ms must be between 1 and 10000");
        }
        let net: Ipv4Net = self
            .fake_ip_range
            .parse()
            .with_context(|| format!("bad fake_ip_range {:?}", self.fake_ip_range))?;
        // The last /24 of the range holds proxytun's own namespace addresses.
        if net.prefix_len() < 8 || net.prefix_len() > 22 {
            bail!(
                "fake_ip_range prefix must be between /8 and /22, got /{} (proxytun keeps the last /24 \
                 for itself, so a proxyhook range narrower than /22 needs widening)",
                net.prefix_len()
            );
        }
        self.upstream_dns_addr("")?;
        for c in &self.localnet {
            c.parse::<IpNet>()
                .with_context(|| format!("bad localnet entry {c:?}"))?;
        }

        for (i, r) in self.rules.iter().enumerate() {
            match r.kind {
                RuleKind::Final => {}
                RuleKind::IpCidr => {
                    r.value
                        .parse::<IpNet>()
                        .with_context(|| format!("rule #{}: bad ip-cidr {:?}", i + 1, r.value))?;
                }
                _ => {
                    if r.value.is_empty() {
                        bail!("rule #{}: `value` is required for {:?}", i + 1, r.kind);
                    }
                }
            }
            if let Some(g) = &r.group {
                if r.action != Action::Proxy {
                    bail!("rule #{}: `group` only applies to action = \"proxy\"", i + 1);
                }
                if !gnames.contains(g.as_str()) {
                    bail!("rule #{}: unknown group '{}'", i + 1, g);
                }
            }
        }
        Ok(())
    }

    /// Where non-A queries go: `upstream_dns` if set, else the first usable
    /// nameserver of the host's resolv.conf (`host_resolv`, its text), else
    /// 127.0.0.1:53 as glibc does without one. We forward from the host, so a
    /// host-local stub resolver (127.0.0.53) is reachable.
    pub fn upstream_dns_addr(&self, host_resolv: &str) -> Result<SocketAddr> {
        match &self.upstream_dns {
            Some(s) => s.parse().with_context(|| format!("bad upstream_dns {s}")),
            None => Ok(first_nameserver(host_resolv).unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 53)))),
        }
    }

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
pub fn redact_url(url: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (Some(s), r),
        None => (None, url),
    };
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
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = s.get(i + 1..i + 3).filter(|h| h.len() == 2);
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
pub fn parse_proxy_url(url: &str) -> Result<ProxyCfg> {
    let (scheme, rest) = url
        .split_once("://")
        .with_context(|| format!("proxy url {:?} needs a scheme (socks5:// or http://)", redact_url(url)))?;
    let kind = match scheme.to_ascii_lowercase().as_str() {
        "socks5" | "socks5h" => ProxyKind::Socks5,
        "http" => ProxyKind::Http,
        other => bail!("unsupported proxy scheme {other:?}"),
    };
    let rest = rest.trim_end_matches('/');
    let (userinfo, hostport) = match rest.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, rest),
    };
    let (username, password) = match userinfo {
        Some(u) => match u.split_once(':') {
            Some((a, b)) => (Some(percent_decode(a)?), Some(percent_decode(b)?)),
            None => (Some(percent_decode(u)?), Some(String::new())),
        },
        None => (None, None),
    };
    Ok(ProxyCfg {
        name: String::new(),
        kind,
        addr: hostport.to_string(),
        username,
        password,
        weight: 1,
    })
}

/// Proxy endpoints named by the program's own environment (`http_proxy`,
/// `https_proxy`, `all_proxy`, any case). Connections to these must never be
/// intercepted a second time.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct EnvProxies {
    pub ips: Vec<(IpAddr, u16)>,
    pub domains: Vec<(String, u16)>,
}

pub fn env_proxies<I>(vars: I) -> EnvProxies
where
    I: IntoIterator<Item = (String, String)>,
{
    const KEYS: [&str; 3] = ["http_proxy", "https_proxy", "all_proxy"];
    let mut out = EnvProxies::default();
    for (k, v) in vars {
        if !KEYS.contains(&k.to_ascii_lowercase().as_str()) || v.is_empty() {
            continue;
        }
        let Some((host, ports)) = proxy_endpoint(&v) else {
            continue;
        };
        for port in ports {
            if let Ok(ip) = host.parse::<IpAddr>() {
                if !out.ips.contains(&(ip, port)) {
                    out.ips.push((ip, port));
                }
            } else {
                let host = host.to_ascii_lowercase();
                if !out.domains.contains(&(host.clone(), port)) {
                    out.domains.push((host, port));
                }
            }
        }
    }
    out
}

/// Extract the host and the ports it may be reached on from values like
/// `http://u:p@10.0.0.1:8080/`, `socks5h://[::1]:1080`, or a bare
/// `host:port`.
fn proxy_endpoint(v: &str) -> Option<(String, Vec<u16>)> {
    let (scheme, rest) = match v.split_once("://") {
        Some((s, r)) => (Some(s.to_ascii_lowercase()), r),
        None => (None, v),
    };
    let rest = rest.split('/').next()?;
    let hostport = rest.rsplit_once('@').map_or(rest, |(_, h)| h);
    // Without a port, clients disagree: curl and git go to 1080 for any
    // scheme, Python, Go, wget, npm and apt to 80 for http:// (443 for
    // https://). Either is the program's own proxy.
    let default_ports = match scheme.as_deref() {
        Some("https") => vec![443],
        Some("socks5" | "socks5h" | "socks4" | "socks4a" | "socks") => vec![1080],
        _ => vec![80, 1080],
    };
    if let Some(stripped) = hostport.strip_prefix('[') {
        let (h, tail) = stripped.split_once(']')?;
        let ports = match tail.strip_prefix(':') {
            Some(p) => vec![p.parse().ok()?],
            None => default_ports,
        };
        return Some((h.to_string(), ports));
    }
    match hostport.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() => Some((h.to_string(), vec![p.parse().ok()?])),
        Some(_) => None,
        None if !hostport.is_empty() => Some((hostport.to_string(), default_ports)),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
        [proxy]
        type = "socks5"
        addr = "127.0.0.1:1080"
    "#;

    #[test]
    fn legacy_proxy_becomes_default_group() {
        let c = Config::parse(MINIMAL).unwrap();
        assert_eq!(c.proxies.len(), 1);
        assert_eq!(c.groups.len(), 1);
        assert_eq!(c.groups[0].name, "default");
        assert_eq!(c.groups[0].members, vec!["default"]);
        assert_eq!(c.fake_ip_range, "198.18.0.0/15");
        assert!(c.localnet.is_empty(), "127.0.0.0/8 never reaches proxytun");
        assert_eq!(c.retries, 2);
        assert_eq!(c.upstream_dns, None, "the host's resolver unless set");
        assert!(c.host_ports_forward);
        assert!(c.direct_to_proxies);
        assert!(c.host_ports_exclude.is_empty());
        assert!(c.sniff);
        assert_eq!(c.sniff_ports, vec![80, 443, 8443]);
        assert_eq!(c.sniff_timeout_ms, 300);
        assert_eq!(c.sniff_skip_domains, vec!["cloudflare-ech.com"]);
        assert!(c.sniff_override_destination);
    }

    #[test]
    fn sniff_settings_parse_and_validate() {
        let c = Config::parse(&format!(
            "sniff = false\nsniff_ports = [80, 443]\nsniff_timeout_ms = 50\n{MINIMAL}"
        ))
        .unwrap();
        assert!(!c.sniff);
        assert_eq!(c.sniff_ports, vec![80, 443]);
        assert_eq!(c.sniff_timeout_ms, 50);
        for bad in [
            "sniff_timeout_ms = 0",
            "sniff_timeout_ms = 60000",
            "sniff_ports = [70000]",
        ] {
            assert!(Config::parse(&format!("{bad}\n{MINIMAL}")).is_err(), "{bad}");
        }
    }

    #[test]
    fn full_multi_proxy_config_parses() {
        let c = Config::parse(
            r#"
            [[proxies]]
            name = "hk"
            type = "socks5"
            addr = "10.0.0.1:1080"
            weight = 3
            [[proxies]]
            name = "jp"
            type = "http"
            addr = "10.0.0.2:8080"
            username = "u"
            password = "p"
            [[groups]]
            name = "default"
            strategy = "least-latency"
            members = ["hk", "jp"]
            [[groups]]
            name = "eu"
            strategy = "hash"
            members = ["jp"]
            [[rules]]
            match = "domain-suffix"
            value = "*.Example.com"
            action = "proxy"
            group = "eu"
            "#,
        )
        .unwrap();
        assert_eq!(c.groups[0].strategy, Strategy::LeastLatency);
        assert_eq!(c.groups[1].strategy, Strategy::Hash);
        assert_eq!(c.proxies[0].weight, 3);
        assert_eq!(c.rules[0].value, "example.com", "suffix is normalised");
    }

    #[test]
    fn unknown_keys_are_reported_not_rejected() {
        // A proxyhook.toml must load as is; its ptrace-only switches and any
        // typo are named so the user learns they have no effect.
        let text = format!(
            "verify_peer_uid = true\nblock_quic = false\ndns_udp_unconnected = true\nsplice = true\nsnif = false\n{MINIMAL}usrname = \"u\"\n"
        );
        let c = Config::parse(&text).unwrap();
        assert_eq!(
            c.ignored_keys,
            [
                "verify_peer_uid",
                "block_quic",
                "dns_udp_unconnected",
                "splice",
                "snif",
                "proxy.usrname"
            ]
        );
        assert!(c.sniff, "the misspelt key changed nothing");
        assert!(Config::parse(MINIMAL).unwrap().ignored_keys.is_empty());
    }

    #[test]
    fn rejects_missing_proxy() {
        assert!(Config::parse("").is_err());
    }

    #[test]
    fn rejects_duplicate_and_unknown_names() {
        let dup = r#"
            [[proxies]]
            name = "a"
            type = "socks5"
            addr = "1.1.1.1:1"
            [[proxies]]
            name = "a"
            type = "socks5"
            addr = "1.1.1.1:2"
        "#;
        assert!(Config::parse(dup).unwrap_err().to_string().contains("duplicate proxy"));

        let unknown = r#"
            [[proxies]]
            name = "a"
            type = "socks5"
            addr = "1.1.1.1:1"
            [[groups]]
            name = "default"
            members = ["a", "ghost"]
        "#;
        assert!(Config::parse(unknown).unwrap_err().to_string().contains("ghost"));
    }

    #[test]
    fn rejects_bad_values() {
        // Top-level keys must precede the tables in TOML.
        for bad in [
            format!("fake_ip_range = \"198.18.0.0/31\"\n{MINIMAL}"),
            // Too small to leave a /24 for the namespace's own addresses.
            format!("fake_ip_range = \"198.18.0.0/23\"\n{MINIMAL}"),
            format!("fake_ip_range = \"10.0.0.0/4\"\n{MINIMAL}"),
            format!("fake_ip_range = \"nonsense\"\n{MINIMAL}"),
            format!("upstream_dns = \"dns.example\"\n{MINIMAL}"),
            format!("localnet = [\"10.0.0.0/99\"]\n{MINIMAL}"),
            format!("{MINIMAL}\n[[rules]]\nmatch=\"ip-cidr\"\nvalue=\"1.2.3.4/40\"\naction=\"direct\""),
            format!("{MINIMAL}\n[[rules]]\nmatch=\"domain\"\naction=\"direct\""),
            format!("{MINIMAL}\n[[rules]]\nmatch=\"final\"\naction=\"direct\"\ngroup=\"default\""),
            format!("{MINIMAL}\n[[rules]]\nmatch=\"final\"\naction=\"proxy\"\ngroup=\"nope\""),
        ] {
            assert!(Config::parse(&bad).is_err(), "should reject:\n{bad}");
        }
        // A proxyhook config's range: say why it no longer fits.
        let e = Config::parse(&format!("fake_ip_range = \"198.18.0.0/24\"\n{MINIMAL}")).unwrap_err();
        assert!(format!("{e:#}").contains("proxyhook range narrower than /22"), "{e:#}");
    }

    #[test]
    fn rejects_zero_weight_and_bad_proxy_addr() {
        let w = r#"
            [[proxies]]
            name = "a"
            type = "socks5"
            addr = "1.1.1.1:1"
            weight = 0
        "#;
        assert!(Config::parse(w).is_err());
        let a = r#"
            [[proxies]]
            name = "a"
            type = "socks5"
            addr = "not-an-addr"
        "#;
        assert!(Config::parse(a).is_err());
    }

    #[test]
    fn rejects_overlong_credentials() {
        let long = "x".repeat(256);
        let t = format!("[proxy]\ntype=\"socks5\"\naddr=\"1.1.1.1:1\"\nusername=\"{long}\"\npassword=\"p\"");
        assert!(Config::parse(&t).is_err());
    }

    #[test]
    fn the_example_rules_work_once_uncommented() {
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../proxytun.toml")).unwrap();
        // Uncomment exactly what a user would: the [[rules]] lines and their keys.
        let rule_line = |l: &str| {
            let t = l.trim_start_matches("# ");
            t == "[[rules]]"
                || ["match ", "value ", "action "]
                    .iter()
                    .any(|k| t.starts_with(k) && t.contains('='))
        };
        let text: String = text
            .lines()
            .map(|l| if rule_line(l) { &l[2..] } else { l })
            .collect::<Vec<_>>()
            .join("\n");
        let c = Config::parse(&text).unwrap();
        assert!(c.ignored_keys.is_empty(), "{:?}", c.ignored_keys);
        let kinds: Vec<RuleKind> = c.rules.iter().map(|r| r.kind).collect();
        assert_eq!(
            kinds,
            [
                RuleKind::IpCidr,
                RuleKind::DomainSuffix,
                RuleKind::DomainKeyword,
                RuleKind::Final
            ]
        );
        assert_eq!(c.rules.last().unwrap().action, Action::Proxy);
    }

    #[test]
    fn shipped_example_config_is_valid() {
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../proxytun.toml")).unwrap();
        let c = Config::parse(&text).unwrap();
        assert!(
            c.ignored_keys.is_empty(),
            "example uses unknown keys: {:?}",
            c.ignored_keys
        );
    }

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
    }

    #[test]
    fn weight_and_health_values_are_bounded() {
        for bad in ["weight = 4000000000", "weight = 1001"] {
            let t = format!("[[proxies]]\nname=\"a\"\ntype=\"socks5\"\naddr=\"1.1.1.1:1\"\n{bad}");
            assert!(Config::parse(&t).is_err(), "{bad}");
        }
        for bad in [
            "timeout_ms = 0",
            "timeout_ms = 50",
            "fail_threshold = 0",
            "interval_secs = 0",
        ] {
            assert!(Config::parse(&format!("{MINIMAL}\n[health]\n{bad}")).is_err(), "{bad}");
        }
        assert!(Config::parse(&format!("{MINIMAL}\n[health]\ntimeout_ms = 500\nfail_threshold = 5")).is_ok());
    }

    #[test]
    fn world_readable_config_with_a_password_is_flagged() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("proxytun-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Gone afterwards, whether the test passes or not.
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(dir.clone());
        let f = dir.join("c.toml");
        std::fs::write(
            &f,
            "[proxy]\ntype=\"socks5\"\naddr=\"1.1.1.1:1\"\nusername=\"u\"\npassword=\"pw\"",
        )
        .unwrap();
        let c = Config::load(&f).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        let w = c.permission_warning(&f).expect("0644 with a password must warn");
        assert!(w.contains("chmod 600") && !w.contains("pw\""));
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(c.permission_warning(&f), None);
        // No password: nothing secret to protect.
        let c2 = Config::parse(MINIMAL).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(c2.permission_warning(&f), None);
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

    fn env(pairs: &[(&str, &str)]) -> EnvProxies {
        env_proxies(pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())))
    }

    #[test]
    fn env_proxy_extraction() {
        let e = env(&[
            ("http_proxy", "http://user:pw@10.0.0.5:8080/"),
            ("HTTPS_PROXY", "http://10.0.0.5:8080"),
            ("ALL_PROXY", "socks5h://[::1]:1081"),
            ("no_proxy", "localhost"),
            ("FOO", "http://9.9.9.9:1"),
        ]);
        assert_eq!(
            e.ips,
            vec![("10.0.0.5".parse().unwrap(), 8080), ("::1".parse().unwrap(), 1081)],
            "deduplicated, unrelated vars ignored"
        );
        assert!(e.domains.is_empty());
    }

    #[test]
    fn env_proxy_hostname_and_default_ports() {
        let e = env(&[
            ("http_proxy", "Proxy.Corp.Example"),
            ("HTTP_PROXY", "http://plain.example"),
            ("https_proxy", "https://secure.example"),
            ("all_proxy", "socks5://s.example"),
        ]);
        // Where curl and git connect (1080), and where pip, Go, wget, npm
        // and apt do (80): both.
        assert_eq!(
            e.domains,
            vec![
                ("proxy.corp.example".to_string(), 80),
                ("proxy.corp.example".to_string(), 1080),
                ("plain.example".to_string(), 80),
                ("plain.example".to_string(), 1080),
                ("secure.example".to_string(), 443),
                ("s.example".to_string(), 1080)
            ]
        );
    }

    #[test]
    fn env_proxy_garbage_is_ignored() {
        let e = env(&[
            ("http_proxy", ""),
            ("https_proxy", "http://:80"),
            ("all_proxy", "host:notaport"),
        ]);
        assert_eq!(e, EnvProxies::default());
    }

    #[test]
    fn upstream_dns_follows_the_host_unless_set() {
        let host = "# WSL\nsearch lan\nnameserver fe80::1%eth0\nnameserver 172.25.32.1\nnameserver 8.8.8.8\n";
        let c = Config::parse(MINIMAL).unwrap();
        assert_eq!(c.upstream_dns_addr(host).unwrap(), "172.25.32.1:53".parse().unwrap());
        assert_eq!(
            c.upstream_dns_addr("nameserver 127.0.0.53\n").unwrap(),
            "127.0.0.53:53".parse().unwrap(),
            "a host stub resolver is fine: we forward from the host"
        );
        assert_eq!(
            c.upstream_dns_addr("nameserver 2001:db8::53\n").unwrap(),
            "[2001:db8::53]:53".parse().unwrap()
        );
        assert_eq!(
            c.upstream_dns_addr("# none\n").unwrap(),
            "127.0.0.1:53".parse().unwrap(),
            "glibc's default"
        );
        let set = Config::parse(&format!("upstream_dns = \"9.9.9.9:5353\"\n{MINIMAL}")).unwrap();
        assert_eq!(set.upstream_dns_addr(host).unwrap(), "9.9.9.9:5353".parse().unwrap());
    }
}
