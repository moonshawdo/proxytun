//! Config file parsing and validation.
//!
//! A config describes: the upstream proxies and how they are grouped for load
//! balancing, the routing rules, and a handful of behaviour switches. The
//! legacy single `[proxy]` table is still accepted and becomes a one-member
//! group named `default`. A proxy given as a URL (`--proxy`) is read by
//! `proxy_url`.

pub mod proxy_url;

use anyhow::{bail, Context, Result};
use ipnet::{IpNet, Ipv4Net};
use serde::Deserialize;
use std::collections::HashSet;
use std::net::SocketAddr;
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

    /// How long a TCP connect out may take (to a proxy, to a destination
    /// reached directly, to a forwarded host port) before the connection is
    /// given up: the program's side is reset, and a proxy that never accepts
    /// counts as failing (another member is tried).
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_ms: u64,

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

/// A domain suffix as matching wants it: lower-case, and `*.example.com` or
/// `.example.com` taken for `example.com`.
fn domain_suffix(v: &str) -> String {
    v.trim_start_matches("*.").trim_start_matches('.').to_ascii_lowercase()
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
fn default_connect_timeout() -> u64 {
    5000
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
                r.value = domain_suffix(&r.value);
            } else if matches!(r.kind, RuleKind::Domain | RuleKind::DomainKeyword) {
                r.value = r.value.to_ascii_lowercase();
            }
        }
        for d in &mut self.sniff_skip_domains {
            *d = domain_suffix(d);
        }
    }

    pub fn validate(&self) -> Result<()> {
        let names = self.validate_proxies()?;
        let gnames = self.validate_groups(&names)?;
        self.validate_limits()?;
        self.validate_rules(&gnames)
    }

    /// At least one proxy, each named once, with a usable address, weight and
    /// credentials. Returns their names.
    fn validate_proxies(&self) -> Result<HashSet<&str>> {
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
        Ok(names)
    }

    /// Each group named once, its members known proxies, and one of them
    /// `default`. Returns their names.
    fn validate_groups(&self, names: &HashSet<&str>) -> Result<HashSet<&str>> {
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
        Ok(gnames)
    }

    /// The settings with bounds or a syntax of their own: health checks,
    /// sniffing, the fake-ip range, upstream DNS, localnet.
    fn validate_limits(&self) -> Result<()> {
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
        // Too short, and even a healthy remote proxy could not be reached.
        if self.connect_timeout_ms < 100 || self.connect_timeout_ms > 60_000 {
            bail!("connect_timeout_ms must be between 100 and 60000");
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
        Ok(())
    }

    /// Each rule complete, and naming only known groups.
    fn validate_rules(&self, gnames: &HashSet<&str>) -> Result<()> {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) const MINIMAL: &str = r#"
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
        assert_eq!(c.connect_timeout_ms, 5000);
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
    fn connect_timeout_parses_and_stays_within_its_range() {
        let c = Config::parse(&format!("connect_timeout_ms = 1500\n{MINIMAL}")).unwrap();
        assert_eq!(c.connect_timeout_ms, 1500);
        for ok in [100, 60_000] {
            assert!(
                Config::parse(&format!("connect_timeout_ms = {ok}\n{MINIMAL}")).is_ok(),
                "{ok}"
            );
        }
        for bad in [0, 99, 60_001] {
            let e = Config::parse(&format!("connect_timeout_ms = {bad}\n{MINIMAL}")).unwrap_err();
            assert!(
                format!("{e:#}").contains("connect_timeout_ms must be between 100 and 60000"),
                "{bad}: {e:#}"
            );
        }
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
    fn the_example_names_the_real_connect_timeout_key_with_its_default() {
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../proxytun.toml")).unwrap();
        let line = text
            .lines()
            .find(|l| l.starts_with("# connect_timeout_ms"))
            .expect("documented in the example");
        let c = Config::parse(&format!("{}\n{MINIMAL}", &line[2..])).unwrap();
        assert!(c.ignored_keys.is_empty(), "{:?}", c.ignored_keys);
        assert_eq!(c.connect_timeout_ms, Config::parse(MINIMAL).unwrap().connect_timeout_ms);
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
