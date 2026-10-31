//! Runtime routing policy built from a `Config` plus the program's own
//! environment. Pure logic: no I/O, so every branch is unit-tested.
//!
//! Two layers decide what happens to a connect():
//!   1. `is_passthrough`: localnet CIDRs, the proxy endpoints named in the
//!      program's `*_proxy` env vars and (`direct_to_proxies`) our own
//!      [[proxies]]. These go straight out: no sniffing, no rules, no proxy.
//!   2. `decide`: the rule list, first match wins.

use crate::config::{Action, Config, EnvProxies, RuleKind, DEFAULT_GROUP};
use crate::types::{Decision, Target};
use anyhow::Result;
use ipnet::IpNet;
use std::net::{IpAddr, Ipv4Addr};

struct Rule {
    kind: RuleKind,
    value: String,
    net: Option<IpNet>,
    decision: Decision,
}

pub struct Policy {
    localnet: Vec<IpNet>,
    env: EnvProxies,
    rules: Vec<Rule>,
}

impl Policy {
    pub fn new(cfg: &Config, mut env: EnvProxies) -> Result<Self> {
        // The program dialing one of our proxies itself (its own proxy
        // setting, not in its environment) must not go through it twice.
        if cfg.direct_to_proxies {
            for p in &cfg.proxies {
                let a = p.socket_addr()?;
                if !env.ips.contains(&(a.ip(), a.port())) {
                    env.ips.push((a.ip(), a.port()));
                }
            }
        }
        let localnet = cfg
            .localnet
            .iter()
            .map(|c| c.parse::<IpNet>().map_err(anyhow::Error::from))
            .collect::<Result<Vec<_>>>()?;
        let rules = cfg
            .rules
            .iter()
            .map(|r| {
                let net = match r.kind {
                    RuleKind::IpCidr => Some(r.value.parse::<IpNet>()?),
                    _ => None,
                };
                let decision = match r.action {
                    Action::Proxy => Decision::Proxy {
                        group: r.group.clone().unwrap_or_else(|| DEFAULT_GROUP.to_string()),
                    },
                    Action::Direct => Decision::Direct,
                    Action::Block => Decision::Block,
                };
                Ok(Rule {
                    kind: r.kind,
                    value: r.value.clone(),
                    net,
                    decision,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Policy { localnet, env, rules })
    }

    /// Should this destination bypass sniffing, the rules and the proxy?
    pub fn is_passthrough(&self, ip: Ipv4Addr, port: u16) -> bool {
        let ip = IpAddr::V4(ip);
        if self.env.ips.iter().any(|(i, p)| unmap(*i) == ip && *p == port) {
            return true;
        }
        self.localnet.iter().any(|n| n.contains(&ip))
    }

    /// Does an ip-cidr rule cover this literal-IP target? Then the user has said
    /// what to do with that address, and a hostname sniffed from the payload
    /// must not override it.
    pub fn has_ip_rule_for(&self, t: &Target) -> bool {
        let ip = match t {
            Target::V4(ip, _) => IpAddr::V4(*ip),
            Target::Domain(..) => return false,
        };
        self.rules
            .iter()
            .any(|r| r.kind == RuleKind::IpCidr && r.net.is_some_and(|n| n.contains(&ip)))
    }

    /// Rule engine. `Target::Domain` goes through the domain rules; literal IPs
    /// go through ip-cidr rules. No match and no `final` => proxy (the safe
    /// default for a proxifier: never silently go direct).
    pub fn decide(&self, t: &Target) -> Decision {
        // Lowercased once, not per rule (rule values are lowercased at load).
        let domain = match t {
            Target::Domain(d, _) => d.to_ascii_lowercase(),
            _ => String::new(),
        };
        // The program's own proxy hostname must be reachable without recursion.
        if let Target::Domain(_, p) = t {
            if self.env.domains.iter().any(|(h, hp)| *h == domain && hp == p) {
                return Decision::Direct;
            }
        }
        for r in &self.rules {
            let hit = match (r.kind, t) {
                (RuleKind::DomainSuffix, Target::Domain(..)) => is_subdomain(&domain, &r.value),
                (RuleKind::DomainKeyword, Target::Domain(..)) => domain.contains(&r.value),
                (RuleKind::Domain, Target::Domain(..)) => domain == r.value,
                (RuleKind::IpCidr, Target::V4(ip, _)) => r.net.is_some_and(|n| n.contains(&IpAddr::V4(*ip))),
                (RuleKind::Final, _) => true,
                _ => false,
            };
            if hit {
                return r.decision.clone();
            }
        }
        Decision::Proxy {
            group: DEFAULT_GROUP.to_string(),
        }
    }
}

/// An address that only means something inside one network (RFC 1918
/// private, loopback, link-local, carrier-grade NAT...). A connection to such
/// an address was aimed there on purpose (/etc/hosts, a LAN service), so its
/// sniffed hostname must not send it somewhere else.
pub fn is_local_scope(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10
}

/// `::ffff:a.b.c.d` -> `a.b.c.d`, everything else unchanged: a proxy in the
/// program's environment may be written either way.
fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Is `name` `suffix` itself or a name under it? Both lowercase; no
/// allocation (this runs per rule, per connection).
pub fn is_subdomain(name: &str, suffix: &str) -> bool {
    name.strip_suffix(suffix)
        .is_some_and(|head| head.is_empty() || head.ends_with('.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_rules_match_whole_labels_only() {
        assert!(is_subdomain("example.com", "example.com"));
        assert!(is_subdomain("a.b.example.com", "example.com"));
        assert!(!is_subdomain("badexample.com", "example.com"), "not a label boundary");
        assert!(!is_subdomain("com", "example.com"));
    }
    use crate::config::{env_proxies, EnvProxies};
    use std::net::Ipv4Addr;

    fn policy(extra: &str, env: &[(&str, &str)]) -> Policy {
        policy_top("", extra, env)
    }

    /// `top` holds top-level keys, which TOML requires before any table.
    fn policy_top(top: &str, extra: &str, env: &[(&str, &str)]) -> Policy {
        let cfg = Config::parse(&format!(
            "{top}\n[proxy]\ntype=\"socks5\"\naddr=\"127.0.0.1:1080\"\n[[groups]]\nname=\"default\"\nmembers=[\"default\"]\n[[groups]]\nname=\"hk\"\nmembers=[\"default\"]\n{extra}"
        ))
        .unwrap_or_else(|e| panic!("{e:#}"));
        let env = env_proxies(env.iter().map(|(k, v)| (k.to_string(), v.to_string())));
        Policy::new(&cfg, env).unwrap()
    }

    fn dom(d: &str) -> Target {
        Target::Domain(d.into(), 443)
    }

    #[test]
    fn domain_rules_first_match_wins() {
        let p = policy(
            r#"
            [[rules]]
            match="domain-suffix"
            value="cn"
            action="direct"
            [[rules]]
            match="domain-keyword"
            value="evil"
            action="block"
            [[rules]]
            match="domain"
            value="exact.example.com"
            action="proxy"
            group="hk"
            [[rules]]
            match="final"
            action="proxy"
            "#,
            &[],
        );
        assert_eq!(p.decide(&dom("baidu.cn")), Decision::Direct);
        assert_eq!(p.decide(&dom("cn")), Decision::Direct, "suffix equals the whole name");
        assert_eq!(p.decide(&dom("WWW.Baidu.CN")), Decision::Direct, "case-insensitive");
        assert_eq!(p.decide(&dom("an-evil-site.com")), Decision::Block);
        assert_eq!(
            p.decide(&dom("exact.example.com")),
            Decision::Proxy { group: "hk".into() }
        );
        assert_eq!(
            p.decide(&dom("other.com")),
            Decision::Proxy {
                group: "default".into()
            }
        );
    }

    #[test]
    fn suffix_requires_label_boundary() {
        let p = policy(
            "[[rules]]\nmatch=\"domain-suffix\"\nvalue=\"example.com\"\naction=\"direct\"",
            &[],
        );
        assert_eq!(
            p.decide(&dom("notexample.com")),
            Decision::Proxy {
                group: "default".into()
            }
        );
        assert_eq!(p.decide(&dom("a.example.com")), Decision::Direct);
        assert_eq!(
            p.decide(&dom("example.com.evil.org")),
            Decision::Proxy {
                group: "default".into()
            }
        );
    }

    #[test]
    fn ip_rules_apply_to_literals_only() {
        let p = policy(
            r#"
            [[rules]]
            match="ip-cidr"
            value="10.0.0.0/8"
            action="direct"
            [[rules]]
            match="ip-cidr"
            value="2001:db8::/32"
            action="block"
            "#,
            &[],
        );
        assert_eq!(p.decide(&Target::V4(Ipv4Addr::new(10, 1, 2, 3), 80)), Decision::Direct);
        assert_eq!(
            p.decide(&Target::V4(Ipv4Addr::new(11, 1, 2, 3), 80)),
            Decision::Proxy {
                group: "default".into()
            }
        );
        // A domain never matches an ip-cidr rule.
        assert_eq!(
            p.decide(&dom("10.0.0.1")),
            Decision::Proxy {
                group: "default".into()
            }
        );
    }

    #[test]
    fn no_rules_defaults_to_proxy_never_direct() {
        let p = policy("", &[]);
        assert_eq!(
            p.decide(&dom("anything.org")),
            Decision::Proxy {
                group: "default".into()
            }
        );
    }

    #[test]
    fn nothing_is_passed_through_by_default() {
        // In proxytun the namespace's own loopback never reaches us, so the
        // old 127.0.0.0/8 default would only have been noise.
        let p = policy("", &[]);
        for ip in [[127, 0, 0, 1], [10, 0, 0, 1], [192, 168, 1, 1]] {
            assert!(!p.is_passthrough(Ipv4Addr::from(ip), 80), "{ip:?}");
        }
    }

    #[test]
    fn a_loopback_localnet_covers_ipv6_and_mapped_loopback_too() {
        let p = policy_top("localnet = [\"127.0.0.0/8\"]", "", &[]);
        assert!(p.is_passthrough(Ipv4Addr::new(127, 0, 0, 1), 80));
        assert!(p.is_passthrough(Ipv4Addr::new(127, 200, 3, 4), 80));
        assert!(!p.is_passthrough(Ipv4Addr::new(10, 0, 0, 1), 80));
        assert!(!p.is_passthrough(Ipv4Addr::new(172, 25, 32, 1), 7897));
        assert!(!p.is_passthrough(Ipv4Addr::new(192, 168, 1, 1), 80));
    }

    #[test]
    fn custom_localnet_is_honoured() {
        let p = policy_top("localnet = [\"10.0.0.0/8\"]", "", &[]);
        assert!(p.is_passthrough(Ipv4Addr::new(10, 9, 9, 9), 1));
        assert!(!p.is_passthrough(Ipv4Addr::new(127, 0, 0, 1), 1));
    }

    #[test]
    fn our_own_proxies_are_reached_directly_by_ip_and_port_only() {
        // The helper's proxy is 127.0.0.1:1080.
        let p = policy("", &[]);
        assert!(p.is_passthrough(Ipv4Addr::LOCALHOST, 1080));
        assert!(
            !p.is_passthrough(Ipv4Addr::LOCALHOST, 1081),
            "other ports of the proxy's host follow the rules"
        );
        let off = policy_top("direct_to_proxies = false", "", &[]);
        assert!(!off.is_passthrough(Ipv4Addr::LOCALHOST, 1080));

        // --proxy / $PROXYTUN_PROXY: the proxy in effect is the one let through.
        let mut cfg = Config::parse("[proxy]\ntype=\"socks5\"\naddr=\"127.0.0.1:1080\"\n").unwrap();
        cfg.override_proxy("socks5://10.1.2.3:7897").unwrap();
        let p = Policy::new(&cfg, EnvProxies::default()).unwrap();
        assert!(p.is_passthrough(Ipv4Addr::new(10, 1, 2, 3), 7897));
        assert!(!p.is_passthrough(Ipv4Addr::LOCALHOST, 1080));
    }

    #[test]
    fn env_proxy_endpoint_is_passthrough_by_ip_and_port() {
        let p = policy("", &[("http_proxy", "http://172.25.32.1:7897")]);
        assert!(p.is_passthrough(Ipv4Addr::new(172, 25, 32, 1), 7897));
        assert!(
            !p.is_passthrough(Ipv4Addr::new(172, 25, 32, 1), 443),
            "other ports on the same host are still proxied"
        );
    }

    #[test]
    fn env_proxy_hostname_goes_direct_via_rules() {
        let p = policy("", &[("https_proxy", "http://Proxy.Corp:3128")]);
        assert_eq!(p.decide(&Target::Domain("proxy.corp".into(), 3128)), Decision::Direct);
        assert_eq!(
            p.decide(&Target::Domain("proxy.corp".into(), 443)),
            Decision::Proxy {
                group: "default".into()
            },
            "only the named port is exempt"
        );
    }

    #[test]
    fn unmap_roundtrip() {
        assert_eq!(
            unmap("::ffff:1.2.3.4".parse().unwrap()),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            unmap("2001:db8::1".parse().unwrap()),
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn ip_rules_are_found_for_literal_targets_only() {
        let p = policy(
            "[[rules]]\nmatch=\"ip-cidr\"\nvalue=\"9.9.9.0/24\"\naction=\"block\"\n[[rules]]\nmatch=\"final\"\naction=\"proxy\"",
            &[],
        );
        assert!(p.has_ip_rule_for(&Target::V4(Ipv4Addr::new(9, 9, 9, 9), 443)));
        assert!(
            !p.has_ip_rule_for(&Target::V4(Ipv4Addr::new(8, 8, 8, 8), 443)),
            "final is not an ip rule"
        );
        assert!(!p.has_ip_rule_for(&dom("9.9.9.9")));
    }

    #[test]
    fn local_scope_addresses() {
        for ip in [
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.10",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "100.127.255.1",
            "0.0.0.0",
        ] {
            assert!(is_local_scope(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "172.32.0.1", "100.128.0.1", "93.184.216.34", "203.0.113.9"] {
            assert!(!is_local_scope(ip.parse().unwrap()), "{ip}");
        }
    }
}
