//! What every relayed connection reads: the rules, proxy groups and sniffing
//! settings of one config generation, swapped as a whole on SIGHUP.

use crate::balancer::Registry;
use crate::config::Config;
use crate::policy::{env_proxies, EnvProxies, Policy};
use anyhow::Result;
use std::time::Duration;

/// Hostname sniffing for connections to a literal IP.
#[derive(Debug, Clone)]
pub(crate) struct SniffCfg {
    pub(crate) enabled: bool,
    pub(crate) ports: Vec<u16>,
    /// Lower-cased domain suffixes that are never the real destination
    /// (the "public name" a real ECH connection shows).
    pub(crate) skip: Vec<String>,
    pub(crate) timeout: Duration,
    /// Dial the sniffed name (true) or only route by it and dial the IP (false).
    pub(crate) override_destination: bool,
}

impl SniffCfg {
    pub(crate) fn skips(&self, name: &str) -> bool {
        self.skip.iter().any(|s| crate::policy::is_subdomain(name, s))
    }
}

/// Everything a connection handler needs; swapped atomically on SIGHUP.
pub struct Live {
    pub(crate) policy: Policy,
    pub registry: Registry,
    pub(crate) retries: u32,
    pub(crate) fail_threshold: u32,
    pub(crate) sniff: SniffCfg,
}

impl Live {
    /// The state for `cfg`, `env` being the program's own proxy endpoints.
    pub(crate) fn new(cfg: &Config, env: EnvProxies) -> Result<Live> {
        Ok(Live {
            policy: Policy::new(cfg, env)?,
            registry: Registry::build(cfg)?,
            retries: cfg.retries,
            fail_threshold: cfg.health.fail_threshold,
            sniff: SniffCfg {
                enabled: cfg.sniff,
                ports: cfg.sniff_ports.clone(),
                skip: cfg.sniff_skip_domains.clone(),
                timeout: Duration::from_millis(cfg.sniff_timeout_ms),
                override_destination: cfg.sniff_override_destination,
            },
        })
    }
}

/// Build the per-connection state from a config. The program's own
/// `*_proxy` variables are read from our environment, which it inherits.
pub fn build_live(cfg: &Config) -> Result<Live> {
    // vars() would panic on one entry that is not UTF-8 (a GBK directory in
    // PWD); no proxy URL is among those.
    let env =
        env_proxies(std::env::vars_os().filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?))));
    Live::new(cfg, env)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skip_list_matches_the_name_and_its_subdomains_only() {
        let cfg = Config::parse("[proxy]\ntype=\"socks5\"\naddr=\"127.0.0.1:1\"\n").unwrap();
        let c = Live::new(&cfg, EnvProxies::default()).unwrap().sniff;
        assert!(c.skips("cloudflare-ech.com"));
        assert!(c.skips("x.cloudflare-ech.com"));
        assert!(!c.skips("notcloudflare-ech.com"));
        assert!(!c.skips("cloudflare.com"));
    }

    #[test]
    fn a_skip_entry_is_written_as_a_domain_suffix_rule_value_may_be() {
        let cfg = Config::parse(
            "sniff_skip_domains = [\"*.Example.com\", \".ech.test\"]\n[proxy]\ntype=\"socks5\"\naddr=\"127.0.0.1:1\"\n",
        )
        .unwrap();
        let c = build_live(&cfg).unwrap().sniff;
        for name in ["example.com", "a.example.com", "ech.test", "b.ech.test"] {
            assert!(c.skips(name), "{name}");
        }
        assert!(!c.skips("badexample.com"));
    }
}
