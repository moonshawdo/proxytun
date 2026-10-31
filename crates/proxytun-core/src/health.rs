//! Active health probing of upstream proxies.
//!
//! A probe is: TCP connect to the proxy, plus (for SOCKS5) the greeting a
//! real connection starts with, authentication included: a proxy that turns
//! our credentials down would fail every connection, so it is not healthy. The elapsed time feeds the node's latency EWMA used by the
//! `least-latency` strategy. It measures the hop to the proxy only, not the
//! proxy-to-target leg, which would need a real external destination.

use crate::balancer::Node;
use crate::config::HealthCfg;
use anyhow::{anyhow, Result};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

/// One probe; returns the measured round trip.
pub async fn probe(node: &Node, timeout: Duration) -> Result<Duration> {
    let started = Instant::now();
    let work = async {
        let mut s = TcpStream::connect(node.addr).await?;
        crate::proxy::greet(&mut s, &node.cfg).await
    };
    tokio::time::timeout(timeout, work)
        .await
        .map_err(|_| anyhow!("probe of {} timed out", node.name))??;
    Ok(started.elapsed())
}

/// Probe once and record the outcome on the node.
pub async fn probe_and_record(node: &Node, cfg: &HealthCfg) {
    match probe(node, Duration::from_millis(cfg.timeout_ms)).await {
        Ok(rtt) => {
            let was_down = !node.is_healthy();
            node.record_success(rtt);
            if was_down {
                tracing::info!(proxy = %node.name, "proxy is healthy again");
            }
        }
        Err(e) if crate::errno::is_local_shortage(&e) => {
            tracing::debug!(proxy = %node.name, "probe skipped for lack of local resources: {e:#}");
        }
        Err(e) => {
            let was_up = node.is_healthy();
            node.record_failure(cfg.fail_threshold);
            if was_up && !node.is_healthy() {
                tracing::warn!(proxy = %node.name, "proxy marked DOWN: {e:#}");
            } else {
                tracing::debug!(proxy = %node.name, "probe failed: {e:#}");
            }
        }
    }
}

/// Probe all nodes at once. A node that does not answer costs its own timeout,
/// not everyone's: probing one after another would make a round take
/// `dead_nodes x timeout` and delay the health news for the healthy ones.
pub async fn probe_round(nodes: &[Arc<Node>], cfg: &HealthCfg) {
    let mut set = tokio::task::JoinSet::new();
    for n in nodes {
        let (n, cfg) = (n.clone(), cfg.clone());
        set.spawn(async move { probe_and_record(&n, &cfg).await });
    }
    while set.join_next().await.is_some() {}
}

/// Probe every node now, then every `interval_secs`. Abort the handle to stop.
pub fn spawn(nodes: Vec<Arc<Node>>, cfg: HealthCfg) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            probe_round(&nodes, &cfg).await;
            tokio::time::sleep(Duration::from_secs(cfg.interval_secs.max(1))).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProxyCfg, ProxyKind};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn node(addr: std::net::SocketAddr, kind: ProxyKind) -> Arc<Node> {
        Node::new(ProxyCfg {
            name: "n".into(),
            kind,
            addr: addr.to_string(),
            username: None,
            password: None,
            weight: 1,
        })
        .unwrap()
    }

    async fn socks_stub() -> std::net::SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut c, _) = l.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut b = [0u8; 3];
                    if c.read_exact(&mut b).await.is_ok() {
                        let _ = c.write_all(&[5, 0]).await;
                    }
                });
            }
        });
        a
    }

    #[tokio::test]
    async fn a_proxy_that_turns_our_credentials_down_stays_down() {
        // Asks for a username and password, then rejects them, as it would
        // every real connection: probes must not bring it back up.
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut c, _) = l.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut g = [0u8; 4];
                    c.read_exact(&mut g).await.ok();
                    c.write_all(&[5, 2]).await.ok();
                    let mut auth = [0u8; 64];
                    let _ = c.read(&mut auth).await;
                    c.write_all(&[1, 1]).await.ok();
                });
            }
        });
        let n = Node::new(ProxyCfg {
            name: "n".into(),
            kind: ProxyKind::Socks5,
            addr: a.to_string(),
            username: Some("u".into()),
            password: Some("wrong".into()),
            weight: 1,
        })
        .unwrap();
        let cfg = HealthCfg {
            fail_threshold: 1,
            ..HealthCfg::default()
        };
        probe_and_record(&n, &cfg).await;
        assert!(!n.is_healthy());
        // Nor one that accepts none of our methods.
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut c, _) = l.accept().await.unwrap();
            let mut g = [0u8; 3];
            c.read_exact(&mut g).await.ok();
            c.write_all(&[5, 0xff]).await.ok();
        });
        let n = node(a, ProxyKind::Socks5);
        probe_and_record(&n, &cfg).await;
        assert!(!n.is_healthy());
    }

    #[tokio::test]
    async fn healthy_socks5_probe_records_latency() {
        let n = node(socks_stub().await, ProxyKind::Socks5);
        let cfg = HealthCfg::default();
        probe_and_record(&n, &cfg).await;
        assert!(n.is_healthy());
        assert!(n.latency_us() > 0);
        assert_eq!(n.stats().ok_total, 1);
    }

    #[tokio::test]
    async fn dead_proxy_goes_down_after_threshold_and_recovers() {
        let dead = crate::testutil::refused();
        let addr = dead.addr;
        let n = node(addr, ProxyKind::Socks5);
        let cfg = HealthCfg {
            interval_secs: 1,
            fail_threshold: 3,
            timeout_ms: 300,
        };
        probe_and_record(&n, &cfg).await;
        probe_and_record(&n, &cfg).await;
        assert!(n.is_healthy(), "two failures are below the threshold of three");
        probe_and_record(&n, &cfg).await;
        assert!(!n.is_healthy());

        // Bring a server up on the same port: the next probe revives the node.
        let l = TcpListener::from_std(dead.into_listener()).unwrap();
        tokio::spawn(async move {
            let (mut c, _) = l.accept().await.unwrap();
            let mut b = [0u8; 3];
            let _ = c.read_exact(&mut b).await;
            let _ = c.write_all(&[5, 0]).await;
        });
        probe_and_record(&n, &cfg).await;
        assert!(n.is_healthy());
    }

    #[tokio::test]
    async fn non_socks_server_fails_the_probe() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut c, _) = l.accept().await.unwrap();
            let _ = c.write_all(b"HTTP/1.1 400\r\n\r\n").await;
            let mut b = [0u8; 8];
            let _ = c.read(&mut b).await;
        });
        let n = node(addr, ProxyKind::Socks5);
        assert!(probe(&n, Duration::from_secs(1)).await.is_err());
    }

    #[tokio::test]
    async fn silent_server_times_out() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (_c, _) = l.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        let n = node(addr, ProxyKind::Socks5);
        let t0 = Instant::now();
        assert!(probe(&n, Duration::from_millis(200)).await.is_err());
        assert!(t0.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn http_proxy_probe_is_tcp_connect_only() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let _keep = l.accept().await;
            std::future::pending::<()>().await;
        });
        let n = node(addr, ProxyKind::Http);
        assert!(probe(&n, Duration::from_secs(1)).await.is_ok());
    }

    #[tokio::test]
    async fn silent_nodes_do_not_delay_each_other() {
        // Five proxies that accept and never answer: each probe waits out its
        // full timeout. Probed one after another that is 5 x 400 ms.
        let mut nodes = vec![];
        let mut keep = vec![];
        for _ in 0..5 {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            nodes.push(node(l.local_addr().unwrap(), ProxyKind::Socks5));
            keep.push(tokio::spawn(async move {
                let mut held = vec![];
                while let Ok((c, _)) = l.accept().await {
                    held.push(c);
                }
            }));
        }
        // ...and one healthy one that must be reported promptly.
        nodes.push(node(socks_stub().await, ProxyKind::Socks5));
        let cfg = HealthCfg {
            interval_secs: 10,
            fail_threshold: 1,
            timeout_ms: 400,
        };
        let t0 = Instant::now();
        probe_round(&nodes, &cfg).await;
        let took = t0.elapsed();
        assert!(
            took < Duration::from_millis(1000),
            "round took {took:?}; probes must run concurrently"
        );
        assert!(nodes[..5].iter().all(|n| !n.is_healthy()), "silent nodes marked down");
        assert!(nodes[5].is_healthy());
        assert!(nodes[5].latency_us() > 0);
    }
}
