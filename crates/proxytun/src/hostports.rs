//! The namespace's loopback is its own and starts empty, so a program that
//! talks to a service on the host's 127.0.0.1 (a database, a dev server, a
//! proxy on 127.0.0.1:7890) would find nothing there. At start-up we read the
//! host's listening TCP sockets once; the setup process binds the same
//! addresses inside the namespace (while it still may, low ports included),
//! and we relay each connection to the host, from the host.
//!
//! Mapping (forwarded address = namespace address = host address dialed):
//!   127.x.x.x:P -> itself;   0.0.0.0:P -> 127.0.0.1:P;
//!   [::1]:P -> itself;       [::]:P -> 127.0.0.1:P and [::1]:P (dual-stack).
//! Port 53 is never forwarded (DNS must reach the fake-ip DNS), nor are ports
//! the user excluded, nor listeners opened after start-up.

use crate::capture::Shared;
use proxytun_core::net::relay;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tracing::Instrument;

/// The fds of one setup answer must fit in one SCM_RIGHTS message (the kernel
/// takes at most 253), together with the TUN device and the capture listener.
pub const MAX_FORWARDS: usize = 250;

const LISTEN: &str = "0A";

/// Listening sockets in /proc/net/tcp (`v6` false) or tcp6 format.
pub fn listening(table: &str, v6: bool) -> Vec<SocketAddr> {
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let mut f = line.split_whitespace();
            let local = f.nth(1)?;
            if f.nth(1)? != LISTEN {
                return None;
            }
            let (ip, port) = local.split_once(':')?;
            let port = u16::from_str_radix(port, 16).ok()?;
            // The kernel prints the address as 32-bit words in host order.
            let mut bytes = Vec::with_capacity(16);
            for i in (0..ip.len()).step_by(8) {
                let word = u32::from_str_radix(ip.get(i..i + 8)?, 16).ok()?;
                bytes.extend_from_slice(&word.to_ne_bytes());
            }
            let ip = match (v6, bytes.len()) {
                (false, 4) => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).ok()?)),
                (true, 16) => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?)),
                _ => return None,
            };
            Some(SocketAddr::new(ip, port))
        })
        .collect()
}

/// What to forward for these host listeners (see the module docs).
pub fn forwards(listening: &[SocketAddr], exclude: &[u16]) -> Vec<SocketAddr> {
    let v4 = |p| SocketAddr::new(Ipv4Addr::LOCALHOST.into(), p);
    let v6 = |p| SocketAddr::new(Ipv6Addr::LOCALHOST.into(), p);
    let mut out = BTreeSet::new();
    for a in listening {
        let p = a.port();
        if p == 53 || exclude.contains(&p) {
            continue;
        }
        let ip = match a.ip() {
            IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
            ip => ip,
        };
        match ip {
            IpAddr::V4(ip) if ip.is_loopback() => {
                out.insert(SocketAddr::new(ip.into(), p));
            }
            IpAddr::V4(ip) if ip.is_unspecified() => {
                out.insert(v4(p));
            }
            IpAddr::V6(ip) if ip.is_loopback() => {
                out.insert(v6(p));
            }
            IpAddr::V6(ip) if ip.is_unspecified() => {
                out.insert(v4(p));
                out.insert(v6(p));
            }
            _ => {} // a specific outward address: reached through the TUN
        }
    }
    out.into_iter().collect()
}

/// Read the host's listeners now and work out the forwards, at most
/// `MAX_FORWARDS` (the rest are named in a warning).
pub fn scan(exclude: &[u16]) -> Vec<SocketAddr> {
    let read = |p| std::fs::read_to_string(p).unwrap_or_default();
    let mut found = listening(&read("/proc/net/tcp"), false);
    found.extend(listening(&read("/proc/net/tcp6"), true));
    let mut fwd = forwards(&found, exclude);
    if fwd.len() > MAX_FORWARDS {
        let dropped: Vec<String> = fwd.split_off(MAX_FORWARDS).iter().map(|a| a.to_string()).collect();
        tracing::warn!(
            count = dropped.len(),
            "too many host listeners; not forwarding {}",
            dropped.join(", ")
        );
    }
    fwd
}

/// Relay connections to the namespace's `addr` to the host's `addr`.
pub async fn serve(listener: TcpListener, addr: SocketAddr, sh: Arc<Shared>) {
    loop {
        let (mut inbound, _) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(%addr, "host port accept: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                continue;
            }
        };
        let id = sh.next_conn_id();
        let span = tracing::error_span!("conn", id, target = %addr);
        let sh = sh.clone();
        tokio::spawn(
            async move {
                sh.stats.connections.fetch_add(1, Ordering::Relaxed);
                sh.stats.active.fetch_add(1, Ordering::Relaxed);
                tracing::info!("routing to the host's own port");
                let r = match TcpStream::connect(addr).await {
                    Ok(mut out) => relay::pump(&mut inbound, &mut out, sh.live().splice).await,
                    Err(e) => Err(e.into()),
                };
                sh.stats.active.fetch_sub(1, Ordering::Relaxed);
                if let Err(e) = r {
                    tracing::debug!("host port relay error: {e:#}");
                }
            }
            .instrument(span),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    // Real lines (little-endian host), trimmed after the inode column.
    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000   120        0 1
   1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 2
   2: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 3
   3: 0100007F:1538 0100007F:9C40 01 00000000:00000000 00:00000000 00000000   120        0 4
   4: 0501A8C0:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5
";
    const TCP6: &str = "  sl  local_address                         remote_address                        st
   0: 00000000000000000000000001000000:0BB8 00000000000000000000000000000000:0000 0A
   1: 00000000000000000000000000000000:1F91 00000000000000000000000000000000:0000 0A
   2: 0000000000000000FFFF00000100007F:2710 00000000000000000000000000000000:0000 0A
";

    #[test]
    fn proc_net_tables_are_read_in_host_byte_order() {
        assert_eq!(
            listening(TCP, false),
            [
                sa("127.0.0.1:5432"),
                sa("0.0.0.0:8080"),
                sa("127.0.0.53:53"),
                sa("192.168.1.5:22")
            ],
            "only LISTEN sockets"
        );
        assert_eq!(
            listening(TCP6, true),
            [sa("[::1]:3000"), sa("[::]:8081"), sa("[::ffff:127.0.0.1]:10000")]
        );
        assert!(listening("header only\n", false).is_empty());
        assert!(
            listening("h\n 0: zz:1 00:0 0A\n", false).is_empty(),
            "garbage is skipped"
        );
    }

    #[test]
    fn forwards_follow_the_mapping_rules() {
        let mut all = listening(TCP, false);
        all.extend(listening(TCP6, true));
        assert_eq!(
            forwards(&all, &[]),
            [
                sa("127.0.0.1:5432"),
                sa("127.0.0.1:8080"),
                sa("127.0.0.1:8081"),
                sa("127.0.0.1:10000"),
                sa("[::1]:3000"),
                sa("[::1]:8081"),
            ],
            "53 skipped (DNS stays ours), 192.168.1.5 left to the TUN, [::] on both families"
        );
        assert_eq!(
            forwards(&[sa("127.0.0.1:5432"), sa("0.0.0.0:5432"), sa("127.0.0.1:80")], &[80]),
            [sa("127.0.0.1:5432")],
            "duplicates merged, excluded ports dropped"
        );
    }
}
