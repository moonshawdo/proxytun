//! Shared types passed between traffic capture (the TUN side) and the async
//! relay/DNS side.

use crate::net::fakeip::FakeGuard;
use std::net::Ipv4Addr;

/// The *real* target the relay should connect to, after fake-ip reverse lookup.
/// A `Domain` means "we recovered the original hostname, send it to the proxy
/// as-is so Clash can do domain-based routing".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Domain(String, u16),
    V4(Ipv4Addr, u16),
}

impl Target {
    pub fn port(&self) -> u16 {
        match self {
            Target::Domain(_, p) | Target::V4(_, p) => *p,
        }
    }

    /// Key used by the `hash` balancing strategy: the host part only, so every
    /// port of one domain maps to the same proxy.
    pub fn host_key(&self) -> String {
        match self {
            Target::Domain(d, _) => d.clone(),
            Target::V4(ip, _) => ip.to_string(),
        }
    }
}

/// Where the relay should send a given connection, decided by the rule engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Forward through the named proxy group, preserving the Target (domain kept).
    Proxy { group: String },
    /// Connect directly from this host (relay resolves the domain itself if needed).
    Direct,
    /// Drop the connection.
    Block,
}

/// One captured connection handed to the relay: where the program meant to go.
pub struct Pending {
    pub target: Target,
    /// Keeps the fake-ip mapping pinned (un-evictable) while the connection lives.
    pub guard: Option<FakeGuard>,
}
