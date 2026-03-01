use std::net::{Ipv6Addr, SocketAddr};
use std::time::Duration;

use rustbgpd_fsm::PeerConfig;

/// Transport-layer configuration for a single BGP peer.
#[derive(Clone)]
pub struct TransportConfig {
    /// FSM-level peer configuration (ASN, hold time, router ID, etc.).
    pub peer: PeerConfig,
    /// TCP address of the remote peer (typically port 179).
    pub remote_addr: SocketAddr,
    /// Timeout for outbound TCP connect attempts.
    pub connect_timeout: Duration,
    /// Maximum number of prefixes accepted from this peer before Cease/1.
    pub max_prefixes: Option<u32>,
    /// TCP MD5 authentication password (RFC 2385).
    pub md5_password: Option<String>,
    /// Enable GTSM / TTL security (RFC 5082).
    pub ttl_security: bool,
    /// Explicit IPv6 next-hop for eBGP advertisements. Used when the TCP
    /// session is IPv4 but IPv6 routes need a valid next-hop in
    /// `MP_REACH_NLRI`. If `None`, the local IPv6 socket address is used
    /// (if available); otherwise IPv6 routes are suppressed.
    pub local_ipv6_nexthop: Option<Ipv6Addr>,
    /// Time to retain stale routes after peer restart (seconds). RFC 4724.
    pub gr_stale_routes_time: u64,
}

impl TransportConfig {
    /// Default TCP connect timeout (30 seconds).
    const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

    /// Create a new transport config with default connect timeout.
    #[must_use]
    pub fn new(peer: PeerConfig, remote_addr: SocketAddr) -> Self {
        Self {
            peer,
            remote_addr,
            connect_timeout: Self::DEFAULT_CONNECT_TIMEOUT,
            max_prefixes: None,
            md5_password: None,
            ttl_security: false,
            local_ipv6_nexthop: None,
            gr_stale_routes_time: 360,
        }
    }
}
