//! Transport-layer configuration types.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use rustbgpd_fsm::PeerConfig;

/// Private AS removal mode for eBGP outbound `AS_PATH` manipulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RemovePrivateAs {
    /// No removal (default).
    #[default]
    Disabled,
    /// Remove all private ASNs only if the entire path is private.
    Remove,
    /// Unconditionally remove all private ASNs from every segment.
    All,
    /// Replace each private ASN with the local ASN.
    Replace,
}

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
    /// Optional peer-group name used for policy matching and operator visibility.
    pub peer_group: Option<String>,
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
    /// Long-lived stale routes time (RFC 9494, seconds). 0 = disabled.
    pub llgr_stale_time: u32,
    /// Local restarting-speaker GR window. When set, outbound OPEN messages
    /// advertise `restart_state = true` until this deadline.
    pub gr_restart_until: Option<Instant>,
    /// Whether this neighbor is a route reflector client (RFC 4456).
    pub route_reflector_client: bool,
    /// Whether this eBGP neighbor is a transparent route-server client.
    pub route_server_client: bool,
    /// Private AS removal mode for eBGP outbound `AS_PATH`.
    pub remove_private_as: RemovePrivateAs,
    /// Local cluster ID for route reflection. `Some` means this speaker is a
    /// route reflector; used for `CLUSTER_LIST` prepend and loop detection.
    pub cluster_id: Option<Ipv4Addr>,
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
            peer_group: None,
            md5_password: None,
            ttl_security: false,
            local_ipv6_nexthop: None,
            gr_stale_routes_time: 360,
            llgr_stale_time: 0,
            gr_restart_until: None,
            route_reflector_client: false,
            route_server_client: false,
            remove_private_as: RemovePrivateAs::Disabled,
            cluster_id: None,
        }
    }
}
