//! Transport-layer configuration types.

use std::fmt;
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

/// TCP-AO MAC/KDF algorithm names accepted by Linux's TCP-AO UAPI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpAoAlgorithm {
    HmacSha1,
    HmacSha256,
    CmacAes128,
}

impl TcpAoAlgorithm {
    /// Return the Linux UAPI algorithm name.
    #[must_use]
    pub const fn linux_name(self) -> &'static str {
        match self {
            Self::HmacSha1 => "hmac(sha1)",
            Self::HmacSha256 => "hmac(sha256)",
            Self::CmacAes128 => "cmac(aes128)",
        }
    }

    /// Parse a Linux UAPI algorithm name.
    #[must_use]
    pub fn from_linux_name(name: &str) -> Option<Self> {
        match name {
            "hmac(sha1)" => Some(Self::HmacSha1),
            "hmac(sha256)" => Some(Self::HmacSha256),
            "cmac(aes128)" => Some(Self::CmacAes128),
            _ => None,
        }
    }
}

/// Static-neighbor TCP-AO configuration for one peer.
#[derive(Clone, PartialEq, Eq)]
pub struct TcpAoConfig {
    /// TCP-AO Master Key Tuple secret.
    pub key: String,
    /// Sender `KeyID` (`sndid` in Linux's TCP-AO UAPI).
    pub send_id: u8,
    /// Receiver `KeyID` (`rcvid` in Linux's TCP-AO UAPI).
    pub recv_id: u8,
    /// TCP-AO MAC/KDF algorithm.
    pub algorithm: TcpAoAlgorithm,
    /// Rollover metadata reserved for future multi-key support.
    pub preferred: bool,
    /// Rollover metadata reserved for future multi-key support.
    pub deprecated: bool,
}

impl fmt::Debug for TcpAoConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpAoConfig")
            .field("key", &"<redacted>")
            .field("send_id", &self.send_id)
            .field("recv_id", &self.recv_id)
            .field("algorithm", &self.algorithm)
            .field("preferred", &self.preferred)
            .field("deprecated", &self.deprecated)
            .finish()
    }
}

/// Transport-layer configuration for a single BGP peer.
#[derive(Clone, Debug)]
pub struct TransportConfig {
    /// FSM-level peer configuration (ASN, hold time, router ID, etc.).
    pub peer: PeerConfig,
    /// TCP address of the remote peer (typically port 179).
    pub remote_addr: SocketAddr,
    /// Configured interface for IPv6 link-local / unnumbered peers.
    pub peer_interface: Option<String>,
    /// Resolved interface index for scoped IPv6 link-local peers.
    pub peer_scope_id: Option<u32>,
    /// Timeout for outbound TCP connect attempts.
    pub connect_timeout: Duration,
    /// Maximum number of prefixes accepted from this peer before Cease/1.
    pub max_prefixes: Option<u32>,
    /// Optional peer-group name used for policy matching and operator visibility.
    pub peer_group: Option<String>,
    /// TCP MD5 authentication password (RFC 2385).
    pub md5_password: Option<String>,
    /// TCP-AO authentication key (RFC 5925).
    pub tcp_ao: Option<TcpAoConfig>,
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
            peer_interface: None,
            peer_scope_id: None,
            connect_timeout: Self::DEFAULT_CONNECT_TIMEOUT,
            max_prefixes: None,
            peer_group: None,
            md5_password: None,
            tcp_ao: None,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_ao_config_debug_redacts_key() {
        let config = TcpAoConfig {
            key: "secret".to_string(),
            send_id: 1,
            recv_id: 1,
            algorithm: TcpAoAlgorithm::HmacSha256,
            preferred: false,
            deprecated: false,
        };

        let rendered = format!("{config:?}");

        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("secret"));
    }
}
