use std::net::SocketAddr;
use std::time::Duration;

use rustbgpd_fsm::PeerConfig;

/// Transport-layer configuration for a single BGP peer.
pub struct TransportConfig {
    /// FSM-level peer configuration (ASN, hold time, router ID, etc.).
    pub peer: PeerConfig,
    /// TCP address of the remote peer (typically port 179).
    pub remote_addr: SocketAddr,
    /// Timeout for outbound TCP connect attempts.
    pub connect_timeout: Duration,
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
        }
    }
}
