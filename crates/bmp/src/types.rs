use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::SystemTime;

use bytes::Bytes;

/// BMP event sent from transport to BMP manager.
#[derive(Debug)]
pub enum BmpEvent {
    /// Peer session established.
    PeerUp {
        peer_info: BmpPeerInfo,
        /// Raw local OPEN PDU bytes (including 19-byte BGP header).
        local_open: Bytes,
        /// Raw remote OPEN PDU bytes (including 19-byte BGP header).
        remote_open: Bytes,
        local_addr: IpAddr,
        local_port: u16,
        remote_port: u16,
    },
    /// Peer session went down.
    PeerDown {
        peer_info: BmpPeerInfo,
        reason: PeerDownReason,
    },
    /// Inbound UPDATE received (pre-policy).
    RouteMonitoring {
        peer_info: BmpPeerInfo,
        /// Raw UPDATE PDU bytes (including 19-byte BGP header).
        update_pdu: Bytes,
    },
    /// Periodic per-peer statistics report.
    StatsReport {
        peer_info: BmpPeerInfo,
        /// RFC 7854 type 7: routes in Adj-RIB-In.
        adj_rib_in_routes: u64,
    },
}

/// Control-plane events sent from BMP clients to the BMP manager.
#[derive(Debug, Clone, Copy)]
pub enum BmpControlEvent {
    /// A collector connected and successfully completed BMP Initiation.
    CollectorConnected {
        collector_id: usize,
        collector_addr: SocketAddr,
    },
    /// A collector disconnected after previously being connected.
    CollectorDisconnected {
        collector_id: usize,
        collector_addr: SocketAddr,
    },
}

/// Information about a monitored peer, used to build the BMP per-peer header.
#[derive(Debug, Clone)]
pub struct BmpPeerInfo {
    pub peer_addr: IpAddr,
    pub peer_asn: u32,
    pub peer_bgp_id: Ipv4Addr,
    pub peer_type: BmpPeerType,
    pub is_ipv6: bool,
    pub is_post_policy: bool,
    pub is_as4: bool,
    pub timestamp: SystemTime,
}

/// BMP peer type field (RFC 7854 §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BmpPeerType {
    /// Global Instance Peer.
    Global = 0,
    /// RD Instance Peer.
    RdInstance = 1,
    /// Local Instance Peer.
    Local = 2,
}

/// Reason for peer session going down (RFC 7854 §4.9).
#[derive(Debug)]
pub enum PeerDownReason {
    /// Type 1: Local system sent NOTIFICATION.
    LocalNotification(Bytes),
    /// Type 2: Local system closed session (FSM event code).
    LocalNoNotification(u16),
    /// Type 3: Remote system sent NOTIFICATION.
    RemoteNotification(Bytes),
    /// Type 4: Remote system closed TCP without NOTIFICATION.
    RemoteNoNotification,
}

/// Configuration for a single BMP collector.
#[derive(Debug, Clone)]
pub struct BmpClientConfig {
    /// Stable collector index assigned at startup.
    pub collector_id: usize,
    pub collector_addr: SocketAddr,
    /// Seconds between reconnection attempts (default: 30).
    pub reconnect_interval: u64,
}
