//! BMP event types, peer info, and client configuration.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::SystemTime;

use bytes::Bytes;
use tokio::sync::mpsc;

/// BMP event sent from transport to BMP manager.
#[derive(Debug)]
pub enum BmpEvent {
    /// Peer session established.
    PeerUp {
        /// Per-peer header data.
        peer_info: BmpPeerInfo,
        /// Raw local OPEN PDU bytes (including 19-byte BGP header).
        local_open: Bytes,
        /// Raw remote OPEN PDU bytes (including 19-byte BGP header).
        remote_open: Bytes,
        /// Local IP address of the TCP session.
        local_addr: IpAddr,
        /// Local TCP port.
        local_port: u16,
        /// Remote TCP port.
        remote_port: u16,
    },
    /// Peer session went down.
    PeerDown {
        /// Per-peer header data.
        peer_info: BmpPeerInfo,
        /// Reason the session went down.
        reason: PeerDownReason,
    },
    /// UPDATE monitoring. Inbound pre-policy Adj-RIB-In when
    /// `peer_info.is_rib_out` is false; outbound post-policy Adj-RIB-Out
    /// (RFC 8671) when true.
    RouteMonitoring {
        /// Per-peer header data.
        peer_info: BmpPeerInfo,
        /// Raw UPDATE PDU bytes (including 19-byte BGP header).
        update_pdu: Bytes,
    },
    /// Periodic per-peer statistics report.
    StatsReport {
        /// Per-peer header data.
        peer_info: BmpPeerInfo,
        /// RFC 7854 type 7: routes in Adj-RIB-In.
        adj_rib_in_routes: u64,
        /// RFC 8671 post-policy Adj-RIB-Out counts per `(afi, safi)`,
        /// encoded as stat type 17 entries plus their sum as type 15.
        /// `None` means the counts were unavailable this tick — types
        /// 15/17 are omitted rather than reported as a false zero.
        adj_rib_out_post: Option<Vec<(u16, u8, u64)>>,
    },
    /// RFC 9069 Loc-RIB route monitoring: a synthesized UPDATE PDU for a
    /// Loc-RIB best-path change, attributed to the emulated Loc-RIB
    /// instance peer (peer type 3). The manager builds the per-peer
    /// header from its [`BmpLocRibConfig`]; dropped when Loc-RIB
    /// monitoring is not configured.
    LocRibRouteMonitoring {
        /// Synthesized BGP UPDATE PDU (including 19-byte BGP header),
        /// 4-octet-ASN encoded per RFC 9069 §5.4.
        update_pdu: Bytes,
        /// Route install time (RFC 9069 per-peer header timestamp).
        timestamp: SystemTime,
    },
    /// RFC 9069 Loc-RIB statistics: per-AFI/SAFI Loc-RIB route counts.
    /// Encoded as stat type 10 entries plus their sum as type 8.
    LocRibStats {
        /// `(afi, safi, count)` for each monitored Loc-RIB family.
        per_family: Vec<(u16, u8, u64)>,
    },
}

/// Identity of the emulated RFC 9069 Loc-RIB instance peer (peer type 3).
///
/// Built once at startup; the manager uses it for every Loc-RIB per-peer
/// header and for the fabricated Peer Up / Peer Down messages.
#[derive(Debug, Clone)]
pub struct BmpLocRibConfig {
    /// Local (primary) BGP autonomous system number → Peer AS field.
    pub local_asn: u32,
    /// Local BGP router ID → Peer BGP ID field (global instance).
    pub router_id: Ipv4Addr,
    /// Fabricated BGP OPEN PDU (including 19-byte header) carrying the
    /// 4-octet-ASN capability plus an MP capability for every AFI/SAFI
    /// streamed on the Loc-RIB view (RFC 9069 §5.2.1). Used verbatim as
    /// both the sent and received OPEN in the Peer Up notification.
    pub open_pdu: Bytes,
}

/// RFC 9069 VRF/Table Name for the default (global) Loc-RIB instance.
pub const LOC_RIB_TABLE_NAME: &str = "global";

impl BmpLocRibConfig {
    /// Per-peer header identity for the Loc-RIB instance peer at a given
    /// timestamp: peer type 3, zero-filled peer address, distinguisher 0
    /// (global instance), Peer AS = local AS, BGP ID = local router-id.
    #[must_use]
    pub fn peer_info(&self, timestamp: SystemTime) -> BmpPeerInfo {
        BmpPeerInfo {
            peer_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            peer_asn: self.local_asn,
            peer_bgp_id: self.router_id,
            peer_type: BmpPeerType::LocRib,
            is_ipv6: false,
            is_post_policy: false,
            is_rib_out: false,
            is_as4: true,
            timestamp,
        }
    }
}

/// A Loc-RIB table-dump request from the BMP manager to the RIB manager,
/// issued when a collector monitoring `loc_rib` (re)connects.
///
/// The RIB manager answers with bounded [`BmpDumpChunk`]s (synthesized
/// UPDATE PDUs with per-route install timestamps, ending with one
/// End-of-RIB PDU per dumped AFI/SAFI) and then drops the sender.
#[derive(Debug)]
pub struct BmpDumpRequest {
    /// Chunk reply channel. Bounded — the dump producer paces on it.
    pub reply: mpsc::Sender<BmpDumpChunk>,
}

/// One bounded chunk of a Loc-RIB table dump.
#[derive(Debug)]
pub struct BmpDumpChunk {
    /// Synthesized UPDATE PDUs with their route install times.
    pub messages: Vec<(Bytes, SystemTime)>,
}

/// Control-plane events sent from BMP clients to the BMP manager.
#[derive(Debug, Clone, Copy)]
pub enum BmpControlEvent {
    /// A collector connected and successfully completed BMP Initiation.
    CollectorConnected {
        /// Index of the collector in the configuration list.
        collector_id: usize,
        /// TCP socket address of the collector.
        collector_addr: SocketAddr,
    },
    /// A collector disconnected after previously being connected.
    CollectorDisconnected {
        /// Index of the collector in the configuration list.
        collector_id: usize,
        /// TCP socket address of the collector.
        collector_addr: SocketAddr,
    },
    /// Coordinated daemon shutdown request.
    ///
    /// The BMP manager stops fan-out and drops collector channels so
    /// per-collector clients can send BMP Termination and exit.
    Shutdown,
}

/// Information about a monitored peer, used to build the BMP per-peer header.
#[expect(
    clippy::struct_excessive_bools,
    reason = "each bool mirrors one RFC 7854/8671 per-peer header flag bit (V/L/A/O)"
)]
#[derive(Debug, Clone)]
pub struct BmpPeerInfo {
    /// Remote peer IP address.
    pub peer_addr: IpAddr,
    /// Remote peer ASN.
    pub peer_asn: u32,
    /// Remote peer BGP identifier.
    pub peer_bgp_id: Ipv4Addr,
    /// BMP peer type (Global / RD Instance / Local).
    pub peer_type: BmpPeerType,
    /// Whether the peer address is IPv6.
    pub is_ipv6: bool,
    /// Whether this is a post-policy view.
    pub is_post_policy: bool,
    /// Whether this is an Adj-RIB-Out view (RFC 8671 O flag). Under
    /// O=1 the L flag (`is_post_policy`) distinguishes pre/post-policy
    /// Adj-RIB-Out; rustbgpd only emits post-policy (O=1, L=1).
    pub is_rib_out: bool,
    /// Whether the peer uses 4-octet AS numbers.
    pub is_as4: bool,
    /// Timestamp of the event.
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
    /// Loc-RIB Instance Peer (RFC 9069).
    LocRib = 3,
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

/// Which route-monitoring streams a collector receives.
///
/// Non-monitoring messages (Peer Up/Down, Stats, Initiation,
/// Termination) always go to every collector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BmpMonitorFilter {
    /// Pre-policy Adj-RIB-In route monitoring (RFC 7854, O=0).
    pub rib_in_pre: bool,
    /// Post-policy Adj-RIB-Out route monitoring (RFC 8671, O=1, L=1).
    pub rib_out_post: bool,
    /// Loc-RIB instance monitoring (RFC 9069, peer type 3). Unlike the
    /// other views, this also scopes the Loc-RIB pseudo-peer's Peer
    /// Up/Down and Stats messages — a collector not monitoring
    /// `loc_rib` never sees the emulated peer at all.
    pub loc_rib: bool,
}

impl Default for BmpMonitorFilter {
    /// Pre-RFC 8671 behavior: Adj-RIB-In monitoring only.
    fn default() -> Self {
        Self {
            rib_in_pre: true,
            rib_out_post: false,
            loc_rib: false,
        }
    }
}

/// Configuration for a single BMP collector.
#[derive(Debug, Clone)]
pub struct BmpClientConfig {
    /// Stable collector index assigned at startup.
    pub collector_id: usize,
    /// Collector TCP socket address.
    pub collector_addr: SocketAddr,
    /// Seconds between reconnection attempts (default: 30).
    pub reconnect_interval: u64,
}
