use std::net::{IpAddr, Ipv6Addr};

use bytes::Bytes;
use rustbgpd_fsm::SessionState;
use rustbgpd_policy::PolicyChain;
use rustbgpd_wire::{Afi, Safi};
use tokio::net::TcpStream;
use tokio::sync::oneshot;

/// Commands sent to the `PeerManager` task.
pub enum PeerManagerCommand {
    AddPeer {
        config: PeerManagerNeighborConfig,
        reply: oneshot::Sender<Result<(), String>>,
    },
    DeletePeer {
        address: IpAddr,
        reply: oneshot::Sender<Result<(), String>>,
    },
    ListPeers {
        reply: oneshot::Sender<Vec<PeerInfo>>,
    },
    GetPeerState {
        address: IpAddr,
        reply: oneshot::Sender<Option<PeerInfo>>,
    },
    EnablePeer {
        address: IpAddr,
        reply: oneshot::Sender<Result<(), String>>,
    },
    DisablePeer {
        address: IpAddr,
        /// RFC 8203 shutdown communication reason (pre-encoded).
        reason: Option<Bytes>,
        reply: oneshot::Sender<Result<(), String>>,
    },
    SoftResetIn {
        address: IpAddr,
        families: Vec<(Afi, Safi)>,
        reply: oneshot::Sender<Result<(), String>>,
    },
    AcceptInbound {
        stream: TcpStream,
        peer_addr: IpAddr,
    },
    Shutdown,
}

/// Configuration for adding a peer dynamically.
#[expect(clippy::struct_excessive_bools)]
pub struct PeerManagerNeighborConfig {
    pub address: IpAddr,
    pub remote_asn: u32,
    pub description: String,
    pub hold_time: Option<u16>,
    pub max_prefixes: Option<u32>,
    pub families: Vec<(Afi, Safi)>,
    pub graceful_restart: bool,
    pub gr_restart_time: u16,
    pub gr_stale_routes_time: u64,
    pub local_ipv6_nexthop: Option<Ipv6Addr>,
    pub route_reflector_client: bool,
    pub add_path_receive: bool,
    pub add_path_send: bool,
    pub add_path_send_max: u32,
    pub import_policy: Option<PolicyChain>,
    pub export_policy: Option<PolicyChain>,
}

/// Snapshot of a peer's state for queries.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub address: IpAddr,
    pub remote_asn: u32,
    pub description: String,
    pub state: SessionState,
    pub enabled: bool,
    pub prefix_count: usize,
    pub hold_time: Option<u16>,
    pub max_prefixes: Option<u32>,
    pub families: Vec<(Afi, Safi)>,
    pub updates_received: u64,
    pub updates_sent: u64,
    pub notifications_received: u64,
    pub notifications_sent: u64,
    pub flap_count: u64,
    pub uptime_secs: u64,
    pub last_error: String,
}
