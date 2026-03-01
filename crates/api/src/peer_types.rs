use std::net::{IpAddr, Ipv6Addr};

use rustbgpd_fsm::SessionState;
use rustbgpd_policy::PrefixList;
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
        reply: oneshot::Sender<Result<(), String>>,
    },
    AcceptInbound {
        stream: TcpStream,
        peer_addr: IpAddr,
    },
    Shutdown,
}

/// Configuration for adding a peer dynamically.
pub struct PeerManagerNeighborConfig {
    pub address: IpAddr,
    pub remote_asn: u32,
    pub description: String,
    pub hold_time: Option<u16>,
    pub max_prefixes: Option<u32>,
    pub families: Vec<(Afi, Safi)>,
    pub local_ipv6_nexthop: Option<Ipv6Addr>,
    pub import_policy: Option<PrefixList>,
    pub export_policy: Option<PrefixList>,
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
