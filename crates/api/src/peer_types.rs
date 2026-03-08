//! Shared types for peer management across the API and `PeerManager`.

use std::net::{IpAddr, Ipv6Addr};

use bytes::Bytes;
use rustbgpd_fsm::SessionState;
use rustbgpd_policy::PolicyChain;
use rustbgpd_transport::RemovePrivateAs;
use rustbgpd_wire::{Afi, Safi};
use tokio::net::TcpStream;
use tokio::sync::oneshot;

/// Kind of reconciliation failure returned to config reload callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileFailureKind {
    /// Failed to add a new peer.
    Add,
    /// Failed to remove an existing peer.
    Remove,
    /// Failed to remove the old config during a peer change.
    ChangeRemove,
    /// Failed to add the new config during a peer change.
    ChangeAdd,
}

/// One failed peer reconciliation operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileFailure {
    /// Which reconciliation step failed.
    pub kind: ReconcileFailureKind,
    /// Peer address that failed.
    pub address: IpAddr,
    /// Human-readable error description.
    pub error: String,
}

/// Result of a peer reconciliation run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcileResult {
    /// List of individual failures (empty means success).
    pub failures: Vec<ReconcileFailure>,
}

impl ReconcileResult {
    /// Returns `true` if all reconciliation operations succeeded.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.failures.is_empty()
    }
}

/// Commands sent to the `PeerManager` task.
pub enum PeerManagerCommand {
    /// Add a new peer with the given configuration.
    AddPeer {
        /// Neighbor configuration.
        config: PeerManagerNeighborConfig,
        /// Whether to update the live config snapshot.
        sync_config_snapshot: bool,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Remove an existing peer by address.
    DeletePeer {
        /// Peer IP address to remove.
        address: IpAddr,
        /// Whether to update the live config snapshot.
        sync_config_snapshot: bool,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// List all configured peers and their state.
    ListPeers {
        /// Reply channel returning all peer snapshots.
        reply: oneshot::Sender<Vec<PeerInfo>>,
    },
    /// Query a single peer's state by address.
    GetPeerState {
        /// Peer IP address to query.
        address: IpAddr,
        /// Reply channel returning the peer snapshot (None if not found).
        reply: oneshot::Sender<Option<PeerInfo>>,
    },
    /// Start (enable) a previously disabled peer.
    EnablePeer {
        /// Peer IP address to enable.
        address: IpAddr,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Disable (stop) a peer, optionally with a shutdown reason.
    DisablePeer {
        /// Peer IP address to disable.
        address: IpAddr,
        /// RFC 8203 shutdown communication reason (pre-encoded).
        reason: Option<Bytes>,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Trigger a soft inbound reset (route refresh) for the given families.
    SoftResetIn {
        /// Peer IP address.
        address: IpAddr,
        /// Families to refresh (empty = all configured).
        families: Vec<(Afi, Safi)>,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Accept an inbound TCP connection for a known peer.
    AcceptInbound {
        /// Already-accepted TCP stream.
        stream: TcpStream,
        /// Remote peer IP address.
        peer_addr: IpAddr,
    },
    /// Reconcile peers after config reload (add/remove/change).
    ReconcilePeers {
        /// Neighbors to add.
        added: Vec<PeerManagerNeighborConfig>,
        /// Neighbor addresses to remove.
        removed: Vec<IpAddr>,
        /// Neighbors whose config changed (remove + re-add).
        changed: Vec<PeerManagerNeighborConfig>,
        /// Reply channel with reconciliation results.
        reply: oneshot::Sender<ReconcileResult>,
    },
    /// List all named policy definitions.
    ListPolicies {
        /// Reply channel returning all named policies.
        reply: oneshot::Sender<Vec<NamedPolicySnapshot>>,
    },
    /// Query a single named policy definition.
    GetPolicy {
        /// Policy definition name.
        name: String,
        /// Reply channel returning the definition if found.
        reply: oneshot::Sender<Option<NamedPolicyDefinition>>,
    },
    /// Create or replace a named policy definition.
    SetPolicy {
        /// Policy definition name.
        name: String,
        /// Full replacement definition.
        definition: NamedPolicyDefinition,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Delete a named policy definition.
    DeletePolicy {
        /// Policy definition name.
        name: String,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// List all named neighbor sets.
    ListNeighborSets {
        /// Reply channel returning all named neighbor sets.
        reply: oneshot::Sender<Vec<NamedNeighborSetSnapshot>>,
    },
    /// Query a single named neighbor set.
    GetNeighborSet {
        /// Neighbor-set name.
        name: String,
        /// Reply channel returning the definition if found.
        reply: oneshot::Sender<Option<NeighborSetDefinition>>,
    },
    /// Create or replace a named neighbor set.
    SetNeighborSet {
        /// Neighbor-set name.
        name: String,
        /// Full replacement definition.
        definition: NeighborSetDefinition,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Delete a named neighbor set.
    DeleteNeighborSet {
        /// Neighbor-set name.
        name: String,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Query global named import/export chains.
    GetGlobalPolicyChains {
        /// Reply channel returning configured chain names.
        reply: oneshot::Sender<PolicyChainAssignment>,
    },
    /// Replace the global import policy chain.
    SetGlobalImportChain {
        /// Ordered policy names.
        policy_names: Vec<String>,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Replace the global export policy chain.
    SetGlobalExportChain {
        /// Ordered policy names.
        policy_names: Vec<String>,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Clear the global import policy chain.
    ClearGlobalImportChain {
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Clear the global export policy chain.
    ClearGlobalExportChain {
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Query per-neighbor named import/export chains.
    GetNeighborPolicyChains {
        /// Neighbor address.
        address: IpAddr,
        /// Reply channel returning configured chain names if the neighbor exists.
        reply: oneshot::Sender<Option<PolicyChainAssignment>>,
    },
    /// Replace the per-neighbor import policy chain.
    SetNeighborImportChain {
        /// Neighbor address.
        address: IpAddr,
        /// Ordered policy names.
        policy_names: Vec<String>,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Replace the per-neighbor export policy chain.
    SetNeighborExportChain {
        /// Neighbor address.
        address: IpAddr,
        /// Ordered policy names.
        policy_names: Vec<String>,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Clear the per-neighbor import policy chain.
    ClearNeighborImportChain {
        /// Neighbor address.
        address: IpAddr,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Clear the per-neighbor export policy chain.
    ClearNeighborExportChain {
        /// Neighbor address.
        address: IpAddr,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// List all peer groups.
    ListPeerGroups {
        /// Reply channel returning all peer-group definitions.
        reply: oneshot::Sender<Vec<NamedPeerGroupSnapshot>>,
    },
    /// Query a single peer group.
    GetPeerGroup {
        /// Peer-group name.
        name: String,
        /// Reply channel returning the definition if found.
        reply: oneshot::Sender<Option<PeerGroupDefinition>>,
    },
    /// Create or replace a peer group.
    SetPeerGroup {
        /// Peer-group name.
        name: String,
        /// Full replacement definition.
        definition: PeerGroupDefinition,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Delete a peer group.
    DeletePeerGroup {
        /// Peer-group name.
        name: String,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Assign a neighbor to a peer group.
    SetNeighborPeerGroup {
        /// Neighbor address.
        address: IpAddr,
        /// Peer-group name.
        peer_group: String,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Clear a neighbor's peer-group membership.
    ClearNeighborPeerGroup {
        /// Neighbor address.
        address: IpAddr,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Shut down all peers and exit the peer manager task.
    Shutdown,
}

/// `AS_PATH` prepend configuration for policy modifications.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyAsPathPrependConfig {
    /// ASN to prepend.
    pub asn: u32,
    /// Number of times to prepend.
    pub count: u8,
}

/// Add-Path settings in config-shaped form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddPathDefinition {
    /// Enable Add-Path receive.
    pub receive: bool,
    /// Enable Add-Path send.
    pub send: bool,
    /// Maximum paths to send (`None` = default/unlimited).
    pub send_max: Option<u32>,
}

/// One policy statement in config-shaped form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyStatementDefinition {
    /// `"permit"` or `"deny"`.
    pub action: String,
    /// Optional prefix match in CIDR form.
    pub prefix: Option<String>,
    /// Optional minimum prefix length.
    pub ge: Option<u8>,
    /// Optional maximum prefix length.
    pub le: Option<u8>,
    /// Community match clauses.
    pub match_community: Vec<String>,
    /// Optional Cisco/Quagga style `AS_PATH` regex.
    pub match_as_path: Option<String>,
    /// Optional named neighbor-set match.
    pub match_neighbor_set: Option<String>,
    /// Optional route-source type match (`"local"`, `"internal"`, `"external"`).
    pub match_route_type: Option<String>,
    /// Optional minimum `AS_PATH` length.
    pub match_as_path_length_ge: Option<u32>,
    /// Optional maximum `AS_PATH` length.
    pub match_as_path_length_le: Option<u32>,
    /// Optional minimum `LOCAL_PREF` match.
    pub match_local_pref_ge: Option<u32>,
    /// Optional maximum `LOCAL_PREF` match.
    pub match_local_pref_le: Option<u32>,
    /// Optional minimum MED match.
    pub match_med_ge: Option<u32>,
    /// Optional maximum MED match.
    pub match_med_le: Option<u32>,
    /// Optional exact next-hop match.
    pub match_next_hop: Option<String>,
    /// Optional RPKI validation state match.
    pub match_rpki_validation: Option<String>,
    /// Optional `LOCAL_PREF` rewrite.
    pub set_local_pref: Option<u32>,
    /// Optional `MED` rewrite.
    pub set_med: Option<u32>,
    /// Optional next-hop rewrite (`"self"` or IP string).
    pub set_next_hop: Option<String>,
    /// Communities to add.
    pub set_community_add: Vec<String>,
    /// Communities to remove.
    pub set_community_remove: Vec<String>,
    /// Optional `AS_PATH` prepend rewrite.
    pub set_as_path_prepend: Option<PolicyAsPathPrependConfig>,
}

/// Full replacement definition for one named neighbor set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighborSetDefinition {
    /// Exact peer addresses.
    pub addresses: Vec<String>,
    /// Remote ASNs in the set.
    pub remote_asns: Vec<u32>,
    /// Peer-group names in the set.
    pub peer_groups: Vec<String>,
}

/// Named neighbor-set definition with its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedNeighborSetSnapshot {
    /// Neighbor-set name.
    pub name: String,
    /// Full definition payload.
    pub definition: NeighborSetDefinition,
}

/// Full replacement definition for one named policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedPolicyDefinition {
    /// `"permit"` or `"deny"` when no statement matches.
    pub default_action: String,
    /// Ordered policy statements.
    pub statements: Vec<PolicyStatementDefinition>,
}

/// Named policy definition with its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedPolicySnapshot {
    /// Policy definition name.
    pub name: String,
    /// Full definition payload.
    pub definition: NamedPolicyDefinition,
}

/// Full replacement definition for one peer-group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerGroupDefinition {
    /// Override hold time.
    pub hold_time: Option<u16>,
    /// Override max prefixes.
    pub max_prefixes: Option<u32>,
    /// Optional TCP MD5 password.
    pub md5_password: Option<String>,
    /// Optional TTL-security override.
    pub ttl_security: Option<bool>,
    /// Address families override.
    pub families: Vec<String>,
    /// Optional GR enable override.
    pub graceful_restart: Option<bool>,
    /// Optional GR restart time override.
    pub gr_restart_time: Option<u16>,
    /// Optional GR stale-routes-time override.
    pub gr_stale_routes_time: Option<u64>,
    /// Optional LLGR stale-time override.
    pub llgr_stale_time: Option<u32>,
    /// Optional explicit IPv6 next-hop.
    pub local_ipv6_nexthop: Option<String>,
    /// Optional route-reflector-client override.
    pub route_reflector_client: Option<bool>,
    /// Optional route-server-client override.
    pub route_server_client: Option<bool>,
    /// Optional private-AS removal mode.
    pub remove_private_as: Option<String>,
    /// Optional Add-Path override.
    pub add_path: Option<AddPathDefinition>,
    /// Inline import policy.
    pub import_policy: Vec<PolicyStatementDefinition>,
    /// Inline export policy.
    pub export_policy: Vec<PolicyStatementDefinition>,
    /// Named import chain.
    pub import_policy_chain: Vec<String>,
    /// Named export chain.
    pub export_policy_chain: Vec<String>,
}

/// Named peer-group definition with its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedPeerGroupSnapshot {
    /// Peer-group name.
    pub name: String,
    /// Full definition payload.
    pub definition: PeerGroupDefinition,
}

/// Ordered import/export chain assignment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyChainAssignment {
    /// Global or per-neighbor import chain names.
    pub import_policy_names: Vec<String>,
    /// Global or per-neighbor export chain names.
    pub export_policy_names: Vec<String>,
}

/// Configuration for adding a peer dynamically.
#[derive(Clone)]
#[expect(clippy::struct_excessive_bools)]
pub struct PeerManagerNeighborConfig {
    /// Remote peer IP address (used as peer identifier).
    pub address: IpAddr,
    /// Remote autonomous system number.
    pub remote_asn: u32,
    /// Human-readable peer description.
    pub description: String,
    /// Optional peer-group reference used to derive defaults.
    pub peer_group: Option<String>,
    /// Override hold time (None = use default).
    pub hold_time: Option<u16>,
    /// Maximum prefixes accepted before Cease/1 (None = unlimited).
    pub max_prefixes: Option<u32>,
    /// Optional TCP MD5 password.
    pub md5_password: Option<String>,
    /// Whether GTSM / TTL security is enabled.
    pub ttl_security: bool,
    /// Negotiated address families for this peer.
    pub families: Vec<(Afi, Safi)>,
    /// Whether to advertise Graceful Restart capability.
    pub graceful_restart: bool,
    /// GR restart time value advertised in OPEN (seconds).
    pub gr_restart_time: u16,
    /// Time to retain stale routes after peer restart (seconds).
    pub gr_stale_routes_time: u64,
    /// Long-lived stale routes time (RFC 9494, seconds). 0 = disabled.
    pub llgr_stale_time: u32,
    /// Whether this peer should participate in the current local
    /// restarting-speaker GR window (static startup peers only).
    pub gr_restart_eligible: bool,
    /// Explicit IPv6 next-hop for eBGP (None = derive from socket).
    pub local_ipv6_nexthop: Option<Ipv6Addr>,
    /// Whether this peer is a route reflector client (RFC 4456).
    pub route_reflector_client: bool,
    /// Whether this eBGP peer is a transparent route-server client.
    pub route_server_client: bool,
    /// Private AS removal mode for eBGP outbound `AS_PATH`.
    pub remove_private_as: RemovePrivateAs,
    /// Enable Add-Path receive capability.
    pub add_path_receive: bool,
    /// Enable Add-Path send capability.
    pub add_path_send: bool,
    /// Maximum number of paths to advertise per prefix (Add-Path).
    pub add_path_send_max: u32,
    /// Import policy chain applied to inbound routes.
    pub import_policy: Option<PolicyChain>,
    /// Export policy chain applied to outbound routes.
    pub export_policy: Option<PolicyChain>,
}

/// A config persistence event sent after successful peer add/delete.
///
/// The binary crate converts these into config file mutations.
/// Kept simple — only the data the neighbor service already has.
pub enum ConfigEvent {
    /// A neighbor was successfully added at runtime.
    NeighborAdded(PeerManagerNeighborConfig),
    /// A neighbor was successfully deleted at runtime.
    NeighborDeleted(IpAddr),
    /// Create or replace a named policy definition.
    SetPolicy {
        /// Policy definition name.
        name: String,
        /// Full replacement definition.
        definition: NamedPolicyDefinition,
    },
    /// Delete a named policy definition.
    DeletePolicy {
        /// Policy definition name.
        name: String,
    },
    /// Create or replace a named neighbor set.
    SetNeighborSet {
        /// Neighbor-set name.
        name: String,
        /// Full replacement definition.
        definition: NeighborSetDefinition,
    },
    /// Delete a named neighbor set.
    DeleteNeighborSet {
        /// Neighbor-set name.
        name: String,
    },
    /// Replace the global import policy chain.
    SetGlobalImportChain {
        /// Ordered policy names.
        policy_names: Vec<String>,
    },
    /// Replace the global export policy chain.
    SetGlobalExportChain {
        /// Ordered policy names.
        policy_names: Vec<String>,
    },
    /// Clear the global import policy chain.
    ClearGlobalImportChain,
    /// Clear the global export policy chain.
    ClearGlobalExportChain,
    /// Replace the per-neighbor import policy chain.
    SetNeighborImportChain {
        /// Neighbor address.
        address: IpAddr,
        /// Ordered policy names.
        policy_names: Vec<String>,
    },
    /// Replace the per-neighbor export policy chain.
    SetNeighborExportChain {
        /// Neighbor address.
        address: IpAddr,
        /// Ordered policy names.
        policy_names: Vec<String>,
    },
    /// Clear the per-neighbor import policy chain.
    ClearNeighborImportChain {
        /// Neighbor address.
        address: IpAddr,
    },
    /// Clear the per-neighbor export policy chain.
    ClearNeighborExportChain {
        /// Neighbor address.
        address: IpAddr,
    },
    /// Create or replace a peer-group definition.
    SetPeerGroup {
        /// Peer-group name.
        name: String,
        /// Full replacement definition.
        definition: PeerGroupDefinition,
    },
    /// Delete a peer-group definition.
    DeletePeerGroup {
        /// Peer-group name.
        name: String,
    },
    /// Set a neighbor's peer-group membership.
    SetNeighborPeerGroup {
        /// Neighbor address.
        address: IpAddr,
        /// Peer-group name.
        peer_group: String,
    },
    /// Clear a neighbor's peer-group membership.
    ClearNeighborPeerGroup {
        /// Neighbor address.
        address: IpAddr,
    },
}

/// Snapshot of a peer's state for queries.
#[derive(Debug, Clone)]
#[expect(clippy::struct_excessive_bools)]
pub struct PeerInfo {
    /// Remote peer IP address.
    pub address: IpAddr,
    /// Remote autonomous system number.
    pub remote_asn: u32,
    /// Human-readable peer description.
    pub description: String,
    /// Optional peer-group reference.
    pub peer_group: Option<String>,
    /// Current FSM state.
    pub state: SessionState,
    /// Whether the peer is administratively enabled.
    pub enabled: bool,
    /// Number of accepted prefixes from this peer.
    pub prefix_count: usize,
    /// Configured hold time override (None = default).
    pub hold_time: Option<u16>,
    /// Maximum prefix limit (None = unlimited).
    pub max_prefixes: Option<u32>,
    /// Configured address families.
    pub families: Vec<(Afi, Safi)>,
    /// Private AS removal mode.
    pub remove_private_as: RemovePrivateAs,
    /// Whether this eBGP peer is a transparent route-server client.
    pub route_server_client: bool,
    /// Add-Path receive enabled.
    pub add_path_receive: bool,
    /// Add-Path send enabled.
    pub add_path_send: bool,
    /// Maximum paths to advertise per prefix (Add-Path).
    pub add_path_send_max: u32,
    /// Total UPDATE messages received.
    pub updates_received: u64,
    /// Total UPDATE messages sent.
    pub updates_sent: u64,
    /// Total NOTIFICATION messages received.
    pub notifications_received: u64,
    /// Total NOTIFICATION messages sent.
    pub notifications_sent: u64,
    /// Number of Established→non-Established transitions.
    pub flap_count: u64,
    /// Seconds since last Established transition (0 if never).
    pub uptime_secs: u64,
    /// Human-readable last error description.
    pub last_error: String,
}
