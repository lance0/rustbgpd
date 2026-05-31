//! Shared types for peer management across the API and `PeerManager`.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv6Addr};

use bytes::Bytes;
use rustbgpd_fsm::SessionState;
use rustbgpd_policy::PolicyChain;
use rustbgpd_transport::{ImportExplainReply, RemovePrivateAs, TcpAoConfig};
use rustbgpd_wire::{Afi, BgpRole, Prefix, Safi};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, oneshot};

/// Maximum number of recent session lifecycle events retained in memory.
pub const SESSION_EVENT_HISTORY_CAPACITY: usize = 4096;

/// Maximum number of recent policy mutation events retained in memory.
pub const POLICY_EVENT_HISTORY_CAPACITY: usize = 4096;

/// Stable identity for a configured BGP peer.
///
/// Numbered peers use only `address`. IPv6 link-local peers must also carry
/// the configured interface name because `fe80::/10` addresses are scoped and
/// not globally unique.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerKey {
    pub address: IpAddr,
    pub interface: Option<String>,
}

impl PeerKey {
    #[must_use]
    pub fn new(address: IpAddr, interface: Option<String>) -> Self {
        Self {
            address,
            interface: interface.and_then(|s| {
                let trimmed = s.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            }),
        }
    }

    #[must_use]
    pub fn label(&self) -> String {
        match &self.interface {
            Some(interface) => format!("{}%{}", self.address, interface),
            None => self.address.to_string(),
        }
    }
}

impl std::fmt::Display for PeerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.label())
    }
}

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
    /// Peer identity that failed.
    pub peer: PeerKey,
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

/// Session lifecycle event type published by `PeerManager`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SessionLifecycleEventType {
    /// BGP FSM state changed.
    StateChanged,
    /// Session reached Established.
    Established,
    /// Session left Established.
    Lost,
    /// Operator enabled a configured peer.
    PeerEnabled,
    /// Operator disabled a configured peer.
    PeerDisabled,
}

/// Structured session event broadcast by `PeerManager` and bridged by
/// `EventService.WatchEvents`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionLifecycleEvent {
    /// Event type.
    pub event_type: SessionLifecycleEventType,
    /// Peer address associated with the event.
    pub peer: IpAddr,
    /// Operator-facing peer label. Scoped IPv6 link-local peers render as
    /// `address%interface`; numbered peers may leave this absent.
    pub peer_label: Option<String>,
    /// Unix epoch seconds, string-shaped to match `RouteEvent`.
    pub timestamp: String,
    /// Previous BGP FSM state, when this is a session transition.
    pub old_state: Option<SessionState>,
    /// New BGP FSM state, when this is a session transition.
    pub new_state: Option<SessionState>,
    /// Session role (`primary` / `inbound_candidate`) for FSM events.
    pub session_role: Option<String>,
    /// Operator-facing reason/summary.
    pub reason: String,
}

/// Direction for a BGP NOTIFICATION event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionNotificationEventType {
    /// rustbgpd sent the NOTIFICATION to the peer.
    Sent,
    /// rustbgpd received the NOTIFICATION from the peer.
    Received,
}

/// BGP NOTIFICATION metadata broadcast by `PeerManager` and bridged by
/// `EventService.WatchEvents`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionNotificationEvent {
    /// Event type / direction.
    pub event_type: SessionNotificationEventType,
    /// Peer address associated with the event.
    pub peer: IpAddr,
    /// Unix epoch seconds, string-shaped to match `RouteEvent`.
    pub timestamp: String,
    /// BGP NOTIFICATION error code.
    pub code: u8,
    /// BGP NOTIFICATION error subcode.
    pub subcode: u8,
    /// Human-readable code/subcode description.
    pub description: String,
    /// Session role (`primary` / `inbound_candidate`) for this event.
    pub session_role: Option<String>,
    /// RFC 8203 shutdown communication reason, when present.
    pub shutdown_reason: Option<String>,
    /// Operator-facing reason/summary.
    pub reason: String,
}

/// Structured policy/config mutation event broadcast by `PeerManager` and
/// bridged by `EventService.WatchEvents`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEvent {
    /// Operation label such as `set`, `delete`, or `clear`.
    pub operation: &'static str,
    /// Target class such as `policy`, `neighbor_set`, or `peer_group`.
    pub target_type: &'static str,
    /// Target name or address-scoped target string.
    pub target: String,
    /// Peer address when this mutation is scoped to one peer.
    pub peer: Option<IpAddr>,
    /// Number of currently managed peers the runtime mutation touched.
    pub affected_peer_count: usize,
    /// Unix epoch seconds, string-shaped to match `RouteEvent`.
    pub timestamp: String,
    /// Operator-facing reason/summary.
    pub reason: String,
}

/// Session-scoped event broadcast by `PeerManager`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    /// BGP FSM or peer enable/disable lifecycle event.
    Lifecycle(SessionLifecycleEvent),
    /// BGP NOTIFICATION sent/received event.
    Notification(SessionNotificationEvent),
}

/// Commands sent to the `PeerManager` task.
/// Failure modes for `SetGracefulShutdown`. Surfaced through the
/// `oneshot` reply on the command so the gRPC handler can map to the
/// correct `tonic::Status` code (`NOT_FOUND` vs `INTERNAL`).
#[derive(Debug)]
pub enum SetGshutError {
    /// Operator addressed a specific peer that isn't currently managed.
    /// Maps to gRPC `NOT_FOUND`.
    PeerNotFound(PeerKey),
    /// Live-session command, RIB refresh, or aggregated per-peer
    /// failure during a broadcast. Maps to gRPC `INTERNAL`.
    /// Authoritative state on `ManagedPeer` has been updated regardless
    /// — the toggle takes effect on the next session spawn even when
    /// the immediate dispatch path failed.
    Internal(String),
}

impl std::fmt::Display for SetGshutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PeerNotFound(peer) => write!(f, "peer {peer} not found"),
            Self::Internal(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for SetGshutError {}

#[derive(Clone, Debug, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "mirrors stable ConfigDiff summary predicates exposed in the proto"
)]
pub struct RuntimeConfigDiff {
    pub has_actionable_changes: bool,
    pub has_reload_applied_changes: bool,
    pub has_restart_required_changes: bool,
    pub has_informational_changes: bool,
    pub has_any_changes: bool,
    pub human_text: String,
    pub diff_json: String,
}

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
        /// Peer identity to remove.
        peer: PeerKey,
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
    /// Subscribe to live session lifecycle events.
    SubscribeSessionEvents {
        /// Reply channel returning a fresh broadcast receiver.
        reply: oneshot::Sender<broadcast::Receiver<SessionEvent>>,
    },
    /// Subscribe to live policy mutation events.
    SubscribePolicyEvents {
        /// Reply channel returning a fresh broadcast receiver.
        reply: oneshot::Sender<broadcast::Receiver<PolicyEvent>>,
    },
    /// Query recent policy mutation events from the bounded in-memory history.
    QueryPolicyEventHistory {
        /// Optional peer filter. Matches only peer-scoped policy events.
        peer: Option<IpAddr>,
        /// Maximum events to return. 0 uses [`POLICY_EVENT_HISTORY_CAPACITY`].
        limit: usize,
        /// Reply channel returning matching events.
        reply: oneshot::Sender<Vec<PolicyEvent>>,
    },
    /// Query recent session lifecycle events from the bounded in-memory history.
    QuerySessionEventHistory {
        /// Optional peer filter.
        peer: Option<IpAddr>,
        /// Optional event-type filter.
        event_types: BTreeSet<SessionLifecycleEventType>,
        /// Maximum events to return. 0 uses [`SESSION_EVENT_HISTORY_CAPACITY`].
        limit: usize,
        /// Reply channel returning matching events.
        reply: oneshot::Sender<Vec<SessionLifecycleEvent>>,
    },
    /// Diff candidate TOML against the live runtime config snapshot.
    DiffRuntimeConfig {
        /// Candidate TOML content supplied by the caller.
        candidate_toml: String,
        /// Reply channel returning redacted diff output only.
        reply: oneshot::Sender<Result<RuntimeConfigDiff, String>>,
    },
    /// Validate a candidate `[[fib_tables]]` set against the live runtime
    /// config (peer-group references, reserved/duplicate table ids, families,
    /// ECMP caps). Used by the gRPC FIB-table CRUD control path to reject bad
    /// input before it reaches the FIB reconciler. Does not mutate anything.
    ValidateFibTables {
        /// The full candidate table set (already merged with the upsert/delete).
        tables: Vec<FibTableSnapshot>,
        /// Reply channel: `Ok(())` if the candidate validates, else `Err(msg)`.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Query a single peer's state by address.
    GetPeerState {
        /// Peer identity to query.
        peer: PeerKey,
        /// Reply channel returning the peer snapshot (None if not found).
        reply: oneshot::Sender<Option<PeerInfo>>,
    },
    /// Start (enable) a previously disabled peer.
    EnablePeer {
        /// Peer identity to enable.
        peer: PeerKey,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Disable (stop) a peer, optionally with a shutdown reason.
    DisablePeer {
        /// Peer identity to disable.
        peer: PeerKey,
        /// RFC 8203 shutdown communication reason (pre-encoded).
        reason: Option<Bytes>,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Trigger a soft inbound reset (route refresh) for the given families.
    SoftResetIn {
        /// Peer identity.
        peer: PeerKey,
        /// Families to refresh (empty = all configured).
        families: Vec<(Afi, Safi)>,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// RFC 8326 graceful-shutdown initiator: toggle attaching the
    /// `GRACEFUL_SHUTDOWN` community on outbound updates for one peer
    /// (`Some(addr)`) or every currently-managed peer (`None`).
    SetGracefulShutdown {
        /// Peer identity; `None` applies to all peers.
        peer: Option<PeerKey>,
        /// `true` attaches the community; `false` clears it.
        enabled: bool,
        /// Reply channel; the error type distinguishes
        /// "peer not found" (operator typo, maps to gRPC `NOT_FOUND`)
        /// from "internal failure" (session/RIB dispatch issue, maps
        /// to gRPC `INTERNAL`) so the handler doesn't conflate them.
        reply: oneshot::Sender<Result<(), SetGshutError>>,
    },
    /// Accept an inbound TCP connection for a known peer.
    AcceptInbound {
        /// Already-accepted TCP stream.
        stream: TcpStream,
        /// Remote peer socket address, including IPv6 scope for link-local.
        peer_addr: std::net::SocketAddr,
    },
    /// Reconcile peers after config reload (add/remove/change).
    ReconcilePeers {
        /// Neighbors to add.
        added: Vec<PeerManagerNeighborConfig>,
        /// Neighbor addresses to remove.
        removed: Vec<PeerKey>,
        /// Neighbors whose config changed (remove + re-add).
        changed: Vec<PeerManagerNeighborConfig>,
        /// Reply channel with reconciliation results.
        reply: oneshot::Sender<ReconcileResult>,
    },
    /// ADR-0073: refresh the peer manager's `[policy.explain]` snapshot
    /// (`enabled` / `cache_size`) ahead of any reload step that
    /// constructs sessions. `build_transport_config` reads these from
    /// the peer manager's `current_config`, which is otherwise replaced
    /// only *after* reconcile — so a peer re-added mid-reload would read
    /// stale explain settings. reload sends this first on the FIFO
    /// command channel (awaited) when explain changed, so both the
    /// neighbor-reconcile and peer-group re-add paths see the new
    /// values. Carries primitives (not the config type) to respect the
    /// api → binary crate-dependency direction.
    SyncExplainConfig {
        /// New `[policy.explain].enabled`.
        enabled: bool,
        /// New `[policy.explain].cache_size`.
        cache_size: usize,
        /// Reply channel acknowledging the snapshot update.
        reply: oneshot::Sender<()>,
    },
    /// List all named policy definitions.
    ListPolicies {
        /// Reply channel returning all named policies.
        reply: oneshot::Sender<Vec<NamedPolicySnapshot>>,
    },
    /// ADR-0073: query a peer's per-session import-decision cache.
    /// Side-effect-free. `reply` carries `None` when the peer has no
    /// live session (its session-local cache is gone), which the
    /// caller renders as a synthetic `NOT_SEEN`.
    ExplainImportPolicy {
        /// Peer whose import-decision cache to consult.
        address: IpAddr,
        /// Address family of the queried NLRI.
        afi: Afi,
        /// Subsequent address family of the queried NLRI.
        safi: Safi,
        /// Queried prefix.
        prefix: Prefix,
        /// Optional Add-Path identifier; `None` = all paths.
        path_id: Option<u32>,
        /// Reply channel; `None` = no live session for `address`.
        reply: oneshot::Sender<Option<ImportExplainReply>>,
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
    /// Hot-apply `[global] honor_graceful_shutdown` by recomputing
    /// effective runtime policies for EBGP peers.
    SetHonorGracefulShutdown {
        /// Whether RFC 8326 receiver behavior is enabled.
        enabled: bool,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Hot-apply `[global] honor_blackhole` by recomputing effective runtime
    /// policies for EBGP peers.
    SetHonorBlackhole {
        /// Whether RFC 7999 receiver scoping behavior is enabled.
        enabled: bool,
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
    /// Create or replace a peer group while preserving the existing
    /// MD5 password atomically inside the peer-manager actor.
    SetPeerGroupPreserveMd5 {
        /// Peer-group name.
        name: String,
        /// Full replacement definition except for the MD5 password.
        definition: PeerGroupDefinition,
        /// Reply channel returning the applied definition for persistence.
        reply: oneshot::Sender<Result<PeerGroupDefinition, String>>,
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
    /// List configured dynamic neighbor ranges.
    ListDynamicRanges {
        reply: oneshot::Sender<Vec<DynamicNeighborInfo>>,
    },
    /// Add a dynamic neighbor range at runtime.
    AddDynamicRange {
        /// IP prefix range (e.g., `10.0.0.0/24`).
        prefix: String,
        /// Peer group whose config dynamic peers inherit.
        peer_group: String,
        /// Expected remote ASN (0 = accept any ASN from OPEN).
        remote_asn: u32,
        /// Optional description applied to dynamic peers from this range.
        description: Option<String>,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), DynamicRangeError>>,
    },
    /// Remove a dynamic neighbor range at runtime. Does not tear down
    /// already-established dynamic peers — they drain on Idle.
    DeleteDynamicRange {
        /// IP prefix range to remove (matched by effective prefix).
        prefix: String,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), DynamicRangeError>>,
    },
}

/// Information about a configured dynamic neighbor range.
#[derive(Debug, Clone)]
pub struct DynamicNeighborInfo {
    pub prefix: String,
    pub peer_group: String,
    pub remote_asn: u32,
    pub description: String,
}

/// Typed failure for runtime dynamic-range mutations so the gRPC layer maps
/// to status codes deterministically, instead of substring-matching an opaque
/// message. Each variant carries a human-readable detail for the status body.
#[derive(Debug, Clone)]
pub enum DynamicRangeError {
    /// A range with the same effective prefix already exists (→ `ALREADY_EXISTS`).
    AlreadyExists(String),
    /// No range with the given effective prefix exists (→ `NOT_FOUND`).
    NotFound(String),
    /// The request was invalid — bad prefix, or unknown / BFD-enabled peer
    /// group (→ `INVALID_ARGUMENT`).
    Invalid(String),
}

impl std::fmt::Display for DynamicRangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyExists(m) | Self::NotFound(m) | Self::Invalid(m) => f.write_str(m),
        }
    }
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
    /// Optional EVPN route-type match (1-5 per RFC 7432 / RFC 9136).
    /// `None` means no constraint; non-EVPN routes never match a set value.
    pub match_evpn_route_type: Option<u8>,
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
    /// Optional ASPA validation state match.
    pub match_aspa_validation: Option<String>,
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
    /// Configured interface for IPv6 link-local peers.
    pub interface: Option<String>,
    /// Resolved interface index for scoped IPv6 link-local peers.
    pub scope_id: Option<u32>,
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
    /// Optional TCP-AO key for static-neighbor runtime sockets.
    pub tcp_ao: Option<TcpAoConfig>,
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
    /// Local BGP Role advertised to this peer (RFC 9234).
    pub local_role: Option<BgpRole>,
    /// Require the peer to advertise a compatible BGP Role.
    pub strict_role: bool,
    /// Import policy chain applied to inbound routes.
    pub import_policy: Option<PolicyChain>,
    /// Export policy chain applied to outbound routes.
    pub export_policy: Option<PolicyChain>,
}

/// Crate-boundary mirror of a binary `FibTableConfig` (`[[fib_tables]]`).
///
/// `ConfigEvent` lives in this API crate but the binary owns the real config
/// types, so FIB-table persistence events carry this plain snapshot instead of
/// the binary struct. The binary's `apply_config_event` converts it back to a
/// `FibTableConfig`, validating the candidate config before assigning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FibTableSnapshot {
    /// Operator-facing handle, unique across the table set.
    pub name: String,
    /// Linux route table id.
    pub table_id: u32,
    /// Kernel route metric / priority for daemon-owned rows.
    pub metric: u32,
    /// Address families eligible for install (empty = both unicast families).
    pub families: Vec<String>,
    /// Optional peer-group allow-list (empty = all peer groups).
    pub allowed_peer_groups: Vec<String>,
    /// Optional neighbor-address allow-list (empty = all neighbors).
    pub allowed_neighbors: Vec<String>,
    /// Optional hard row cap (None = no cap).
    pub max_routes: Option<u32>,
    /// Optional ECMP caps (ADR-0066); None = single next-hop / fallback.
    pub maximum_paths: Option<u32>,
    /// Per-class eBGP ECMP cap; None falls back to `maximum_paths`.
    pub maximum_paths_ebgp: Option<u32>,
    /// Per-class iBGP ECMP cap; None falls back to `maximum_paths`.
    pub maximum_paths_ibgp: Option<u32>,
}

/// A config persistence event sent after successful peer add/delete.
///
/// The binary crate converts these into config file mutations.
/// Kept simple — only the data the neighbor service already has.
pub enum ConfigEvent {
    /// The `[[fib_tables]]` set was replaced at runtime (gRPC FIB-table CRUD).
    /// Carries the full accepted table set the FIB reconciler acknowledged, so
    /// persistence writes exactly what the runtime applied.
    FibTablesReplaced(Vec<FibTableSnapshot>),
    /// A neighbor was successfully added at runtime.
    NeighborAdded(PeerManagerNeighborConfig),
    /// A neighbor was successfully deleted at runtime.
    NeighborDeleted(PeerKey),
    /// A dynamic neighbor range was successfully added at runtime.
    DynamicNeighborAdded {
        /// IP prefix range (e.g., `10.0.0.0/24`).
        prefix: String,
        /// Peer group whose config dynamic peers inherit.
        peer_group: String,
        /// Expected remote ASN (0 = accept any ASN from OPEN).
        remote_asn: u32,
        /// Optional description.
        description: Option<String>,
    },
    /// A dynamic neighbor range was successfully removed at runtime.
    DynamicNeighborDeleted {
        /// IP prefix range that was removed (matched by effective prefix).
        prefix: String,
    },
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
    /// Configured interface for IPv6 link-local peers.
    pub interface: Option<String>,
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
    /// Locally configured BGP Role, if advertised.
    pub local_role: Option<BgpRole>,
    /// Require a compatible remote BGP Role.
    pub strict_role: bool,
    /// Remote BGP Role advertised in OPEN, if present in the current session.
    pub remote_role: Option<BgpRole>,
    /// True when both sides advertised compatible BGP Roles.
    pub role_negotiated: bool,
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
    /// Number of unicast route announcements blocked by RFC 9234 OTC rules.
    pub otc_routes_blocked: u64,
    /// Import policy evaluations that permitted a route.
    pub import_policy_routes_permitted: u64,
    /// Import policy evaluations that denied a route.
    pub import_policy_routes_denied: u64,
    /// Export policy evaluations that permitted a route.
    pub export_policy_routes_permitted: u64,
    /// Export policy evaluations that denied a route.
    pub export_policy_routes_denied: u64,
    /// Number of Established→non-Established transitions.
    pub flap_count: u64,
    /// Seconds since last Established transition (0 if never).
    pub uptime_secs: u64,
    /// Human-readable last error description.
    pub last_error: String,
    /// True for peers auto-created from a `[[dynamic_neighbors]]` range.
    pub is_dynamic: bool,
    /// True when the per-peer session-state query did not complete in time
    /// (e.g. the session task is parked on TCP write back-pressure). The
    /// `state` field falls back to `Idle` in that case, so consumers that
    /// care about liveness — `GetHealth`'s active-peer count, `ListNeighbors`
    /// observability — should treat `stale = true` as "state unknown" rather
    /// than as an authoritative Idle reading.
    pub stale: bool,
}
