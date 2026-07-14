//! Shared types for peer management across the API and `PeerManager`.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv6Addr};

use bytes::Bytes;
use rustbgpd_fsm::SessionState;
use rustbgpd_policy::PolicyChain;
use rustbgpd_transport::{
    ImportExplainReply, ImportPolicyTermHits, RemovePrivateAs, TcpAoInfoSnapshot, TcpAoKeyring,
    TransportAuthSecret,
};
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

/// Typed failure for static peer lifecycle/admin commands.
///
/// These commands are called by gRPC services, config transactions, and reload
/// paths. Keeping the failure class in the reply avoids fragile substring
/// checks when the caller needs to choose a stable gRPC status code.
#[derive(Debug, Clone)]
pub enum PeerLifecycleError {
    /// Static peer already exists (gRPC callers map to `ALREADY_EXISTS`).
    AlreadyExists(PeerKey),
    /// Target peer is not managed (gRPC callers map to `NOT_FOUND`).
    NotFound(PeerKey),
    /// Operator supplied invalid peer/config input (gRPC callers map to
    /// `INVALID_ARGUMENT`).
    Invalid(String),
    /// Operation requires daemon/session reconstruction outside this hot path
    /// (gRPC callers map to `FAILED_PRECONDITION`).
    RestartRequired(String),
    /// Session, RIB, restore, or internal snapshot failure (gRPC callers map
    /// to `INTERNAL`).
    Internal(String),
}

impl PeerLifecycleError {
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }
}

impl std::fmt::Display for PeerLifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyExists(peer) => write!(f, "peer {peer} already exists"),
            Self::NotFound(peer) => write!(f, "peer {peer} not found"),
            Self::Invalid(message) | Self::RestartRequired(message) | Self::Internal(message) => {
                f.write_str(message)
            }
        }
    }
}

impl std::error::Error for PeerLifecycleError {}

/// Typed failure for runtime catalog mutations.
///
/// These commands are surfaced by gRPC services. Keeping the failure class in
/// the peer-manager reply lets API handlers choose stable status codes without
/// parsing operator-facing error text.
#[derive(Debug, Clone)]
pub enum CatalogMutationError {
    /// Target object or neighbor was not found (maps to gRPC `NOT_FOUND`).
    NotFound(String),
    /// Target object is still referenced and cannot be deleted
    /// (maps to gRPC `FAILED_PRECONDITION`).
    StillReferenced {
        /// Human-readable catalog object kind.
        kind: &'static str,
        /// Object name.
        name: String,
        /// References blocking deletion.
        references: Vec<String>,
    },
    /// Operator supplied invalid catalog data (maps to gRPC
    /// `INVALID_ARGUMENT`).
    Invalid(String),
    /// Applying the mutation would reconfigure something only a daemon
    /// restart can change, e.g. a TCP-AO delta on a reshaped peer-group
    /// member (maps to gRPC `FAILED_PRECONDITION`).
    RestartRequired(String),
    /// Runtime/session failure while applying otherwise-valid catalog data
    /// (maps to gRPC `INTERNAL`).
    Internal(String),
}

impl CatalogMutationError {
    #[must_use]
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::NotFound(message.into())
    }

    #[must_use]
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }

    #[must_use]
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }
}

impl std::fmt::Display for CatalogMutationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(message)
            | Self::Invalid(message)
            | Self::RestartRequired(message)
            | Self::Internal(message) => f.write_str(message),
            Self::StillReferenced {
                kind,
                name,
                references,
            } => write!(
                f,
                "{kind} {name} is still referenced by {}",
                references.join(", ")
            ),
        }
    }
}

impl std::error::Error for CatalogMutationError {}

/// Lifecycle failures surface through catalog mutations when a peer-group
/// change commits its member fan-out via the captured-prior reshape
/// primitive (ADR-0081). Preserve the failure class so the gRPC layer keeps
/// stable status codes: a TCP-AO delta stays `FAILED_PRECONDITION`, a
/// missing member stays `NOT_FOUND`.
impl From<PeerLifecycleError> for CatalogMutationError {
    fn from(error: PeerLifecycleError) -> Self {
        match error {
            PeerLifecycleError::RestartRequired(message) => Self::RestartRequired(message),
            PeerLifecycleError::NotFound(peer) => Self::NotFound(format!("peer {peer} not found")),
            PeerLifecycleError::Invalid(message) => Self::Invalid(message),
            error @ (PeerLifecycleError::AlreadyExists(_) | PeerLifecycleError::Internal(_)) => {
                Self::Internal(error.to_string())
            }
        }
    }
}

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

/// Validate-only diff failure returned by the peer manager.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeConfigDiffError {
    /// Candidate TOML/config failed validation.
    InvalidCandidate(String),
    /// Internal diff rendering or serialization failed.
    Internal(String),
}

/// Validate-only classification for the config transaction model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeConfigTransactionStatus {
    /// Candidate matches the runtime snapshot.
    Noop,
    /// Candidate contains only sections the v1 transaction model can commit.
    Committable,
    /// Candidate is valid TOML/config but contains unsupported or
    /// restart-required sections.
    Rejected,
}

/// Validate-only transaction plan returned by the peer manager.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeConfigTransactionPlan {
    pub status: RuntimeConfigTransactionStatus,
    pub runtime_snapshot_token: String,
    /// Keyed token the live runtime config would carry once this candidate is
    /// committed if the negotiated snapshot is unchanged. Live policy apply
    /// refreshes the authoritative token after RIB convergence before returning
    /// it, so clients can safely chain a follow-up plan. Not surfaced in the
    /// gRPC plan response.
    pub post_commit_runtime_snapshot_token: String,
    pub diff: RuntimeConfigDiff,
    pub supported_sections: Vec<String>,
    pub unsupported_sections: Vec<String>,
    pub restart_required_sections: Vec<String>,
    pub human_text: String,
    /// Side-effect-free update-group projection from the same runtime snapshot.
    pub update_group_impact: rustbgpd_rib::UpdateGroupImpactPlan,
}

/// Validate-only transaction planning error returned by the peer manager.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeConfigTransactionPlanError {
    /// Caller planned against an older runtime config snapshot.
    StaleSnapshot { expected: String, current: String },
    /// Candidate TOML/config failed validation.
    InvalidCandidate(String),
    /// Internal serialization / diff rendering failed.
    Internal(String),
}

impl RuntimeConfigTransactionPlanError {
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::StaleSnapshot { expected, current } => {
                format!("runtime config snapshot changed: expected {expected}, current {current}")
            }
            Self::InvalidCandidate(message) | Self::Internal(message) => message.clone(),
        }
    }
}

impl std::fmt::Display for RuntimeConfigTransactionPlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StaleSnapshot { expected, current } => {
                write!(
                    f,
                    "runtime config snapshot changed: expected {expected}, current {current}"
                )
            }
            Self::InvalidCandidate(message) | Self::Internal(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for RuntimeConfigTransactionPlanError {}

/// Error returned when the peer manager stages a candidate runtime config snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StageConfigSnapshotError {
    /// Candidate TOML/config failed validation.
    InvalidCandidate(String),
    /// Serializing the previous runtime snapshot for rollback failed.
    SerializePreviousSnapshot(String),
}

impl std::fmt::Display for StageConfigSnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCandidate(message) => f.write_str(message),
            Self::SerializePreviousSnapshot(message) => {
                write!(
                    f,
                    "failed to serialize previous runtime config snapshot: {message}"
                )
            }
        }
    }
}

impl std::error::Error for StageConfigSnapshotError {}

/// Import-policy validation state that can change route admissibility after an
/// external cache update.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportValidationDependency {
    /// RPKI origin-validation state (`match_rpki_validation`).
    Rpki,
    /// ASPA path-validation state (`match_aspa_validation`).
    Aspa,
}

/// Canonical `[[dynamic_neighbors]]` range selector identifying the live
/// dynamic sessions a command targets.
///
/// Carried by [`PeerManagerCommand::ApplyPolicyImpactSnapshot`] (re-apply
/// resolved policy chains) and [`PeerManagerCommand::BounceDynamicRangePeers`]
/// (graceful session reset after a peer-group reshape). The peer manager
/// expands these selectors against its live `ManagedPeer` map so a
/// dynamic-range transaction targets exactly the dynamic sessions that were
/// accepted by the impacted range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DynamicRangeTarget {
    /// Canonical network address of the accepted dynamic range.
    pub addr: IpAddr,
    /// Prefix length of the accepted dynamic range.
    pub prefix_len: u8,
    /// Peer group inherited by sessions accepted by this range.
    pub peer_group: String,
}

/// Outcome of [`PeerManagerCommand::BounceDynamicRangePeers`].
///
/// The bounce is deliberately best-effort: it runs only after the owning
/// config transaction has persisted, so a per-peer signaling failure must not
/// fail (or roll back) the already-committed transaction. A peer that could
/// not be signaled keeps its running session config until it reconnects —
/// the same documented semantics SIGHUP and the targeted peer-group RPCs
/// apply to live dynamic sessions — and is reported here instead of being
/// silently swallowed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DynamicPeerBounceOutcome {
    /// Live dynamic sessions that were signaled to gracefully reset.
    pub signaled: usize,
    /// Per-peer signaling failures (`"<peer>: <error>"`). These peers keep
    /// their running config until they reconnect.
    pub failures: Vec<String>,
}

/// Resolved import/export policy chains for one live peer session.
///
/// Carried by [`PeerManagerCommand::ApplyResolvedPolicySnapshot`]. The same
/// shape is reused for the captured PRIOR chains the command returns, so a
/// rollback is just `ApplyResolvedPolicySnapshot` of the priors.
#[derive(Clone, Debug)]
pub struct ResolvedPeerPolicy {
    /// Peer address (with `interface` for IPv6 link-local) identifying the live session.
    pub address: IpAddr,
    /// Interface name for IPv6 link-local peers; `None` for numbered peers.
    pub interface: Option<String>,
    /// Resolved import chain to apply (`None` clears the peer's import policy).
    pub import_policy: Option<PolicyChain>,
    /// Resolved export chain to apply (`None` clears the peer's export policy).
    pub export_policy: Option<PolicyChain>,
}

/// Reply payload of [`PeerManagerCommand::RuntimeConfigSnapshot`]: the
/// normalized runtime TOML plus the live compiled `.rpol` registry
/// (which the TOML deliberately excludes — see the command docs).
#[derive(Debug, Clone)]
pub struct RuntimeConfigSnapshotReply {
    /// Normalized TOML for the current runtime snapshot.
    pub toml: String,
    /// Live `[policy] rpol_files` list (absolute paths).
    pub rpol_files: Vec<String>,
    /// Live compiled `.rpol` policy registry.
    pub rpol: rustbgpd_policy::rpol::RpolPolicySet,
}

/// Current static-session negotiation identity captured for one coordinated
/// warm checkpoint. This is daemon-internal plumbing, not a public API view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarmCheckpointSession {
    /// Unambiguous configured peer identity (V1 admits numbered peers only).
    pub peer: PeerKey,
    /// Peer-manager generation of the exact active transport session.
    pub session_id: u64,
    /// Remote ASN negotiated in the current OPEN exchange.
    pub peer_asn: u32,
    /// Remote BGP identifier negotiated in the current OPEN exchange.
    pub peer_router_id: std::net::Ipv4Addr,
    /// Address families negotiated on this exact session.
    pub negotiated_families: Vec<(Afi, Safi)>,
    /// GR families advertised by this exact session's peer OPEN.
    pub peer_gr_families: Vec<(Afi, Safi)>,
    /// Families for which Add-Path receive/both was negotiated.
    pub add_path_receive_families: Vec<(Afi, Safi)>,
    /// Canonical, redacted identity of the effective import policy captured
    /// from the same peer-manager actor state as the session generation.
    pub canonical_import_policy: Vec<u8>,
}

/// One peer-manager-actor-consistent checkpoint capture. The effective
/// redacted config and resolved policies are sampled in the same blocked actor
/// command, so a reload cannot pair routes with a different config identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarmCheckpointCapture {
    /// Authoritative local ASN from the live runtime config snapshot.
    pub local_asn: u32,
    /// Authoritative local router ID from the live runtime config snapshot.
    pub local_router_id: std::net::Ipv4Addr,
    /// Deterministic effective config with defaults materialized and secrets
    /// redacted, captured from the live peer-manager config actor.
    pub effective_config_toml: String,
    /// Largest positive local GR restart retention among current resolved,
    /// enabled static neighbors. `None` means no marker/cache is useful.
    pub restart_time_secs: Option<u64>,
    /// Current session generations plus their exact resolved import policies.
    pub sessions: Vec<WarmCheckpointSession>,
}

pub enum PeerManagerCommand {
    /// Add a new peer with the given configuration.
    AddPeer {
        /// Neighbor configuration.
        config: PeerManagerNeighborConfig,
        /// Whether to update the live config snapshot.
        sync_config_snapshot: bool,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), PeerLifecycleError>>,
    },
    /// Remove an existing peer by address.
    DeletePeer {
        /// Peer identity to remove.
        peer: PeerKey,
        /// Whether to update the live config snapshot.
        sync_config_snapshot: bool,
        /// Reply channel returning the removed config on success.
        reply: oneshot::Sender<Result<PeerManagerNeighborConfig, PeerLifecycleError>>,
    },
    /// Reconfigure an existing static peer by replacing its live session with
    /// a newly resolved configuration.
    ReconfigurePeer {
        /// Replacement neighbor configuration.
        config: PeerManagerNeighborConfig,
        /// Reply channel returning the previous config on success.
        reply: oneshot::Sender<Result<PeerManagerNeighborConfig, PeerLifecycleError>>,
    },
    /// List all configured peers and their state.
    ListPeers {
        /// Reply channel returning all peer snapshots.
        reply: oneshot::Sender<Vec<PeerInfo>>,
    },
    /// Capture all checkpoint-eligible static sessions under the peer-manager
    /// actor. Any candidate query timeout rejects the entire reply.
    QueryWarmCheckpointCapture {
        /// Reply channel returning one actor-consistent config/session capture.
        reply: oneshot::Sender<Result<WarmCheckpointCapture, String>>,
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
        reply: oneshot::Sender<Result<RuntimeConfigDiff, RuntimeConfigDiffError>>,
    },
    /// Validate and classify a candidate config transaction without mutating
    /// daemon state.
    PlanConfigTransaction {
        /// Candidate TOML content supplied by the caller.
        candidate_toml: String,
        /// Optional optimistic-concurrency token the caller expects to plan
        /// against.
        expected_runtime_snapshot_token: Option<String>,
        /// Reply channel returning the transaction plan.
        reply: oneshot::Sender<
            Result<RuntimeConfigTransactionPlan, RuntimeConfigTransactionPlanError>,
        >,
    },
    /// Stage a full validated runtime config snapshot from TOML and return the
    /// previous normalized TOML snapshot for rollback.
    StageConfigSnapshot {
        /// Complete candidate TOML content.
        candidate_toml: String,
        /// Reply returns the previous normalized runtime snapshot on success.
        reply: oneshot::Sender<Result<String, StageConfigSnapshotError>>,
    },
    /// Mark the currently staged runtime config snapshot as durably committed.
    ///
    /// The transaction controller sends this after the config writer has
    /// acked persistence. Until then the peer manager treats the snapshot as
    /// provisional and refuses dynamic inbound accepts that would be born from
    /// candidate-only ranges.
    CommitConfigSnapshotStage {
        /// Reply is sent after the staged marker is cleared.
        reply: oneshot::Sender<()>,
    },
    /// Restore a full runtime config snapshot during transaction rollback.
    ///
    /// Unlike [`PeerManagerCommand::StageConfigSnapshot`], this is a terminal
    /// rollback operation: it clears the staged marker and reaps dynamic peers
    /// whose accepted range is no longer present in the restored snapshot.
    RestoreConfigSnapshot {
        /// Complete rollback TOML content.
        candidate_toml: String,
        /// Reply returns success/failure after the restored snapshot is active.
        reply: oneshot::Sender<Result<(), StageConfigSnapshotError>>,
    },
    /// Return the current normalized runtime config snapshot as TOML.
    ///
    /// Internal SIGHUP code uses this after taking the shared runtime-config
    /// coordinator so reload diffing starts from the latest transaction-updated
    /// peer-manager snapshot, not from main.rs' process-local startup/reload
    /// copy.
    ///
    /// The reply also carries the LIVE compiled `.rpol` registry
    /// (ADR-0096): the registry is derived state excluded from the
    /// TOML, and re-loading the TOML would recompile the `.rpol` files
    /// from disk — masking exactly the disk edits a SIGHUP diff must
    /// detect. Callers overlay it onto the re-loaded snapshot config.
    RuntimeConfigSnapshot {
        /// Reply returns normalized TOML plus the live rpol registry.
        reply: oneshot::Sender<Result<RuntimeConfigSnapshotReply, String>>,
    },
    /// Return the effective running config as normalized TOML with defaults
    /// materialized and secret material redacted, for
    /// `ConfigService.GetEffectiveConfig`. Unlike
    /// [`PeerManagerCommand::RuntimeConfigSnapshot`], the reply is safe to
    /// hand to `sensitive_read` API callers: secrets never leave the daemon.
    EffectiveRuntimeConfig {
        /// Reply returns the redacted effective config TOML.
        reply: oneshot::Sender<Result<String, String>>,
    },
    /// Atomically apply resolved import/export policy chains to a set of live
    /// peer sessions, returning each peer's PRIOR chains for rollback.
    ///
    /// Used by the ADR-0076 live-impact policy executor to commit policy /
    /// neighbor-set / peer-group / global-chain edits that reshape existing
    /// peers' resolved policy. Each target's prior chains are captured before the
    /// new ones are hot-applied through the same per-peer path SIGHUP uses. The
    /// command is atomic at the peer-manager layer: on the first per-peer apply
    /// failure it restores the peers it already changed (reverse order) and
    /// returns `Err` with nothing left mutated. On success it returns the
    /// captured priors; the executor replays them through this same command to
    /// roll back after a later persistence failure. Targets not currently live
    /// (e.g. a dynamic peer that disconnected) are skipped and absent from the
    /// returned priors. Never mutates `current_config` — snapshot staging owns
    /// that, keeping a single token-advance point.
    ApplyResolvedPolicySnapshot {
        /// Resolved chains to apply, one entry per concrete live peer.
        targets: Vec<ResolvedPeerPolicy>,
        /// Reply returns the captured prior chains (the rollback token).
        reply: oneshot::Sender<Result<Vec<ResolvedPeerPolicy>, String>>,
    },
    /// Atomically apply resolved import/export policy chains for a live-impact
    /// transaction that may include static neighbors and dynamic ranges.
    ///
    /// `static_targets` are already resolved by the transaction controller.
    /// `dynamic_ranges` are expanded inside the peer-manager actor against live
    /// dynamic peers whose stored accepted-range attribution matches the target.
    /// The expanded concrete target set is then committed through the same
    /// atomic apply/restore path as [`PeerManagerCommand::ApplyResolvedPolicySnapshot`].
    ApplyPolicyImpactSnapshot {
        /// Concrete static-neighbor targets.
        static_targets: Vec<ResolvedPeerPolicy>,
        /// Dynamic-range selectors to expand against live dynamic peers.
        dynamic_ranges: Vec<DynamicRangeTarget>,
        /// Reply returns the captured prior chains (the rollback token).
        reply: oneshot::Sender<Result<Vec<ResolvedPeerPolicy>, String>>,
    },
    /// Gracefully reset the live dynamic sessions accepted by the given
    /// `[[dynamic_neighbors]]` ranges so they re-accept under the committed
    /// runtime config.
    ///
    /// The dynamic counterpart of [`PeerManagerCommand::ApplyPeerReshapeSnapshot`]:
    /// an accepted dynamic peer cannot be delete/re-added (it exists only
    /// because the remote dialed in), so a peer-group session reshape reaches
    /// it by sending a graceful stop (Cease NOTIFICATION with an RFC 8203
    /// shutdown communication). The normal `BackToIdle` auto-removal then
    /// reaps the `ManagedPeer` and frees its `dynamic_neighbor_limit` slot,
    /// and the remote's reconnect is re-accepted through `handle_inbound`,
    /// which resolves the session config from the already-staged candidate
    /// snapshot. Issued only after the owning transaction has persisted;
    /// per-peer failures are reported in the outcome, never as a command
    /// error. Admin-disabled dynamic peers are skipped (they have no running
    /// session to reset and `BackToIdle` deliberately does not reap them).
    BounceDynamicRangePeers {
        /// Dynamic-range selectors to expand against live dynamic peers.
        ranges: Vec<DynamicRangeTarget>,
        /// Reply returns the per-peer signaling outcome.
        reply: oneshot::Sender<DynamicPeerBounceOutcome>,
    },
    /// Atomically reconfigure a set of live static peers and return each peer's
    /// PRIOR neighbor config for rollback.
    ///
    /// Used by the config-transaction peer-group/session reshape executor. Each
    /// target is a fully resolved replacement config. The command reuses the
    /// same delete/re-add semantics as [`PeerManagerCommand::ReconfigurePeer`],
    /// including disabled-state and graceful-shutdown preservation. On the first
    /// per-peer failure, peers already changed by this command are restored in
    /// reverse order and the command returns `Err`. On success, replaying the
    /// returned prior configs through this same command rolls back a later
    /// persistence failure. Never mutates `current_config`; snapshot staging
    /// owns the config-token advance.
    ApplyPeerReshapeSnapshot {
        /// Fully resolved replacement configs, one entry per concrete live peer.
        targets: Vec<PeerManagerNeighborConfig>,
        /// Reply returns captured prior configs (the rollback token), in the
        /// same order as `targets` — replaying them as a fresh
        /// `ApplyPeerReshapeSnapshot` restores the pre-apply state.
        reply: oneshot::Sender<Result<Vec<PeerManagerNeighborConfig>, PeerLifecycleError>>,
    },
    /// Atomically validate a candidate `[[fib_tables]]` set against the live
    /// runtime config (peer-group references, reserved/duplicate table ids,
    /// families, ECMP caps) and, on success, stage it into
    /// `current_config.fib_tables`. Used by the gRPC FIB-table CRUD control
    /// path before it reaches the FIB reconciler. Validating and staging in one
    /// command (the peer manager processes commands serially) closes the TOCTOU
    /// against a concurrent peer-group deletion that would otherwise check a
    /// snapshot that doesn't yet reflect the in-flight table's references.
    StageFibTables {
        /// The full candidate table set (already merged with the upsert/delete).
        tables: Vec<FibTableSnapshot>,
        /// Reply: `Ok(())` if it validated and was staged, else `Err(msg)`
        /// (nothing staged).
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Refresh the peer manager's runtime config snapshot with the accepted
    /// `[[fib_tables]]` set after a successful gRPC CRUD mutation, so the
    /// snapshot the live `DiffRuntimeConfig` compares against doesn't report
    /// the just-applied set as a pending change. The control path awaits the
    /// ack (while holding the FIB coordinator lock) so the snapshot is applied
    /// before the mutation returns and before a concurrent SIGHUP reload can
    /// run — keeping the two snapshot writers serialized.
    SetFibTablesSnapshot {
        /// The full accepted table set the FIB reconciler acknowledged.
        tables: Vec<FibTableSnapshot>,
        /// Acknowledgement, sent after `current_config.fib_tables` is assigned.
        reply: oneshot::Sender<()>,
    },
    /// Apply a persisted runtime config event to the peer manager's runtime
    /// config snapshot without changing live peer/session state.
    ApplyConfigEvent {
        /// Event that has already been accepted by the config persister.
        event: ConfigEvent,
        /// Reply channel for success/failure.
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
        reply: oneshot::Sender<Result<(), PeerLifecycleError>>,
    },
    /// Disable (stop) a peer, optionally with a shutdown reason.
    DisablePeer {
        /// Peer identity to disable.
        peer: PeerKey,
        /// RFC 8203 shutdown communication reason (pre-encoded).
        reason: Option<Bytes>,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), PeerLifecycleError>>,
    },
    /// Trigger a soft inbound reset (route refresh) for the given families.
    SoftResetIn {
        /// Peer identity.
        peer: PeerKey,
        /// Families to refresh (empty = all configured).
        families: Vec<(Afi, Safi)>,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), PeerLifecycleError>>,
    },
    /// Trigger soft inbound reset for established peers whose resolved import
    /// policy depends on an external validation cache.
    SoftResetImportValidationDependents {
        /// Validation cache that changed.
        dependency: ImportValidationDependency,
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
        /// Initial TCP-AO inspection tied to this accepted stream. The session
        /// refreshes it when state is queried.
        tcp_ao_info: Option<rustbgpd_transport::TcpAoInfoSnapshot>,
        /// Listener generation that reconciled this protected child. `None`
        /// for plaintext/MD5 accepts.
        tcp_ao_generation: Option<rustbgpd_transport::TcpAoRotationGeneration>,
    },
    /// Apply the established-session portion of one globally preflighted
    /// add-only TCP-AO generation.
    ApplyTcpAoAddOnly {
        generation: rustbgpd_transport::TcpAoRotationGeneration,
        /// Complete desired listener owner inventory. The peer manager derives
        /// exact active-open and covering accepted-socket projections from it.
        listener_keys: Vec<rustbgpd_transport::TcpAoListenerKey>,
        /// Desired exact keyrings for static active-open peers, including
        /// families that do not share the process listener socket.
        static_keyrings: Vec<(PeerKey, TcpAoKeyring)>,
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Validate every currently managed protected session target before the
    /// listener socket is mutated.
    PreflightTcpAoAddOnly {
        generation: rustbgpd_transport::TcpAoRotationGeneration,
        listener_keys: Vec<rustbgpd_transport::TcpAoListenerKey>,
        static_keyrings: Vec<(PeerKey, TcpAoKeyring)>,
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Publish a failed global add-only phase when listener application fails
    /// after session preflight has already advertised the desired generation.
    MarkTcpAoAddOnlyFailed {
        generation: rustbgpd_transport::TcpAoRotationGeneration,
        error: String,
        reply: oneshot::Sender<Result<(), String>>,
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
    /// LAN-341: apply a config change whose every edited field is
    /// reload-matrix `live` (hot-applied) to an existing static peer in
    /// place — no session-task delete/re-add, no TCP/FSM impact. The
    /// SIGHUP reload path routes a changed neighbor here instead of
    /// `ReconcilePeers.changed` when the changed-field set is entirely
    /// hot-applicable (`description`, `max_prefixes`,
    /// `gr_stale_routes_time`, `local_ipv6_nexthop`,
    /// `remove_private_as`, `log_level`, import/export policies and
    /// chains).
    HotUpdatePeer {
        /// Full replacement neighbor configuration (only hot-applicable
        /// fields may differ from the live peer's).
        config: PeerManagerNeighborConfig,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), PeerLifecycleError>>,
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
    /// ADR-0096: replace the compiled `.rpol` policy registry
    /// (SIGHUP reload of `[policy] rpol_files` or of a referenced
    /// file's content) and re-resolve every live peer's chains
    /// through it. Route Refresh fires for peers whose import chain
    /// materially changed, via the same atomic resolved-policy
    /// snapshot path as `[policy.definitions]` edits.
    SyncRpolPolicies {
        /// New `[policy] rpol_files` list (paths already absolute).
        rpol_files: Vec<String>,
        /// New compiled registry.
        rpol: rustbgpd_policy::rpol::RpolPolicySet,
        /// Dataset bindings the new registry's `dataset` declarations
        /// resolve through (LAN-305) — handles reused from the running
        /// config where declarations are unchanged, so a
        /// content-equal reload still diffs chains as no-ops.
        dataset_bindings: rustbgpd_policy::datasets::DatasetBindings,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), CatalogMutationError>>,
    },
    /// LAN-305: one or more external dataset snapshots swapped content
    /// during a reload. Refresh exactly the peers whose chains
    /// reference a swapped dataset — Route Refresh inbound for import
    /// chains, forced outbound re-emission for export chains — and
    /// count failed refreshes (prior snapshot retained) in metrics.
    /// Chains themselves are untouched: they share the swapped
    /// handles and pin the new generation at their next walk.
    RefreshDatasetDependents {
        /// Dataset names whose content swapped (generation bumped).
        swapped: Vec<String>,
        /// `(name, reason)` for datasets whose refresh failed.
        failed: Vec<(String, String)>,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// LAN-305: operator-facing status of every bound external
    /// dataset (name, kind, generation, records, path, last refresh
    /// error), sorted by name. Read-only; backs `rbgp policy stats`.
    QueryPolicyDatasets {
        /// Reply channel returning one row per bound dataset.
        reply: oneshot::Sender<Vec<PolicyDatasetStatusRow>>,
    },
    /// List all named policy definitions.
    ListPolicies {
        /// Reply channel returning all named policies.
        reply: oneshot::Sender<Vec<NamedPolicySnapshot>>,
    },
    /// ADR-0073: query a peer's per-session import-decision cache.
    /// Side-effect-free. `reply` carries `None` when the peer has no
    /// live session (its session-local cache is gone), which the
    /// caller renders as a synthetic `NO_SESSION` (LAN-320).
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
    /// Snapshot the live import-chain per-term hit counters of peer
    /// sessions (ADR-0096 Decision 3.3, import direction). Read-only —
    /// no counter moves. Peers without a live session or without an
    /// installed import chain are omitted from the reply.
    QueryImportPolicyTermHits {
        /// Optional peer filter; `None` = every session.
        peer: Option<IpAddr>,
        /// Reply channel: `(peer address, snapshot)` sorted by peer
        /// address for deterministic output.
        reply: oneshot::Sender<Vec<(IpAddr, ImportPolicyTermHits)>>,
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
        reply: oneshot::Sender<Result<(), CatalogMutationError>>,
    },
    /// Delete a named policy definition.
    DeletePolicy {
        /// Policy definition name.
        name: String,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), CatalogMutationError>>,
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
        reply: oneshot::Sender<Result<(), CatalogMutationError>>,
    },
    /// Delete a named neighbor set.
    DeleteNeighborSet {
        /// Neighbor-set name.
        name: String,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), CatalogMutationError>>,
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
        reply: oneshot::Sender<Result<(), CatalogMutationError>>,
    },
    /// Replace the global export policy chain.
    SetGlobalExportChain {
        /// Ordered policy names.
        policy_names: Vec<String>,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), CatalogMutationError>>,
    },
    /// Clear the global import policy chain.
    ClearGlobalImportChain {
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), CatalogMutationError>>,
    },
    /// Clear the global export policy chain.
    ClearGlobalExportChain {
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), CatalogMutationError>>,
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
        reply: oneshot::Sender<Result<(), CatalogMutationError>>,
    },
    /// Replace the per-neighbor export policy chain.
    SetNeighborExportChain {
        /// Neighbor address.
        address: IpAddr,
        /// Ordered policy names.
        policy_names: Vec<String>,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), CatalogMutationError>>,
    },
    /// Clear the per-neighbor import policy chain.
    ClearNeighborImportChain {
        /// Neighbor address.
        address: IpAddr,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), CatalogMutationError>>,
    },
    /// Clear the per-neighbor export policy chain.
    ClearNeighborExportChain {
        /// Neighbor address.
        address: IpAddr,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), CatalogMutationError>>,
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
        reply: oneshot::Sender<Result<(), CatalogMutationError>>,
    },
    /// Create or replace a peer group while preserving the existing
    /// MD5 password atomically inside the peer-manager actor.
    SetPeerGroupPreserveMd5 {
        /// Peer-group name.
        name: String,
        /// Full replacement definition except for the MD5 password.
        definition: PeerGroupDefinition,
        /// Reply channel returning the applied definition for persistence.
        reply: oneshot::Sender<Result<PeerGroupDefinition, CatalogMutationError>>,
    },
    /// Delete a peer group.
    DeletePeerGroup {
        /// Peer-group name.
        name: String,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), CatalogMutationError>>,
    },
    /// Assign a neighbor to a peer group.
    SetNeighborPeerGroup {
        /// Neighbor address.
        address: IpAddr,
        /// Peer-group name.
        peer_group: String,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), CatalogMutationError>>,
    },
    /// Clear a neighbor's peer-group membership.
    ClearNeighborPeerGroup {
        /// Neighbor address.
        address: IpAddr,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), CatalogMutationError>>,
    },
    /// Read a neighbor's current peer-group membership (used by the
    /// persisted catalog CRUD paths to capture prior state for rollback).
    GetNeighborPeerGroupMembership {
        /// Neighbor address.
        address: IpAddr,
        /// Outer `None` = neighbor not configured; inner `None` = no
        /// membership.
        reply: oneshot::Sender<Option<Option<String>>>,
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
        /// Reply channel: on success carries the removed range so a failed
        /// persist can roll the deletion back by re-adding the exact range.
        reply: oneshot::Sender<Result<RemovedDynamicRange, DynamicRangeError>>,
    },
}

/// Read-only peer-manager queries admitted between bounded policy-transaction
/// steps. This separate lane is intentionally narrow: mutation commands remain
/// ordered on [`PeerManagerCommand`] and cannot observe or alter a partially
/// applied transaction.
pub enum PeerManagerReadinessQuery {
    /// Return a live snapshot of all configured peers.
    ListPeers {
        /// Reply channel returning all peer snapshots.
        reply: oneshot::Sender<Vec<PeerInfo>>,
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

/// A dynamic neighbor range removed by `DeleteDynamicRange`, returned so the
/// gRPC handler can roll the deletion back (re-add the exact range) if config
/// persistence fails after the runtime mutation succeeded.
#[derive(Debug, Clone)]
pub struct RemovedDynamicRange {
    pub prefix: String,
    pub peer_group: String,
    pub remote_asn: u32,
    pub description: Option<String>,
}

/// Typed failure for runtime dynamic-range mutations so the gRPC layer maps
/// to status codes deterministically, instead of substring-matching an opaque
/// message. Each variant carries a human-readable detail for the status body.
#[derive(Debug, Clone)]
pub enum DynamicRangeError {
    /// A range with the same effective prefix already exists (→ `ALREADY_EXISTS`).
    AlreadyExists(String),
    /// No range with the given effective prefix exists, or an add references a
    /// peer group that does not exist (→ `NOT_FOUND`).
    NotFound(String),
    /// The request was invalid — bad prefix or BFD-enabled peer group
    /// (→ `INVALID_ARGUMENT`).
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
    /// Experimental Paths-Limit receiver preference.
    pub receive_max: Option<u16>,
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
    /// Override RFC 9687 send hold time in seconds; 0 disables (None =
    /// derive the RFC 9687 §6 default from the hold time).
    pub send_hold_time: Option<u32>,
    /// Override max prefixes.
    pub max_prefixes: Option<u32>,
    /// Optional TCP MD5 password.
    pub md5_password: Option<TransportAuthSecret>,
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
    /// Optional RFC 9107 ORR vantage point (IGP location) inherited by
    /// neighbors in this group. Requires `route_reflector_client`.
    pub orr_vantage: Option<IpAddr>,
    /// Optional route-server-client override.
    pub route_server_client: Option<bool>,
    /// Optional RFC 7947 §2.3.2 per-client best-path override
    /// (path-hiding mitigation). Requires `route_server_client`.
    pub per_client_best: Option<bool>,
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
#[expect(
    clippy::struct_excessive_bools,
    reason = "neighbor config mirrors independent protocol flags from config/proto"
)]
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
    /// Override RFC 9687 send hold time in seconds; 0 disables (None =
    /// derive the RFC 9687 §6 default from the hold time).
    pub send_hold_time: Option<u32>,
    /// Maximum prefixes accepted before Cease/1 (None = unlimited).
    pub max_prefixes: Option<u32>,
    /// Optional TCP MD5 password.
    pub md5_password: Option<TransportAuthSecret>,
    /// Optional ordered TCP-AO keyring for static-neighbor runtime sockets.
    pub tcp_ao: Option<TcpAoKeyring>,
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
    /// RFC 9107 ORR vantage point (IGP location) for this RR client.
    pub orr_vantage: Option<IpAddr>,
    /// Whether this eBGP peer is a transparent route-server client.
    pub route_server_client: bool,
    /// RFC 7947 §2.3.2 per-client best-path (path-hiding mitigation
    /// for route-server clients without Add-Path). Requires
    /// `route_server_client`.
    pub per_client_best: bool,
    /// Private AS removal mode for eBGP outbound `AS_PATH`.
    pub remove_private_as: RemovePrivateAs,
    /// Enable Add-Path receive capability.
    pub add_path_receive: bool,
    /// Enable Add-Path send capability.
    pub add_path_send: bool,
    /// Maximum number of paths to advertise per prefix (Add-Path).
    pub add_path_send_max: u32,
    /// Experimental Paths-Limit receiver preference (0 = disabled).
    pub paths_limit_receive_max: u16,
    /// Local BGP Role advertised to this peer (RFC 9234).
    pub local_role: Option<BgpRole>,
    /// Require the peer to advertise a compatible BGP Role.
    pub strict_role: bool,
    /// Advertise willingness to receive Address-Prefix ORF entries and apply
    /// them to this peer's outbound advertisements (RFC 5291/5292).
    pub prefix_orf_receive: bool,
    /// Never treat IPv4 unicast as available on this session (IPv6-only
    /// peering): excluded from our `MultiProtocol` capability and the
    /// RFC 4760 §8 implicit-IPv4 fallback is suppressed.
    pub disable_ipv4_unicast: bool,
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
    /// persistence writes exactly what the runtime applied. The optional ack is
    /// used by the FIB-table CRUD path to keep its coordinator lock held until
    /// the config bridge and persister have absorbed the accepted set.
    FibTablesReplaced {
        /// Full accepted table set.
        tables: Vec<FibTableSnapshot>,
        /// Optional persistence acknowledgement.
        ack: Option<oneshot::Sender<Result<(), String>>>,
    },
    /// A neighbor was successfully added at runtime.
    NeighborAdded {
        /// Neighbor configuration that was added.
        config: PeerManagerNeighborConfig,
        /// Optional persistence acknowledgement. Runtime CRUD paths hold the
        /// shared runtime-config lock until this fires, so SIGHUP cannot read a
        /// stale TOML between runtime mutation and on-disk commit.
        ack: Option<oneshot::Sender<Result<(), String>>>,
    },
    /// A neighbor was successfully deleted at runtime.
    NeighborDeleted {
        /// Peer identity that was deleted.
        peer: PeerKey,
        /// Optional persistence acknowledgement (see `NeighborAdded`).
        ack: Option<oneshot::Sender<Result<(), String>>>,
    },
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
        /// Optional persistence acknowledgement. The dynamic-neighbor CRUD path
        /// holds the shared runtime-config lock until this fires, so a SIGHUP
        /// reload cannot read a stale TOML between the runtime mutation and the
        /// on-disk commit.
        ack: Option<oneshot::Sender<Result<(), String>>>,
    },
    /// A dynamic neighbor range was successfully removed at runtime.
    DynamicNeighborDeleted {
        /// IP prefix range that was removed (matched by effective prefix).
        prefix: String,
        /// Optional persistence acknowledgement (see `DynamicNeighborAdded`).
        ack: Option<oneshot::Sender<Result<(), String>>>,
    },
    /// A config transaction committed a full candidate snapshot. This event is
    /// daemon-internal: transaction apply has already proven the live diff is a
    /// supported transaction family, and the config bridge parses this TOML back
    /// into the exact candidate before persistence.
    ConfigTransactionCommitted {
        /// Complete candidate TOML to parse, validate, and persist.
        candidate_toml: String,
        /// Optional persistence acknowledgement.
        ack: Option<oneshot::Sender<Result<(), String>>>,
    },
    /// Create or replace a named policy definition.
    SetPolicy {
        /// Policy definition name.
        name: String,
        /// Full replacement definition.
        definition: NamedPolicyDefinition,
        /// Optional persistence acknowledgement. Catalog CRUD paths hold
        /// the shared runtime-config lock until this fires (see
        /// `NeighborAdded`).
        ack: Option<oneshot::Sender<Result<(), String>>>,
    },
    /// Delete a named policy definition.
    DeletePolicy {
        /// Policy definition name.
        name: String,
        /// Optional persistence acknowledgement (see `SetPolicy`).
        ack: Option<oneshot::Sender<Result<(), String>>>,
    },
    /// Create or replace a named neighbor set.
    SetNeighborSet {
        /// Neighbor-set name.
        name: String,
        /// Full replacement definition.
        definition: NeighborSetDefinition,
        /// Optional persistence acknowledgement (see `SetPolicy`).
        ack: Option<oneshot::Sender<Result<(), String>>>,
    },
    /// Delete a named neighbor set.
    DeleteNeighborSet {
        /// Neighbor-set name.
        name: String,
        /// Optional persistence acknowledgement (see `SetPolicy`).
        ack: Option<oneshot::Sender<Result<(), String>>>,
    },
    /// Replace the global import policy chain.
    SetGlobalImportChain {
        /// Ordered policy names.
        policy_names: Vec<String>,
        /// Optional persistence acknowledgement (see `SetPolicy`).
        ack: Option<oneshot::Sender<Result<(), String>>>,
    },
    /// Replace the global export policy chain.
    SetGlobalExportChain {
        /// Ordered policy names.
        policy_names: Vec<String>,
        /// Optional persistence acknowledgement (see `SetPolicy`).
        ack: Option<oneshot::Sender<Result<(), String>>>,
    },
    /// Clear the global import policy chain.
    ClearGlobalImportChain {
        /// Optional persistence acknowledgement (see `SetPolicy`).
        ack: Option<oneshot::Sender<Result<(), String>>>,
    },
    /// Clear the global export policy chain.
    ClearGlobalExportChain {
        /// Optional persistence acknowledgement (see `SetPolicy`).
        ack: Option<oneshot::Sender<Result<(), String>>>,
    },
    /// Replace the per-neighbor import policy chain.
    SetNeighborImportChain {
        /// Neighbor address.
        address: IpAddr,
        /// Ordered policy names.
        policy_names: Vec<String>,
        /// Optional persistence acknowledgement (see `SetPolicy`).
        ack: Option<oneshot::Sender<Result<(), String>>>,
    },
    /// Replace the per-neighbor export policy chain.
    SetNeighborExportChain {
        /// Neighbor address.
        address: IpAddr,
        /// Ordered policy names.
        policy_names: Vec<String>,
        /// Optional persistence acknowledgement (see `SetPolicy`).
        ack: Option<oneshot::Sender<Result<(), String>>>,
    },
    /// Clear the per-neighbor import policy chain.
    ClearNeighborImportChain {
        /// Neighbor address.
        address: IpAddr,
        /// Optional persistence acknowledgement (see `SetPolicy`).
        ack: Option<oneshot::Sender<Result<(), String>>>,
    },
    /// Clear the per-neighbor export policy chain.
    ClearNeighborExportChain {
        /// Neighbor address.
        address: IpAddr,
        /// Optional persistence acknowledgement (see `SetPolicy`).
        ack: Option<oneshot::Sender<Result<(), String>>>,
    },
    /// Create or replace a peer-group definition.
    SetPeerGroup {
        /// Peer-group name.
        name: String,
        /// Full replacement definition.
        definition: PeerGroupDefinition,
        /// Optional persistence acknowledgement (see `SetPolicy`).
        ack: Option<oneshot::Sender<Result<(), String>>>,
    },
    /// Delete a peer-group definition.
    DeletePeerGroup {
        /// Peer-group name.
        name: String,
        /// Optional persistence acknowledgement (see `SetPolicy`).
        ack: Option<oneshot::Sender<Result<(), String>>>,
    },
    /// Set a neighbor's peer-group membership.
    SetNeighborPeerGroup {
        /// Neighbor address.
        address: IpAddr,
        /// Peer-group name.
        peer_group: String,
        /// Optional persistence acknowledgement (see `SetPolicy`).
        ack: Option<oneshot::Sender<Result<(), String>>>,
    },
    /// Clear a neighbor's peer-group membership.
    ClearNeighborPeerGroup {
        /// Neighbor address.
        address: IpAddr,
        /// Optional persistence acknowledgement (see `SetPolicy`).
        ack: Option<oneshot::Sender<Result<(), String>>>,
    },
}

/// Snapshot of a peer's state for queries.
#[derive(Debug, Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "peer status DTO mirrors independent runtime/config booleans for API consumers"
)]
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
    /// Effective RFC 9687 send hold time in seconds (0 = disabled).
    pub send_hold_time: u32,
    /// Maximum prefix limit (None = unlimited).
    pub max_prefixes: Option<u32>,
    /// Configured address families.
    pub families: Vec<(Afi, Safi)>,
    /// Private AS removal mode.
    pub remove_private_as: RemovePrivateAs,
    /// Whether this eBGP peer is a transparent route-server client.
    pub route_server_client: bool,
    /// RFC 7947 §2.3.2 per-client best-path enabled for this
    /// route-server client.
    pub per_client_best: bool,
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
    /// Configured Paths-Limit receiver preference.
    pub paths_limit_receive_max: u16,
    /// Peer-advertised Paths-Limit values by family.
    pub peer_paths_limits: Vec<((Afi, Safi), u16)>,
    /// Effective outbound Add-Path cap by family.
    pub effective_add_path_send_limits: Vec<((Afi, Safi), u32)>,
    /// Total UPDATE messages received.
    pub updates_received: u64,
    /// Total UPDATE messages sent.
    pub updates_sent: u64,
    /// Total NOTIFICATION messages received.
    pub notifications_received: u64,
    /// Total NOTIFICATION messages sent.
    pub notifications_sent: u64,
    /// Total BGP messages received, all types (daemon-lifetime;
    /// persists across session flaps and includes KEEPALIVEs).
    pub messages_received: u64,
    /// Total BGP messages sent, all types (daemon-lifetime).
    pub messages_sent: u64,
    /// Whether this iBGP peer is configured as a route-reflector client.
    pub route_reflector_client: bool,
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
    /// Effective transport authentication: plaintext, MD5, or `tcp_ao`.
    /// Protected accepted dynamic sessions derive this from durable live
    /// transport identity rather than a per-neighbor key configuration.
    pub authentication: String,
    /// Query-time TCP-AO inspection snapshot for the currently owned stream,
    /// including `KeyID` validity flags and cumulative verification counters.
    /// Health classification is derived at the protobuf/API boundary.
    pub tcp_ao_info: Option<TcpAoInfoSnapshot>,
    /// Desired/applied add-only rotation generation and actionable failure.
    pub tcp_ao_rotation: rustbgpd_transport::TcpAoRotationStatus,
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

/// One `QueryPolicyDatasets` reply row (LAN-305): the policy crate's
/// dataset status plus the config-bound snapshot path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDatasetStatusRow {
    /// Name / kind / generation / records / last-error snapshot.
    pub status: rustbgpd_policy::datasets::DatasetStatus,
    /// Bound snapshot file path (`[policy.datasets.<name>].path`).
    pub path: String,
}
