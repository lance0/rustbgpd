use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::stream::{self, StreamExt};
use rustbgpd_api::peer_types::{
    ConfigEvent, DynamicNeighborInfo, EnqueuedOperatorQuery, OwnedCatalogMutation,
    OwnedCatalogMutationOutcome, OwnedHotUpdatePeerOutcome, OwnedNeighborMutation,
    OwnedNeighborMutationError, OwnedNeighborMutationOutcome, PeerKey, PeerManagerCommand,
    PeerManagerNeighborConfig, PeerManagerOperatorQuery, PeerManagerReadinessQuery,
    PeerReconcileAuthority, PolicyDatasetStatusRow, PolicyEvent, RuntimeConfigTransactionPlanError,
    SessionEvent, SessionLifecycleEvent,
};
use rustbgpd_bmp::BmpEvent;
use rustbgpd_fsm::PeerConfig;
use rustbgpd_policy::PolicyChain;
use rustbgpd_rib::RibUpdate;
use rustbgpd_telemetry::BgpMetrics;
#[cfg(test)]
use rustbgpd_transport::SessionNotification;
use rustbgpd_transport::{
    PeerHandle, SessionLifecycleNotification,
    SessionNotificationEvent as TransportNotificationEvent, SessionNotificationReceiver,
    SessionNotificationSender, SessionQueryOutcome, TransportConfig, session_notification_channel,
};
use rustbgpd_wire::{Afi, Safi};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::task::JoinSet;
use tracing::{debug, error, info};

use crate::config::{Config, raw_config_document_bounded};
use crate::policy_admin::{
    apply_config_event, global_policy_chains_from_config, named_neighbor_set_from_config,
    named_neighbor_sets_from_config, named_peer_group_from_config, named_peer_groups_from_config,
    named_policies_from_config, named_policy_from_config, neighbor_peer_group_from_config,
    neighbor_policy_chains_from_config,
};

mod admission;
mod bfd;
mod dynamic;
mod events;
pub(crate) mod generation;
mod inbound;
mod lifecycle;
mod notifications;
mod policy;
mod queries;
mod reconcile;
mod rotation;
pub(crate) use rotation::TCP_AO_AWAITING_PEER_PREFIX;
mod snapshot;
#[cfg(test)]
pub(crate) mod test_support;
mod update_group_plan;

use dynamic::{AcceptedDynamicRange, DeadLetteredPending, DynamicRange};

const DEFAULT_HOLD_TIME: u16 = rustbgpd_fsm::DEFAULT_HOLD_TIME;
const DEFAULT_CONNECT_RETRY_SECS: u32 = 5;
const BGP_PORT: u16 = 179;
const BMP_STATS_INTERVAL_SECS: u64 = 60;

/// The current policy-transaction phase used to label operator-read waits.
/// Labels `bgp_peer_manager_operator_query_wait_seconds{seam}`; the set is
/// closed and every value is pre-registered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum OperatorReadSeam {
    /// No marked policy command overlapped the read's send-to-service interval.
    Unfenced,
    /// Policy preflight, cohort selection, destination prestage and session setup.
    Prestage,
    /// A forward reload awaiting the cohort RIB transition.
    ForwardTransition,
    /// A reload's authoritative commit batches.
    CommitBatches,
    /// A rejected reload's rollback.
    Rollback,
}

impl OperatorReadSeam {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Unfenced => "unfenced",
            Self::Prestage => "prestage",
            Self::ForwardTransition => "forward_transition",
            Self::CommitBatches => "commit_batches",
            Self::Rollback => "rollback",
        }
    }
}

/// Hard deadline for any single per-peer `query_state` request. Bounded so a
/// session task that's parked on TCP write back-pressure can't hang an admin
/// path (`ListPeers`, `GetPeerState`, periodic BMP stats). 100ms is well
/// above any healthy session-task command latency (typically <1ms) and well
/// below the 5-minute soak-harness gRPC health-check cadence, so a single
/// stalled peer surfaces as `stale = true` instead of as a wedged RPC.
const PEER_QUERY_TIMEOUT: Duration = Duration::from_millis(100);

/// One absolute retry window shared by every clean-convergence state check in
/// a settlement-owned policy cohort. A first 100 ms miss may be load rather
/// than session loss; it is retried at most once inside this fixed window.
const CLEAN_STATE_QUERY_WINDOW: Duration = Duration::from_secs(2);

/// Hard deadline for any single peer-session policy hot-apply (import or
/// export). Larger than [`PEER_QUERY_TIMEOUT`] because applying a policy
/// chain involves more session-side work than a state read, but still
/// bounded so a stalled peer can't park the peer-manager actor mid-reload.
/// If a policy update fails this deadline, the new policy still applies on
/// the peer's next session restart — the warn! is just a heads-up.
const PEER_POLICY_UPDATE_TIMEOUT: Duration = Duration::from_millis(500);

/// Hard deadline for any single peer-session lifecycle command send or
/// shutdown join driven by the `PeerManager` actor. The session command channel
/// is bounded, so a session task parked on TCP write back-pressure can stop
/// draining it; actor paths must fail/log within this deadline instead of
/// blocking every peer's RPC/reconcile work behind one stalled session.
const PEER_LIFECYCLE_COMMAND_TIMEOUT: Duration = Duration::from_millis(500);

/// Maximum number of independently owned peers drained at once during
/// process shutdown. Each peer still drains a pending inbound candidate before
/// its primary session, preserving the collision-owner ordering, while the
/// fixed cross-peer cap prevents the daemon's shutdown time from growing as
/// `peer_count * PEER_LIFECYCLE_COMMAND_TIMEOUT` under transport back-pressure.
const PEER_SHUTDOWN_CONCURRENCY: usize = 64;

/// Readiness requests serviced after each bounded policy-transaction step.
/// A small fixed budget prevents probe traffic from starving forward policy
/// progress while still keeping the unchanged 200 ms end-to-end deadline.
const READINESS_QUERY_BUDGET_PER_POLICY_STEP: usize = 1;

/// Hard deadline for RIB channel admission and reply on a single-peer policy
/// edit. Also used by per-peer outbound refresh and other bounded RIB steps.
/// Bounded so a wedged RIB task cannot park the
/// peer-manager actor (and therefore SIGHUP reload / gRPC policy apply)
/// forever.
///
/// It is not a claim that the RIB answers quickly. These commands queue on
/// the RIB manager's primary lane, which is not polled while route chunks
/// pend, and an export-policy replacement then performs a full Loc-RIB
/// distribution pass of its own — seconds at route-server scale under load.
/// Five seconds is therefore only defensible for one command whose latency
/// an operator is waiting on directly. Every `O(peers)` policy walk shares
/// one [`RIB_BATCH_REPLY_TIMEOUT`] budget across all of its steps instead,
/// so the walk is bounded in total rather than per peer.
const RIB_REPLY_TIMEOUT: Duration = Duration::from_secs(5);

/// Hard deadline for the batched authoritative export-policy apply
/// (`RibUpdate::ReplacePeerExportPoliciesAuthoritatively`). One command
/// carries the whole fallback cohort, so unlike the inline replies above
/// it legitimately performs a destination-table build plus a cohort-wide
/// emission — seconds at route-server scale. Twice the clean
/// transition's 60-second pre-commit ownership budget, and still bounded
/// so a wedged RIB task cannot park the peer-manager actor forever.
const RIB_BATCH_REPLY_TIMEOUT: Duration = Duration::from_mins(2);

/// ADR-0073: deadline for an `ExplainImportPolicy` round-trip to a
/// session task. Bounded for the same reason as the policy-update
/// timeout — a session parked on TCP back-pressure must not park the
/// peer-manager actor. The typed outcome prevents that timeout from
/// masquerading as a missing session.
const EXPLAIN_QUERY_TIMEOUT: Duration = Duration::from_millis(500);

/// Whether an actor-owned wait admits the bounded operator-read lane
/// (`rbgp neighbor`, `rbgp policy stats`, dataset status) while it is driven.
/// The dedicated readiness lane is always admitted; the ordinary command
/// receiver never is, so mutations stay strictly behind the owner. Operator
/// reads carry deadlines of 100 ms to 2 s, so any wait that can outlast them
/// must justify fencing them at the site: a fenced wait names what bounds it
/// or what a served read would observe, the same way a lint allowance names
/// its reason.
#[derive(Clone, Copy, Debug)]
enum OperatorReadAdmission {
    /// Serve each operator read as it arrives; the wait resumes after the
    /// read completes.
    Served,
    /// Leave operator reads queued behind the wait.
    Fenced {
        #[expect(
            dead_code,
            reason = "the reason documents the fence at its call site; it is not runtime state"
        )]
        reason: &'static str,
    },
}

impl OperatorReadAdmission {
    const fn admits(self) -> bool {
        matches!(self, Self::Served)
    }
}

/// Maximum number of session-side import-policy snapshots in flight per
/// collector/RPC. The cap bounds each collector's memory/work while every
/// query still shares the caller's single absolute deadline.
const IMPORT_POLICY_QUERY_CONCURRENCY: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransactionConfigScope {
    Full,
    FibTablesOnly,
}

/// Opaque proof of the exact live config displaced by a transaction stage.
#[derive(Debug)]
pub(crate) struct TransactionConfigRollbackToken {
    previous: Box<Config>,
    scope: TransactionConfigScope,
}

impl TransactionConfigRollbackToken {
    pub(crate) fn capture(previous: Box<Config>, scope: TransactionConfigScope) -> Self {
        Self { previous, scope }
    }

    pub(crate) fn previous(&self) -> &Config {
        &self.previous
    }
}

#[derive(Debug)]
pub(crate) struct PlannedTransactionConfig {
    pub(crate) plan: rustbgpd_api::peer_types::RuntimeConfigTransactionPlan,
    pub(crate) candidate: Box<Config>,
}

pub(crate) use generation::ReloadGenerationOutcome;

/// A debug-build-only, one-shot failure for a controlled SIGHUP regression.
#[cfg(all(debug_assertions, not(test)))]
fn debug_reconfigure_failures() -> std::collections::BTreeMap<PeerKey, u32> {
    const VARIABLE: &str = "RUSTBGPD_TEST_SIGHUP_RECONFIGURE_FAILURE_PEER";
    let value = match std::env::var(VARIABLE) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return std::collections::BTreeMap::new(),
        Err(error) => {
            tracing::warn!(variable = VARIABLE, %error, "invalid debug-only reconfigure failure setting; injection disabled");
            return std::collections::BTreeMap::new();
        }
    };
    match value.parse::<IpAddr>() {
        Ok(peer) => std::collections::BTreeMap::from([(PeerKey::new(peer, None), 0)]),
        Err(error) => {
            tracing::warn!(variable = VARIABLE, %error, "invalid debug-only reconfigure failure peer; injection disabled");
            std::collections::BTreeMap::new()
        }
    }
}

pub(crate) enum InternalCommand {
    /// Apply one complete SIGHUP candidate as an owned runtime generation.
    ApplyReloadGeneration {
        candidate: Box<Config>,
        actions: Vec<crate::config::ReloadPeerAction>,
        datasets: crate::config::PreparedDatasetGeneration,
        reply: oneshot::Sender<ReloadGenerationOutcome>,
    },
    ReplaceConfigSnapshot {
        config: Box<Config>,
        /// Optional acknowledgement, sent after `current_config` is assigned.
        /// The SIGHUP reload path awaits this before releasing the FIB
        /// coordinator lock so a following gRPC FIB-table CRUD can't have its
        /// snapshot overtaken by this (stale) one on the separate channel.
        ack: Option<oneshot::Sender<()>>,
    },
    /// Plan a retained accepted snapshot for an apply and return the exact
    /// typed object that was planned.
    PlanAcceptedTransactionConfig {
        snapshot: std::sync::Arc<crate::config::AcceptedConfigSnapshot>,
        expected_runtime_snapshot_token: Option<String>,
        reply: oneshot::Sender<Result<PlannedTransactionConfig, RuntimeConfigTransactionPlanError>>,
    },
    /// Plan an already loaded candidate and return that exact typed object.
    PlanTransactionConfig {
        candidate: Box<Config>,
        expected_runtime_snapshot_token: Option<String>,
        reply: oneshot::Sender<Result<PlannedTransactionConfig, RuntimeConfigTransactionPlanError>>,
    },
    /// Stage an already planned typed candidate without reopening any source.
    StageTransactionConfig {
        candidate: Box<Config>,
        scope: TransactionConfigScope,
        reply: oneshot::Sender<Result<TransactionConfigRollbackToken, String>>,
    },
    /// Restore the exact source-attached snapshot returned by
    /// [`InternalCommand::StageTransactionConfig`].
    RestoreTransactionConfig {
        rollback: TransactionConfigRollbackToken,
        reply: oneshot::Sender<()>,
    },
}

#[allow(
    clippy::struct_excessive_bools,
    reason = "peer lifecycle capabilities are independent negotiated and runtime states"
)]
struct ManagedPeer {
    handle: PeerHandle,
    session_id: u64,
    remote_asn: u32,
    description: String,
    peer_group: Option<String>,
    enabled: bool,
    hold_time: Option<u16>,
    max_prefixes: Option<u32>,
    /// Manager-owned max-prefix restart policy. Session tasks only report the
    /// breach and never observe or schedule this hold-down.
    max_prefix_restart_seconds: Option<u32>,
    transport_config: TransportConfig,
    import_policy: Option<PolicyChain>,
    export_policy: Option<PolicyChain>,
    /// Live inbound session waiting for collision resolution.
    pending_inbound: Option<PendingInbound>,
    /// True for peers auto-created from a `[[dynamic_neighbors]]` range.
    /// Dynamic peers are ephemeral: removed when session falls to Idle.
    is_dynamic: bool,
    /// ADR-0112 RFC 8212 external classification, pinned at the resolution
    /// that created this peer and never recomputed.
    ///
    /// It is the one piece of policy provenance the running config cannot
    /// reproduce later: an accept-any (`remote_asn = 0`) range's child has its
    /// sentinel overwritten by the ASN learned from OPEN, so a re-resolution
    /// keyed on `remote_asn` alone could reclassify a live external session as
    /// iBGP and silently drop its reserved deny. Every later chain
    /// re-resolution for this peer feeds it back in as `external_pinned`.
    rfc8212_external: bool,
    /// Durable, non-secret TCP-AO protection identity used when the bounded
    /// session-state query times out or the task has exited.
    tcp_ao_protected: bool,
    /// Desired/applied global TCP-AO inventory generation as observed by this
    /// peer's session command. Kept outside the session query so a wedged task
    /// cannot make a failed rotation look applied.
    tcp_ao_rotation: rustbgpd_transport::TcpAoRotationStatus,
    /// Canonical `[[dynamic_neighbors]]` range that accepted this peer.
    ///
    /// Static peers are `None`. Dynamic peers keep the accepted range even if
    /// the live matcher changes later, giving transaction planning a stable
    /// target key for established dynamic sessions.
    accepted_dynamic_range: Option<AcceptedDynamicRange>,
    /// Tracks unfired Route Refresh intent across calls. Set in any
    /// of three places that can leave a refresh undelivered:
    /// (1) `soft_reset_in` returned Err (session not reachable for
    /// `send_route_refresh` despite Established state); (2) the
    /// function bailed before reaching `soft_reset_in` because some
    /// downstream step failed (session-side hot-apply, RIB update),
    /// and `needs_refresh` was true at bail time — covers the
    /// cross-side carry case where import succeeded (advancing
    /// bookkeeping) but export bailed; (3) the peer wasn't
    /// Established at the time of an inherited
    /// `had_pending_refresh`, so no refresh was sendable. Drained
    /// at the start of every `update_runtime_policies` call and
    /// folded into `needs_refresh` alongside `import_changed`.
    /// Without this, a transient failure would leave the new policy
    /// applied to *future* UPDATEs while routes already in
    /// `AdjRibIn` — accepted under the prior policy — keep flowing
    /// until the operator reissues a `SetPolicy`.
    pending_refresh: bool,
    /// Symmetric counterpart for the export side. Set when
    /// `update_export_policy_timeout` failed for an export-changing
    /// edit, OR when the function bailed before completing the
    /// export-side pipeline with `needs_export_apply` true (the
    /// cross-side carry case). Drained by the next
    /// `update_runtime_policies` call and folded into
    /// `needs_export_apply` alongside `export_changed`. Without
    /// this, a transient session-side export-policy update failure
    /// would leave the peer announcing under the prior policy while
    /// the daemon's config snapshot has already advanced —
    /// permit→deny export edits would silently keep leaking routes,
    /// and the symmetry with the import side guarantees both halves
    /// of a `SetPolicy` carry the same all-or-nothing semantics.
    pending_export_apply: bool,
    /// RFC 8326 graceful-shutdown initiator toggle — operator-driven
    /// desired state. When true, every outbound update gets
    /// `COMMUNITY_GRACEFUL_SHUTDOWN` (`0xFFFF_0000`) attached.
    ///
    /// `PeerManager` is the authority; the per-session bool in
    /// `PeerSession` mirrors this value and gets re-seeded on every
    /// session spawn (collision-replace, dynamic peer re-establish,
    /// flap-and-reconnect). Without this lift, an operator who
    /// runs `rbgp gshut --peer X` and then experiences a peer
    /// flap would have the toggle silently lost — the new session
    /// would come up advertising untagged routes during the very
    /// maintenance window the toggle was supposed to cover.
    advertise_graceful_shutdown: bool,
}

#[derive(Debug, Clone)]
struct MaxPrefixLatch {
    error: String,
    generation: u64,
    source_session_id: u64,
    deadline: Option<tokio::time::Instant>,
}

/// Exact global inventory bound to an in-progress or failed TCP-AO
/// generation. Retained until commit so a same-generation retry cannot change
/// key material after any listener/session may already have installed a
/// prefix of the original candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TcpAoDesiredInventory {
    generation: rustbgpd_transport::TcpAoRotationGeneration,
    operation: rustbgpd_transport::TcpAoRotationOperation,
    listener_keys: Vec<rustbgpd_transport::TcpAoListenerKey>,
    static_keyrings: Vec<(
        rustbgpd_api::peer_types::PeerKey,
        rustbgpd_transport::TcpAoKeyring,
    )>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PeerShutdownOutcome {
    Joined,
    TimedOut,
}

impl PeerShutdownOutcome {
    #[must_use]
    pub(super) fn joined(self) -> bool {
        matches!(self, Self::Joined)
    }
}

struct PendingInbound {
    handle: PeerHandle,
    session_id: u64,
}

/// Manages the lifecycle of all peer sessions.
///
/// Runs as a single tokio task, receiving commands via an mpsc channel.
/// Same single-task ownership pattern as `RibManager`.
pub struct PeerManager {
    peers: HashMap<PeerKey, ManagedPeer>,
    /// Max-prefix shutdowns owned by the manager rather than a disposable
    /// session task. Presence fences passive accepts, collision handling, and
    /// config reconciliation until explicit enable or one configured restart
    /// attempt reaches its deadline; a failed attempt remains latched down.
    max_prefix_latches: HashMap<PeerKey, MaxPrefixLatch>,
    /// Cached earliest deadline, recomputed only when latch state mutates so
    /// ordinary actor traffic does not scan every disabled peer.
    next_max_prefix_restart_deadline: Option<tokio::time::Instant>,
    next_max_prefix_latch_generation: u64,
    /// Session generations being joined before an ownership transfer or
    /// deletion completes. A terminal max-prefix signal emitted during that
    /// barrier still belongs to the peer; entries are removed only after the
    /// actor is gone and the lossless notification lane has been drained.
    retiring_sessions: HashMap<u64, PeerKey>,
    /// Reverse lookup from transport session id to configured peer identity.
    /// Session lifecycle notifications are keyed by session id, and scoped
    /// link-local peers can share the same address on different interfaces.
    session_index: HashMap<u64, PeerKey>,
    rx: mpsc::Receiver<PeerManagerCommand>,
    /// Dedicated read-only lane drained only at safe actor seams. Mutation
    /// commands remain on `rx` and therefore stay ordered behind a policy
    /// transaction until it either commits or rolls back.
    readiness_rx: Option<mpsc::Receiver<PeerManagerReadinessQuery>>,
    /// Operator snapshots use the normal loop and explicitly served transaction
    /// wait sites. Mutations remain ordered on the separate command lane.
    operator_rx: Option<mpsc::Receiver<EnqueuedOperatorQuery>>,
    /// Neighbor snapshots deferred while another normal snapshot services
    /// lightweight reads. Bounded by the operator channel's capacity.
    deferred_operator_queries: VecDeque<EnqueuedOperatorQuery>,
    /// Current command's policy phase. Reset before each command; ordinary
    /// commands must not erase the last completed policy phase below.
    operator_read_seam: OperatorReadSeam,
    /// Last policy marker and enclosing command's completion instant. The
    /// marker includes trailing command work, not a causal split of the wait.
    completed_operator_seam: Option<(OperatorReadSeam, tokio::time::Instant)>,
    internal_rx: Option<mpsc::Receiver<InternalCommand>>,
    local_asn: u32,
    router_id: Ipv4Addr,
    /// Local cluster ID for route reflection (RFC 4456). `None` when not an RR.
    cluster_id: Option<Ipv4Addr>,
    /// Process-wide local restarting-speaker GR deadline. Static peers
    /// restored during this window advertise `restart_state = true`.
    local_gr_restart_until: Option<Instant>,
    metrics: BgpMetrics,
    rib_tx: mpsc::Sender<RibUpdate>,
    /// Optional BMP event sender (None when BMP not configured).
    bmp_tx: Option<mpsc::Sender<BmpEvent>>,
    /// RPKI/ASPA validation snapshot receiver, cloned to each peer session.
    validation_rx: Option<watch::Receiver<rustbgpd_rpki::ValidationSnapshot>>,
    session_notify_tx: SessionNotificationSender,
    session_notify_rx: SessionNotificationReceiver,
    session_lifecycle_tx: mpsc::Sender<SessionLifecycleNotification>,
    session_lifecycle_rx: mpsc::Receiver<SessionLifecycleNotification>,
    session_notification_event_tx: mpsc::Sender<TransportNotificationEvent>,
    session_notification_event_rx: mpsc::Receiver<TransportNotificationEvent>,
    session_events_tx: broadcast::Sender<Arc<SessionEvent>>,
    session_event_history: VecDeque<SessionLifecycleEvent>,
    policy_events_tx: broadcast::Sender<Arc<PolicyEvent>>,
    policy_event_history: VecDeque<Arc<PolicyEvent>>,
    current_config: Config,
    /// True between typed transaction staging and the controller's
    /// persist/rollback completion signal. Dynamic inbound accepts are refused
    /// in this window so candidate-only ranges cannot create live peers before
    /// the candidate is durable.
    config_snapshot_staged: bool,
    /// Installed policy-route metric reachability before a successful staged
    /// config transaction. Consumed only by commit; restore/replacement clear
    /// it without retiring series.
    staged_policy_routes_prior: Option<policy::InstalledPolicyRoutesReachability>,
    /// Resolved dynamic neighbor ranges for prefix-based auto-accept.
    dynamic_ranges: Vec<DynamicRange>,
    /// Current number of active dynamic peers (for limit enforcement).
    dynamic_peer_count: usize,
    /// Maximum dynamic peers allowed. Default 100.
    dynamic_neighbor_limit: u32,
    /// ADR-0120 per-source accept-rate limiter. `None` when
    /// `[inbound_admission]` is disabled (the default); built once at
    /// startup — every field is restart-required.
    inbound_admission: Option<admission::InboundAdmission>,
    /// Dead-lettered hot-apply / Route Refresh / `GShut` intent from dynamic
    /// peers auto-removed by `BackToIdle`. Restored on the next inbound
    /// from the same address. Bounded at `dynamic_neighbor_limit` so a
    /// pathological churn pattern can't grow it without bound; an over-
    /// cap insert evicts the oldest recorded address with a `warn!`.
    dead_lettered_pending: HashMap<IpAddr, DeadLetteredPending>,
    /// Insertion order for [`Self::dead_lettered_pending`]. Stale addresses
    /// are skipped lazily when the bounded table needs to evict.
    dead_lettered_pending_order: VecDeque<IpAddr>,
    next_session_id: u64,
    /// Globally committed TCP-AO inventory generation. Protected accepts from
    /// a newer listener generation are rejected until established-session
    /// rotation convergence commits the same generation here.
    tcp_ao_generation: rustbgpd_transport::TcpAoRotationGeneration,
    /// Global rotation phase gates protected accepts between preflight and
    /// established-session commit so no new session can escape the preflight
    /// inventory.
    tcp_ao_rotation: rustbgpd_transport::TcpAoRotationStatus,
    /// Immutable candidate retained across preflight/apply failure and cleared
    /// only after the peer-manager generation globally commits.
    tcp_ao_desired_inventory: Option<TcpAoDesiredInventory>,
    /// ADR-0067 step 4 — RFC 5882 coupling. `PeerManager` owns the desired BFD
    /// session set; the BFD actor is a pure session-runner that reconciles it.
    /// `None` when no neighbor configures BFD.
    bfd_coupling: Option<bfd::BfdCoupling>,
    /// Optional handle to the durable event outbox (ADR-0072). When
    /// `Some`, each `publish_*_event` call additionally enqueues an
    /// encoded `BgpEvent` for durable cursor replay. The legacy
    /// ring + broadcast remain unconditional. When `None`, the
    /// durable enqueue is skipped — daemons with `[event_history]
    /// .enabled = false` see no behavior change.
    event_history: Option<rustbgpd_event_history::EventHistoryHandle>,
    /// Out-of-crate transport event sink (ADR-0072 follow-up). When
    /// `Some`, each spawned `PeerHandle` is wired with this sink so
    /// transport-layer policy events (today: OTC route-leak
    /// decisions) are published through the durable cursor. Wired
    /// at the same daemon-startup site as `event_history`.
    transport_event_sink: Option<std::sync::Arc<dyn rustbgpd_transport::TransportEventSink>>,
    /// Per-process key for the optimistic config-transaction snapshot token.
    /// Seeded once at construction; never leaves the process. Keeps the token
    /// from acting as an offline oracle for config secrets. See
    /// [`crate::config::RuntimeSnapshotKey`].
    snapshot_key: crate::config::RuntimeSnapshotKey,
    /// Accepted-config authority (ADR-0121) for external-input identity
    /// verification on the config-transaction plan path. `None` (no config
    /// file, tests) keeps every candidate `Unverified`, i.e. the presence
    /// fence.
    accepted_rx: Option<watch::Receiver<Arc<crate::config::AcceptedConfigSnapshot>>>,
    /// Deterministic test/debug failure injection: `reconfigure_peer` against
    /// a mapped key fails up front, before the delete/re-add cycle, once the
    /// key's budget of remaining successful calls reaches zero (a value of 0
    /// fails the next call; a value of 1 lets one call succeed, then fails
    /// the one after — e.g. apply succeeds, rollback fails). Models a
    /// transient runtime failure (e.g. a session task that cannot start) —
    /// the only mid-fanout failure class left, since config-shaped failures
    /// are all caught by validation, resolution, or the reshape preflight
    /// before any peer is touched.
    #[cfg(any(test, debug_assertions))]
    inject_reconfigure_failures: std::collections::BTreeMap<PeerKey, u32>,
    #[cfg(test)]
    dataset_generations_at_peer_construction: Option<Vec<(PeerKey, String, u64)>>,
    /// The same deterministic fault injection for the in-place applier
    /// (`hot_update_peer_in_place`), so the peer-group hot path's
    /// mid-cohort failure and rollback contract can be exercised.
    #[cfg(test)]
    inject_hot_update_failures: std::collections::BTreeMap<PeerKey, u32>,
}

impl PeerManager {
    #[cfg(test)]
    #[expect(
        clippy::too_many_arguments,
        reason = "peer construction keeps all explicit lifecycle dependencies visible"
    )]
    pub fn new(
        rx: mpsc::Receiver<PeerManagerCommand>,
        local_asn: u32,
        router_id: Ipv4Addr,
        cluster_id: Option<Ipv4Addr>,
        local_gr_restart_until: Option<Instant>,
        metrics: BgpMetrics,
        rib_tx: mpsc::Sender<RibUpdate>,
        bmp_tx: Option<mpsc::Sender<BmpEvent>>,
    ) -> Self {
        let (_internal_tx, internal_rx) = mpsc::channel(1);
        Self::new_with_config(
            rx,
            internal_rx,
            local_asn,
            router_id,
            cluster_id,
            local_gr_restart_until,
            metrics,
            rib_tx,
            bmp_tx,
            None, // no RPKI validation in tests
            Config {
                config_epoch: None,
                global: crate::config::Global {
                    asn: local_asn,
                    router_id: router_id.to_string(),
                    listen_port: BGP_PORT,
                    listen_addresses: None,
                    cluster_id: cluster_id.map(|id| id.to_string()),
                    runtime_state_dir: "/tmp/rustbgpd-tests".to_string(),
                    telemetry: crate::config::TelemetryConfig {
                        prometheus_addr: Some("127.0.0.1:9179".to_string()),
                        log_format: crate::config::LogFormatConfig::Json,
                        grpc_tcp: None,
                        grpc_uds: None,
                    },
                    dynamic_neighbor_limit: None,
                    worker_threads: None,
                    honor_graceful_shutdown: false,
                    honor_blackhole: false,
                    multipath_relax: false,
                    link_bandwidth_weighted: false,
                    install_blackhole_discard: false,
                    allow_blackhole_broad_prefixes: false,
                    blackhole_discard_max_active: None,
                    blackhole_discard_install_rate_per_minute: None,
                    blackhole_discard_install_burst: None,
                    ebgp_requires_policy: None,
                    warm_cache_checkpoint_on_shutdown: false,
                    max_as_path_length: rustbgpd_transport::DEFAULT_MAX_AS_PATH_LENGTH,
                },
                // PeerManager::new constructs an in-memory baseline
                // Config before the operator's TOML is applied. The
                // tier default with no listeners and no roles is valid
                // since the implicit local-operator amendment (the
                // implicit owner-only UDS listener needs no
                // [security.grpc.roles]), so the baseline can carry
                // the plain schema default; the real config arrives
                // via reload / config-bridge with its own
                // [security.grpc] block.
                security: crate::config::SecurityConfig::default(),
                neighbors: Vec::new(),
                peer_groups: HashMap::new(),
                policy: crate::config::PolicyConfig::default(),
                rpki: None,
                bmp: None,
                gnmi_dialout: None,
                mrt: None,
                file_path: None,
                dynamic_neighbors: Vec::new(),
                evpn_instances: Vec::new(),
                ethernet_segments: Vec::new(),
                evpn_ip_vrfs: Vec::new(),
                managed_netdevs: crate::config::ManagedNetdevsConfig::default(),
                fib_tables: Vec::new(),
                bfd_profiles: Vec::new(),
                apply_bum_enforcement: false,
                event_history: crate::config::EventHistoryConfig::default(),
                inbound_admission: crate::config::InboundAdmissionConfig::default(),
            },
        )
    }

    /// Install the accepted-config authority used to verify a transaction
    /// candidate's captured external-input identity (ADR-0130).
    #[must_use]
    pub fn with_accepted_identity(
        mut self,
        accepted_rx: watch::Receiver<Arc<crate::config::AcceptedConfigSnapshot>>,
    ) -> Self {
        self.accepted_rx = Some(accepted_rx);
        self
    }

    /// Install the dedicated read-only readiness-query receiver.
    #[must_use]
    pub fn with_readiness_queries(
        mut self,
        readiness_rx: mpsc::Receiver<PeerManagerReadinessQuery>,
    ) -> Self {
        self.readiness_rx = Some(readiness_rx);
        self
    }

    /// Install the bounded operator snapshot lane.
    #[must_use]
    pub fn with_operator_queries(
        mut self,
        operator_rx: mpsc::Receiver<EnqueuedOperatorQuery>,
    ) -> Self {
        self.operator_rx = Some(operator_rx);
        self
    }

    /// Latest completed marked command overlapping the read's queue wait.
    fn seam_that_held(&self, enqueued: tokio::time::Instant) -> OperatorReadSeam {
        match self.completed_operator_seam {
            Some((seam, released)) if enqueued < released => seam,
            _ => OperatorReadSeam::Unfenced,
        }
    }

    fn finish_operator_seam(&mut self) {
        if self.operator_read_seam != OperatorReadSeam::Unfenced {
            self.completed_operator_seam =
                Some((self.operator_read_seam, tokio::time::Instant::now()));
        }
    }

    /// Record one operator read's send-to-service wait under `seam`.
    /// Observed at service, so a read whose caller already gave up still
    /// reports its queue wait. Service execution and reply delivery follow it.
    fn observe_operator_query_wait(&self, enqueued: tokio::time::Instant, seam: OperatorReadSeam) {
        self.metrics
            .observe_peer_manager_operator_query_wait(seam.label(), enqueued.elapsed());
    }

    async fn handle_operator_query(&mut self, query: EnqueuedOperatorQuery, during_prestage: bool) {
        let EnqueuedOperatorQuery { enqueued, query } = query;
        if during_prestage {
            // A marked transaction wait owns the attribution. An unmarked
            // admitting wait retains a completed policy seam that held this read.
            let seam = if self.operator_read_seam == OperatorReadSeam::Unfenced {
                self.seam_that_held(enqueued)
            } else {
                self.operator_read_seam
            };
            self.observe_operator_query_wait(enqueued, seam);
            // Finish the admitted snapshot before a prestage ACK can let
            // the reload advance any session's installed policy.
            if let Some(task) = self.answer_operator_query(query).await {
                let _ = self.finish_admitted_operator_read(task).await;
            }
        } else {
            self.observe_operator_query_wait(enqueued, self.seam_that_held(enqueued));
            self.answer_normal_operator_query(query).await;
        }
    }

    async fn answer_operator_query(
        &self,
        query: PeerManagerOperatorQuery,
    ) -> Option<tokio::task::JoinHandle<()>> {
        match query {
            PeerManagerOperatorQuery::ListPeers { reply } => self.answer_list_peers(reply).await,
            PeerManagerOperatorQuery::GetPeerState { peer, mut reply } => {
                let info = tokio::select! {
                    biased;
                    () = reply.closed() => return None,
                    info = self.get_peer_info(&peer) => info,
                };
                let _ = reply.send(info);
            }
            PeerManagerOperatorQuery::HasPeerAddress { address, reply } => {
                let _ = reply.send(self.unique_peer_key_for_address(address).is_some());
            }
            PeerManagerOperatorQuery::QueryImportPolicyTermHits {
                peer,
                deadline,
                reply,
            } => {
                return self.dispatch_import_policy_term_hits(peer, deadline, reply);
            }
            PeerManagerOperatorQuery::QueryPolicyDatasets { reply } => {
                if !reply.is_closed() {
                    let _ = reply.send(self.policy_dataset_status_rows());
                }
            }
        }
        None
    }

    /// A normal neighbor snapshot keeps mutations fenced while allowing a
    /// bounded number of lightweight operator reads to use their own deadlines.
    /// Further neighbor snapshots wait without starting another session fan-out.
    async fn answer_normal_operator_query(&mut self, query: PeerManagerOperatorQuery) {
        let Some(mut operator_rx) = self.operator_rx.take() else {
            drop(self.answer_operator_query(query).await);
            return;
        };
        let capacity = operator_rx.max_capacity();
        let mut remaining = capacity;
        let mut deferred = std::mem::take(&mut self.deferred_operator_queries);
        let mut disconnected = false;
        {
            // The receiver is local so the snapshot can keep borrowing all
            // manager metadata until its complete reply or cancellation.
            let snapshot = self.answer_operator_query(query);
            tokio::pin!(snapshot);
            loop {
                tokio::select! {
                    biased;
                    // Completion/cancellation wins over a ready read flood.
                    // Normal import collectors retain their detached lifetime.
                    task = &mut snapshot => {
                        drop(task);
                        break;
                    }
                    query = operator_rx.recv(),
                        if !disconnected && remaining > 0 && deferred.len() < capacity => {
                        match query {
                            Some(query) => {
                                remaining -= 1;
                                if matches!(
                                    query.query,
                                    PeerManagerOperatorQuery::ListPeers { .. }
                                        | PeerManagerOperatorQuery::GetPeerState { .. }
                                ) {
                                    deferred.push_back(query);
                                } else {
                                    let EnqueuedOperatorQuery { enqueued, query } = query;
                                    self.observe_operator_query_wait(
                                        enqueued,
                                        self.seam_that_held(enqueued),
                                    );
                                    drop(self.answer_operator_query(query).await);
                                }
                            }
                            None => disconnected = true,
                        }
                    }
                }
            }
        }
        self.operator_rx = (!disconnected).then_some(operator_rx);
        self.deferred_operator_queries = deferred;
        // Return to the normal select before starting another snapshot, so
        // queued mutations remain eligible even when reads keep arriving.
    }

    fn dispatch_import_policy_term_hits(
        &self,
        peer: Option<IpAddr>,
        deadline: tokio::time::Instant,
        mut reply: oneshot::Sender<
            SessionQueryOutcome<Vec<(IpAddr, rustbgpd_transport::ImportPolicyTermHits)>>,
        >,
    ) -> Option<tokio::task::JoinHandle<()>> {
        // Import chains and counters live in sessions. Normal reads detach
        // this collector; prestage reads finish it before session application,
        // while continuing to service readiness. Every send and reply shares
        // the RPC deadline, and any failed session fails the complete snapshot.
        if deadline <= tokio::time::Instant::now() {
            let _ = reply.send(SessionQueryOutcome::TimedOut);
            return None;
        }
        // Do not clone a fleet of session senders for an
        // RPC that was cancelled while its command waited
        // in the manager queue.
        if reply.is_closed() {
            return None;
        }
        let targets: Vec<_> = if let Some(address) = peer {
            let Some(key) = self.unique_peer_key_for_address(address) else {
                let _ = reply.send(SessionQueryOutcome::SessionGone);
                return None;
            };
            let Some(managed) = self.peers.get(&key) else {
                let _ = reply.send(SessionQueryOutcome::SessionGone);
                return None;
            };
            vec![(key.address, managed.handle.commands_sender())]
        } else {
            self.peers
                .iter()
                .map(|(key, managed)| (key.address, managed.handle.commands_sender()))
                .collect()
        };
        Some(tokio::spawn(async move {
            let collection = async move {
                let mut out = Vec::new();
                let queries = stream::iter(targets)
                    .map(|(address, commands)| async move {
                        let outcome = PeerHandle::query_import_policy_term_hits_with_deadline(
                            commands, deadline,
                        )
                        .await;
                        (address, outcome)
                    })
                    .buffer_unordered(IMPORT_POLICY_QUERY_CONCURRENCY);
                tokio::pin!(queries);
                while let Some((address, outcome)) = queries.next().await {
                    match outcome {
                        SessionQueryOutcome::Reply(Some(snapshot)) => {
                            out.push((address, snapshot));
                        }
                        SessionQueryOutcome::Reply(None) => {}
                        SessionQueryOutcome::TimedOut => {
                            return SessionQueryOutcome::TimedOut;
                        }
                        SessionQueryOutcome::SessionGone => {
                            return SessionQueryOutcome::SessionGone;
                        }
                    }
                }
                out.sort_unstable_by_key(|(address, _)| *address);
                SessionQueryOutcome::Reply(out)
            };
            let result = tokio::select! {
                biased;
                // Dropping `collection` releases every
                // target sender and in-flight reply future.
                () = reply.closed() => return,
                result = collection => result,
            };
            let _ = reply.send(result);
        }))
    }

    fn policy_dataset_status_rows(&self) -> Vec<PolicyDatasetStatusRow> {
        let mut rows: Vec<_> = self
            .current_config
            .policy
            .dataset_bindings
            .handles()
            .map(|handle| {
                let status = handle.status();
                let path = self
                    .current_config
                    .policy
                    .datasets
                    .get(&status.name)
                    .map(|entry| entry.path.clone())
                    .unwrap_or_default();
                PolicyDatasetStatusRow { status, path }
            })
            .collect();
        rows.sort_by(|a, b| a.status.name.cmp(&b.status.name));
        rows
    }

    async fn receive_operator_query(
        operator_rx: &mut Option<mpsc::Receiver<EnqueuedOperatorQuery>>,
        deferred: &mut VecDeque<EnqueuedOperatorQuery>,
    ) -> Option<EnqueuedOperatorQuery> {
        if let Some(query) = deferred.pop_front() {
            return Some(query);
        }
        match operator_rx {
            Some(rx) => rx.recv().await,
            None => std::future::pending().await,
        }
    }

    /// Service a bounded number of live readiness snapshots at a transaction
    /// seam. `try_recv` is deliberate: when no probe is waiting this does not
    /// introduce an async suspension point or let ordinary commands bypass the
    /// transaction.
    async fn drain_readiness_queries(&mut self) {
        for _ in 0..READINESS_QUERY_BUDGET_PER_POLICY_STEP {
            let query = match self.readiness_rx.as_mut() {
                Some(rx) => match rx.try_recv() {
                    Ok(query) => query,
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        self.readiness_rx = None;
                        break;
                    }
                },
                None => break,
            };
            self.handle_readiness_query(query).await;
        }
    }

    async fn handle_readiness_query(&self, query: PeerManagerReadinessQuery) {
        match query {
            PeerManagerReadinessQuery::Ping { reply } => {
                let _ = reply.send(());
            }
            PeerManagerReadinessQuery::ListPeers { reply } => {
                self.answer_list_peers(reply).await;
            }
        }
    }

    /// Finish one admitted operator read while servicing only the readiness
    /// lane. This is the one wait that takes no admission: the read it
    /// drives was itself admitted by an [`Self::await_with_readiness`] wait,
    /// which admits the next read once this one completes, so reads stay in
    /// order and the admitting wait never nests.
    async fn finish_admitted_operator_read<F>(&mut self, future: F) -> F::Output
    where
        F: Future,
    {
        tokio::pin!(future);
        loop {
            let Some(readiness_rx) = self.readiness_rx.as_mut() else {
                return future.await;
            };
            tokio::select! {
                biased;
                result = &mut future => return result,
                query = readiness_rx.recv() => {
                    match query {
                        Some(query) => self.handle_readiness_query(query).await,
                        None => self.readiness_rx = None,
                    }
                }
            }
        }
    }

    /// Drive one owned step while servicing at most one read-only readiness
    /// query at a time and, when `admission` is [`OperatorReadAdmission::Served`],
    /// the bounded operator-read lane as well. The step future is biased
    /// first, so a probe flood cannot delay a completed apply/rollback step.
    /// Each admitted operator read completes (through a fenced wait of its
    /// own) before this wait resumes, and the ordinary command receiver is
    /// never polled here, so mutations remain strictly behind the owner.
    ///
    /// A forward reload serves reads while it awaits the cohort's RIB
    /// transition and while the same transaction's rollback awaits its
    /// registered RIB aggregate. During the transition every cohort session
    /// already runs its new chains, so a read observes the same mixed
    /// per-session generation the destination prestage admits; during the
    /// rollback reads report live session state after restoration has been
    /// attempted, including failed restores. Neither wait pins a common
    /// generation across sessions or the RIB, whose authoritative restore
    /// still fences its general-query lane.
    async fn await_with_readiness<F>(
        &mut self,
        future: F,
        admission: OperatorReadAdmission,
    ) -> F::Output
    where
        F: Future,
    {
        tokio::pin!(future);
        loop {
            tokio::select! {
                biased;
                result = &mut future => return result,
                query = Self::receive_readiness_query(&mut self.readiness_rx) => {
                    match query {
                        Some(query) => self.handle_readiness_query(query).await,
                        None => self.readiness_rx = None,
                    }
                }
                query = Self::receive_operator_query(&mut self.operator_rx, &mut self.deferred_operator_queries), if admission.admits() => {
                    match query {
                        // Boxed so the read's handler is not part of every
                        // fenced wait's state machine; it allocates only
                        // when a read is actually admitted.
                        Some(query) => Box::pin(self.handle_operator_query(query, true)).await,
                        None => self.operator_rx = None,
                    }
                }
            }
        }
    }

    /// Like [`Self::await_with_readiness`], but bound the step by a budget
    /// that accrues only while the step itself is being driven. Wall time
    /// spent servicing an interleaved readiness or operator query is not
    /// charged: a `tokio::time::timeout` inside the step would keep counting
    /// during that servicing, so a probe flood (or any long servicing burst)
    /// would be deducted from a healthy session command's deadline — the
    /// mechanism behind the cohort-setup starvation. Returns `None` when the
    /// accrued budget elapses before the future completes.
    async fn await_with_readiness_budget<F>(
        &mut self,
        future: F,
        budget: Duration,
        admission: OperatorReadAdmission,
    ) -> Option<F::Output>
    where
        F: Future,
    {
        tokio::pin!(future);
        let mut remaining = budget;
        loop {
            let attended = tokio::time::Instant::now();
            tokio::select! {
                biased;
                result = tokio::time::timeout(remaining, &mut future) => return result.ok(),
                query = Self::receive_readiness_query(&mut self.readiness_rx) => {
                    // Time until the query arrived was genuine waiting on the
                    // step; the servicing below is not, so stop the clock.
                    remaining = remaining.saturating_sub(attended.elapsed());
                    match query {
                        Some(query) => self.handle_readiness_query(query).await,
                        None => self.readiness_rx = None,
                    }
                    if remaining.is_zero() {
                        return None;
                    }
                }
                query = Self::receive_operator_query(&mut self.operator_rx, &mut self.deferred_operator_queries), if admission.admits() => {
                    remaining = remaining.saturating_sub(attended.elapsed());
                    match query {
                        Some(query) => Box::pin(self.handle_operator_query(query, true)).await,
                        None => self.operator_rx = None,
                    }
                    if remaining.is_zero() {
                        return None;
                    }
                }
            }
        }
    }

    async fn receive_readiness_query(
        readiness_rx: &mut Option<mpsc::Receiver<PeerManagerReadinessQuery>>,
    ) -> Option<PeerManagerReadinessQuery> {
        match readiness_rx {
            Some(rx) => rx.recv().await,
            None => std::future::pending().await,
        }
    }

    async fn receive_internal_command(
        internal_rx: &mut Option<mpsc::Receiver<InternalCommand>>,
    ) -> Option<InternalCommand> {
        let command = match internal_rx.as_mut() {
            Some(rx) => rx.recv().await,
            None => std::future::pending().await,
        };
        if command.is_none() {
            *internal_rx = None;
            debug!("peer manager internal command channel closed");
        }
        command
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "configured peer construction keeps all explicit lifecycle dependencies visible"
    )]
    pub fn new_with_config(
        rx: mpsc::Receiver<PeerManagerCommand>,
        internal_rx: mpsc::Receiver<InternalCommand>,
        local_asn: u32,
        router_id: Ipv4Addr,
        cluster_id: Option<Ipv4Addr>,
        local_gr_restart_until: Option<Instant>,
        metrics: BgpMetrics,
        rib_tx: mpsc::Sender<RibUpdate>,
        bmp_tx: Option<mpsc::Sender<BmpEvent>>,
        validation_rx: Option<watch::Receiver<rustbgpd_rpki::ValidationSnapshot>>,
        current_config: Config,
    ) -> Self {
        let (session_notify_tx, session_notify_rx) = session_notification_channel(metrics.clone());
        let (session_lifecycle_tx, session_lifecycle_rx) = mpsc::channel(4096);
        let (session_notification_event_tx, session_notification_event_rx) = mpsc::channel(4096);
        let (session_events_tx, _) = broadcast::channel(4096);
        let (policy_events_tx, _) = broadcast::channel(4096);
        // ADR-0110 freshness: constructing the manager is the initial
        // policy apply — stamp the generation and every bound dataset.
        metrics.record_policy_generation_loaded();
        for handle in current_config.policy.dataset_bindings.handles() {
            metrics.record_policy_dataset_loaded(handle.name());
        }
        metrics.set_dynamic_neighbor_capacity(
            0,
            Config::effective_dynamic_neighbor_limit(&current_config),
        );
        Self {
            peers: HashMap::new(),
            max_prefix_latches: HashMap::new(),
            next_max_prefix_restart_deadline: None,
            next_max_prefix_latch_generation: 1,
            retiring_sessions: HashMap::new(),
            session_index: HashMap::new(),
            rx,
            readiness_rx: None,
            operator_rx: None,
            deferred_operator_queries: VecDeque::new(),
            operator_read_seam: OperatorReadSeam::Unfenced,
            completed_operator_seam: None,
            internal_rx: Some(internal_rx),
            local_asn,
            router_id,
            cluster_id,
            local_gr_restart_until,
            metrics,
            rib_tx,
            bmp_tx,
            validation_rx,
            session_notify_tx,
            session_notify_rx,
            session_lifecycle_tx,
            session_lifecycle_rx,
            session_notification_event_tx,
            session_notification_event_rx,
            session_events_tx,
            session_event_history: VecDeque::new(),
            policy_events_tx,
            policy_event_history: VecDeque::new(),
            config_snapshot_staged: false,
            staged_policy_routes_prior: None,
            dynamic_ranges: Self::parse_dynamic_ranges(&current_config),
            dynamic_peer_count: 0,
            dynamic_neighbor_limit: current_config.effective_dynamic_neighbor_limit(),
            inbound_admission: admission::InboundAdmission::from_config(
                &current_config.inbound_admission,
            ),
            dead_lettered_pending: HashMap::new(),
            dead_lettered_pending_order: VecDeque::new(),
            next_session_id: 1,
            tcp_ao_generation: rustbgpd_transport::TcpAoRotationGeneration::STARTUP,
            tcp_ao_rotation: rustbgpd_transport::TcpAoRotationStatus::default(),
            tcp_ao_desired_inventory: None,
            current_config,
            bfd_coupling: None,
            event_history: None,
            transport_event_sink: None,
            snapshot_key: crate::config::RuntimeSnapshotKey::random(),
            accepted_rx: None,
            #[cfg(test)]
            inject_reconfigure_failures: std::collections::BTreeMap::new(),
            #[cfg(all(debug_assertions, not(test)))]
            inject_reconfigure_failures: debug_reconfigure_failures(),
            #[cfg(test)]
            dataset_generations_at_peer_construction: None,
            #[cfg(test)]
            inject_hot_update_failures: std::collections::BTreeMap::new(),
        }
    }

    /// Install the durable event-outbox handle (ADR-0072). Called
    /// once at startup by the daemon binary when `[event_history]
    /// .enabled = true`. With the handle installed, every
    /// `publish_*_event` call additionally encodes the event and
    /// enqueues it for durable cursor replay; the legacy ring +
    /// broadcast surfaces are unchanged.
    #[must_use]
    pub fn with_event_history(
        mut self,
        handle: Option<rustbgpd_event_history::EventHistoryHandle>,
    ) -> Self {
        self.event_history = handle;
        self
    }

    /// Install the out-of-crate transport event sink (ADR-0072
    /// follow-up). Each spawned `PeerHandle` carries this sink so
    /// transport-layer policy events (OTC route-leak decisions) are
    /// published through the durable cursor alongside the existing
    /// counter + per-`NeighborState` scalar. Called at the same
    /// startup site as `with_event_history`.
    #[must_use]
    pub fn with_transport_event_sink(
        mut self,
        sink: Option<std::sync::Arc<dyn rustbgpd_transport::TransportEventSink>>,
    ) -> Self {
        self.transport_event_sink = sink;
        self
    }

    fn allocate_session_id(&mut self) -> u64 {
        let id = self.next_session_id;
        // Session IDs are a stale-notification discriminator, not a durable
        // protocol identifier. Wrapping would require 2^64 session spawns in
        // one process lifetime; skip zero so `SessionIdentity::default()`
        // remains visibly outside the peer-manager allocated range.
        self.next_session_id = self.next_session_id.wrapping_add(1).max(1);
        id
    }

    pub(super) fn refresh_dynamic_neighbor_capacity_metrics(&self) {
        self.metrics
            .set_dynamic_neighbor_capacity(self.dynamic_peer_count, self.dynamic_neighbor_limit);
    }

    pub(super) fn register_session(&mut self, session_id: u64, peer: &PeerKey) {
        self.session_index.insert(session_id, peer.clone());
    }

    pub(super) fn unregister_session(&mut self, session_id: u64) {
        self.session_index.remove(&session_id);
    }

    fn build_transport_config(&self, config: &PeerManagerNeighborConfig) -> TransportConfig {
        let families = if config.families.is_empty() {
            vec![(Afi::Ipv4, Safi::Unicast)]
        } else {
            config.families.clone()
        };
        let mut peer = PeerConfig::new(self.local_asn, config.remote_asn, self.router_id);
        peer.hold_time = config.hold_time.unwrap_or(DEFAULT_HOLD_TIME);
        peer.min_hold_time = config.min_hold_time;
        // RFC 9687 §6 default: greater of 8 minutes or 2× hold time.
        peer.send_hold_time = config
            .send_hold_time
            .unwrap_or_else(|| rustbgpd_fsm::default_send_hold_time(peer.hold_time));
        peer.connect_retry_secs = DEFAULT_CONNECT_RETRY_SECS;
        peer.families = families;
        peer.required_families.clone_from(&config.required_families);
        peer.graceful_restart = config.graceful_restart;
        peer.gr_restart_time = config.gr_restart_time;
        peer.llgr_stale_time = config.llgr_stale_time;
        peer.add_path_receive = config.add_path_receive;
        peer.add_path_send = config.add_path_send;
        peer.add_path_send_max = config.add_path_send_max;
        peer.paths_limit_receive_max = config.paths_limit_receive_max;
        peer.local_role = config.local_role;
        peer.strict_role = config.strict_role;
        peer.prefix_orf_receive = config.prefix_orf_receive;
        peer.disable_ipv4_unicast = config.disable_ipv4_unicast;
        let scope_id = config.scope_id.or_else(|| {
            config
                .interface
                .as_ref()
                .and_then(|interface| nix::net::if_::if_nametoindex(interface.as_str()).ok())
        });
        let remote_addr = match (config.address, scope_id) {
            (IpAddr::V6(v6), Some(scope_id)) => {
                SocketAddr::V6(std::net::SocketAddrV6::new(v6, BGP_PORT, 0, scope_id))
            }
            _ => SocketAddr::new(config.address, BGP_PORT),
        };
        let mut transport = TransportConfig::new(peer, remote_addr);
        transport.local_address = self.current_config.active_source_for(config.address);
        transport.peer_interface.clone_from(&config.interface);
        transport.peer_scope_id = scope_id;
        transport.max_prefixes = config.max_prefixes;
        transport.max_prefixes_ipv4 = config.max_prefixes_ipv4;
        transport.max_prefixes_ipv6 = config.max_prefixes_ipv6;
        transport.max_prefixes_received_ipv4 = config.max_prefixes_received_ipv4;
        transport.max_prefixes_received_ipv6 = config.max_prefixes_received_ipv6;
        transport.max_prefix_action = config.max_prefix_action;
        transport.max_prefix_warning_percent = config.max_prefix_warning_percent;
        transport.peer_group.clone_from(&config.peer_group);
        transport.md5_password.clone_from(&config.md5_password);
        transport.tcp_ao.clone_from(&config.tcp_ao);
        transport.tcp_mss = config.tcp_mss;
        transport.ttl_security_hops = config.ttl_security_hops;
        transport.local_ipv6_nexthop = config.local_ipv6_nexthop;
        transport.gr_stale_routes_time = config.gr_stale_routes_time;
        transport.gr_peer_restart_time_max = config.gr_peer_restart_time_max;
        transport.llgr_stale_time = config.llgr_stale_time;
        transport.gr_restart_until = if config.gr_restart_eligible && config.graceful_restart {
            self.local_gr_restart_until
                .filter(|deadline| *deadline > Instant::now())
        } else {
            None
        };
        transport.route_reflector_client = config.route_reflector_client;
        transport.orr_vantage = config.orr_vantage;
        transport.route_server_client = config.route_server_client;
        transport.send_non_transitive_extended_communities =
            config.send_non_transitive_extended_communities;
        // RFC 7947 §2.3.2 / ADR-0101: without this line the knob
        // parses, validates, and reloads — and every session still
        // registers single-best (caught by M83; the RIB/CLI unit
        // layers are wired above this seam and never saw it).
        transport.per_client_best = config.per_client_best;
        // ADR-0107: same threading class as per_client_best — without
        // this line the knob parses, validates, and reloads while every
        // session imports unguarded (pinned by the field-threading test).
        transport.next_hop_ownership_strict_peer = config.next_hop_ownership_strict_peer;
        // Slow-peer knobs are resolved values; both transport-construction
        // paths must thread them (ADR-0073 note in config/mod.rs).
        transport.slow_peer_threshold_pct = config.slow_peer_threshold_pct;
        transport.slow_peer_duration = config.slow_peer_duration;
        transport.slow_peer_isolation = config.slow_peer_isolation;
        // RFC 1997: resolved in config (default !route_server_client);
        // pinned by the build_transport_config field-threading test.
        transport.interpret_rfc1997 = config.interpret_rfc1997;
        // RFC 7947 §2.3.2: resolved in config (default
        // route_server_client); same field-threading hazard as the
        // knobs above — without this line control communities are
        // parsed and validated but never enforced.
        transport.rs_control_communities = config.rs_control_communities;
        transport.remove_private_as = config.remove_private_as;
        transport.discard_path_attributes = config.discard_path_attributes.clone();
        transport.cluster_id = self.cluster_id;
        transport.max_as_path_length = self.current_config.global.max_as_path_length;
        // ADR-0073: per-session import-decision explain cache wiring.
        // Both the enable flag and the capacity must be threaded — a
        // missing `explain_enabled` here would silently leave the
        // write-path gate at its `true` default regardless of config.
        transport.explain_enabled = self.current_config.policy.explain.enabled;
        transport.explain_cache_size = self.current_config.policy.explain.cache_size;
        // LAN-472: rejected-route retention wiring — same threading
        // hazard as the explain knobs above.
        transport.reject_retention_enabled = self.current_config.policy.reject_retention.enabled;
        transport.reject_retention_capacity = self.current_config.policy.reject_retention.capacity;
        // RFC 8671: tap outbound UPDATEs for BMP only when some collector
        // actually monitors the post-policy Adj-RIB-Out stream ([bmp]
        // changes require a restart, so read-at-construction is
        // authoritative for the session's lifetime).
        transport.bmp_rib_out = self.current_config.bmp.as_ref().is_some_and(|bmp| {
            bmp.collectors.iter().any(|c| {
                c.monitor
                    .contains(&crate::config::BmpMonitorView::RibOutPost)
            })
        });
        transport
    }

    pub(super) fn unique_peer_key_for_address(&self, address: IpAddr) -> Option<PeerKey> {
        let mut matches = self.peers.keys().filter(|key| key.address == address);
        let first = matches.next()?.clone();
        matches.next().is_none().then_some(first)
    }

    pub(super) fn peer_keys_for_address(&self, address: IpAddr) -> Vec<PeerKey> {
        self.peers
            .keys()
            .filter(|key| key.address == address)
            .cloned()
            .collect()
    }

    pub(super) fn peer_key_for_session(&self, session_id: u64) -> Option<PeerKey> {
        self.session_index.get(&session_id).cloned()
    }

    /// Run the `PeerManager` event loop until shutdown or channel close.
    #[expect(
        clippy::too_many_lines,
        reason = "peer manager run loop centralizes command, notification, and reload orchestration"
    )]
    pub async fn run(mut self) {
        let mut bmp_stats_interval = self.bmp_tx.as_ref().map(|_| {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(BMP_STATS_INTERVAL_SECS));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval
        });
        // Consume the immediate first tick so the first report is emitted
        // after one full interval.
        if let Some(interval) = bmp_stats_interval.as_mut() {
            interval.tick().await;
        }

        // Take the BFD state-change receiver into a local so the select! arm
        // captures the local (not `self`), and publish the initial desired set
        // (the configured set overlaid with the disabled/deleted set — empty at
        // startup, so every configured peer starts enabled).
        let mut bfd_state_change_rx = self.take_bfd_state_change_rx();
        if bfd_state_change_rx.is_some() {
            self.republish_bfd_desired();
        }

        loop {
            let max_prefix_restart_deadline = self.next_max_prefix_restart_deadline;
            tokio::select! {
                query = Self::receive_readiness_query(&mut self.readiness_rx) => {
                    match query {
                        Some(PeerManagerReadinessQuery::ListPeers { reply }) => {
                            self.answer_normal_operator_query(PeerManagerOperatorQuery::ListPeers { reply }).await;
                        }
                        Some(query) => self.handle_readiness_query(query).await,
                        None => self.readiness_rx = None,
                    }
                }
                query = Self::receive_operator_query(&mut self.operator_rx, &mut self.deferred_operator_queries) => {
                    match query {
                        Some(query) => self.handle_operator_query(query, false).await,
                        None => self.operator_rx = None,
                    }
                }
                cmd = self.rx.recv() => {
                    let Some(cmd) = cmd else {
                        debug!("peer manager channel closed");
                        return;
                    };
                    self.operator_read_seam = OperatorReadSeam::Unfenced;
                    match cmd {
                        PeerManagerCommand::Ping { reply } => {
                            let _ = reply.send(());
                        }
                        PeerManagerCommand::AddPeer { config, sync_config_snapshot, reply } => {
                            let result = self.add_peer(config, sync_config_snapshot).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::RuntimeCreatePeer { spec, reply } => {
                            let result = self.runtime_create_peer(spec).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::DeletePeer { peer, sync_config_snapshot, reply } => {
                            let result = self.delete_peer_runtime(peer, sync_config_snapshot).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::OwnedNeighborMutation { mutation, reply } => {
                            // Static delete and both dynamic operations validate
                            // before effect; static add reports cleanup explicitly.
                            let outcome = match mutation {
                                OwnedNeighborMutation::Add(spec) => {
                                    let mut effect =
                                        lifecycle::RuntimeCreatePeerFailureEffect::NoEffect;
                                    match self
                                        .runtime_create_peer_classified(spec, Some(&mut effect))
                                        .await
                                    {
                                        Ok(()) => OwnedNeighborMutationOutcome::Success,
                                        Err(error) => match effect {
                                            lifecycle::RuntimeCreatePeerFailureEffect::NoEffect => {
                                                OwnedNeighborMutationOutcome::RejectedNoEffect(
                                                    OwnedNeighborMutationError::Peer(error),
                                                )
                                            }
                                            lifecycle::RuntimeCreatePeerFailureEffect::FullyCompensated => {
                                                OwnedNeighborMutationOutcome::FullyCompensated(
                                                    OwnedNeighborMutationError::Peer(error),
                                                )
                                            }
                                        },
                                    }
                                }
                                OwnedNeighborMutation::Delete(peer) => {
                                    match self.delete_peer_runtime(peer, true).await {
                                        Ok(_) => OwnedNeighborMutationOutcome::Success,
                                        Err(error) => OwnedNeighborMutationOutcome::RejectedNoEffect(
                                            OwnedNeighborMutationError::Peer(error),
                                        ),
                                    }
                                }
                                OwnedNeighborMutation::DynamicAdd {
                                    prefix,
                                    peer_group,
                                    remote_asn,
                                    description,
                                } => match self.add_dynamic_range(
                                        prefix,
                                        peer_group,
                                        remote_asn,
                                        description,
                                    ) {
                                        Ok(()) => OwnedNeighborMutationOutcome::Success,
                                        Err(error) => OwnedNeighborMutationOutcome::RejectedNoEffect(
                                            OwnedNeighborMutationError::Dynamic(error),
                                        ),
                                    },
                                OwnedNeighborMutation::DynamicDelete { prefix } => {
                                    match self.delete_dynamic_range(&prefix) {
                                        Ok(_) => OwnedNeighborMutationOutcome::Success,
                                        Err(error) => OwnedNeighborMutationOutcome::RejectedNoEffect(
                                            OwnedNeighborMutationError::Dynamic(error),
                                        ),
                                    }
                                }
                            };
                            let _ = reply.send(outcome);
                        }
                        PeerManagerCommand::OwnedCatalogMutation { mutation, reply } => {
                            let policy_routes_prior =
                                self.installed_policy_routes_reachability();
                            let outcome = match mutation {
                                OwnedCatalogMutation::SetPeerGroup { name, definition } => {
                                    let event = ConfigEvent::SetPeerGroup {
                                        name: name.clone(),
                                        definition: (*definition).clone(),
                                        ack: None,
                                    };
                                    if self.peer_group_policy_only_update(&name, &definition) {
                                        self.apply_policy_change_owned(event, None).await
                                    } else {
                                        let affected: Vec<IpAddr> = self.current_config
                                            .neighbors
                                            .iter()
                                            .filter(|neighbor| neighbor.peer_group.as_deref() == Some(name.as_str()))
                                            .filter_map(|neighbor| neighbor.address.parse().ok())
                                            .collect();
                                        self.apply_peer_group_change_owned(event, affected).await
                                    }
                                }
                                OwnedCatalogMutation::SyncRpolPolicies {
                                    rpol_files,
                                    rpol,
                                    dataset_bindings,
                                } => self
                                    .sync_rpol_policies_owned(rpol_files, rpol, dataset_bindings)
                                    .await,
                                OwnedCatalogMutation::DeletePeerGroup { name } => {
                                    self.apply_peer_group_change_owned(
                                        ConfigEvent::DeletePeerGroup { name, ack: None },
                                        Vec::new(),
                                    ).await
                                }
                                OwnedCatalogMutation::SetNeighborPeerGroup { address, peer_group } => {
                                    self.apply_peer_group_change_owned(
                                        ConfigEvent::SetNeighborPeerGroup { address, peer_group, ack: None },
                                        vec![address],
                                    ).await
                                }
                                OwnedCatalogMutation::ClearNeighborPeerGroup { address } => {
                                    self.apply_peer_group_change_owned(
                                        ConfigEvent::ClearNeighborPeerGroup { address, ack: None },
                                        vec![address],
                                    ).await
                                }
                                OwnedCatalogMutation::SetPolicy { name, definition } => {
                                    self.apply_policy_change_owned(
                                        ConfigEvent::SetPolicy {
                                            name,
                                            definition: *definition,
                                            ack: None,
                                        },
                                        None,
                                    ).await
                                }
                                OwnedCatalogMutation::DeletePolicy { name } => {
                                    self.apply_policy_change_owned(
                                        ConfigEvent::DeletePolicy { name, ack: None },
                                        None,
                                    ).await
                                }
                                OwnedCatalogMutation::SetNeighborSet { name, definition } => {
                                    self.apply_policy_change_owned(
                                        ConfigEvent::SetNeighborSet { name, definition, ack: None },
                                        None,
                                    ).await
                                }
                                OwnedCatalogMutation::DeleteNeighborSet { name } => {
                                    self.apply_policy_change_owned(
                                        ConfigEvent::DeleteNeighborSet { name, ack: None },
                                        None,
                                    ).await
                                }
                                OwnedCatalogMutation::SetGlobalImportChain { policy_names } => {
                                    self.apply_policy_change_owned(
                                        ConfigEvent::SetGlobalImportChain { policy_names, ack: None },
                                        None,
                                    ).await
                                }
                                OwnedCatalogMutation::SetGlobalExportChain { policy_names } => {
                                    self.apply_policy_change_owned(
                                        ConfigEvent::SetGlobalExportChain { policy_names, ack: None },
                                        None,
                                    ).await
                                }
                                OwnedCatalogMutation::ClearGlobalImportChain => {
                                    self.apply_policy_change_owned(
                                        ConfigEvent::ClearGlobalImportChain { ack: None },
                                        None,
                                    ).await
                                }
                                OwnedCatalogMutation::ClearGlobalExportChain => {
                                    self.apply_policy_change_owned(
                                        ConfigEvent::ClearGlobalExportChain { ack: None },
                                        None,
                                    ).await
                                }
                                OwnedCatalogMutation::SetNeighborImportChain { address, policy_names } => {
                                    self.apply_policy_change_owned(
                                        ConfigEvent::SetNeighborImportChain { address, policy_names, ack: None },
                                        Some(vec![address]),
                                    ).await
                                }
                                OwnedCatalogMutation::SetNeighborExportChain { address, policy_names } => {
                                    self.apply_policy_change_owned(
                                        ConfigEvent::SetNeighborExportChain { address, policy_names, ack: None },
                                        Some(vec![address]),
                                    ).await
                                }
                                OwnedCatalogMutation::ClearNeighborImportChain { address } => {
                                    self.apply_policy_change_owned(
                                        ConfigEvent::ClearNeighborImportChain { address, ack: None },
                                        Some(vec![address]),
                                    ).await
                                }
                                OwnedCatalogMutation::ClearNeighborExportChain { address } => {
                                    self.apply_policy_change_owned(
                                        ConfigEvent::ClearNeighborExportChain { address, ack: None },
                                        Some(vec![address]),
                                    ).await
                                }
                            };
                            if matches!(&outcome, OwnedCatalogMutationOutcome::Success) {
                                self.reap_retired_policy_routes(&policy_routes_prior);
                            }
                            let _ = reply.send(outcome);
                        }
                        PeerManagerCommand::ReconfigurePeer { config, reply } => {
                            let result = self.reconfigure_peer_runtime(config).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::ListPeers { reply } => {
                            self.answer_normal_operator_query(PeerManagerOperatorQuery::ListPeers { reply }).await;
                        }
                        PeerManagerCommand::QueryWarmCheckpointCapture { reply } => {
                            self.answer_warm_checkpoint_capture(reply).await;
                        }
                        PeerManagerCommand::SubscribeSessionEvents { reply } => {
                            let _ = reply.send(self.session_events_tx.subscribe());
                        }
                        PeerManagerCommand::SubscribePolicyEvents { reply } => {
                            let _ = reply.send(self.policy_events_tx.subscribe());
                        }
                        PeerManagerCommand::QueryPolicyEventHistory { peer, limit, reply } => {
                            self.handle_query_policy_event_history(peer, limit, reply);
                        }
                        PeerManagerCommand::QuerySessionEventHistory {
                            peer,
                            event_types,
                            limit,
                            reply,
                        } => {
                            self.handle_query_session_event_history(
                                peer,
                                &event_types,
                                limit,
                                reply,
                            );
                        }
                        PeerManagerCommand::DiffRuntimeConfig { candidate_toml, reply } => {
                            let result = self.diff_runtime_config(&candidate_toml);
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::PlanConfigTransaction {
                            candidate_toml,
                            expected_runtime_snapshot_token,
                            verify_external_inputs,
                            mut reply,
                        } => {
                            let planning = self.plan_config_transaction(
                                &candidate_toml,
                                expected_runtime_snapshot_token.as_deref(),
                                verify_external_inputs,
                            );
                            tokio::pin!(planning);
                            let result = tokio::select! {
                                biased;
                                () = reply.closed() => continue,
                                result = &mut planning => result,
                            };
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::CommitConfigSnapshotStage { reply } => {
                            if let Some(prior) = self.staged_policy_routes_prior.take() {
                                self.reap_retired_policy_routes(&prior);
                            }
                            self.config_snapshot_staged = false;
                            let _ = reply.send(());
                        }
                        PeerManagerCommand::RuntimeConfigSnapshot { reply } => {
                            let result = raw_config_document_bounded(&mut self.current_config)
                                .map_err(|error| {
                                    format!(
                                        "failed to serialize runtime config snapshot: {error}"
                                    )
                                })
                                .map(|toml| {
                                    rustbgpd_api::peer_types::RuntimeConfigSnapshotReply {
                                        toml,
                                        rpol_files: self.current_config.policy.rpol_files.clone(),
                                        rpol: self.current_config.policy.rpol.clone(),
                                    }
                                });
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::EffectiveRuntimeConfig { reply } => {
                            let _ = reply.send(self.current_config.effective_redacted_toml());
                        }
                        PeerManagerCommand::ApplyResolvedPolicySnapshot { targets, reply } => {
                            let result = self.apply_resolved_policy_snapshot(targets).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::ApplyPolicyImpactSnapshot {
                            static_targets,
                            dynamic_ranges,
                            reply,
                        } => {
                            let result = self
                                .apply_policy_impact_snapshot(static_targets, dynamic_ranges)
                                .await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::ApplyPeerReshapeSnapshot { targets, reply } => {
                            let result = self.apply_peer_reshape_snapshot(targets).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::BounceDynamicRangePeers {
                            ranges,
                            purge_ranges,
                            reply,
                        } => {
                            let outcome = self
                                .bounce_dynamic_peers_for_ranges(&ranges, &purge_ranges)
                                .await;
                            let _ = reply.send(outcome);
                        }
                        PeerManagerCommand::StageFibTables { tables, reply } => {
                            let result = self.stage_fib_tables_candidate(&tables);
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::SetFibTablesSnapshot { tables, reply } => {
                            self.set_fib_tables_snapshot(&tables);
                            let _ = reply.send(());
                        }
                        PeerManagerCommand::ApplyConfigEvent { event, reply } => {
                            let result = apply_config_event(&mut self.current_config, &event)
                                .map_err(|error| error.to_string());
                            if result.is_ok() {
                                self.reconcile_stale_dynamic_max_prefix_restarts();
                            }
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::GetPeerState { peer, reply } => {
                            self.answer_normal_operator_query(PeerManagerOperatorQuery::GetPeerState { peer, reply }).await;
                        }
                        PeerManagerCommand::HasPeerAddress { address, reply } => {
                            let _ = reply.send(self.unique_peer_key_for_address(address).is_some());
                        }
                        PeerManagerCommand::EnablePeer { peer, reply } => {
                            let result = self.enable_peer(peer).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::DisablePeer { peer, reason, reply } => {
                            let result = self.disable_peer(peer, reason).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::ResetPeer { peer, reason, reply } => {
                            let result = self.reset_peer(peer, reason).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::SoftResetIn { peer, families, reply } => {
                            let result = self.soft_reset_in(peer, families).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::RefreshOutbound { peer, reply } => {
                            let result = self.refresh_outbound(peer).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::ReplayOutbound { peer, reply } => {
                            self.replay_outbound(peer, reply).await;
                        }
                        PeerManagerCommand::SoftResetImportValidationDependents {
                            dependency,
                            reply,
                        } => {
                            let result =
                                self.soft_reset_import_validation_dependents(dependency).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::SetGracefulShutdown { peer, enabled, reply } => {
                            let result = self.set_graceful_shutdown(peer, enabled).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::AcceptInbound { stream, peer_addr, tcp_ao_info, tcp_ao_generation } => {
                            self.accept_inbound(stream, peer_addr, tcp_ao_info, tcp_ao_generation).await;
                        }
                        PeerManagerCommand::ApplyTcpAoRotation { generation, operation, listener_keys, current_listener_keys, static_keyrings, current_static_keyrings, reply } => {
                            let result = self.apply_tcp_ao_rotation(generation, operation, &listener_keys, &current_listener_keys, &static_keyrings, &current_static_keyrings).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::PreflightTcpAoRotation { generation, operation, listener_keys, current_listener_keys, static_keyrings, current_static_keyrings, reply } => {
                            let result = self.preflight_tcp_ao_rotation(generation, operation, &listener_keys, &current_listener_keys, &static_keyrings, &current_static_keyrings).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::MarkTcpAoRotationFailed { generation, operation, error, reply } => {
                            self.mark_tcp_ao_rotation_failed(generation, operation, &error);
                            let _ = reply.send(Ok(()));
                        }
                        PeerManagerCommand::ReconcilePeers { added, removed, changed, reply } => {
                            let policy_routes_prior =
                                self.installed_policy_routes_reachability();
                            let result = self.reconcile_peers(added, removed, changed).await;
                            if result.authority == PeerReconcileAuthority::Known
                                && result.failures.is_empty()
                            {
                                self.reap_retired_policy_routes(&policy_routes_prior);
                            }
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::HotUpdatePeer { config, reply } => {
                            let policy_routes_prior =
                                self.installed_policy_routes_reachability();
                            let outcome = self.hot_update_peer_owned(config).await;
                            if matches!(&outcome, OwnedHotUpdatePeerOutcome::Success) {
                                self.reap_retired_policy_routes(&policy_routes_prior);
                            }
                            let _ = reply.send(outcome);
                        }
                        PeerManagerCommand::SyncExplainConfig {
                            enabled,
                            cache_size,
                            reject_retention_enabled,
                            reject_retention_capacity,
                            reply,
                        } => {
                            // ADR-0073 / LAN-472: make the diagnostic-retention
                            // snapshot fresh before any subsequent
                            // reconcile/peer-group command on this FIFO channel
                            // constructs a session via build_transport_config.
                            self.current_config.policy.explain.enabled = enabled;
                            self.current_config.policy.explain.cache_size = cache_size;
                            self.current_config.policy.reject_retention.enabled =
                                reject_retention_enabled;
                            self.current_config.policy.reject_retention.capacity =
                                reject_retention_capacity;
                            let _ = reply.send(());
                        }
                        PeerManagerCommand::RefreshDatasetDependents { swapped, failed, reply } => {
                            let result = self.refresh_dataset_dependents(&swapped, &failed).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::QueryPolicyDatasets { reply } => {
                            let _ = reply.send(self.policy_dataset_status_rows());
                        }
                        PeerManagerCommand::ListPolicies { reply } => {
                            let _ = reply.send(named_policies_from_config(&self.current_config));
                        }
                        PeerManagerCommand::GetValidationPolicyPosture { reply } => {
                            let _ = reply.send(self.validation_policy_posture());
                        }
                        PeerManagerCommand::ExplainImportPolicy {
                            address, afi, safi, prefix, path_id, reply,
                        } => {
                            // Resolve the unique session for this address and
                            // forward to its task. A missing/exited task is a
                            // genuine no-session result; timeout remains
                            // distinct so overload cannot masquerade as
                            // absence (LAN-661).
                            let result = match self
                                .unique_peer_key_for_address(address)
                                .and_then(|key| self.peers.get(&key))
                            {
                                Some(managed) => {
                                    managed
                                        .handle
                                        .explain_import_policy_timeout(
                                            afi, safi, prefix, path_id, EXPLAIN_QUERY_TIMEOUT,
                                        )
                                        .await
                                }
                                None => SessionQueryOutcome::SessionGone,
                            };
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::ListRejectedRoutes { address, reply } => {
                            // LAN-472: same resolution + bounded-forward
                            // shape as ExplainImportPolicy. A missing/exited
                            // session maps to NOT_FOUND, while a stalled live
                            // task remains an explicit timeout.
                            let result = match self
                                .unique_peer_key_for_address(address)
                                .and_then(|key| self.peers.get(&key))
                            {
                                Some(managed) => {
                                    managed
                                        .handle
                                        .list_rejected_routes_timeout(EXPLAIN_QUERY_TIMEOUT)
                                        .await
                                }
                                None => SessionQueryOutcome::SessionGone,
                            };
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::QueryImportPolicyTermHits { peer, deadline, reply } => {
                            self.dispatch_import_policy_term_hits(peer, deadline, reply);
                        }
                        PeerManagerCommand::GetPolicy { name, reply } => {
                            let _ = reply.send(named_policy_from_config(&self.current_config, &name));
                        }
                        PeerManagerCommand::SetPolicy { name, definition, reply } => {
                            let result = self.apply_policy_change(
                                ConfigEvent::SetPolicy { name, definition, ack: None },
                                None,
                            ).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::DeletePolicy { name, reply } => {
                            let result = self.apply_policy_change(
                                ConfigEvent::DeletePolicy { name, ack: None },
                                None,
                            ).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::ListNeighborSets { reply } => {
                            let _ = reply.send(named_neighbor_sets_from_config(&self.current_config));
                        }
                        PeerManagerCommand::GetNeighborSet { name, reply } => {
                            let _ = reply.send(named_neighbor_set_from_config(&self.current_config, &name));
                        }
                        PeerManagerCommand::SetNeighborSet { name, definition, reply } => {
                            let result = self.apply_policy_change(
                                ConfigEvent::SetNeighborSet { name, definition, ack: None },
                                None,
                            ).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::DeleteNeighborSet { name, reply } => {
                            let result = self.apply_policy_change(
                                ConfigEvent::DeleteNeighborSet { name, ack: None },
                                None,
                            ).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::GetGlobalPolicyChains { reply } => {
                            let _ = reply.send(global_policy_chains_from_config(&self.current_config));
                        }
                        PeerManagerCommand::SetGlobalImportChain { policy_names, reply } => {
                            let result = self.apply_policy_change(
                                ConfigEvent::SetGlobalImportChain { policy_names, ack: None },
                                None,
                            ).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::SetGlobalExportChain { policy_names, reply } => {
                            let result = self.apply_policy_change(
                                ConfigEvent::SetGlobalExportChain { policy_names, ack: None },
                                None,
                            ).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::ClearGlobalImportChain { reply } => {
                            let result = self.apply_policy_change(
                                ConfigEvent::ClearGlobalImportChain { ack: None },
                                None,
                            ).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::ClearGlobalExportChain { reply } => {
                            let result = self.apply_policy_change(
                                ConfigEvent::ClearGlobalExportChain { ack: None },
                                None,
                            ).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::SetHonorGracefulShutdown { enabled, reply } => {
                            let policy_routes_prior =
                                self.installed_policy_routes_reachability();
                            let result = self.set_honor_graceful_shutdown(enabled).await;
                            if result.is_ok() {
                                self.reap_retired_policy_routes(&policy_routes_prior);
                            }
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::SetHonorBlackhole { enabled, reply } => {
                            let policy_routes_prior =
                                self.installed_policy_routes_reachability();
                            let result = self.set_honor_blackhole(enabled).await;
                            if result.is_ok() {
                                self.reap_retired_policy_routes(&policy_routes_prior);
                            }
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::GetNeighborPolicyChains { address, reply } => {
                            let _ = reply.send(neighbor_policy_chains_from_config(&self.current_config, address));
                        }
                        PeerManagerCommand::SetNeighborImportChain { address, policy_names, reply } => {
                            let result = self.apply_policy_change(
                                ConfigEvent::SetNeighborImportChain { address, policy_names, ack: None },
                                Some(vec![address]),
                            ).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::SetNeighborExportChain { address, policy_names, reply } => {
                            let result = self.apply_policy_change(
                                ConfigEvent::SetNeighborExportChain { address, policy_names, ack: None },
                                Some(vec![address]),
                            ).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::ClearNeighborImportChain { address, reply } => {
                            let result = self.apply_policy_change(
                                ConfigEvent::ClearNeighborImportChain { address, ack: None },
                                Some(vec![address]),
                            ).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::ClearNeighborExportChain { address, reply } => {
                            let result = self.apply_policy_change(
                                ConfigEvent::ClearNeighborExportChain { address, ack: None },
                                Some(vec![address]),
                            ).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::ListPeerGroups { reply } => {
                            let _ = reply.send(named_peer_groups_from_config(&self.current_config));
                        }
                        PeerManagerCommand::GetPeerGroup { name, reply } => {
                            let _ = reply.send(named_peer_group_from_config(&self.current_config, &name));
                        }
                        PeerManagerCommand::SetPeerGroup { name, definition, reply } => {
                            let event = ConfigEvent::SetPeerGroup { name: name.clone(), definition: definition.clone(), ack: None };
                            let result = if self.peer_group_policy_only_update(&name, &definition) {
                                self.apply_policy_change(event, None).await
                            } else {
                                let affected: Vec<IpAddr> = self.current_config
                                    .neighbors
                                    .iter()
                                    .filter(|neighbor| neighbor.peer_group.as_deref() == Some(name.as_str()))
                                    .filter_map(|neighbor| neighbor.address.parse().ok())
                                    .collect();
                                self.apply_peer_group_change(event, affected).await
                            };
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::DeletePeerGroup { name, reply } => {
                            let result = self.apply_peer_group_change(
                                ConfigEvent::DeletePeerGroup { name, ack: None },
                                Vec::new(),
                            ).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::SetNeighborPeerGroup { address, peer_group, reply } => {
                            let result = self.apply_peer_group_change(
                                ConfigEvent::SetNeighborPeerGroup { address, peer_group, ack: None },
                                vec![address],
                            ).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::ClearNeighborPeerGroup { address, reply } => {
                            let result = self.apply_peer_group_change(
                                ConfigEvent::ClearNeighborPeerGroup { address, ack: None },
                                vec![address],
                            ).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::GetNeighborPeerGroupMembership { address, reply } => {
                            let _ = reply.send(neighbor_peer_group_from_config(&self.current_config, address));
                        }
                        PeerManagerCommand::ListDynamicRanges { reply } => {
                            let ranges = self.dynamic_ranges.iter().map(|r| {
                                DynamicNeighborInfo {
                                    prefix: format!("{}/{}", r.addr, r.prefix_len),
                                    peer_group: r.peer_group.clone(),
                                    remote_asn: r.remote_asn,
                                    description: r.description.clone().unwrap_or_default(),
                                }
                            }).collect();
                            let _ = reply.send(ranges);
                        }
                        PeerManagerCommand::AddDynamicRange {
                            prefix,
                            peer_group,
                            remote_asn,
                            description,
                            reply,
                        } => {
                            let result = self
                                .add_dynamic_range(prefix, peer_group, remote_asn, description);
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::DeleteDynamicRange { prefix, reply } => {
                            let result = self.delete_dynamic_range(&prefix).map(|cfg| {
                                rustbgpd_api::peer_types::RemovedDynamicRange {
                                    prefix: cfg.prefix,
                                    peer_group: cfg.peer_group,
                                    remote_asn: cfg.remote_asn,
                                    description: cfg.description,
                                }
                            });
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::Shutdown => {
                            info!("peer manager shutting down {} peers", self.peers.len());
                            let drained: Vec<_> = self.peers.drain().collect();
                            let mut shutdowns = JoinSet::new();
                            for (addr, mut managed) in drained {
                                if shutdowns.len() == PEER_SHUTDOWN_CONCURRENCY
                                    && let Some(Err(error)) = shutdowns.join_next().await
                                {
                                    error!(%error, "peer shutdown worker failed");
                                }
                                shutdowns.spawn(async move {
                                    debug!(%addr, "shutting down peer");
                                    if let Some(pending) = managed.pending_inbound.take() {
                                        let _ = Self::shutdown_handle_bounded_owned(
                                            addr.address,
                                            "PeerManager shutdown pending inbound",
                                            pending.handle,
                                        )
                                        .await;
                                    }
                                    if Self::shutdown_handle_bounded_owned(
                                        addr.address,
                                        "PeerManager shutdown primary",
                                        managed.handle,
                                    )
                                    .await
                                    .joined()
                                    {
                                        debug!(%addr, "peer shut down");
                                    }
                                });
                            }
                            while let Some(result) = shutdowns.join_next().await {
                                if let Err(error) = result {
                                    error!(%error, "peer shutdown worker failed");
                                }
                            }
                            return;
                        }
                    }
                    self.finish_operator_seam();
                }
                internal = Self::receive_internal_command(&mut self.internal_rx) => {
                    self.operator_read_seam = OperatorReadSeam::Unfenced;
                    match internal {
                        Some(InternalCommand::ApplyReloadGeneration { candidate, actions, datasets, reply }) => {
                            let policy_routes_prior =
                                self.installed_policy_routes_reachability();
                            let outcome =
                                Box::pin(self.apply_reload_generation(*candidate, actions, datasets)).await;
                            if matches!(outcome, ReloadGenerationOutcome::Applied(_)) {
                                self.reap_retired_policy_routes(&policy_routes_prior);
                            }
                            let _ = reply.send(outcome);
                        }
                        Some(InternalCommand::ReplaceConfigSnapshot { config, ack }) => {
                            self.current_config = *config;
                            self.config_snapshot_staged = false;
                            self.staged_policy_routes_prior = None;
                        // #338: rebuild the live dynamic-neighbor accept-matcher so
                        // [[dynamic_neighbors]] edits applied via SIGHUP take effect
                        // (previously only `current_config` was swapped). The shared
                        // runtime-config lock guarantees the reloaded config already
                        // reflects any accepted runtime CRUD, so a plain re-parse is
                        // correct — no merge/provenance needed.
                        self.dynamic_ranges = Self::parse_dynamic_ranges(&self.current_config);
                        self.reconcile_stale_dynamic_max_prefix_restarts();
                        // ADR-0110 freshness: every successful reload flows
                        // through this snapshot replacement — stamp the
                        // generation even when policy content is unchanged
                        // (the daemon re-accepted the artifacts). A rejected
                        // reload aborts before this command is ever sent.
                        self.metrics.record_policy_generation_loaded();
                            if let Some(ack) = ack {
                                let _ = ack.send(());
                            }
                        }
                        Some(InternalCommand::PlanAcceptedTransactionConfig {
                            snapshot,
                            expected_runtime_snapshot_token,
                            reply,
                        }) => {
                            let mut candidate = snapshot.config();
                            // A retained/prior snapshot carries its own
                            // captured external-source manifest; seed the
                            // candidate's identity from it so the ADR-0130
                            // verification compares that capture against the
                            // current accepted authority.
                            candidate.policy.external_sources_digest =
                                crate::config::ExternalSourcesDigest(Some(
                                    snapshot.source_manifest().external_sources_sha256(),
                                ));
                            let result = self
                                .plan_preloaded_config_transaction(
                                    &mut candidate,
                                    expected_runtime_snapshot_token.as_deref(),
                                )
                                .await
                                .map(|plan| PlannedTransactionConfig {
                                    plan,
                                    candidate: Box::new(candidate),
                                });
                            let _ = reply.send(result);
                        }
                        Some(InternalCommand::PlanTransactionConfig {
                            mut candidate,
                            expected_runtime_snapshot_token,
                            reply,
                        }) => {
                            let result = self
                                .plan_preloaded_config_transaction(
                                    &mut candidate,
                                    expected_runtime_snapshot_token.as_deref(),
                                )
                                .await
                                .map(|plan| PlannedTransactionConfig { plan, candidate });
                            let _ = reply.send(result);
                        }
                        Some(InternalCommand::StageTransactionConfig {
                            candidate,
                            scope,
                            reply,
                        }) => {
                            self.staged_policy_routes_prior = None;
                            let policy_routes_prior =
                                self.installed_policy_routes_reachability();
                            let result = match scope {
                                TransactionConfigScope::Full => Ok(*candidate),
                                TransactionConfigScope::FibTablesOnly => {
                                    let mut staged = self.current_config.clone();
                                    staged.fib_tables.clone_from(&candidate.fib_tables);
                                    staged.config_epoch = candidate.config_epoch;
                                    staged.global.ebgp_requires_policy =
                                        candidate.global.ebgp_requires_policy;
                                    staged
                                        .validate()
                                        .map_err(|error| error.to_string())
                                        .map(|()| staged)
                                }
                            }
                            .map(|staged| {
                                    let previous = std::mem::replace(
                                        &mut self.current_config,
                                        staged,
                                    );
                                    self.dynamic_ranges =
                                        Self::parse_dynamic_ranges(&self.current_config);
                                    self.reconcile_stale_dynamic_max_prefix_restarts();
                                    self.config_snapshot_staged = true;
                                    self.staged_policy_routes_prior = Some(policy_routes_prior);
                                    self.metrics.record_policy_generation_loaded();
                                    TransactionConfigRollbackToken::capture(
                                        Box::new(previous),
                                        scope,
                                    )
                                });
                            let _ = reply.send(result);
                        }
                        Some(InternalCommand::RestoreTransactionConfig {
                            rollback,
                            reply,
                        }) => {
                            self.current_config = *rollback.previous;
                            self.dynamic_ranges = Self::parse_dynamic_ranges(&self.current_config);
                            self.reconcile_stale_dynamic_max_prefix_restarts();
                            self.config_snapshot_staged = false;
                            self.staged_policy_routes_prior = None;
                            self.metrics.record_policy_generation_loaded();
                            if rollback.scope == TransactionConfigScope::Full {
                                self.reap_dynamic_peers_not_allowed_by_current_ranges()
                                    .await;
                            }
                            let _ = reply.send(());
                        }
                        None => {}
                    }
                    self.finish_operator_seam();
                }
                notification = self.session_notify_rx.recv() => {
                    if let Some(notification) = notification {
                        self.drain_ready_session_lifecycle_notifications();
                        self.handle_session_notification(notification).await;
                    }
                }
                lifecycle = self.session_lifecycle_rx.recv() => {
                    if let Some(notification) = lifecycle {
                        self.handle_session_lifecycle_notification(&notification);
                    }
                }
                event = self.session_notification_event_rx.recv() => {
                    if let Some(event) = event {
                        self.publish_notification_event(event);
                    }
                }
                change = async {
                    match bfd_state_change_rx.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    match change {
                        Some(change) => self.handle_bfd_state_change(change).await,
                        // The actor's state-change sender is gone; stop polling
                        // a closed channel (recv would return None in a tight
                        // loop otherwise).
                        None => bfd_state_change_rx = None,
                    }
                }
                () = async {
                    if let Some(interval) = bmp_stats_interval.as_mut() {
                        interval.tick().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    self.emit_periodic_bmp_stats().await;
                }
                () = async move {
                    if let Some(deadline) = max_prefix_restart_deadline {
                        tokio::time::sleep_until(deadline).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    self.handle_due_max_prefix_restarts().await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
