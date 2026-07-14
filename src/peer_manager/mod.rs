use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use rustbgpd_api::peer_types::{
    ConfigEvent, DynamicNeighborInfo, POLICY_EVENT_HISTORY_CAPACITY, PeerKey, PeerManagerCommand,
    PeerManagerNeighborConfig, PeerManagerReadinessQuery, PolicyDatasetStatusRow, PolicyEvent,
    SESSION_EVENT_HISTORY_CAPACITY, SessionEvent, SessionLifecycleEvent, StageConfigSnapshotError,
};
use rustbgpd_bmp::BmpEvent;
use rustbgpd_fsm::PeerConfig;
use rustbgpd_policy::PolicyChain;
use rustbgpd_rib::RibUpdate;
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_transport::{
    PeerHandle, SessionLifecycleNotification, SessionNotification,
    SessionNotificationEvent as TransportNotificationEvent, TransportConfig,
};
use rustbgpd_wire::{Afi, Safi};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::task::JoinSet;
use tracing::{debug, error, info};

use crate::config::Config;
use crate::policy_admin::{
    apply_config_event, global_policy_chains_from_config, named_neighbor_set_from_config,
    named_neighbor_sets_from_config, named_peer_group_from_config, named_peer_groups_from_config,
    named_policies_from_config, named_policy_from_config, neighbor_peer_group_from_config,
    neighbor_policy_chains_from_config,
};

mod bfd;
mod dynamic;
mod events;
mod inbound;
mod lifecycle;
mod notifications;
mod policy;
mod reconcile;
mod rotation;
mod snapshot;
#[cfg(test)]
pub(crate) mod test_support;
mod update_group_plan;

use dynamic::{AcceptedDynamicRange, DeadLetteredPending, DynamicRange};

const DEFAULT_HOLD_TIME: u16 = rustbgpd_fsm::DEFAULT_HOLD_TIME;
const DEFAULT_CONNECT_RETRY_SECS: u32 = 5;
const BGP_PORT: u16 = 179;
const BMP_STATS_INTERVAL_SECS: u64 = 60;

/// Hard deadline for any single per-peer `query_state` request. Bounded so a
/// session task that's parked on TCP write back-pressure can't hang an admin
/// path (`ListPeers`, `GetPeerState`, periodic BMP stats). 100ms is well
/// above any healthy session-task command latency (typically <1ms) and well
/// below the 5-minute soak-harness gRPC health-check cadence, so a single
/// stalled peer surfaces as `stale = true` instead of as a wedged RPC.
const PEER_QUERY_TIMEOUT: Duration = Duration::from_millis(100);

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

/// Hard deadline for a RIB-manager reply awaited from the `PeerManager`
/// actor (export-policy swap, per-peer outbound refresh). Generous — the
/// RIB answers these inline and never legitimately takes seconds — but
/// bounded so a wedged RIB task cannot park the peer-manager actor (and
/// therefore SIGHUP reload / gRPC policy apply) forever.
const RIB_REPLY_TIMEOUT: Duration = Duration::from_secs(5);

/// ADR-0073: deadline for an `ExplainImportPolicy` round-trip to a
/// session task. Bounded for the same reason as the policy-update
/// timeout — a session parked on TCP back-pressure must not park the
/// peer-manager actor. On timeout the explain RPC reports the peer as
/// having no answer (synthetic `NOT_SEEN`), which is honest: we could
/// not read its cache in time.
const EXPLAIN_QUERY_TIMEOUT: Duration = Duration::from_millis(500);

pub(crate) enum InternalCommand {
    ReplaceConfigSnapshot {
        config: Box<Config>,
        /// Optional acknowledgement, sent after `current_config` is assigned.
        /// The SIGHUP reload path awaits this before releasing the FIB
        /// coordinator lock so a following gRPC FIB-table CRUD can't have its
        /// snapshot overtaken by this (stale) one on the separate channel.
        ack: Option<oneshot::Sender<()>>,
    },
}

#[allow(clippy::struct_excessive_bools)]
struct ManagedPeer {
    handle: PeerHandle,
    session_id: u64,
    remote_asn: u32,
    description: String,
    peer_group: Option<String>,
    enabled: bool,
    hold_time: Option<u16>,
    max_prefixes: Option<u32>,
    transport_config: TransportConfig,
    import_policy: Option<PolicyChain>,
    export_policy: Option<PolicyChain>,
    /// Live inbound session waiting for collision resolution.
    pending_inbound: Option<PendingInbound>,
    /// True for peers auto-created from a `[[dynamic_neighbors]]` range.
    /// Dynamic peers are ephemeral: removed when session falls to Idle.
    is_dynamic: bool,
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

/// Exact global inventory bound to an in-progress or failed TCP-AO
/// generation. Retained until commit so a same-generation retry cannot change
/// key material after any listener/session may already have installed a
/// prefix of the original candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TcpAoDesiredInventory {
    generation: rustbgpd_transport::TcpAoRotationGeneration,
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
    /// Reverse lookup from transport session id to configured peer identity.
    /// Session lifecycle notifications are keyed by session id, and scoped
    /// link-local peers can share the same address on different interfaces.
    session_index: HashMap<u64, PeerKey>,
    rx: mpsc::Receiver<PeerManagerCommand>,
    /// Dedicated read-only lane drained only at safe actor seams. Mutation
    /// commands remain on `rx` and therefore stay ordered behind a policy
    /// transaction until it either commits or rolls back.
    readiness_rx: Option<mpsc::Receiver<PeerManagerReadinessQuery>>,
    internal_rx: mpsc::UnboundedReceiver<InternalCommand>,
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
    session_notify_tx: mpsc::UnboundedSender<SessionNotification>,
    session_notify_rx: mpsc::UnboundedReceiver<SessionNotification>,
    session_lifecycle_tx: mpsc::Sender<SessionLifecycleNotification>,
    session_lifecycle_rx: mpsc::Receiver<SessionLifecycleNotification>,
    session_notification_event_tx: mpsc::Sender<TransportNotificationEvent>,
    session_notification_event_rx: mpsc::Receiver<TransportNotificationEvent>,
    session_events_tx: broadcast::Sender<SessionEvent>,
    session_event_history: VecDeque<SessionLifecycleEvent>,
    policy_events_tx: broadcast::Sender<PolicyEvent>,
    policy_event_history: VecDeque<PolicyEvent>,
    current_config: Config,
    /// True between `StageConfigSnapshot` and the transaction controller's
    /// persist/rollback completion signal. Dynamic inbound accepts are refused
    /// in this window so candidate-only ranges cannot create live peers before
    /// the candidate is durable.
    config_snapshot_staged: bool,
    /// Resolved dynamic neighbor ranges for prefix-based auto-accept.
    dynamic_ranges: Vec<DynamicRange>,
    /// Current number of active dynamic peers (for limit enforcement).
    dynamic_peer_count: usize,
    /// Maximum dynamic peers allowed. Default 100.
    dynamic_neighbor_limit: u32,
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
    /// add-only convergence commits the same generation here.
    tcp_ao_generation: rustbgpd_transport::TcpAoRotationGeneration,
    /// Global add-only phase gates protected accepts between preflight and
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
    /// Test-only deterministic fault injection: `reconfigure_peer` against
    /// a mapped key fails up front, before the delete/re-add cycle, once the
    /// key's budget of remaining successful calls reaches zero (a value of 0
    /// fails the next call; a value of 1 lets one call succeed, then fails
    /// the one after — e.g. apply succeeds, rollback fails). Models a
    /// transient runtime failure (e.g. a session task that cannot start) —
    /// the only mid-fanout failure class left, since config-shaped failures
    /// are all caught by validation, resolution, or the reshape preflight
    /// before any peer is touched.
    #[cfg(test)]
    inject_reconfigure_failures: std::collections::BTreeMap<PeerKey, u32>,
}

impl PeerManager {
    #[cfg(test)]
    #[expect(clippy::too_many_arguments)]
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
        let (_internal_tx, internal_rx) = mpsc::unbounded_channel();
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
                global: crate::config::Global {
                    asn: local_asn,
                    router_id: router_id.to_string(),
                    listen_port: BGP_PORT,
                    cluster_id: cluster_id.map(|id| id.to_string()),
                    runtime_state_dir: "/tmp/rustbgpd-tests".to_string(),
                    telemetry: crate::config::TelemetryConfig {
                        prometheus_addr: Some("127.0.0.1:9179".to_string()),
                        log_format: "json".to_string(),
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
                    warm_cache_checkpoint_on_shutdown: false,
                },
                // PeerManager::new constructs an in-memory baseline
                // Config before the operator's TOML is applied. The
                // schema default is `enforcement = "tier"` after the
                // v0.24.0 flip, but a defaulted Config has no
                // [security.grpc.roles], which would fail
                // post-apply validation in `apply_config_event`.
                // Use the explicit legacy posture here so the
                // baseline is internally consistent; the real
                // config arrives via reload / config-bridge with
                // its own [security.grpc] block.
                security: crate::config::SecurityConfig {
                    grpc: crate::config::GrpcSecurityConfig {
                        enforcement: crate::config::GrpcEnforcementConfig::Legacy,
                        roles: std::collections::HashMap::new(),
                    },
                },
                neighbors: Vec::new(),
                peer_groups: HashMap::new(),
                policy: crate::config::PolicyConfig::default(),
                rpki: None,
                bmp: None,
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
            },
        )
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
            PeerManagerReadinessQuery::ListPeers { reply } => {
                if reply.is_closed() {
                    return;
                }
                let infos = self.list_peers().await;
                let _ = reply.send(infos);
            }
        }
    }

    /// Drive one owned transaction step while servicing at most one read-only
    /// readiness query at a time. The transaction future is biased first, so a
    /// probe flood cannot delay a completed apply/rollback step.
    async fn await_with_readiness<F>(&mut self, future: F) -> F::Output
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

    async fn receive_readiness_query(
        readiness_rx: &mut Option<mpsc::Receiver<PeerManagerReadinessQuery>>,
    ) -> Option<PeerManagerReadinessQuery> {
        match readiness_rx {
            Some(rx) => rx.recv().await,
            None => std::future::pending().await,
        }
    }

    #[expect(clippy::too_many_arguments)]
    pub fn new_with_config(
        rx: mpsc::Receiver<PeerManagerCommand>,
        internal_rx: mpsc::UnboundedReceiver<InternalCommand>,
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
        let (session_notify_tx, session_notify_rx) = mpsc::unbounded_channel();
        let (session_lifecycle_tx, session_lifecycle_rx) = mpsc::channel(4096);
        let (session_notification_event_tx, session_notification_event_rx) = mpsc::channel(4096);
        let (session_events_tx, _) = broadcast::channel(4096);
        let (policy_events_tx, _) = broadcast::channel(4096);
        Self {
            peers: HashMap::new(),
            session_index: HashMap::new(),
            rx,
            readiness_rx: None,
            internal_rx,
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
            session_event_history: VecDeque::with_capacity(SESSION_EVENT_HISTORY_CAPACITY),
            policy_events_tx,
            policy_event_history: VecDeque::with_capacity(POLICY_EVENT_HISTORY_CAPACITY),
            config_snapshot_staged: false,
            dynamic_ranges: Self::parse_dynamic_ranges(&current_config),
            dynamic_peer_count: 0,
            dynamic_neighbor_limit: current_config.global.dynamic_neighbor_limit.unwrap_or(100),
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
            #[cfg(test)]
            inject_reconfigure_failures: std::collections::BTreeMap::new(),
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
        // RFC 9687 §6 default: greater of 8 minutes or 2× hold time.
        peer.send_hold_time = config
            .send_hold_time
            .unwrap_or_else(|| rustbgpd_fsm::default_send_hold_time(peer.hold_time));
        peer.connect_retry_secs = DEFAULT_CONNECT_RETRY_SECS;
        peer.families = families;
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
        transport.peer_interface.clone_from(&config.interface);
        transport.peer_scope_id = scope_id;
        transport.max_prefixes = config.max_prefixes;
        transport.peer_group.clone_from(&config.peer_group);
        transport.md5_password = config.md5_password.clone().map(Into::into);
        transport.tcp_ao.clone_from(&config.tcp_ao);
        transport.ttl_security = config.ttl_security;
        transport.local_ipv6_nexthop = config.local_ipv6_nexthop;
        transport.gr_stale_routes_time = config.gr_stale_routes_time;
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
        // RFC 7947 §2.3.2 / ADR-0101: without this line the knob
        // parses, validates, and reloads — and every session still
        // registers single-best (caught by M83; the RIB/CLI unit
        // layers are wired above this seam and never saw it).
        transport.per_client_best = config.per_client_best;
        transport.remove_private_as = config.remove_private_as;
        transport.cluster_id = self.cluster_id;
        // ADR-0073: per-session import-decision explain cache wiring.
        // Both the enable flag and the capacity must be threaded — a
        // missing `explain_enabled` here would silently leave the
        // write-path gate at its `true` default regardless of config.
        transport.explain_enabled = self.current_config.policy.explain.enabled;
        transport.explain_cache_size = self.current_config.policy.explain.cache_size;
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
            tokio::select! {
                query = Self::receive_readiness_query(&mut self.readiness_rx) => {
                    match query {
                        Some(query) => self.handle_readiness_query(query).await,
                        None => self.readiness_rx = None,
                    }
                }
                cmd = self.rx.recv() => {
                    let Some(cmd) = cmd else {
                        debug!("peer manager channel closed");
                        return;
                    };
                    match cmd {
                        PeerManagerCommand::AddPeer { config, sync_config_snapshot, reply } => {
                            let result = self.add_peer(config, sync_config_snapshot).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::DeletePeer { peer, sync_config_snapshot, reply } => {
                            let result = self.delete_peer(peer, sync_config_snapshot).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::ReconfigurePeer { config, reply } => {
                            let result = self.reconfigure_peer(config).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::ListPeers { reply } => {
                            let infos = self.list_peers().await;
                            let _ = reply.send(infos);
                        }
                        PeerManagerCommand::QueryWarmCheckpointCapture { reply } => {
                            let capture = self.query_warm_checkpoint_capture().await;
                            let _ = reply.send(capture);
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
                            reply,
                        } => {
                            let result = self.plan_config_transaction(
                                &candidate_toml,
                                expected_runtime_snapshot_token.as_deref(),
                            ).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::StageConfigSnapshot {
                            candidate_toml,
                            reply,
                        } => {
                            let result = Config::load_toml_with_diagnostics(
                                &candidate_toml,
                                "candidate config transaction",
                            )
                            .map_err(StageConfigSnapshotError::InvalidCandidate)
                            .and_then(|candidate| {
                                let previous =
                                    toml::to_string_pretty(&self.current_config).map_err(
                                        |error| {
                                            StageConfigSnapshotError::SerializePreviousSnapshot(
                                                error.to_string(),
                                            )
                                        },
                                    )?;
                                self.current_config = candidate;
                                self.dynamic_ranges =
                                    Self::parse_dynamic_ranges(&self.current_config);
                                self.config_snapshot_staged = true;
                                Ok(previous)
                            });
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::CommitConfigSnapshotStage { reply } => {
                            self.config_snapshot_staged = false;
                            let _ = reply.send(());
                        }
                        PeerManagerCommand::RestoreConfigSnapshot {
                            candidate_toml,
                            reply,
                        } => {
                            let result = Config::load_toml_with_diagnostics(
                                &candidate_toml,
                                "rollback config transaction",
                            )
                            .map_err(StageConfigSnapshotError::InvalidCandidate);
                            match result {
                                Ok(candidate) => {
                                    self.current_config = candidate;
                                    self.dynamic_ranges =
                                        Self::parse_dynamic_ranges(&self.current_config);
                                    self.config_snapshot_staged = false;
                                    self.reap_dynamic_peers_not_allowed_by_current_ranges()
                                        .await;
                                    let _ = reply.send(Ok(()));
                                }
                                Err(error) => {
                                    let _ = reply.send(Err(error));
                                }
                            }
                        }
                        PeerManagerCommand::RuntimeConfigSnapshot { reply } => {
                            let result = toml::to_string_pretty(&self.current_config)
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
                        PeerManagerCommand::BounceDynamicRangePeers { ranges, reply } => {
                            let outcome = self.bounce_dynamic_peers_for_ranges(&ranges).await;
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
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::GetPeerState { peer, reply } => {
                            let info = self.get_peer_info(&peer).await;
                            let _ = reply.send(info);
                        }
                        PeerManagerCommand::EnablePeer { peer, reply } => {
                            let result = self.enable_peer(peer).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::DisablePeer { peer, reason, reply } => {
                            let result = self.disable_peer(peer, reason).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::SoftResetIn { peer, families, reply } => {
                            let result = self.soft_reset_in(peer, families).await;
                            let _ = reply.send(result);
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
                            self.handle_inbound(stream, peer_addr, tcp_ao_info, tcp_ao_generation).await;
                        }
                        PeerManagerCommand::ApplyTcpAoAddOnly { generation, listener_keys, static_keyrings, reply } => {
                            let result = self.apply_tcp_ao_add_only(generation, &listener_keys, &static_keyrings).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::PreflightTcpAoAddOnly { generation, listener_keys, static_keyrings, reply } => {
                            let result = self.preflight_tcp_ao_add_only(generation, &listener_keys, &static_keyrings).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::MarkTcpAoAddOnlyFailed { generation, error, reply } => {
                            self.mark_tcp_ao_add_only_failed(generation, &error);
                            let _ = reply.send(Ok(()));
                        }
                        PeerManagerCommand::ReconcilePeers { added, removed, changed, reply } => {
                            let result = self.reconcile_peers(added, removed, changed).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::HotUpdatePeer { config, reply } => {
                            let result = self.hot_update_peer(config).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::SyncExplainConfig { enabled, cache_size, reply } => {
                            // ADR-0073: make the explain snapshot fresh before
                            // any subsequent reconcile/peer-group command on
                            // this FIFO channel constructs a session via
                            // build_transport_config.
                            self.current_config.policy.explain.enabled = enabled;
                            self.current_config.policy.explain.cache_size = cache_size;
                            let _ = reply.send(());
                        }
                        PeerManagerCommand::SyncRpolPolicies { rpol_files, rpol, dataset_bindings, reply } => {
                            let result = self.sync_rpol_policies(rpol_files, rpol, dataset_bindings).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::RefreshDatasetDependents { swapped, failed, reply } => {
                            let result = self.refresh_dataset_dependents(&swapped, &failed).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::QueryPolicyDatasets { reply } => {
                            // LAN-305: status straight off the shared
                            // handles; sorted for deterministic output.
                            let mut rows: Vec<PolicyDatasetStatusRow> = self
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
                            let _ = reply.send(rows);
                        }
                        PeerManagerCommand::ListPolicies { reply } => {
                            let _ = reply.send(named_policies_from_config(&self.current_config));
                        }
                        PeerManagerCommand::ExplainImportPolicy {
                            address, afi, safi, prefix, path_id, reply,
                        } => {
                            // Resolve the unique session for this address and
                            // forward to its task. No live session → None,
                            // which the RPC layer renders as NO_SESSION (the
                            // session-local cache is gone, per ADR-0073 /
                            // LAN-320).
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
                                None => None,
                            };
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::QueryImportPolicyTermHits { peer, reply } => {
                            // Read-only snapshot forwarded to each session
                            // task (the import chain and its counters live
                            // there). Bounded per session like explain: a
                            // wedged task drops out of the answer instead of
                            // parking the actor. Sessions without an
                            // installed import chain reply None and are
                            // omitted.
                            let keys: Vec<_> = match peer {
                                Some(address) => self
                                    .unique_peer_key_for_address(address)
                                    .into_iter()
                                    .collect(),
                                None => self.peers.keys().cloned().collect(),
                            };
                            let mut out = Vec::new();
                            for key in keys {
                                let Some(managed) = self.peers.get(&key) else {
                                    continue;
                                };
                                if let Some(snapshot) = managed
                                    .handle
                                    .query_import_policy_term_hits_timeout(EXPLAIN_QUERY_TIMEOUT)
                                    .await
                                {
                                    out.push((key.address, snapshot));
                                }
                            }
                            out.sort_unstable_by_key(|(address, _)| *address);
                            let _ = reply.send(out);
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
                            let result = self.set_honor_graceful_shutdown(enabled).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::SetHonorBlackhole { enabled, reply } => {
                            let result = self.set_honor_blackhole(enabled).await;
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
                        PeerManagerCommand::SetPeerGroupPreserveMd5 { name, mut definition, reply } => {
                            let result = match named_peer_group_from_config(&self.current_config, &name) {
                                Some(existing) => {
                                    definition.md5_password = existing.md5_password;
                                    let applied_definition = definition.clone();
                                    let event = ConfigEvent::SetPeerGroup {
                                        name: name.clone(),
                                        definition: definition.clone(),
                                        ack: None,
                                    };
                                    if self.peer_group_policy_only_update(&name, &definition) {
                                        self.apply_policy_change(event, None).await
                                    } else {
                                        let affected: Vec<IpAddr> = self.current_config
                                            .neighbors
                                            .iter()
                                            .filter(|neighbor| {
                                                neighbor.peer_group.as_deref() == Some(name.as_str())
                                            })
                                            .filter_map(|neighbor| neighbor.address.parse().ok())
                                            .collect();
                                        self.apply_peer_group_change(event, affected).await
                                    }
                                    .map(|()| applied_definition)
                                }
                                None => Err(rustbgpd_api::peer_types::CatalogMutationError::not_found(
                                    format!("peer group {name} not found"),
                                )),
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
                }
                internal = self.internal_rx.recv() => {
                    if let Some(InternalCommand::ReplaceConfigSnapshot { config, ack }) = internal {
                        self.current_config = *config;
                        self.config_snapshot_staged = false;
                        // #338: rebuild the live dynamic-neighbor accept-matcher so
                        // [[dynamic_neighbors]] edits applied via SIGHUP take effect
                        // (previously only `current_config` was swapped). The shared
                        // runtime-config lock guarantees the reloaded config already
                        // reflects any accepted runtime CRUD, so a plain re-parse is
                        // correct — no merge/provenance needed.
                        self.dynamic_ranges = Self::parse_dynamic_ranges(&self.current_config);
                        if let Some(ack) = ack {
                            let _ = ack.send(());
                        }
                    }
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
            }
        }
    }
}

#[cfg(test)]
mod tests;
