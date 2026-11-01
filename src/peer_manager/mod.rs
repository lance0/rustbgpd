use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::ControlFlow;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustbgpd_api::peer_types::{
    CatalogMutationError, ConfigEvent, DynamicNeighborInfo, EnqueuedOperatorQuery,
    OwnedCatalogMutation, OwnedCatalogMutationOutcome, OwnedHotUpdatePeerOutcome,
    OwnedNeighborMutation, OwnedNeighborMutationError, OwnedNeighborMutationOutcome, PeerKey,
    PeerManagerCommand, PeerManagerNeighborConfig, PeerManagerOperatorQuery,
    PeerManagerReadinessQuery, PeerReconcileAuthority, PolicyEvent,
    RuntimeConfigTransactionPlanError, SessionEvent, SessionLifecycleEvent,
};
use rustbgpd_bmp::BmpEvent;
use rustbgpd_fsm::PeerConfig;
use rustbgpd_policy::PolicyChain;
use rustbgpd_rib::RibUpdate;
use rustbgpd_telemetry::BgpMetrics;
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
mod conditional;
mod configured_owners;
mod dampening_control;
mod dynamic;
mod events;
pub(crate) mod generation;
mod inbound;
mod lifecycle;
mod link_failover;
mod notifications;
mod peer_table;
mod policy;
mod queries;
mod reconcile;
mod recovery;
mod retained_dynamic;
mod rotation;
pub(crate) use rotation::TCP_AO_AWAITING_PEER_PREFIX;
mod snapshot;
#[cfg(target_os = "linux")]
mod unnumbered;
/// Interface-only neighbors need Linux; configuration validation refuses
/// them elsewhere, so this stand-in is never constructed.
#[cfg(not(target_os = "linux"))]
mod unnumbered {
    use rustbgpd_api::peer_types::PeerKey;
    use std::net::IpAddr;

    pub(crate) enum Unnumbered {}
    pub(crate) enum DiscoveryEvent {}
    #[derive(Default)]
    pub(crate) struct UnnumberedRuntime {
        pub(crate) config_due: bool,
    }

    impl Unnumbered {
        pub(super) async fn shutdown(self) {
            match self {}
        }
    }

    impl super::PeerManager {
        pub(super) async fn receive_discovery_event(
            _: &mut Option<Box<Unnumbered>>,
        ) -> Option<DiscoveryEvent> {
            std::future::pending().await
        }
        pub(super) fn handle_discovery_event(&mut self, event: DiscoveryEvent) {
            match event {}
        }
        pub(super) fn unnumbered_reconcile_due(&self) -> bool {
            false
        }
        pub(super) async fn reconcile_unnumbered(&mut self) {}
        pub(super) fn feed_unnumbered_links(&mut self) {}
        pub(super) fn note_unnumbered_session_state(
            &mut self,
            _: &PeerKey,
            _: rustbgpd_fsm::SessionState,
            _: rustbgpd_fsm::SessionState,
        ) {
        }
        pub(super) fn recheck_refused_bindings(&mut self) {}
        pub(super) fn note_unnumbered_session_idle(&mut self, _: &PeerKey) {}
        pub(super) fn unnumbered_retry_at(&self) -> Option<tokio::time::Instant> {
            None
        }
        pub(super) fn unnumbered_retry_due(&mut self) {}
        pub(super) fn unnumbered_owner_of(&self, _: &PeerKey) -> Option<&str> {
            None
        }
        pub(super) fn unnumbered_binding_endpoints(&self) -> Vec<(IpAddr, String)> {
            Vec::new()
        }
        pub(super) fn unnumbered_stopped(&self, _: &PeerKey) -> bool {
            false
        }
        pub(super) fn unnumbered_presence_reason(&self, _: &PeerKey) -> Option<&'static str> {
            None
        }
        pub(super) fn unnumbered_bound_addresses(&self) -> std::collections::HashSet<IpAddr> {
            std::collections::HashSet::new()
        }
        pub(super) fn unnumbered_bindings(&self) -> Vec<(String, std::net::Ipv6Addr, u32)> {
            Vec::new()
        }
        pub(super) fn unnumbered_bound_peer(&self, _: &str) -> Option<PeerKey> {
            None
        }
        pub(super) fn unnumbered_preflight(
            &self,
            candidate: &crate::config::Config,
        ) -> Result<(), String> {
            self.validate_live_shared_addresses(candidate)
        }
        pub(super) fn preflight_reload_generation(
            &mut self,
            _: &crate::config::Config,
            _: std::sync::Weak<()>,
        ) -> Result<(), String> {
            Ok(())
        }
        pub(super) fn release_generation_hold(&mut self) {}
        pub(super) async fn apply_interface_only_policy_deltas(
            &mut self,
            _: &crate::config::Config,
        ) -> Result<
            Vec<rustbgpd_api::peer_types::ResolvedPeerPolicy>,
            super::policy::PolicySnapshotFailure,
        > {
            Ok(Vec::new())
        }
        pub(super) async fn restore_interface_only_policies(
            &mut self,
            _: Vec<rustbgpd_api::peer_types::ResolvedPeerPolicy>,
        ) -> bool {
            true
        }
        pub(super) fn add_interface_only_neighbor(
            &mut self,
            _: Box<rustbgpd_api::peer_types::PresenceAwareNeighborCreate>,
        ) -> Result<(), rustbgpd_api::peer_types::PeerLifecycleError> {
            Err(rustbgpd_api::peer_types::PeerLifecycleError::Invalid(
                "interface-only neighbors need Linux".to_string(),
            ))
        }
        pub(super) fn delete_interface_only_neighbor(
            &mut self,
            interface: &str,
        ) -> Result<(), rustbgpd_api::peer_types::PeerLifecycleError> {
            Err(
                rustbgpd_api::peer_types::PeerLifecycleError::InterfaceOnlyNotFound(
                    interface.to_owned(),
                ),
            )
        }
        pub(super) fn unbound_interface_only_infos(
            &self,
        ) -> Vec<rustbgpd_api::peer_types::PeerInfo> {
            Vec::new()
        }
        pub(super) fn interface_only_port_at(&self, _: u32) -> Option<String> {
            None
        }
        pub(super) async fn learn_inbound_endpoint(
            &mut self,
            _: &str,
            _: std::net::Ipv6Addr,
            _: u32,
        ) -> Option<PeerKey> {
            None
        }
    }
}
pub(crate) use unnumbered::{Unnumbered, UnnumberedRuntime};
#[cfg(test)]
pub(crate) mod test_support;
mod update_group_plan;

use dynamic::{AcceptedDynamicRange, DeadLetteredPending, DynamicRange};
use peer_table::{ManagedPeer, PeerTable};

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

/// One retry allowance shared by every clean-convergence state check in a
/// settlement-owned policy cohort. A first 100 ms miss may be load rather
/// than session loss; it is retried at most once, and the retries together
/// spend at most this much time. Work between state checks is not charged.
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

/// Ordered primary-lane RIB updates queued while the mailbox was full, so a
/// deletion never holds the actor on mailbox admission.
///
/// Every later update the actor sends through the ordered path
/// (`send_rib_update`, or a flush before a direct send) goes behind them. No
/// session starts under a label one of them reaps until it is admitted, and
/// inbound connections are refused meanwhile (see
/// `refuse_inbound_behind_deferred_cleanup`). An interface-only bind that
/// would wait for mailbox room (a cleanup queued under its interface's
/// label, or no room for its `RebindPeer`) is retried on the reconcile timer
/// or, from an inbound connection, refused.
///
/// Every `await_with_readiness*` wait and a session's bounded shutdown
/// drive the oldest one's reservation (`drive_while`), sending it once it is
/// granted while keeping its place among waiting senders. The BMP tick sends
/// it only if it is already granted (`send_if_granted`), and peer-manager
/// shutdown gives it back. The other bounded waits (session start, stop,
/// state, purge-reset and collision-dump commands, and the session reads of
/// `GetPeerState` and `ListPeers`) do neither: a reservation granted while
/// one of them waits holds one slot until the next drive. That leaves the
/// other slots of any mailbox above capacity 1; at capacity 1, a test-only
/// setting, such a wait can run out its own timeout.
///
/// Depth is bounded by state, not by network event rate. While the queue is
/// not empty, the only inbound connection that creates a RIB identity is a
/// retained neighbor's reconnect from another AS, which allocates one
/// handle in place of the retained one it releases. A new dynamic neighbor,
/// a collision candidate beside a retained reconnect, and a new identity
/// after an eviction are refused; a retained neighbor's reconnect from its
/// own AS resumes the identity it kept. Static adds wait for the cleanup
/// under their label. The entries are then:
/// - at most two per identity (its `PeerDeleted` and `ReleasePeer`) that
///   existed when the mailbox filled or that an operator or reconcile change
///   has created since;
/// - at most four for an interface-only neighbor being removed: a retired
///   endpoint's deletion, the removal's final deletion, its `ReleasePeer` and
///   its End-of-RIB grace retirement;
/// - one `ReleasePeer` per refused operator or reconcile add, or per
///   interface-only bind that fails to start;
/// - the update a `send_rib_update` call owns while it flushes.
///
/// The queue never leaves the actor; only `sender` moves into a flush's
/// wait, so a dropped flush loses nothing but its reservation, which the run
/// loop restores. `send_rib_update` queues its own update before it
/// flushes, so a dropped call would still deliver it later; no caller drops
/// one, and cancellable callers (planning) flush and then send directly.
#[derive(Default)]
struct DeferredRibUpdates {
    /// Oldest first, each with the `peer` metric label its handling reaps.
    queue: VecDeque<(Option<String>, RibUpdate)>,
    /// Admission for the oldest: set while `queue` is not empty, except while
    /// a flush has moved it into its wait. A reservation in progress survives
    /// a dropped wait, so the update keeps its place among waiting senders.
    sender: Option<tokio_util::sync::PollSender<RibUpdate>>,
}

impl DeferredRibUpdates {
    /// Whether a wait should drive the oldest update's reservation: there is
    /// one, and no flush owns the sender.
    fn ready(&self) -> bool {
        self.sender.is_some() && !self.queue.is_empty()
    }

    /// Wait for room and send the oldest update. Cancel-safe: the sender
    /// stays in place while it waits, and the send follows the reservation
    /// without another suspension point. `false` once the RIB has exited.
    async fn send_oldest(&mut self) -> bool {
        debug_assert!(self.ready(), "polled with nothing to send");
        let Some(port) = self.sender.as_mut() else {
            return true;
        };
        let reserved = std::future::poll_fn(|cx| port.poll_reserve(cx))
            .await
            .is_ok();
        let port = self.sender.take().expect("still in place after the wait");
        self.send_reserved(port, reserved)
    }

    /// Send the oldest update on `port`'s reservation, keeping `port` while
    /// updates remain. A RIB that has exited (`!reserved`, or a failed send)
    /// discards them all, so no wait polls a closed channel again.
    fn send_reserved(
        &mut self,
        mut port: tokio_util::sync::PollSender<RibUpdate>,
        reserved: bool,
    ) -> bool {
        let sent = reserved
            && self
                .queue
                .pop_front()
                .is_some_and(|(_, update)| port.send_item(update).is_ok());
        if !sent {
            self.queue.clear();
        }
        self.sender = (!self.queue.is_empty()).then_some(port);
        sent
    }

    /// Give back a reservation in progress, granted or not, and with it the
    /// update's place among waiting senders. Only for peer-manager shutdown,
    /// whose sessions need every slot for their final `PeerDown` and after
    /// which nothing is sent. The update stays queued.
    fn release_reservation(&mut self) {
        if let Some(port) = self.sender.as_mut() {
            port.abort_send();
        }
    }

    /// Before a short wait that cannot drive the reservation: send the oldest
    /// update if its reservation is already granted, so the wait does not sit
    /// beside an unused slot, and otherwise keep its place among waiting
    /// senders. A grant during the wait leaves one slot unused until the next
    /// drive, which matters only at a mailbox capacity of 1.
    fn send_if_granted(&mut self) {
        use futures::FutureExt as _;
        if !self.ready() {
            return;
        }
        if let Some(sent) = self.send_oldest().now_or_never()
            && !sent
        {
            debug!("RIB exited: discarding deferred RIB updates");
        }
    }

    /// Await `future`, which must not need the actor, while driving the
    /// oldest deferred update's reservation: a granted one is sent at once,
    /// so `future` never waits beside a slot the actor holds, and the update
    /// keeps its place among waiting senders.
    async fn drive_while<F: Future>(&mut self, future: F) -> F::Output {
        tokio::pin!(future);
        loop {
            tokio::select! {
                biased;
                output = &mut future => return output,
                sent = self.send_oldest(), if self.ready() => {
                    if !sent {
                        debug!("RIB exited: discarding deferred RIB updates");
                    }
                }
            }
        }
    }

    /// Whether `interface`'s End-of-RIB grace retirement is queued.
    fn retires_eor_grace(&self, interface: &str) -> bool {
        self.queue.iter().any(|(_, update)| {
            matches!(update, RibUpdate::RetireEorGraceInterface { interface: queued } if &**queued == interface)
        })
    }

    /// Whether a queued update reaps `label`.
    fn reaps(&self, label: &str) -> bool {
        self.queue
            .iter()
            .any(|(reaps, _)| reaps.as_deref() == Some(label))
    }
}

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
/// (`rbgp neighbor` and other peer snapshots) while it is driven.
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
    /// ADR-0142 preflight of a SIGHUP candidate, before the reload route's
    /// first effect outside the peer manager. Acceptance holds the
    /// candidate's static link-local addresses closed to learned endpoints
    /// until its `ApplyReloadGeneration` or until `route` is dropped.
    PreflightReloadGeneration {
        candidate: Box<Config>,
        route: std::sync::Weak<()>,
        reply: oneshot::Sender<Result<(), String>>,
    },
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
        /// Preview reads must reject an unsettled baseline at actor entry.
        /// Owned mutation callers already retain this coordinator themselves.
        read_coordinator: Option<rustbgpd_api::server::RuntimeConfigCoordinator>,
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
/// The manager's state for one managed peer, apart from its current session
/// (see [`ManagedPeer`], which only the peer table can change).
struct ManagedPeerState {
    remote_asn: u32,
    description: String,
    peer_group: Option<String>,
    enabled: bool,
    /// Config-owned administrative-down state the peer was added or last
    /// reloaded with. Reload compares it with the candidate: only a change
    /// overrides the runtime `enabled` toggle.
    admin_down: Option<String>,
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
    /// A positively known-down peer classified during the authoritative
    /// per-peer apply pass (Idle/Connect/Active). Its pending flags after that
    /// apply represent deferred `PeerUp` adoption intent rather than
    /// convergence debt, so it owes no Route Refresh to the transaction that
    /// armed them. The classification is written by the per-peer apply state
    /// query and retained across cohort captures so rollback compensation
    /// does not treat a positively down member as convergence debt.
    policy_known_down: bool,
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

impl MaxPrefixLatch {
    /// An indefinite or consumed hold-down never gains a new automatic attempt.
    fn reschedule(&mut self, generation: u64, seconds: Option<u32>) -> bool {
        if self.deadline.is_none() {
            return false;
        }
        self.generation = generation;
        self.deadline = seconds.map(|seconds| {
            tokio::time::Instant::now() + std::time::Duration::from_secs(seconds.into())
        });
        true
    }
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
    recovery_reset: Option<recovery::SessionRecoveryReset>,
}

#[cfg(test)]
type CommandHook = Arc<dyn Fn(&PeerManagerCommand) + Send + Sync>;

/// Manages the lifecycle of all peer sessions.
///
/// Runs as a single tokio task, receiving commands via an mpsc channel.
/// Same single-task ownership pattern as `RibManager`.
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent run-loop flags owned by different subsystems, not one state machine"
)]
pub struct PeerManager {
    /// Managed peers and the import roster published from them (ADR-0136).
    peers: PeerTable,
    /// Max-prefix shutdowns owned by the manager rather than a disposable
    /// session task. Presence fences passive accepts, collision handling, and
    /// config reconciliation until explicit enable or one configured restart
    /// attempt reaches its deadline; a failed attempt remains latched down.
    max_prefix_latches: HashMap<PeerKey, MaxPrefixLatch>,
    /// Neighbors admitted at an address another neighbor holds while every
    /// BMP collector is set to `on_identity_conflict = "exclude"`: their
    /// sessions report nothing to BMP. Kept until the neighbor's peer goes.
    pub(super) bmp_excluded: BTreeSet<PeerKey>,
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
    evpn_recovery_retry_at: Option<tokio::time::Instant>,
    evpn_recovery_retry_cursor: u64,
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
    /// Neighbor snapshots admitted at a transaction wait whose session
    /// replies are still being joined (ADR-0132, 2026-10-10 amendment).
    /// At most the operator lane's capacity; dropping the manager aborts
    /// them, and their callers observe a dropped reply.
    detached_list_peers: JoinSet<()>,
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
    /// Nesting depth of [`Self::handle_session_notification`]. Handling one
    /// notification can drain the queue again (collision promotion and
    /// session retirement both do).
    ///
    /// Invariant: no future that can reach `handle_session_notification` is
    /// dropped before it completes, so the increment and decrement always pair.
    /// Reaching it needs `&mut PeerManager`, which rules out `&self` futures,
    /// spawned tasks and the inner future of `await_with_readiness{,_budget}`.
    /// The only `&mut self` futures raced in a `select!` or wrapped in a
    /// `timeout` are `plan_config_transaction`, `await_with_readiness` (whose
    /// arms serve only readiness and operator reads and send deferred RIB
    /// updates) and
    /// `query_warm_checkpoint_capture`, and none of them drains session
    /// notifications. Keep it that way, or reset the depth where a drop can
    /// happen; the run loop `debug_assert!`s the depth is zero between steps.
    session_notification_depth: usize,
    /// Notifications a nested drain left for the outermost handler because
    /// they belong to a different peer, with the peer their session resolved
    /// to. Empty whenever the depth is zero.
    deferred_session_notifications: VecDeque<(Option<PeerKey>, SessionNotification)>,
    /// Per-peer count of `deferred_session_notifications`, so a fence scans
    /// the queue only when its own peer has an entry there.
    deferred_session_notification_counts: HashMap<PeerKey, usize>,
    session_lifecycle_tx: mpsc::Sender<SessionLifecycleNotification>,
    session_lifecycle_rx: mpsc::Receiver<SessionLifecycleNotification>,
    session_notification_event_tx: mpsc::Sender<TransportNotificationEvent>,
    session_notification_event_rx: mpsc::Receiver<TransportNotificationEvent>,
    session_events_tx: broadcast::Sender<Arc<SessionEvent>>,
    session_event_history: VecDeque<SessionLifecycleEvent>,
    policy_events_tx: broadcast::Sender<Arc<PolicyEvent>>,
    policy_event_history: VecDeque<Arc<PolicyEvent>>,
    current_config: Config,
    configured_owners: configured_owners::ConfiguredOwners,
    /// Ordered RIB updates a deletion queued while the RIB mailbox was full.
    deferred_rib: DeferredRibUpdates,
    /// A history-enabled retirement failed its primary-RIB barrier. The next
    /// actor turn terminates through existing daemon component supervision.
    dampening_control_failed: bool,
    /// ADR-0137: the conditional-advertisement set the RIB last
    /// acknowledged. The RIB install is the only copy the gate reads; this
    /// is the comparison basis for deciding when to install again.
    conditional_advertisements: rustbgpd_rib::ConditionalAdvertisementSet,
    /// Set by every config replacement; the run loop then reconciles the
    /// RIB install against `current_config`.
    conditional_reconcile_pending: bool,
    /// After a failed reconcile: when the run loop retries it, and the
    /// backoff that produced that deadline.
    conditional_reconcile_retry: Option<(tokio::time::Instant, Duration)>,
    /// A conditional-advertisement install was dispatched without a
    /// conclusive acknowledgement: the RIB may hold it, the cached set may
    /// not, so the next install is sent even if it equals the cache.
    conditional_install_uncertain: bool,
    local_forwarding_state: Arc<crate::forwarding_state::ForwardingState>,
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
    /// Lifetime counter blocks by neighbor key, shared with every session
    /// spawned for that neighbor. A block lives until the neighbor is
    /// deleted, like its Prometheus series, so a reconfigure that re-adds
    /// the neighbor keeps counting.
    neighbor_counters: BTreeMap<PeerKey, rustbgpd_transport::NeighborCounters>,
    /// RIB identity slots by neighbor key, shared with every session spawned
    /// for that neighbor. Like the counter blocks, a slot lives until the
    /// neighbor is deleted, so a reconfigure keeps the neighbor's `PeerId`;
    /// a deletion releases it, so a re-added neighbor gets a new one.
    rib_peers: BTreeMap<PeerKey, rustbgpd_transport::RibPeerSlot>,
    /// Idle dynamic neighbors kept, with their `rib_peers` slot, while
    /// graceful restart may still hold routes on either side. Each still
    /// counts in `dynamic_peer_count`.
    retained_dynamic: BTreeMap<PeerKey, retained_dynamic::RetainedDynamicPeer>,
    /// The checks that end each retention.
    retention: retained_dynamic::RetentionChecks,
    /// Maximum dynamic peers allowed. Default 100.
    dynamic_neighbor_limit: u32,
    /// ADR-0120 per-source accept-rate limiter. `None` when
    /// `[inbound_admission]` is disabled (the default); built once at
    /// startup — every field is restart-required.
    inbound_admission: Option<admission::InboundAdmission>,
    /// Throttles the log line for inbound connections held by a neighbor's
    /// NOTIFICATION reconnect backoff.
    notification_backoff_log: admission::LogThrottle,
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
    /// Fast external failover: the link monitor's snapshot feed and the
    /// sessions whose `CheckLinks` is waiting for mailbox space.
    link_check: link_failover::LinkCheckDelivery,
    /// ADR-0142 interface-only neighbors: Router Advertisement discovery and
    /// the peers created for its bindings. `None` when none is configured.
    unnumbered: Option<Box<Unnumbered>>,
    /// Whether the configured interface-only set needs reconciling, and how
    /// discovery opens when the first one arrives at runtime.
    unnumbered_runtime: UnnumberedRuntime,
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
    /// Runs synchronously at the start of every dispatched command.
    #[cfg(test)]
    test_command_hook: Option<CommandHook>,
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
                    unnumbered: None,
                    telemetry: crate::config::TelemetryConfig {
                        prometheus_addr: Some("127.0.0.1:9179".to_string()),
                        dataplane_readiness: false,
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
                    fast_external_failover: None,
                    install_blackhole_discard: false,
                    allow_blackhole_broad_prefixes: false,
                    blackhole_discard_max_active: None,
                    blackhole_discard_install_rate_per_minute: None,
                    blackhole_discard_install_burst: None,
                    ebgp_requires_policy: None,
                    warm_cache_checkpoint_on_shutdown: false,
                    max_as_path_length: rustbgpd_transport::DEFAULT_MAX_AS_PATH_LENGTH,
                    gr_eor_replay_owners: Vec::new(),
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
                neighbors: Vec::new().into(),
                peer_groups: HashMap::new(),
                policy: crate::config::PolicyConfig::default(),
                flowspec: crate::config::FlowSpecConfig::default(),
                rpki: None,
                bmp: None,
                gnmi_dialout: None,
                mrt: None,
                file_path: None,
                dynamic_neighbors: Vec::new(),
                evpn_instances: Vec::new(),
                ethernet_segments: Vec::new(),
                evpn_core_isolation: None,
                evpn_ip_vrfs: Vec::new(),
                managed_netdevs: crate::config::ManagedNetdevsConfig::default(),
                fib_tables: Vec::new(),
                bfd_profiles: Vec::new(),
                apply_bum_enforcement: false,
                inbound_admission: crate::config::InboundAdmissionConfig::default(),
            },
        )
    }

    pub(crate) fn with_local_forwarding_state(
        mut self,
        state: Arc<crate::forwarding_state::ForwardingState>,
    ) -> Self {
        self.local_forwarding_state = state;
        self
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

    /// A reading end of the import roster this manager publishes (ADR-0136).
    #[must_use]
    pub fn import_roster(&self) -> rustbgpd_api::import_roster::ImportRosterReader {
        self.peers.roster()
    }

    /// Test builds: the published import roster equals the projection of the
    /// peer table and the live config's dataset bindings.
    #[cfg(test)]
    pub(crate) fn assert_import_roster_projection(&self) {
        self.peers.assert_published();
        assert!(
            peer_table::same_datasets(
                self.peers.roster().load().datasets(),
                &peer_table::dataset_projection(&self.current_config),
            ),
            "published datasets are the live config's bindings"
        );
    }

    /// Replace the live configuration, republishing its dataset bindings in
    /// the import roster. Every wholesale replacement goes through here.
    fn replace_current_config(&mut self, config: Config) -> Config {
        let previous = std::mem::replace(&mut self.current_config, config);
        self.peers.set_datasets(&self.current_config);
        self.conditional_reconcile_pending = true;
        self.unnumbered_runtime.config_due = true;
        previous
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

    /// Seam for a read admitted inside a transaction. A marked transaction
    /// wait owns the attribution; an unmarked admitting wait retains a
    /// completed policy seam that held this read.
    fn admitted_operator_seam(&self, enqueued: tokio::time::Instant) -> OperatorReadSeam {
        if self.operator_read_seam == OperatorReadSeam::Unfenced {
            self.seam_that_held(enqueued)
        } else {
            self.operator_read_seam
        }
    }

    async fn handle_operator_query(&mut self, query: EnqueuedOperatorQuery, during_prestage: bool) {
        let EnqueuedOperatorQuery { enqueued, query } = query;
        if during_prestage {
            self.observe_operator_query_wait(enqueued, self.admitted_operator_seam(enqueued));
            // Finish the admitted snapshot before a prestage ACK can let
            // the reload advance any session's installed policy.
            self.answer_operator_query(query).await;
        } else {
            self.observe_operator_query_wait(enqueued, self.seam_that_held(enqueued));
            self.answer_normal_operator_query(query).await;
        }
    }

    /// A read admitted by an owner's wait helper. `ListPeers` is detached
    /// when possible so the owner can resume as soon as its own future is
    /// ready; every other read, and a snapshot that cannot be detached, is
    /// answered in place.
    async fn handle_waiting_operator_query(&mut self, query: EnqueuedOperatorQuery) {
        let EnqueuedOperatorQuery { enqueued, query } = query;
        self.observe_operator_query_wait(enqueued, self.admitted_operator_seam(enqueued));
        let query = match query {
            PeerManagerOperatorQuery::ListPeers { reply } => match self.detach_list_peers(reply) {
                Ok(()) => return,
                Err(reply) => PeerManagerOperatorQuery::ListPeers { reply },
            },
            query => query,
        };
        self.answer_operator_query(query).await;
    }

    async fn answer_operator_query(&self, query: PeerManagerOperatorQuery) {
        match query {
            PeerManagerOperatorQuery::ListPeers { reply } => self.answer_list_peers(reply).await,
            PeerManagerOperatorQuery::GetPeerState { peer, mut reply } => {
                let info = tokio::select! {
                    biased;
                    () = reply.closed() => return,
                    info = self.get_peer_info(&peer) => info,
                };
                let _ = reply.send(info);
            }
            PeerManagerOperatorQuery::HasPeerAddress { address, reply } => {
                let _ = reply.send(self.has_peer_address(address));
            }
            PeerManagerOperatorQuery::SubscribeSessionEvents { reply } => {
                let _ = reply.send(self.session_events_tx.subscribe());
            }
        }
    }

    /// A normal neighbor snapshot keeps mutations fenced while allowing a
    /// bounded number of lightweight operator reads to use their own deadlines.
    /// Further neighbor snapshots wait without starting another session fan-out.
    async fn answer_normal_operator_query(&mut self, query: PeerManagerOperatorQuery) {
        let Some(mut operator_rx) = self.operator_rx.take() else {
            self.answer_operator_query(query).await;
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
                    () = &mut snapshot => break,
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
                                    self.answer_operator_query(query).await;
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

    /// Service queued reads when session policies and manager bookkeeping
    /// agree. Bound each seam so a read flood cannot
    /// prevent the owning transaction from advancing to its next step.
    async fn drain_operator_queries(&mut self, admission: OperatorReadAdmission) {
        if !admission.admits() {
            return;
        }
        for _ in 0..READINESS_QUERY_BUDGET_PER_POLICY_STEP {
            let query = self
                .deferred_operator_queries
                .pop_front()
                .or_else(|| self.operator_rx.as_mut().and_then(|rx| rx.try_recv().ok()));
            let Some(query) = query else { break };
            Box::pin(self.handle_operator_query(query, true)).await;
        }
    }

    /// Answer a readiness query, then yield. The reply wakes the probe's task
    /// into this worker's LIFO slot, which other workers cannot steal; without
    /// the yield it waits until the actor next returns `Pending`, which a
    /// queue of ready commands can defer for Tokio's whole cooperative budget.
    ///
    /// `ActivePeers` (the `GetHealth` count) reads each session's published
    /// state and never waits on a session, so no readiness query fans out.
    async fn handle_readiness_query(&mut self, query: PeerManagerReadinessQuery) {
        match query {
            PeerManagerReadinessQuery::Ping { reply } => {
                let _ = reply.send(());
            }
            PeerManagerReadinessQuery::ActivePeers { reply } => {
                let _ = reply.send(self.active_peer_count());
            }
        }
        tokio::task::yield_now().await;
    }

    /// Drive one owned step while servicing at most one read-only readiness
    /// query at a time and, when `admission` is [`OperatorReadAdmission::Served`],
    /// the bounded operator-read lane as well. The step future is biased
    /// first, so a probe flood cannot delay a completed apply/rollback step.
    /// An admitted operator `ListPeers` is detached (its session replies are
    /// joined by a separate task, with every query enqueued before this wait
    /// resumes); every other admitted read completes before this wait resumes. The
    /// ordinary command receiver is never polled here, so mutations remain
    /// strictly behind the owner.
    ///
    /// A forward policy apply serves reads while it awaits the cohort's RIB
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
                // A deferred update's reservation can take the next free
                // slot; sending it frees the lane for the step's own send.
                // Polled before the read lanes, so a probe flood cannot keep
                // a granted slot unused.
                sent = self.deferred_rib.send_oldest(), if self.deferred_rib.ready() => {
                    if !sent {
                        debug!("RIB exited: discarding deferred RIB updates");
                    }
                }
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
                        Some(query) => Box::pin(self.handle_waiting_operator_query(query)).await,
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
                // As in `await_with_readiness`: ahead of the read and event
                // lanes. Sending is not the step, so it is not charged.
                sent = self.deferred_rib.send_oldest(), if self.deferred_rib.ready() => {
                    remaining = remaining.saturating_sub(attended.elapsed());
                    if !sent {
                        debug!("RIB exited: discarding deferred RIB updates");
                    }
                    if remaining.is_zero() {
                        return None;
                    }
                }
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
                        Some(query) => Box::pin(self.handle_waiting_operator_query(query)).await,
                        None => self.operator_rx = None,
                    }
                    if remaining.is_zero() {
                        return None;
                    }
                }
                // Fast external failover never waits behind this step: link
                // changes dispatch their checks and full-mailbox retries keep
                // being delivered. Both are non-blocking.
                changed = Self::receive_link_change(&mut self.link_check.changes) => {
                    remaining = remaining.saturating_sub(attended.elapsed());
                    if changed {
                        self.handle_links_changed();
                    }
                    if remaining.is_zero() {
                        return None;
                    }
                }
                () = async {
                    match self.link_check.retry_at {
                        Some(deadline) => tokio::time::sleep_until(deadline).await,
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    remaining = remaining.saturating_sub(attended.elapsed());
                    self.retry_link_checks();
                    if remaining.is_zero() {
                        return None;
                    }
                }
            }
        }
    }

    /// Readiness-aware mailbox admission: queue one RIB update on the primary
    /// lane, behind every deferred one, serving readiness while that lane is
    /// full. This covers only the admission wait; a caller whose update
    /// carries a reply awaits it separately. The update keeps the RIB's peer
    /// or export state in step with this actor, so it is never dropped for
    /// time: the send waits for capacity for as long as the RIB runs, and
    /// fails only once the RIB has exited.
    async fn send_rib_update(
        &mut self,
        update: RibUpdate,
        admission: OperatorReadAdmission,
    ) -> Result<(), ()> {
        self.defer_rib_update(None, update)?;
        self.flush_deferred_rib_updates(admission).await
    }

    /// Queue `update` on the primary lane without waiting for room: sent now
    /// when nothing is deferred and the mailbox has room, else after every
    /// update deferred before it, by the run loop or the next flush. `label`
    /// is the `peer` metric label a deletion reaps, which no new session may
    /// emit before the RIB has handled it. Fails only once the RIB has
    /// exited.
    fn defer_rib_update(&mut self, label: Option<String>, update: RibUpdate) -> Result<(), ()> {
        if self.deferred_rib.queue.is_empty() {
            match self.rib_tx.try_send(update) {
                Ok(()) => return Ok(()),
                Err(mpsc::error::TrySendError::Closed(_)) => return Err(()),
                Err(mpsc::error::TrySendError::Full(update)) => {
                    debug!("RIB mailbox full: deferring an ordered RIB update");
                    self.deferred_rib.sender =
                        Some(tokio_util::sync::PollSender::new(self.rib_tx.clone()));
                    self.deferred_rib.queue.push_back((label, update));
                }
            }
        } else {
            self.deferred_rib.queue.push_back((label, update));
        }
        Ok(())
    }

    /// Send every deferred update, oldest first, serving readiness while the
    /// mailbox is full. Fails once the RIB has exited, which discards them.
    async fn flush_deferred_rib_updates(
        &mut self,
        admission: OperatorReadAdmission,
    ) -> Result<(), ()> {
        while !self.deferred_rib.queue.is_empty() {
            // Only the sender moves into the wait, so the wait's own drain
            // arm stays idle and the queue stays with the actor.
            let mut port = self
                .deferred_rib
                .sender
                .take()
                .unwrap_or_else(|| tokio_util::sync::PollSender::new(self.rib_tx.clone()));
            let (port, reserved) = self
                .await_with_readiness(
                    async move {
                        let reserved = std::future::poll_fn(|cx| port.poll_reserve(cx))
                            .await
                            .is_ok();
                        (port, reserved)
                    },
                    admission,
                )
                .await;
            if !self.deferred_rib.send_reserved(port, reserved) {
                return Err(());
            }
        }
        Ok(())
    }

    /// Start no session at `peer` while a deferred deletion under its metric
    /// label has not reached the RIB: handling that deletion reaps the label,
    /// and with it the new session's series. This waits for mailbox room.
    /// Its callers are static adds (operator and reconcile adds run as owned
    /// mutations under the settlement watchdog) and the replacement of a
    /// session whose peer is still in the table. An interface-only bind never
    /// reaches this wait: it retries or refuses first (`bind_would_wait`).
    /// Inbound accepts refuse instead
    /// (`refuse_inbound_behind_deferred_cleanup`).
    pub(super) async fn admit_deferred_rib_updates_for(&mut self, peer: &PeerKey) {
        if self.deferred_rib.reaps(&self.peer_metric_label(peer)) {
            let _ = self
                .flush_deferred_rib_updates(OperatorReadAdmission::Fenced {
                    reason: "a new session waits for a deleted neighbor's RIB cleanup",
                })
                .await;
        }
    }

    /// Refuse an inbound connection rather than wait for mailbox room while a
    /// deleted neighbor's RIB cleanup is deferred: under `peer`'s label, or,
    /// for a connection that would admit a new dynamic neighbor
    /// (`new_identity`), under any label, so no new identity joins the queue
    /// until it drains. The neighbor reconnects on its own timer.
    pub(super) fn refuse_inbound_behind_deferred_cleanup(
        &self,
        peer: &PeerKey,
        new_identity: bool,
    ) -> bool {
        let refused = if new_identity {
            !self.deferred_rib.queue.is_empty()
        } else {
            self.deferred_rib.reaps(&self.peer_metric_label(peer))
        };
        if refused {
            self.metrics.record_inbound_connection_drop(
                rustbgpd_telemetry::reason_labels::InboundConnectionDropReason::RibCleanupPending,
            );
            debug!(peer = %peer, deferred = self.deferred_rib.queue.len(), "dropping inbound connection while a deleted neighbor's RIB cleanup waits for mailbox room");
        }
        refused
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
        clippy::too_many_lines,
        reason = "configured peer construction keeps all explicit lifecycle dependencies and \
                  every actor field's initial state visible"
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
            peers: PeerTable::new(&current_config),
            configured_owners: configured_owners::ConfiguredOwners::new(&current_config),
            deferred_rib: DeferredRibUpdates::default(),
            dampening_control_failed: false,
            max_prefix_latches: HashMap::new(),
            bmp_excluded: BTreeSet::new(),
            next_max_prefix_restart_deadline: None,
            next_max_prefix_latch_generation: 1,
            retiring_sessions: HashMap::new(),
            session_index: HashMap::new(),
            evpn_recovery_retry_at: None,
            evpn_recovery_retry_cursor: 0,
            rx,
            readiness_rx: None,
            operator_rx: None,
            deferred_operator_queries: VecDeque::new(),
            detached_list_peers: JoinSet::new(),
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
            session_notification_depth: 0,
            deferred_session_notifications: VecDeque::new(),
            deferred_session_notification_counts: HashMap::new(),
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
            neighbor_counters: BTreeMap::new(),
            rib_peers: BTreeMap::new(),
            retained_dynamic: BTreeMap::new(),
            retention: retained_dynamic::RetentionChecks::default(),
            dynamic_neighbor_limit: current_config.effective_dynamic_neighbor_limit(),
            inbound_admission: admission::InboundAdmission::from_config(
                &current_config.inbound_admission,
            ),
            notification_backoff_log: admission::LogThrottle::default(),
            dead_lettered_pending: HashMap::new(),
            dead_lettered_pending_order: VecDeque::new(),
            next_session_id: 1,
            tcp_ao_generation: rustbgpd_transport::TcpAoRotationGeneration::STARTUP,
            tcp_ao_rotation: rustbgpd_transport::TcpAoRotationStatus::default(),
            tcp_ao_desired_inventory: None,
            local_forwarding_state: Arc::new(crate::forwarding_state::ForwardingState::new(
                &current_config,
            )),
            // main seeds the RIB from the same config before the actor
            // starts; a resolution failure there exits the daemon.
            conditional_advertisements: current_config
                .conditional_advertisement_set()
                .unwrap_or_default(),
            conditional_reconcile_pending: false,
            conditional_reconcile_retry: None,
            conditional_install_uncertain: false,
            current_config,
            bfd_coupling: None,
            link_check: link_failover::LinkCheckDelivery::default(),
            unnumbered: None,
            unnumbered_runtime: UnnumberedRuntime::default(),
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
            #[cfg(test)]
            test_command_hook: None,
        }
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
        if let Some(key) = self.session_index.remove(&session_id)
            && let Some((_, slot)) = self.peers.recovery_session_mut(&key, session_id)
        {
            *slot = None;
        }
    }

    /// `[rpki] local_revalidation`: RFC 9324 local re-evaluation instead of
    /// inbound Route Refresh on a validation-cache change.
    fn local_revalidation(&self) -> bool {
        self.current_config
            .rpki
            .as_ref()
            .is_some_and(|rpki| rpki.local_revalidation)
    }

    fn build_transport_config(&self, config: &PeerManagerNeighborConfig) -> TransportConfig {
        let families = if config.families.is_empty() {
            vec![(Afi::Ipv4, Safi::Unicast)]
        } else {
            config.families.clone()
        };
        let mut peer = PeerConfig::new(self.local_asn, config.remote_asn, self.router_id);
        peer.remote_asn_external = config.remote_asn_external;
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
        peer.link_local_next_hop = config.link_local_next_hop;
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
        transport.local_forwarding_state =
            Some(rustbgpd_transport::ForwardingStateSource::Configured(
                crate::forwarding_state::configured_kernel_families(&self.current_config),
            ));
        transport.local_address = self.current_config.active_source_for(config.address);
        transport.peer_interface.clone_from(&config.interface);
        transport.peer_scope_id = scope_id;
        transport.max_prefixes = config.max_prefixes;
        transport.max_prefixes_ipv4 = config.max_prefixes_ipv4;
        transport.max_prefixes_ipv6 = config.max_prefixes_ipv6;
        transport.max_prefixes_received_ipv4 = config.max_prefixes_received_ipv4;
        transport.max_prefixes_received_ipv6 = config.max_prefixes_received_ipv6;
        transport.max_prefixes_family = config.max_prefixes_family;
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
        transport.fast_external_failover = config.fast_external_failover;
        transport.link_state = self.link_state_feed(config.fast_external_failover);
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
        // RFC 9324: `[rpki]` is restart-required, so construction-time reads hold.
        transport.local_revalidation = self.local_revalidation();
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

    /// `NOT_FOUND` when a scoped selector names an address whose managed
    /// neighbors all use other interfaces, so a mutation keyed by address
    /// never lands on, and a read never reports, a neighbor the caller did
    /// not select. Checked when the command is served, after any concurrent
    /// reload has settled.
    pub(super) fn stale_neighbor_scope(&self, key: &PeerKey) -> Option<CatalogMutationError> {
        let keys = self.peer_keys_for_address(key.address);
        (!keys.is_empty() && !keys.contains(key))
            .then(|| CatalogMutationError::NotFound(format!("neighbor {key} not found")))
    }

    /// The configured BMP collectors' combined choice for a neighbor at an
    /// address another neighbor holds, `None` without collectors. Configured
    /// collectors decide, connected or not, so a collector reconnecting
    /// never changes admission.
    pub(super) fn bmp_identity_conflict(&self) -> Option<crate::config::BmpIdentityConflict> {
        self.current_config.bmp_identity_conflict()
    }

    /// The other managed neighbors at `peer`'s address. Only a link-local
    /// address can be shared, so a numbered peer never searches the table.
    pub(super) fn peers_sharing_address(&self, peer: &PeerKey) -> Vec<PeerKey> {
        if !matches!(peer.address, IpAddr::V6(v6) if v6.is_unicast_link_local()) {
            return Vec::new();
        }
        self.peers
            .keys()
            .filter(|key| key.address == peer.address && *key != peer)
            .cloned()
            .collect()
    }

    /// Why a neighbor at `peer` cannot share its link-local address with the
    /// neighbors the table holds or `view` configures there: a feature keyed
    /// by the bare address (BFD, TCP MD5, TCP-AO, or, unless every neighbor
    /// there is interface-only, a differing GTSM policy or log level). `None`
    /// when it can, or when no other neighbor is there.
    pub(super) fn shared_address_feature_conflict(
        &self,
        peer: &PeerKey,
        view: &crate::config::Config,
    ) -> Option<String> {
        if !matches!(peer.address, IpAddr::V6(v6) if v6.is_unicast_link_local()) {
            return None;
        }
        let mut keys = self.peers_sharing_address(peer);
        let address = peer.address.to_string();
        for neighbor in &view.neighbors {
            if neighbor.address == address {
                let key = PeerKey::new(peer.address, neighbor.interface.clone());
                if key != *peer && !keys.contains(&key) {
                    keys.push(key);
                }
            }
        }
        if keys.is_empty() {
            return None;
        }
        let records: Vec<_> = keys
            .iter()
            .chain(std::iter::once(peer))
            .filter_map(|key| view.neighbor_record(key))
            .collect();
        if records.len() < 2 {
            return None;
        }
        let records: Vec<&crate::config::Neighbor> =
            records.iter().map(std::borrow::Cow::as_ref).collect();
        view.validate_shared_address_features(&records)
            .err()
            .map(|error| error.to_string())
    }

    /// Refuse a candidate configuration under which the neighbors at one
    /// link-local address, the live endpoints there plus the candidate's
    /// static neighbors, could not share it: a new static neighbor beside a
    /// live one while a BMP collector refuses identity conflicts
    /// (`bmp_identity_conflict`), or a feature keyed by the bare address,
    /// such as a reload enabling BFD on a static neighbor beside a learned
    /// one. Checked before any effect, on every reload and transaction route.
    pub(super) fn validate_live_shared_addresses(
        &self,
        candidate: &crate::config::Config,
    ) -> Result<(), String> {
        let link_local =
            |address: &IpAddr| matches!(address, IpAddr::V6(v6) if v6.is_unicast_link_local());
        let mut by_address: BTreeMap<IpAddr, BTreeSet<PeerKey>> = BTreeMap::new();
        for key in self.peers.keys().filter(|key| link_local(&key.address)) {
            by_address
                .entry(key.address)
                .or_default()
                .insert(key.clone());
        }
        for neighbor in &candidate.neighbors {
            if let Ok(address) = neighbor.address.parse::<IpAddr>()
                && link_local(&address)
            {
                by_address
                    .entry(address)
                    .or_default()
                    .insert(PeerKey::new(address, neighbor.interface.clone()));
            }
        }
        let refuse =
            self.bmp_identity_conflict() == Some(crate::config::BmpIdentityConflict::Refuse);
        for keys in by_address.values().filter(|keys| keys.len() > 1) {
            // Configuration validation refuses two static neighbors at one
            // address under a refusing collector, so the new one meets a
            // live endpoint here.
            if refuse
                && let Some(new) = keys.iter().find(|key| !self.peers.contains_key(key))
                && let Some(holder) = keys.iter().find(|key| self.peers.contains_key(key))
            {
                return Err(format!(
                    "bmp_identity_conflict: neighbor {new} uses {}, which {holder} holds, \
                     and BMP collectors cannot tell the two sessions apart",
                    new.address
                ));
            }
            let records: Vec<_> = keys
                .iter()
                .filter_map(|key| candidate.neighbor_record(key))
                .collect();
            if records.len() < 2 {
                continue;
            }
            let records: Vec<&crate::config::Neighbor> =
                records.iter().map(std::borrow::Cow::as_ref).collect();
            candidate
                .validate_shared_address_features(&records)
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    /// Of the neighbors `sharing` an address, one that BMP monitors, by
    /// label: a managed peer not itself left out of BMP. Configured
    /// collectors see every such peer, so the two would be
    /// indistinguishable.
    pub(super) fn bmp_identity_holder_of(&self, sharing: &[PeerKey]) -> Option<String> {
        sharing
            .iter()
            .find(|key| !self.bmp_excluded.contains(*key))
            .map(PeerKey::label)
    }

    pub(super) fn publish_bmp_excluded_metric(&self) {
        self.metrics
            .set_bmp_identity_excluded_neighbors(self.bmp_excluded.len());
    }

    /// The BMP event sender for `peer`'s session: none for a neighbor left
    /// out of BMP for an identity conflict.
    pub(super) fn session_bmp_tx(&self, peer: &PeerKey) -> Option<mpsc::Sender<BmpEvent>> {
        if self.bmp_excluded.contains(peer) {
            None
        } else {
            self.bmp_tx.clone()
        }
    }

    /// The configured members of peer group `name`, each by its own key.
    pub(super) fn peer_group_member_keys(&self, name: &str) -> Vec<PeerKey> {
        self.current_config
            .neighbors
            .iter()
            .filter(|neighbor| neighbor.peer_group.as_deref() == Some(name))
            .filter_map(|neighbor| {
                Some(PeerKey::new(
                    neighbor.address.parse().ok()?,
                    neighbor.interface.clone(),
                ))
            })
            .collect()
    }

    /// Whether any managed neighbor uses `address`: every neighbor on a
    /// link-local address that several interfaces share counts.
    pub(super) fn has_peer_address(&self, address: IpAddr) -> bool {
        self.peers.keys().any(|key| key.address == address)
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

    /// Dispatch one accepted command without keeping its handler temporaries in
    /// every run-loop poll (including the independently selected reload path).
    /// This is awaited in place: command ownership and cancellation are unchanged.
    #[expect(
        clippy::too_many_lines,
        reason = "command dispatch preserves one exhaustive match over the public actor protocol"
    )]
    async fn dispatch_command(&mut self, cmd: PeerManagerCommand) -> ControlFlow<()> {
        #[cfg(test)]
        if let Some(hook) = &self.test_command_hook {
            hook(&cmd);
        }
        self.operator_read_seam = OperatorReadSeam::Unfenced;
        match cmd {
            PeerManagerCommand::EnablePeerOwned { peer, reply } => {
                let outcome = self.enable_peer_owned(peer).await;
                let _ = reply.send(outcome);
            }
            PeerManagerCommand::DisableDampeningCapacity { notice, reply } => {
                let outcome = self.disable_dampening_capacity(notice).await;
                let _ = reply.send(outcome);
            }
            PeerManagerCommand::ConfiguredOwnerPublication { operation, reply } => {
                let outcome = self.configured_owner_publication(operation).await;
                let _ = reply.send(outcome);
            }
            PeerManagerCommand::Ping { reply } => {
                let _ = reply.send(());
            }
            PeerManagerCommand::ActivePeers { reply } => {
                let _ = reply.send(self.active_peer_count());
            }
            PeerManagerCommand::AddPeer {
                config,
                sync_config_snapshot,
                reply,
            } => {
                let result = self.add_peer(config, sync_config_snapshot).await;
                let _ = reply.send(result);
            }
            PeerManagerCommand::AddConfiguredPeers { configs, reply } => {
                let result = self.add_configured_peers(configs).await;
                let _ = reply.send(result);
            }
            PeerManagerCommand::RuntimeCreatePeer { spec, reply } => {
                let result = self.runtime_create_peer(spec).await;
                let _ = reply.send(result);
            }
            PeerManagerCommand::DeletePeer {
                peer,
                sync_config_snapshot,
                reply,
            } => {
                let result = self.delete_peer_runtime(peer, sync_config_snapshot).await;
                let _ = reply.send(result);
            }
            PeerManagerCommand::OwnedNeighborMutation { mutation, reply } => {
                // Static delete and both dynamic operations validate
                // before effect; static add reports cleanup explicitly.
                let outcome = match mutation {
                    OwnedNeighborMutation::Add(spec) => {
                        let mut effect = lifecycle::RuntimeCreatePeerFailureEffect::NoEffect;
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
                    OwnedNeighborMutation::DeleteInterfaceOnly(interface) => {
                        match self.delete_interface_only_neighbor(&interface) {
                            Ok(()) => OwnedNeighborMutationOutcome::Success,
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
                    } => {
                        match self.add_dynamic_range(prefix, peer_group, remote_asn, description) {
                            Ok(()) => OwnedNeighborMutationOutcome::Success,
                            Err(error) => OwnedNeighborMutationOutcome::RejectedNoEffect(
                                OwnedNeighborMutationError::Dynamic(error),
                            ),
                        }
                    }
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
                if let Some(error) = mutation
                    .neighbor()
                    .and_then(|key| {
                        if self.interface_only_owns(key.interface.as_deref())
                            && (key.address.is_unspecified()
                                || matches!(key.address, IpAddr::V6(address) if address.is_unicast_link_local()))
                        {
                            None
                        } else {
                            self.stale_neighbor_scope(&key)
                        }
                    })
                {
                    let _ = reply.send(OwnedCatalogMutationOutcome::RejectedNoEffect(error));
                    return ControlFlow::Continue(());
                }
                let policy_routes_prior = self.installed_policy_routes_reachability();
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
                            // Static members are reshaped here; interface-only
                            // members rebind on the port reconcile that follows.
                            let affected = self.peer_group_member_keys(&name);
                            self.apply_peer_group_change_owned(event, affected).await
                        }
                    }
                    OwnedCatalogMutation::SyncRpolPolicies {
                        rpol_files,
                        rpol,
                        dataset_bindings,
                    } => {
                        self.sync_rpol_policies_owned(rpol_files, rpol, dataset_bindings)
                            .await
                    }
                    OwnedCatalogMutation::DeletePeerGroup { name } => {
                        self.apply_peer_group_change_owned(
                            ConfigEvent::DeletePeerGroup { name, ack: None },
                            Vec::new(),
                        )
                        .await
                    }
                    OwnedCatalogMutation::SetNeighborPeerGroup {
                        address,
                        interface,
                        peer_group,
                    } => {
                        let peer = PeerKey::new(address, interface.clone());
                        self.apply_peer_group_change_owned(
                            ConfigEvent::SetNeighborPeerGroup {
                                address,
                                interface,
                                peer_group,
                                ack: None,
                            },
                            vec![peer],
                        )
                        .await
                    }
                    OwnedCatalogMutation::ClearNeighborPeerGroup { address, interface } => {
                        let peer = PeerKey::new(address, interface.clone());
                        self.apply_peer_group_change_owned(
                            ConfigEvent::ClearNeighborPeerGroup {
                                address,
                                interface,
                                ack: None,
                            },
                            vec![peer],
                        )
                        .await
                    }
                    OwnedCatalogMutation::SetPolicy { name, definition } => {
                        self.apply_policy_change_owned(
                            ConfigEvent::SetPolicy {
                                name,
                                definition: *definition,
                                ack: None,
                            },
                            None,
                        )
                        .await
                    }
                    OwnedCatalogMutation::DeletePolicy { name } => {
                        self.apply_policy_change_owned(
                            ConfigEvent::DeletePolicy { name, ack: None },
                            None,
                        )
                        .await
                    }
                    OwnedCatalogMutation::SetNeighborSet { name, definition } => {
                        self.apply_policy_change_owned(
                            ConfigEvent::SetNeighborSet {
                                name,
                                definition,
                                ack: None,
                            },
                            None,
                        )
                        .await
                    }
                    OwnedCatalogMutation::DeleteNeighborSet { name } => {
                        self.apply_policy_change_owned(
                            ConfigEvent::DeleteNeighborSet { name, ack: None },
                            None,
                        )
                        .await
                    }
                    OwnedCatalogMutation::SetGlobalImportChain { policy_names } => {
                        self.apply_policy_change_owned(
                            ConfigEvent::SetGlobalImportChain {
                                policy_names,
                                ack: None,
                            },
                            None,
                        )
                        .await
                    }
                    OwnedCatalogMutation::SetGlobalExportChain { policy_names } => {
                        self.apply_policy_change_owned(
                            ConfigEvent::SetGlobalExportChain {
                                policy_names,
                                ack: None,
                            },
                            None,
                        )
                        .await
                    }
                    OwnedCatalogMutation::ClearGlobalImportChain => {
                        self.apply_policy_change_owned(
                            ConfigEvent::ClearGlobalImportChain { ack: None },
                            None,
                        )
                        .await
                    }
                    OwnedCatalogMutation::ClearGlobalExportChain => {
                        self.apply_policy_change_owned(
                            ConfigEvent::ClearGlobalExportChain { ack: None },
                            None,
                        )
                        .await
                    }
                    OwnedCatalogMutation::SetNeighborImportChain {
                        address,
                        interface,
                        policy_names,
                    } => {
                        let peer = PeerKey::new(address, interface.clone());
                        self.apply_policy_change_owned(
                            ConfigEvent::SetNeighborImportChain {
                                address,
                                interface,
                                policy_names,
                                ack: None,
                            },
                            Some(vec![peer]),
                        )
                        .await
                    }
                    OwnedCatalogMutation::SetNeighborExportChain {
                        address,
                        interface,
                        policy_names,
                    } => {
                        let peer = PeerKey::new(address, interface.clone());
                        self.apply_policy_change_owned(
                            ConfigEvent::SetNeighborExportChain {
                                address,
                                interface,
                                policy_names,
                                ack: None,
                            },
                            Some(vec![peer]),
                        )
                        .await
                    }
                    OwnedCatalogMutation::ClearNeighborImportChain { address, interface } => {
                        let peer = PeerKey::new(address, interface.clone());
                        self.apply_policy_change_owned(
                            ConfigEvent::ClearNeighborImportChain {
                                address,
                                interface,
                                ack: None,
                            },
                            Some(vec![peer]),
                        )
                        .await
                    }
                    OwnedCatalogMutation::ClearNeighborExportChain { address, interface } => {
                        let peer = PeerKey::new(address, interface.clone());
                        self.apply_policy_change_owned(
                            ConfigEvent::ClearNeighborExportChain {
                                address,
                                interface,
                                ack: None,
                            },
                            Some(vec![peer]),
                        )
                        .await
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
                self.answer_normal_operator_query(PeerManagerOperatorQuery::ListPeers { reply })
                    .await;
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
                self.handle_query_policy_event_history(peer.as_ref(), limit, reply);
            }
            PeerManagerCommand::QuerySessionEventHistory {
                peer,
                event_types,
                limit,
                reply,
            } => {
                self.handle_query_session_event_history(peer.as_ref(), &event_types, limit, reply);
            }
            PeerManagerCommand::DiffRuntimeConfig {
                candidate_toml,
                reply,
            } => {
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
                    () = reply.closed() => return ControlFlow::Continue(()),
                    result = &mut planning => result,
                };
                let _ = reply.send(result);
            }
            PeerManagerCommand::CommitConfigSnapshotStage { reply } => {
                self.local_forwarding_state
                    .publish_fib(&self.current_config.fib_tables);
                if let Some(prior) = self.staged_policy_routes_prior.take() {
                    self.reap_retired_policy_routes(&prior);
                }
                self.config_snapshot_staged = false;
                let _ = reply.send(());
            }
            PeerManagerCommand::RuntimeConfigSnapshot { reply } => {
                let result = raw_config_document_bounded(&mut self.current_config)
                    .map_err(|error| {
                        format!("failed to serialize runtime config snapshot: {error}")
                    })
                    .map(
                        |toml| rustbgpd_api::peer_types::RuntimeConfigSnapshotReply {
                            toml,
                            rpol_files: self.current_config.policy.rpol_files.clone(),
                            rpol: self.current_config.policy.rpol.clone(),
                        },
                    );
                let _ = reply.send(result);
            }
            PeerManagerCommand::EffectiveRuntimeConfig { reply } => {
                let _ = reply.send(self.current_config.effective_redacted_toml());
            }
            PeerManagerCommand::ApplyResolvedPolicySnapshot { targets, reply } => {
                // API publication rollback restores policy chains before the
                // staged config. Reads report each source's current values.
                let result = self
                    .apply_resolved_policy_snapshot_with_prestage_reads(
                        targets,
                        false,
                        OperatorReadAdmission::Served,
                    )
                    .await
                    .map_err(policy::PolicySnapshotFailure::into_apply_error);
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
                // A committed transaction event replaces the whole
                // config, dataset bindings included.
                self.peers.set_datasets(&self.current_config);
                if result.is_ok() {
                    self.reconcile_stale_dynamic_max_prefix_restarts();
                }
                let _ = reply.send(result);
            }
            PeerManagerCommand::GetPeerState { peer, reply } => {
                self.answer_normal_operator_query(PeerManagerOperatorQuery::GetPeerState {
                    peer,
                    reply,
                })
                .await;
            }
            PeerManagerCommand::HasPeerAddress { address, reply } => {
                let _ = reply.send(self.has_peer_address(address));
            }
            PeerManagerCommand::EnablePeer { peer, reply } => {
                let result = self.enable_peer(peer).await;
                let _ = reply.send(result);
            }
            PeerManagerCommand::DisablePeer {
                peer,
                reason,
                reply,
            } => {
                let result = self.disable_peer(peer, reason).await;
                let _ = reply.send(result);
            }
            PeerManagerCommand::ResetPeer {
                peer,
                reason,
                reply,
            } => {
                let result = self.reset_peer(peer, reason).await;
                let _ = reply.send(result);
            }
            PeerManagerCommand::ResetEvpnRecoverySession { request, reply } => {
                self.reset_evpn_recovery_session(request, reply);
            }
            PeerManagerCommand::SoftResetIn {
                peer,
                families,
                reply,
            } => {
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
            PeerManagerCommand::SoftResetImportValidationDependents { delta, reply } => {
                let result = if self.local_revalidation() {
                    self.revalidate_import_validation_dependents(delta).await
                } else {
                    self.soft_reset_import_validation_dependents(policy::validation_dependency(
                        &delta,
                    ))
                    .await
                };
                let _ = reply.send(result);
            }
            PeerManagerCommand::SetGracefulShutdown {
                peer,
                enabled,
                reply,
            } => {
                let result = self.set_graceful_shutdown(peer, enabled).await;
                let _ = reply.send(result);
            }
            PeerManagerCommand::AcceptInbound {
                stream,
                peer_addr,
                tcp_ao_info,
                tcp_ao_generation,
            } => {
                self.accept_inbound(stream, peer_addr, tcp_ao_info, tcp_ao_generation)
                    .await;
            }
            PeerManagerCommand::ApplyTcpAoRotation {
                generation,
                operation,
                listener_keys,
                current_listener_keys,
                static_keyrings,
                current_static_keyrings,
                reply,
            } => {
                let result = self
                    .apply_tcp_ao_rotation(
                        generation,
                        operation,
                        &listener_keys,
                        &current_listener_keys,
                        &static_keyrings,
                        &current_static_keyrings,
                    )
                    .await;
                let _ = reply.send(result);
            }
            PeerManagerCommand::PreflightTcpAoRotation {
                generation,
                operation,
                listener_keys,
                current_listener_keys,
                static_keyrings,
                current_static_keyrings,
                reply,
            } => {
                let result = self
                    .preflight_tcp_ao_rotation(
                        generation,
                        operation,
                        &listener_keys,
                        &current_listener_keys,
                        &static_keyrings,
                        &current_static_keyrings,
                    )
                    .await;
                let _ = reply.send(result);
            }
            PeerManagerCommand::MarkTcpAoRotationFailed {
                generation,
                operation,
                error,
                reply,
            } => {
                self.mark_tcp_ao_rotation_failed(generation, operation, &error);
                let _ = reply.send(Ok(()));
            }
            PeerManagerCommand::ReconcilePeers {
                added,
                removed,
                changed,
                reply,
            } => {
                let policy_routes_prior = self.installed_policy_routes_reachability();
                let result = self.reconcile_peers(added, removed, changed).await;
                if result.authority == PeerReconcileAuthority::Known && result.failures.is_empty() {
                    self.reap_retired_policy_routes(&policy_routes_prior);
                }
                let _ = reply.send(result);
            }
            PeerManagerCommand::HotUpdatePeer { config, reply } => {
                let policy_routes_prior = self.installed_policy_routes_reachability();
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
                self.current_config.policy.reject_retention.enabled = reject_retention_enabled;
                self.current_config.policy.reject_retention.capacity = reject_retention_capacity;
                let _ = reply.send(());
            }
            PeerManagerCommand::RefreshDatasetDependents {
                swapped,
                failed,
                reply,
            } => {
                let result = self.refresh_dataset_dependents(&swapped, &failed).await;
                let _ = reply.send(result);
            }
            PeerManagerCommand::ListPolicies { reply } => {
                let _ = reply.send(named_policies_from_config(&self.current_config));
            }
            PeerManagerCommand::GetValidationPolicyPosture { reply } => {
                let _ = reply.send(self.validation_policy_posture());
            }
            PeerManagerCommand::ExplainImportPolicy {
                peer,
                afi,
                safi,
                prefix,
                path_id,
                reply,
            } => {
                // Resolve the selected neighbor's session, scope included,
                // and forward to its task. A missing/exited task is a
                // genuine no-session result; timeout remains
                // distinct so overload cannot masquerade as
                // absence (LAN-661).
                let result = match self.peers.get(&peer) {
                    _ if self.stale_neighbor_scope(&peer).is_some() => None,
                    Some(managed) => Some(
                        managed
                            .handle()
                            .explain_import_policy_timeout(
                                afi,
                                safi,
                                prefix,
                                path_id,
                                EXPLAIN_QUERY_TIMEOUT,
                            )
                            .await,
                    ),
                    None => Some(SessionQueryOutcome::SessionGone),
                };
                let _ = reply.send(result);
            }
            PeerManagerCommand::ListRejectedRoutes { peer, reply } => {
                // LAN-472: same resolution + bounded-forward
                // shape as ExplainImportPolicy. A missing/exited
                // session maps to NOT_FOUND, while a stalled live
                // task remains an explicit timeout.
                let result = match self.peers.get(&peer) {
                    _ if self.stale_neighbor_scope(&peer).is_some() => None,
                    Some(managed) => Some(
                        managed
                            .handle()
                            .list_rejected_routes_timeout(EXPLAIN_QUERY_TIMEOUT)
                            .await,
                    ),
                    None => Some(SessionQueryOutcome::SessionGone),
                };
                let _ = reply.send(result);
            }
            PeerManagerCommand::GetPolicy { name, reply } => {
                let _ = reply.send(named_policy_from_config(&self.current_config, &name));
            }
            PeerManagerCommand::SetPolicy {
                name,
                definition,
                reply,
            } => {
                let result = self
                    .apply_policy_change(
                        ConfigEvent::SetPolicy {
                            name,
                            definition,
                            ack: None,
                        },
                        None,
                    )
                    .await;
                let _ = reply.send(result);
            }
            PeerManagerCommand::DeletePolicy { name, reply } => {
                let result = self
                    .apply_policy_change(ConfigEvent::DeletePolicy { name, ack: None }, None)
                    .await;
                let _ = reply.send(result);
            }
            PeerManagerCommand::ListNeighborSets { reply } => {
                let _ = reply.send(named_neighbor_sets_from_config(&self.current_config));
            }
            PeerManagerCommand::GetNeighborSet { name, reply } => {
                let _ = reply.send(named_neighbor_set_from_config(&self.current_config, &name));
            }
            PeerManagerCommand::SetNeighborSet {
                name,
                definition,
                reply,
            } => {
                let result = self
                    .apply_policy_change(
                        ConfigEvent::SetNeighborSet {
                            name,
                            definition,
                            ack: None,
                        },
                        None,
                    )
                    .await;
                let _ = reply.send(result);
            }
            PeerManagerCommand::DeleteNeighborSet { name, reply } => {
                let result = self
                    .apply_policy_change(ConfigEvent::DeleteNeighborSet { name, ack: None }, None)
                    .await;
                let _ = reply.send(result);
            }
            PeerManagerCommand::GetGlobalPolicyChains { reply } => {
                let _ = reply.send(global_policy_chains_from_config(&self.current_config));
            }
            PeerManagerCommand::SetGlobalImportChain {
                policy_names,
                reply,
            } => {
                let result = self
                    .apply_policy_change(
                        ConfigEvent::SetGlobalImportChain {
                            policy_names,
                            ack: None,
                        },
                        None,
                    )
                    .await;
                let _ = reply.send(result);
            }
            PeerManagerCommand::SetGlobalExportChain {
                policy_names,
                reply,
            } => {
                let result = self
                    .apply_policy_change(
                        ConfigEvent::SetGlobalExportChain {
                            policy_names,
                            ack: None,
                        },
                        None,
                    )
                    .await;
                let _ = reply.send(result);
            }
            PeerManagerCommand::ClearGlobalImportChain { reply } => {
                let result = self
                    .apply_policy_change(ConfigEvent::ClearGlobalImportChain { ack: None }, None)
                    .await;
                let _ = reply.send(result);
            }
            PeerManagerCommand::ClearGlobalExportChain { reply } => {
                let result = self
                    .apply_policy_change(ConfigEvent::ClearGlobalExportChain { ack: None }, None)
                    .await;
                let _ = reply.send(result);
            }
            PeerManagerCommand::SetHonorGracefulShutdown { enabled, reply } => {
                let policy_routes_prior = self.installed_policy_routes_reachability();
                let result = self.set_honor_graceful_shutdown(enabled).await;
                if result.is_ok() {
                    self.reap_retired_policy_routes(&policy_routes_prior);
                }
                let _ = reply.send(result);
            }
            PeerManagerCommand::SetHonorBlackhole { enabled, reply } => {
                let policy_routes_prior = self.installed_policy_routes_reachability();
                let result = self.set_honor_blackhole(enabled).await;
                if result.is_ok() {
                    self.reap_retired_policy_routes(&policy_routes_prior);
                }
                let _ = reply.send(result);
            }
            PeerManagerCommand::GetNeighborPolicyChains { peer, reply } => {
                let _ = reply.send(neighbor_policy_chains_from_config(
                    &self.current_config,
                    &peer,
                ));
            }
            PeerManagerCommand::SetNeighborImportChain {
                address,
                policy_names,
                reply,
            } => {
                let result = self
                    .apply_policy_change(
                        ConfigEvent::SetNeighborImportChain {
                            address,
                            interface: None,
                            policy_names,
                            ack: None,
                        },
                        Some(vec![PeerKey::new(address, None)]),
                    )
                    .await;
                let _ = reply.send(result);
            }
            PeerManagerCommand::SetNeighborExportChain {
                address,
                policy_names,
                reply,
            } => {
                let result = self
                    .apply_policy_change(
                        ConfigEvent::SetNeighborExportChain {
                            address,
                            interface: None,
                            policy_names,
                            ack: None,
                        },
                        Some(vec![PeerKey::new(address, None)]),
                    )
                    .await;
                let _ = reply.send(result);
            }
            PeerManagerCommand::ClearNeighborImportChain { address, reply } => {
                let result = self
                    .apply_policy_change(
                        ConfigEvent::ClearNeighborImportChain {
                            address,
                            interface: None,
                            ack: None,
                        },
                        Some(vec![PeerKey::new(address, None)]),
                    )
                    .await;
                let _ = reply.send(result);
            }
            PeerManagerCommand::ClearNeighborExportChain { address, reply } => {
                let result = self
                    .apply_policy_change(
                        ConfigEvent::ClearNeighborExportChain {
                            address,
                            interface: None,
                            ack: None,
                        },
                        Some(vec![PeerKey::new(address, None)]),
                    )
                    .await;
                let _ = reply.send(result);
            }
            PeerManagerCommand::ListPeerGroups { reply } => {
                let _ = reply.send(named_peer_groups_from_config(&self.current_config));
            }
            PeerManagerCommand::GetPeerGroup { name, reply } => {
                let _ = reply.send(named_peer_group_from_config(&self.current_config, &name));
            }
            PeerManagerCommand::SetPeerGroup {
                name,
                definition,
                reply,
            } => {
                let event = ConfigEvent::SetPeerGroup {
                    name: name.clone(),
                    definition: definition.clone(),
                    ack: None,
                };
                let result = if self.peer_group_policy_only_update(&name, &definition) {
                    self.apply_policy_change(event, None).await
                } else {
                    // Static members are reshaped here; interface-only members
                    // rebind on the port reconcile that follows.
                    let affected = self.peer_group_member_keys(&name);
                    self.apply_peer_group_change(event, affected).await
                };
                let _ = reply.send(result);
            }
            PeerManagerCommand::DeletePeerGroup { name, reply } => {
                let result = self
                    .apply_peer_group_change(
                        ConfigEvent::DeletePeerGroup { name, ack: None },
                        Vec::new(),
                    )
                    .await;
                let _ = reply.send(result);
            }
            PeerManagerCommand::SetNeighborPeerGroup {
                address,
                peer_group,
                reply,
            } => {
                let result = self
                    .apply_peer_group_change(
                        ConfigEvent::SetNeighborPeerGroup {
                            address,
                            interface: None,
                            peer_group,
                            ack: None,
                        },
                        vec![PeerKey::new(address, None)],
                    )
                    .await;
                let _ = reply.send(result);
            }
            PeerManagerCommand::ClearNeighborPeerGroup { address, reply } => {
                let result = self
                    .apply_peer_group_change(
                        ConfigEvent::ClearNeighborPeerGroup {
                            address,
                            interface: None,
                            ack: None,
                        },
                        vec![PeerKey::new(address, None)],
                    )
                    .await;
                let _ = reply.send(result);
            }
            PeerManagerCommand::GetNeighborPeerGroupMembership { address, reply } => {
                let _ = reply.send(neighbor_peer_group_from_config(
                    &self.current_config,
                    address,
                ));
            }
            PeerManagerCommand::ListDynamicRanges { reply } => {
                let ranges = self
                    .dynamic_ranges
                    .iter()
                    .map(|r| DynamicNeighborInfo {
                        prefix: format!("{}/{}", r.addr, r.prefix_len),
                        peer_group: r.peer_group.clone(),
                        remote_asn: r.remote_asn,
                        description: r.description.clone().unwrap_or_default(),
                    })
                    .collect();
                let _ = reply.send(ranges);
            }
            PeerManagerCommand::AddDynamicRange {
                prefix,
                peer_group,
                remote_asn,
                description,
                reply,
            } => {
                let result = self.add_dynamic_range(prefix, peer_group, remote_asn, description);
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
                // Sessions send their final PeerDown while they stop.
                self.deferred_rib.release_reservation();
                let drained = self.peers.drain();
                let mut shutdowns = JoinSet::new();
                for (addr, managed) in drained {
                    let (primary, _, mut managed) = managed.into_parts();
                    if shutdowns.len() == PEER_SHUTDOWN_CONCURRENCY
                        && let Some(Err(error)) = shutdowns.join_next().await
                    {
                        error!(%error, "peer shutdown worker failed");
                    }
                    shutdowns.spawn(async move {
                        debug!(peer = %addr, "shutting down peer");
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
                            primary,
                        )
                        .await
                        .joined()
                        {
                            debug!(peer = %addr, "peer shut down");
                        }
                    });
                }
                while let Some(result) = shutdowns.join_next().await {
                    if let Err(error) = result {
                        error!(%error, "peer shutdown worker failed");
                    }
                }
                // Final lifetime-0 Router Advertisements (RFC 4861 §6.2.5).
                if let Some(unnumbered) = self.unnumbered.take() {
                    unnumbered.shutdown().await;
                }
                // Deleted neighbors' cleanup still waiting for mailbox room
                // ends with the daemon: no later session can reuse what it
                // would have released.
                if !self.deferred_rib.queue.is_empty() {
                    info!(
                        updates = self.deferred_rib.queue.len(),
                        "peer manager stopped with deferred RIB updates unsent"
                    );
                }
                return ControlFlow::Break(());
            }
        }
        self.finish_operator_seam();
        ControlFlow::Continue(())
    }

    /// The owner loop's reconciles, in dependency order. Retiring an
    /// interface-only endpoint can ask for a conditional-advertisement
    /// reconcile, which then runs in the same step: the loop may otherwise
    /// wait with nothing due to wake it, leaving the retired gate installed.
    async fn run_due_reconciles(&mut self) {
        if self.unnumbered_reconcile_due() {
            self.reconcile_unnumbered().await;
        }
        if self.conditional_reconcile_pending {
            self.reconcile_conditional_advertisements().await;
        }
    }

    /// Run the `PeerManager` event loop until shutdown or channel close.
    #[expect(
        clippy::too_many_lines,
        reason = "peer manager run loop centralizes command, notification, and reload orchestration"
    )]
    pub async fn run(mut self) {
        if let Err(error) = self.publish_initial_configured_owners().await {
            error!(%error, "initial configured-owner publication failed");
            return;
        }
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
            if self.dampening_control_failed {
                tracing::error!(
                    "dampening source retirement is unacknowledged; terminating peer manager"
                );
                return;
            }
            // Between run-loop steps no roster batch is open, and in test
            // builds the published import roster is exactly the peer table
            // and live dataset bindings.
            self.peers.settle_abandoned_batches();
            #[cfg(test)]
            self.assert_import_roster_projection();
            debug_assert!(
                self.session_notification_depth == 0
                    && self.deferred_session_notifications.is_empty()
                    && self.deferred_session_notification_counts.is_empty()
            );
            // Link-local BFD scope moves run after the link checks they
            // follow were dispatched, never ahead of them.
            self.run_due_bfd_scope_refresh().await;
            self.run_due_reconciles().await;
            let bfd_retry_at = self.bfd_retry_deadline();
            let evpn_recovery_retry_at = self.evpn_recovery_retry_at;
            let link_check_retry_at = self.link_check.retry_at;
            let bfd_scope_retry_at = self.bfd_scope_deadline();
            let max_prefix_restart_deadline = self.next_max_prefix_restart_deadline;
            let conditional_retry_at = self.conditional_reconcile_retry.map(|(at, _)| at);
            let unnumbered_retry_at = self.unnumbered_retry_at();
            if self.retention.admission_dirty && !self.config_snapshot_staged {
                self.release_unadmitted_retained_dynamic();
            }
            self.reconcile_retained_dynamic_candidates();
            if !self.retention.orphaned.is_empty() {
                self.release_orphaned_retained_handles();
            }
            let retained_dynamic_check_at = self.next_retained_dynamic_check();
            if self.deferred_rib.sender.is_none() && !self.deferred_rib.queue.is_empty() {
                // Only a flush dropped mid-wait leaves its updates without
                // a sender; none is, but nothing queued is ever stranded.
                self.deferred_rib.sender =
                    Some(tokio_util::sync::PollSender::new(self.rib_tx.clone()));
            }
            tokio::select! {
                query = Self::receive_readiness_query(&mut self.readiness_rx) => {
                    match query {
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
                    if Box::pin(self.dispatch_command(cmd)).await.is_break() {
                        return;
                    }
                }
                internal = Self::receive_internal_command(&mut self.internal_rx) => {
                    self.operator_read_seam = OperatorReadSeam::Unfenced;
                    match internal {
                        Some(InternalCommand::PreflightReloadGeneration { candidate, route, reply }) => {
                            let _ = reply.send(self.preflight_reload_generation(&candidate, route));
                        }
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
                            self.replace_current_config(*config);
                            self.local_forwarding_state.publish_fib(&self.current_config.fib_tables);
                            self.config_snapshot_staged = false;
                            self.staged_policy_routes_prior = None;
                        // #338: rebuild the live dynamic-neighbor accept-matcher so
                        // [[dynamic_neighbors]] edits applied via SIGHUP take effect
                        // (previously only `current_config` was swapped). The shared
                        // runtime-config lock guarantees the reloaded config already
                        // reflects any accepted runtime CRUD, so a plain re-parse is
                        // correct — no merge/provenance needed.
                        self.dynamic_ranges = Self::parse_dynamic_ranges(&self.current_config);
                        self.retention.admission_dirty = true;
                        self.reconcile_stale_dynamic_max_prefix_restarts();
                        self.dynamic_neighbor_limit =
                            self.current_config.effective_dynamic_neighbor_limit();
                        self.metrics.set_dynamic_neighbor_capacity(
                            self.dynamic_peer_count,
                            self.dynamic_neighbor_limit,
                        );
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
                            read_coordinator,
                            mut reply,
                        }) => {
                            if let Some(coordinator) = read_coordinator {
                                let Some(permit) = coordinator.try_acquire() else {
                                    let _ = reply.send(Err(RuntimeConfigTransactionPlanError::Unavailable(
                                        "runtime config is changing or unavailable; retry the rollback preview".into(),
                                    )));
                                    continue;
                                };
                                // This actor owns current_config until planning returns.
                                // Do not hold mutation admission through RIB waits.
                                drop(permit);
                            }
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
                            let result = {
                                let planning = self.plan_preloaded_config_transaction(
                                    &mut candidate,
                                    expected_runtime_snapshot_token.as_deref(),
                                );
                                tokio::pin!(planning);
                                tokio::select! {
                                    biased;
                                    () = reply.closed() => continue,
                                    result = &mut planning => result,
                                }
                            }
                                .map(|plan| PlannedTransactionConfig {
                                    plan,
                                    candidate: Box::new(candidate),
                                });
                            let _ = reply.send(result);
                        }
                        Some(InternalCommand::PlanTransactionConfig {
                            mut candidate,
                            expected_runtime_snapshot_token,
                            mut reply,
                        }) => {
                            let result = {
                                let planning = self.plan_preloaded_config_transaction(
                                    &mut candidate,
                                    expected_runtime_snapshot_token.as_deref(),
                                );
                                tokio::pin!(planning);
                                tokio::select! {
                                    biased;
                                    () = reply.closed() => continue,
                                    result = &mut planning => result,
                                }
                            }
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
                                // ADR-0142: discovery may have bound an endpoint since
                                // the plan. Recheck in this owner turn, before the
                                // candidate is installed; once it is staged, binding
                                // waits for the commit or rollback.
                                TransactionConfigScope::Full => self
                                    .unnumbered_preflight(&candidate)
                                    .map(|()| *candidate),
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
                                    let previous = self.replace_current_config(staged,
                                    );
                                    self.dynamic_ranges =
                                        Self::parse_dynamic_ranges(&self.current_config);
                                    self.retention.admission_dirty = true;
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
                            self.replace_current_config(*rollback.previous);
                            self.dynamic_ranges = Self::parse_dynamic_ranges(&self.current_config);
                            self.retention.admission_dirty = true;
                            self.reconcile_stale_dynamic_max_prefix_restarts();
                            self.dynamic_neighbor_limit =
                                self.current_config.effective_dynamic_neighbor_limit();
                            self.metrics.set_dynamic_neighbor_capacity(
                                self.dynamic_peer_count,
                                self.dynamic_neighbor_limit,
                            );
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
                sent = self.deferred_rib.send_oldest(), if self.deferred_rib.ready() => {
                    if !sent {
                        debug!("RIB exited: discarding deferred RIB updates");
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
                () = async {
                    if let Some(deadline) = bfd_retry_at {
                        tokio::time::sleep_until(deadline).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => self.retry_bfd_commands(bfd_state_change_rx.as_ref()),
                () = async {
                    if let Some(deadline) = evpn_recovery_retry_at {
                        tokio::time::sleep_until(deadline).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => self.retry_evpn_recovery_resets(),
                () = async {
                    if let Some(deadline) = link_check_retry_at {
                        tokio::time::sleep_until(deadline).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => self.retry_link_checks(),
                () = async {
                    if let Some(deadline) = bfd_scope_retry_at {
                        tokio::time::sleep_until(deadline).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => self.bfd_scope_retry_due(),
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
                changed = Self::receive_link_change(&mut self.link_check.changes) => {
                    if changed {
                        self.handle_links_changed();
                    }
                }
                event = Self::receive_discovery_event(&mut self.unnumbered) => {
                    if let Some(event) = event {
                        self.handle_discovery_event(event);
                    }
                }
                () = async {
                    match unnumbered_retry_at {
                        Some(deadline) => tokio::time::sleep_until(deadline).await,
                        None => std::future::pending::<()>().await,
                    }
                } => self.unnumbered_retry_due(),
                () = async {
                    match retained_dynamic_check_at {
                        Some(deadline) => tokio::time::sleep_until(deadline).await,
                        None => std::future::pending::<()>().await,
                    }
                } => self.check_due_retained_dynamic(),
                answer = Self::receive_retention_pass(&mut self.retention.pass) => {
                    self.finish_retention_pass(answer);
                }
                () = async {
                    if let Some(interval) = bmp_stats_interval.as_mut() {
                        interval.tick().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    // The BMP sampling waits, each bounded by
                    // PEER_QUERY_TIMEOUT, do not drive deferred admission.
                    self.deferred_rib.send_if_granted();
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
                () = async move {
                    if let Some(deadline) = conditional_retry_at {
                        tokio::time::sleep_until(deadline).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => self.conditional_reconcile_pending = true,
            }
        }
    }
}

#[cfg(test)]
mod tests;
