//! Daemon-side Ethernet Segment orchestrator — Gate 8.
//!
//! Pairs the per-ESI [`LocalEsOriginator`] / [`LocalEadPerEsOriginator`]
//! / [`LocalEadPerEviOriginator`] state machines with the
//! [`DfElection`] state machine and drives them from RIB events.
//!
//! ## Lifecycle per ESI
//!
//! 1. **Spawn** — daemon main reads `[[ethernet_segments]]`, resolves
//!    via `Config::resolve_ethernet_segments`, hands the resulting
//!    `Vec<EthernetSegment>` here.
//! 2. **Startup** — for each ES: emit the Type 4 ES route (with the
//!    auto-derived ES-Import RT extcomm) + Type 1 EAD-per-ES route
//!    (with the ESI Label extcomm), run DF election with the local
//!    PE as sole candidate (the local PE is DF for all member VNIs
//!    at startup because no peers have been observed yet), emit one
//!    Type 1 EAD-per-EVI per member VNI.
//! 3. **Steady state** — subscribe to the
//!    [`rustbgpd_rib::EvpnRouteEvent`] broadcast; on every Type 4
//!    event for a tracked ESI, re-gather candidates from the RIB
//!    via `QueryEvpnRoutes`, re-run election, update the Prometheus
//!    gauge / counter, and fire `on_vni_role_changed` so the
//!    per-VNI originator's role state stays in sync. The Gate 8
//!    EAD-per-EVI wire shape is role-independent (RFC 7432 §14), so
//!    a flip on an already-advertising VNI emits no wire churn — the
//!    operator-facing signal is `evpn_df_role_changes_total`. Gate 8b
//!    will layer aliasing extcomms on top and re-introduce the
//!    wire-side re-emit for actual shape-changing events.
//! 4. **Shutdown** — drain all per-ESI Type 1/4 routes before peer
//!    sessions tear down so peer state converges from the
//!    most-specific NLRI shape down (same convention as the
//!    existing originator + SVI tasks).
//!
//! ## Scope (Gate 8 + Gate 8b prep)
//!
//! The daemon-side path here ships the **observation** half of the
//! gate plus the wire-side extcomms peers need to import / filter
//! the segment (ES-Import RT on Type 4, ESI Label on Type 1
//! EAD-per-ES). Forwarding-blocking enforcement (split-horizon
//! drops on non-DF receivers, aliasing-driven backup paths,
//! mass-withdraw on `AS_PATH` change, DF-role-aware MAC origination)
//! remains Gate 8b — see ADR-0057.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustbgpd_evpn::{
    AcGateState, BumEnforcementTable, DfAlgorithm, DfCandidate, DfElection, DfRole,
    EthernetSegment, EvpnInstance, EvpnInstanceId, EvpnInstanceTable, LocalEadPerEsOriginator,
    LocalEadPerEviOriginator, LocalEsOriginator, OriginationAction, RedundancyMode,
    SameEsiBiasTable,
};
use rustbgpd_rib::AttrSet;
use rustbgpd_rib::{EvpnRouteEvent, RibRowFilter, RibUpdate, route::EvpnRibRoute};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{
    AsPath, EthernetSegmentIdentifier, EvpnEadPerEs, EvpnEadPerEvi, EvpnEs, EvpnRoute,
    EvpnRouteKey, MplsLabel, Origin, PathAttribute, RouteDistinguisher,
};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::evpn_ack::{PendingRibOps, RibAckOutcome, send_and_ack};
use crate::evpn_es_link_drain::EsLinkBindings;
use crate::evpn_originator::{LOCAL_PEER, instance_extcomms};

/// Boot-timer ceiling: any DF wait due within this
/// long of actor start waits for every established EVPN session's End-of-RIB
/// (remote routes cannot be present earlier), but never past the ceiling.
const BOOT_RECOVERY_MAX_WAIT: Duration = Duration::from_secs(30);
/// Re-check interval for the boot-timer End-of-RIB condition.
const BOOT_SYNC_POLL: Duration = Duration::from_secs(1);

/// Cloneable ADR-0063 runtime control surface for the Ethernet
/// Segment owner.
///
/// The full handle remains owned by coordinated shutdown. Runtime
/// commits publish complete ES snapshots through this control; the
/// segment actor remains the only Type 1/4 originator.
#[derive(Clone, Debug)]
#[allow(
    clippy::struct_field_names,
    reason = "the _tx postfix identifies each field as an actor-watch sender"
)]
pub(crate) struct EvpnSegmentRuntimeControl {
    instances_tx: watch::Sender<Arc<EvpnInstanceTable>>,
    segments_tx: watch::Sender<Arc<Vec<EthernetSegment>>>,
    drained_esis_tx: watch::Sender<Arc<BTreeSet<EthernetSegmentIdentifier>>>,
    df_status_rx: watch::Receiver<Arc<SegmentDfStatusTable>>,
    /// Daemon wiring only: the actor task, started on the first
    /// committed Ethernet Segment (see [`Self::with_deferred_start`]).
    slot: Option<Arc<std::sync::Mutex<SegmentActorSlot>>>,
    /// Test-only: shutdown closes the slot at the next start decision,
    /// after the converge's publishes landed.
    #[cfg(test)]
    close_at_next_start: Arc<std::sync::atomic::AtomicBool>,
    /// Test-only: the running actor's handle that hook-driven close took,
    /// kept for the test's shutdown drain.
    #[cfg(test)]
    closed_handle: Arc<std::sync::Mutex<Option<EvpnSegmentHandle>>>,
}

/// Starts a prepared segment actor task.
pub(crate) type StartSegmentActor = Box<dyn FnOnce() -> EvpnSegmentHandle + Send>;

/// Where the daemon's segment actor task lives. Its channels exist from
/// startup, so the runtime control, drain hook and link-drain
/// coordinator are wired once whether or not a segment is configured.
enum SegmentActorSlot {
    Pending(StartSegmentActor),
    Running(EvpnSegmentHandle),
    Closed,
}

impl std::fmt::Debug for SegmentActorSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Pending(_) => "Pending",
            Self::Running(_) => "Running",
            Self::Closed => "Closed",
        })
    }
}

impl EvpnSegmentRuntimeControl {
    /// Hold the actor task until [`Self::start_if_configured`] sees a
    /// committed Ethernet Segment. Until then publishes land in the
    /// watches, which the task reads when it starts.
    #[must_use]
    pub(crate) fn with_deferred_start(mut self, start: StartSegmentActor) -> Self {
        self.slot = Some(Arc::new(std::sync::Mutex::new(SegmentActorSlot::Pending(
            start,
        ))));
        self
    }

    fn slot_state(&self) -> Option<std::sync::MutexGuard<'_, SegmentActorSlot>> {
        self.slot.as_ref().map(|slot| {
            slot.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        })
    }

    /// Start the deferred actor task once the published Ethernet Segment
    /// set is non-empty. Callers run this only after a converge succeeded,
    /// so a refused or rolled-back apply never starts it. No-op when the
    /// task already runs, the set is empty, or without a slot.
    ///
    /// Returns `false` whenever [`Self::close_for_shutdown`] has closed the
    /// slot, including for an empty segment set: shutdown took the slot
    /// before this commit point, so the caller must fail the converge
    /// rather than commit state (a first segment no actor serves, or the
    /// final segment's removal) during teardown. The publishes stay in
    /// place; the caller reports them as not restored. The closed check,
    /// the empty check and the transition all run under the slot mutex.
    #[must_use]
    pub(crate) fn start_if_configured(&self) -> bool {
        #[cfg(test)]
        if self
            .close_at_next_start
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            let handle = self.close_for_shutdown();
            *self
                .closed_handle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = handle;
        }
        let Some(mut state) = self.slot_state() else {
            return true;
        };
        if matches!(*state, SegmentActorSlot::Closed) {
            return false;
        }
        if self.segments_tx.borrow().is_empty() {
            return true;
        }
        match std::mem::replace(&mut *state, SegmentActorSlot::Closed) {
            SegmentActorSlot::Pending(start) => {
                info!("first Ethernet Segment committed; starting the EVPN segment orchestrator");
                *state = SegmentActorSlot::Running(start());
                true
            }
            running @ SegmentActorSlot::Running(_) => {
                *state = running;
                true
            }
            SegmentActorSlot::Closed => false,
        }
    }

    /// Test-only: close the slot for shutdown at the next
    /// [`Self::start_if_configured`], placing the close between a
    /// converge's publishes and its start decision.
    #[cfg(test)]
    pub(crate) fn close_at_next_start(&self) {
        self.close_at_next_start
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Test-only: the running actor's handle a hook-driven close took.
    #[cfg(test)]
    pub(crate) fn take_closed_handle(&self) -> Option<EvpnSegmentHandle> {
        self.closed_handle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    /// Whether coordinated shutdown has closed the actor slot. Runtime
    /// applies that name an Ethernet Segment are refused from then on,
    /// even when their runtime plan is a no-op.
    #[must_use]
    pub(crate) fn is_closed_for_shutdown(&self) -> bool {
        self.slot_state()
            .is_some_and(|state| matches!(*state, SegmentActorSlot::Closed))
    }

    /// Coordinated-shutdown admission closure: no later publish starts
    /// the task, and a task that never started drops its receivers, so
    /// the control reports closed. Returns the running task's handle for
    /// the bounded drain.
    pub(crate) fn close_for_shutdown(&self) -> Option<EvpnSegmentHandle> {
        let mut state = self.slot_state()?;
        match std::mem::replace(&mut *state, SegmentActorSlot::Closed) {
            SegmentActorSlot::Running(handle) => Some(handle),
            SegmentActorSlot::Pending(_) | SegmentActorSlot::Closed => None,
        }
    }

    /// Live per-ESI advertised DF state and pending recovery.
    pub(crate) fn df_status(&self) -> watch::Receiver<Arc<SegmentDfStatusTable>> {
        self.df_status_rx.clone()
    }

    /// Whether the segment actor can still receive runtime instance
    /// and ES snapshots.
    #[must_use]
    pub fn is_open(&self) -> bool {
        !self.instances_tx.is_closed()
            && !self.segments_tx.is_closed()
            && !self.drained_esis_tx.is_closed()
    }

    /// Replace the EVPN instance snapshot the segment actor resolves
    /// member VNIs against. Returns `false` if the actor has already
    /// exited.
    #[must_use]
    pub fn replace_instances(&self, instances: Arc<EvpnInstanceTable>) -> bool {
        if self.instances_tx.is_closed() {
            return false;
        }
        self.instances_tx.send_replace(instances);
        true
    }

    /// Replace the desired Ethernet Segment snapshot consumed by the
    /// segment actor. Returns `false` if the actor has already exited.
    #[must_use]
    pub fn replace_segments(&self, segments: Arc<Vec<EthernetSegment>>) -> bool {
        if self.segments_tx.is_closed() {
            return false;
        }
        self.segments_tx.send_replace(segments);
        true
    }

    /// Rollback republish; see [`crate::evpn_runtime_converger::restore_watch`].
    #[must_use]
    pub(crate) fn restore_instances(&self, instances: Arc<EvpnInstanceTable>) -> bool {
        crate::evpn_runtime_converger::restore_watch(&self.instances_tx, instances)
    }

    /// Rollback republish; see [`crate::evpn_runtime_converger::restore_watch`].
    #[must_use]
    pub(crate) fn restore_segments(&self, segments: Arc<Vec<EthernetSegment>>) -> bool {
        crate::evpn_runtime_converger::restore_watch(&self.segments_tx, segments)
    }

    /// Replace the operator-drained ESI set (ADR-0084). Newly-drained
    /// ESIs withdraw their Type 4 + EAD-per-ES + EAD-per-EVI routes
    /// without dropping their `SegmentState`; newly-undrained ESIs
    /// re-originate and re-run DF election. Returns `false` if the
    /// actor has already exited.
    #[must_use]
    pub fn replace_drained_esis(&self, drained: Arc<BTreeSet<EthernetSegmentIdentifier>>) -> bool {
        if self.drained_esis_tx.is_closed() {
            return false;
        }
        self.drained_esis_tx.send_replace(drained);
        true
    }
}

/// Test-only stand-in for a running segment actor: a runtime control
/// whose watch receivers are held open so publishes succeed, plus the
/// drained-ESI receiver for asserting actor-facing fanout. Used by the
/// ADR-0085 link-drain coordinator tests.
#[cfg(test)]
pub(crate) struct EvpnSegmentControlProbe {
    pub control: EvpnSegmentRuntimeControl,
    pub drained_rx: watch::Receiver<Arc<BTreeSet<EthernetSegmentIdentifier>>>,
    _instances_rx: watch::Receiver<Arc<EvpnInstanceTable>>,
    _segments_rx: watch::Receiver<Arc<Vec<EthernetSegment>>>,
}

#[cfg(test)]
impl EvpnSegmentControlProbe {
    pub fn new() -> Self {
        let (instances_tx, instances_rx) = watch::channel(Arc::new(EvpnInstanceTable::new()));
        let (segments_tx, segments_rx) = watch::channel(Arc::new(Vec::new()));
        let (drained_esis_tx, drained_rx) = watch::channel(Arc::new(BTreeSet::new()));
        Self {
            control: EvpnSegmentRuntimeControl {
                instances_tx,
                segments_tx,
                drained_esis_tx,
                df_status_rx: watch::channel(Arc::new(SegmentDfStatusTable::new())).1,
                slot: None,
                close_at_next_start: Arc::default(),
                closed_handle: Arc::default(),
            },
            drained_rx,
            _instances_rx: instances_rx,
            _segments_rx: segments_rx,
        }
    }
}

/// Per-ESI DF state the actor advertises, for the operator API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SegmentDfStatus {
    /// Preference and Don't-Preempt carried (or to be carried) on the local
    /// Type 4 route; differs from config while a preference is inherited.
    pub(crate) advertised: (u32, bool),
    /// Pending DF wait; only Don't-Preempt recovery delays local Type 4.
    pub(crate) recovery_deadline: Option<tokio::time::Instant>,
}

pub(crate) type SegmentDfStatusTable = BTreeMap<EthernetSegmentIdentifier, SegmentDfStatus>;

/// Handle returned to the daemon for shutdown coordination.
#[derive(Debug)]
pub struct EvpnSegmentHandle {
    pub(crate) shutdown: CancellationToken,
    pub(crate) join: tokio::task::JoinHandle<()>,
    /// Daemon wiring takes its control from [`prepare_with_local_bias`].
    #[cfg(test)]
    control: EvpnSegmentRuntimeControl,
}

impl EvpnSegmentHandle {
    /// Cloneable ADR-0063 runtime control surface.
    #[cfg(test)]
    pub(crate) fn runtime_control(&self) -> EvpnSegmentRuntimeControl {
        self.control.clone()
    }

    /// Live per-ESI advertised DF state and pending recovery.
    #[cfg(test)]
    pub(crate) fn df_status(&self) -> watch::Receiver<Arc<SegmentDfStatusTable>> {
        self.control.df_status()
    }

    /// Cancel the actor and wait for the bounded shutdown drain.
    pub async fn shutdown(self) {
        self.shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), self.join).await;
    }
}

/// Spawn the orchestrator. Returns `None` when no ES is configured —
/// single-homed deployments and route reflectors take this path and
/// pay zero runtime cost.
#[must_use = "drop the handle to shut down the EVPN segment orchestrator"]
#[cfg(test)]
pub fn spawn(
    instances: &Arc<EvpnInstanceTable>,
    segments: Vec<EthernetSegment>,
    rib_tx: mpsc::Sender<RibUpdate>,
    bum_enforcement_tx: Option<watch::Sender<Arc<BumEnforcementTable>>>,
    metrics: BgpMetrics,
    daemon_shutdown: CancellationToken,
) -> Option<EvpnSegmentHandle> {
    if segments.is_empty() {
        return None;
    }
    Some(spawn_with_local_bias(
        instances,
        segments,
        rib_tx,
        bum_enforcement_tx,
        None,
        None,
        metrics,
        daemon_shutdown,
    ))
}

/// [`spawn`] plus the ADR-0085 decision 5 inputs: the same-ESI
/// bias-eligibility publisher (toward the dataplane supervisor,
/// alongside the BUM-enforcement flow) and the resolved
/// `[[ethernet_segments]]` interface-binding watch (the "locally
/// attached" half of the eligibility condition). Either may be absent
/// — no dataplane / no binding feed — in which case no bias snapshot
/// is published / no segment counts as bound. Spawns even with no
/// segments. Daemon wiring defers the start ([`prepare_with_local_bias`]).
#[must_use = "drop the handle to shut down the EVPN segment orchestrator"]
#[cfg(test)]
#[expect(
    clippy::too_many_arguments,
    reason = "the segment actor keeps the dataplane supervisor's dependency spine explicit"
)]
pub(crate) fn spawn_with_local_bias(
    instances: &Arc<EvpnInstanceTable>,
    segments: Vec<EthernetSegment>,
    rib_tx: mpsc::Sender<RibUpdate>,
    bum_enforcement_tx: Option<watch::Sender<Arc<BumEnforcementTable>>>,
    same_esi_bias_tx: Option<watch::Sender<Arc<SameEsiBiasTable>>>,
    es_link_bindings_rx: Option<watch::Receiver<EsLinkBindings>>,
    metrics: BgpMetrics,
    daemon_shutdown: CancellationToken,
) -> EvpnSegmentHandle {
    let (_, start) = prepare_with_local_bias(
        instances,
        segments,
        rib_tx,
        bum_enforcement_tx,
        same_esi_bias_tx,
        es_link_bindings_rx,
        metrics,
        daemon_shutdown,
    );
    start()
}

/// The segment actor without starting its task: the runtime
/// control works at once, and the returned closure starts the task from
/// the latest published instances, segments, drained set and bindings.
#[expect(
    clippy::too_many_arguments,
    reason = "the segment actor keeps the dataplane supervisor's dependency spine explicit"
)]
pub(crate) fn prepare_with_local_bias(
    instances: &Arc<EvpnInstanceTable>,
    segments: Vec<EthernetSegment>,
    rib_tx: mpsc::Sender<RibUpdate>,
    bum_enforcement_tx: Option<watch::Sender<Arc<BumEnforcementTable>>>,
    same_esi_bias_tx: Option<watch::Sender<Arc<SameEsiBiasTable>>>,
    es_link_bindings_rx: Option<watch::Receiver<EsLinkBindings>>,
    metrics: BgpMetrics,
    daemon_shutdown: CancellationToken,
) -> (EvpnSegmentRuntimeControl, StartSegmentActor) {
    let (segments_tx, mut segments_rx) = watch::channel(Arc::new(segments));
    let (instances_tx, mut instances_rx) = watch::channel(instances.clone());
    // Drain state is runtime-only and in-memory (ADR-0084): the set
    // always starts empty, so a daemon restart clears any drain and
    // replays configured state.
    let (drained_esis_tx, mut drained_esis_rx) = watch::channel(Arc::new(BTreeSet::new()));
    let (df_status_tx, df_status_rx) = watch::channel(Arc::new(SegmentDfStatusTable::new()));
    let control = EvpnSegmentRuntimeControl {
        instances_tx,
        segments_tx,
        drained_esis_tx,
        df_status_rx,
        slot: None,
        #[cfg(test)]
        close_at_next_start: Arc::default(),
        #[cfg(test)]
        closed_handle: Arc::default(),
    };
    #[cfg(test)]
    let handle_control = control.clone();
    let start = Box::new(move || {
        // Mark the latest snapshots seen: the loop starts from them, so
        // a value published before the start is not replayed as a change.
        segments_rx.borrow_and_update();
        let runtime = SegmentRuntime {
            watches: None,
            instances: instances_rx.borrow_and_update().clone(),
            rib_tx,
            bum_enforcement_tx,
            same_esi_bias_tx,
            metrics,
            shutdown: daemon_shutdown.clone(),
            drained_esis: drained_esis_rx.borrow_and_update().clone(),
            es_link_bindings: EsLinkBindings::default(),
            boot_until: Some(tokio::time::Instant::now() + BOOT_RECOVERY_MAX_WAIT),
        };
        let join = tokio::spawn(segment_loop(
            runtime,
            instances_rx,
            segments_rx,
            drained_esis_rx,
            es_link_bindings_rx,
            df_status_tx,
        ));
        EvpnSegmentHandle {
            shutdown: daemon_shutdown,
            join,
            #[cfg(test)]
            control: handle_control,
        }
    });
    (control, start)
}

/// Non-consuming views of the actor's existing desired-state publications.
/// Originators recheck these after RIB awaits without recursively reconciling.
struct SegmentWatches {
    instances: watch::Receiver<Arc<EvpnInstanceTable>>,
    segments: watch::Receiver<Arc<Vec<EthernetSegment>>>,
    drained: watch::Receiver<Arc<BTreeSet<EthernetSegmentIdentifier>>>,
    bindings: Option<watch::Receiver<EsLinkBindings>>,
}

struct SegmentRuntime {
    watches: Option<SegmentWatches>,
    instances: Arc<EvpnInstanceTable>,
    rib_tx: mpsc::Sender<RibUpdate>,
    bum_enforcement_tx: Option<watch::Sender<Arc<BumEnforcementTable>>>,
    /// ADR-0085 decision 5: same-ESI bias-eligibility publisher toward
    /// the dataplane supervisor. `None` when no dataplane runs.
    same_esi_bias_tx: Option<watch::Sender<Arc<SameEsiBiasTable>>>,
    metrics: BgpMetrics,
    shutdown: CancellationToken,
    /// ADR-0084 operator-drained ESIs. While an ESI is in this set the
    /// actor keeps its `SegmentState` but originates nothing for it —
    /// startup, election, and snapshot reapplication all skip it, so a
    /// SIGHUP/runtime snapshot republish cannot resurrect the routes.
    drained_esis: Arc<BTreeSet<EthernetSegmentIdentifier>>,
    /// Resolved `[[ethernet_segments]].interface` bindings in the
    /// committed config (ADR-0085 decision 1) — mirrored from the
    /// binding watch. Bound-ness gates bias eligibility (decision 5:
    /// unbound segments have unknowable AC health), and the bound
    /// link name is the port handle the single-active AC gate ships
    /// to the dataplane.
    es_link_bindings: EsLinkBindings,
    /// RFC 9785 §4.3 boot timer: while set, no recovery decision runs until
    /// the EVPN sessions have synced or this ceiling passes.
    boot_until: Option<tokio::time::Instant>,
}

/// Per-ESI runtime state.
struct SegmentState {
    config: EthernetSegment,
    es_origin: LocalEsOriginator,
    ead_per_es: LocalEadPerEsOriginator,
    ead_per_evi: LocalEadPerEviOriginator,
    election: DfElection,
    /// RFC 9785 §4.3 operational advertisement, separate from admin config.
    operational_df: (u32, bool),
    /// DF wait for remote Type 4 routes; Don't-Preempt also delays publication.
    recovery_deadline: Option<tokio::time::Instant>,
    /// Last role assignment per member VNI. Used to detect flips.
    last_roles: BTreeMap<EvpnInstanceId, DfRole>,
    /// Reference instance used for path-attribute construction. We
    /// pick the first member VNI's instance — they should all share
    /// the same `route_targets` and `local_vtep_ip` in practice; if they
    /// don't, the user has a misconfigured deployment that no amount
    /// of clever fanout will save.
    reference_instance_id: EvpnInstanceId,
    /// ESI label assigned by the per-ESI allocator. Shared between
    /// the EAD-per-ES route's MPLS label field and the ESI Label
    /// extcomm — both must agree, and both must remain stable
    /// across reconfiguration so peers don't see split-horizon
    /// filter-table flap.
    esi_label: MplsLabel,
}

#[expect(
    clippy::too_many_lines,
    reason = "setup and the select loop form one ordered segment lifecycle"
)]
async fn segment_loop(
    mut runtime: SegmentRuntime,
    mut instances_rx: watch::Receiver<Arc<EvpnInstanceTable>>,
    mut segments_rx: watch::Receiver<Arc<Vec<EthernetSegment>>>,
    mut drained_esis_rx: watch::Receiver<Arc<BTreeSet<EthernetSegmentIdentifier>>>,
    mut es_link_bindings_rx: Option<watch::Receiver<EsLinkBindings>>,
    df_status_tx: watch::Sender<Arc<SegmentDfStatusTable>>,
) {
    runtime.watches = Some(SegmentWatches {
        instances: instances_rx.clone(),
        segments: segments_rx.clone(),
        drained: drained_esis_rx.clone(),
        bindings: es_link_bindings_rx.clone(),
    });
    let mut by_esi: HashMap<EthernetSegmentIdentifier, SegmentState> = HashMap::new();
    // ADR-0102 acknowledgement tracker for Type 1/4 publication.
    // In-memory only: a restart re-derives segment intent from config
    // and re-originates idempotently.
    let mut pending_rib_ops = PendingRibOps::new();
    // One allocator per spawn so two operators on different daemons
    // don't have to coordinate label space; the allocator survives
    // for the lifetime of the actor task and assignments stay
    // stable across reconfiguration within that lifetime.
    let mut esi_label_allocator = rustbgpd_evpn::EsiLabelAllocator::new();
    // Binding projection before the first snapshot publish so the
    // initial bias-eligibility table and AC-gate rows see startup
    // bindings.
    if let Some(rx) = es_link_bindings_rx.as_mut() {
        runtime.es_link_bindings = rx.borrow_and_update().clone();
    }
    let startup_segments = segments_rx.borrow().as_ref().clone();
    rebuild_segment_states(
        &runtime,
        &mut by_esi,
        &mut esi_label_allocator,
        startup_segments,
    );

    // Suppress forwarding before any RIB subscription or publication await.
    // Every member needs an explicit NonDf row: incomplete roles fail open.
    for state in by_esi.values_mut() {
        if !runtime.drained_esis.contains(&state.config.esi) {
            prepare_segment_startup(&runtime, state, true);
        }
    }
    publish_dataplane_snapshots(&runtime, &by_esi);
    publish_df_status(&df_status_tx, &by_esi);

    // Subscribe to the EVPN best-path broadcast for re-election triggers.
    let mut evpn_event_rx = subscribe_evpn_events(&runtime.rib_tx).await;
    if evpn_event_rx.is_none() {
        warn!(
            "EVPN segment orchestrator: failed to subscribe to RIB event broadcast; \
             falling back to startup-only election (no candidate-set re-evaluation)"
        );
    }

    // Initial origination + election.
    initial_startup(&runtime, &mut by_esi, &mut pending_rib_ops).await;
    publish_dataplane_snapshots(&runtime, &by_esi);
    publish_df_status(&df_status_tx, &by_esi);

    // Periodic re-election timer — backstop in case we're in poll-only mode
    // (broadcast subscription failed) or events get dropped under load.
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;
            () = runtime.shutdown.cancelled() => {
                drain(&runtime, &mut by_esi, &mut pending_rib_ops).await;
                publish_empty_dataplane_snapshots(&runtime);
                return;
            }
            changed = segments_rx.changed() => {
                if let Ok(()) = changed {
                    apply_runtime_snapshot(
                        &mut runtime,
                        &mut by_esi,
                        &mut esi_label_allocator,
                        (&instances_rx, &segments_rx),
                        (&mut drained_esis_rx, es_link_bindings_rx.as_ref()),
                        &mut pending_rib_ops,
                        &df_status_tx,
                    )
                    .await;
                } else {
                    debug!("EVPN segment: runtime segment watch closed; draining");
                    drain(&runtime, &mut by_esi, &mut pending_rib_ops).await;
                    publish_empty_dataplane_snapshots(&runtime);
                    return;
                }
            },
            changed = instances_rx.changed() => {
                if let Ok(()) = changed {
                    apply_runtime_snapshot(
                        &mut runtime,
                        &mut by_esi,
                        &mut esi_label_allocator,
                        (&instances_rx, &segments_rx),
                        (&mut drained_esis_rx, es_link_bindings_rx.as_ref()),
                        &mut pending_rib_ops,
                        &df_status_tx,
                    ).await;
                } else {
                    debug!("EVPN segment: runtime instance watch closed; draining");
                    drain(&runtime, &mut by_esi, &mut pending_rib_ops).await;
                    publish_empty_dataplane_snapshots(&runtime);
                    return;
                }
            },
            changed = drained_esis_rx.changed() => {
                if let Ok(()) = changed {
                    refresh_segment_dependencies(
                        &mut runtime,
                        &mut by_esi,
                        &mut drained_esis_rx,
                        es_link_bindings_rx.as_ref(),
                        (&instances_rx, &segments_rx),
                        &mut pending_rib_ops,
                        &df_status_tx,
                    ).await;
                } else {
                    // The drained-set sender lives on the same handle as the
                    // instance/segment senders, so a closed watch here means
                    // daemon teardown — same exit path as the other watches.
                    debug!("EVPN segment: runtime drained-ESI watch closed; draining");
                    drain(&runtime, &mut by_esi, &mut pending_rib_ops).await;
                    publish_empty_dataplane_snapshots(&runtime);
                    return;
                }
            },
            changed = bindings_changed(&mut es_link_bindings_rx) => {
                if changed.is_ok() {
                    if let Some(rx) = es_link_bindings_rx.as_mut() {
                        let previous = std::mem::replace(
                            &mut runtime.es_link_bindings,
                            rx.borrow_and_update().clone(),
                        );
                        publish_dataplane_snapshots(&runtime, &by_esi);
                        // Resume only changed bindings, including a start that
                        // paused after any Type 4, EAD or candidate-query await.
                        // The existing originators make every retry idempotent.
                        for state in by_esi.values_mut() {
                            if previous.get(&state.config.esi)
                                != runtime.es_link_bindings.get(&state.config.esi)
                            {
                                startup_segment_state(&runtime, state, &mut pending_rib_ops).await;
                            }
                        }
                        publish_dataplane_snapshots(&runtime, &by_esi);
                    }
                } else {
                    // Bindings publisher gone (daemon teardown / test
                    // rig). Keep the last-known bound set — the drain
                    // watch still lifts the bias fail-safe (a dead AC
                    // drains, drained ESIs are never eligible) — and
                    // stop selecting on the closed channel.
                    debug!("EVPN segment: ES link-binding watch closed; keeping last bound set");
                    es_link_bindings_rx = None;
                }
            },
            () = crate::evpn_ack::retry_delay(by_esi.values().filter_map(|s| s.recovery_deadline).min()) => {
                if settle_boot_wait(&mut runtime, &mut by_esi).await {
                    reelection_sweep(&runtime, &mut by_esi, &mut pending_rib_ops).await;
                }
            }
            event = recv_evpn_event(&mut evpn_event_rx) => match event {
                Ok(ev) => {
                    handle_evpn_event(&runtime, &mut by_esi, &ev, &mut pending_rib_ops).await;
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(
                        skipped,
                        "EVPN segment orchestrator: event broadcast lagged; running full re-election sweep"
                    );
                    reelection_sweep(&runtime, &mut by_esi, &mut pending_rib_ops).await;
                }
                Err(broadcast::error::RecvError::Closed) => {
                    warn!("EVPN segment orchestrator: RIB event broadcast closed; reverting to poll-only");
                    evpn_event_rx = None;
                }
            },
            // ADR-0102: re-drive RIB operations whose acknowledgement
            // was lost. Parks forever while nothing is pending.
            () = crate::evpn_ack::retry_delay(pending_rib_ops.next_deadline()) => {
                retry_pending_rib_ops(&runtime, &by_esi, &mut pending_rib_ops).await;
            }
            _ = tick.tick() => {
                reelection_sweep(&runtime, &mut by_esi, &mut pending_rib_ops).await;
            }
        }
        publish_df_status(&df_status_tx, &by_esi);
    }
}

/// Republish the operator DF view after every actor step. The current
/// snapshot is compared in place, so an unchanged step allocates nothing and
/// wakes no watcher.
fn publish_df_status(
    tx: &watch::Sender<Arc<SegmentDfStatusTable>>,
    by_esi: &HashMap<EthernetSegmentIdentifier, SegmentState>,
) {
    let status = |state: &SegmentState| SegmentDfStatus {
        advertised: state.operational_df,
        recovery_deadline: state.recovery_deadline,
    };
    tx.send_if_modified(|current| {
        let unchanged = current.len() == by_esi.len()
            && by_esi
                .iter()
                .all(|(esi, state)| current.get(esi) == Some(&status(state)));
        if !unchanged {
            *current = Arc::new(
                by_esi
                    .iter()
                    .map(|(esi, state)| (*esi, status(state)))
                    .collect(),
            );
        }
        !unchanged
    });
}

fn rebuild_segment_states(
    runtime: &SegmentRuntime,
    by_esi: &mut HashMap<EthernetSegmentIdentifier, SegmentState>,
    esi_label_allocator: &mut rustbgpd_evpn::EsiLabelAllocator,
    segments: Vec<EthernetSegment>,
) {
    // Release labels for ESIs dropped by this snapshot so the allocator
    // returns them to its free list and can reuse the label space across
    // runtime add/remove churn. Persisting ESIs are left reserved —
    // `reserve` is idempotent and returns their existing label below.
    let next_esis: HashSet<EthernetSegmentIdentifier> =
        segments.iter().map(|seg| seg.esi).collect();
    let removed: Vec<EthernetSegmentIdentifier> = by_esi
        .keys()
        .copied()
        .filter(|esi| !next_esis.contains(esi))
        .collect();
    for esi in removed {
        esi_label_allocator.release(esi);
    }

    by_esi.clear();
    for seg in segments {
        let Some(state) = build_segment_state(runtime, seg, esi_label_allocator) else {
            continue;
        };
        if by_esi.insert(state.config.esi, state).is_some() {
            warn!("duplicate Ethernet Segment in runtime snapshot; last entry wins");
        }
    }
}

fn build_segment_state(
    runtime: &SegmentRuntime,
    seg: EthernetSegment,
    esi_label_allocator: &mut rustbgpd_evpn::EsiLabelAllocator,
) -> Option<SegmentState> {
    let Some(reference_vni) = seg.member_vnis.iter().copied().next() else {
        warn!(
            esi = %seg.esi,
            "ethernet_segments entry has no member_vnis — skipping"
        );
        return None;
    };
    let Some(inst) = runtime.instances.get(reference_vni) else {
        warn!(
            esi = %seg.esi,
            vni = reference_vni.as_u32(),
            "ethernet_segments entry references unknown VNI — skipping"
        );
        return None;
    };
    let rd = inst.rd;
    // Reserve the per-ESI label via the allocator. First-seen ESIs
    // land on their deterministic synth label so operators upgrading
    // from Gate 8b prep observe no label change; subsequent collisions
    // get distinct labels from the allocator's free-list / fresh-scan
    // paths.
    let esi_label = match esi_label_allocator.reserve(seg.esi) {
        Ok(label) => label,
        Err(e) => {
            warn!(
                esi = %seg.esi,
                error = %e,
                "ESI label allocator exhausted — skipping segment"
            );
            return None;
        }
    };
    let es_origin = LocalEsOriginator::new(rd, seg.esi, seg.originator_ip);
    let ead_per_es = LocalEadPerEsOriginator::new(rd, seg.esi, esi_label);
    let mut ead_per_evi = LocalEadPerEviOriginator::new(rd, seg.esi);
    let labels: BTreeMap<EvpnInstanceId, MplsLabel> = seg
        .member_vnis
        .iter()
        .map(|&v| (v, MplsLabel::new(v.as_u32())))
        .collect();
    let mut rds = BTreeMap::new();
    for &v in &seg.member_vnis {
        let Some(inst) = runtime.instances.get(v) else {
            warn!(
                esi = %seg.esi,
                vni = v.as_u32(),
                "ethernet_segments entry references unknown VNI — skipping"
            );
            return None;
        };
        rds.insert(v, inst.rd);
    }
    ead_per_evi.set_rds(rds);
    ead_per_evi.set_labels(labels);
    let election = DfElection::new(seg.esi, seg.member_vnis.iter().copied());
    Some(SegmentState {
        operational_df: (seg.df_preference, seg.df_dont_preempt),
        recovery_deadline: None,
        config: seg,
        es_origin,
        ead_per_es,
        ead_per_evi,
        election,
        last_roles: BTreeMap::new(),
        reference_instance_id: reference_vni,
        esi_label,
    })
}

/// Reconcile only affected ESIs. An unrelated configuration change must not
/// turn a healthy non-revertive DF into a recovering PE and surrender its role.
#[expect(
    clippy::too_many_lines,
    reason = "snapshot reconciliation revalidates desired state across each owned withdrawal and startup"
)]
async fn apply_runtime_snapshot(
    runtime: &mut SegmentRuntime,
    by_esi: &mut HashMap<EthernetSegmentIdentifier, SegmentState>,
    esi_label_allocator: &mut rustbgpd_evpn::EsiLabelAllocator,
    desired_rx: (
        &watch::Receiver<Arc<EvpnInstanceTable>>,
        &watch::Receiver<Arc<Vec<EthernetSegment>>>,
    ),
    dependencies_rx: (
        &mut watch::Receiver<Arc<BTreeSet<EthernetSegmentIdentifier>>>,
        Option<&watch::Receiver<EsLinkBindings>>,
    ),
    pending: &mut PendingRibOps,
    df_status_tx: &watch::Sender<Arc<SegmentDfStatusTable>>,
) {
    // Retain ownership of every prepared start if a later publication forces
    // another reconciliation pass. Unchanged prepared states still need startup.
    let mut starting = VecDeque::new();
    'reconcile: loop {
        let (instances, segments) = refresh_segment_dependencies(
            runtime,
            by_esi,
            dependencies_rx.0,
            dependencies_rx.1,
            desired_rx,
            pending,
            df_status_tx,
        )
        .await;
        let mut latest = (instances.clone(), segments.clone());
        if runtime.shutdown.is_cancelled() {
            return;
        }
        starting.retain(|esi| !runtime.drained_esis.contains(esi));
        let previous_instances = std::mem::replace(&mut runtime.instances, instances);
        let next_esis: HashSet<_> = segments.iter().map(|seg| seg.esi).collect();
        let removed: Vec<_> = by_esi
            .keys()
            .copied()
            .filter(|esi| !next_esis.contains(esi))
            .collect();
        for esi in removed {
            starting.retain(|pending_esi| *pending_esi != esi);
            if let Some(mut state) = by_esi.remove(&esi) {
                drain_segment_state(runtime, &mut state, pending).await;
                latest = {
                    let segments = desired_rx.1.borrow();
                    (desired_rx.0.borrow().clone(), segments.as_ref().clone())
                };
            }
            esi_label_allocator.release(esi);
        }
        let mut reconciled = BTreeSet::new();
        for seg in &segments {
            if by_esi.get(&seg.esi).is_some_and(|state| {
                state.config == *seg
                    && seg
                        .member_vnis
                        .iter()
                        .all(|&vni| previous_instances.get(vni) == runtime.instances.get(vni))
            }) {
                reconciled.insert(seg.esi);
                continue;
            }
            let mut administrative_change = false;
            if let Some(mut old) = by_esi.remove(&seg.esi) {
                // RFC 9785 §4.1: explicit administrative DF changes force
                // a switchover instead of inheriting the previous reference.
                // A prepared override remains administrative if a newer
                // member/config publication makes us rebuild it before startup.
                administrative_change = (starting.contains(&seg.esi)
                    && old.recovery_deadline.is_none())
                    || (
                        old.config.df_preference,
                        old.config.df_dont_preempt,
                        old.config.df_algorithm,
                    ) != (seg.df_preference, seg.df_dont_preempt, seg.df_algorithm);
                drain_segment_state(runtime, &mut old, pending).await;
                latest = {
                    let segments = desired_rx.1.borrow();
                    (desired_rx.0.borrow().clone(), segments.as_ref().clone())
                };
            }
            let esi = seg.esi;
            let Some(mut state) = build_segment_state(runtime, seg.clone(), esi_label_allocator)
            else {
                starting.retain(|pending_esi| *pending_esi != esi);
                esi_label_allocator.release(esi);
                continue;
            };
            let start = !runtime.drained_esis.contains(&esi);
            if start {
                prepare_segment_startup(runtime, &mut state, !administrative_change);
            }
            by_esi.insert(esi, state);
            if start && !starting.contains(&esi) {
                starting.push_back(esi);
            }
            // Publish this prepared replacement before another ES can await
            // teardown, retaining old AC gates for states still owned there.
            reconciled.insert(esi);
            publish_bum_enforcement_snapshot(runtime, by_esi, Some(&reconciled));
            publish_same_esi_bias_snapshot(runtime, by_esi);
            publish_df_status(df_status_tx, by_esi);
        }
        // Publish every prepared NonDf before another withdrawal or startup
        // can await. A stale prepared state retains its gate until the next
        // pass replaces it through the normal owned teardown/rebuild path.
        publish_dataplane_snapshots(runtime, by_esi);
        publish_df_status(df_status_tx, by_esi);
        if !Arc::ptr_eq(&runtime.instances, &latest.0) || segments != latest.1 {
            continue;
        }
        while let Some(&esi) = starting.front() {
            let (instances, segments) = refresh_segment_dependencies(
                runtime,
                by_esi,
                dependencies_rx.0,
                dependencies_rx.1,
                desired_rx,
                pending,
                df_status_tx,
            )
            .await;
            if runtime.shutdown.is_cancelled() {
                return;
            }
            if !segment_matches_snapshot(runtime, &by_esi[&esi].config, &instances, &segments) {
                // Keep both the state and its queued start: removing it here
                // would drop its blocked gate before a later start can await.
                continue 'reconcile;
            }
            starting.pop_front();
            if !runtime.drained_esis.contains(&esi) {
                startup_segment_state(runtime, by_esi.get_mut(&esi).unwrap(), pending).await;
            }
        }
        publish_dataplane_snapshots(runtime, by_esi);
        return;
    }
}

/// A pending start belongs to the exact segment and member-instance snapshot
/// that prepared it; bindings and effective drains are refreshed separately.
fn segment_matches_snapshot(
    runtime: &SegmentRuntime,
    segment: &EthernetSegment,
    instances: &EvpnInstanceTable,
    segments: &[EthernetSegment],
) -> bool {
    segments.iter().any(|desired| desired == segment)
        && segment
            .member_vnis
            .iter()
            .all(|&vni| runtime.instances.get(vni) == instances.get(vni))
}

async fn subscribe_evpn_events(
    rib_tx: &mpsc::Sender<RibUpdate>,
) -> Option<broadcast::Receiver<Arc<EvpnRouteEvent>>> {
    let (reply_tx, reply_rx) = oneshot::channel();
    rib_tx
        .send(RibUpdate::SubscribeEvpnRouteEvents { reply: reply_tx })
        .await
        .ok()?;
    reply_rx.await.ok()
}

async fn recv_evpn_event(
    rx: &mut Option<broadcast::Receiver<Arc<EvpnRouteEvent>>>,
) -> Result<Arc<EvpnRouteEvent>, broadcast::error::RecvError> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

/// Await the next ES link-binding publish. `Ok` means a new snapshot
/// is readable, `Err` means the sender closed; a `None` receiver (no
/// binding feed wired, or closed earlier) parks forever so the
/// surrounding `select!` services the other arms.
async fn bindings_changed(
    rx: &mut Option<watch::Receiver<EsLinkBindings>>,
) -> Result<(), watch::error::RecvError> {
    match rx {
        Some(r) => r.changed().await,
        None => std::future::pending().await,
    }
}

async fn initial_startup(
    runtime: &SegmentRuntime,
    by_esi: &mut HashMap<EthernetSegmentIdentifier, SegmentState>,
    pending: &mut PendingRibOps,
) {
    for state in by_esi.values_mut() {
        // ADR-0084: an operator-drained ESI stays withdrawn across
        // instance/segment snapshot reapplication — a SIGHUP while
        // drained must not resurrect the routes.
        if runtime.drained_esis.contains(&state.config.esi) {
            continue;
        }
        startup_segment_state(runtime, state, pending).await;
    }
}

/// Suppress forwarding before any awaited RIB work. Explicit administrative
/// DF changes elect immediately after origination instead of entering recovery.
fn prepare_segment_startup(runtime: &SegmentRuntime, state: &mut SegmentState, recover: bool) {
    state.operational_df = (state.config.df_preference, state.config.df_dont_preempt);
    // RFC 7432 §8.5 / RFC 8584 §2.1: ordinary starts wait as NonDf.
    state.recovery_deadline = recover.then(|| tokio::time::Instant::now() + Duration::from_secs(3));
    state.last_roles = state
        .config
        .member_vnis
        .iter()
        .map(|&vni| (vni, DfRole::NonDf))
        .collect();
    let esi = format_esi(state.config.esi);
    for &vni in &state.config.member_vnis {
        runtime.metrics.set_evpn_df_role(&esi, vni.as_u32(), false);
    }
}

/// Check the exact ES and its dependencies, not an unrelated watch version.
/// No watch guard crosses an await, and none consumes the actor's notification.
fn segment_intent_is_current(runtime: &SegmentRuntime, state: &SegmentState) -> bool {
    if runtime.shutdown.is_cancelled() || runtime.drained_esis.contains(&state.config.esi) {
        return false;
    }
    let Some(watches) = &runtime.watches else {
        return true;
    };
    if watches.segments.has_changed().is_err()
        || watches.instances.has_changed().is_err()
        || watches.drained.has_changed().is_err()
    {
        return false;
    }
    let segments = watches.segments.borrow();
    let instances = watches.instances.borrow();
    let drained = watches.drained.borrow();
    if drained.contains(&state.config.esi)
        || !segment_matches_snapshot(runtime, &state.config, &instances, &segments)
    {
        return false;
    }
    // A final unseen binding still precedes closure. The ordinary binding
    // branch consumes it before retaining that last-known value after close.
    watches.bindings.as_ref().is_none_or(|bindings| {
        bindings.borrow().get(&state.config.esi) == runtime.es_link_bindings.get(&state.config.esi)
    })
}

/// Originate a prepared ES. Ordinary `DF_WAIT` advertises the candidate now;
/// RFC 9785 §4.3(5) Don't-Preempt recovery delays publication until election.
async fn startup_segment_state(
    runtime: &SegmentRuntime,
    state: &mut SegmentState,
    pending: &mut PendingRibOps,
) {
    if !segment_intent_is_current(runtime, state)
        || (state.recovery_deadline.is_some() && state.config.df_dont_preempt)
    {
        return;
    }
    // Type 4 ES first so peers see us as a candidate before any
    // EAD routes show up.
    let actions = state.es_origin.on_startup();
    apply(runtime, state, actions, pending).await;
    if !segment_intent_is_current(runtime, state) {
        return;
    }

    let actions = state.ead_per_es.on_startup();
    apply(runtime, state, actions, pending).await;
    if !segment_intent_is_current(runtime, state) {
        return;
    }

    // Include already received remote Type 4 routes in the initial election.
    run_election_for(runtime, state, pending).await;
}

async fn drain(
    runtime: &SegmentRuntime,
    by_esi: &mut HashMap<EthernetSegmentIdentifier, SegmentState>,
    pending: &mut PendingRibOps,
) {
    for state in by_esi.values_mut() {
        drain_segment_state(runtime, state, pending).await;
    }
}

/// Withdraw one ES's three route classes (EAD-per-EVI, EAD-per-ES,
/// Type 4 — most-specific NLRI shape down, the shutdown convention)
/// without dropping its `SegmentState`. Clears the per-VNI role
/// tracking so a later re-origination re-runs election from a clean
/// slate (the EAD-per-EVI re-emit rides the role-transition diff) and
/// the BUM enforcement table stops carrying rows for the ES.
async fn drain_segment_state(
    runtime: &SegmentRuntime,
    state: &mut SegmentState,
    pending: &mut PendingRibOps,
) {
    state.recovery_deadline = None;
    state.operational_df = (state.config.df_preference, state.config.df_dont_preempt);
    let actions = state.ead_per_evi.drain_to_withdraws();
    apply(runtime, state, actions, pending).await;
    let actions = state.ead_per_es.on_shutdown();
    apply(runtime, state, actions, pending).await;
    let actions = state.es_origin.on_shutdown();
    apply(runtime, state, actions, pending).await;

    let esi_str = format_esi(state.config.esi);
    for (vni, _) in std::mem::take(&mut state.last_roles) {
        runtime
            .metrics
            .set_evpn_df_role(esi_str.as_str(), vni.as_u32(), false);
    }
}

/// The converger seeds Link drain before publishing a newly bound ES, then
/// publishes its binding only after commit. The biased segment branch must
/// observe that seed; a subsequent undrain must observe the committed binding
/// before it originates. Apply transitions rather than assigning the set so
/// an existing ES's pending drain still withdraws its owned routes.
async fn refresh_segment_dependencies(
    runtime: &mut SegmentRuntime,
    by_esi: &mut HashMap<EthernetSegmentIdentifier, SegmentState>,
    drained_rx: &mut watch::Receiver<Arc<BTreeSet<EthernetSegmentIdentifier>>>,
    bindings_rx: Option<&watch::Receiver<EsLinkBindings>>,
    desired_rx: (
        &watch::Receiver<Arc<EvpnInstanceTable>>,
        &watch::Receiver<Arc<Vec<EthernetSegment>>>,
    ),
    pending: &mut PendingRibOps,
    df_status_tx: &watch::Sender<Arc<SegmentDfStatusTable>>,
) -> (Arc<EvpnInstanceTable>, Vec<EthernetSegment>) {
    // Keep ownership of prepared undrains across withdrawal acknowledgements.
    // Re-reading the same drained set must not discard an unstarted recovery.
    let mut withdrawing = BTreeSet::new();
    let mut starting = BTreeSet::new();
    loop {
        let (instances, segments, drained, rebound) = {
            // Freeze desired segments before reading their dependencies. The
            // producer publishes instances and Link seeds before segments, and
            // GCs removed drains afterwards. No watch guard crosses an await.
            let segments = desired_rx.1.borrow();
            let instances = desired_rx.0.borrow();
            // Committed bindings precede undrain. Non-consuming reads leave
            // newer notifications available to the ordinary actor branches.
            let drained = drained_rx.borrow().clone();
            let mut rebound = BTreeSet::new();
            if let Some(rx) = bindings_rx {
                let bindings = rx.borrow().clone();
                rebound.extend(
                    by_esi
                        .values()
                        .filter(|state| {
                            state.es_origin.is_advertising()
                                && runtime.es_link_bindings.get(&state.config.esi)
                                    != bindings.get(&state.config.esi)
                        })
                        .map(|state| state.config.esi),
                );
                runtime.es_link_bindings = bindings;
            }
            (
                instances.clone(),
                segments.as_ref().clone(),
                drained,
                rebound,
            )
        };
        let retained: BTreeSet<_> = segments
            .iter()
            .filter_map(|segment| {
                by_esi
                    .get(&segment.esi)
                    .filter(|state| {
                        state.config == *segment
                            && segment
                                .member_vnis
                                .iter()
                                .all(|&vni| runtime.instances.get(vni) == instances.get(vni))
                    })
                    .map(|_| segment.esi)
            })
            .collect();
        let prior = std::mem::replace(&mut runtime.drained_esis, drained.clone());
        withdrawing.extend(drained.difference(&prior).copied());
        starting.retain(|esi| !drained.contains(esi) && retained.contains(esi));
        // A binding may change while an undrain's startup acknowledgement is
        // held. Preserve that retry before updating the cached binding erases
        // the delta seen by the ordinary binding notification branch. Unstarted
        // prepared states remain owned by the outer reconciliation queue.
        starting.extend(
            rebound
                .into_iter()
                .filter(|esi| !drained.contains(esi) && retained.contains(esi)),
        );
        for esi in prior
            .difference(&drained)
            .filter(|esi| retained.contains(*esi))
        {
            let state = by_esi.get_mut(esi).unwrap();
            prepare_segment_startup(runtime, state, true);
            starting.insert(*esi);
        }
        // Publish every prepared recovery before any other ES can wait for a
        // withdrawal acknowledgement. Refresh committed port names on every
        // pass, including the pass immediately before recovery origination.
        publish_bum_enforcement_snapshot(runtime, by_esi, Some(&retained));
        publish_same_esi_bias_snapshot(runtime, by_esi);
        publish_df_status(df_status_tx, by_esi);
        if runtime.shutdown.is_cancelled() {
            return (instances, segments);
        }
        if let Some(esi) = withdrawing.pop_first() {
            if let Some(state) = by_esi.get_mut(&esi) {
                info!(esi = %esi, "EVPN segment: draining Ethernet Segment (operator)");
                drain_segment_state(runtime, state, pending).await;
                // A queued drain may have been undone while another ES was
                // settling. Its own withdrawal cleared the prepared roles.
                if starting.contains(&esi) {
                    prepare_segment_startup(runtime, state, true);
                }
            }
            continue;
        }
        if let Some(esi) = starting.pop_first() {
            // Membership, effective drain and committed bindings were just
            // re-read. Removed/replaced or re-drained work was discarded above.
            let state = by_esi.get_mut(&esi).unwrap();
            info!(esi = %esi, "EVPN segment: undraining Ethernet Segment (operator)");
            startup_segment_state(runtime, state, pending).await;
            continue;
        }
        return (instances, segments);
    }
}

async fn handle_evpn_event(
    runtime: &SegmentRuntime,
    by_esi: &mut HashMap<EthernetSegmentIdentifier, SegmentState>,
    event: &EvpnRouteEvent,
    pending: &mut PendingRibOps,
) {
    // Only Type 4 events affect the candidate set.
    let EvpnRouteKey::Es { esi, .. } = event.key else {
        return;
    };
    if !by_esi.contains_key(&esi) {
        return;
    }
    // For correctness we re-gather all candidates from the RIB
    // rather than apply the single event as a delta — the projection
    // model that bit us in Gate 7c (RD-keyed events vs.
    // (VNI, MAC)-keyed cache) doesn't apply here since Type 4 is
    // already 1:1 with `(ESI, originator_ip)`, but the full repoll
    // is simpler and the broadcast-trigger keeps it sub-second.
    let Some(state) = by_esi.get_mut(&esi) else {
        return;
    };
    run_election_for(runtime, state, pending).await;
    publish_dataplane_snapshots(runtime, by_esi);
}

async fn reelection_sweep(
    runtime: &SegmentRuntime,
    by_esi: &mut HashMap<EthernetSegmentIdentifier, SegmentState>,
    pending: &mut PendingRibOps,
) {
    // Every ESI's election reads only Type 4 ES rows; the sweep shares one
    // snapshot across all of them, so narrow to that route type in the RIB
    // task rather than copying the (Type 2 dominated) whole table.
    let routes = match query_evpn_routes(
        &runtime.rib_tx,
        Some(Box::new(|route: &EvpnRibRoute| {
            matches!(route.route, EvpnRoute::Es(_))
        })),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "EVPN segment: sweep candidate gather failed");
            // Avoid an expired recovery timer spinning on an unavailable RIB.
            for state in by_esi.values_mut() {
                if let Some(deadline) = &mut state.recovery_deadline {
                    *deadline =
                        (*deadline).max(tokio::time::Instant::now() + Duration::from_secs(1));
                }
            }
            return;
        }
    };
    for state in by_esi.values_mut() {
        run_election_for_routes(runtime, state, &routes, pending).await;
    }
    publish_dataplane_snapshots(runtime, by_esi);
}

/// Re-gather candidates from the RIB and re-run election for one
/// ESI. Diffs against the prior `last_roles` map; per-VNI flips
/// trigger `on_vni_role_changed` plus telemetry updates.
async fn run_election_for(
    runtime: &SegmentRuntime,
    state: &mut SegmentState,
    pending: &mut PendingRibOps,
) {
    let candidates = match gather_candidates(state, &runtime.rib_tx).await {
        Ok(c) => c,
        Err(e) => {
            warn!(esi = %state.config.esi, error = %e, "EVPN segment: candidate gather failed");
            return;
        }
    };
    run_election_with_candidates(runtime, state, candidates, pending).await;
}

async fn run_election_for_routes(
    runtime: &SegmentRuntime,
    state: &mut SegmentState,
    routes: &[EvpnRibRoute],
    pending: &mut PendingRibOps,
) {
    let candidates = gather_candidates_from_routes(state, routes);
    run_election_with_candidates(runtime, state, candidates, pending).await;
}

async fn run_election_with_candidates(
    runtime: &SegmentRuntime,
    state: &mut SegmentState,
    mut candidates: Vec<DfCandidate>,
    pending: &mut PendingRibOps,
) {
    // ADR-0084: a drained ES has withdrawn its Type 4 and exited DF
    // election; role transitions must not re-emit EAD-per-EVI routes
    // for it (sweeps and remote Type 4 events keep firing while
    // drained).
    if !segment_intent_is_current(runtime, state) {
        return;
    }
    if state.recovery_deadline.is_some_and(|deadline| {
        runtime.boot_until.is_some() || tokio::time::Instant::now() < deadline
    }) {
        return;
    }
    let recovering = state.recovery_deadline.take().is_some();
    let delayed_publication = recovering && state.config.df_dont_preempt;
    let changed = update_operational_df(state, &candidates, recovering);
    for candidate in &mut candidates {
        if candidate.originator_ip == state.config.originator_ip {
            (candidate.df_preference, candidate.df_dont_preempt) = state.operational_df;
        }
    }
    if delayed_publication || changed {
        let actions = state.es_origin.on_refresh();
        apply(runtime, state, actions, pending).await;
        if !segment_intent_is_current(runtime, state) {
            return;
        }
    }
    if delayed_publication {
        let actions = state.ead_per_es.on_startup();
        apply(runtime, state, actions, pending).await;
        if !segment_intent_is_current(runtime, state) {
            return;
        }
    }
    // Re-advertise after recovery even if the prepared NonDf role is unchanged,
    // retaining those published roles until every awaited action is current.
    let advertise_all = recovering || state.ead_per_evi.advertised_count() == 0;
    let new_roles = match state.election.run(&candidates, state.config.originator_ip) {
        Ok(r) => r,
        Err(e) => {
            warn!(
                esi = %state.config.esi,
                error = %e,
                "EVPN segment: DF election failed"
            );
            return;
        }
    };

    let esi_str = format_esi(state.config.esi);
    // Compute and apply per-VNI role changes.
    let mut transitions: Vec<(EvpnInstanceId, DfRole)> = Vec::new();
    for (&vni, &role) in &new_roles {
        let prior = state.last_roles.get(&vni).copied();
        if advertise_all || prior != Some(role) {
            transitions.push((vni, role));
        }
    }

    for &(vni, role) in &transitions {
        let actions = state.ead_per_evi.on_vni_role_changed(vni, role);
        let Some(inst) = runtime.instances.get(vni).cloned() else {
            warn!(
                esi = esi_str.as_str(),
                vni = vni.as_u32(),
                "EVPN segment: role changed for unknown VNI"
            );
            continue;
        };
        apply_with_instance(
            runtime,
            &inst,
            state.esi_label,
            state.config.df_algorithm,
            state.operational_df.0,
            state.operational_df.1,
            state.config.redundancy_mode,
            actions,
            pending,
        )
        .await;
        if !segment_intent_is_current(runtime, state) {
            return;
        }
    }
    // Publish one complete election only after every member's owned action
    // has settled against current intent. A stale later ACK must not expose
    // an earlier member's DF role while the old routes await teardown.
    for (vni, role) in transitions {
        runtime
            .metrics
            .set_evpn_df_role(esi_str.as_str(), vni.as_u32(), role.is_df());
        if !advertise_all && state.last_roles.contains_key(&vni) {
            runtime
                .metrics
                .record_evpn_df_role_change(esi_str.as_str(), vni.as_u32());
        }
        state.last_roles.insert(vni, role);
        debug!(
            esi = esi_str.as_str(),
            vni = vni.as_u32(),
            role = role.as_str(),
            "EVPN segment: DF role updated"
        );
    }
}

/// RFC 9785 §4.3: on recovery inherit a protected remote reference's
/// preference with DP=0. Keep it until we become reference; then restore admin.
fn update_operational_df(
    state: &mut SegmentState,
    candidates: &[DfCandidate],
    recovering: bool,
) -> bool {
    let admin = (state.config.df_preference, state.config.df_dont_preempt);
    let before = state.operational_df;
    let agreed = candidates
        .iter()
        .all(|c| c.df_algorithm == state.config.df_algorithm);
    if !agreed {
        state.operational_df = admin;
    } else if recovering && admin.1 {
        let remote: Vec<_> = candidates
            .iter()
            .copied()
            .filter(|c| c.originator_ip != state.config.originator_ip)
            .collect();
        if let Some(reference) = DfElection::preference_reference(&remote) {
            let would_preempt = match state.config.df_algorithm {
                DfAlgorithm::HighestPreference => admin.0 >= reference.df_preference,
                DfAlgorithm::LowestPreference => admin.0 <= reference.df_preference,
                _ => false,
            };
            if reference.df_dont_preempt && would_preempt {
                state.operational_df = (reference.df_preference, false);
            }
        }
    } else if DfElection::preference_reference(candidates)
        .is_some_and(|reference| reference.originator_ip == state.config.originator_ip)
    {
        state.operational_df = admin;
    }
    before != state.operational_df
}

/// Publish both dataplane-supervisor snapshots the segment actor
/// owns: the Gate 8b BUM-enforcement table and the ADR-0085 same-ESI
/// bias-eligibility table. Both derive from the same per-ES role
/// state, so every event that republishes one republishes the other.
fn publish_dataplane_snapshots(
    runtime: &SegmentRuntime,
    by_esi: &HashMap<EthernetSegmentIdentifier, SegmentState>,
) {
    publish_bum_enforcement_snapshot(runtime, by_esi, None);
    publish_same_esi_bias_snapshot(runtime, by_esi);
}

fn publish_empty_dataplane_snapshots(runtime: &SegmentRuntime) {
    publish_empty_bum_enforcement_snapshot(runtime);
    if let Some(tx) = &runtime.same_esi_bias_tx {
        send_same_esi_bias_if_modified(tx, SameEsiBiasTable::new());
    }
}

fn publish_bum_enforcement_snapshot(
    runtime: &SegmentRuntime,
    by_esi: &HashMap<EthernetSegmentIdentifier, SegmentState>,
    retained: Option<&BTreeSet<EthernetSegmentIdentifier>>,
) {
    let Some(tx) = &runtime.bum_enforcement_tx else {
        return;
    };
    let mut table = build_bum_enforcement_table(&runtime.instances, by_esi);
    populate_ac_gates(
        &mut table,
        &runtime.es_link_bindings,
        &runtime.drained_esis,
        by_esi,
    );
    if let Some(retained) = retained {
        // A dependency refresh may observe committed bindings for a deletion
        // or replacement before apply_runtime_snapshot settles the old routes.
        // Keep that owned state's old AC gate until its teardown finishes.
        for gate in tx.borrow().ac_gates() {
            if by_esi.contains_key(&gate.esi) && !retained.contains(&gate.esi) {
                table.set_ac_gate(gate.esi, gate.interface.clone(), gate.state);
            }
        }
    }
    publish_enforcement_table(runtime, tx, table);
}

fn publish_empty_bum_enforcement_snapshot(runtime: &SegmentRuntime) {
    if let Some(tx) = &runtime.bum_enforcement_tx {
        publish_enforcement_table(runtime, tx, BumEnforcementTable::new());
    }
}

/// `send_replace` plus the AC-gate operator surface: the per-ES
/// `evpn_es_ac_gate` gauge tracks every published gate row (cleared
/// for rows that left the table), and entering the mixed-roles
/// partial-enforcement condition logs a transition-only structured
/// warning — both diffed against the previously published table so
/// the 10 s re-election sweep's identical republishes stay silent.
fn publish_enforcement_table(
    runtime: &SegmentRuntime,
    tx: &watch::Sender<Arc<BumEnforcementTable>>,
    table: BumEnforcementTable,
) {
    let prev = tx.borrow().clone();
    for entry in table.ac_gates() {
        let esi_str = format_esi(entry.esi);
        runtime
            .metrics
            .set_evpn_es_ac_gate(esi_str.as_str(), entry.state.as_str());
        if entry.state == AcGateState::MixedRoles
            && prev.ac_gate(entry.esi).map(|e| e.state) != Some(AcGateState::MixedRoles)
        {
            warn!(
                esi = esi_str.as_str(),
                interface = entry.interface.as_str(),
                "single-active ES has split DF roles across its member VNIs \
                 (RFC 8584 service carving): the whole-port AC gate stays \
                 forwarding and only per-VNI BUM flood flags enforce — \
                 partial enforcement until the roles converge"
            );
        }
    }
    for prev_entry in prev.ac_gates() {
        if table.ac_gate(prev_entry.esi).is_none() {
            runtime
                .metrics
                .clear_evpn_es_ac_gate(format_esi(prev_entry.esi).as_str());
        }
    }
    debug!(
        rows = table.len(),
        ac_gates = table.ac_gates_len(),
        "EVPN segment: published BUM enforcement intent"
    );
    tx.send_replace(Arc::new(table));
}

/// Attach the single-active AC-gate rows to the enforcement table —
/// the "single-active non-DF full AC blocking" half of Gate 8b
/// (RFC 7432 §14.1.1: the non-DF must block ALL traffic on the
/// segment AC, known unicast included; the BUM flood flags alone
/// cover only the flood classes). One row per single-active ES with
/// an ADR-0085 `interface` binding; see [`ac_gate_state_for_es`] for
/// the role/drain → state rule.
fn populate_ac_gates(
    table: &mut BumEnforcementTable,
    bindings: &EsLinkBindings,
    drained_esis: &BTreeSet<EthernetSegmentIdentifier>,
    by_esi: &HashMap<EthernetSegmentIdentifier, SegmentState>,
) {
    for (esi, state) in by_esi {
        let Some(binding) = bindings.get(esi) else {
            continue;
        };
        let Some(gate) = ac_gate_state_for_es(
            state.config.redundancy_mode,
            drained_esis.contains(esi),
            &state.config.member_vnis,
            &state.last_roles,
        ) else {
            continue;
        };
        table.set_ac_gate(*esi, binding.interface.clone(), gate);
    }
}

/// Pure AC-gate rule for one **bound** ES. Returns `None` when no
/// gate row applies (all-active: every member PE forwards known
/// unicast by design — RFC 7432 §14.1.2 — so the port is never
/// gated). For single-active:
///
/// - **drained** (any reason) → `Blocked`. A drained ES has
///   withdrawn and must not attract traffic; blocking the AC is the
///   maintenance semantic, and the ADR-0085 recovery hold-off keeps
///   the port blocked until the segment has re-converged.
/// - **non-DF for EVERY member VNI** → `Blocked`. The kernel gate is
///   per PORT, not per VLAN, so blocking is only safe when no member
///   VNI elects this PE as DF.
/// - **DF and non-DF split across member VNIs** (RFC 8584 service
///   carving) → `MixedRoles`: the port stays forwarding (a port
///   block would break the DF VNIs) and the caller surfaces the
///   partial-enforcement condition via gauge + warning.
/// - **otherwise** (DF everywhere, or roles not yet known for every
///   member VNI — e.g. mid-election) → `Forwarding`. Incomplete
///   roles fail open, matching the BUM table's posture for the same
///   window.
pub(crate) fn ac_gate_state_for_es(
    redundancy_mode: RedundancyMode,
    drained: bool,
    member_vnis: &BTreeSet<EvpnInstanceId>,
    roles: &BTreeMap<EvpnInstanceId, DfRole>,
) -> Option<AcGateState> {
    if !redundancy_mode.is_single_active() {
        return None;
    }
    if drained {
        return Some(AcGateState::Blocked);
    }
    let any_df = roles.values().any(|r| r.is_df());
    let any_non_df = roles.values().any(|r| !r.is_df());
    let all_member_roles_known =
        !member_vnis.is_empty() && member_vnis.iter().all(|v| roles.contains_key(v));
    Some(if any_df && any_non_df {
        AcGateState::MixedRoles
    } else if any_non_df && all_member_roles_known {
        AcGateState::Blocked
    } else {
        AcGateState::Forwarding
    })
}

/// ADR-0085 decision 5: publish the per-`(ESI, VNI)` same-ESI
/// bias-eligibility snapshot toward the dataplane supervisor.
///
/// Published change-only (`send_if_modified`): a bias change forces a
/// full remote-MAC re-projection on the supervisor side, and the
/// re-election sweep republishes every 10 s with usually-identical
/// content.
fn publish_same_esi_bias_snapshot(
    runtime: &SegmentRuntime,
    by_esi: &HashMap<EthernetSegmentIdentifier, SegmentState>,
) {
    let Some(tx) = &runtime.same_esi_bias_tx else {
        return;
    };
    let bound_esis: BTreeSet<EthernetSegmentIdentifier> =
        runtime.es_link_bindings.keys().copied().collect();
    let mut table = build_same_esi_bias_table_from_roles(
        &bound_esis,
        &runtime.drained_esis,
        by_esi.iter().flat_map(|(&esi, state)| {
            state
                .last_roles
                .iter()
                .map(move |(&vni, &role)| (esi, state.config.redundancy_mode, vni, role))
        }),
    );
    for (&esi, binding) in runtime.es_link_bindings.iter() {
        table.bind_interface(esi, binding.interface.clone());
    }
    if send_same_esi_bias_if_modified(tx, table) {
        debug!("EVPN segment: published same-ESI bias eligibility");
    }
}

fn send_same_esi_bias_if_modified(
    tx: &watch::Sender<Arc<SameEsiBiasTable>>,
    table: SameEsiBiasTable,
) -> bool {
    tx.send_if_modified(|current| {
        if **current == table {
            return false;
        }
        *current = Arc::new(table);
        true
    })
}

/// Pure ADR-0085 decision 5 eligibility rule. A `(ESI, VNI)` pair is
/// bias-eligible — remote MAC/MAC-IP routes for it must not program a
/// remote FDB row — iff the segment is:
///
/// - **locally attached**: in `bound_esis` (has an `interface`
///   binding). Unbound segments are never eligible — AC health is
///   unknowable, today's projection behavior is preserved.
/// - **healthy and not drained**: not in `drained_esis`. The flat
///   drained set already encodes link health: per decision 2 a
///   carrier loss (or a missing link, a dead monitor, a non-Linux
///   build — all fail-closed) holds the `Link` drain reason, so
///   "attached and not drained" implies "healthy". The decision 3
///   recovery hold-off keeps the ES drained after carrier returns,
///   which correctly suppresses the bias until the segment has
///   re-converged. No separate health channel is needed.
/// - **entitled to forward**, redundancy-mode-aware: all-active —
///   always (every member PE forwards); single-active — only when
///   this PE is the DF for the `(ESI, VNI)`. A healthy single-active
///   *backup* keeps the remote row toward the active PE: its own AC
///   is non-forwarding by definition, and biasing there would become
///   a blackhole the moment the non-DF all-traffic AC blocking gap
///   is closed.
///
/// `roles` carries one entry per actively-originated `(ESI, VNI)`
/// (the actor's `last_roles`, cleared while an ES is drained), so a
/// drained ES contributes nothing through either condition.
pub(crate) fn build_same_esi_bias_table_from_roles<I>(
    bound_esis: &BTreeSet<EthernetSegmentIdentifier>,
    drained_esis: &BTreeSet<EthernetSegmentIdentifier>,
    roles: I,
) -> SameEsiBiasTable
where
    I: IntoIterator<
        Item = (
            EthernetSegmentIdentifier,
            RedundancyMode,
            EvpnInstanceId,
            DfRole,
        ),
    >,
{
    let mut table = SameEsiBiasTable::new();
    for (esi, redundancy_mode, vni, role) in roles {
        if !bound_esis.contains(&esi) || drained_esis.contains(&esi) {
            continue;
        }
        let entitled_to_forward = match redundancy_mode {
            RedundancyMode::AllActive => true,
            RedundancyMode::SingleActive => role.is_df(),
        };
        if entitled_to_forward {
            table.insert(esi, vni);
        }
    }
    table
}

fn build_bum_enforcement_table(
    instances: &EvpnInstanceTable,
    by_esi: &HashMap<EthernetSegmentIdentifier, SegmentState>,
) -> BumEnforcementTable {
    build_bum_enforcement_table_from_roles(
        instances,
        by_esi.iter().flat_map(|(&esi, state)| {
            state
                .last_roles
                .iter()
                .map(move |(&vni, &role)| (esi, vni, role))
        }),
    )
}

fn build_bum_enforcement_table_from_roles<I>(
    instances: &EvpnInstanceTable,
    roles: I,
) -> BumEnforcementTable
where
    I: IntoIterator<Item = (EthernetSegmentIdentifier, EvpnInstanceId, DfRole)>,
{
    let mut table = BumEnforcementTable::new();
    for (esi, vni, role) in roles {
        let Some(inst) = instances.get(vni) else {
            continue;
        };
        let Some(bridge) = inst.bridge.as_ref() else {
            continue;
        };
        table.insert(esi, vni, role, bridge.clone());
    }
    table
}

/// Pull all current Type 4 ES best-paths from the RIB and project
/// them into the candidate set for one ESI. Always includes the
/// local PE, even if its Type 4 hasn't surfaced through the
/// broadcast yet.
async fn gather_candidates(
    state: &SegmentState,
    rib_tx: &mpsc::Sender<RibUpdate>,
) -> Result<Vec<DfCandidate>, RibQueryError> {
    // Only this segment's Type 4 ES rows are candidates, and they are a
    // small minority of an EVPN table dominated by Type 2. Narrowing in
    // the RIB task keeps a DF re-election off the actor's critical path;
    // `gather_candidates_from_routes` re-checks the same predicate, so
    // its direct callers see identical results.
    let esi = state.config.esi;
    let routes = query_evpn_routes(
        rib_tx,
        Some(Box::new(
            move |route: &EvpnRibRoute| matches!(&route.route, EvpnRoute::Es(es) if es.esi == esi),
        )),
    )
    .await?;
    Ok(gather_candidates_from_routes(state, &routes))
}

/// Project Type 4 ES routes into one DF candidate per originator IP.
///
/// The local PE always comes from configuration, never from a Type 4 route
/// that carries its own originator IP. RFC 7432 §8.5 orders candidates by
/// originator IP but does not say which route counts when one originator
/// advertises the ESI under several RDs (an RD change, or a misconfiguration)
/// with different DF Election Extended Communities. The route with the lowest
/// RD supplies that PE's preference, don't-preempt bit and algorithm, so the
/// election never depends on the order the RIB yields routes in.
fn gather_candidates_from_routes(
    state: &SegmentState,
    routes: &[EvpnRibRoute],
) -> Vec<DfCandidate> {
    let mut remote: BTreeMap<IpAddr, (RouteDistinguisher, DfCandidate)> = BTreeMap::new();
    for r in routes {
        let EvpnRoute::Es(es) = &r.route else {
            continue;
        };
        if es.esi != state.config.esi || es.originator_ip == state.config.originator_ip {
            continue;
        }
        if !has_matching_es_import_rt(&r.attributes, state.config.esi) {
            debug!(
                esi = %state.config.esi,
                originator_ip = %es.originator_ip,
                "EVPN segment: ignoring Type 4 ES route without matching ES-Import RT"
            );
            continue;
        }
        // Per-PE candidate. df_algorithm decodes from the route's DF
        // Election extcomm if present; absent extcomm → DefaultModulo
        // + default preference (matches RFC 8584 fallback rules).
        let (pref, dont_preempt, alg) = decode_df_election_extcomm(&r.attributes).unwrap_or((
            crate::config::DEFAULT_DF_PREFERENCE,
            false,
            DfAlgorithm::DefaultModulo,
        ));
        let candidate = DfCandidate {
            originator_ip: es.originator_ip,
            df_preference: pref,
            df_dont_preempt: dont_preempt,
            df_algorithm: alg,
        };
        match remote.entry(es.originator_ip) {
            Entry::Vacant(slot) => {
                slot.insert((es.rd, candidate));
            }
            Entry::Occupied(mut slot) if es.rd < slot.get().0 => {
                slot.insert((es.rd, candidate));
            }
            Entry::Occupied(_) => {}
        }
    }
    let mut by_ip: BTreeMap<IpAddr, DfCandidate> = remote
        .into_iter()
        .map(|(ip, (_, candidate))| (ip, candidate))
        .collect();
    by_ip.insert(
        state.config.originator_ip,
        DfCandidate {
            originator_ip: state.config.originator_ip,
            df_preference: state.operational_df.0,
            df_dont_preempt: state.operational_df.1,
            df_algorithm: state.config.df_algorithm,
        },
    );
    by_ip.into_values().collect()
}

fn has_matching_es_import_rt(attrs: &[PathAttribute], esi: EthernetSegmentIdentifier) -> bool {
    let expected = es_import_rt_from_esi(esi);
    attrs.iter().any(|attr| {
        let Some(extcomms) = attr.extended_communities() else {
            return false;
        };
        extcomms
            .iter()
            .copied()
            .any(|ec| ec.as_es_import_rt() == Some(expected))
    })
}

fn decode_df_election_extcomm(attrs: &[PathAttribute]) -> Option<(u32, bool, DfAlgorithm)> {
    // RFC 8584 §2.2 / RFC 9785 §3: DF Election extcomm type 0x06
    // subtype 0x06, carrying RSV(3 bits), DF Alg(5 bits), bitmap(16
    // bits), and algorithm-specific trailing bytes. Decode is
    // best-effort — unrecognized extcomms fall back to defaults at
    // the call site.
    for attr in attrs {
        let Some(ecs) = attr.extended_communities() else {
            continue;
        };
        for ec in ecs {
            if let Some(df) = ec.as_df_election() {
                let alg = DfAlgorithm::from_algorithm_id(df.algorithm_id);
                let pref = df
                    .preference
                    .map_or(crate::config::DEFAULT_DF_PREFERENCE, u32::from);
                let dont_preempt = (df.capabilities & 0x8000) != 0;
                return Some((pref, dont_preempt, alg));
            }
        }
    }
    None
}

fn type4_es_extcomms(
    esi: EthernetSegmentIdentifier,
    df_algorithm: DfAlgorithm,
    df_preference: u32,
    df_dont_preempt: bool,
) -> Vec<rustbgpd_wire::ExtendedCommunity> {
    let mut extcomms = vec![rustbgpd_wire::ExtendedCommunity::es_import_rt(
        es_import_rt_from_esi(esi),
    )];
    if let Some(df) = df_election_extcomm(df_algorithm, df_preference, df_dont_preempt) {
        extcomms.push(df);
    }
    extcomms
}

/// RFC 9785 §3 DF Election extcomm capabilities bitmask: bit 15 (`0x8000`)
/// is the Don't-Preempt (DP) flag.
const DF_ELECTION_DONT_PREEMPT: u16 = 0x8000;

fn df_election_extcomm(
    df_algorithm: DfAlgorithm,
    df_preference: u32,
    df_dont_preempt: bool,
) -> Option<rustbgpd_wire::ExtendedCommunity> {
    match df_algorithm {
        DfAlgorithm::DefaultModulo => None,
        DfAlgorithm::HighestRandomWeight => Some(rustbgpd_wire::ExtendedCommunity::df_election(
            df_algorithm.algorithm_id(),
            0,
            None,
        )),
        DfAlgorithm::HighestPreference | DfAlgorithm::LowestPreference => {
            let preference =
                u16::try_from(df_preference).expect("validated RFC 9785 df_preference fits u16");
            // DP only applies to the preference algorithms (config validation
            // rejects df_dont_preempt for default-modulo / HRW).
            let capabilities = if df_dont_preempt {
                DF_ELECTION_DONT_PREEMPT
            } else {
                0
            };
            Some(rustbgpd_wire::ExtendedCommunity::df_election(
                df_algorithm.algorithm_id(),
                capabilities,
                Some(preference),
            ))
        }
    }
}

/// Boot synchronization for the DF wait. Remote Type 4 routes cannot be present before
/// the BGP sessions carrying them are up, so after a restart the recovery
/// decision waits until every established EVPN session has sent End-of-RIB
/// and GR selection deferral has released L2VPN/EVPN, bounded by
/// `BOOT_RECOVERY_MAX_WAIT`. Returns whether recovery may proceed;
/// otherwise expired recovery deadlines move to the next poll.
async fn settle_boot_wait(
    runtime: &mut SegmentRuntime,
    by_esi: &mut HashMap<EthernetSegmentIdentifier, SegmentState>,
) -> bool {
    let Some(boot_until) = runtime.boot_until else {
        return true;
    };
    let now = tokio::time::Instant::now();
    let next = (now + BOOT_SYNC_POLL).min(boot_until);
    if now < boot_until && !evpn_sessions_synced(&runtime.rib_tx, next).await {
        for deadline in by_esi
            .values_mut()
            .filter_map(|s| s.recovery_deadline.as_mut())
        {
            *deadline = (*deadline).max(next);
        }
        return false;
    }
    runtime.boot_until = None;
    true
}

/// A stalled RIB must not hold the actor past the boot ceiling: the whole
/// query is bounded by `deadline`, and a timeout counts as not synced.
async fn evpn_sessions_synced(
    rib_tx: &mpsc::Sender<RibUpdate>,
    deadline: tokio::time::Instant,
) -> bool {
    let (reply, rx) = oneshot::channel();
    tokio::time::timeout_at(deadline, async {
        rib_tx
            .send(RibUpdate::QueryEvpnSessionsSynced { reply })
            .await
            .is_ok()
            && rx.await.unwrap_or(false)
    })
    .await
    .unwrap_or(false)
}

async fn query_evpn_routes(
    rib_tx: &mpsc::Sender<RibUpdate>,
    filter: Option<RibRowFilter<EvpnRibRoute>>,
) -> Result<Vec<EvpnRibRoute>, RibQueryError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    rib_tx
        .send(RibUpdate::QueryEvpnRoutes {
            filter,
            reply: reply_tx,
        })
        .await
        .map_err(|_| RibQueryError::SendFailed)?;
    reply_rx.await.map_err(|_| RibQueryError::ReplyDropped)
}

#[derive(Debug, thiserror::Error)]
enum RibQueryError {
    #[error("RIB channel send failed")]
    SendFailed,
    #[error("RIB query reply channel dropped")]
    ReplyDropped,
}

async fn apply(
    runtime: &SegmentRuntime,
    state: &SegmentState,
    actions: Vec<OriginationAction>,
    pending: &mut PendingRibOps,
) {
    let Some(inst) = runtime.instances.get(state.reference_instance_id).cloned() else {
        // The reference instance is gone — e.g. a tenant teardown removed the
        // member L2VNI before this drain runs. Inject actions can't be built
        // without the instance's path attributes, but Withdraw actions only
        // need the route key, so still emit those; otherwise teardown would
        // strand the segment's Type 1/4 routes in peers' RIBs.
        apply_withdraws_only(runtime, state.reference_instance_id, actions, pending).await;
        return;
    };
    apply_with_instance(
        runtime,
        &inst,
        state.esi_label,
        state.config.df_algorithm,
        state.operational_df.0,
        state.operational_df.1,
        state.config.redundancy_mode,
        actions,
        pending,
    )
    .await;
}

/// Emit only the Withdraw actions from `actions`, dropping any Inject (which
/// can't be built without the now-removed reference instance). Used when the
/// member L2VNI has already been torn down but the segment's routes still need
/// to be withdrawn from the RIB.
async fn apply_withdraws_only(
    runtime: &SegmentRuntime,
    vni: EvpnInstanceId,
    actions: Vec<OriginationAction>,
    pending: &mut PendingRibOps,
) {
    for action in actions {
        let OriginationAction::Withdraw { key, .. } = &action else {
            continue;
        };
        let generation = pending.submit(*key, vni, action.clone());
        attempt_es_action(runtime, pending, generation, &action, None).await;
    }
}

/// Per-ES route-build context an inject attempt needs. Rebuilt from
/// the *current* `SegmentState` + instance table on every attempt so
/// retries never re-inject under stale fields.
struct EsRouteBuildCtx<'a> {
    inst: &'a EvpnInstance,
    esi_label: MplsLabel,
    df_algorithm: DfAlgorithm,
    df_preference: u32,
    df_dont_preempt: bool,
    redundancy_mode: RedundancyMode,
}

#[expect(
    clippy::too_many_arguments,
    reason = "per-ES origination context (esi_label + DF algorithm/preference/don't-preempt + redundancy mode) is threaded positionally; bundling it is a larger refactor than this slice warrants"
)]
async fn apply_with_instance(
    runtime: &SegmentRuntime,
    inst: &EvpnInstance,
    esi_label: MplsLabel,
    df_algorithm: DfAlgorithm,
    df_preference: u32,
    df_dont_preempt: bool,
    redundancy_mode: RedundancyMode,
    actions: Vec<OriginationAction>,
    pending: &mut PendingRibOps,
) {
    let ctx = EsRouteBuildCtx {
        inst,
        esi_label,
        df_algorithm,
        df_preference,
        df_dont_preempt,
        redundancy_mode,
    };
    for action in actions {
        let key = match &action {
            OriginationAction::Inject { key, .. } | OriginationAction::Withdraw { key, .. } => *key,
        };
        let generation = pending.submit(key, inst.id, action.clone());
        attempt_es_action(runtime, pending, generation, &action, Some(&ctx)).await;
    }
}

/// One send-and-ack attempt for a registered pending Type 1/4
/// operation (ADR-0102). Confirms on ack, defers on failure so the
/// actor's retry arm re-drives it. An inject attempted without a build
/// context (segment/instance no longer in the model) is dropped — the
/// teardown that removed it already superseded the route's state with
/// withdraws.
async fn attempt_es_action(
    runtime: &SegmentRuntime,
    pending: &mut PendingRibOps,
    generation: u64,
    action: &OriginationAction,
    ctx: Option<&EsRouteBuildCtx<'_>>,
) {
    let key = match action {
        OriginationAction::Inject { key, .. } | OriginationAction::Withdraw { key, .. } => *key,
    };
    match action {
        OriginationAction::Inject { .. } => {
            let Some(ctx) = ctx else {
                pending.forget(key, generation);
                debug!(
                    ?key,
                    "EVPN segment: dropping pending inject — segment or instance left the model"
                );
                return;
            };
            let Some(route) = build_es_route(
                ctx.inst,
                &key,
                ctx.esi_label,
                ctx.df_algorithm,
                ctx.df_preference,
                ctx.df_dont_preempt,
                ctx.redundancy_mode,
            ) else {
                // Wrong key shape is a programming bug (already logged at
                // warn by the builder) — retrying cannot fix it, so drop
                // the pending op instead of deferring it forever.
                pending.forget(key, generation);
                return;
            };
            match send_and_ack(&runtime.rib_tx, |reply| RibUpdate::InjectEvpn {
                route,
                reply,
            })
            .await
            {
                RibAckOutcome::Acked => {
                    pending.confirm(key, generation);
                    debug!(?key, "EVPN segment: originated");
                }
                RibAckOutcome::Rejected(e) => {
                    pending.defer(key, generation);
                    warn!(?key, error = %e, "EVPN segment: RIB rejected inject; will retry");
                }
                RibAckOutcome::NoAck(reason) => {
                    pending.defer(key, generation);
                    warn!(
                        ?key,
                        reason, "EVPN segment: inject unacknowledged; will retry"
                    );
                }
            }
        }
        OriginationAction::Withdraw { .. } => {
            let outcome = send_and_ack(&runtime.rib_tx, |reply| RibUpdate::WithdrawEvpn {
                key,
                reply,
            })
            .await;
            let not_found = outcome.is_not_found();
            match outcome {
                RibAckOutcome::Acked => {
                    pending.confirm(key, generation);
                    debug!(?key, "EVPN segment: withdrew");
                }
                // Already absent — e.g. the paired inject was lost
                // before ever applying. Absence is the goal: confirm.
                RibAckOutcome::Rejected(e) if not_found => {
                    pending.confirm(key, generation);
                    debug!(?key, error = %e, "EVPN segment: withdraw target absent — treating as complete");
                }
                RibAckOutcome::Rejected(e) => {
                    pending.defer(key, generation);
                    warn!(?key, error = %e, "EVPN segment: RIB rejected withdraw; will retry");
                }
                RibAckOutcome::NoAck(reason) => {
                    pending.defer(key, generation);
                    warn!(
                        ?key,
                        reason, "EVPN segment: withdraw unacknowledged; will retry"
                    );
                }
            }
        }
    }
}

/// The ESI carried by a Type 1/4 route key, used to relocate the
/// owning `SegmentState` when a pending inject is retried.
fn es_key_esi(key: &EvpnRouteKey) -> Option<EthernetSegmentIdentifier> {
    match key {
        EvpnRouteKey::Es { esi, .. }
        | EvpnRouteKey::EadPerEs { esi, .. }
        | EvpnRouteKey::EadPerEvi { esi, .. } => Some(*esi),
        _ => None,
    }
}

/// Re-drive every pending Type 1/4 operation whose backoff has
/// elapsed (ADR-0102). Withdraws only need the key; injects rebuild
/// their route from the current segment/instance model and are
/// dropped when that model no longer contains them (the removal path
/// already superseded the route's state with withdraws).
async fn retry_pending_rib_ops(
    runtime: &SegmentRuntime,
    by_esi: &HashMap<EthernetSegmentIdentifier, SegmentState>,
    pending: &mut PendingRibOps,
) {
    for (key, op) in pending.due(tokio::time::Instant::now()) {
        match &op.action {
            OriginationAction::Withdraw { .. } => {
                attempt_es_action(runtime, pending, op.generation, &op.action, None).await;
            }
            OriginationAction::Inject { .. } => {
                let segment = es_key_esi(&key)
                    .filter(|esi| !runtime.drained_esis.contains(esi))
                    .and_then(|esi| by_esi.get(&esi));
                let ctx = segment.and_then(|state| {
                    runtime.instances.get(op.vni).map(|inst| EsRouteBuildCtx {
                        inst,
                        esi_label: state.esi_label,
                        df_algorithm: state.config.df_algorithm,
                        df_preference: state.operational_df.0,
                        df_dont_preempt: state.operational_df.1,
                        redundancy_mode: state.config.redundancy_mode,
                    })
                });
                attempt_es_action(runtime, pending, op.generation, &op.action, ctx.as_ref()).await;
            }
        }
    }
}

/// Build the wire-shaped `EvpnRibRoute` for a Type 1/4 origination.
///
/// Path attributes: Origin, empty `AsPath`, plus the instance's
/// configured RT extcomms and the VXLAN BGP Encapsulation extcomm
/// (RFC 8365 §5.1.3 lists ES and both EAD routes). The VTEP IP is carried separately as the
/// route's `next_hop` and encoded only in `MP_REACH_NLRI`; no `NEXT_HOP`
/// attribute is stored. Per RFC 7432, Gate 8b prep
/// also attaches:
///
/// - **Type 4 ES**: ES-Import RT extcomm (§7.6) auto-derived from
///   ESI bytes [1..7]. Peers can now correlate the segment via RT
///   match without preconfiguration.
/// - **Type 1 EAD-per-ES**: ESI Label extcomm (§7.5) carrying the
///   synthesized ESI label and the configured redundancy-mode flag
///   (`single_active` set for single-active). Peers wire the label
///   into their split-horizon filter tables; Gate 8b adds the
///   dataplane drops on non-DF receivers.
/// - **Type 4 ES with RFC 8584/9785 DF extcomm**: non-default
///   algorithms advertise their algorithm ID; preference algorithms
///   also advertise the configured DF Preference, with the
///   Don't-Preempt bit set when the ES is configured non-revertive.
/// - **Type 1 EAD-per-EVI**: no extra extcomms (the per-EVI label
///   lives in the route's MPLS label field; aliasing extcomms are
///   Gate 8b territory).
///
/// Returns `None` for key shapes this builder does not originate
/// (anything other than Type 4 ES / EAD-per-ES / EAD-per-EVI): the old
/// fallback synthesized a zero-ESI Type 4 route that the wire decoder
/// itself rejects as malformed, so a fired fallback emitted
/// undecodable bytes.
fn build_es_route(
    instance: &EvpnInstance,
    key: &EvpnRouteKey,
    esi_label: MplsLabel,
    df_algorithm: DfAlgorithm,
    df_preference: u32,
    df_dont_preempt: bool,
    redundancy_mode: RedundancyMode,
) -> Option<EvpnRibRoute> {
    let (route, key_specific_extcomms): (EvpnRoute, Vec<rustbgpd_wire::ExtendedCommunity>) =
        match key {
            EvpnRouteKey::Es {
                rd,
                esi,
                originator_ip,
            } => (
                EvpnRoute::Es(EvpnEs {
                    rd: *rd,
                    esi: *esi,
                    originator_ip: *originator_ip,
                }),
                // RFC 7432 §7.6: ES-Import RT is the high-order 6
                // octets of the ESI Value (= ESI bytes [1..7] of the
                // 10-byte wire encoding). Peers that filter Type 4
                // imports on this RT can correlate the segment back
                // to the ESI without RT preconfiguration.
                type4_es_extcomms(*esi, df_algorithm, df_preference, df_dont_preempt),
            ),
            EvpnRouteKey::EadPerEs {
                rd,
                esi,
                ethernet_tag,
            } => (
                EvpnRoute::EadPerEs(EvpnEadPerEs {
                    rd: *rd,
                    esi: *esi,
                    ethernet_tag: *ethernet_tag,
                    label: esi_label,
                }),
                // RFC 7432 §7.5: ESI Label extcomm carries the label
                // peers will match against the inner VXLAN/MPLS label
                // for split-horizon enforcement. Single source of
                // truth: the per-ESI allocator's reservation, threaded
                // through `apply_with_instance` so the route's
                // `EvpnEadPerEs.label` field and this extcomm always
                // agree.
                vec![rustbgpd_wire::ExtendedCommunity::esi_label(
                    redundancy_mode.is_single_active(),
                    esi_label.value(),
                )],
            ),
            EvpnRouteKey::EadPerEvi {
                rd,
                esi,
                ethernet_tag,
            } => (
                EvpnRoute::EadPerEvi(EvpnEadPerEvi {
                    rd: *rd,
                    esi: *esi,
                    // 0 for VLAN-based service (RFC 7432 §6.1 /
                    // RFC 8365 §5.1.3) — must match the Type 2 routes'
                    // tag so remote `(ESI, EthernetTag)` aliasing /
                    // eligible-set joins resolve.
                    ethernet_tag: *ethernet_tag,
                    // RFC 8365 §5.1.3: the EAD-per-EVI label field
                    // carries the VNI. Every per-EVI Inject reaches
                    // this builder with the member VNI's own instance
                    // (`run_election_with_candidates` looks it up per
                    // VNI before `apply_with_instance`).
                    label: MplsLabel::new(instance.id.as_u32()),
                }),
                // RFC 7432 §14: EAD-per-EVI carries no ESI Label —
                // the per-EVI label comes from the route's own MPLS
                // label field. The aliasing extcomms (single-active
                // backup signaling) land in Gate 8b.
                Vec::new(),
            ),
            // Other key shapes shouldn't reach this builder — Type 1/4
            // originators only emit the three above. A zero-ESI Type 4
            // fallback is not an option: the decoder rejects it as
            // malformed, so it would put undecodable bytes on the wire.
            other => {
                warn!(
                    ?other,
                    "EVPN segment: unexpected key shape passed to ES route builder; skipping"
                );
                return None;
            }
        };

    let mut ext_communities = instance_extcomms(instance);
    ext_communities.extend(key_specific_extcomms);

    let attributes: Vec<PathAttribute> = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        PathAttribute::ExtendedCommunities(ext_communities),
    ];

    Some(EvpnRibRoute {
        route,
        next_hop: instance.local_vtep_ip,
        link_local_next_hop: None,
        peer: LOCAL_PEER,
        attributes: AttrSet::new(attributes),
        received_at: Instant::now(),
        origin_type: rustbgpd_rib::route::RouteOrigin::Local,
        peer_router_id: std::net::Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
    })
}

/// Derive the ES-Import Route Target MAC from an ESI per
/// RFC 7432 §7.6: the high-order 6 octets of the 9-byte ESI Value
/// (i.e. bytes [1..7] of the 10-byte wire encoding). All ESI types
/// share this rule; for Type 0/1/2 system-MAC-derived ESIs the
/// resulting RT happens to encode that system MAC, which is what
/// FRR / Junos / Cumulus already filter on.
fn es_import_rt_from_esi(esi: EthernetSegmentIdentifier) -> [u8; 6] {
    let o = esi.octets();
    [o[1], o[2], o[3], o[4], o[5], o[6]]
}

/// Format an ESI as colon-separated hex bytes, matching the operator
/// config text form. Used as a metric label and CLI output.
fn format_esi(esi: EthernetSegmentIdentifier) -> String {
    let o = esi.octets();
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7], o[8], o[9],
    )
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;
    use rustbgpd_evpn::{EvpnInstance, EvpnInstanceTable};
    use rustbgpd_wire::{EthernetTagId, ExtendedCommunity};

    use crate::test_support::{
        RibReplyMode, ScriptedRib, assert_wire_vxlan_encapsulation, evpn_instance, ip as ipa, rd,
        vni,
    };

    fn esi(seed: u8) -> EthernetSegmentIdentifier {
        EthernetSegmentIdentifier::new([seed; 10])
    }

    fn instance(v: u32) -> EvpnInstance {
        instance_with_rd(v, v)
    }

    fn instance_with_rd(v: u32, rd_value: u32) -> EvpnInstance {
        evpn_instance(65000, v, rd_value, Some(format!("br{v}")), false)
    }

    fn segment_state(id: EthernetSegmentIdentifier) -> SegmentState {
        let member_vnis = std::collections::BTreeSet::from([vni(100)]);
        let config = EthernetSegment {
            esi: id,
            member_vnis: member_vnis.clone(),
            df_preference: 32_768,
            df_algorithm: DfAlgorithm::DefaultModulo,
            df_dont_preempt: false,
            redundancy_mode: RedundancyMode::AllActive,
            originator_ip: ipa("10.0.0.1"),
        };
        SegmentState {
            operational_df: (config.df_preference, config.df_dont_preempt),
            recovery_deadline: None,
            config,
            es_origin: LocalEsOriginator::new(rd(65000, 100), id, ipa("10.0.0.1")),
            ead_per_es: LocalEadPerEsOriginator::new(rd(65000, 100), id, MplsLabel::new(123)),
            ead_per_evi: LocalEadPerEviOriginator::new(rd(65000, 100), id),
            election: DfElection::new(id, member_vnis),
            last_roles: BTreeMap::new(),
            reference_instance_id: vni(100),
            esi_label: MplsLabel::new(123),
        }
    }

    fn segment(id: EthernetSegmentIdentifier, members: &[u32]) -> EthernetSegment {
        EthernetSegment {
            esi: id,
            member_vnis: members.iter().copied().map(vni).collect(),
            df_preference: 32_768,
            df_algorithm: DfAlgorithm::DefaultModulo,
            df_dont_preempt: false,
            redundancy_mode: RedundancyMode::AllActive,
            originator_ip: ipa("10.0.0.1"),
        }
    }

    fn type_4_es_route(
        id: EthernetSegmentIdentifier,
        originator_ip: &str,
        attrs: Vec<PathAttribute>,
    ) -> EvpnRibRoute {
        EvpnRibRoute {
            route: EvpnRoute::Es(EvpnEs {
                rd: rd(65000, 100),
                esi: id,
                originator_ip: ipa(originator_ip),
            }),
            next_hop: ipa(originator_ip),
            link_local_next_hop: None,
            peer: ipa(originator_ip),
            attributes: AttrSet::new(attrs),
            received_at: Instant::now(),
            origin_type: rustbgpd_rib::route::RouteOrigin::Ibgp,
            peer_router_id: "192.0.2.1".parse().unwrap(),
            is_stale: false,
            is_llgr_stale: false,
        }
    }

    fn attrs_with_es_import_rt(id: EthernetSegmentIdentifier) -> Vec<PathAttribute> {
        vec![PathAttribute::ExtendedCommunities(vec![
            ExtendedCommunity::es_import_rt(es_import_rt_from_esi(id)),
        ])]
    }

    fn rib_recorder(
        mut rib_rx: mpsc::Receiver<RibUpdate>,
        injects: Arc<tokio::sync::Mutex<Vec<EvpnRouteKey>>>,
        withdraws: Arc<tokio::sync::Mutex<Vec<EvpnRouteKey>>>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let (events_tx, _) = broadcast::channel(16);
            while let Some(update) = rib_rx.recv().await {
                match update {
                    RibUpdate::SubscribeEvpnRouteEvents { reply } => {
                        let _ = reply.send(events_tx.subscribe());
                    }
                    RibUpdate::QueryEvpnRoutes { reply, .. } => {
                        let _ = reply.send(Vec::new());
                    }
                    RibUpdate::QueryEvpnSessionsSynced { reply } => {
                        let _ = reply.send(true);
                    }
                    RibUpdate::InjectEvpn { route, reply } => {
                        injects.lock().await.push(route.key());
                        let _ = reply.send(Ok(()));
                    }
                    RibUpdate::WithdrawEvpn { key, reply } => {
                        withdraws.lock().await.push(key);
                        let _ = reply.send(Ok(()));
                    }
                    _ => {}
                }
            }
        })
    }

    async fn wait_for_keys(
        keys: &Arc<tokio::sync::Mutex<Vec<EvpnRouteKey>>>,
        expected: usize,
        label: &str,
    ) -> Vec<EvpnRouteKey> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let observed = keys.lock().await.clone();
            if observed.len() >= expected {
                return observed;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {expected} {label}; observed {observed:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[test]
    fn esi_label_allocator_is_deterministic_for_first_seen() {
        // The orchestrator now reaches for the per-ESI allocator,
        // which delegates first-seen ESIs to the deterministic
        // synth so operators upgrading from Gate 8b prep see no
        // label change. The allocator's collision-avoidance path
        // is covered by `crates/evpn/src/label_allocator.rs::tests`.
        use rustbgpd_evpn::EsiLabelAllocator;
        let mut a = EsiLabelAllocator::new();
        let label_a = a.reserve(esi(0x42)).unwrap();
        let label_b = a.reserve(esi(0x42)).unwrap();
        assert_eq!(label_a, label_b);
        assert!(label_a.value() >= 16);
        assert!(label_a.value() < (1 << 20));
    }

    #[test]
    fn format_esi_matches_operator_text_form() {
        let id = EthernetSegmentIdentifier::new([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        ]);
        assert_eq!(format_esi(id), "01:02:03:04:05:06:07:08:09:0a");
    }

    #[test]
    fn build_es_route_emits_path_attributes_minimum() {
        let inst = instance(100);
        let key = EvpnRouteKey::Es {
            rd: rd(65000, 100),
            esi: esi(1),
            originator_ip: ipa("10.0.0.1"),
        };
        let route = build_es_route(
            &inst,
            &key,
            MplsLabel::new(123),
            DfAlgorithm::DefaultModulo,
            32_768,
            false,
            RedundancyMode::AllActive,
        )
        .expect("ES route builder accepts Type 1/4 keys");
        assert!(matches!(route.route, EvpnRoute::Es(_)));
        // Must carry: Origin, AsPath, ExtendedCommunities; no NEXT_HOP
        // beside the MP_REACH next hop.
        assert!(
            route
                .attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::Origin(_)))
        );
        assert!(
            route
                .attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::AsPath(_)))
        );
        assert!(
            !route
                .attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::NextHop(_)))
        );
        assert!(
            route
                .attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::ExtendedCommunities(_)))
        );
    }

    /// Regression: a key shape the Type 1/4 originators never emit is
    /// skipped, not "handled" by synthesizing a fallback route. The old
    /// fallback built a zero-ESI Type 4 that the wire decoder itself
    /// rejects ("EVPN Type 4 ES route with all-zero ESI"), so a fired
    /// fallback put undecodable bytes on the wire.
    #[test]
    fn build_es_route_skips_unexpected_key_shape() {
        let inst = instance(100);
        let key = EvpnRouteKey::Imet {
            rd: rd(65000, 100),
            ethernet_tag: EthernetTagId(0),
            originator_ip: ipa("10.0.0.1"),
        };
        let route = build_es_route(
            &inst,
            &key,
            MplsLabel::new(123),
            DfAlgorithm::DefaultModulo,
            32_768,
            false,
            RedundancyMode::AllActive,
        );
        assert!(route.is_none(), "unexpected key shape must be skipped");
    }

    #[test]
    fn build_ead_per_es_route_uses_max_et() {
        let inst = instance(100);
        let key = EvpnRouteKey::EadPerEs {
            rd: rd(65000, 100),
            esi: esi(1),
            ethernet_tag: EthernetTagId::MAX_ET,
        };
        let route = build_es_route(
            &inst,
            &key,
            MplsLabel::new(123),
            DfAlgorithm::DefaultModulo,
            32_768,
            false,
            RedundancyMode::AllActive,
        )
        .expect("ES route builder accepts Type 1/4 keys");
        match route.route {
            EvpnRoute::EadPerEs(r) => {
                assert_eq!(r.ethernet_tag, EthernetTagId::MAX_ET);
            }
            other => panic!("expected EadPerEs, got {other:?}"),
        }
    }

    #[test]
    fn build_ead_per_evi_route_carries_vni_label_and_zero_tag() {
        // RFC 8365 §5.1.3: the VNI rides in the route's label field;
        // the Ethernet Tag stays 0 for VLAN-based service (RFC 7432
        // §6.1) so the route joins remote (ESI, tag 0) MAC keys.
        let inst = instance(100);
        let key = EvpnRouteKey::EadPerEvi {
            rd: rd(65000, 100),
            esi: esi(1),
            ethernet_tag: EthernetTagId(0),
        };
        let route = build_es_route(
            &inst,
            &key,
            MplsLabel::new(123),
            DfAlgorithm::DefaultModulo,
            32_768,
            false,
            RedundancyMode::AllActive,
        )
        .expect("ES route builder accepts Type 1/4 keys");
        match route.route {
            EvpnRoute::EadPerEvi(r) => {
                assert_eq!(r.ethernet_tag.0, 0);
                assert_eq!(r.label.value(), 100, "label must carry the instance VNI");
            }
            other => panic!("expected EadPerEvi, got {other:?}"),
        }
    }

    /// RFC 8365 §5.1.3 lists ES, EAD-per-ES and EAD-per-EVI routes among
    /// those that carry the VXLAN Encapsulation extended community.
    #[test]
    fn es_and_ead_wire_attributes_carry_vxlan_encapsulation() {
        let inst = instance(100);
        let keys = [
            EvpnRouteKey::Es {
                rd: rd(65000, 100),
                esi: esi(1),
                originator_ip: ipa("10.0.0.1"),
            },
            EvpnRouteKey::EadPerEs {
                rd: rd(65000, 100),
                esi: esi(1),
                ethernet_tag: EthernetTagId::MAX_ET,
            },
            EvpnRouteKey::EadPerEvi {
                rd: rd(65000, 100),
                esi: esi(1),
                ethernet_tag: EthernetTagId(0),
            },
        ];
        for key in keys {
            let route = build_es_route(
                &inst,
                &key,
                MplsLabel::new(123),
                DfAlgorithm::DefaultModulo,
                32_768,
                false,
                RedundancyMode::AllActive,
            )
            .expect("ES route builder accepts Type 1/4 keys");
            assert_wire_vxlan_encapsulation(&route);
        }
    }

    #[test]
    fn decode_df_election_extcomm_reads_five_bit_algorithm() {
        let ec = ExtendedCommunity::df_election(1, 0, None);
        let attrs = [PathAttribute::ExtendedCommunities(vec![ec])];
        let (pref, dont_preempt, alg) = decode_df_election_extcomm(&attrs).unwrap();
        assert_eq!(pref, 32_767);
        assert!(!dont_preempt);
        assert_eq!(alg, DfAlgorithm::HighestRandomWeight);
    }

    #[test]
    fn decode_df_election_extcomm_reads_rfc9785_preference_bytes() {
        let ec = ExtendedCommunity::df_election(3, 0x8000, Some(42));
        let attrs = [PathAttribute::ExtendedCommunities(vec![ec])];
        let (pref, dont_preempt, alg) = decode_df_election_extcomm(&attrs).unwrap();
        assert_eq!(pref, 42);
        assert!(dont_preempt);
        assert_eq!(alg, DfAlgorithm::LowestPreference);
    }

    #[test]
    fn partial_extended_communities_preserve_es_import_and_df_election() {
        let id = esi(0x44);
        let communities = vec![
            ExtendedCommunity::es_import_rt(es_import_rt_from_esi(id)),
            ExtendedCommunity::df_election(3, 0x8000, Some(42)),
        ];
        let canonical = [PathAttribute::ExtendedCommunities(communities.clone())];
        let partial = [PathAttribute::ExtendedCommunitiesPartial(communities)];

        assert!(has_matching_es_import_rt(&canonical, id));
        assert_eq!(
            has_matching_es_import_rt(&partial, id),
            has_matching_es_import_rt(&canonical, id)
        );
        assert_eq!(
            decode_df_election_extcomm(&partial),
            decode_df_election_extcomm(&canonical)
        );
    }

    #[test]
    fn es_import_rt_derives_from_esi_value_high_six_octets() {
        // RFC 7432 §7.6: bytes [1..7] of the 10-byte ESI.
        let id = EthernetSegmentIdentifier::new([
            0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, 0x01,
        ]);
        assert_eq!(
            es_import_rt_from_esi(id),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
    }

    #[test]
    fn type_4_es_route_carries_es_import_rt_extcomm() {
        let inst = instance(100);
        let id = EthernetSegmentIdentifier::new([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x00, 0x00, 0x01,
        ]);
        let key = EvpnRouteKey::Es {
            rd: rd(65000, 100),
            esi: id,
            originator_ip: ipa("10.0.0.1"),
        };
        let route = build_es_route(
            &inst,
            &key,
            MplsLabel::new(123),
            DfAlgorithm::DefaultModulo,
            32_768,
            false,
            RedundancyMode::AllActive,
        )
        .expect("ES route builder accepts Type 1/4 keys");
        let extcomms = route
            .attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::ExtendedCommunities(v) => Some(v.clone()),
                _ => None,
            })
            .expect("ExtendedCommunities attribute present");
        let derived = extcomms
            .iter()
            .copied()
            .find_map(ExtendedCommunity::as_es_import_rt)
            .expect("ES-Import RT extcomm attached");
        assert_eq!(derived, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    }

    #[test]
    fn type_4_es_route_carries_hrw_df_election_extcomm_when_configured() {
        let inst = instance(100);
        let id = esi(0x21);
        let key = EvpnRouteKey::Es {
            rd: rd(65000, 100),
            esi: id,
            originator_ip: ipa("10.0.0.1"),
        };
        let route = build_es_route(
            &inst,
            &key,
            MplsLabel::new(123),
            DfAlgorithm::HighestRandomWeight,
            32_768,
            false,
            RedundancyMode::AllActive,
        )
        .expect("ES route builder accepts Type 1/4 keys");
        let extcomms = route
            .attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::ExtendedCommunities(v) => Some(v.clone()),
                _ => None,
            })
            .expect("ExtendedCommunities attribute present");
        let df = extcomms
            .iter()
            .copied()
            .find_map(ExtendedCommunity::as_df_election)
            .expect("DF Election extcomm attached");
        assert_eq!(
            df.algorithm_id,
            DfAlgorithm::HighestRandomWeight.algorithm_id()
        );
        assert_eq!(df.capabilities, 0);
        assert_eq!(df.preference, None);
    }

    #[test]
    fn type_4_es_route_carries_preference_df_election_extcomm_when_configured() {
        let inst = instance(100);
        let id = esi(0x23);
        let key = EvpnRouteKey::Es {
            rd: rd(65000, 100),
            esi: id,
            originator_ip: ipa("10.0.0.1"),
        };
        let route = build_es_route(
            &inst,
            &key,
            MplsLabel::new(123),
            DfAlgorithm::HighestPreference,
            500,
            false,
            RedundancyMode::AllActive,
        )
        .expect("ES route builder accepts Type 1/4 keys");
        let extcomms = route
            .attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::ExtendedCommunities(v) => Some(v.clone()),
                _ => None,
            })
            .expect("ExtendedCommunities attribute present");
        let df = extcomms
            .iter()
            .copied()
            .find_map(ExtendedCommunity::as_df_election)
            .expect("DF Election extcomm attached");
        assert_eq!(
            df.algorithm_id,
            DfAlgorithm::HighestPreference.algorithm_id()
        );
        assert_eq!(df.capabilities, 0);
        assert_eq!(df.preference, Some(500));
    }

    #[test]
    fn preference_df_election_extcomm_sets_dont_preempt_bit_when_configured() {
        let inst = instance(100);
        let key = EvpnRouteKey::Es {
            rd: rd(65000, 100),
            esi: esi(0x24),
            originator_ip: ipa("10.0.0.1"),
        };
        let route = build_es_route(
            &inst,
            &key,
            MplsLabel::new(123),
            DfAlgorithm::HighestPreference,
            500,
            true, // df_dont_preempt
            RedundancyMode::AllActive,
        )
        .expect("ES route builder accepts Type 1/4 keys");
        let df = route
            .attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::ExtendedCommunities(v) => Some(v.clone()),
                _ => None,
            })
            .expect("ExtendedCommunities attribute present")
            .iter()
            .copied()
            .find_map(ExtendedCommunity::as_df_election)
            .expect("DF Election extcomm attached");
        assert_eq!(df.capabilities, 0x8000, "RFC 9785 DP bit must be set");
        assert_eq!(df.preference, Some(500));

        // The decode path a peer would run must read DP=true back.
        let (_pref, dont_preempt, _alg) =
            decode_df_election_extcomm(&route.attributes).expect("decodes");
        assert!(dont_preempt);
    }

    #[test]
    fn lowest_preference_df_election_extcomm_carries_dont_preempt_and_algorithm() {
        let inst = instance(100);
        let key = EvpnRouteKey::Es {
            rd: rd(65000, 100),
            esi: esi(0x25),
            originator_ip: ipa("10.0.0.1"),
        };
        let route = build_es_route(
            &inst,
            &key,
            MplsLabel::new(123),
            DfAlgorithm::LowestPreference,
            42,
            true, // df_dont_preempt
            RedundancyMode::AllActive,
        )
        .expect("ES route builder accepts Type 1/4 keys");
        let df = route
            .attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::ExtendedCommunities(v) => Some(v.clone()),
                _ => None,
            })
            .expect("ExtendedCommunities attribute present")
            .iter()
            .copied()
            .find_map(ExtendedCommunity::as_df_election)
            .expect("DF Election extcomm attached");
        assert_eq!(
            df.algorithm_id,
            DfAlgorithm::LowestPreference.algorithm_id()
        );
        assert_eq!(df.capabilities, 0x8000, "RFC 9785 DP bit must be set");
        assert_eq!(df.preference, Some(42));
        let (_pref, dont_preempt, alg) =
            decode_df_election_extcomm(&route.attributes).expect("decodes");
        assert!(dont_preempt);
        assert_eq!(alg, DfAlgorithm::LowestPreference);
    }

    #[test]
    fn default_modulo_type_4_es_route_omits_df_election_extcomm() {
        let inst = instance(100);
        let id = esi(0x22);
        let key = EvpnRouteKey::Es {
            rd: rd(65000, 100),
            esi: id,
            originator_ip: ipa("10.0.0.1"),
        };
        let route = build_es_route(
            &inst,
            &key,
            MplsLabel::new(123),
            DfAlgorithm::DefaultModulo,
            32_768,
            false,
            RedundancyMode::AllActive,
        )
        .expect("ES route builder accepts Type 1/4 keys");
        let extcomms = route
            .attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::ExtendedCommunities(v) => Some(v.clone()),
                _ => None,
            })
            .expect("ExtendedCommunities attribute present");
        assert!(
            extcomms
                .iter()
                .copied()
                .all(|ec| ec.as_df_election().is_none())
        );
    }

    #[test]
    fn gather_candidates_accepts_type_4_with_matching_es_import_rt() {
        let id = esi(0x11);
        let state = segment_state(id);
        let routes = vec![type_4_es_route(id, "10.0.0.2", attrs_with_es_import_rt(id))];

        let candidates = gather_candidates_from_routes(&state, &routes);

        assert_eq!(candidates.len(), 2);
        assert!(
            candidates
                .iter()
                .any(|c| c.originator_ip == ipa("10.0.0.1"))
        );
        assert!(
            candidates
                .iter()
                .any(|c| c.originator_ip == ipa("10.0.0.2"))
        );
    }

    #[test]
    fn gather_candidates_captures_remote_preference_df_fields() {
        let id = esi(0x16);
        let state = segment_state(id);
        let mut attrs = attrs_with_es_import_rt(id);
        attrs.push(PathAttribute::ExtendedCommunities(vec![
            ExtendedCommunity::df_election(
                DfAlgorithm::LowestPreference.algorithm_id(),
                0x8000,
                Some(42),
            ),
        ]));
        let routes = vec![type_4_es_route(id, "10.0.0.2", attrs)];

        let candidates = gather_candidates_from_routes(&state, &routes);
        let remote = candidates
            .iter()
            .find(|c| c.originator_ip == ipa("10.0.0.2"))
            .expect("remote candidate present");
        assert_eq!(remote.df_algorithm, DfAlgorithm::LowestPreference);
        assert_eq!(remote.df_preference, 42);
        assert!(remote.df_dont_preempt);
    }

    #[test]
    fn gather_candidates_resolves_one_originator_under_two_rds_by_lowest_rd() {
        // One remote PE advertises the ESI under two RDs whose DF Election
        // extcomms disagree. The lower RD supplies the candidate whichever
        // order the RIB yields the routes in.
        let id = esi(0x17);
        let state = segment_state(id);
        let es_route = |rd_value: u32, alg: DfAlgorithm, capabilities: u16, preference: u16| {
            let mut attrs = attrs_with_es_import_rt(id);
            attrs.push(PathAttribute::ExtendedCommunities(vec![
                ExtendedCommunity::df_election(alg.algorithm_id(), capabilities, Some(preference)),
            ]));
            let mut route = type_4_es_route(id, "10.0.0.2", attrs);
            route.route = EvpnRoute::Es(EvpnEs {
                rd: rd(65000, rd_value),
                esi: id,
                originator_ip: ipa("10.0.0.2"),
            });
            route
        };
        // Every DF field differs, so a mixed candidate cannot pass.
        let low_rd = es_route(100, DfAlgorithm::HighestPreference, 0x8000, 500);
        let high_rd = es_route(200, DfAlgorithm::LowestPreference, 0, 900);

        for routes in [
            vec![low_rd.clone(), high_rd.clone()],
            vec![high_rd.clone(), low_rd.clone()],
        ] {
            let candidates = gather_candidates_from_routes(&state, &routes);
            assert_eq!(candidates.len(), 2);
            let remote = candidates
                .iter()
                .find(|c| c.originator_ip == ipa("10.0.0.2"))
                .expect("remote candidate present");
            assert_eq!(remote.df_preference, 500);
            assert!(remote.df_dont_preempt);
            assert_eq!(remote.df_algorithm, DfAlgorithm::HighestPreference);
        }
    }

    #[test]
    fn gather_candidates_ignores_type_4_missing_es_import_rt() {
        let id = esi(0x12);
        let state = segment_state(id);
        let routes = vec![type_4_es_route(id, "10.0.0.2", Vec::new())];

        let candidates = gather_candidates_from_routes(&state, &routes);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].originator_ip, ipa("10.0.0.1"));
    }

    #[test]
    fn gather_candidates_ignores_type_4_with_mismatched_es_import_rt() {
        let id = esi(0x13);
        let state = segment_state(id);
        let routes = vec![type_4_es_route(
            id,
            "10.0.0.2",
            attrs_with_es_import_rt(esi(0x44)),
        )];

        let candidates = gather_candidates_from_routes(&state, &routes);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].originator_ip, ipa("10.0.0.1"));
    }

    #[test]
    fn gather_candidates_still_ignores_unrelated_esi_with_matching_rt() {
        let id = esi(0x14);
        let other_id = esi(0x15);
        let state = segment_state(id);
        let routes = vec![type_4_es_route(
            other_id,
            "10.0.0.2",
            attrs_with_es_import_rt(other_id),
        )];

        let candidates = gather_candidates_from_routes(&state, &routes);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].originator_ip, ipa("10.0.0.1"));
    }

    #[test]
    fn type_1_ead_per_es_carries_esi_label_extcomm() {
        let inst = instance(100);
        let id = esi(7);
        let key = EvpnRouteKey::EadPerEs {
            rd: rd(65000, 100),
            esi: id,
            ethernet_tag: EthernetTagId::MAX_ET,
        };
        let route = build_es_route(
            &inst,
            &key,
            MplsLabel::new(123),
            DfAlgorithm::DefaultModulo,
            32_768,
            false,
            RedundancyMode::AllActive,
        )
        .expect("ES route builder accepts Type 1/4 keys");
        let extcomms = route
            .attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::ExtendedCommunities(v) => Some(v.clone()),
                _ => None,
            })
            .expect("ExtendedCommunities attribute present");
        let (single_active, label) = extcomms
            .iter()
            .copied()
            .find_map(ExtendedCommunity::as_esi_label)
            .expect("ESI Label extcomm attached");
        assert!(!single_active, "Gate 8 default is all-active");
        // Allocator-driven label is whatever we passed to
        // build_es_route, so the test asserts the round-trip rather
        // than a specific synth value.
        assert_eq!(label, 123);
        // The EAD-per-ES NLRI's MPLS label field must agree with
        // the extcomm — single source of truth via `esi_label`.
        let EvpnRoute::EadPerEs(ead) = &route.route else {
            panic!("expected EadPerEs route, got {:?}", route.route);
        };
        assert_eq!(ead.label.value(), 123);
        let _ = id; // ESI not asserted here; covered by other tests.
    }

    #[test]
    fn type_1_ead_per_es_sets_single_active_flag_when_configured() {
        let inst = instance(100);
        let id = esi(8);
        let key = EvpnRouteKey::EadPerEs {
            rd: rd(65000, 100),
            esi: id,
            ethernet_tag: EthernetTagId::MAX_ET,
        };
        let route = build_es_route(
            &inst,
            &key,
            MplsLabel::new(123),
            DfAlgorithm::DefaultModulo,
            32_768,
            false,
            RedundancyMode::SingleActive,
        )
        .expect("ES route builder accepts Type 1/4 keys");
        let extcomms = route
            .attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::ExtendedCommunities(v) => Some(v.clone()),
                _ => None,
            })
            .expect("ExtendedCommunities attribute present");
        let (single_active, label) = extcomms
            .iter()
            .copied()
            .find_map(ExtendedCommunity::as_esi_label)
            .expect("ESI Label extcomm attached");
        assert!(single_active);
        assert_eq!(label, 123);
    }

    #[test]
    fn type_1_ead_per_evi_does_not_carry_esi_label_extcomm() {
        let inst = instance(100);
        let key = EvpnRouteKey::EadPerEvi {
            rd: rd(65000, 100),
            esi: esi(1),
            ethernet_tag: EthernetTagId(0),
        };
        let route = build_es_route(
            &inst,
            &key,
            MplsLabel::new(123),
            DfAlgorithm::DefaultModulo,
            32_768,
            false,
            RedundancyMode::AllActive,
        )
        .expect("ES route builder accepts Type 1/4 keys");
        let extcomms = route
            .attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::ExtendedCommunities(v) => Some(v.clone()),
                _ => None,
            })
            .expect("ExtendedCommunities attribute present");
        assert!(
            extcomms
                .iter()
                .copied()
                .all(|ec| ec.as_esi_label().is_none()),
            "EAD-per-EVI must not carry ESI Label (RFC 7432 §14)"
        );
        assert!(
            extcomms
                .iter()
                .copied()
                .all(|ec| ec.as_es_import_rt().is_none()),
            "EAD-per-EVI must not carry ES-Import RT (Type 4 only)"
        );
    }

    #[tokio::test]
    async fn spawn_returns_none_for_empty_segments() {
        let mut t = EvpnInstanceTable::new();
        t.insert(instance(100)).unwrap();
        let instances = Arc::new(t);
        let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(4);
        let metrics = BgpMetrics::new();
        let h = spawn(
            &instances,
            Vec::new(),
            rib_tx,
            None,
            metrics,
            CancellationToken::new(),
        );
        assert!(h.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn runtime_control_replaces_segments_and_drains_removed_routes() {
        let mut t = EvpnInstanceTable::new();
        t.insert(instance(100)).unwrap();
        let instances = Arc::new(t);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(32);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _rib = rib_recorder(rib_rx, injects.clone(), withdraws.clone());

        let handle = spawn(
            &instances,
            vec![segment(esi(0x21), &[100])],
            rib_tx,
            None,
            BgpMetrics::new(),
            CancellationToken::new(),
        )
        .expect("non-empty ES config should spawn segment actor");
        let control = handle.runtime_control();
        assert!(control.is_open());

        let injected = wait_for_keys(&injects, 3, "ES injections").await;
        assert!(
            injected
                .iter()
                .any(|key| matches!(key, EvpnRouteKey::Es { .. }))
        );
        assert!(
            injected
                .iter()
                .any(|key| matches!(key, EvpnRouteKey::EadPerEs { .. }))
        );
        assert!(
            injected
                .iter()
                .any(|key| matches!(key, EvpnRouteKey::EadPerEvi { .. }))
        );

        assert!(control.replace_segments(Arc::new(Vec::new())));
        let drained_keys = wait_for_keys(&withdraws, 3, "ES withdraws").await;
        assert!(
            drained_keys
                .iter()
                .any(|key| matches!(key, EvpnRouteKey::Es { .. }))
        );
        assert!(
            drained_keys
                .iter()
                .any(|key| matches!(key, EvpnRouteKey::EadPerEs { .. }))
        );
        assert!(
            drained_keys
                .iter()
                .any(|key| matches!(key, EvpnRouteKey::EadPerEvi { .. }))
        );

        handle.shutdown().await;
        assert!(!control.is_open());
    }

    #[tokio::test(start_paused = true)]
    async fn runtime_control_drains_routes_when_member_instance_removed_with_segment() {
        // Tenant teardown removes the member L2VNI and its Ethernet Segment in
        // the same pass, so the segment actor sees an empty instance table when
        // it drains. The drain must still withdraw the Type 1/4 routes — a
        // missing reference instance only blocks (re-)origination, not withdraw.
        let mut t = EvpnInstanceTable::new();
        t.insert(instance(100)).unwrap();
        let instances = Arc::new(t);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(32);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _rib = rib_recorder(rib_rx, injects.clone(), withdraws.clone());

        let handle = spawn(
            &instances,
            vec![segment(esi(0x21), &[100])],
            rib_tx,
            None,
            BgpMetrics::new(),
            CancellationToken::new(),
        )
        .expect("non-empty ES config should spawn segment actor");
        let control = handle.runtime_control();
        let _ = wait_for_keys(&injects, 3, "initial ES injections").await;

        // Mirror the converge_tenant_teardown publish order: empty instances,
        // then empty segments.
        assert!(control.replace_instances(Arc::new(EvpnInstanceTable::new())));
        assert!(control.replace_segments(Arc::new(Vec::new())));

        let drained_keys = wait_for_keys(&withdraws, 3, "teardown ES withdraws").await;
        assert!(
            drained_keys
                .iter()
                .any(|key| matches!(key, EvpnRouteKey::Es { .. })),
            "teardown should withdraw the Type 4 ES route; drained {drained_keys:?}"
        );
        assert!(
            drained_keys
                .iter()
                .any(|key| matches!(key, EvpnRouteKey::EadPerEs { .. })),
            "teardown should withdraw the EAD-per-ES route; drained {drained_keys:?}"
        );
        assert!(
            drained_keys
                .iter()
                .any(|key| matches!(key, EvpnRouteKey::EadPerEvi { .. })),
            "teardown should withdraw the EAD-per-EVI route; drained {drained_keys:?}"
        );

        handle.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn runtime_control_uses_replaced_instances_for_dependent_segment_snapshot() {
        let mut t = EvpnInstanceTable::new();
        t.insert(instance(100)).unwrap();
        let instances = Arc::new(t);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _rib = rib_recorder(rib_rx, injects.clone(), withdraws);

        let handle = spawn(
            &instances,
            vec![segment(esi(0x21), &[100])],
            rib_tx,
            None,
            BgpMetrics::new(),
            CancellationToken::new(),
        )
        .expect("non-empty ES config should spawn segment actor");
        let control = handle.runtime_control();
        let _ = wait_for_keys(&injects, 3, "initial ES injections").await;

        let mut replacement = instances.as_ref().clone();
        replacement.insert(instance(200)).unwrap();
        assert!(control.replace_instances(Arc::new(replacement)));
        assert!(control.replace_segments(Arc::new(vec![segment(esi(0x22), &[200])])));

        let injected = wait_for_keys(&injects, 6, "runtime-added VNI ES injections").await;
        // The Ethernet Tag is pinned to 0 (RFC 7432 §6.1); the per-VNI
        // RD is what identifies the member VNI's EAD-per-EVI route.
        let added_rd = instance(200).rd;
        assert!(
            injected.iter().any(|key| {
                matches!(
                    key,
                    EvpnRouteKey::EadPerEvi { rd, .. } if *rd == added_rd
                )
            }),
            "segment actor should originate EAD-per-EVI for the runtime-added VNI"
        );

        handle.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn runtime_control_rebuilds_routes_when_member_instance_redefined() {
        let mut t = EvpnInstanceTable::new();
        t.insert(instance(100)).unwrap();
        let instances = Arc::new(t);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _rib = rib_recorder(rib_rx, injects.clone(), withdraws.clone());

        let handle = spawn(
            &instances,
            vec![segment(esi(0x21), &[100])],
            rib_tx,
            None,
            BgpMetrics::new(),
            CancellationToken::new(),
        )
        .expect("non-empty ES config should spawn segment actor");
        let control = handle.runtime_control();
        let old_rd = rd(65000, 100);
        let new_rd = rd(65000, 111);
        let _ = wait_for_keys(&injects, 3, "initial ES injections").await;

        let mut replacement = EvpnInstanceTable::new();
        replacement.insert(instance_with_rd(100, 111)).unwrap();
        assert!(control.replace_instances(Arc::new(replacement)));

        let drained = wait_for_keys(&withdraws, 3, "member redefine ES withdraws").await;
        assert!(
            drained.iter().any(|key| matches!(
                key,
                EvpnRouteKey::Es { rd, .. } if *rd == old_rd
            )),
            "member instance redefine should withdraw old-RD Type 4; drained {drained:?}"
        );
        assert!(
            drained.iter().any(|key| matches!(
                key,
                EvpnRouteKey::EadPerEs { rd, .. } if *rd == old_rd
            )),
            "member instance redefine should withdraw old-RD EAD-per-ES; drained {drained:?}"
        );
        assert!(
            drained.iter().any(|key| matches!(
                key,
                EvpnRouteKey::EadPerEvi { rd, .. } if *rd == old_rd
            )),
            "member instance redefine should withdraw old-RD EAD-per-EVI; drained {drained:?}"
        );

        let injected = wait_for_keys(&injects, 6, "member redefine ES injections").await;
        assert!(
            injected.iter().any(|key| matches!(
                key,
                EvpnRouteKey::Es { rd, .. } if *rd == new_rd
            )),
            "member instance redefine should originate new-RD Type 4; injected {injected:?}"
        );
        assert!(
            injected.iter().any(|key| matches!(
                key,
                EvpnRouteKey::EadPerEs { rd, .. } if *rd == new_rd
            )),
            "member instance redefine should originate new-RD EAD-per-ES; injected {injected:?}"
        );
        assert!(
            injected.iter().any(|key| matches!(
                key,
                EvpnRouteKey::EadPerEvi { rd, .. } if *rd == new_rd
            )),
            "member instance redefine should originate new-RD EAD-per-EVI; injected {injected:?}"
        );

        handle.shutdown().await;
    }

    #[test]
    fn rebuild_segment_states_releases_dropped_esi_labels() {
        let mut t = EvpnInstanceTable::new();
        t.insert(instance(100)).unwrap();
        let instances = Arc::new(t);
        let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(1);
        let runtime = SegmentRuntime {
            watches: None,
            instances,
            rib_tx,
            bum_enforcement_tx: None,
            same_esi_bias_tx: None,
            metrics: BgpMetrics::new(),
            shutdown: CancellationToken::new(),
            drained_esis: Arc::new(BTreeSet::new()),
            es_link_bindings: EsLinkBindings::default(),
            boot_until: None,
        };
        let mut by_esi: HashMap<EthernetSegmentIdentifier, SegmentState> = HashMap::new();
        let mut alloc = rustbgpd_evpn::EsiLabelAllocator::new();

        rebuild_segment_states(
            &runtime,
            &mut by_esi,
            &mut alloc,
            vec![segment(esi(0x21), &[100]), segment(esi(0x22), &[100])],
        );
        assert_eq!(alloc.len(), 2);
        let label_a = alloc.get(esi(0x21)).expect("esi A reserved");

        // Re-apply a snapshot that drops ESI B. The allocator must
        // release B (so its label returns to the free list) while the
        // persisting ESI A keeps its existing label.
        rebuild_segment_states(
            &runtime,
            &mut by_esi,
            &mut alloc,
            vec![segment(esi(0x21), &[100])],
        );
        assert_eq!(alloc.len(), 1, "dropped ESI label must be released");
        assert!(
            alloc.get(esi(0x22)).is_none(),
            "removed ESI must be released from the allocator"
        );
        assert_eq!(
            alloc.get(esi(0x21)),
            Some(label_a),
            "persisting ESI must keep its existing label"
        );
        assert_eq!(by_esi.len(), 1);
    }

    #[test]
    fn bum_enforcement_table_maps_roles_to_bridges() {
        let mut instances = EvpnInstanceTable::new();
        instances.insert(instance(100)).unwrap();
        instances.insert(instance(200)).unwrap();
        let id = esi(7);

        let table = build_bum_enforcement_table_from_roles(
            &instances,
            [(id, vni(100), DfRole::Df), (id, vni(200), DfRole::NonDf)],
        );

        assert_eq!(table.len(), 2);
        assert_eq!(table.get(id, vni(100)).unwrap().bridge, "br100");
        assert_eq!(
            table.get(id, vni(200)).unwrap().action,
            rustbgpd_evpn::BumForwardingAction::Suppress
        );
    }

    #[test]
    fn bum_enforcement_table_skips_unbound_instances() {
        let mut instances = EvpnInstanceTable::new();
        let mut inst = instance(100);
        inst.bridge = None;
        instances.insert(inst).unwrap();

        let table =
            build_bum_enforcement_table_from_roles(&instances, [(esi(7), vni(100), DfRole::NonDf)]);
        assert!(table.is_empty());
    }

    // -- ADR-0085 decision 5: same-ESI bias eligibility ---------------

    /// The full decision 5 matrix: (DF / non-DF) x (all-active /
    /// single-active) x (drained / not drained) x (bound / unbound).
    /// Eligible iff bound AND not drained AND entitled to forward
    /// (all-active always; single-active only as DF).
    #[test]
    fn same_esi_bias_table_covers_the_role_mode_drain_matrix() {
        use RedundancyMode::{AllActive, SingleActive};
        let bound: BTreeSet<EthernetSegmentIdentifier> = [esi(1)].into_iter().collect();
        let no_drain: BTreeSet<EthernetSegmentIdentifier> = BTreeSet::new();
        let drained: BTreeSet<EthernetSegmentIdentifier> = [esi(1)].into_iter().collect();

        let cases = [
            // (mode, role, drained set, expected eligible)
            (AllActive, DfRole::Df, &no_drain, true),
            // All-active entitles every member PE — non-DF included.
            (AllActive, DfRole::NonDf, &no_drain, true),
            (SingleActive, DfRole::Df, &no_drain, true),
            // A healthy single-active backup is NOT eligible: its AC
            // is non-forwarding; the remote row toward the active PE
            // must stay (operator review amendment).
            (SingleActive, DfRole::NonDf, &no_drain, false),
            // Drain (operator or link reason, incl. the recovery
            // hold-off) lifts the bias regardless of role/mode.
            (AllActive, DfRole::Df, &drained, false),
            (AllActive, DfRole::NonDf, &drained, false),
            (SingleActive, DfRole::Df, &drained, false),
            (SingleActive, DfRole::NonDf, &drained, false),
        ];
        for (mode, role, drain_set, expected) in cases {
            let table = build_same_esi_bias_table_from_roles(
                &bound,
                drain_set,
                [(esi(1), mode, vni(100), role)],
            );
            assert_eq!(
                table.is_eligible(esi(1), vni(100)),
                expected,
                "mode={mode:?} role={role:?} drained={}",
                !drain_set.is_empty()
            );
        }

        // Unbound (no interface binding): never eligible — AC health
        // is unknowable, today's projection behavior is preserved.
        let unbound: BTreeSet<EthernetSegmentIdentifier> = BTreeSet::new();
        let table = build_same_esi_bias_table_from_roles(
            &unbound,
            &no_drain,
            [(esi(1), AllActive, vni(100), DfRole::Df)],
        );
        assert!(table.is_empty(), "unbound segments get no bias");
    }

    /// Eligibility is per-(ESI, VNI): one ES spanning two VNIs with
    /// split DF roles biases only the DF VNI in single-active mode.
    #[test]
    fn same_esi_bias_table_is_keyed_per_esi_vni() {
        let bound: BTreeSet<EthernetSegmentIdentifier> = [esi(1)].into_iter().collect();
        let table = build_same_esi_bias_table_from_roles(
            &bound,
            &BTreeSet::new(),
            [
                (esi(1), RedundancyMode::SingleActive, vni(100), DfRole::Df),
                (
                    esi(1),
                    RedundancyMode::SingleActive,
                    vni(200),
                    DfRole::NonDf,
                ),
            ],
        );
        assert!(table.is_eligible(esi(1), vni(100)));
        assert!(!table.is_eligible(esi(1), vni(200)));
        assert_eq!(table.len(), 1);
    }

    // -- Single-active AC gate (whole-port blocking) -----------------

    /// Role matrix for the pure per-ES gate rule. The caller
    /// ([`populate_ac_gates`]) only invokes it for BOUND segments, so
    /// bound-ness is implicit here; unbound coverage lives in
    /// `ac_gate_rows_require_binding_and_single_active`.
    #[test]
    fn ac_gate_state_matrix() {
        use RedundancyMode::{AllActive, SingleActive};

        let members: BTreeSet<EvpnInstanceId> = [vni(100), vni(200)].into_iter().collect();
        let roles = |pairs: &[(u32, DfRole)]| -> BTreeMap<EvpnInstanceId, DfRole> {
            pairs.iter().map(|&(v, r)| (vni(v), r)).collect()
        };

        // All-active never gates the port, role state irrespective.
        assert_eq!(
            ac_gate_state_for_es(AllActive, false, &members, &roles(&[])),
            None
        );
        assert_eq!(
            ac_gate_state_for_es(
                AllActive,
                false,
                &members,
                &roles(&[(100, DfRole::NonDf), (200, DfRole::NonDf)])
            ),
            None
        );

        // Drained single-active blocks regardless of (cleared) roles —
        // the maintenance semantic; the recovery hold-off keeps it
        // blocked until the segment re-converges.
        assert_eq!(
            ac_gate_state_for_es(SingleActive, true, &members, &roles(&[])),
            Some(AcGateState::Blocked)
        );

        // Non-DF for EVERY member VNI → block the whole port.
        assert_eq!(
            ac_gate_state_for_es(
                SingleActive,
                false,
                &members,
                &roles(&[(100, DfRole::NonDf), (200, DfRole::NonDf)])
            ),
            Some(AcGateState::Blocked)
        );

        // DF everywhere → forwarding.
        assert_eq!(
            ac_gate_state_for_es(
                SingleActive,
                false,
                &members,
                &roles(&[(100, DfRole::Df), (200, DfRole::Df)])
            ),
            Some(AcGateState::Forwarding)
        );

        // RFC 8584 service carving split the roles → the port-level
        // gate must NOT block (it would break the DF VNI); fall back
        // to BUM-only enforcement and surface mixed-roles.
        assert_eq!(
            ac_gate_state_for_es(
                SingleActive,
                false,
                &members,
                &roles(&[(100, DfRole::Df), (200, DfRole::NonDf)])
            ),
            Some(AcGateState::MixedRoles)
        );

        // Roles incomplete (mid-election: one member VNI not yet
        // resolved) → fail open to forwarding; "non-DF everywhere"
        // cannot be claimed for an unknown VNI.
        assert_eq!(
            ac_gate_state_for_es(
                SingleActive,
                false,
                &members,
                &roles(&[(100, DfRole::NonDf)])
            ),
            Some(AcGateState::Forwarding)
        );
        assert_eq!(
            ac_gate_state_for_es(SingleActive, false, &members, &roles(&[])),
            Some(AcGateState::Forwarding)
        );

        // Single-VNI ES — the common case (and the M66/M67 shape) —
        // gets full enforcement either way.
        let one_member: BTreeSet<EvpnInstanceId> = [vni(100)].into_iter().collect();
        assert_eq!(
            ac_gate_state_for_es(
                SingleActive,
                false,
                &one_member,
                &roles(&[(100, DfRole::NonDf)])
            ),
            Some(AcGateState::Blocked)
        );
        assert_eq!(
            ac_gate_state_for_es(
                SingleActive,
                false,
                &one_member,
                &roles(&[(100, DfRole::Df)])
            ),
            Some(AcGateState::Forwarding)
        );
    }

    /// Table-level rule: rows exist only for bound single-active
    /// segments; unbound and all-active segments produce none.
    #[test]
    fn ac_gate_rows_require_binding_and_single_active() {
        let mut t = EvpnInstanceTable::new();
        t.insert(instance(100)).unwrap();
        let instances = Arc::new(t);
        let mut by_esi: HashMap<EthernetSegmentIdentifier, SegmentState> = HashMap::new();
        let mut alloc = rustbgpd_evpn::EsiLabelAllocator::new();
        let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(1);
        let runtime = SegmentRuntime {
            watches: None,
            instances,
            rib_tx,
            bum_enforcement_tx: None,
            same_esi_bias_tx: None,
            metrics: BgpMetrics::new(),
            shutdown: CancellationToken::new(),
            drained_esis: Arc::new(BTreeSet::new()),
            es_link_bindings: EsLinkBindings::default(),
            boot_until: None,
        };
        let mut sa_bound = segment(esi(0x31), &[100]);
        sa_bound.redundancy_mode = RedundancyMode::SingleActive;
        let mut sa_unbound = segment(esi(0x32), &[100]);
        sa_unbound.redundancy_mode = RedundancyMode::SingleActive;
        let aa_bound = segment(esi(0x33), &[100]); // all-active default
        rebuild_segment_states(
            &runtime,
            &mut by_esi,
            &mut alloc,
            vec![sa_bound, sa_unbound, aa_bound],
        );
        // Mark every member VNI non-DF so a row, if any, is Blocked.
        for state in by_esi.values_mut() {
            state.last_roles.insert(vni(100), DfRole::NonDf);
        }

        let bindings: EsLinkBindings = Arc::new(
            [
                (
                    esi(0x31),
                    crate::config::EsLinkBinding {
                        interface: "eth2".to_string(),
                        recovery_delay: Duration::from_secs(30),
                    },
                ),
                (
                    esi(0x33),
                    crate::config::EsLinkBinding {
                        interface: "eth3".to_string(),
                        recovery_delay: Duration::from_secs(30),
                    },
                ),
            ]
            .into_iter()
            .collect(),
        );
        let mut table = BumEnforcementTable::new();
        populate_ac_gates(&mut table, &bindings, &BTreeSet::new(), &by_esi);

        let row = table.ac_gate(esi(0x31)).expect("bound single-active row");
        assert_eq!(row.interface, "eth2");
        assert_eq!(row.state, AcGateState::Blocked);
        assert!(
            table.ac_gate(esi(0x32)).is_none(),
            "unbound single-active cannot be gated (no port handle)"
        );
        assert!(
            table.ac_gate(esi(0x33)).is_none(),
            "all-active is never gated"
        );
        assert_eq!(table.ac_gates_len(), 1);
    }

    /// Drain interaction at the table level: a drained bound
    /// single-active ES rows out as Blocked even though drain cleared
    /// its `last_roles`.
    #[test]
    fn ac_gate_blocks_drained_bound_single_active_es() {
        let mut t = EvpnInstanceTable::new();
        t.insert(instance(100)).unwrap();
        let instances = Arc::new(t);
        let mut by_esi: HashMap<EthernetSegmentIdentifier, SegmentState> = HashMap::new();
        let mut alloc = rustbgpd_evpn::EsiLabelAllocator::new();
        let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(1);
        let runtime = SegmentRuntime {
            watches: None,
            instances,
            rib_tx,
            bum_enforcement_tx: None,
            same_esi_bias_tx: None,
            metrics: BgpMetrics::new(),
            shutdown: CancellationToken::new(),
            drained_esis: Arc::new(BTreeSet::new()),
            es_link_bindings: EsLinkBindings::default(),
            boot_until: None,
        };
        let mut sa = segment(esi(0x41), &[100]);
        sa.redundancy_mode = RedundancyMode::SingleActive;
        rebuild_segment_states(&runtime, &mut by_esi, &mut alloc, vec![sa]);
        // Drain semantics: last_roles is cleared (drain_segment_state
        // takes it); the gate must still block.

        let bindings: EsLinkBindings = Arc::new(
            [(
                esi(0x41),
                crate::config::EsLinkBinding {
                    interface: "eth2".to_string(),
                    recovery_delay: Duration::from_secs(30),
                },
            )]
            .into_iter()
            .collect(),
        );
        let drained: BTreeSet<EthernetSegmentIdentifier> = [esi(0x41)].into_iter().collect();
        let mut table = BumEnforcementTable::new();
        populate_ac_gates(&mut table, &bindings, &drained, &by_esi);
        assert_eq!(
            table.ac_gate(esi(0x41)).map(|e| e.state),
            Some(AcGateState::Blocked),
            "drained ES must block its AC (maintenance semantic)"
        );
    }

    // -- ADR-0084 Ethernet Segment drain/undrain ---------------------

    fn drained_set(esis: &[EthernetSegmentIdentifier]) -> Arc<BTreeSet<EthernetSegmentIdentifier>> {
        Arc::new(esis.iter().copied().collect())
    }

    fn esi_of_key(key: &EvpnRouteKey) -> Option<EthernetSegmentIdentifier> {
        match key {
            EvpnRouteKey::Es { esi, .. }
            | EvpnRouteKey::EadPerEs { esi, .. }
            | EvpnRouteKey::EadPerEvi { esi, .. } => Some(*esi),
            _ => None,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn drain_withdraws_exactly_target_esi_route_classes() {
        let mut t = EvpnInstanceTable::new();
        t.insert(instance(100)).unwrap();
        t.insert(instance(200)).unwrap();
        let instances = Arc::new(t);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _rib = rib_recorder(rib_rx, injects.clone(), withdraws.clone());

        let handle = spawn(
            &instances,
            vec![segment(esi(0x31), &[100]), segment(esi(0x32), &[200])],
            rib_tx,
            None,
            BgpMetrics::new(),
            CancellationToken::new(),
        )
        .expect("non-empty ES config should spawn segment actor");
        let control = handle.runtime_control();
        let _ = wait_for_keys(&injects, 6, "initial ES injections").await;

        assert!(control.replace_drained_esis(drained_set(&[esi(0x31)])));
        let drained_keys = wait_for_keys(&withdraws, 3, "drain withdraws").await;
        assert_eq!(
            drained_keys.len(),
            3,
            "drain must withdraw exactly the three route classes; got {drained_keys:?}"
        );
        assert!(
            drained_keys
                .iter()
                .all(|key| esi_of_key(key) == Some(esi(0x31))),
            "drain must only withdraw the target ESI's routes; got {drained_keys:?}"
        );
        assert!(
            drained_keys
                .iter()
                .any(|key| matches!(key, EvpnRouteKey::Es { .. }))
        );
        assert!(
            drained_keys
                .iter()
                .any(|key| matches!(key, EvpnRouteKey::EadPerEs { .. }))
        );
        assert!(
            drained_keys
                .iter()
                .any(|key| matches!(key, EvpnRouteKey::EadPerEvi { .. }))
        );

        handle.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn undrain_reoriginates_all_route_classes() {
        let mut t = EvpnInstanceTable::new();
        t.insert(instance(100)).unwrap();
        let instances = Arc::new(t);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _rib = rib_recorder(rib_rx, injects.clone(), withdraws.clone());

        let handle = spawn(
            &instances,
            vec![segment(esi(0x33), &[100])],
            rib_tx,
            None,
            BgpMetrics::new(),
            CancellationToken::new(),
        )
        .expect("non-empty ES config should spawn segment actor");
        let control = handle.runtime_control();
        let _ = wait_for_keys(&injects, 3, "initial ES injections").await;

        assert!(control.replace_drained_esis(drained_set(&[esi(0x33)])));
        let _ = wait_for_keys(&withdraws, 3, "drain withdraws").await;

        assert!(control.replace_drained_esis(drained_set(&[])));
        let injected = wait_for_keys(&injects, 6, "undrain re-originations").await;
        let reoriginated = &injected[3..];
        assert!(
            reoriginated
                .iter()
                .any(|key| matches!(key, EvpnRouteKey::Es { .. })),
            "undrain must re-originate the Type 4 ES route; got {reoriginated:?}"
        );
        assert!(
            reoriginated
                .iter()
                .any(|key| matches!(key, EvpnRouteKey::EadPerEs { .. })),
            "undrain must re-originate the EAD-per-ES route; got {reoriginated:?}"
        );
        assert!(
            reoriginated
                .iter()
                .any(|key| matches!(key, EvpnRouteKey::EadPerEvi { .. })),
            "undrain must re-originate the EAD-per-EVI route; got {reoriginated:?}"
        );

        handle.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn segment_snapshot_reapply_while_drained_does_not_resurrect_routes() {
        let mut t = EvpnInstanceTable::new();
        t.insert(instance(100)).unwrap();
        t.insert(instance(200)).unwrap();
        let instances = Arc::new(t);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _rib = rib_recorder(rib_rx, injects.clone(), withdraws.clone());

        let handle = spawn(
            &instances,
            vec![segment(esi(0x34), &[100]), segment(esi(0x35), &[200])],
            rib_tx,
            None,
            BgpMetrics::new(),
            CancellationToken::new(),
        )
        .expect("non-empty ES config should spawn segment actor");
        let control = handle.runtime_control();
        let _ = wait_for_keys(&injects, 6, "initial ES injections").await;

        assert!(control.replace_drained_esis(drained_set(&[esi(0x34)])));
        let _ = wait_for_keys(&withdraws, 3, "drain withdraws").await;
        let injected_before_reapply = injects.lock().await.len();

        // Republish a changed segment snapshot (the drained ES kept,
        // the other ES redefined) — the SIGHUP/runtime-apply shape.
        // The full drain + rebuild + startup pass must skip the
        // drained ESI.
        let mut redefined = segment(esi(0x35), &[200]);
        redefined.df_preference = 100;
        assert!(control.replace_segments(Arc::new(vec![segment(esi(0x34), &[100]), redefined])));

        let injected = wait_for_keys(
            &injects,
            injected_before_reapply + 3,
            "snapshot-reapply re-originations",
        )
        .await;
        assert!(
            injected[injected_before_reapply..]
                .iter()
                .all(|key| esi_of_key(key) != Some(esi(0x34))),
            "snapshot reapply while drained must not resurrect the drained ESI's routes; got {injected:?}"
        );

        handle.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn drained_esi_removed_from_config_drops_cleanly() {
        let mut t = EvpnInstanceTable::new();
        t.insert(instance(100)).unwrap();
        let instances = Arc::new(t);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _rib = rib_recorder(rib_rx, injects.clone(), withdraws.clone());

        let handle = spawn(
            &instances,
            vec![segment(esi(0x36), &[100])],
            rib_tx,
            None,
            BgpMetrics::new(),
            CancellationToken::new(),
        )
        .expect("non-empty ES config should spawn segment actor");
        let control = handle.runtime_control();
        let _ = wait_for_keys(&injects, 3, "initial ES injections").await;

        assert!(control.replace_drained_esis(drained_set(&[esi(0x36)])));
        let _ = wait_for_keys(&withdraws, 3, "drain withdraws").await;

        // Remove the drained ES from config entirely; the actor must
        // drop its state without re-emitting anything (routes are
        // already withdrawn) and stay healthy.
        assert!(control.replace_segments(Arc::new(Vec::new())));
        // The coordinator GCs the drain entry on segment-set replace;
        // mirror that here and confirm the empty set is a no-op (no
        // resurrected routes for an ESI with no state).
        assert!(control.replace_drained_esis(drained_set(&[])));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            injects.lock().await.len(),
            3,
            "no route may re-originate after the drained ES was removed from config"
        );

        handle.shutdown().await;
        assert!(!control.is_open());
    }

    /// ADR-0084 decision 3, the re-add half at the actor seam: after a
    /// drained ES leaves the config (the converger publishes the
    /// segment snapshot first, then the GC'd drained set), re-adding
    /// the same ESI in a later apply must start undrained — no phantom
    /// drain may survive inside the actor.
    #[tokio::test(start_paused = true)]
    async fn re_added_esi_after_drain_gc_starts_undrained() {
        let mut t = EvpnInstanceTable::new();
        t.insert(instance(100)).unwrap();
        let instances = Arc::new(t);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _rib = rib_recorder(rib_rx, injects.clone(), withdraws.clone());

        let handle = spawn(
            &instances,
            vec![segment(esi(0x37), &[100])],
            rib_tx,
            None,
            BgpMetrics::new(),
            CancellationToken::new(),
        )
        .expect("non-empty ES config should spawn segment actor");
        let control = handle.runtime_control();
        let _ = wait_for_keys(&injects, 3, "initial ES injections").await;

        assert!(control.replace_drained_esis(drained_set(&[esi(0x37)])));
        let _ = wait_for_keys(&withdraws, 3, "drain withdraws").await;

        // Runtime apply removes the drained ES: segment snapshot
        // first, then the coordinator-GC'd drained set (the
        // `publish_ethernet_segment_runtime_snapshot` order).
        assert!(control.replace_segments(Arc::new(Vec::new())));
        assert!(control.replace_drained_esis(drained_set(&[])));

        // A later apply re-adds the same ESI: it must originate all
        // three route classes — the prior drain is gone.
        assert!(control.replace_segments(Arc::new(vec![segment(esi(0x37), &[100])])));
        let injected = wait_for_keys(&injects, 6, "re-added ES re-originations").await;
        let re_added = &injected[3..];
        assert!(
            re_added
                .iter()
                .any(|key| matches!(key, EvpnRouteKey::Es { .. })),
            "re-added ES must re-originate its Type 4; got {re_added:?}"
        );
        assert!(
            re_added
                .iter()
                .any(|key| matches!(key, EvpnRouteKey::EadPerEs { .. })),
            "re-added ES must re-originate its EAD-per-ES; got {re_added:?}"
        );
        assert!(
            re_added
                .iter()
                .any(|key| matches!(key, EvpnRouteKey::EadPerEvi { .. })),
            "re-added ES must re-originate its EAD-per-EVI; got {re_added:?}"
        );

        handle.shutdown().await;
    }

    /// Cross-snapshot coherence between the two dataplane snapshots
    /// the segment actor publishes from one state
    /// (`publish_dataplane_snapshots`): a `(ESI, VNI)` pair the bias
    /// table marks eligible can never belong to a drained ES, and
    /// never to an ES whose AC gate row says `Blocked` — for EVERY
    /// combination of redundancy mode, drain state, binding, and
    /// per-VNI DF role assignment. A consumer that honors the bias
    /// (suppresses the remote FDB row) is therefore never pointed at
    /// an attachment circuit the gate is blocking.
    #[test]
    fn bias_eligibility_never_coexists_with_a_blocked_ac_gate() {
        let id = esi(0x51);
        let members: BTreeSet<EvpnInstanceId> = [vni(100), vni(200)].into_iter().collect();
        let role_options = [None, Some(DfRole::Df), Some(DfRole::NonDf)];
        for mode in [RedundancyMode::AllActive, RedundancyMode::SingleActive] {
            for drained in [false, true] {
                for bound in [false, true] {
                    for r1 in role_options {
                        for r2 in role_options {
                            let mut roles = BTreeMap::new();
                            if let Some(role) = r1 {
                                roles.insert(vni(100), role);
                            }
                            if let Some(role) = r2 {
                                roles.insert(vni(200), role);
                            }
                            let bound_esis: BTreeSet<EthernetSegmentIdentifier> =
                                if bound { [id].into() } else { BTreeSet::new() };
                            let drained_esis: BTreeSet<EthernetSegmentIdentifier> = if drained {
                                [id].into()
                            } else {
                                BTreeSet::new()
                            };
                            let bias = build_same_esi_bias_table_from_roles(
                                &bound_esis,
                                &drained_esis,
                                roles.iter().map(|(&v, &r)| (id, mode, v, r)),
                            );
                            let gate = ac_gate_state_for_es(mode, drained, &members, &roles);
                            for &(_, eligible_vni) in bias.iter() {
                                assert!(
                                    !drained,
                                    "a drained ES must never be bias-eligible \
                                     (mode={mode:?} roles={roles:?})"
                                );
                                assert_ne!(
                                    gate,
                                    Some(AcGateState::Blocked),
                                    "bias-eligible (.., {eligible_vni:?}) must not coexist \
                                     with a Blocked AC gate (mode={mode:?} drained={drained} \
                                     bound={bound} roles={roles:?})"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    /// Like [`rib_recorder`] but serving a test-controlled Type 4
    /// route set on `QueryEvpnRoutes` and broadcasting from a
    /// test-held event sender, so a remote PE's Type 4 can drive a
    /// real DF re-election through the actor.
    fn rib_recorder_with_routes(
        mut rib_rx: mpsc::Receiver<RibUpdate>,
        injects: Arc<tokio::sync::Mutex<Vec<EvpnRouteKey>>>,
        withdraws: Arc<tokio::sync::Mutex<Vec<EvpnRouteKey>>>,
        routes: Arc<tokio::sync::Mutex<Vec<EvpnRibRoute>>>,
        events_tx: broadcast::Sender<Arc<EvpnRouteEvent>>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            while let Some(update) = rib_rx.recv().await {
                match update {
                    RibUpdate::SubscribeEvpnRouteEvents { reply } => {
                        let _ = reply.send(events_tx.subscribe());
                    }
                    RibUpdate::QueryEvpnRoutes { filter, reply } => {
                        // Applies the pushed-down predicate exactly as the RIB
                        // actor does, so the election tests see the same rows
                        // production would hand back.
                        let rows = routes.lock().await;
                        let _ = reply.send(
                            rows.iter()
                                .filter(|row| filter.as_ref().is_none_or(|matches| matches(row)))
                                .cloned()
                                .collect(),
                        );
                    }
                    RibUpdate::QueryEvpnSessionsSynced { reply } => {
                        let _ = reply.send(true);
                    }
                    RibUpdate::InjectEvpn { route, reply } => {
                        injects.lock().await.push(route.key());
                        let _ = reply.send(Ok(()));
                    }
                    RibUpdate::WithdrawEvpn { key, reply } => {
                        withdraws.lock().await.push(key);
                        let _ = reply.send(Ok(()));
                    }
                    _ => {}
                }
            }
        })
    }

    async fn wait_for_dataplane_state<F>(
        bias_rx: &watch::Receiver<Arc<SameEsiBiasTable>>,
        bum_rx: &watch::Receiver<Arc<BumEnforcementTable>>,
        label: &str,
        mut pred: F,
    ) where
        F: FnMut(&SameEsiBiasTable, &BumEnforcementTable) -> bool,
    {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let bias = bias_rx.borrow().clone();
            let bum = bum_rx.borrow().clone();
            if pred(&bias, &bum) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {label}; bias={bias:?} bum={bum:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// DF-election seam toward the dataplane consumers: a remote Type
    /// 4 that flips this PE to non-DF on a bound single-active ES
    /// updates BOTH published snapshots from the same election pass —
    /// the `(ESI, VNI)` bias eligibility drops AND the AC gate row
    /// flips to `Blocked`, with no further stimulus.
    #[tokio::test(start_paused = true)]
    async fn df_flip_republishes_bias_and_ac_gate_together() {
        // With candidates sorted [10.0.0.1, 10.0.0.2], DefaultModulo
        // gives VNI 101 → slot 101 % 2 = 1 → the remote wins DF.
        let id = esi(0x52);
        let mut t = EvpnInstanceTable::new();
        t.insert(instance(101)).unwrap();
        let instances = Arc::new(t);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let routes = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let (events_tx, _events_keepalive) = broadcast::channel(16);
        let _rib = rib_recorder_with_routes(
            rib_rx,
            injects.clone(),
            withdraws.clone(),
            routes.clone(),
            events_tx.clone(),
        );

        let (bum_tx, bum_rx) = watch::channel(Arc::new(BumEnforcementTable::new()));
        let (bias_tx, bias_rx) = watch::channel(Arc::new(SameEsiBiasTable::new()));
        let bindings: EsLinkBindings = Arc::new(
            [(
                id,
                crate::config::EsLinkBinding {
                    interface: "es0".to_string(),
                    recovery_delay: Duration::ZERO,
                },
            )]
            .into_iter()
            .collect(),
        );
        let (_bindings_tx, bindings_rx) = watch::channel(bindings);

        let mut single_active = segment(id, &[101]);
        single_active.redundancy_mode = RedundancyMode::SingleActive;
        let handle = spawn_with_local_bias(
            &instances,
            vec![single_active],
            rib_tx,
            Some(bum_tx),
            Some(bias_tx),
            Some(bindings_rx),
            BgpMetrics::new(),
            CancellationToken::new(),
        );

        // Startup: sole candidate → DF everywhere → bias-eligible and
        // the AC gate forwarding.
        wait_for_dataplane_state(&bias_rx, &bum_rx, "startup DF snapshots", |bias, bum| {
            bias.is_eligible(id, vni(101))
                && bias.bound_interface(id, vni(101)) == Some("es0")
                && bum.ac_gate(id).map(|entry| entry.state) == Some(AcGateState::Forwarding)
        })
        .await;

        // The remote PE's Type 4 lands: it wins the modulo election
        // for VNI 101, demoting this PE to non-DF.
        let remote_type4 = type_4_es_route(id, "10.0.0.2", attrs_with_es_import_rt(id));
        routes.lock().await.push(remote_type4.clone());
        events_tx
            .send(Arc::new(EvpnRouteEvent {
                event_type: rustbgpd_rib::RouteEventType::Added,
                key: EvpnRouteKey::Es {
                    rd: rd(65000, 100),
                    esi: id,
                    originator_ip: ipa("10.0.0.2"),
                },
                best: Some(remote_type4),
                previous_best: None,
                peer: Some(ipa("10.0.0.2")),
                previous_peer: None,
                timestamp: rustbgpd_rib::event::unix_timestamp_now(),
            }))
            .expect("segment actor subscribed");

        wait_for_dataplane_state(&bias_rx, &bum_rx, "post-flip snapshots", |bias, bum| {
            !bias.is_eligible(id, vni(101))
                && bum.ac_gate(id).map(|entry| entry.state) == Some(AcGateState::Blocked)
        })
        .await;

        handle.shutdown().await;
    }

    // -----------------------------------------------------------------
    // ADR-0102: acknowledgement-aware Type 1/4 publication.
    // -----------------------------------------------------------------

    fn scripted_runtime(rib: &ScriptedRib) -> SegmentRuntime {
        let mut table = EvpnInstanceTable::new();
        table.insert(instance(100)).unwrap();
        SegmentRuntime {
            watches: None,
            instances: Arc::new(table),
            rib_tx: rib.rib_tx.clone(),
            bum_enforcement_tx: None,
            same_esi_bias_tx: None,
            metrics: BgpMetrics::new(),
            shutdown: CancellationToken::new(),
            drained_esis: Arc::new(BTreeSet::new()),
            es_link_bindings: EsLinkBindings::default(),
            boot_until: None,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn nonrevertive_df_survives_other_segment_and_instance_changes() {
        let rib = ScriptedRib::spawn(RibReplyMode::Ok);
        let mut runtime = scripted_runtime(&rib);
        let mut allocator = rustbgpd_evpn::EsiLabelAllocator::new();
        let mut pending = PendingRibOps::new();
        let mut config_a = segment(esi(1), &[100]);
        config_a.df_algorithm = DfAlgorithm::HighestPreference;
        config_a.df_preference = 500;
        config_a.df_dont_preempt = true;
        let mut state_a = build_segment_state(&runtime, config_a.clone(), &mut allocator).unwrap();
        prepare_segment_startup(&runtime, &mut state_a, true);
        startup_segment_state(&runtime, &mut state_a, &mut pending).await;
        tokio::time::advance(Duration::from_secs(3)).await;
        run_election_for_routes(&runtime, &mut state_a, &[], &mut pending).await;
        let mut candidates = gather_candidates_from_routes(&state_a, &[]);
        candidates.push(DfCandidate {
            originator_ip: ipa("10.0.0.2"),
            df_preference: 200,
            df_dont_preempt: true,
            df_algorithm: DfAlgorithm::HighestPreference,
        });
        run_election_with_candidates(&runtime, &mut state_a, candidates, &mut pending).await;
        assert_eq!(state_a.last_roles[&vni(100)], DfRole::Df);
        let mut states = HashMap::from([(config_a.esi, state_a)]);
        let mut instances = runtime.instances.as_ref().clone();
        instances.insert(instance(200)).unwrap();
        let mut config_b = segment(esi(2), &[200]);
        // Adding B must not withdraw A or restart its recovery timer.
        apply_test_runtime_snapshot(
            &mut runtime,
            &mut states,
            &mut allocator,
            Arc::new(instances),
            vec![config_a.clone(), config_b.clone()],
            &mut pending,
        )
        .await;
        assert_eq!(rib.withdraw_count(), 0);
        assert!(states[&config_a.esi].recovery_deadline.is_none());
        assert_eq!(states[&config_a.esi].operational_df, (500, true));
        assert_eq!(states[&config_a.esi].last_roles[&vni(100)], DfRole::Df);
        tokio::time::advance(Duration::from_secs(3)).await;
        run_election_for_routes(
            &runtime,
            states.get_mut(&config_b.esi).unwrap(),
            &[],
            &mut pending,
        )
        .await;
        // Editing B withdraws only B's three route classes.
        config_b.originator_ip = ipa("10.0.0.22");
        let instances = runtime.instances.clone();
        apply_test_runtime_snapshot(
            &mut runtime,
            &mut states,
            &mut allocator,
            instances,
            vec![config_a.clone(), config_b.clone()],
            &mut pending,
        )
        .await;
        assert_eq!(rib.withdraw_count(), 3);
        assert_eq!(states[&config_a.esi].last_roles[&vni(100)], DfRole::Df);
        tokio::time::advance(Duration::from_secs(3)).await;
        run_election_for_routes(
            &runtime,
            states.get_mut(&config_b.esi).unwrap(),
            &[],
            &mut pending,
        )
        .await;
        // Redefining B's member instance likewise preserves A's running state.
        let mut replacement = EvpnInstanceTable::new();
        replacement.insert(instance(100)).unwrap();
        replacement.insert(instance_with_rd(200, 201)).unwrap();
        apply_test_runtime_snapshot(
            &mut runtime,
            &mut states,
            &mut allocator,
            Arc::new(replacement),
            vec![config_a.clone(), config_b],
            &mut pending,
        )
        .await;
        assert_eq!(rib.withdraw_count(), 6);
        assert!(states[&config_a.esi].recovery_deadline.is_none());
        assert_eq!(states[&config_a.esi].operational_df, (500, true));
        assert_eq!(states[&config_a.esi].last_roles[&vni(100)], DfRole::Df);
    }

    #[test]
    fn nonrevertive_reference_boundaries_and_fallback() {
        for algorithm in [
            DfAlgorithm::HighestPreference,
            DfAlgorithm::LowestPreference,
        ] {
            for (admin, remote, dp, inherit) in [
                (0, 0, true, true),
                (65535, 65535, true, true),
                (100, 100, false, false),
                (65535, 0, true, algorithm == DfAlgorithm::HighestPreference),
                (0, 65535, true, algorithm == DfAlgorithm::LowestPreference),
            ] {
                let mut state = segment_state(esi(1));
                state.config.df_algorithm = algorithm;
                state.config.df_preference = admin;
                state.config.df_dont_preempt = true;
                state.operational_df = (admin, true);
                let candidate = DfCandidate {
                    originator_ip: ipa("10.0.0.2"),
                    df_preference: remote,
                    df_dont_preempt: dp,
                    df_algorithm: algorithm,
                };
                update_operational_df(&mut state, &[candidate], true);
                assert_eq!(
                    state.operational_df,
                    if inherit {
                        (remote, false)
                    } else {
                        (admin, true)
                    }
                );
                let incompatible = DfCandidate {
                    df_algorithm: DfAlgorithm::DefaultModulo,
                    ..candidate
                };
                update_operational_df(&mut state, &[incompatible], false);
                assert_eq!(
                    state.operational_df,
                    (admin, true),
                    "mismatch clears inherited state"
                );
            }
        }
    }

    async fn apply_test_runtime_snapshot(
        runtime: &mut SegmentRuntime,
        by_esi: &mut HashMap<EthernetSegmentIdentifier, SegmentState>,
        allocator: &mut rustbgpd_evpn::EsiLabelAllocator,
        instances: Arc<EvpnInstanceTable>,
        segments: Vec<EthernetSegment>,
        pending: &mut PendingRibOps,
    ) {
        let (_instances_tx, instances_rx) = watch::channel(instances);
        let (_segments_tx, segments_rx) = watch::channel(Arc::new(segments));
        let (_drained_tx, mut drained_rx) = watch::channel(runtime.drained_esis.clone());
        let (status_tx, _status_rx) = watch::channel(Arc::new(SegmentDfStatusTable::new()));
        apply_runtime_snapshot(
            runtime,
            by_esi,
            allocator,
            (&instances_rx, &segments_rx),
            (&mut drained_rx, None),
            pending,
            &status_tx,
        )
        .await;
    }

    /// Drive real actor/RIB boundaries explicitly: holding a reply prevents
    /// clock advancement or a scheduling guess from establishing the ordering.
    struct DfWaitActor {
        handle: EvpnSegmentHandle,
        rib_tx: mpsc::Sender<RibUpdate>,
        rib_rx: mpsc::Receiver<RibUpdate>,
        events: broadcast::Sender<Arc<EvpnRouteEvent>>,
        bum: watch::Receiver<Arc<BumEnforcementTable>>,
        status: watch::Receiver<Arc<SegmentDfStatusTable>>,
        injected: Vec<EvpnRouteKey>,
        metrics: BgpMetrics,
        bindings: watch::Sender<EsLinkBindings>,
    }

    impl DfWaitActor {
        fn new(algorithm: DfAlgorithm) -> Self {
            let mut instances = EvpnInstanceTable::new();
            for member in [101, 103, 105] {
                instances.insert(instance(member)).unwrap();
            }
            let mut config = segment(esi(1), &[101]);
            config.df_algorithm = algorithm;
            config.df_preference = 100;
            config.redundancy_mode = RedundancyMode::SingleActive;
            let (rib_tx, rib_rx) = mpsc::channel(64);
            let (bum_tx, bum) = watch::channel(Arc::new(BumEnforcementTable::new()));
            let bindings: EsLinkBindings = Arc::new(
                [(1, "es0"), (2, "es1"), (3, "es2")]
                    .into_iter()
                    .map(|(id, interface)| {
                        (
                            esi(id),
                            crate::config::EsLinkBinding {
                                interface: interface.to_string(),
                                recovery_delay: Duration::ZERO,
                            },
                        )
                    })
                    .collect(),
            );
            let (bindings_tx, bindings_rx) = watch::channel(bindings);
            let metrics = BgpMetrics::new();
            let handle = spawn_with_local_bias(
                &Arc::new(instances),
                vec![config],
                rib_tx.clone(),
                Some(bum_tx),
                None,
                Some(bindings_rx),
                metrics.clone(),
                CancellationToken::new(),
            );
            let status = handle.df_status();
            Self {
                handle,
                rib_tx,
                rib_rx,
                events: broadcast::channel(16).0,
                bum,
                status,
                injected: Vec::new(),
                metrics,
                bindings: bindings_tx,
            }
        }

        async fn next_query(&mut self) -> RibUpdate {
            loop {
                let update = tokio::time::timeout(Duration::from_secs(1), self.rib_rx.recv())
                    .await
                    .expect("actor must reach the next RIB boundary without advancing a timer")
                    .expect("segment actor RIB sender remains open");
                match update {
                    RibUpdate::SubscribeEvpnRouteEvents { reply } => {
                        reply.send(self.events.subscribe()).unwrap();
                    }
                    RibUpdate::InjectEvpn { route, reply } => {
                        self.injected.push(route.key());
                        reply.send(Ok(())).unwrap();
                    }
                    RibUpdate::WithdrawEvpn { reply, .. } => {
                        reply.send(Ok(())).unwrap();
                    }
                    query @ (RibUpdate::QueryEvpnRoutes { .. }
                    | RibUpdate::QueryEvpnSessionsSynced { .. }) => return query,
                    _ => panic!("unexpected segment actor RIB operation"),
                }
            }
        }

        async fn routes_reply(&mut self) -> oneshot::Sender<Vec<EvpnRibRoute>> {
            let RibUpdate::QueryEvpnRoutes { reply, .. } = self.next_query().await else {
                panic!("expected route query, not boot synchronization");
            };
            reply
        }

        async fn sync_reply(&mut self) -> oneshot::Sender<bool> {
            let RibUpdate::QueryEvpnSessionsSynced { reply } = self.next_query().await else {
                panic!("election must wait for boot synchronization");
            };
            reply
        }

        fn assert_role(&self, role: DfRole) {
            self.assert_segment_role(esi(1), vni(101), role);
        }

        fn assert_segment_role(
            &self,
            id: EthernetSegmentIdentifier,
            member: EvpnInstanceId,
            role: DfRole,
        ) {
            let bum = self.bum.borrow();
            let row = bum.get(id, member).expect("explicit member intent");
            assert_eq!(row.role, role);
            assert_eq!(
                row.action,
                rustbgpd_evpn::BumForwardingAction::from_df_role(role)
            );
            assert_eq!(
                bum.ac_gate(id).unwrap().state,
                if role.is_df() {
                    AcGateState::Forwarding
                } else {
                    AcGateState::Blocked
                }
            );
            let families = self.metrics.registry().gather();
            let family = families
                .iter()
                .find(|family| family.name() == "evpn_df_role")
                .unwrap();
            let esi_label = format_esi(id);
            let vni_label = member.as_u32().to_string();
            let df = family
                .get_metric()
                .iter()
                .find(|metric| {
                    [
                        ("role", "df"),
                        ("esi", esi_label.as_str()),
                        ("vni", vni_label.as_str()),
                    ]
                    .into_iter()
                    .all(|(name, value)| {
                        metric
                            .get_label()
                            .iter()
                            .any(|label| label.name() == name && label.value() == value)
                    })
                })
                .unwrap();
            let expected = if role.is_df() { 1.0 } else { 0.0 };
            assert!((df.get_gauge().get_value() - expected).abs() < f64::EPSILON);
        }

        async fn startup(&mut self) {
            tokio::time::timeout(Duration::from_secs(1), self.bum.changed())
                .await
                .expect("suppression must publish before any RIB reply")
                .unwrap();
            self.assert_role(DfRole::NonDf);
            assert!(self.status.borrow()[&esi(1)].recovery_deadline.is_some());
            // No RIB request has been answered: suppression precedes both
            // subscription and the first Type 4 acknowledgement.
            assert_eq!(self.injected, Vec::new());
            self.routes_reply().await.send(Vec::new()).unwrap();
            assert_eq!(self.injected.len(), 2, "Type 4 + EAD-per-ES during DF_WAIT");
            assert!(
                self.injected
                    .iter()
                    .any(|key| matches!(key, EvpnRouteKey::Es { .. }))
            );
            assert!(
                self.injected
                    .iter()
                    .any(|key| matches!(key, EvpnRouteKey::EadPerEs { .. }))
            );
            // The interval's first immediate tick is another election attempt.
            self.routes_reply().await.send(Vec::new()).unwrap();
            self.status.borrow_and_update();
        }

        fn remote_event(&self, route: &EvpnRibRoute) {
            self.events
                .send(Arc::new(EvpnRouteEvent {
                    event_type: rustbgpd_rib::RouteEventType::Added,
                    key: route.key(),
                    best: Some(route.clone()),
                    previous_best: None,
                    peer: Some(route.peer),
                    previous_peer: None,
                    timestamp: rustbgpd_rib::event::unix_timestamp_now(),
                }))
                .unwrap();
        }

        async fn finish(self) {
            // Closing the fake RIB lets the actor's bounded drain settle.
            drop(self.rib_rx);
            self.handle.shutdown().await;
        }
    }

    #[tokio::test(start_paused = true)]
    #[expect(
        clippy::too_many_lines,
        reason = "held startup acknowledgements exercise same-ES model, drain, binding and closure publications"
    )]
    async fn held_startup_ack_revalidates_the_same_segment() {
        for stage in ["type4", "ead"] {
            for change in [
                "delete",
                "replace",
                "redrain",
                "instances",
                "binding",
                "binding-close",
                "binding-final-close",
                "shutdown",
                "segments-close",
                "instances-close",
                "drain-close",
            ] {
                let mut actor = DfWaitActor::new(DfAlgorithm::HighestPreference);
                let mut control = actor.handle.runtime_control();
                let RibUpdate::SubscribeEvpnRouteEvents { reply } =
                    actor.rib_rx.recv().await.unwrap()
                else {
                    panic!("initial startup subscribes before originating");
                };
                reply.send(actor.events.subscribe()).unwrap();
                let held = loop {
                    let RibUpdate::InjectEvpn { route, reply } = actor.rib_rx.recv().await.unwrap()
                    else {
                        panic!("startup must reach the selected origination acknowledgement");
                    };
                    let is_type4 = matches!(route.key(), EvpnRouteKey::Es { .. });
                    actor.injected.push(route.key());
                    if (stage == "type4") == is_type4 {
                        break reply;
                    }
                    reply.send(Ok(())).unwrap();
                };
                actor.assert_role(DfRole::NonDf);
                let mut desired = control.segments_tx.borrow().as_ref().clone();
                match change {
                    "delete" => assert!(control.replace_segments(Arc::new(Vec::new()))),
                    "replace" => {
                        desired[0].member_vnis = BTreeSet::from([vni(103)]);
                        assert!(control.replace_segments(Arc::new(desired)));
                    }
                    "redrain" => {
                        assert!(control.replace_drained_esis(Arc::new(BTreeSet::from([esi(1)]))));
                    }
                    "instances" => {
                        let mut instances = EvpnInstanceTable::new();
                        for member in [101, 103, 105] {
                            instances
                                .insert(instance_with_rd(
                                    member,
                                    if member == 101 { 201 } else { member },
                                ))
                                .unwrap();
                        }
                        assert!(control.replace_instances(Arc::new(instances)));
                    }
                    "binding" | "binding-final-close" => {
                        let mut bindings = actor.bindings.borrow().as_ref().clone();
                        bindings.get_mut(&esi(1)).unwrap().interface = "es-new".to_string();
                        actor.bindings.send_replace(Arc::new(bindings));
                    }
                    "binding-close" => {}
                    "shutdown" => actor.handle.shutdown.cancel(),
                    "segments-close" => {
                        let tx = watch::channel(Arc::new(Vec::new())).0;
                        control.segments_tx = tx.clone();
                        actor.handle.control.segments_tx = tx;
                    }
                    "instances-close" => {
                        let tx = watch::channel(Arc::new(EvpnInstanceTable::new())).0;
                        control.instances_tx = tx.clone();
                        actor.handle.control.instances_tx = tx;
                    }
                    "drain-close" => {
                        let tx = watch::channel(Arc::new(BTreeSet::new())).0;
                        control.drained_esis_tx = tx.clone();
                        actor.handle.control.drained_esis_tx = tx;
                    }
                    _ => unreachable!(),
                }
                if matches!(change, "binding-close" | "binding-final-close") {
                    actor.bindings = watch::channel(Arc::new(BTreeMap::new())).0;
                }
                held.send(Ok(())).unwrap();
                if change.starts_with("binding") {
                    let expected = if change == "binding-close" {
                        "es0"
                    } else {
                        "es-new"
                    };
                    if stage == "type4" {
                        let RibUpdate::InjectEvpn { route, reply } =
                            actor.rib_rx.recv().await.unwrap()
                        else {
                            panic!("a binding-only retry must resume its EAD-per-ES");
                        };
                        assert!(matches!(route.key(), EvpnRouteKey::EadPerEs { .. }));
                        assert_eq!(
                            actor.bum.borrow().ac_gate(esi(1)).unwrap().interface,
                            expected
                        );
                        actor.assert_role(DfRole::NonDf);
                        actor.injected.push(route.key());
                        reply.send(Ok(())).unwrap();
                    }
                    let query = actor.routes_reply().await;
                    assert_eq!(
                        actor.bum.borrow().ac_gate(esi(1)).unwrap().interface,
                        expected
                    );
                    actor.assert_role(DfRole::NonDf);
                    assert_eq!(
                        actor
                            .injected
                            .iter()
                            .filter(|key| matches!(key, EvpnRouteKey::Es { .. }))
                            .count(),
                        1
                    );
                    assert_eq!(
                        actor
                            .injected
                            .iter()
                            .filter(|key| matches!(key, EvpnRouteKey::EadPerEs { .. }))
                            .count(),
                        1
                    );
                    query.send(Vec::new()).unwrap();
                } else {
                    for index in 0..if stage == "type4" { 1 } else { 2 } {
                        let RibUpdate::WithdrawEvpn { key, reply } =
                            actor.rib_rx.recv().await.unwrap()
                        else {
                            panic!(
                                "stale startup must withdraw owned routes before another EAD or query: {stage}/{change}"
                            );
                        };
                        assert_eq!(esi_of_key(&key), Some(esi(1)));
                        assert_eq!(
                            matches!(key, EvpnRouteKey::Es { .. }),
                            stage == "type4" || index == 1
                        );
                        actor.assert_role(DfRole::NonDf);
                        assert_eq!(actor.bum.borrow().ac_gate(esi(1)).unwrap().interface, "es0");
                        reply.send(Ok(())).unwrap();
                    }
                    if matches!(change, "replace" | "instances") {
                        let RibUpdate::InjectEvpn { route, reply } =
                            actor.rib_rx.recv().await.unwrap()
                        else {
                            panic!("current replacement must restart after its owned teardown");
                        };
                        let EvpnRouteKey::Es { rd: route_rd, .. } = route.key() else {
                            panic!("replacement restarts with Type 4");
                        };
                        assert_eq!(
                            route_rd,
                            rd(65000, if change == "replace" { 103 } else { 201 })
                        );
                        actor.injected.push(route.key());
                        reply.send(Ok(())).unwrap();
                        actor.routes_reply().await.send(Vec::new()).unwrap();
                    }
                }
                actor.finish().await;
            }
        }
    }

    #[tokio::test(start_paused = true)]
    #[expect(
        clippy::too_many_lines,
        reason = "real live starts hold the same ES Type 4 across desired-state changes"
    )]
    async fn live_startup_ack_revalidates_add_admin_and_undrain() {
        for start in ["addition", "admin", "undrain"] {
            for change in ["delete", "redrain", "binding"] {
                let mut actor = DfWaitActor::new(DfAlgorithm::HighestPreference);
                actor.startup().await;
                tokio::time::advance(Duration::from_secs(3)).await;
                actor.sync_reply().await.send(true).unwrap();
                actor.routes_reply().await.send(Vec::new()).unwrap();
                let event = type_4_es_route(esi(1), "10.0.0.2", attrs_with_es_import_rt(esi(1)));
                actor.remote_event(&event);
                let before = actor.routes_reply().await;
                actor.assert_role(DfRole::Df);
                let control = actor.handle.runtime_control();
                let mut desired = control.segments_tx.borrow().as_ref().clone();
                let (id, member, old_interface) = if start == "addition" {
                    (2, 103, "es1")
                } else {
                    (1, 101, "es0")
                };
                match start {
                    "addition" => {
                        let mut added = desired[0].clone();
                        added.esi = esi(id);
                        added.member_vnis = BTreeSet::from([vni(member)]);
                        desired.push(added);
                        assert!(control.replace_segments(Arc::new(desired.clone())));
                    }
                    "admin" => {
                        desired[0].df_preference = 200;
                        assert!(control.replace_segments(Arc::new(desired.clone())));
                    }
                    "undrain" => {
                        assert!(control.replace_drained_esis(Arc::new(BTreeSet::from([esi(id)]))));
                    }
                    _ => unreachable!(),
                }
                before.send(Vec::new()).unwrap();
                if start != "addition" {
                    for index in 0..3 {
                        let RibUpdate::WithdrawEvpn { reply, .. } =
                            actor.rib_rx.recv().await.unwrap()
                        else {
                            panic!("the old DF owns three routes to withdraw");
                        };
                        if start == "undrain" && index == 2 {
                            assert!(control.replace_drained_esis(Arc::new(BTreeSet::new())));
                        }
                        reply.send(Ok(())).unwrap();
                    }
                }
                let RibUpdate::InjectEvpn { route, reply: held } =
                    actor.rib_rx.recv().await.unwrap()
                else {
                    panic!("the live start must reach its Type 4 acknowledgement");
                };
                assert!(
                    matches!(route.key(), EvpnRouteKey::Es { esi: key_esi, .. } if key_esi == esi(id))
                );
                actor.injected.push(route.key());
                let injected_before = actor.injected.len();
                match change {
                    "delete" => {
                        desired.retain(|segment| segment.esi != esi(id));
                        assert!(control.replace_segments(Arc::new(desired)));
                    }
                    "redrain" => {
                        assert!(control.replace_drained_esis(Arc::new(BTreeSet::from([esi(id)]))));
                    }
                    "binding" => {
                        let mut bindings = actor.bindings.borrow().as_ref().clone();
                        bindings.get_mut(&esi(id)).unwrap().interface = "es-live-new".to_string();
                        actor.bindings.send_replace(Arc::new(bindings));
                    }
                    _ => unreachable!(),
                }
                held.send(Ok(())).unwrap();
                if change == "binding" {
                    let RibUpdate::InjectEvpn { route, reply } = actor.rib_rx.recv().await.unwrap()
                    else {
                        panic!("binding retry must resume the live EAD-per-ES");
                    };
                    assert!(
                        matches!(route.key(), EvpnRouteKey::EadPerEs { esi: key_esi, .. } if key_esi == esi(id))
                    );
                    actor.assert_segment_role(esi(id), vni(member), DfRole::NonDf);
                    assert_eq!(
                        actor.bum.borrow().ac_gate(esi(id)).unwrap().interface,
                        "es-live-new"
                    );
                    actor.injected.push(route.key());
                    reply.send(Ok(())).unwrap();
                    actor.routes_reply().await.send(Vec::new()).unwrap();
                } else {
                    let RibUpdate::WithdrawEvpn { key, reply } = actor.rib_rx.recv().await.unwrap()
                    else {
                        panic!(
                            "stale live start must withdraw Type 4 before EAD or query: {start}/{change}"
                        );
                    };
                    assert!(
                        matches!(key, EvpnRouteKey::Es { esi: key_esi, .. } if key_esi == esi(id))
                    );
                    actor.assert_segment_role(esi(id), vni(member), DfRole::NonDf);
                    assert_eq!(
                        actor.bum.borrow().ac_gate(esi(id)).unwrap().interface,
                        old_interface
                    );
                    assert_eq!(actor.injected.len(), injected_before);
                    reply.send(Ok(())).unwrap();
                }
                actor.finish().await;
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn delayed_recovery_ack_revalidates_before_ead() {
        for change in ["delete", "replace", "redrain", "binding"] {
            let mut actor = DfWaitActor::new(DfAlgorithm::HighestPreference);
            let control = actor.handle.runtime_control();
            let mut desired = control.segments_tx.borrow().as_ref().clone();
            desired[0].df_dont_preempt = true;
            assert!(control.replace_segments(Arc::new(desired.clone())));
            let RibUpdate::SubscribeEvpnRouteEvents { reply } = actor.rib_rx.recv().await.unwrap()
            else {
                panic!("recovery subscribes before waiting for boot synchronization");
            };
            reply.send(actor.events.subscribe()).unwrap();
            // The immediate interval query cannot elect or originate during wait.
            actor.routes_reply().await.send(Vec::new()).unwrap();
            tokio::time::advance(Duration::from_secs(3)).await;
            actor.sync_reply().await.send(true).unwrap();
            actor.routes_reply().await.send(Vec::new()).unwrap();
            let RibUpdate::InjectEvpn { route, reply: held } = actor.rib_rx.recv().await.unwrap()
            else {
                panic!("Don't-Preempt recovery must reach its delayed Type 4 acknowledgement");
            };
            assert!(matches!(route.key(), EvpnRouteKey::Es { .. }));
            actor.injected.push(route.key());
            match change {
                "delete" => assert!(control.replace_segments(Arc::new(Vec::new()))),
                "replace" => {
                    desired[0].member_vnis = BTreeSet::from([vni(103)]);
                    assert!(control.replace_segments(Arc::new(desired)));
                }
                "redrain" => {
                    assert!(control.replace_drained_esis(Arc::new(BTreeSet::from([esi(1)]))));
                }
                "binding" => {
                    let mut bindings = actor.bindings.borrow().as_ref().clone();
                    bindings.get_mut(&esi(1)).unwrap().interface = "es-dp-new".to_string();
                    actor.bindings.send_replace(Arc::new(bindings));
                }
                _ => unreachable!(),
            }
            held.send(Ok(())).unwrap();
            if change == "binding" {
                let RibUpdate::InjectEvpn { route, reply } = actor.rib_rx.recv().await.unwrap()
                else {
                    panic!("delayed recovery must resume its EAD on the current binding");
                };
                assert!(matches!(route.key(), EvpnRouteKey::EadPerEs { .. }));
                assert_eq!(
                    actor.bum.borrow().ac_gate(esi(1)).unwrap().interface,
                    "es-dp-new"
                );
                actor.assert_role(DfRole::NonDf);
                reply.send(Ok(())).unwrap();
                actor.routes_reply().await.send(Vec::new()).unwrap();
            } else {
                let RibUpdate::WithdrawEvpn { key, reply } = actor.rib_rx.recv().await.unwrap()
                else {
                    panic!("stale delayed recovery must withdraw Type 4 before EAD: {change}");
                };
                assert!(matches!(key, EvpnRouteKey::Es { .. }));
                actor.assert_role(DfRole::NonDf);
                assert_eq!(actor.bum.borrow().ac_gate(esi(1)).unwrap().interface, "es0");
                reply.send(Ok(())).unwrap();
            }
            actor.finish().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn held_candidate_query_revalidates_before_election() {
        for change in ["delete", "redrain", "binding"] {
            let mut actor = DfWaitActor::new(DfAlgorithm::HighestPreference);
            actor.startup().await;
            tokio::time::advance(Duration::from_secs(3)).await;
            actor.sync_reply().await.send(true).unwrap();
            // Boot wait has settled; answering this query would elect local DF.
            let held = actor.routes_reply().await;
            let control = actor.handle.runtime_control();
            match change {
                "delete" => assert!(control.replace_segments(Arc::new(Vec::new()))),
                "redrain" => {
                    assert!(control.replace_drained_esis(Arc::new(BTreeSet::from([esi(1)]))));
                }
                "binding" => {
                    let mut bindings = actor.bindings.borrow().as_ref().clone();
                    bindings.get_mut(&esi(1)).unwrap().interface = "es-query-new".to_string();
                    actor.bindings.send_replace(Arc::new(bindings));
                }
                _ => unreachable!(),
            }
            held.send(Vec::new()).unwrap();
            if change == "binding" {
                let refreshed_query = actor.routes_reply().await;
                actor.assert_role(DfRole::NonDf);
                assert_eq!(
                    actor.bum.borrow().ac_gate(esi(1)).unwrap().interface,
                    "es-query-new"
                );
                refreshed_query.send(Vec::new()).unwrap();
            } else {
                let RibUpdate::WithdrawEvpn { key, reply } = actor.rib_rx.recv().await.unwrap()
                else {
                    panic!(
                        "stale candidate query must not elect or originate per-EVI EAD: {change}"
                    );
                };
                assert!(matches!(key, EvpnRouteKey::EadPerEs { .. }));
                actor.assert_role(DfRole::NonDf);
                assert_eq!(actor.bum.borrow().ac_gate(esi(1)).unwrap().interface, "es0");
                reply.send(Ok(())).unwrap();
            }
            actor.finish().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn later_member_ack_cannot_publish_a_partial_election() {
        for change in ["delete", "replace", "redrain", "binding"] {
            let mut actor = DfWaitActor::new(DfAlgorithm::HighestPreference);
            let control = actor.handle.runtime_control();
            let mut desired = control.segments_tx.borrow().as_ref().clone();
            desired[0].member_vnis.insert(vni(103));
            assert!(control.replace_segments(Arc::new(desired.clone())));
            actor.startup().await;
            tokio::time::advance(Duration::from_secs(3)).await;
            actor.sync_reply().await.send(true).unwrap();
            actor.routes_reply().await.send(Vec::new()).unwrap();
            let mut held = None;
            for index in 0..2 {
                let RibUpdate::InjectEvpn { route, reply } = actor.rib_rx.recv().await.unwrap()
                else {
                    panic!("both prepared members must reach their per-EVI acknowledgement");
                };
                assert!(matches!(route.key(), EvpnRouteKey::EadPerEvi { .. }));
                actor.injected.push(route.key());
                if index == 0 {
                    reply.send(Ok(())).unwrap();
                } else {
                    held = Some(reply);
                }
            }
            // Even one acknowledged member must not expose a partial role set.
            for member in [101, 103] {
                actor.assert_segment_role(esi(1), vni(member), DfRole::NonDf);
            }
            match change {
                "delete" => assert!(control.replace_segments(Arc::new(Vec::new()))),
                "replace" => {
                    desired[0].member_vnis = BTreeSet::from([vni(105)]);
                    assert!(control.replace_segments(Arc::new(desired)));
                }
                "redrain" => {
                    assert!(control.replace_drained_esis(Arc::new(BTreeSet::from([esi(1)]))));
                }
                "binding" => {
                    let mut bindings = actor.bindings.borrow().as_ref().clone();
                    bindings.get_mut(&esi(1)).unwrap().interface = "es-members-new".to_string();
                    actor.bindings.send_replace(Arc::new(bindings));
                }
                _ => unreachable!(),
            }
            held.unwrap().send(Ok(())).unwrap();
            if change == "binding" {
                let refreshed_query = actor.routes_reply().await;
                for member in [101, 103] {
                    actor.assert_segment_role(esi(1), vni(member), DfRole::NonDf);
                }
                assert_eq!(
                    actor.bum.borrow().ac_gate(esi(1)).unwrap().interface,
                    "es-members-new"
                );
                refreshed_query.send(Vec::new()).unwrap();
            } else {
                let RibUpdate::WithdrawEvpn { key, reply } = actor.rib_rx.recv().await.unwrap()
                else {
                    panic!("stale member election must settle its owned EAD routes");
                };
                assert!(matches!(key, EvpnRouteKey::EadPerEvi { .. }));
                assert_eq!(
                    actor.bum.borrow().ac_gate(esi(1)).unwrap().state,
                    AcGateState::Blocked,
                    "a stale later member acknowledgement must retain the complete blocked gate"
                );
                for member in [101, 103] {
                    actor.assert_segment_role(esi(1), vni(member), DfRole::NonDf);
                }
                assert_eq!(actor.bum.borrow().ac_gate(esi(1)).unwrap().interface, "es0");
                reply.send(Ok(())).unwrap();
            }
            actor.finish().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn every_df_algorithm_waits_before_first_election() {
        for algorithm in [
            DfAlgorithm::DefaultModulo,
            DfAlgorithm::HighestRandomWeight,
            DfAlgorithm::HighestPreference,
            DfAlgorithm::LowestPreference,
        ] {
            let mut actor = DfWaitActor::new(algorithm);
            actor.startup().await;
            tokio::time::advance(Duration::from_millis(2999)).await;
            actor.assert_role(DfRole::NonDf);
            tokio::time::advance(Duration::from_millis(1)).await;
            actor.sync_reply().await.send(true).unwrap();
            actor.routes_reply().await.send(Vec::new()).unwrap();
            actor.remote_event(&type_4_es_route(
                esi(1),
                "10.0.0.2",
                attrs_with_es_import_rt(esi(1)),
            ));
            let next_event = actor.routes_reply().await;
            assert!(
                actor.status.borrow_and_update()[&esi(1)]
                    .recovery_deadline
                    .is_none()
            );
            actor.assert_role(DfRole::Df);
            // Ordinary wait completion must not refresh its Type 4 or EAD-per-ES.
            assert_eq!(
                actor
                    .injected
                    .iter()
                    .filter(|key| matches!(key, EvpnRouteKey::Es { .. }))
                    .count(),
                1
            );
            next_event.send(Vec::new()).unwrap();
            actor.finish().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn first_df_election_includes_type4_received_during_wait() {
        let mut actor = DfWaitActor::new(DfAlgorithm::HighestPreference);
        actor.startup().await;
        let mut attrs = attrs_with_es_import_rt(esi(1));
        attrs.push(PathAttribute::ExtendedCommunities(vec![
            ExtendedCommunity::df_election(
                DfAlgorithm::HighestPreference.algorithm_id(),
                0,
                Some(200),
            ),
        ]));
        let remote = type_4_es_route(esi(1), "10.0.0.2", attrs);
        tokio::time::advance(Duration::from_millis(2999)).await;
        actor.remote_event(&remote);
        actor
            .routes_reply()
            .await
            .send(vec![remote.clone()])
            .unwrap();
        // Reaching the next event query proves the first event's election
        // attempt completed, rather than inspecting state before it ran.
        actor.remote_event(&remote);
        let second_event = actor.routes_reply().await;
        actor.assert_role(DfRole::NonDf);
        assert_eq!(actor.injected.len(), 2);
        second_event.send(vec![remote.clone()]).unwrap();
        tokio::time::advance(Duration::from_millis(1)).await;
        actor.sync_reply().await.send(false).unwrap();
        actor.status.changed().await.unwrap();
        assert!(
            actor.status.borrow_and_update()[&esi(1)]
                .recovery_deadline
                .is_some()
        );
        actor.assert_role(DfRole::NonDf);
        tokio::time::advance(Duration::from_secs(1)).await;
        actor.sync_reply().await.send(true).unwrap();
        actor.routes_reply().await.send(vec![remote]).unwrap();
        // A second query cannot start until the completed election's EAD has
        // been acknowledged. Trigger it to drive that acknowledgement.
        let remote = type_4_es_route(esi(1), "10.0.0.2", attrs_with_es_import_rt(esi(1)));
        actor.remote_event(&remote);
        let next_event = actor.routes_reply().await;
        assert!(actor.status.borrow()[&esi(1)].recovery_deadline.is_none());
        actor.assert_role(DfRole::NonDf);
        assert_eq!(
            actor.injected.len(),
            3,
            "first election adds only EAD-per-EVI"
        );
        next_event.send(Vec::new()).unwrap();
        actor.finish().await;
    }

    #[tokio::test(start_paused = true)]
    async fn live_added_segments_publish_all_waits_before_first_type4_ack() {
        let mut actor = DfWaitActor::new(DfAlgorithm::DefaultModulo);
        actor.startup().await;
        tokio::time::advance(Duration::from_secs(3)).await;
        actor.sync_reply().await.send(true).unwrap();
        actor.routes_reply().await.send(Vec::new()).unwrap();
        actor.remote_event(&type_4_es_route(
            esi(1),
            "10.0.0.2",
            attrs_with_es_import_rt(esi(1)),
        ));
        let barrier = actor.routes_reply().await;
        actor.assert_role(DfRole::Df);
        barrier.send(Vec::new()).unwrap();

        let configs = [(1, 101), (2, 103), (3, 105)]
            .into_iter()
            .map(|(id, member)| {
                let mut config = segment(esi(id), &[member]);
                config.df_preference = 100;
                config.redundancy_mode = RedundancyMode::SingleActive;
                config
            })
            .collect();
        assert!(
            actor
                .handle
                .runtime_control()
                .replace_segments(Arc::new(configs))
        );
        let RibUpdate::InjectEvpn { route, reply } = actor.rib_rx.recv().await.unwrap() else {
            panic!("live add must first advertise Type 4");
        };
        assert!(matches!(route.key(), EvpnRouteKey::Es { esi: id, .. } if id == esi(2)));
        // Neither the first Type 4 nor anything from the second added ES has
        // been acknowledged. Both complete watch views must already exist.
        for (id, member) in [(2, 103), (3, 105)] {
            actor.assert_segment_role(esi(id), vni(member), DfRole::NonDf);
            assert_eq!(
                actor.status.borrow()[&esi(id)].recovery_deadline.unwrap()
                    - tokio::time::Instant::now(),
                Duration::from_secs(3)
            );
        }
        actor.assert_role(DfRole::Df);
        actor.injected.push(route.key());
        reply.send(Ok(())).unwrap();
        // Finish each added ES's initial candidate query without inventing a
        // remote route. The first's RIB acknowledgement cannot hide the second.
        actor.routes_reply().await.send(Vec::new()).unwrap();
        actor.routes_reply().await.send(Vec::new()).unwrap();
        let remote = type_4_es_route(esi(2), "10.0.0.2", attrs_with_es_import_rt(esi(2)));
        tokio::time::advance(Duration::from_millis(2999)).await;
        actor.remote_event(&remote);
        actor
            .routes_reply()
            .await
            .send(vec![remote.clone()])
            .unwrap();
        actor.remote_event(&remote);
        let barrier = actor.routes_reply().await;
        for (id, member) in [(2, 103), (3, 105)] {
            actor.assert_segment_role(esi(id), vni(member), DfRole::NonDf);
            assert!(actor.status.borrow()[&esi(id)].recovery_deadline.is_some());
        }
        assert_eq!(
            actor.injected.len(),
            7,
            "one existing EAD-per-EVI, only Type 4/EAD-per-ES for both new ESs"
        );
        barrier.send(vec![remote]).unwrap();
        actor.finish().await;
    }

    #[tokio::test(start_paused = true)]
    async fn administrative_df_change_suppresses_until_origination_ack_without_wait() {
        for (preference, expected_role) in [(150, DfRole::NonDf), (250, DfRole::Df)] {
            let mut actor = DfWaitActor::new(DfAlgorithm::HighestPreference);
            actor.startup().await;
            let mut attrs = attrs_with_es_import_rt(esi(1));
            attrs.push(PathAttribute::ExtendedCommunities(vec![
                ExtendedCommunity::df_election(
                    DfAlgorithm::HighestPreference.algorithm_id(),
                    0,
                    Some(200),
                ),
            ]));
            let remote = type_4_es_route(esi(1), "10.0.0.2", attrs);
            tokio::time::advance(Duration::from_secs(3)).await;
            actor.sync_reply().await.send(true).unwrap();
            actor
                .routes_reply()
                .await
                .send(vec![remote.clone()])
                .unwrap();
            actor.remote_event(&remote);
            let before_change = actor.routes_reply().await;
            actor.assert_role(DfRole::NonDf);
            assert!(actor.status.borrow()[&esi(1)].recovery_deadline.is_none());

            let mut replacement = segment(esi(1), &[101]);
            replacement.df_algorithm = DfAlgorithm::HighestPreference;
            replacement.df_preference = preference;
            replacement.redundancy_mode = RedundancyMode::SingleActive;
            let changed_at = tokio::time::Instant::now();
            assert!(
                actor
                    .handle
                    .runtime_control()
                    .replace_segments(Arc::new(vec![replacement]))
            );
            before_change.send(vec![remote.clone()]).unwrap();
            for _ in 0..3 {
                let RibUpdate::WithdrawEvpn { key, reply } = actor.rib_rx.recv().await.unwrap()
                else {
                    panic!("all old route classes must withdraw before the administrative change");
                };
                assert_eq!(esi_of_key(&key), Some(esi(1)));
                reply.send(Ok(())).unwrap();
            }
            let RibUpdate::InjectEvpn { route, reply } = actor.rib_rx.recv().await.unwrap() else {
                panic!("administrative change must first advertise Type 4");
            };
            assert!(matches!(route.key(), EvpnRouteKey::Es { .. }));
            // Holding the first origination reply proves the pre-start watch
            // publication has run. BUM and the bound AC must remain suppressed.
            actor.assert_role(DfRole::NonDf);
            assert!(actor.status.borrow()[&esi(1)].recovery_deadline.is_none());
            actor.injected.push(route.key());
            reply.send(Ok(())).unwrap();
            let RibUpdate::InjectEvpn { route, reply } = actor.rib_rx.recv().await.unwrap() else {
                panic!("EAD-per-ES must follow Type 4");
            };
            assert!(matches!(route.key(), EvpnRouteKey::EadPerEs { .. }));
            actor.assert_role(DfRole::NonDf);
            actor.injected.push(route.key());
            reply.send(Ok(())).unwrap();
            actor
                .routes_reply()
                .await
                .send(vec![remote.clone()])
                .unwrap();
            // The next event query follows election and its EAD-per-EVI ACK.
            actor.remote_event(&remote);
            let after_change = actor.routes_reply().await;
            actor.assert_role(expected_role);
            assert!(actor.status.borrow()[&esi(1)].recovery_deadline.is_none());
            assert_eq!(tokio::time::Instant::now(), changed_at);
            assert_eq!(
                actor
                    .injected
                    .iter()
                    .filter(|key| matches!(key, EvpnRouteKey::EadPerEvi { .. }))
                    .count(),
                2,
                "replacement EAD-per-EVI must originate even when election remains NonDf"
            );
            after_change.send(vec![remote]).unwrap();
            actor.finish().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn lagging_actor_keeps_both_uncommitted_revisions_drained() {
        let mut actor = DfWaitActor::new(DfAlgorithm::DefaultModulo);
        let initial_bindings = Arc::new(BTreeMap::from([(
            esi(1),
            actor.bindings.borrow()[&esi(1)].clone(),
        )]));
        actor.bindings.send_replace(initial_bindings);
        actor.startup().await;
        let event = type_4_es_route(esi(1), "10.0.0.2", attrs_with_es_import_rt(esi(1)));
        actor.remote_event(&event);
        let held = actor.routes_reply().await;
        let control = actor.handle.runtime_control();
        let configs = |members: &[(u8, u32)]| {
            Arc::new(
                members
                    .iter()
                    .map(|&(id, member)| {
                        let mut config = segment(esi(id), &[member]);
                        config.df_preference = 100;
                        config.redundancy_mode = RedundancyMode::SingleActive;
                        config
                    })
                    .collect(),
            )
        };
        // Queue revision A, then revision B, while an acknowledged RIB
        // boundary holds the actor. Each revision seeds Link drain before
        // publishing dependent segments; neither binding has committed.
        assert!(control.replace_drained_esis(drained_set(&[esi(2)])));
        assert!(control.replace_segments(configs(&[(1, 101), (2, 103)])));
        assert!(control.replace_drained_esis(drained_set(&[esi(2), esi(3)])));
        assert!(control.replace_segments(configs(&[(1, 101), (2, 103), (3, 105)])));
        held.send(Vec::new()).unwrap();
        actor.remote_event(&event);
        let observed = actor.routes_reply().await;
        for id in [2, 3] {
            assert!(actor.status.borrow().contains_key(&esi(id)));
            assert!(!actor.bindings.borrow().contains_key(&esi(id)));
        }
        assert_eq!(
            actor.injected.len(),
            2,
            "neither uncommitted revision may originate"
        );
        observed.send(Vec::new()).unwrap();
        actor.finish().await;
    }

    #[tokio::test(start_paused = true)]
    #[expect(
        clippy::too_many_lines,
        reason = "one held commit verifies candidate publication, binding commit, undrain and removal ordering"
    )]
    async fn committed_binding_precedes_undrain_and_removal_gc_does_not_reoriginate() {
        use crate::evpn_es_drain::{EsDrainReason, EvpnEsDrainState, apply_ethernet_segment_drain};
        use crate::evpn_runtime_converger::{
            DaemonEvpnRuntimeConvergeFuture, DaemonEvpnRuntimeConverger, EvpnRuntimeActorConverger,
            EvpnRuntimeReloadApply,
        };

        // Run the real converger, but hold its return so the actor consumes
        // candidate publication before the reload owner commits the binding.
        struct HoldCommit {
            inner: EvpnRuntimeActorConverger,
            published: tokio::sync::Notify,
            commit: tokio::sync::Notify,
        }
        impl DaemonEvpnRuntimeConverger for HoldCommit {
            fn converge<'a>(
                &'a self,
                current: &'a rustbgpd_evpn::EvpnRuntimeModel,
                candidate: &'a rustbgpd_evpn::EvpnRuntimeCandidate,
                plan: &'a rustbgpd_evpn::EvpnRuntimePlan,
            ) -> DaemonEvpnRuntimeConvergeFuture<'a> {
                Box::pin(async move {
                    self.inner.converge(current, candidate, plan).await?;
                    self.published.notify_one();
                    self.commit.notified().await;
                    Ok(())
                })
            }

            fn seed_link_drain(
                &self,
                esis: &BTreeSet<EthernetSegmentIdentifier>,
            ) -> Option<Arc<crate::evpn_es_drain::EsDrainReasonMap>> {
                self.inner.seed_link_drain(esis)
            }

            fn restore_link_drain(&self, prior: Arc<crate::evpn_es_drain::EsDrainReasonMap>) {
                self.inner.restore_link_drain(prior);
            }
        }

        let mut baseline_toml = "[global]\nasn=65000\nrouter_id=\"10.0.0.1\"\nlisten_port=179\n\n[global.telemetry]\nlog_format=\"json\"\n".to_string();
        for member in [101, 103, 105] {
            writeln!(baseline_toml,
                "\n[[evpn_instances]]\nvni={member}\nrd=\"65000:{member}\"\nroute_targets=[\"65000:{member}\"]\nlocal_vtep_ip=\"10.0.0.1\"\nbridge=\"br{member}\"\nadvertise_svi_mac=false"
            ).unwrap();
        }
        let es_config = |id, member, interface| {
            format!(
                "\n[[ethernet_segments]]\nesi=\"{}\"\nmember_vnis=[{member}]\noriginator_ip=\"10.0.0.1\"\ndf_preference=100\ndf_algorithm=\"highest-preference\"\nredundancy_mode=\"single-active\"\ninterface=\"{interface}\"\nrecovery_delay_seconds=0\n",
                format_esi(esi(id))
            )
        };
        baseline_toml.push_str(&es_config(1, 101, "es0"));
        let candidate_toml = baseline_toml.clone() + &es_config(2, 103, "es1");
        let baseline = crate::config::Config::load_toml_with_diagnostics(
            &crate::test_support::tier_authorized_uds_test_config(&baseline_toml),
            "baseline",
        )
        .unwrap();
        let candidate = crate::config::Config::load_toml_with_diagnostics(
            &crate::test_support::tier_authorized_uds_test_config(&candidate_toml),
            "candidate",
        )
        .unwrap();
        let mut actor = DfWaitActor::new(DfAlgorithm::HighestPreference);
        let initial_bindings = Arc::new(BTreeMap::from([(
            esi(1),
            actor.bindings.borrow()[&esi(1)].clone(),
        )]));
        actor.bindings.send_replace(initial_bindings);
        actor.startup().await;
        tokio::time::advance(Duration::from_secs(3)).await;
        actor.sync_reply().await.send(true).unwrap();
        actor.routes_reply().await.send(Vec::new()).unwrap();
        actor.remote_event(&type_4_es_route(
            esi(1),
            "10.0.0.2",
            attrs_with_es_import_rt(esi(1)),
        ));
        let before_apply = actor.routes_reply().await;
        actor.assert_role(DfRole::Df);

        let coordinator = Arc::new(std::sync::Mutex::new(
            rustbgpd_evpn::EvpnRuntimeCoordinator::new(
                baseline.resolve_evpn_instances().unwrap(),
                baseline.resolve_evpn_ip_vrfs().unwrap(),
                baseline.resolve_ethernet_segments().unwrap(),
            ),
        ));
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        let drain = EvpnEsDrainState::default();
        let control = actor.handle.runtime_control();
        let held = Arc::new(HoldCommit {
            inner: EvpnRuntimeActorConverger::new(
                actor.rib_tx.clone(),
                Arc::new(tokio::sync::Mutex::new(
                    crate::evpn_imet::EvpnImetController::new(),
                )),
                None,
                None,
                None,
                None,
                Some(control.clone()),
                drain.clone(),
            ),
            published: tokio::sync::Notify::new(),
            commit: tokio::sync::Notify::new(),
        });
        let apply = Arc::new(
            EvpnRuntimeReloadApply::new(
                coordinator.clone(),
                lock.clone(),
                held.clone(),
                baseline.clone(),
            )
            .with_es_link_bindings_publisher(Arc::new(actor.bindings.clone())),
        );
        let apply_task = apply.clone();
        let applying = tokio::spawn(async move { apply_task.apply_config(&candidate).await });
        held.published.notified().await;
        assert_eq!(
            drain.reasons_for(esi(2)),
            BTreeSet::from([EsDrainReason::Link])
        );
        assert!(
            !actor.bindings.borrow().contains_key(&esi(2)),
            "binding is not committed yet"
        );

        // Both the seed and candidate are queued while the actor is held.
        // Its biased segment branch must consume the seed before startup.
        before_apply.send(Vec::new()).unwrap();
        let event = type_4_es_route(esi(2), "10.0.0.2", attrs_with_es_import_rt(esi(2)));
        actor.remote_event(&event);
        let before_commit = actor.routes_reply().await;
        assert!(actor.status.borrow().contains_key(&esi(2)));
        assert_eq!(
            actor.injected.len(),
            3,
            "no uncommitted bound ES origination"
        );

        held.commit.notify_one();
        applying.await.unwrap().unwrap();
        assert!(actor.bindings.borrow().contains_key(&esi(2)));
        // The real drain mutation follows the same post-commit carrier-probe
        // path. Queue it while the actor is still held: drain is biased ahead
        // of bindings, so undrain must explicitly read the latest binding.
        apply_ethernet_segment_drain(
            esi(2),
            EsDrainReason::Link,
            false,
            &lock,
            &coordinator,
            &drain,
            Some(&control),
            None,
        )
        .await
        .unwrap();
        before_commit.send(Vec::new()).unwrap();
        let RibUpdate::InjectEvpn { route, reply } = actor.rib_rx.recv().await.unwrap() else {
            panic!("undrain must first originate Type 4");
        };
        assert!(matches!(route.key(), EvpnRouteKey::Es { esi: id, .. } if id == esi(2)));
        actor.assert_segment_role(esi(2), vni(103), DfRole::NonDf);
        assert!(actor.status.borrow()[&esi(2)].recovery_deadline.is_some());
        actor.injected.push(route.key());
        reply.send(Ok(())).unwrap();
        actor.routes_reply().await.send(Vec::new()).unwrap();
        actor.remote_event(&event);
        let barrier = actor.routes_reply().await;
        actor.assert_segment_role(esi(2), vni(103), DfRole::NonDf);

        // Drain the new ES, then hold the actor while the real deletion
        // publishes its segment snapshot and garbage-collects that drain.
        apply_ethernet_segment_drain(
            esi(2),
            EsDrainReason::Operator,
            true,
            &lock,
            &coordinator,
            &drain,
            Some(&control),
            None,
        )
        .await
        .unwrap();
        barrier.send(Vec::new()).unwrap();
        let retained_event = type_4_es_route(esi(1), "10.0.0.2", attrs_with_es_import_rt(esi(1)));
        actor.remote_event(&retained_event);
        let before_remove = actor.routes_reply().await;
        assert_eq!(
            actor.bum.borrow().ac_gate(esi(2)).unwrap().state,
            AcGateState::Blocked
        );
        let injected_before_remove = actor.injected.len();
        let removing = tokio::spawn(async move { apply.apply_config(&baseline).await });
        held.published.notified().await;
        assert!(
            drain.reasons_for(esi(2)).is_empty(),
            "real converger GC removed the drain reason"
        );
        before_remove.send(Vec::new()).unwrap();
        actor.remote_event(&retained_event);
        let after_remove = actor.routes_reply().await;
        assert!(!actor.status.borrow().contains_key(&esi(2)));
        assert_eq!(
            actor.injected.len(),
            injected_before_remove,
            "drain GC must not reoriginate the removed ES"
        );
        held.commit.notify_one();
        removing.await.unwrap().unwrap();
        after_remove.send(Vec::new()).unwrap();
        actor.finish().await;
    }

    fn df_wait_reload_config(
        include_y: bool,
        y_interface: &str,
        y_member: u32,
    ) -> crate::config::Config {
        let mut text = "[global]\nasn=65000\nrouter_id=\"10.0.0.1\"\nlisten_port=179\n\n[global.telemetry]\nlog_format=\"json\"\n".to_string();
        for member in [101, 103, 105] {
            writeln!(text,
                "\n[[evpn_instances]]\nvni={member}\nrd=\"65000:{member}\"\nroute_targets=[\"65000:{member}\"]\nlocal_vtep_ip=\"10.0.0.1\"\nbridge=\"br{member}\"\nadvertise_svi_mac=false"
            ).unwrap();
        }
        for (id, member, interface) in [(1, y_member, y_interface), (2, 103, "es2")] {
            if id == 1 && !include_y {
                continue;
            }
            writeln!(text,
                "\n[[ethernet_segments]]\nesi=\"{}\"\nmember_vnis=[{member}]\noriginator_ip=\"10.0.0.1\"\ndf_preference=100\ndf_algorithm=\"highest-preference\"\nredundancy_mode=\"single-active\"\ninterface=\"{interface}\"\nrecovery_delay_seconds=0",
                format_esi(esi(id))
            ).unwrap();
        }
        crate::config::Config::load_toml_with_diagnostics(
            &crate::test_support::tier_authorized_uds_test_config(&text),
            "held-withdrawal",
        )
        .unwrap()
    }

    #[tokio::test(start_paused = true)]
    #[expect(
        clippy::too_many_lines,
        reason = "one controlled withdrawal exercises committed binding, removal, redrain and shutdown transitions"
    )]
    async fn held_withdrawal_revalidates_prepared_undrain_before_origination() {
        use crate::evpn_es_drain::{EsDrainReason, EvpnEsDrainState, apply_ethernet_segment_drain};
        use crate::evpn_runtime_converger::{EvpnRuntimeActorConverger, EvpnRuntimeReloadApply};

        // Each case holds X's actual withdrawal acknowledgement while Y is a
        // prepared undrain. Changes commit through the real reload/drain path.
        for change in ["binding", "delete", "redrain", "shutdown"] {
            let baseline = df_wait_reload_config(true, "es0", 101);
            let mut actor = DfWaitActor::new(DfAlgorithm::HighestPreference);
            actor.bindings.send_replace(Arc::new(
                baseline
                    .resolve_es_link_bindings(&crate::config::AutoLacpEsis::default())
                    .unwrap(),
            ));
            actor.startup().await;
            let control = actor.handle.runtime_control();
            assert!(
                control.replace_segments(Arc::new(baseline.resolve_ethernet_segments().unwrap()))
            );
            actor.routes_reply().await.send(Vec::new()).unwrap();
            let event = type_4_es_route(esi(2), "10.0.0.2", attrs_with_es_import_rt(esi(2)));
            actor.remote_event(&event);
            let before_drain = actor.routes_reply().await;

            let coordinator = Arc::new(std::sync::Mutex::new(
                rustbgpd_evpn::EvpnRuntimeCoordinator::new(
                    baseline.resolve_evpn_instances().unwrap(),
                    baseline.resolve_evpn_ip_vrfs().unwrap(),
                    baseline.resolve_ethernet_segments().unwrap(),
                ),
            ));
            let lock = Arc::new(tokio::sync::Mutex::new(()));
            let drain = EvpnEsDrainState::default();
            let converger = Arc::new(EvpnRuntimeActorConverger::new(
                actor.rib_tx.clone(),
                Arc::new(tokio::sync::Mutex::new(
                    crate::evpn_imet::EvpnImetController::new(),
                )),
                None,
                None,
                None,
                None,
                Some(control.clone()),
                drain.clone(),
            ));
            let apply =
                EvpnRuntimeReloadApply::new(coordinator.clone(), lock.clone(), converger, baseline)
                    .with_es_link_bindings_publisher(Arc::new(actor.bindings.clone()));
            apply_ethernet_segment_drain(
                esi(1),
                EsDrainReason::Operator,
                true,
                &lock,
                &coordinator,
                &drain,
                Some(&control),
                None,
            )
            .await
            .unwrap();
            before_drain.send(Vec::new()).unwrap();
            actor.remote_event(&event);
            let before_swap = actor.routes_reply().await;
            assert!(actor.status.borrow()[&esi(1)].recovery_deadline.is_none());
            let injections_before = actor.injected.len();

            // Coalesce prior={Y}, incoming={X} while the actor is held.
            for (id, drained) in [(2, true), (1, false)] {
                apply_ethernet_segment_drain(
                    esi(id),
                    EsDrainReason::Operator,
                    drained,
                    &lock,
                    &coordinator,
                    &drain,
                    Some(&control),
                    None,
                )
                .await
                .unwrap();
            }
            before_swap.send(Vec::new()).unwrap();
            let RibUpdate::WithdrawEvpn {
                reply: held_withdrawal,
                ..
            } = actor.rib_rx.recv().await.unwrap()
            else {
                panic!("X must reach its real withdrawal acknowledgement");
            };
            actor.assert_segment_role(esi(1), vni(101), DfRole::NonDf);
            assert!(actor.status.borrow()[&esi(1)].recovery_deadline.is_some());
            assert_eq!(actor.bum.borrow().ac_gate(esi(1)).unwrap().interface, "es0");
            match change {
                "binding" => {
                    apply
                        .apply_config(&df_wait_reload_config(true, "es1", 101))
                        .await
                        .unwrap();
                    assert_eq!(actor.bindings.borrow()[&esi(1)].interface, "es1");
                }
                "delete" => {
                    apply
                        .apply_config(&df_wait_reload_config(false, "es0", 101))
                        .await
                        .unwrap();
                }
                "redrain" => {
                    apply_ethernet_segment_drain(
                        esi(1),
                        EsDrainReason::Operator,
                        true,
                        &lock,
                        &coordinator,
                        &drain,
                        Some(&control),
                        None,
                    )
                    .await
                    .unwrap();
                }
                "shutdown" => actor.handle.shutdown.cancel(),
                _ => unreachable!(),
            }
            held_withdrawal.send(Ok(())).unwrap();
            if change == "binding" {
                loop {
                    match actor.rib_rx.recv().await.unwrap() {
                        RibUpdate::WithdrawEvpn { reply, .. } => {
                            reply.send(Ok(())).unwrap();
                        }
                        RibUpdate::InjectEvpn { route, reply } => {
                            assert!(
                                matches!(route.key(), EvpnRouteKey::Es { esi: id, .. } if id == esi(1))
                            );
                            actor.assert_segment_role(esi(1), vni(101), DfRole::NonDf);
                            let gate = actor.bum.borrow().ac_gate(esi(1)).unwrap().clone();
                            assert_eq!(
                                gate.interface, "es1",
                                "gate must follow the committed binding before Type 4"
                            );
                            assert_eq!(gate.state, AcGateState::Blocked);
                            actor.injected.push(route.key());
                            reply.send(Ok(())).unwrap();
                            break;
                        }
                        _ => panic!("undrain must originate only after X's withdrawals"),
                    }
                }
                actor.routes_reply().await.send(Vec::new()).unwrap();
            } else if change == "shutdown" {
                let mut join = actor.handle.join;
                loop {
                    tokio::select! {
                        result = &mut join => { result.unwrap(); break; }
                        update = actor.rib_rx.recv() => match update.unwrap() {
                            RibUpdate::WithdrawEvpn { reply, .. } => { reply.send(Ok(())).unwrap(); }
                            _ => panic!("shutdown must settle withdrawals without new origination"),
                        }
                    }
                }
                continue;
            } else {
                actor.remote_event(&event);
                let observed = actor.routes_reply().await;
                assert_eq!(
                    actor.injected.len(),
                    injections_before,
                    "{change} must cancel Y's prepared origination"
                );
                if change == "delete" {
                    assert!(!actor.status.borrow().contains_key(&esi(1)));
                } else {
                    assert_eq!(
                        actor.bum.borrow().ac_gate(esi(1)).unwrap().state,
                        AcGateState::Blocked
                    );
                    assert!(actor.status.borrow()[&esi(1)].recovery_deadline.is_none());
                }
                observed.send(Vec::new()).unwrap();
            }
            actor.finish().await;
        }
    }

    #[tokio::test(start_paused = true)]
    #[expect(
        clippy::too_many_lines,
        reason = "held replacement withdrawals exercise configuration, drain and binding publications through the real actor"
    )]
    async fn held_replacement_withdrawal_revalidates_before_origination() {
        use crate::evpn_es_drain::{EsDrainReason, EvpnEsDrainState, apply_ethernet_segment_drain};
        use crate::evpn_runtime_converger::{EvpnRuntimeActorConverger, EvpnRuntimeReloadApply};

        for change in ["delete", "replace", "redrain", "binding", "instances"] {
            let baseline = df_wait_reload_config(true, "es0", 101);
            let mut actor = DfWaitActor::new(DfAlgorithm::HighestPreference);
            actor.bindings.send_replace(Arc::new(
                baseline
                    .resolve_es_link_bindings(&crate::config::AutoLacpEsis::default())
                    .unwrap(),
            ));
            actor.startup().await;
            let control = actor.handle.runtime_control();
            assert!(
                control.replace_segments(Arc::new(baseline.resolve_ethernet_segments().unwrap()))
            );
            actor.routes_reply().await.send(Vec::new()).unwrap();
            let event = type_4_es_route(esi(2), "10.0.0.2", attrs_with_es_import_rt(esi(2)));
            actor.remote_event(&event);
            let before_apply = actor.routes_reply().await;
            let coordinator = Arc::new(std::sync::Mutex::new(
                rustbgpd_evpn::EvpnRuntimeCoordinator::new(
                    baseline.resolve_evpn_instances().unwrap(),
                    baseline.resolve_evpn_ip_vrfs().unwrap(),
                    baseline.resolve_ethernet_segments().unwrap(),
                ),
            ));
            let lock = Arc::new(tokio::sync::Mutex::new(()));
            let drain = EvpnEsDrainState::default();
            let converger = Arc::new(EvpnRuntimeActorConverger::new(
                actor.rib_tx.clone(),
                Arc::new(tokio::sync::Mutex::new(
                    crate::evpn_imet::EvpnImetController::new(),
                )),
                None,
                None,
                None,
                None,
                Some(control.clone()),
                drain.clone(),
            ));
            let apply =
                EvpnRuntimeReloadApply::new(coordinator.clone(), lock.clone(), converger, baseline)
                    .with_es_link_bindings_publisher(Arc::new(actor.bindings.clone()));
            apply
                .apply_config(&df_wait_reload_config(true, "es1", 105))
                .await
                .unwrap();
            before_apply.send(Vec::new()).unwrap();
            let RibUpdate::WithdrawEvpn { reply: held, .. } = actor.rib_rx.recv().await.unwrap()
            else {
                panic!("replacement must await its old routes' withdrawal");
            };
            assert_eq!(actor.bum.borrow().ac_gate(esi(1)).unwrap().interface, "es0");
            let injections_before = actor.injected.len();
            match change {
                "delete" => {
                    apply
                        .apply_config(&df_wait_reload_config(false, "es1", 105))
                        .await
                        .unwrap();
                }
                "replace" => {
                    apply
                        .apply_config(&df_wait_reload_config(true, "es1", 101))
                        .await
                        .unwrap();
                }
                "binding" => {
                    apply
                        .apply_config(&df_wait_reload_config(true, "es-new", 105))
                        .await
                        .unwrap();
                }
                "redrain" => {
                    apply_ethernet_segment_drain(
                        esi(1),
                        EsDrainReason::Operator,
                        true,
                        &lock,
                        &coordinator,
                        &drain,
                        Some(&control),
                        None,
                    )
                    .await
                    .unwrap();
                }
                "instances" => {
                    let mut instances = EvpnInstanceTable::new();
                    for member in [101, 103, 105] {
                        instances
                            .insert(instance_with_rd(
                                member,
                                if member == 105 { 205 } else { member },
                            ))
                            .unwrap();
                    }
                    assert!(control.replace_instances(Arc::new(instances)));
                }
                _ => unreachable!(),
            }
            held.send(Ok(())).unwrap();
            let RibUpdate::WithdrawEvpn { reply, .. } = actor.rib_rx.recv().await.unwrap() else {
                panic!("both old route classes must settle before a new candidate");
            };
            assert_eq!(actor.bum.borrow().ac_gate(esi(1)).unwrap().interface, "es0");
            reply.send(Ok(())).unwrap();
            if matches!(change, "delete" | "redrain") {
                actor.remote_event(&event);
                let observed = actor.routes_reply().await;
                assert_eq!(actor.injected.len(), injections_before, "{change}");
                if change == "delete" {
                    assert!(!actor.status.borrow().contains_key(&esi(1)));
                } else {
                    assert_eq!(
                        actor.bum.borrow().ac_gate(esi(1)).unwrap().state,
                        AcGateState::Blocked
                    );
                }
                observed.send(Vec::new()).unwrap();
            } else {
                let RibUpdate::InjectEvpn { route, reply } = actor.rib_rx.recv().await.unwrap()
                else {
                    panic!("latest replacement must originate after withdrawal");
                };
                let EvpnRouteKey::Es { esi: id, rd, .. } = route.key() else {
                    panic!("replacement starts with its Type 4 candidate");
                };
                assert_eq!(id, esi(1));
                let expected_rd = match change {
                    "instances" => 205,
                    "replace" => 101,
                    _ => 105,
                };
                assert_eq!(rd, instance_with_rd(105, expected_rd).rd);
                let member = if change == "replace" { 101 } else { 105 };
                actor.assert_segment_role(esi(1), vni(member), DfRole::NonDf);
                assert_eq!(
                    actor.bum.borrow().ac_gate(esi(1)).unwrap().interface,
                    if change == "binding" { "es-new" } else { "es1" }
                );
                actor.injected.push(route.key());
                reply.send(Ok(())).unwrap();
                actor.routes_reply().await.send(Vec::new()).unwrap();
            }
            actor.finish().await;
        }
    }

    #[tokio::test(start_paused = true)]
    #[expect(
        clippy::too_many_lines,
        reason = "two real DF replacements hold the second teardown to verify both owned attachment circuit gates"
    )]
    async fn prepared_replacement_publishes_before_another_withdrawal() {
        use crate::evpn_es_drain::EvpnEsDrainState;
        use crate::evpn_runtime_converger::{EvpnRuntimeActorConverger, EvpnRuntimeReloadApply};

        let baseline = df_wait_reload_config(true, "es0", 101);
        let mut actor = DfWaitActor::new(DfAlgorithm::HighestPreference);
        actor.bindings.send_replace(Arc::new(
            baseline
                .resolve_es_link_bindings(&crate::config::AutoLacpEsis::default())
                .unwrap(),
        ));
        actor.startup().await;
        let control = actor.handle.runtime_control();
        assert!(control.replace_segments(Arc::new(baseline.resolve_ethernet_segments().unwrap())));
        actor.routes_reply().await.send(Vec::new()).unwrap();
        tokio::time::advance(Duration::from_secs(3)).await;
        actor.sync_reply().await.send(true).unwrap();
        actor.routes_reply().await.send(Vec::new()).unwrap();
        let event = type_4_es_route(esi(1), "10.0.0.2", attrs_with_es_import_rt(esi(1)));
        actor.remote_event(&event);
        let before_apply = actor.routes_reply().await;
        for (id, member, interface) in [(1, 101, "es0"), (2, 103, "es2")] {
            actor.assert_segment_role(esi(id), vni(member), DfRole::Df);
            assert!(actor.status.borrow()[&esi(id)].recovery_deadline.is_none());
            assert_eq!(
                actor.bum.borrow().ac_gate(esi(id)).unwrap().interface,
                interface
            );
            assert_eq!(
                actor
                    .injected
                    .iter()
                    .filter(|key| esi_of_key(key) == Some(esi(id)))
                    .count(),
                3
            );
        }
        let injections_before = actor.injected.len();
        let coordinator = Arc::new(std::sync::Mutex::new(
            rustbgpd_evpn::EvpnRuntimeCoordinator::new(
                baseline.resolve_evpn_instances().unwrap(),
                baseline.resolve_evpn_ip_vrfs().unwrap(),
                baseline.resolve_ethernet_segments().unwrap(),
            ),
        ));
        let converger = Arc::new(EvpnRuntimeActorConverger::new(
            actor.rib_tx.clone(),
            Arc::new(tokio::sync::Mutex::new(
                crate::evpn_imet::EvpnImetController::new(),
            )),
            None,
            None,
            None,
            None,
            Some(control),
            EvpnEsDrainState::default(),
        ));
        let apply = EvpnRuntimeReloadApply::new(
            coordinator,
            Arc::new(tokio::sync::Mutex::new(())),
            converger,
            baseline,
        )
        .with_es_link_bindings_publisher(Arc::new(actor.bindings.clone()));
        let mut replacement = df_wait_reload_config(true, "es-a-new", 105);
        replacement.ethernet_segments[1].originator_ip = "10.0.0.3".to_string();
        replacement.ethernet_segments[1].interface = Some("es-b-new".to_string());
        apply.apply_config(&replacement).await.unwrap();
        before_apply.send(Vec::new()).unwrap();

        // A owned all three route classes as a real DF. Acknowledge its entire
        // teardown, then stop on B's first actual withdrawal acknowledgement.
        for _ in 0..3 {
            let RibUpdate::WithdrawEvpn { key, reply } = actor.rib_rx.recv().await.unwrap() else {
                panic!("A must withdraw every old route before any new origination");
            };
            assert_eq!(esi_of_key(&key), Some(esi(1)));
            assert_eq!(actor.bum.borrow().ac_gate(esi(1)).unwrap().interface, "es0");
            reply.send(Ok(())).unwrap();
        }
        let RibUpdate::WithdrawEvpn { key, reply: held_b } = actor.rib_rx.recv().await.unwrap()
        else {
            panic!("B must reach its real teardown before any prepared start");
        };
        assert_eq!(esi_of_key(&key), Some(esi(2)));
        assert_eq!(
            actor
                .bum
                .borrow()
                .get(esi(1), vni(105))
                .expect(
                    "prepared A must publish its latest NonDf member while B withdrawal is held"
                )
                .role,
            DfRole::NonDf
        );
        actor.assert_segment_role(esi(1), vni(105), DfRole::NonDf);
        assert!(actor.bum.borrow().get(esi(1), vni(101)).is_none());
        assert_eq!(
            actor.bum.borrow().ac_gate(esi(1)).unwrap().interface,
            "es-a-new"
        );
        assert!(actor.status.borrow()[&esi(1)].recovery_deadline.is_some());
        actor.assert_segment_role(esi(2), vni(103), DfRole::Df);
        assert_eq!(actor.bum.borrow().ac_gate(esi(2)).unwrap().interface, "es2");
        assert!(actor.status.borrow()[&esi(2)].recovery_deadline.is_none());
        assert_eq!(actor.injected.len(), injections_before);
        held_b.send(Ok(())).unwrap();
        actor.routes_reply().await.send(Vec::new()).unwrap();
        actor.routes_reply().await.send(Vec::new()).unwrap();
        actor.remote_event(&event);
        let settled = actor.routes_reply().await;
        for (id, member, interface) in [(1, 105, "es-a-new"), (2, 103, "es-b-new")] {
            actor.assert_segment_role(esi(id), vni(member), DfRole::NonDf);
            assert_eq!(
                actor.bum.borrow().ac_gate(esi(id)).unwrap().interface,
                interface
            );
            assert!(actor.status.borrow()[&esi(id)].recovery_deadline.is_some());
        }
        assert_eq!(actor.injected.len(), injections_before + 4);
        settled.send(Vec::new()).unwrap();
        actor.finish().await;
    }

    #[tokio::test(start_paused = true)]
    #[expect(
        clippy::too_many_lines,
        reason = "one held origination verifies every queued start against intervening desired-state publications"
    )]
    async fn queued_addition_revalidates_after_another_startup_ack() {
        for change in ["delete", "replace", "redrain", "binding", "instances"] {
            let mut actor = DfWaitActor::new(DfAlgorithm::HighestPreference);
            actor.startup().await;
            let control = actor.handle.runtime_control();
            let mut desired = control.segments_tx.borrow().as_ref().clone();
            for (id, member) in [(2, 103), (3, 105), (4, 101)] {
                let mut added = desired[0].clone();
                added.esi = esi(id);
                added.member_vnis = BTreeSet::from([vni(member)]);
                desired.push(added);
            }
            let mut bindings = actor.bindings.borrow().as_ref().clone();
            let mut fourth_binding = bindings[&esi(3)].clone();
            fourth_binding.interface = "es3".to_string();
            bindings.insert(esi(4), fourth_binding);
            actor.bindings.send_replace(Arc::new(bindings));
            let event = type_4_es_route(esi(1), "10.0.0.2", attrs_with_es_import_rt(esi(1)));
            actor.remote_event(&event);
            let before_apply = actor.routes_reply().await;
            assert!(control.replace_segments(Arc::new(desired.clone())));
            before_apply.send(Vec::new()).unwrap();
            let RibUpdate::InjectEvpn { route, reply: held } = actor.rib_rx.recv().await.unwrap()
            else {
                panic!("first addition must reach its Type 4 acknowledgement");
            };
            assert_eq!(esi_of_key(&route.key()), Some(esi(2)));
            actor.injected.push(route.key());
            for (id, member) in [(2, 103), (3, 105), (4, 101)] {
                actor.assert_segment_role(esi(id), vni(member), DfRole::NonDf);
            }
            match change {
                "delete" => {
                    desired.retain(|segment| segment.esi != esi(3));
                    assert!(control.replace_segments(Arc::new(desired)));
                }
                "replace" => {
                    desired[2].originator_ip = ipa("10.0.0.3");
                    desired[2].member_vnis = BTreeSet::from([vni(103)]);
                    assert!(control.replace_segments(Arc::new(desired)));
                }
                "redrain" => {
                    assert!(control.replace_drained_esis(drained_set(&[esi(3)])));
                }
                "binding" => {
                    let mut bindings = actor.bindings.borrow().as_ref().clone();
                    bindings.get_mut(&esi(3)).unwrap().interface = "es-new".to_string();
                    actor.bindings.send_replace(Arc::new(bindings));
                }
                "instances" => {
                    let mut instances = EvpnInstanceTable::new();
                    for member in [101, 103, 105] {
                        instances
                            .insert(instance_with_rd(
                                member,
                                if member == 105 { 205 } else { member },
                            ))
                            .unwrap();
                    }
                    assert!(control.replace_instances(Arc::new(instances)));
                }
                _ => unreachable!(),
            }
            held.send(Ok(())).unwrap();
            actor.routes_reply().await.send(Vec::new()).unwrap();
            let mut third_starts = 0;
            let held_fourth = loop {
                let RibUpdate::InjectEvpn { route, reply } = actor.rib_rx.recv().await.unwrap()
                else {
                    panic!("each prepared addition must reach its Type 4 acknowledgement");
                };
                let EvpnRouteKey::Es {
                    esi: id,
                    rd: route_rd,
                    originator_ip,
                } = route.key()
                else {
                    panic!("queued addition begins with Type 4");
                };
                actor.injected.push(route.key());
                if id == esi(4) {
                    break reply;
                }
                assert_eq!(id, esi(3));
                assert!(!matches!(change, "delete" | "redrain"), "{change}");
                third_starts += 1;
                assert_eq!(
                    originator_ip,
                    ipa(if change == "replace" {
                        "10.0.0.3"
                    } else {
                        "10.0.0.1"
                    })
                );
                let expected_rd = match change {
                    "instances" => 205,
                    "replace" => 103,
                    _ => 105,
                };
                assert_eq!(route_rd, rd(65000, expected_rd));
                let member = if change == "replace" { 103 } else { 105 };
                actor.assert_segment_role(esi(3), vni(member), DfRole::NonDf);
                reply.send(Ok(())).unwrap();
                actor.routes_reply().await.send(Vec::new()).unwrap();
            };
            // ES4 is actually waiting for its acknowledgement. A replaced ES3
            // must keep complete current BUM intent and its blocked AC gate;
            // neither its pending startup nor ES4's may disappear on retry.
            actor.assert_segment_role(esi(4), vni(101), DfRole::NonDf);
            if change == "delete" {
                assert!(!actor.status.borrow().contains_key(&esi(3)));
                assert!(actor.bum.borrow().ac_gate(esi(3)).is_none());
            } else {
                assert_eq!(
                    actor
                        .bum
                        .borrow()
                        .ac_gate(esi(3))
                        .expect("pending ES3 must keep its blocked AC gate while ES4 acknowledgement is held")
                        .state,
                    AcGateState::Blocked
                );
                if change != "redrain" {
                    let member = if change == "replace" { 103 } else { 105 };
                    actor.assert_segment_role(esi(3), vni(member), DfRole::NonDf);
                    assert_eq!(
                        actor.bum.borrow().ac_gate(esi(3)).unwrap().interface,
                        if change == "binding" { "es-new" } else { "es2" }
                    );
                }
            }
            assert_eq!(
                third_starts,
                usize::from(!matches!(change, "delete" | "redrain"))
            );
            held_fourth.send(Ok(())).unwrap();
            actor.routes_reply().await.send(Vec::new()).unwrap();
            actor.remote_event(&event);
            let observed = actor.routes_reply().await;
            assert_eq!(
                actor
                    .injected
                    .iter()
                    .filter(|key| matches!(key, EvpnRouteKey::Es { esi: id, .. } if *id == esi(3)))
                    .count(),
                third_starts,
                "the latest ES3 starts exactly once"
            );
            observed.send(Vec::new()).unwrap();
            actor.finish().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn queued_administrative_start_survives_member_republication() {
        let mut actor = DfWaitActor::new(DfAlgorithm::HighestPreference);
        actor.startup().await;
        let control = actor.handle.runtime_control();
        let mut desired = control.segments_tx.borrow().as_ref().clone();
        let mut third = desired[0].clone();
        third.esi = esi(3);
        third.member_vnis = BTreeSet::from([vni(105)]);
        desired.push(third);
        assert!(control.replace_segments(Arc::new(desired.clone())));
        actor.routes_reply().await.send(Vec::new()).unwrap();
        let event = type_4_es_route(esi(1), "10.0.0.2", attrs_with_es_import_rt(esi(1)));
        actor.remote_event(&event);
        let before_apply = actor.routes_reply().await;
        let mut second = desired[0].clone();
        second.esi = esi(2);
        second.member_vnis = BTreeSet::from([vni(103)]);
        desired.insert(1, second);
        desired[2].df_preference = 200;
        assert!(control.replace_segments(Arc::new(desired.clone())));
        before_apply.send(Vec::new()).unwrap();
        // Settle ES3's old routes before ES2's first origination. The whole
        // desired snapshot, including ES3's admin override, is now prepared.
        for _ in 0..2 {
            let RibUpdate::WithdrawEvpn { key, reply } = actor.rib_rx.recv().await.unwrap() else {
                panic!("old ES3 routes must settle before the prepared additions");
            };
            assert_eq!(esi_of_key(&key), Some(esi(3)));
            reply.send(Ok(())).unwrap();
        }
        let RibUpdate::InjectEvpn { route, reply: held } = actor.rib_rx.recv().await.unwrap()
        else {
            panic!("ES2 must reach its real Type 4 acknowledgement");
        };
        assert_eq!(esi_of_key(&route.key()), Some(esi(2)));
        actor.injected.push(route.key());
        assert!(actor.status.borrow()[&esi(3)].recovery_deadline.is_none());
        actor.assert_segment_role(esi(3), vni(105), DfRole::NonDf);
        // This later publication changes no DF field. Rebuilding the pending
        // ES3 must preserve its already accepted administrative start.
        desired[2].member_vnis = BTreeSet::from([vni(101)]);
        assert!(control.replace_segments(Arc::new(desired)));
        held.send(Ok(())).unwrap();
        actor.routes_reply().await.send(Vec::new()).unwrap();
        let RibUpdate::InjectEvpn { route, reply } = actor.rib_rx.recv().await.unwrap() else {
            panic!("the latest administrative ES3 must originate");
        };
        assert!(
            matches!(route.key(), EvpnRouteKey::Es { esi: id, rd: route_rd, .. }
            if id == esi(3) && route_rd == rd(65000, 101))
        );
        assert!(actor.status.borrow()[&esi(3)].recovery_deadline.is_none());
        actor.assert_segment_role(esi(3), vni(101), DfRole::NonDf);
        actor.injected.push(route.key());
        reply.send(Ok(())).unwrap();
        actor.routes_reply().await.send(Vec::new()).unwrap();
        actor.remote_event(&event);
        let observed = actor.routes_reply().await;
        actor.assert_segment_role(esi(3), vni(101), DfRole::Df);
        observed.send(Vec::new()).unwrap();
        actor.finish().await;
    }

    #[tokio::test(start_paused = true)]
    #[expect(
        clippy::too_many_lines,
        reason = "one acknowledged withdrawal sequence verifies old and replacement attachment circuit gates"
    )]
    async fn retiring_live_non_df_keeps_old_ac_gate_until_withdrawals_settle() {
        use crate::evpn_es_drain::EvpnEsDrainState;
        use crate::evpn_runtime_converger::{EvpnRuntimeActorConverger, EvpnRuntimeReloadApply};

        for replace in [false, true] {
            let baseline = df_wait_reload_config(true, "es0", 101);
            let mut actor = DfWaitActor::new(DfAlgorithm::HighestPreference);
            actor.bindings.send_replace(Arc::new(
                baseline
                    .resolve_es_link_bindings(&crate::config::AutoLacpEsis::default())
                    .unwrap(),
            ));
            actor.startup().await;
            let control = actor.handle.runtime_control();
            assert!(
                control.replace_segments(Arc::new(baseline.resolve_ethernet_segments().unwrap()))
            );
            actor.routes_reply().await.send(Vec::new()).unwrap();
            let mut attrs = attrs_with_es_import_rt(esi(1));
            attrs.push(PathAttribute::ExtendedCommunities(vec![
                ExtendedCommunity::df_election(
                    DfAlgorithm::HighestPreference.algorithm_id(),
                    0,
                    Some(200),
                ),
            ]));
            let remote = type_4_es_route(esi(1), "10.0.0.2", attrs);
            tokio::time::advance(Duration::from_secs(3)).await;
            actor.sync_reply().await.send(true).unwrap();
            actor
                .routes_reply()
                .await
                .send(vec![remote.clone()])
                .unwrap();
            actor.remote_event(&remote);
            let before_apply = actor.routes_reply().await;
            actor.assert_role(DfRole::NonDf);
            assert!(actor.status.borrow()[&esi(1)].recovery_deadline.is_none());
            assert_eq!(
                actor
                    .injected
                    .iter()
                    .filter(|key| esi_of_key(key) == Some(esi(1)))
                    .count(),
                3,
                "the retiring non-DF owns Type 4 and both EAD route classes"
            );

            let coordinator = Arc::new(std::sync::Mutex::new(
                rustbgpd_evpn::EvpnRuntimeCoordinator::new(
                    baseline.resolve_evpn_instances().unwrap(),
                    baseline.resolve_evpn_ip_vrfs().unwrap(),
                    baseline.resolve_ethernet_segments().unwrap(),
                ),
            ));
            let converger = Arc::new(EvpnRuntimeActorConverger::new(
                actor.rib_tx.clone(),
                Arc::new(tokio::sync::Mutex::new(
                    crate::evpn_imet::EvpnImetController::new(),
                )),
                None,
                None,
                None,
                None,
                Some(control),
                EvpnEsDrainState::default(),
            ));
            let apply = EvpnRuntimeReloadApply::new(
                coordinator,
                Arc::new(tokio::sync::Mutex::new(())),
                converger,
                baseline,
            )
            .with_es_link_bindings_publisher(Arc::new(actor.bindings.clone()));
            apply
                .apply_config(&df_wait_reload_config(replace, "es1", 105))
                .await
                .unwrap();
            before_apply.send(vec![remote]).unwrap();

            // Observe every acknowledgement, including the first and last.
            // The old gate must survive until all three owned classes settle.
            for _ in 0..3 {
                let RibUpdate::WithdrawEvpn { key, reply } = actor.rib_rx.recv().await.unwrap()
                else {
                    panic!("old route classes must withdraw before replacement origination");
                };
                assert_eq!(esi_of_key(&key), Some(esi(1)));
                let table = actor.bum.borrow().clone();
                let gate = table
                    .ac_gate(esi(1))
                    .expect("retiring segment keeps its old AC gate");
                assert_eq!(gate.interface, "es0");
                assert_eq!(gate.state, AcGateState::Blocked);
                assert_eq!(table.get(esi(1), vni(101)).unwrap().role, DfRole::NonDf);
                reply.send(Ok(())).unwrap();
            }
            if replace {
                let RibUpdate::InjectEvpn { route, reply } = actor.rib_rx.recv().await.unwrap()
                else {
                    panic!("replacement may originate after the old withdrawals settle");
                };
                assert!(matches!(route.key(), EvpnRouteKey::Es { esi: id, .. } if id == esi(1)));
                actor.assert_segment_role(esi(1), vni(105), DfRole::NonDf);
                let table = actor.bum.borrow().clone();
                assert_eq!(table.ac_gate(esi(1)).unwrap().interface, "es1");
                assert!(table.ac_gates().all(|gate| gate.interface != "es0"));
                actor.injected.push(route.key());
                reply.send(Ok(())).unwrap();
                actor.routes_reply().await.send(Vec::new()).unwrap();
            } else {
                actor.remote_event(&type_4_es_route(
                    esi(2),
                    "10.0.0.2",
                    attrs_with_es_import_rt(esi(2)),
                ));
                let observed = actor.routes_reply().await;
                assert!(actor.bum.borrow().ac_gate(esi(1)).is_none());
                assert!(!actor.status.borrow().contains_key(&esi(1)));
                observed.send(Vec::new()).unwrap();
            }
            actor.finish().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn recovery_deadline_precedes_queued_evpn_events() {
        for ceiling in [false, true] {
            let mut actor = DfWaitActor::new(DfAlgorithm::DefaultModulo);
            actor.startup().await;
            if ceiling {
                for second in 3..30 {
                    tokio::time::advance(Duration::from_secs(if second == 3 { 3 } else { 1 }))
                        .await;
                    actor.sync_reply().await.send(false).unwrap();
                    actor.status.changed().await.unwrap();
                    actor.status.borrow_and_update();
                    if second % 10 == 0 {
                        // Explicitly acknowledge the periodic sweep as well.
                        actor.routes_reply().await.send(Vec::new()).unwrap();
                    }
                }
                tokio::time::advance(Duration::from_millis(999)).await;
            } else {
                tokio::time::advance(Duration::from_millis(2999)).await;
            }
            let event = type_4_es_route(esi(1), "10.0.0.2", attrs_with_es_import_rt(esi(1)));
            actor.remote_event(&event);
            let held = actor.routes_reply().await;
            // The actor cannot select again until this reply is released.
            // Queue an event and expire recovery while it is held, guaranteeing
            // both branches are ready on the same subsequent select poll.
            actor.remote_event(&event);
            tokio::time::advance(Duration::from_millis(1)).await;
            held.send(Vec::new()).unwrap();
            if !ceiling {
                actor.sync_reply().await.send(true).unwrap();
            }
            actor.routes_reply().await.send(Vec::new()).unwrap();
            let queued = actor.routes_reply().await;
            actor.assert_role(DfRole::Df);
            assert!(actor.status.borrow()[&esi(1)].recovery_deadline.is_none());
            queued.send(Vec::new()).unwrap();
            actor.finish().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn ordinary_df_boot_wait_is_bounded_without_sessions() {
        let mut actor = DfWaitActor::new(DfAlgorithm::DefaultModulo);
        actor.startup().await;
        tokio::time::advance(Duration::from_secs(3)).await;
        actor.sync_reply().await.send(false).unwrap();
        actor.status.changed().await.unwrap();
        actor.status.borrow_and_update();
        // Move directly to the ceiling; missed periodic ticks may query the
        // RIB, but the boot deadline prevents them from electing prematurely.
        tokio::time::advance(Duration::from_secs(27)).await;
        actor.routes_reply().await.send(Vec::new()).unwrap();
        actor.remote_event(&type_4_es_route(
            esi(1),
            "10.0.0.2",
            attrs_with_es_import_rt(esi(1)),
        ));
        let next_event = actor.routes_reply().await;
        assert!(actor.status.borrow()[&esi(1)].recovery_deadline.is_none());
        actor.assert_role(DfRole::Df);
        next_event.send(Vec::new()).unwrap();
        actor.finish().await;
    }

    #[tokio::test(start_paused = true)]
    async fn undrain_reenters_df_wait_after_boot_sync_has_completed() {
        let mut actor = DfWaitActor::new(DfAlgorithm::DefaultModulo);
        actor.startup().await;
        tokio::time::advance(Duration::from_secs(3)).await;
        actor.sync_reply().await.send(true).unwrap();
        actor.routes_reply().await.send(Vec::new()).unwrap();
        let event = type_4_es_route(esi(1), "10.0.0.2", attrs_with_es_import_rt(esi(1)));
        actor.remote_event(&event);
        let barrier = actor.routes_reply().await;
        actor.assert_role(DfRole::Df);
        barrier.send(Vec::new()).unwrap();

        let control = actor.handle.runtime_control();
        assert!(control.replace_drained_esis(drained_set(&[esi(1)])));
        actor.remote_event(&event);
        let drained = actor.routes_reply().await;
        assert_eq!(
            actor.bum.borrow().ac_gate(esi(1)).unwrap().state,
            AcGateState::Blocked
        );
        drained.send(Vec::new()).unwrap();

        assert!(control.replace_drained_esis(drained_set(&[])));
        // Reaching the startup query acknowledges the re-advertised Type 4
        // and EAD-per-ES, while the AC was already published as blocked.
        let startup = actor.routes_reply().await;
        actor.assert_role(DfRole::NonDf);
        assert_eq!(actor.injected.len(), 5);
        startup.send(Vec::new()).unwrap();
        actor.remote_event(&event);
        let barrier = actor.routes_reply().await;
        let deadline = actor.status.borrow()[&esi(1)].recovery_deadline.unwrap();
        assert_eq!(
            deadline - tokio::time::Instant::now(),
            Duration::from_secs(3)
        );
        barrier.send(Vec::new()).unwrap();

        tokio::time::advance(Duration::from_millis(2999)).await;
        actor.remote_event(&event);
        let during_wait = actor.routes_reply().await;
        actor.assert_role(DfRole::NonDf);
        // Hold this candidate reply across the deadline. The actor may
        // complete election from it; no separate timer query is required.
        tokio::time::advance(Duration::from_millis(1)).await;
        during_wait.send(Vec::new()).unwrap();
        // This explicit next-event query proves that reply was consumed.
        actor.remote_event(&event);
        let barrier = actor.routes_reply().await;
        actor.assert_role(DfRole::Df);
        assert!(actor.status.borrow()[&esi(1)].recovery_deadline.is_none());
        barrier.send(Vec::new()).unwrap();
        actor.finish().await;
    }

    /// Full segment actor against a RIB whose EVPN sessions report synced
    /// only when the test says so, or never answer the sync query when
    /// `stall_sync_query` is set. Returns the sync flag, the served Type 4
    /// rows, and every injected route.
    #[expect(
        clippy::type_complexity,
        reason = "test harness returns its three shared probes together"
    )]
    fn boot_recovery_harness(
        stall_sync_query: bool,
    ) -> (
        EvpnSegmentHandle,
        Arc<std::sync::atomic::AtomicBool>,
        Arc<tokio::sync::Mutex<Vec<EvpnRibRoute>>>,
        Arc<tokio::sync::Mutex<Vec<EvpnRibRoute>>>,
    ) {
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(64);
        let synced = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let routes = Arc::new(tokio::sync::Mutex::new(Vec::<EvpnRibRoute>::new()));
        let injected = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let (rib_synced, rib_routes, rib_injected) =
            (synced.clone(), routes.clone(), injected.clone());
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Some(update) = rib_rx.recv().await {
                match update {
                    RibUpdate::QueryEvpnSessionsSynced { reply } if stall_sync_query => {
                        held.push(reply);
                    }
                    RibUpdate::QueryEvpnSessionsSynced { reply } => {
                        let _ = reply.send(rib_synced.load(std::sync::atomic::Ordering::SeqCst));
                    }
                    RibUpdate::QueryEvpnRoutes { reply, .. } => {
                        let _ = reply.send(rib_routes.lock().await.clone());
                    }
                    RibUpdate::InjectEvpn { route, reply } => {
                        rib_injected.lock().await.push(route);
                        let _ = reply.send(Ok(()));
                    }
                    RibUpdate::WithdrawEvpn { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    _ => {}
                }
            }
        });
        let mut table = EvpnInstanceTable::new();
        table.insert(instance(100)).unwrap();
        let mut config = segment(esi(1), &[100]);
        config.df_algorithm = DfAlgorithm::HighestPreference;
        config.df_preference = 65535;
        config.df_dont_preempt = true;
        let handle = spawn(
            &Arc::new(table),
            vec![config],
            rib_tx,
            None,
            BgpMetrics::new(),
            CancellationToken::new(),
        )
        .unwrap();
        (handle, synced, routes, injected)
    }

    async fn advertised_type4_df(
        injected: &tokio::sync::Mutex<Vec<EvpnRibRoute>>,
    ) -> Option<(u32, bool, DfAlgorithm)> {
        injected
            .lock()
            .await
            .iter()
            .rev()
            .find(|r| matches!(r.route, EvpnRoute::Es(_)))
            .and_then(|r| decode_df_election_extcomm(&r.attributes))
    }

    /// RFC 9785 §4.3(5) boot timer: after a restart, the surviving DF's
    /// Type 4 route can arrive later than the fixed recovery window. The
    /// recovering PE must hold its advertisement until the EVPN sessions
    /// report End-of-RIB, then inherit instead of preempting.
    #[tokio::test(start_paused = true)]
    async fn nonrevertive_boot_waits_for_evpn_end_of_rib_before_recovery() {
        let (handle, synced, routes, injected) = boot_recovery_harness(false);
        let df_status = handle.df_status();
        tokio::time::sleep(Duration::from_millis(4500)).await;
        assert_eq!(
            advertised_type4_df(&injected).await,
            None,
            "no Type 4 before the EVPN sessions have synced"
        );
        let pending = df_status.borrow()[&esi(1)];
        assert_eq!(pending.advertised, (65535, true));
        assert!(
            pending
                .recovery_deadline
                .is_some_and(|deadline| deadline > tokio::time::Instant::now()),
            "operator view shows the pending recovery and its deadline"
        );
        let mut attrs = attrs_with_es_import_rt(esi(1));
        attrs.push(PathAttribute::ExtendedCommunities(vec![
            ExtendedCommunity::df_election(
                DfAlgorithm::HighestPreference.algorithm_id(),
                DF_ELECTION_DONT_PREEMPT,
                Some(200),
            ),
        ]));
        routes
            .lock()
            .await
            .push(type_4_es_route(esi(1), "10.0.0.2", attrs));
        synced.store(true, std::sync::atomic::Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(
            advertised_type4_df(&injected).await,
            Some((200, false, DfAlgorithm::HighestPreference)),
            "inherits the surviving DF's preference instead of preempting"
        );
        assert_eq!(
            df_status.borrow()[&esi(1)],
            SegmentDfStatus {
                advertised: (200, false),
                recovery_deadline: None,
            },
            "operator view reports the inherited values, not the configured ones"
        );
        let mut df_status = df_status;
        df_status.mark_unchanged();
        // Periodic re-election sweeps change no DF state.
        tokio::time::sleep(Duration::from_secs(25)).await;
        assert!(
            !df_status.has_changed().unwrap(),
            "steps that change no DF state do not republish"
        );
        handle.shutdown().await;
    }

    /// A RIB that never answers the sync query cannot hold the actor past
    /// the boot ceiling.
    #[tokio::test(start_paused = true)]
    async fn nonrevertive_boot_wait_is_bounded_with_stalled_rib_query() {
        let (handle, _synced, _routes, injected) = boot_recovery_harness(true);
        tokio::time::sleep(Duration::from_millis(30_500)).await;
        assert_eq!(
            advertised_type4_df(&injected).await,
            Some((65535, true, DfAlgorithm::HighestPreference))
        );
        handle.shutdown().await;
    }

    /// The boot wait is bounded: a PE whose EVPN sessions never sync still
    /// advertises its administrative values once the ceiling passes.
    #[tokio::test(start_paused = true)]
    async fn nonrevertive_boot_wait_is_bounded_without_evpn_sessions() {
        let (handle, _synced, _routes, injected) = boot_recovery_harness(false);
        tokio::time::sleep(Duration::from_millis(29_500)).await;
        assert_eq!(advertised_type4_df(&injected).await, None);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(
            advertised_type4_df(&injected).await,
            Some((65535, true, DfAlgorithm::HighestPreference))
        );
        handle.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    #[expect(
        clippy::too_many_lines,
        reason = "one controlled-time recovery lifecycle verifies wire advertisements and forwarding transitions together"
    )]
    async fn nonrevertive_recovery_updates_wire_and_single_active_gate() {
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(64);
        let injected = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let captured = injected.clone();
        let recorder = tokio::spawn(async move {
            while let Some(update) = rib_rx.recv().await {
                match update {
                    RibUpdate::InjectEvpn { route, reply } => {
                        captured.lock().await.push(route);
                        let _ = reply.send(Ok(()));
                    }
                    RibUpdate::WithdrawEvpn { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    RibUpdate::QueryEvpnRoutes { reply, .. } => {
                        let _ = reply.send(vec![]);
                    }
                    _ => {}
                }
            }
        });
        let mut instances = EvpnInstanceTable::new();
        instances.insert(instance(100)).unwrap();
        let mut runtime = SegmentRuntime {
            watches: None,
            instances: Arc::new(instances),
            rib_tx,
            bum_enforcement_tx: None,
            same_esi_bias_tx: None,
            metrics: BgpMetrics::new(),
            shutdown: CancellationToken::new(),
            drained_esis: Arc::new(BTreeSet::new()),
            es_link_bindings: EsLinkBindings::default(),
            boot_until: None,
        };
        for (algorithm, admin) in [
            (DfAlgorithm::HighestPreference, 65535),
            (DfAlgorithm::LowestPreference, 0),
        ] {
            let mut state = segment_state(esi(1));
            state.config.df_algorithm = algorithm;
            state.config.df_preference = admin;
            state.config.df_dont_preempt = true;
            state.config.redundancy_mode = RedundancyMode::SingleActive;
            let mut pending = PendingRibOps::new();
            let mut attrs = attrs_with_es_import_rt(state.config.esi);
            attrs.push(PathAttribute::ExtendedCommunities(vec![
                ExtendedCommunity::df_election(
                    algorithm.algorithm_id(),
                    DF_ELECTION_DONT_PREEMPT,
                    Some(200),
                ),
            ]));
            let remote = type_4_es_route(state.config.esi, "10.0.0.2", attrs);
            injected.lock().await.clear();
            prepare_segment_startup(&runtime, &mut state, true);
            startup_segment_state(&runtime, &mut state, &mut pending).await;
            assert_eq!(
                ac_gate_state_for_es(
                    state.config.redundancy_mode,
                    false,
                    &state.config.member_vnis,
                    &state.last_roles
                ),
                Some(AcGateState::Blocked)
            );
            tokio::time::advance(Duration::from_millis(2999)).await;
            run_election_for_routes(
                &runtime,
                &mut state,
                std::slice::from_ref(&remote),
                &mut pending,
            )
            .await;
            assert!(
                injected.lock().await.is_empty(),
                "no Type 4 before recovery deadline"
            );
            tokio::time::advance(Duration::from_millis(1)).await;
            run_election_for_routes(
                &runtime,
                &mut state,
                std::slice::from_ref(&remote),
                &mut pending,
            )
            .await;
            assert_eq!(state.operational_df, (200, false));
            assert_eq!(
                state.last_roles[&vni(100)],
                DfRole::NonDf,
                "lower local IP must not preempt protected incumbent"
            );
            assert_eq!(
                ac_gate_state_for_es(
                    state.config.redundancy_mode,
                    false,
                    &state.config.member_vnis,
                    &state.last_roles
                ),
                Some(AcGateState::Blocked)
            );
            let routes = injected.lock().await;
            let type4 = routes
                .iter()
                .find(|r| matches!(r.route, EvpnRoute::Es(_)))
                .unwrap();
            assert_eq!(
                decode_df_election_extcomm(&type4.attributes),
                Some((200, false, algorithm))
            );
            assert_eq!(routes.len(), 3, "Type 4 and both EAD classes advertised");
            drop(routes);
            // An owner change at equal preference remains protected even though
            // our address wins the final IP tie-break against either owner.
            let mut replacement = remote.clone();
            if let EvpnRoute::Es(es) = &mut replacement.route {
                es.originator_ip = ipa("10.0.0.3");
            }
            run_election_for_routes(&runtime, &mut state, &[replacement], &mut pending).await;
            assert_eq!(state.last_roles[&vni(100)], DfRole::NonDf);
            // Withdrawal of the reference promotes us and restores admin on wire.
            run_election_for_routes(&runtime, &mut state, &[], &mut pending).await;
            assert_eq!(state.operational_df, (admin, true));
            assert_eq!(state.last_roles[&vni(100)], DfRole::Df);
            assert_eq!(
                ac_gate_state_for_es(
                    state.config.redundancy_mode,
                    false,
                    &state.config.member_vnis,
                    &state.last_roles
                ),
                Some(AcGateState::Forwarding)
            );
            let routes = injected.lock().await;
            let type4 = routes
                .iter()
                .rev()
                .find(|r| matches!(r.route, EvpnRoute::Es(_)))
                .unwrap();
            assert_eq!(
                decode_df_election_extcomm(&type4.attributes),
                Some((admin, true, algorithm))
            );
            drop(routes);
            // Drain/rejoin loses local history and derives non-preemption anew.
            drain_segment_state(&runtime, &mut state, &mut pending).await;
            prepare_segment_startup(&runtime, &mut state, true);
            startup_segment_state(&runtime, &mut state, &mut pending).await;
            tokio::time::advance(Duration::from_secs(3)).await;
            run_election_for_routes(&runtime, &mut state, &[remote], &mut pending).await;
            assert_eq!(state.operational_df, (200, false));
            assert_eq!(state.last_roles[&vni(100)], DfRole::NonDf);
            drain_segment_state(&runtime, &mut state, &mut pending).await;
            // The runtime configuration path overrides inherited preference.
            let id = state.config.esi;
            let mut replacement = state.config.clone();
            replacement.df_preference = if admin == 0 { 1 } else { admin - 1 };
            let expected = replacement.df_preference;
            let mut states = HashMap::from([(id, state)]);
            let instances = runtime.instances.clone();
            apply_test_runtime_snapshot(
                &mut runtime,
                &mut states,
                &mut rustbgpd_evpn::EsiLabelAllocator::new(),
                instances,
                vec![replacement],
                &mut pending,
            )
            .await;
            assert!(states[&id].recovery_deadline.is_none());
            assert_eq!(states[&id].operational_df, (expected, true));
            drain(&runtime, &mut states, &mut pending).await;
        }
        drop(runtime);
        recorder.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn es_dropped_replies_keep_type_1_4_ops_pending_and_retry_confirms() {
        let rib = ScriptedRib::spawn(RibReplyMode::DropReply);
        let runtime = scripted_runtime(&rib);
        let mut pending = crate::evpn_ack::PendingRibOps::new();
        let mut state = segment_state(esi(1));

        // Startup publishes Type 4 ES + Type 1 EAD-per-ES, then the
        // self-only election emits Type 1 EAD-per-EVI for the member
        // VNI — all three replies are dropped.
        prepare_segment_startup(&runtime, &mut state, false);
        startup_segment_state(&runtime, &mut state, &mut pending).await;

        assert_eq!(rib.inject_count(), 3, "ES + EAD-per-ES + EAD-per-EVI sent");
        assert_eq!(
            pending.len(),
            3,
            "unacknowledged Type 1/4 injects stay pending"
        );

        // The retry re-drives all three from the current model and the
        // acks clear the tracker.
        rib.set_mode(RibReplyMode::Ok);
        tokio::time::advance(Duration::from_secs(35)).await;
        let mut by_esi = HashMap::new();
        by_esi.insert(state.config.esi, state);
        retry_pending_rib_ops(&runtime, &by_esi, &mut pending).await;

        assert_eq!(rib.inject_count(), 6, "all three injects retried");
        assert!(pending.is_empty(), "acks confirmed every pending op");
    }

    #[tokio::test(start_paused = true)]
    async fn es_withdrawals_survive_dropped_replies_even_after_segment_removal() {
        let rib = ScriptedRib::spawn(RibReplyMode::Ok);
        let runtime = scripted_runtime(&rib);
        let mut pending = crate::evpn_ack::PendingRibOps::new();
        let mut state = segment_state(esi(1));

        prepare_segment_startup(&runtime, &mut state, false);
        startup_segment_state(&runtime, &mut state, &mut pending).await;
        assert!(pending.is_empty(), "startup acked cleanly");

        // Teardown withdraws lose their replies...
        rib.set_mode(RibReplyMode::DropReply);
        drain_segment_state(&runtime, &mut state, &mut pending).await;
        assert_eq!(rib.withdraw_count(), 3, "three withdraw attempts sent");
        assert_eq!(
            pending.len(),
            3,
            "unacknowledged withdrawals must not be forgotten"
        );

        // ...and the segment is gone entirely by the time the retry
        // fires. Withdraws need only their key, so they still complete
        // against an empty segment map.
        rib.set_mode(RibReplyMode::Ok);
        tokio::time::advance(Duration::from_secs(35)).await;
        let by_esi = HashMap::new();
        retry_pending_rib_ops(&runtime, &by_esi, &mut pending).await;

        assert_eq!(rib.withdraw_count(), 6, "withdrawals retried to completion");
        assert!(pending.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn es_retry_drops_pending_inject_when_segment_left_the_model() {
        let rib = ScriptedRib::spawn(RibReplyMode::DropReply);
        let runtime = scripted_runtime(&rib);
        let mut pending = crate::evpn_ack::PendingRibOps::new();
        let mut state = segment_state(esi(1));

        prepare_segment_startup(&runtime, &mut state, false);
        startup_segment_state(&runtime, &mut state, &mut pending).await;
        assert_eq!(pending.len(), 3);

        // The segment is removed before the retry fires: pending
        // injects can no longer be rebuilt and are dropped (segment
        // teardown already drains routes through the state machines).
        rib.set_mode(RibReplyMode::Ok);
        tokio::time::advance(Duration::from_secs(35)).await;
        let by_esi = HashMap::new();
        retry_pending_rib_ops(&runtime, &by_esi, &mut pending).await;

        assert!(pending.is_empty(), "stale injects dropped");
        assert_eq!(rib.inject_count(), 3, "no re-inject under stale fields");
    }
}
