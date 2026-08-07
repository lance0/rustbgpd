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

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustbgpd_evpn::{
    AcGateState, BumEnforcementTable, DfAlgorithm, DfCandidate, DfElection, DfRole,
    EthernetSegment, EvpnInstance, EvpnInstanceId, EvpnInstanceTable, LocalEadPerEsOriginator,
    LocalEadPerEviOriginator, LocalEsOriginator, OriginationAction, RedundancyMode,
    SameEsiBiasTable,
};
use rustbgpd_rib::{EvpnRouteEvent, RibUpdate, route::EvpnRibRoute};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{
    AsPath, EthernetSegmentIdentifier, EvpnEadPerEs, EvpnEadPerEvi, EvpnEs, EvpnRoute,
    EvpnRouteKey, MplsLabel, Origin, PathAttribute,
};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::evpn_ack::{PendingRibOps, RibAckOutcome, send_and_ack};
use crate::evpn_es_link_drain::EsLinkBindings;
use crate::evpn_originator::{LOCAL_PEER, route_target_to_extcomm};

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
}

impl EvpnSegmentRuntimeControl {
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
            },
            drained_rx,
            _instances_rx: instances_rx,
            _segments_rx: segments_rx,
        }
    }
}

/// Handle returned to the daemon for shutdown coordination.
#[derive(Debug)]
pub struct EvpnSegmentHandle {
    pub(crate) shutdown: CancellationToken,
    pub(crate) join: tokio::task::JoinHandle<()>,
    instances_tx: watch::Sender<Arc<EvpnInstanceTable>>,
    segments_tx: watch::Sender<Arc<Vec<EthernetSegment>>>,
    drained_esis_tx: watch::Sender<Arc<BTreeSet<EthernetSegmentIdentifier>>>,
}

impl EvpnSegmentHandle {
    /// Cloneable ADR-0063 runtime control surface for future daemon
    /// apply wiring.
    pub(crate) fn runtime_control(&self) -> EvpnSegmentRuntimeControl {
        EvpnSegmentRuntimeControl {
            instances_tx: self.instances_tx.clone(),
            segments_tx: self.segments_tx.clone(),
            drained_esis_tx: self.drained_esis_tx.clone(),
        }
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
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "daemon wiring spawns via spawn_with_local_bias since ADR-0085 decision 5; this bias-less shape is kept for the actor lifecycle tests"
    )
)]
pub fn spawn(
    instances: &Arc<EvpnInstanceTable>,
    segments: Vec<EthernetSegment>,
    rib_tx: mpsc::Sender<RibUpdate>,
    bum_enforcement_tx: Option<watch::Sender<Arc<BumEnforcementTable>>>,
    metrics: BgpMetrics,
    daemon_shutdown: CancellationToken,
) -> Option<EvpnSegmentHandle> {
    spawn_with_local_bias(
        instances,
        segments,
        rib_tx,
        bum_enforcement_tx,
        None,
        None,
        metrics,
        daemon_shutdown,
    )
}

/// [`spawn`] plus the ADR-0085 decision 5 inputs: the same-ESI
/// bias-eligibility publisher (toward the dataplane supervisor,
/// alongside the BUM-enforcement flow) and the resolved
/// `[[ethernet_segments]]` interface-binding watch (the "locally
/// attached" half of the eligibility condition). Either may be absent
/// — no dataplane / no binding feed — in which case no bias snapshot
/// is published / no segment counts as bound.
#[must_use = "drop the handle to shut down the EVPN segment orchestrator"]
#[allow(
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
) -> Option<EvpnSegmentHandle> {
    if segments.is_empty() {
        info!("no [[ethernet_segments]] configured — EVPN segment orchestrator not spawned");
        return None;
    }
    let (segments_tx, segments_rx) = watch::channel(Arc::new(segments));
    let (instances_tx, instances_rx) = watch::channel(instances.clone());
    // Drain state is runtime-only and in-memory (ADR-0084): the set
    // always starts empty, so a daemon restart clears any drain and
    // replays configured state.
    let (drained_esis_tx, drained_esis_rx) = watch::channel(Arc::new(BTreeSet::new()));
    let runtime = SegmentRuntime {
        instances: instances.clone(),
        rib_tx,
        bum_enforcement_tx,
        same_esi_bias_tx,
        metrics,
        shutdown: daemon_shutdown.clone(),
        drained_esis: Arc::new(BTreeSet::new()),
        es_link_bindings: EsLinkBindings::default(),
    };
    let join = tokio::spawn(segment_loop(
        runtime,
        instances_rx,
        segments_rx,
        drained_esis_rx,
        es_link_bindings_rx,
    ));
    Some(EvpnSegmentHandle {
        shutdown: daemon_shutdown,
        join,
        instances_tx,
        segments_tx,
        drained_esis_tx,
    })
}

struct SegmentRuntime {
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
}

/// Per-ESI runtime state.
struct SegmentState {
    config: EthernetSegment,
    es_origin: LocalEsOriginator,
    ead_per_es: LocalEadPerEsOriginator,
    ead_per_evi: LocalEadPerEviOriginator,
    election: DfElection,
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

#[allow(
    clippy::too_many_lines,
    reason = "setup and the select loop form one ordered segment lifecycle"
)]
async fn segment_loop(
    mut runtime: SegmentRuntime,
    mut instances_rx: watch::Receiver<Arc<EvpnInstanceTable>>,
    mut segments_rx: watch::Receiver<Arc<Vec<EthernetSegment>>>,
    mut drained_esis_rx: watch::Receiver<Arc<BTreeSet<EthernetSegmentIdentifier>>>,
    mut es_link_bindings_rx: Option<watch::Receiver<EsLinkBindings>>,
) {
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
                    // A coordinator may publish an instance snapshot immediately
                    // before the segment snapshot that depends on it. Watch
                    // receivers expose the latest value even if their own
                    // `changed()` branch has not run yet, so refresh here before
                    // rebuilding ES state.
                    apply_runtime_instance_snapshot(&mut runtime, instances_rx.borrow().clone());
                    let segments = segments_rx.borrow_and_update().as_ref().clone();
                    apply_runtime_segment_snapshot(
                        &runtime,
                        &mut by_esi,
                        &mut esi_label_allocator,
                        segments,
                        &mut pending_rib_ops,
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
                    let instances = instances_rx.borrow_and_update().clone();
                    if segment_member_instances_changed(
                        runtime.instances.as_ref(),
                        instances.as_ref(),
                        &by_esi,
                    ) {
                        let segments = segments_rx.borrow().as_ref().clone();
                        drain(&runtime, &mut by_esi, &mut pending_rib_ops).await;
                        apply_runtime_instance_snapshot(&mut runtime, instances);
                        rebuild_segment_states(
                            &runtime,
                            &mut by_esi,
                            &mut esi_label_allocator,
                            segments,
                        );
                        initial_startup(&runtime, &mut by_esi, &mut pending_rib_ops).await;
                        publish_dataplane_snapshots(&runtime, &by_esi);
                    } else {
                        apply_runtime_instance_snapshot(&mut runtime, instances);
                    }
                } else {
                    debug!("EVPN segment: runtime instance watch closed; draining");
                    drain(&runtime, &mut by_esi, &mut pending_rib_ops).await;
                    publish_empty_dataplane_snapshots(&runtime);
                    return;
                }
            },
            changed = drained_esis_rx.changed() => {
                if let Ok(()) = changed {
                    let drained = drained_esis_rx.borrow_and_update().clone();
                    apply_drained_esi_snapshot(&mut runtime, &mut by_esi, drained, &mut pending_rib_ops).await;
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
                        runtime.es_link_bindings = rx.borrow_and_update().clone();
                    }
                    // Bindings shape both snapshots: bias eligibility
                    // (bound-ness) and the AC-gate rows riding the
                    // BUM-enforcement table (the bound link name is
                    // the gate's port handle).
                    publish_dataplane_snapshots(&runtime, &by_esi);
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
    }
}

fn apply_runtime_instance_snapshot(
    runtime: &mut SegmentRuntime,
    instances: Arc<EvpnInstanceTable>,
) {
    // Assign unconditionally: the snapshot arrives as an `Arc` from a
    // watch channel and is only republished on a runtime mutation, so a
    // deep `EvpnInstanceTable` comparison costs more than the Arc move
    // it would guard.
    runtime.instances = instances;
}

fn segment_member_instances_changed(
    old: &EvpnInstanceTable,
    new: &EvpnInstanceTable,
    by_esi: &HashMap<EthernetSegmentIdentifier, SegmentState>,
) -> bool {
    by_esi.values().any(|state| {
        state
            .config
            .member_vnis
            .iter()
            .any(|&vni| old.get(vni) != new.get(vni))
    })
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
            esi = ?seg.esi.octets(),
            "ethernet_segments entry has no member_vnis — skipping"
        );
        return None;
    };
    let Some(inst) = runtime.instances.get(reference_vni) else {
        warn!(
            esi = ?seg.esi.octets(),
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
                esi = ?seg.esi.octets(),
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
                esi = ?seg.esi.octets(),
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

async fn apply_runtime_segment_snapshot(
    runtime: &SegmentRuntime,
    by_esi: &mut HashMap<EthernetSegmentIdentifier, SegmentState>,
    esi_label_allocator: &mut rustbgpd_evpn::EsiLabelAllocator,
    segments: Vec<EthernetSegment>,
    pending: &mut PendingRibOps,
) {
    let changed = segments.len() != by_esi.len()
        || segments.iter().any(|seg| {
            by_esi
                .get(&seg.esi)
                .is_none_or(|state| state.config != *seg)
        });
    if !changed {
        return;
    }

    drain(runtime, by_esi, pending).await;
    rebuild_segment_states(runtime, by_esi, esi_label_allocator, segments);
    initial_startup(runtime, by_esi, pending).await;
    publish_dataplane_snapshots(runtime, by_esi);
}

async fn subscribe_evpn_events(
    rib_tx: &mpsc::Sender<RibUpdate>,
) -> Option<broadcast::Receiver<EvpnRouteEvent>> {
    let (reply_tx, reply_rx) = oneshot::channel();
    rib_tx
        .send(RibUpdate::SubscribeEvpnRouteEvents { reply: reply_tx })
        .await
        .ok()?;
    reply_rx.await.ok()
}

async fn recv_evpn_event(
    rx: &mut Option<broadcast::Receiver<EvpnRouteEvent>>,
) -> Result<EvpnRouteEvent, broadcast::error::RecvError> {
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

/// Originate one ES's Type 4 + EAD-per-ES and run its DF election.
/// Shared by startup and by an ADR-0084 undrain, which mirrors what
/// segment-set application does for a new ES.
async fn startup_segment_state(
    runtime: &SegmentRuntime,
    state: &mut SegmentState,
    pending: &mut PendingRibOps,
) {
    // Type 4 ES first so peers see us as a candidate before any
    // EAD routes show up.
    let actions = state.es_origin.on_startup();
    apply(runtime, state, actions, pending).await;

    let actions = state.ead_per_es.on_startup();
    apply(runtime, state, actions, pending).await;

    // Initial election with self as sole candidate. Local PE is
    // DF for all member VNIs.
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

/// Apply an ADR-0084 drained-ESI snapshot: withdraw routes for
/// newly-drained ESIs, re-originate + re-elect newly-undrained ones,
/// and republish the BUM enforcement snapshot when anything moved.
/// ESIs not in the current segment config are ignored — the
/// coordinator GCs their drain entries on segment-set replace.
async fn apply_drained_esi_snapshot(
    runtime: &mut SegmentRuntime,
    by_esi: &mut HashMap<EthernetSegmentIdentifier, SegmentState>,
    drained: Arc<BTreeSet<EthernetSegmentIdentifier>>,
    pending: &mut PendingRibOps,
) {
    let prior = std::mem::replace(&mut runtime.drained_esis, drained.clone());
    if *prior == *drained {
        return;
    }
    let mut changed = false;
    for esi in drained.iter().filter(|esi| !prior.contains(*esi)) {
        let Some(state) = by_esi.get_mut(esi) else {
            continue;
        };
        info!(esi = %format_esi(*esi), "EVPN segment: draining Ethernet Segment (operator)");
        drain_segment_state(runtime, state, pending).await;
        changed = true;
    }
    for esi in prior.iter().filter(|esi| !drained.contains(*esi)) {
        let Some(state) = by_esi.get_mut(esi) else {
            continue;
        };
        info!(esi = %format_esi(*esi), "EVPN segment: undraining Ethernet Segment (operator)");
        startup_segment_state(runtime, state, pending).await;
        changed = true;
    }
    if changed {
        publish_dataplane_snapshots(runtime, by_esi);
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
    let routes = match query_evpn_routes(&runtime.rib_tx).await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "EVPN segment: sweep candidate gather failed");
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
            warn!(esi = ?state.config.esi.octets(), error = %e, "EVPN segment: candidate gather failed");
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
    candidates: Vec<DfCandidate>,
    pending: &mut PendingRibOps,
) {
    // ADR-0084: a drained ES has withdrawn its Type 4 and exited DF
    // election; role transitions must not re-emit EAD-per-EVI routes
    // for it (sweeps and remote Type 4 events keep firing while
    // drained).
    if runtime.drained_esis.contains(&state.config.esi) {
        return;
    }
    let new_roles = match state.election.run(&candidates, state.config.originator_ip) {
        Ok(r) => r,
        Err(e) => {
            warn!(
                esi = ?state.config.esi.octets(),
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
        if prior != Some(role) {
            transitions.push((vni, role));
        }
    }

    for (vni, role) in transitions {
        let actions = state.ead_per_evi.on_vni_role_changed(vni, role);
        // Update telemetry first so it reflects the wire-side state
        // we're about to commit.
        runtime
            .metrics
            .set_evpn_df_role(esi_str.as_str(), vni.as_u32(), role.is_df());
        if state.last_roles.contains_key(&vni) {
            runtime
                .metrics
                .record_evpn_df_role_change(esi_str.as_str(), vni.as_u32());
        }
        state.last_roles.insert(vni, role);
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
            state.config.df_preference,
            state.config.df_dont_preempt,
            state.config.redundancy_mode,
            actions,
            pending,
        )
        .await;
        debug!(
            esi = esi_str.as_str(),
            vni = vni.as_u32(),
            role = role.as_str(),
            "EVPN segment: DF role updated"
        );
    }
}

/// Publish both dataplane-supervisor snapshots the segment actor
/// owns: the Gate 8b BUM-enforcement table and the ADR-0085 same-ESI
/// bias-eligibility table. Both derive from the same per-ES role
/// state, so every event that republishes one republishes the other.
fn publish_dataplane_snapshots(
    runtime: &SegmentRuntime,
    by_esi: &HashMap<EthernetSegmentIdentifier, SegmentState>,
) {
    publish_bum_enforcement_snapshot(runtime, by_esi);
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
    let table = build_same_esi_bias_table_from_roles(
        &bound_esis,
        &runtime.drained_esis,
        by_esi.iter().flat_map(|(&esi, state)| {
            state
                .last_roles
                .iter()
                .map(move |(&vni, &role)| (esi, state.config.redundancy_mode, vni, role))
        }),
    );
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
    let routes = query_evpn_routes(rib_tx).await?;
    Ok(gather_candidates_from_routes(state, &routes))
}

fn gather_candidates_from_routes(
    state: &SegmentState,
    routes: &[EvpnRibRoute],
) -> Vec<DfCandidate> {
    let mut by_ip: BTreeMap<IpAddr, DfCandidate> = BTreeMap::new();
    // Local PE always present.
    by_ip.insert(
        state.config.originator_ip,
        DfCandidate {
            originator_ip: state.config.originator_ip,
            df_preference: state.config.df_preference,
            df_dont_preempt: state.config.df_dont_preempt,
            df_algorithm: state.config.df_algorithm,
        },
    );
    for r in routes {
        let EvpnRoute::Es(es) = &r.route else {
            continue;
        };
        if es.esi != state.config.esi {
            continue;
        }
        if !has_matching_es_import_rt(&r.attributes, state.config.esi) {
            debug!(
                esi = %format_esi(state.config.esi),
                originator_ip = %es.originator_ip,
                "EVPN segment: ignoring Type 4 ES route without matching ES-Import RT"
            );
            continue;
        }
        // Per-PE candidate. df_algorithm decodes from the route's DF
        // Election extcomm if present; absent extcomm → DefaultModulo
        // + default preference (matches RFC 8584 fallback rules).
        let (pref, dont_preempt, alg) = decode_df_election_extcomm(&r.attributes).unwrap_or((
            32_768,
            false,
            DfAlgorithm::DefaultModulo,
        ));
        by_ip.entry(es.originator_ip).or_insert(DfCandidate {
            originator_ip: es.originator_ip,
            df_preference: pref,
            df_dont_preempt: dont_preempt,
            df_algorithm: alg,
        });
    }
    by_ip.into_values().collect()
}

fn has_matching_es_import_rt(attrs: &[PathAttribute], esi: EthernetSegmentIdentifier) -> bool {
    let expected = es_import_rt_from_esi(esi);
    attrs.iter().any(|attr| {
        let PathAttribute::ExtendedCommunities(extcomms) = attr else {
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
        let PathAttribute::ExtendedCommunities(ecs) = attr else {
            continue;
        };
        for ec in ecs {
            if let Some(df) = ec.as_df_election() {
                let alg = DfAlgorithm::from_algorithm_id(df.algorithm_id);
                let pref = df.preference.map_or(32_768, u32::from);
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

async fn query_evpn_routes(
    rib_tx: &mpsc::Sender<RibUpdate>,
) -> Result<Vec<EvpnRibRoute>, RibQueryError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    rib_tx
        .send(RibUpdate::QueryEvpnRoutes { reply: reply_tx })
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
        state.config.df_preference,
        state.config.df_dont_preempt,
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
                        df_preference: state.config.df_preference,
                        df_dont_preempt: state.config.df_dont_preempt,
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
/// Path attributes: Origin, empty `AsPath`, `NextHop`, plus the
/// instance's configured RT extcomms. Per RFC 7432, Gate 8b prep
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

    let mut ext_communities: Vec<rustbgpd_wire::ExtendedCommunity> = instance
        .route_targets
        .iter()
        .copied()
        .map(route_target_to_extcomm)
        .collect();
    ext_communities.extend(key_specific_extcomms);

    let attributes: Vec<PathAttribute> = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        next_hop_path_attribute(instance.local_vtep_ip),
        PathAttribute::ExtendedCommunities(ext_communities),
    ];

    Some(EvpnRibRoute {
        route,
        next_hop: instance.local_vtep_ip,
        link_local_next_hop: None,
        peer: LOCAL_PEER,
        attributes: Arc::new(attributes),
        received_at: Instant::now(),
        origin_type: rustbgpd_rib::route::RouteOrigin::Local,
        peer_router_id: std::net::Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
    })
}

fn next_hop_path_attribute(vtep_ip: IpAddr) -> PathAttribute {
    match vtep_ip {
        IpAddr::V4(v4) => PathAttribute::NextHop(v4),
        IpAddr::V6(_) => PathAttribute::NextHop(std::net::Ipv4Addr::UNSPECIFIED),
    }
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
    use super::*;
    use rustbgpd_evpn::{EvpnInstance, EvpnInstanceTable};
    use rustbgpd_wire::{EthernetTagId, ExtendedCommunity};

    use crate::test_support::{RibReplyMode, ScriptedRib, evpn_instance, ip as ipa, rd, vni};

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
            attributes: Arc::new(attrs),
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
                    RibUpdate::QueryEvpnRoutes { reply } => {
                        let _ = reply.send(Vec::new());
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
        // Must carry: Origin, AsPath, NextHop, ExtendedCommunities.
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
            route
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

    #[test]
    fn decode_df_election_extcomm_reads_five_bit_algorithm() {
        let ec = ExtendedCommunity::df_election(1, 0, None);
        let attrs = [PathAttribute::ExtendedCommunities(vec![ec])];
        let (pref, dont_preempt, alg) = decode_df_election_extcomm(&attrs).unwrap();
        assert_eq!(pref, 32_768);
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

    #[tokio::test]
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

    #[tokio::test]
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

    #[tokio::test]
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

    #[tokio::test]
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
            instances,
            rib_tx,
            bum_enforcement_tx: None,
            same_esi_bias_tx: None,
            metrics: BgpMetrics::new(),
            shutdown: CancellationToken::new(),
            drained_esis: Arc::new(BTreeSet::new()),
            es_link_bindings: EsLinkBindings::default(),
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
            instances,
            rib_tx,
            bum_enforcement_tx: None,
            same_esi_bias_tx: None,
            metrics: BgpMetrics::new(),
            shutdown: CancellationToken::new(),
            drained_esis: Arc::new(BTreeSet::new()),
            es_link_bindings: EsLinkBindings::default(),
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
            instances,
            rib_tx,
            bum_enforcement_tx: None,
            same_esi_bias_tx: None,
            metrics: BgpMetrics::new(),
            shutdown: CancellationToken::new(),
            drained_esis: Arc::new(BTreeSet::new()),
            es_link_bindings: EsLinkBindings::default(),
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

    #[tokio::test]
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

    #[tokio::test]
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

    #[tokio::test]
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

    #[tokio::test]
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
    #[tokio::test]
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
        events_tx: broadcast::Sender<EvpnRouteEvent>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            while let Some(update) = rib_rx.recv().await {
                match update {
                    RibUpdate::SubscribeEvpnRouteEvents { reply } => {
                        let _ = reply.send(events_tx.subscribe());
                    }
                    RibUpdate::QueryEvpnRoutes { reply } => {
                        let _ = reply.send(routes.lock().await.clone());
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
    #[tokio::test]
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
        )
        .expect("non-empty ES config should spawn segment actor");

        // Startup: sole candidate → DF everywhere → bias-eligible and
        // the AC gate forwarding.
        wait_for_dataplane_state(&bias_rx, &bum_rx, "startup DF snapshots", |bias, bum| {
            bias.is_eligible(id, vni(101))
                && bum.ac_gate(id).map(|entry| entry.state) == Some(AcGateState::Forwarding)
        })
        .await;

        // The remote PE's Type 4 lands: it wins the modulo election
        // for VNI 101, demoting this PE to non-DF.
        let remote_type4 = type_4_es_route(id, "10.0.0.2", attrs_with_es_import_rt(id));
        routes.lock().await.push(remote_type4.clone());
        events_tx
            .send(EvpnRouteEvent {
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
            })
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
            instances: Arc::new(table),
            rib_tx: rib.rib_tx.clone(),
            bum_enforcement_tx: None,
            same_esi_bias_tx: None,
            metrics: BgpMetrics::new(),
            shutdown: CancellationToken::new(),
            drained_esis: Arc::new(BTreeSet::new()),
            es_link_bindings: EsLinkBindings::default(),
        }
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
