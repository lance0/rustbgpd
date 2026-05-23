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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustbgpd_evpn::{
    BumEnforcementTable, DfAlgorithm, DfCandidate, DfElection, DfRole, EthernetSegment,
    EvpnInstance, EvpnInstanceId, EvpnInstanceTable, LocalEadPerEsOriginator,
    LocalEadPerEviOriginator, LocalEsOriginator, OriginationAction, RedundancyMode,
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

use crate::evpn_originator::{LOCAL_PEER, route_target_to_extcomm};

/// Cloneable ADR-0063 runtime control surface for the Ethernet
/// Segment owner.
///
/// The full handle remains owned by coordinated shutdown. Runtime
/// commits publish complete ES snapshots through this control; the
/// segment actor remains the only Type 1/4 originator.
#[derive(Clone, Debug)]
pub(crate) struct EvpnSegmentRuntimeControl {
    instances_tx: watch::Sender<Arc<EvpnInstanceTable>>,
    segments_tx: watch::Sender<Arc<Vec<EthernetSegment>>>,
}

impl EvpnSegmentRuntimeControl {
    /// Whether the segment actor can still receive runtime instance
    /// and ES snapshots.
    #[must_use]
    pub fn is_open(&self) -> bool {
        !self.instances_tx.is_closed() && !self.segments_tx.is_closed()
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
}

/// Handle returned to the daemon for shutdown coordination.
#[derive(Debug)]
pub struct EvpnSegmentHandle {
    pub(crate) shutdown: CancellationToken,
    pub(crate) join: tokio::task::JoinHandle<()>,
    instances_tx: watch::Sender<Arc<EvpnInstanceTable>>,
    segments_tx: watch::Sender<Arc<Vec<EthernetSegment>>>,
}

impl EvpnSegmentHandle {
    /// Cloneable ADR-0063 runtime control surface for future daemon
    /// apply wiring.
    pub(crate) fn runtime_control(&self) -> EvpnSegmentRuntimeControl {
        EvpnSegmentRuntimeControl {
            instances_tx: self.instances_tx.clone(),
            segments_tx: self.segments_tx.clone(),
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
pub fn spawn(
    instances: &Arc<EvpnInstanceTable>,
    segments: Vec<EthernetSegment>,
    rib_tx: mpsc::Sender<RibUpdate>,
    bum_enforcement_tx: Option<watch::Sender<Arc<BumEnforcementTable>>>,
    metrics: BgpMetrics,
    daemon_shutdown: CancellationToken,
) -> Option<EvpnSegmentHandle> {
    if segments.is_empty() {
        info!("no [[ethernet_segments]] configured — EVPN segment orchestrator not spawned");
        return None;
    }
    let (segments_tx, segments_rx) = watch::channel(Arc::new(segments));
    let (instances_tx, instances_rx) = watch::channel(instances.clone());
    let runtime = SegmentRuntime {
        instances: instances.clone(),
        rib_tx,
        bum_enforcement_tx,
        metrics,
        shutdown: daemon_shutdown.clone(),
    };
    let join = tokio::spawn(segment_loop(runtime, instances_rx, segments_rx));
    Some(EvpnSegmentHandle {
        shutdown: daemon_shutdown,
        join,
        instances_tx,
        segments_tx,
    })
}

struct SegmentRuntime {
    instances: Arc<EvpnInstanceTable>,
    rib_tx: mpsc::Sender<RibUpdate>,
    bum_enforcement_tx: Option<watch::Sender<Arc<BumEnforcementTable>>>,
    metrics: BgpMetrics,
    shutdown: CancellationToken,
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

#[allow(clippy::too_many_lines)] // setup + main select loop combined; further extraction hurts the lifecycle story
async fn segment_loop(
    mut runtime: SegmentRuntime,
    mut instances_rx: watch::Receiver<Arc<EvpnInstanceTable>>,
    mut segments_rx: watch::Receiver<Arc<Vec<EthernetSegment>>>,
) {
    let mut by_esi: HashMap<EthernetSegmentIdentifier, SegmentState> = HashMap::new();
    // One allocator per spawn so two operators on different daemons
    // don't have to coordinate label space; the allocator survives
    // for the lifetime of the actor task and assignments stay
    // stable across reconfiguration within that lifetime.
    let mut esi_label_allocator = rustbgpd_evpn::EsiLabelAllocator::new();
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
    initial_startup(&runtime, &mut by_esi).await;
    publish_bum_enforcement_snapshot(&runtime, &by_esi);

    // Periodic re-election timer — backstop in case we're in poll-only mode
    // (broadcast subscription failed) or events get dropped under load.
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;
            () = runtime.shutdown.cancelled() => {
                drain(&runtime, &mut by_esi).await;
                publish_empty_bum_enforcement_snapshot(&runtime);
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
                    )
                    .await;
                } else {
                    debug!("EVPN segment: runtime segment watch closed; draining");
                    drain(&runtime, &mut by_esi).await;
                    publish_empty_bum_enforcement_snapshot(&runtime);
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
                        drain(&runtime, &mut by_esi).await;
                        apply_runtime_instance_snapshot(&mut runtime, instances);
                        rebuild_segment_states(
                            &runtime,
                            &mut by_esi,
                            &mut esi_label_allocator,
                            segments,
                        );
                        initial_startup(&runtime, &mut by_esi).await;
                        publish_bum_enforcement_snapshot(&runtime, &by_esi);
                    } else {
                        apply_runtime_instance_snapshot(&mut runtime, instances);
                    }
                } else {
                    debug!("EVPN segment: runtime instance watch closed; draining");
                    drain(&runtime, &mut by_esi).await;
                    publish_empty_bum_enforcement_snapshot(&runtime);
                    return;
                }
            },
            event = recv_evpn_event(&mut evpn_event_rx) => match event {
                Ok(ev) => {
                    handle_evpn_event(&runtime, &mut by_esi, &ev).await;
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(
                        skipped,
                        "EVPN segment orchestrator: event broadcast lagged; running full re-election sweep"
                    );
                    reelection_sweep(&runtime, &mut by_esi).await;
                }
                Err(broadcast::error::RecvError::Closed) => {
                    warn!("EVPN segment orchestrator: RIB event broadcast closed; reverting to poll-only");
                    evpn_event_rx = None;
                }
            },
            _ = tick.tick() => {
                reelection_sweep(&runtime, &mut by_esi).await;
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

    drain(runtime, by_esi).await;
    rebuild_segment_states(runtime, by_esi, esi_label_allocator, segments);
    initial_startup(runtime, by_esi).await;
    publish_bum_enforcement_snapshot(runtime, by_esi);
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

async fn initial_startup(
    runtime: &SegmentRuntime,
    by_esi: &mut HashMap<EthernetSegmentIdentifier, SegmentState>,
) {
    for state in by_esi.values_mut() {
        // Type 4 ES first so peers see us as a candidate before any
        // EAD routes show up.
        let actions = state.es_origin.on_startup();
        apply(runtime, state, actions).await;

        let actions = state.ead_per_es.on_startup();
        apply(runtime, state, actions).await;

        // Initial election with self as sole candidate. Local PE is
        // DF for all member VNIs.
        run_election_for(runtime, state).await;
    }
}

async fn drain(
    runtime: &SegmentRuntime,
    by_esi: &mut HashMap<EthernetSegmentIdentifier, SegmentState>,
) {
    for state in by_esi.values_mut() {
        let actions = state.ead_per_evi.drain_to_withdraws();
        apply(runtime, state, actions).await;
        let actions = state.ead_per_es.on_shutdown();
        apply(runtime, state, actions).await;
        let actions = state.es_origin.on_shutdown();
        apply(runtime, state, actions).await;
    }
}

async fn handle_evpn_event(
    runtime: &SegmentRuntime,
    by_esi: &mut HashMap<EthernetSegmentIdentifier, SegmentState>,
    event: &EvpnRouteEvent,
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
    run_election_for(runtime, state).await;
    publish_bum_enforcement_snapshot(runtime, by_esi);
}

async fn reelection_sweep(
    runtime: &SegmentRuntime,
    by_esi: &mut HashMap<EthernetSegmentIdentifier, SegmentState>,
) {
    let routes = match query_evpn_routes(&runtime.rib_tx).await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "EVPN segment: sweep candidate gather failed");
            return;
        }
    };
    for state in by_esi.values_mut() {
        run_election_for_routes(runtime, state, &routes).await;
    }
    publish_bum_enforcement_snapshot(runtime, by_esi);
}

/// Re-gather candidates from the RIB and re-run election for one
/// ESI. Diffs against the prior `last_roles` map; per-VNI flips
/// trigger `on_vni_role_changed` plus telemetry updates.
async fn run_election_for(runtime: &SegmentRuntime, state: &mut SegmentState) {
    let candidates = match gather_candidates(state, &runtime.rib_tx).await {
        Ok(c) => c,
        Err(e) => {
            warn!(esi = ?state.config.esi.octets(), error = %e, "EVPN segment: candidate gather failed");
            return;
        }
    };
    run_election_with_candidates(runtime, state, candidates).await;
}

async fn run_election_for_routes(
    runtime: &SegmentRuntime,
    state: &mut SegmentState,
    routes: &[EvpnRibRoute],
) {
    let candidates = gather_candidates_from_routes(state, routes);
    run_election_with_candidates(runtime, state, candidates).await;
}

async fn run_election_with_candidates(
    runtime: &SegmentRuntime,
    state: &mut SegmentState,
    candidates: Vec<DfCandidate>,
) {
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
            state.config.redundancy_mode,
            actions,
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

fn publish_bum_enforcement_snapshot(
    runtime: &SegmentRuntime,
    by_esi: &HashMap<EthernetSegmentIdentifier, SegmentState>,
) {
    let Some(tx) = &runtime.bum_enforcement_tx else {
        return;
    };
    let table = Arc::new(build_bum_enforcement_table(&runtime.instances, by_esi));
    debug!(
        rows = table.len(),
        "EVPN segment: published BUM enforcement intent"
    );
    tx.send_replace(table);
}

fn publish_empty_bum_enforcement_snapshot(runtime: &SegmentRuntime) {
    if let Some(tx) = &runtime.bum_enforcement_tx {
        tx.send_replace(Arc::new(BumEnforcementTable::new()));
    }
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
            df_dont_preempt: false,
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
) -> Vec<rustbgpd_wire::ExtendedCommunity> {
    let mut extcomms = vec![rustbgpd_wire::ExtendedCommunity::es_import_rt(
        es_import_rt_from_esi(esi),
    )];
    if let Some(df) = df_election_extcomm(df_algorithm, df_preference) {
        extcomms.push(df);
    }
    extcomms
}

fn df_election_extcomm(
    df_algorithm: DfAlgorithm,
    df_preference: u32,
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
            Some(rustbgpd_wire::ExtendedCommunity::df_election(
                df_algorithm.algorithm_id(),
                0,
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

async fn apply(runtime: &SegmentRuntime, state: &SegmentState, actions: Vec<OriginationAction>) {
    let Some(inst) = runtime.instances.get(state.reference_instance_id).cloned() else {
        // The reference instance is gone — e.g. a tenant teardown removed the
        // member L2VNI before this drain runs. Inject actions can't be built
        // without the instance's path attributes, but Withdraw actions only
        // need the route key, so still emit those; otherwise teardown would
        // strand the segment's Type 1/4 routes in peers' RIBs.
        apply_withdraws_only(runtime, actions).await;
        return;
    };
    apply_with_instance(
        runtime,
        &inst,
        state.esi_label,
        state.config.df_algorithm,
        state.config.df_preference,
        state.config.redundancy_mode,
        actions,
    )
    .await;
}

/// Emit only the Withdraw actions from `actions`, dropping any Inject (which
/// can't be built without the now-removed reference instance). Used when the
/// member L2VNI has already been torn down but the segment's routes still need
/// to be withdrawn from the RIB.
async fn apply_withdraws_only(runtime: &SegmentRuntime, actions: Vec<OriginationAction>) {
    for action in actions {
        let OriginationAction::Withdraw { key, .. } = action else {
            continue;
        };
        let (reply_tx, reply_rx) = oneshot::channel();
        if runtime
            .rib_tx
            .send(RibUpdate::WithdrawEvpn {
                key,
                reply: reply_tx,
            })
            .await
            .is_err()
        {
            warn!(?key, "EVPN segment: RIB channel closed; cannot withdraw");
            return;
        }
        match reply_rx.await {
            Ok(Ok(())) => debug!(
                ?key,
                "EVPN segment: withdrew (member instance already removed)"
            ),
            Ok(Err(e)) => debug!(?key, error = %e, "EVPN segment: RIB withdraw declined"),
            Err(_) => warn!(?key, "EVPN segment: RIB withdraw reply dropped"),
        }
    }
}

async fn apply_with_instance(
    runtime: &SegmentRuntime,
    inst: &EvpnInstance,
    esi_label: MplsLabel,
    df_algorithm: DfAlgorithm,
    df_preference: u32,
    redundancy_mode: RedundancyMode,
    actions: Vec<OriginationAction>,
) {
    for action in actions {
        match action {
            OriginationAction::Inject { key, .. } => {
                let route = build_es_route(
                    inst,
                    &key,
                    esi_label,
                    df_algorithm,
                    df_preference,
                    redundancy_mode,
                );
                let (reply_tx, reply_rx) = oneshot::channel();
                if runtime
                    .rib_tx
                    .send(RibUpdate::InjectEvpn {
                        route,
                        reply: reply_tx,
                    })
                    .await
                    .is_err()
                {
                    warn!(?key, "EVPN segment: RIB channel closed; cannot inject");
                    return;
                }
                match reply_rx.await {
                    Ok(Ok(())) => debug!(?key, "EVPN segment: originated"),
                    Ok(Err(e)) => warn!(?key, error = %e, "EVPN segment: RIB rejected inject"),
                    Err(_) => warn!(?key, "EVPN segment: RIB inject reply dropped"),
                }
            }
            OriginationAction::Withdraw { key, .. } => {
                let (reply_tx, reply_rx) = oneshot::channel();
                if runtime
                    .rib_tx
                    .send(RibUpdate::WithdrawEvpn {
                        key,
                        reply: reply_tx,
                    })
                    .await
                    .is_err()
                {
                    warn!(?key, "EVPN segment: RIB channel closed; cannot withdraw");
                    return;
                }
                match reply_rx.await {
                    Ok(Ok(())) => debug!(?key, "EVPN segment: withdrew"),
                    Ok(Err(e)) => debug!(?key, error = %e, "EVPN segment: RIB withdraw declined"),
                    Err(_) => warn!(?key, "EVPN segment: RIB withdraw reply dropped"),
                }
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
///   also advertise the configured DF Preference with local
///   Don't-Preempt unset.
/// - **Type 1 EAD-per-EVI**: no extra extcomms (the per-EVI label
///   lives in the route's MPLS label field; aliasing extcomms are
///   Gate 8b territory).
fn build_es_route(
    instance: &EvpnInstance,
    key: &EvpnRouteKey,
    esi_label: MplsLabel,
    df_algorithm: DfAlgorithm,
    df_preference: u32,
    redundancy_mode: RedundancyMode,
) -> EvpnRibRoute {
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
                type4_es_extcomms(*esi, df_algorithm, df_preference),
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
                    ethernet_tag: *ethernet_tag,
                    label: MplsLabel::new(ethernet_tag.0),
                }),
                // RFC 7432 §14: EAD-per-EVI carries no ESI Label —
                // the per-EVI label comes from the route's own MPLS
                // label field. The aliasing extcomms (single-active
                // backup signaling) land in Gate 8b.
                Vec::new(),
            ),
            // Other key shapes shouldn't reach this builder — Type 1/4
            // originators only emit the three above.
            other => {
                warn!(
                    ?other,
                    "EVPN segment: unexpected key shape passed to ES route builder"
                );
                // Synthesize a degenerate Type 4 to avoid panicking in
                // production; callers will see the warn-level log.
                (
                    EvpnRoute::Es(EvpnEs {
                        rd: instance.rd,
                        esi: EthernetSegmentIdentifier::ZERO,
                        originator_ip: instance.local_vtep_ip,
                    }),
                    Vec::new(),
                )
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

    EvpnRibRoute {
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
    }
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
    use rustbgpd_evpn::{EvpnInstance, EvpnInstanceTable, RouteTarget};
    use rustbgpd_wire::{EthernetTagId, ExtendedCommunity};

    fn rd(asn: u16, val: u32) -> rustbgpd_wire::RouteDistinguisher {
        let mut bytes = [0u8; 8];
        bytes[2..4].copy_from_slice(&asn.to_be_bytes());
        bytes[4..8].copy_from_slice(&val.to_be_bytes());
        rustbgpd_wire::RouteDistinguisher::new(bytes)
    }

    fn ipa(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn vni(n: u32) -> EvpnInstanceId {
        EvpnInstanceId::new(n).unwrap()
    }

    fn esi(seed: u8) -> EthernetSegmentIdentifier {
        EthernetSegmentIdentifier::new([seed; 10])
    }

    fn instance(v: u32) -> EvpnInstance {
        instance_with_rd(v, v)
    }

    fn instance_with_rd(v: u32, rd_value: u32) -> EvpnInstance {
        EvpnInstance::new(
            vni(v),
            rd(65000, rd_value),
            vec![RouteTarget::TwoOctetAs {
                asn: 65000,
                value: rd_value,
            }],
            ipa("10.0.0.1"),
            Some(format!("br{v}")),
            false,
        )
        .unwrap()
    }

    fn segment_state(id: EthernetSegmentIdentifier) -> SegmentState {
        let member_vnis = std::collections::BTreeSet::from([vni(100)]);
        let config = EthernetSegment {
            esi: id,
            member_vnis: member_vnis.clone(),
            df_preference: 32_768,
            df_algorithm: DfAlgorithm::DefaultModulo,
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
            RedundancyMode::AllActive,
        );
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
            RedundancyMode::AllActive,
        );
        match route.route {
            EvpnRoute::EadPerEs(r) => {
                assert_eq!(r.ethernet_tag, EthernetTagId::MAX_ET);
            }
            other => panic!("expected EadPerEs, got {other:?}"),
        }
    }

    #[test]
    fn build_ead_per_evi_route_carries_vni_label() {
        let inst = instance(100);
        let key = EvpnRouteKey::EadPerEvi {
            rd: rd(65000, 100),
            esi: esi(1),
            ethernet_tag: EthernetTagId(100),
        };
        let route = build_es_route(
            &inst,
            &key,
            MplsLabel::new(123),
            DfAlgorithm::DefaultModulo,
            32_768,
            RedundancyMode::AllActive,
        );
        match route.route {
            EvpnRoute::EadPerEvi(r) => {
                assert_eq!(r.ethernet_tag.0, 100);
                assert_eq!(r.label.value(), 100);
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
            RedundancyMode::AllActive,
        );
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
            RedundancyMode::AllActive,
        );
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
            RedundancyMode::AllActive,
        );
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
            RedundancyMode::AllActive,
        );
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
            RedundancyMode::AllActive,
        );
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
            RedundancyMode::SingleActive,
        );
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
            ethernet_tag: EthernetTagId(100),
        };
        let route = build_es_route(
            &inst,
            &key,
            MplsLabel::new(123),
            DfAlgorithm::DefaultModulo,
            32_768,
            RedundancyMode::AllActive,
        );
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
        assert!(
            injected.iter().any(|key| {
                matches!(
                    key,
                    EvpnRouteKey::EadPerEvi { ethernet_tag, .. } if ethernet_tag.0 == 200
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
            metrics: BgpMetrics::new(),
            shutdown: CancellationToken::new(),
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
}
