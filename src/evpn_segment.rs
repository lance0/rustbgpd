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

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustbgpd_evpn::{
    BumEnforcementTable, DfAlgorithm, DfCandidate, DfElection, DfRole, EthernetSegment,
    EvpnInstance, EvpnInstanceId, EvpnInstanceTable, LocalEadPerEsOriginator,
    LocalEadPerEviOriginator, LocalEsOriginator, OriginationAction,
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

/// Handle returned to the daemon for shutdown coordination.
#[derive(Debug)]
pub struct EvpnSegmentHandle {
    pub(crate) shutdown: CancellationToken,
    pub(crate) join: tokio::task::JoinHandle<()>,
}

impl EvpnSegmentHandle {
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
    let runtime = SegmentRuntime {
        instances: instances.clone(),
        rib_tx,
        bum_enforcement_tx,
        metrics,
        shutdown: daemon_shutdown.clone(),
    };
    let join = tokio::spawn(segment_loop(runtime, segments));
    Some(EvpnSegmentHandle {
        shutdown: daemon_shutdown,
        join,
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
}

async fn segment_loop(runtime: SegmentRuntime, segments: Vec<EthernetSegment>) {
    let mut by_esi: HashMap<EthernetSegmentIdentifier, SegmentState> = HashMap::new();

    // Build per-ESI state.
    for seg in segments {
        let Some(reference_vni) = seg.member_vnis.iter().copied().next() else {
            warn!(
                esi = ?seg.esi.octets(),
                "ethernet_segments entry has no member_vnis — skipping"
            );
            continue;
        };
        let Some(inst) = runtime.instances.get(reference_vni) else {
            warn!(
                esi = ?seg.esi.octets(),
                vni = reference_vni.as_u32(),
                "ethernet_segments entry references unknown VNI — skipping"
            );
            continue;
        };
        let rd = inst.rd;
        // ESI label: a synthetic per-ESI label below the kernel's
        // typical reserved range. Gate 8 uses a deterministic
        // function of the ESI bytes so peers don't see thrash; Gate
        // 8b can swap this for a proper allocator alongside the
        // split-horizon enforcement work.
        let esi_label = synthesize_esi_label(seg.esi);
        let es_origin = LocalEsOriginator::new(rd, seg.esi, seg.originator_ip);
        let ead_per_es = LocalEadPerEsOriginator::new(rd, seg.esi, esi_label);
        let mut ead_per_evi = LocalEadPerEviOriginator::new(rd, seg.esi);
        let labels: BTreeMap<EvpnInstanceId, MplsLabel> = seg
            .member_vnis
            .iter()
            .map(|&v| (v, MplsLabel::new(v.as_u32())))
            .collect();
        let rds: BTreeMap<_, _> = seg
            .member_vnis
            .iter()
            .map(|&v| {
                let inst = runtime
                    .instances
                    .get(v)
                    .expect("validated by Config::resolve_ethernet_segments");
                (v, inst.rd)
            })
            .collect();
        ead_per_evi.set_rds(rds);
        ead_per_evi.set_labels(labels);
        let election = DfElection::new(seg.esi, seg.member_vnis.iter().copied());
        by_esi.insert(
            seg.esi,
            SegmentState {
                config: seg,
                es_origin,
                ead_per_es,
                ead_per_evi,
                election,
                last_roles: BTreeMap::new(),
                reference_instance_id: reference_vni,
            },
        );
    }

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
        apply_with_instance(runtime, &inst, actions).await;
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
        // Per-PE candidate. df_algorithm decodes from the route's DF
        // Election extcomm if present; absent extcomm → DefaultModulo
        // + default preference (matches RFC 8584 fallback rules).
        let (pref, alg) = decode_df_election_extcomm(&r.attributes)
            .unwrap_or((32_768, DfAlgorithm::DefaultModulo));
        by_ip.entry(es.originator_ip).or_insert(DfCandidate {
            originator_ip: es.originator_ip,
            df_preference: pref,
            df_algorithm: alg,
        });
    }
    by_ip.into_values().collect()
}

fn decode_df_election_extcomm(attrs: &[PathAttribute]) -> Option<(u32, DfAlgorithm)> {
    // RFC 8584 §3.1: DF Election extcomm type 0x06 subtype 0x06,
    // carrying RSV(3 bits), DF Alg(5 bits), bitmap(16 bits), and
    // reserved bytes. Decode is best-effort — unrecognized extcomms
    // fall back to defaults at the call site.
    for attr in attrs {
        let PathAttribute::ExtendedCommunities(ecs) = attr else {
            continue;
        };
        for ec in ecs {
            let bytes = ec.as_u64().to_be_bytes();
            if bytes[0] == 0x06 && bytes[1] == 0x06 {
                let alg = DfAlgorithm::from_algorithm_id(bytes[2] & 0x1f);
                return Some((32_768, alg));
            }
        }
    }
    None
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
        return;
    };
    apply_with_instance(runtime, &inst, actions).await;
}

async fn apply_with_instance(
    runtime: &SegmentRuntime,
    inst: &EvpnInstance,
    actions: Vec<OriginationAction>,
) {
    for action in actions {
        match action {
            OriginationAction::Inject { key, .. } => {
                let route = build_es_route(inst, &key);
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
///   synthesized ESI label with `single_active = false`. Peers wire
///   the label into their split-horizon filter tables; Gate 8b adds
///   the dataplane drops on non-DF receivers.
/// - **Type 1 EAD-per-EVI**: no extra extcomms (the per-EVI label
///   lives in the route's MPLS label field; aliasing extcomms are
///   Gate 8b territory).
fn build_es_route(instance: &EvpnInstance, key: &EvpnRouteKey) -> EvpnRibRoute {
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
                vec![rustbgpd_wire::ExtendedCommunity::es_import_rt(
                    es_import_rt_from_esi(*esi),
                )],
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
                    label: synthesize_esi_label(*esi),
                }),
                // RFC 7432 §7.5: ESI Label extcomm carries the label
                // peers will match against the inner VXLAN/MPLS label
                // for split-horizon enforcement. Gate 8 publishes the
                // value so peers can wire up their import + filter
                // tables; Gate 8b adds the dataplane drops on
                // non-DF receivers. `single_active = false` for the
                // all-active default mode.
                vec![rustbgpd_wire::ExtendedCommunity::esi_label(
                    false,
                    synthesize_esi_label(*esi).value(),
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

/// Synthesize a deterministic ESI label from the ESI bytes. Gate 8
/// uses a content-derived label so peers don't see thrash on
/// daemon restarts; Gate 8b's split-horizon work will swap this for
/// a proper label allocator that survives across operator-level
/// configuration changes.
///
/// Maps ESI bytes [4..7] (the AS / value half of an LACP- or
/// preference-derived ESI) into the 16..=2^20 - 1 range so the
/// resulting label is always within the 20-bit MPLS label space.
fn synthesize_esi_label(esi: EthernetSegmentIdentifier) -> MplsLabel {
    let octets = esi.octets();
    let raw = u32::from_be_bytes([octets[4], octets[5], octets[6], octets[7]]);
    // Keep above the reserved range while staying inside 20 bits.
    let label = 16 + (raw % ((1 << 20) - 16));
    MplsLabel::new(label)
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
        EvpnInstance::new(
            vni(v),
            rd(65000, v),
            vec![RouteTarget::TwoOctetAs {
                asn: 65000,
                value: v,
            }],
            ipa("10.0.0.1"),
            Some(format!("br{v}")),
            false,
        )
        .unwrap()
    }

    #[test]
    fn synthesize_esi_label_is_deterministic_and_in_range() {
        let label_a = synthesize_esi_label(esi(0x42));
        let label_b = synthesize_esi_label(esi(0x42));
        assert_eq!(label_a, label_b);
        // Within 20-bit MPLS range, above reserved 16.
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
        let route = build_es_route(&inst, &key);
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
        let route = build_es_route(&inst, &key);
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
        let route = build_es_route(&inst, &key);
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
        let ec =
            ExtendedCommunity::new(u64::from_be_bytes([0x06, 0x06, 0b1110_0001, 0, 0, 0, 0, 0]));
        let attrs = [PathAttribute::ExtendedCommunities(vec![ec])];
        let (pref, alg) = decode_df_election_extcomm(&attrs).unwrap();
        assert_eq!(pref, 32_768);
        assert_eq!(alg, DfAlgorithm::HighestRandomWeight);
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
        let route = build_es_route(&inst, &key);
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
    fn type_1_ead_per_es_carries_esi_label_extcomm() {
        let inst = instance(100);
        let id = esi(7);
        let key = EvpnRouteKey::EadPerEs {
            rd: rd(65000, 100),
            esi: id,
            ethernet_tag: EthernetTagId::MAX_ET,
        };
        let route = build_es_route(&inst, &key);
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
        assert_eq!(label, synthesize_esi_label(id).value());
    }

    #[test]
    fn type_1_ead_per_evi_does_not_carry_esi_label_extcomm() {
        let inst = instance(100);
        let key = EvpnRouteKey::EadPerEvi {
            rd: rd(65000, 100),
            esi: esi(1),
            ethernet_tag: EthernetTagId(100),
        };
        let route = build_es_route(&inst, &key);
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
