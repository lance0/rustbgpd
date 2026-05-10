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
//! 2. **Startup** — for each ES: emit the Type 4 ES route + Type 1
//!    EAD-per-ES route, run DF election with the local PE as sole
//!    candidate (the local PE is DF for all member VNIs at startup
//!    because no peers have been observed yet), emit one Type 1
//!    EAD-per-EVI per member VNI carrying the role-aware shape.
//! 3. **Steady state** — subscribe to the
//!    [`rustbgpd_rib::EvpnRouteEvent`] broadcast; on every Type 4
//!    event for a tracked ESI, re-gather candidates from the RIB
//!    via `QueryEvpnRoutes`, re-run election, fire per-VNI
//!    `on_vni_role_changed` for any flipped slot, and update the
//!    Prometheus gauge / counter.
//! 4. **Shutdown** — drain all per-ESI Type 1/4 routes before peer
//!    sessions tear down so peer state converges from the
//!    most-specific NLRI shape down (same convention as the
//!    existing originator + SVI tasks).
//!
//! ## Scope (Gate 8 — observable)
//!
//! The daemon-side path here ships the **observation** half of the
//! gate: Prometheus surface + tracing logs + the wire-side Type 1/4
//! origination needed for peers to see the local PE as a candidate.
//! Forwarding-blocking enforcement (split-horizon via the ESI Label
//! extcomm, aliasing-driven backup paths, mass-withdraw on
//! `AS_PATH` change) is Gate 8b — see ADR-0057.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustbgpd_evpn::{
    DfAlgorithm, DfCandidate, DfElection, DfRole, EthernetSegment, EvpnInstance, EvpnInstanceId,
    EvpnInstanceTable, LocalEadPerEsOriginator, LocalEadPerEviOriginator, LocalEsOriginator,
    OriginationAction,
};
use rustbgpd_rib::{EvpnRouteEvent, RibUpdate, route::EvpnRibRoute};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{
    AsPath, EthernetSegmentIdentifier, EvpnEadPerEs, EvpnEadPerEvi, EvpnEs, EvpnRoute,
    EvpnRouteKey, MplsLabel, Origin, PathAttribute,
};
use tokio::sync::{broadcast, mpsc, oneshot};
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

    // Periodic re-election timer — backstop in case we're in poll-only mode
    // (broadcast subscription failed) or events get dropped under load.
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;
            () = runtime.shutdown.cancelled() => {
                drain(&runtime, &mut by_esi).await;
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
/// Gate 8 ships a minimal path-attribute set: Origin, empty `AsPath`,
/// `NextHop`, RT extcomms from the instance's configured `route_targets`.
/// The ES-Import RT (RFC 7432 §7.6) and the ESI Label extcomm
/// (RFC 7432 §7.5) are intentionally **not** emitted — they're load-
/// bearing for split-horizon enforcement, which is Gate 8b. Peers
/// will see the routes via reflection but won't import them via RT
/// match. ADR-0057 records the gap.
fn build_es_route(instance: &EvpnInstance, key: &EvpnRouteKey) -> EvpnRibRoute {
    let route = match key {
        EvpnRouteKey::Es {
            rd,
            esi,
            originator_ip,
        } => EvpnRoute::Es(EvpnEs {
            rd: *rd,
            esi: *esi,
            originator_ip: *originator_ip,
        }),
        EvpnRouteKey::EadPerEs {
            rd,
            esi,
            ethernet_tag,
        } => EvpnRoute::EadPerEs(EvpnEadPerEs {
            rd: *rd,
            esi: *esi,
            ethernet_tag: *ethernet_tag,
            label: synthesize_esi_label(*esi),
        }),
        EvpnRouteKey::EadPerEvi {
            rd,
            esi,
            ethernet_tag,
        } => EvpnRoute::EadPerEvi(EvpnEadPerEvi {
            rd: *rd,
            esi: *esi,
            ethernet_tag: *ethernet_tag,
            label: MplsLabel::new(ethernet_tag.0),
        }),
        // Other key shapes shouldn't reach this builder — Type 1/4
        // originators only emit the three above.
        other => {
            warn!(
                ?other,
                "EVPN segment: unexpected key shape passed to ES route builder"
            );
            // Synthesize a degenerate Type 4 to avoid panicking in
            // production; callers will see the warn-level log.
            EvpnRoute::Es(EvpnEs {
                rd: instance.rd,
                esi: EthernetSegmentIdentifier::ZERO,
                originator_ip: instance.local_vtep_ip,
            })
        }
    };

    let ext_communities: Vec<rustbgpd_wire::ExtendedCommunity> = instance
        .route_targets
        .iter()
        .copied()
        .map(route_target_to_extcomm)
        .collect();

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
            metrics,
            CancellationToken::new(),
        );
        assert!(h.is_none());
    }
}
