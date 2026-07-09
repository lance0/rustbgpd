use super::{
    ACTION_INJECT, ACTION_WITHDRAW, BTreeSet, BgpMetrics, EthernetSegmentIdentifier, EvpnInstance,
    EvpnInstanceId, EvpnInstanceTable, EvpnRouteKey, IpAddr, OriginatedLocalMacCounts,
    OriginationAction, OriginatorState, PathAttribute, RibUpdate, build_originated_route, debug,
    mpsc, warn,
};
use crate::evpn_ack::{PendingRibOps, RibAckOutcome, send_and_ack};

/// Drain on shutdown: emit Withdraws for every still-advertised
/// route across both originators. MAC+IP first so peer state
/// converges from the most-specific NLRIs down — same pattern the
/// daemon's coordinated shutdown uses for SVI then originator then
/// IMET.
pub(super) async fn drain_to_withdraws(
    state: &mut OriginatorState,
    instances: &EvpnInstanceTable,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
) {
    let vnis: BTreeSet<EvpnInstanceId> = state
        .mac_ip_originators
        .keys()
        .chain(state.mac_originators.keys())
        .copied()
        .collect();
    for vni in vnis {
        drain_vni_to_withdraws(
            state,
            instances,
            vni,
            rib_tx,
            metrics,
            originated_local_mac_counts,
            vni_to_esi,
        )
        .await;
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn drain_vni_to_withdraws(
    state: &mut OriginatorState,
    instances: &EvpnInstanceTable,
    vni: EvpnInstanceId,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
) {
    let Some(inst) = instances.get(vni) else {
        return;
    };
    if let Some(orig) = state.mac_ip_originators.get_mut(&vni) {
        let actions = orig.drain_to_withdraws();
        if !actions.is_empty() {
            apply_actions(
                &mut state.pending_rib_ops,
                actions,
                inst,
                rib_tx,
                metrics,
                originated_local_mac_counts,
                vni_to_esi,
            )
            .await;
        }
    }
    if let Some(orig) = state.mac_originators.get_mut(&vni) {
        let actions = orig.drain_to_withdraws();
        if !actions.is_empty() {
            apply_actions(
                &mut state.pending_rib_ops,
                actions,
                inst,
                rib_tx,
                metrics,
                originated_local_mac_counts,
                vni_to_esi,
            )
            .await;
        }
    }
}

/// Translate `OriginationAction`s into `RibUpdate`s and ship them to
/// the RIB, acknowledgement-aware per ADR-0102: each operation is
/// registered as pending (superseding any older pending operation for
/// the same route identity) before its first attempt, and only the
/// RIB's acknowledgement clears it. Failed attempts stay pending; the
/// actor's retry arm re-drives them with bounded backoff.
#[allow(clippy::too_many_arguments)]
pub(super) async fn apply_actions(
    pending: &mut PendingRibOps,
    actions: Vec<OriginationAction>,
    instance: &EvpnInstance,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
) {
    for action in actions {
        let key = action_key(&action);
        let generation = pending.submit(key, instance.id, action.clone());
        attempt_action(
            pending,
            generation,
            &action,
            instance.id,
            Some(instance),
            rib_tx,
            metrics,
            originated_local_mac_counts,
            vni_to_esi,
        )
        .await;
    }
}

/// Re-drive every pending operation whose backoff has elapsed.
/// Injects rebuild their route from the *current* instance model; a
/// pending inject whose VNI left the model (or changed RD) is dropped
/// — the lifecycle drain that removed it already superseded the
/// route's state with withdraws. Withdraws only need the key and are
/// retried until the RIB acknowledges them.
pub(super) async fn retry_pending_rib_ops(
    state: &mut OriginatorState,
    instances: &EvpnInstanceTable,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
) {
    for (_key, op) in state.pending_rib_ops.due(tokio::time::Instant::now()) {
        attempt_action(
            &mut state.pending_rib_ops,
            op.generation,
            &op.action,
            op.vni,
            instances.get(op.vni),
            rib_tx,
            metrics,
            originated_local_mac_counts,
            vni_to_esi,
        )
        .await;
    }
}

fn action_key(action: &OriginationAction) -> EvpnRouteKey {
    match action {
        OriginationAction::Inject { key, .. } | OriginationAction::Withdraw { key, .. } => *key,
    }
}

/// One send-and-ack attempt for a registered pending operation.
/// Confirms (and does the success bookkeeping) on ack, defers on any
/// failure. Shared by the first attempt ([`apply_actions`]) and the
/// retry path ([`retry_pending_rib_ops`]).
#[allow(clippy::too_many_arguments)]
async fn attempt_action(
    pending: &mut PendingRibOps,
    generation: u64,
    action: &OriginationAction,
    vni: EvpnInstanceId,
    instance: Option<&EvpnInstance>,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
) {
    match action {
        OriginationAction::Inject {
            mac,
            mobility_seq,
            sticky,
            key,
        } => {
            // The route is rebuilt from the current model on every
            // attempt. A VNI that left the model — or was redefined
            // under a new RD — invalidates the pending inject; the
            // lifecycle path that changed the model already drained
            // (superseded) the route's state, so drop rather than
            // re-inject under stale fields.
            let stale = match instance {
                None => true,
                Some(inst) => matches!(key, EvpnRouteKey::MacIp { rd, .. } if *rd != inst.rd),
            };
            let Some(inst) = instance.filter(|_| !stale) else {
                pending.forget(*key, generation);
                debug!(
                    ?key,
                    "dropping pending Type 2 inject for removed/redefined VNI"
                );
                return;
            };
            // ESI-aware origination: when the VNI is part of a
            // configured Ethernet Segment, attach the segment's
            // ESI so peers can resolve aliasing alternatives.
            // Single-homed VNIs default to ZERO.
            let esi = vni_to_esi
                .get(&inst.id)
                .copied()
                .unwrap_or(EthernetSegmentIdentifier::ZERO);
            let route = build_originated_route(inst, *mac, *mobility_seq, *sticky, *key, esi);
            match send_and_ack(rib_tx, |reply| RibUpdate::InjectEvpn { route, reply }).await {
                RibAckOutcome::Acked => {
                    pending.confirm(*key, generation);
                    metrics.record_evpn_local_origination(ACTION_INJECT);
                    originated_local_mac_counts.record_inject(inst.id, *mac, *key);
                    debug!(?key, ?mobility_seq, "originated Type 2");
                }
                RibAckOutcome::Rejected(e) => {
                    pending.defer(*key, generation);
                    metrics.record_evpn_local_origination_error(ACTION_INJECT);
                    warn!(?key, error = %e, "RIB rejected Type 2 inject; will retry");
                }
                RibAckOutcome::NoAck(reason) => {
                    pending.defer(*key, generation);
                    metrics.record_evpn_local_origination_error(ACTION_INJECT);
                    warn!(?key, reason, "Type 2 inject unacknowledged; will retry");
                }
            }
        }
        OriginationAction::Withdraw { mac, key } => {
            let outcome =
                send_and_ack(rib_tx, |reply| RibUpdate::WithdrawEvpn { key: *key, reply }).await;
            let not_found = outcome.is_not_found();
            match outcome {
                RibAckOutcome::Acked => {
                    pending.confirm(*key, generation);
                    metrics.record_evpn_local_origination(ACTION_WITHDRAW);
                    originated_local_mac_counts.record_withdraw(vni, *mac, *key);
                    debug!(?key, "withdrew Type 2");
                }
                // NotFound means the route is already absent — e.g.
                // its inject was lost before ever applying, or the
                // withdraw raced an in-flight inject failure. Absence
                // is the withdraw's goal: confirm instead of retrying
                // forever against a route that will never exist.
                RibAckOutcome::Rejected(e) if not_found => {
                    pending.confirm(*key, generation);
                    metrics.record_evpn_local_origination_error(ACTION_WITHDRAW);
                    originated_local_mac_counts.record_withdraw(vni, *mac, *key);
                    debug!(?key, error = %e, "RIB withdraw target absent — treating as complete");
                }
                RibAckOutcome::Rejected(e) => {
                    pending.defer(*key, generation);
                    metrics.record_evpn_local_origination_error(ACTION_WITHDRAW);
                    warn!(?key, error = %e, "RIB rejected Type 2 withdraw; will retry");
                }
                RibAckOutcome::NoAck(reason) => {
                    pending.defer(*key, generation);
                    metrics.record_evpn_local_origination_error(ACTION_WITHDRAW);
                    warn!(?key, reason, "Type 2 withdraw unacknowledged; will retry");
                }
            }
        }
    }
}

/// Pull the optional host IP back out of the route key the state
/// machine produced. Gate 7b+1 always uses `ip = None`, but stays
/// faithful to the key for forward-compat when ARP suppression
/// learning lands.
pub(super) fn extract_ip_from_key(key: &EvpnRouteKey) -> Option<IpAddr> {
    match key {
        EvpnRouteKey::MacIp { ip, .. } => *ip,
        _ => None,
    }
}

/// IPv4 next-hop attribute — for IPv6 VTEP IPs the `MP_REACH_NLRI`
/// next-hop carries the address; we still emit a `NEXT_HOP` attribute
/// pointing at 0.0.0.0 in that case to satisfy peers that expect one.
pub(super) fn next_hop_path_attribute(vtep_ip: IpAddr) -> PathAttribute {
    match vtep_ip {
        IpAddr::V4(v4) => PathAttribute::NextHop(v4),
        IpAddr::V6(_) => PathAttribute::NextHop(std::net::Ipv4Addr::UNSPECIFIED),
    }
}
