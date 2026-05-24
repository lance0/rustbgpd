use super::{
    ACTION_INJECT, ACTION_WITHDRAW, BTreeSet, BgpMetrics, EthernetSegmentIdentifier, EvpnInstance,
    EvpnInstanceId, EvpnInstanceTable, EvpnRouteKey, IpAddr, OriginatedLocalMacCounts,
    OriginationAction, OriginatorState, PathAttribute, RibUpdate, build_originated_route, debug,
    mpsc, warn,
};

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
/// the RIB. Awaits each oneshot reply so failed injects are logged.
pub(super) async fn apply_actions(
    actions: Vec<OriginationAction>,
    instance: &EvpnInstance,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
) {
    for action in actions {
        match action {
            OriginationAction::Inject {
                mac,
                mobility_seq,
                sticky,
                key,
            } => {
                // ESI-aware origination: when the VNI is part of a
                // configured Ethernet Segment, attach the segment's
                // ESI so peers can resolve aliasing alternatives.
                // Single-homed VNIs default to ZERO.
                let esi = vni_to_esi
                    .get(&instance.id)
                    .copied()
                    .unwrap_or(EthernetSegmentIdentifier::ZERO);
                let route = build_originated_route(instance, mac, mobility_seq, sticky, key, esi);
                let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                if rib_tx
                    .send(RibUpdate::InjectEvpn {
                        route,
                        reply: reply_tx,
                    })
                    .await
                    .is_err()
                {
                    metrics.record_evpn_local_origination_error(ACTION_INJECT);
                    warn!("RIB channel closed; cannot inject EVPN Type 2");
                    return;
                }
                match reply_rx.await {
                    Ok(Ok(())) => {
                        metrics.record_evpn_local_origination(ACTION_INJECT);
                        originated_local_mac_counts.record_inject(instance.id, mac, key);
                        debug!(?key, ?mobility_seq, "originated Type 2");
                    }
                    Ok(Err(e)) => {
                        metrics.record_evpn_local_origination_error(ACTION_INJECT);
                        warn!(?key, error = %e, "RIB rejected Type 2 inject");
                    }
                    Err(_) => {
                        metrics.record_evpn_local_origination_error(ACTION_INJECT);
                        warn!(?key, "RIB inject reply dropped");
                    }
                }
            }
            OriginationAction::Withdraw { mac, key } => {
                let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                if rib_tx
                    .send(RibUpdate::WithdrawEvpn {
                        key,
                        reply: reply_tx,
                    })
                    .await
                    .is_err()
                {
                    metrics.record_evpn_local_origination_error(ACTION_WITHDRAW);
                    warn!("RIB channel closed; cannot withdraw EVPN Type 2");
                    return;
                }
                match reply_rx.await {
                    Ok(Ok(())) => {
                        metrics.record_evpn_local_origination(ACTION_WITHDRAW);
                        originated_local_mac_counts.record_withdraw(instance.id, mac, key);
                        debug!(?key, "withdrew Type 2");
                    }
                    Ok(Err(e)) => {
                        metrics.record_evpn_local_origination_error(ACTION_WITHDRAW);
                        // Withdraws for unknown keys can race with
                        // in-flight inject failures; log at debug.
                        debug!(?key, error = %e, "RIB withdraw declined");
                    }
                    Err(_) => {
                        metrics.record_evpn_local_origination_error(ACTION_WITHDRAW);
                        warn!(?key, "RIB withdraw reply dropped");
                    }
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
