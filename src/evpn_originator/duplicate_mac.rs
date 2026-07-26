use super::{
    Arc, BTreeSet, BgpMetrics, ClearDuplicateMacQuarantineResult, DuplicateMacAction,
    DuplicateMacDecision, DuplicateMacKey, EthernetSegmentIdentifier, EvpnInstance, EvpnInstanceId,
    EvpnInstanceTable, EvpnRouteKey, Instant, IpAddr, MacAddress, OriginatedLocalMacCounts,
    OriginationAction, OriginatorCommand, OriginatorState, RibUpdate, debug, info, mpsc, warn,
    watch,
};
use crate::evpn_originator::rib_write::apply_actions;

#[allow(
    clippy::too_many_arguments,
    reason = "duplicate-MAC state construction keeps all explicit ownership inputs visible"
)]
pub(super) async fn handle_originator_command(
    command: OriginatorCommand,
    state: &mut OriginatorState,
    instances: &EvpnInstanceTable,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
    drained_esis: &BTreeSet<EthernetSegmentIdentifier>,
) {
    match command {
        OriginatorCommand::ClearDuplicateMacQuarantine { key, reply } => {
            let result = clear_duplicate_mac_quarantine(
                key,
                state,
                instances,
                rib_tx,
                metrics,
                originated_local_mac_counts,
                vni_to_esi,
                drained_esis,
            )
            .await;
            let _ = reply.send(result);
        }
    }
}

/// Resolve the sticky bit for `(vni, mac)` per ADR-0056. Returns
/// `false` if the instance is unknown — caller treats that as the
/// safe default.
pub(super) fn sticky_for(
    instances: &EvpnInstanceTable,
    vni: EvpnInstanceId,
    mac: MacAddress,
) -> bool {
    instances
        .get(vni)
        .is_some_and(|inst| inst.sticky_macs.contains(&mac))
}

pub(super) fn duplicate_action_label(action: DuplicateMacAction) -> &'static str {
    match action {
        DuplicateMacAction::DetectOnly => "detect",
        DuplicateMacAction::SuppressLocal => "suppress_local",
    }
}

pub(super) fn duplicate_mac_is_quarantined(
    state: &OriginatorState,
    vni: EvpnInstanceId,
    mac: MacAddress,
) -> bool {
    state
        .duplicate_mac_detector
        .is_quarantined(DuplicateMacKey::new(vni, mac), Instant::now())
}

pub(super) fn remote_route_processing_suppressed(
    state: &OriginatorState,
    vni: EvpnInstanceId,
    mac: MacAddress,
) -> bool {
    if !duplicate_mac_is_quarantined(state, vni, mac) {
        return false;
    }
    debug!(
        ?vni,
        ?mac,
        "EVPN duplicate-MAC quarantine suppresses remote route-processing diff"
    );
    true
}

pub(super) fn publish_duplicate_mac_quarantines(
    tx: &watch::Sender<Arc<BTreeSet<DuplicateMacKey>>>,
    active: &BTreeSet<DuplicateMacKey>,
) {
    tx.send_replace(Arc::new(active.clone()));
}

pub(super) fn set_duplicate_mac_quarantine_active(
    state: &mut OriginatorState,
    key: DuplicateMacKey,
    active: bool,
) {
    let changed = if active {
        state.active_duplicate_mac_quarantines.insert(key)
    } else {
        state.active_duplicate_mac_quarantines.remove(&key)
    };
    if changed {
        publish_duplicate_mac_quarantines(
            &state.duplicate_mac_quarantine_tx,
            &state.active_duplicate_mac_quarantines,
        );
    }
}

pub(super) fn outstanding_route_keys_for_mac(
    state: &OriginatorState,
    vni: EvpnInstanceId,
    mac: MacAddress,
) -> Vec<EvpnRouteKey> {
    let mut keys = Vec::new();
    if let Some(orig) = state.mac_originators.get(&vni) {
        keys.extend(
            orig.outstanding_keys()
                .filter_map(|(m, key)| (m == mac).then_some(key)),
        );
    }
    if let Some(orig) = state.mac_ip_originators.get(&vni) {
        keys.extend(
            orig.outstanding_keys()
                .filter_map(|(k, key)| (k.mac == mac).then_some(key)),
        );
    }
    keys
}

pub(super) fn record_duplicate_mac_move(
    metrics: &BgpMetrics,
    state: &mut OriginatorState,
    inst: &EvpnInstance,
    vni: EvpnInstanceId,
    mac: MacAddress,
) -> bool {
    metrics.record_evpn_duplicate_mac_move(vni.as_u32(), &mac.to_string());
    let config = inst.duplicate_mac_detection;
    let now = Instant::now();
    let key = DuplicateMacKey::new(vni, mac);
    state.known_duplicate_mac_keys.insert(key);
    if state.duplicate_mac_detector.expire_key(key, now) {
        metrics.set_evpn_duplicate_mac_quarantine_active(vni.as_u32(), &mac.to_string(), false);
        set_duplicate_mac_quarantine_active(state, key, false);
    }
    match state.duplicate_mac_detector.record_move(key, now, config) {
        DuplicateMacDecision::Recorded { .. } => false,
        DuplicateMacDecision::ThresholdExceeded { window_count } => {
            metrics.record_evpn_duplicate_mac_threshold_exceeded(
                vni.as_u32(),
                &mac.to_string(),
                duplicate_action_label(config.action),
            );
            warn!(
                ?vni,
                ?mac,
                window_count,
                threshold = config.threshold,
                window_seconds = config.window.as_secs(),
                "EVPN duplicate-MAC threshold exceeded; action is detect-only"
            );
            false
        }
        DuplicateMacDecision::Quarantined {
            window_count,
            until,
        } => {
            metrics.record_evpn_duplicate_mac_threshold_exceeded(
                vni.as_u32(),
                &mac.to_string(),
                duplicate_action_label(config.action),
            );
            metrics.set_evpn_duplicate_mac_quarantine_active(vni.as_u32(), &mac.to_string(), true);
            set_duplicate_mac_quarantine_active(state, key, true);
            warn!(
                ?vni,
                ?mac,
                window_count,
                threshold = config.threshold,
                window_seconds = config.window.as_secs(),
                recovery_seconds = config.recovery.as_secs(),
                ?until,
                "EVPN duplicate-MAC local-origin suppression active"
            );
            true
        }
        DuplicateMacDecision::AlreadyQuarantined { .. } => true,
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "duplicate-MAC observation handling needs the key, timers, and actor state"
)]
pub(super) async fn apply_actions_with_duplicate_policy(
    actions: Vec<OriginationAction>,
    view_present: bool,
    preexisting_keys: Vec<EvpnRouteKey>,
    vni: EvpnInstanceId,
    mac: MacAddress,
    state: &mut OriginatorState,
    inst: &EvpnInstance,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
) {
    if view_present
        && !actions.is_empty()
        && record_duplicate_mac_move(metrics, state, inst, vni, mac)
    {
        suppress_local_originations_for_mac(
            vni,
            mac,
            state,
            inst,
            Some(preexisting_keys),
            rib_tx,
            metrics,
            originated_local_mac_counts,
            vni_to_esi,
        )
        .await;
        return;
    }
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

#[allow(
    clippy::too_many_arguments,
    reason = "duplicate-MAC transition handling needs the key, timers, and actor state"
)]
pub(super) async fn suppress_local_originations_for_mac(
    vni: EvpnInstanceId,
    mac: MacAddress,
    state: &mut OriginatorState,
    inst: &EvpnInstance,
    withdraw_keys: Option<Vec<EvpnRouteKey>>,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
) {
    let mut actions = Vec::new();
    if let Some(mac_ip_orig) = state.mac_ip_originators.get_mut(&vni) {
        actions.extend(mac_ip_orig.on_local_mac_aged(mac));
    }
    if let Some(mac_orig) = state.mac_originators.get_mut(&vni) {
        actions.extend(mac_orig.on_local_aged(mac));
    }
    if let Some(keys) = withdraw_keys {
        actions.retain(|action| match action {
            OriginationAction::Withdraw { key, .. } => keys.contains(key),
            OriginationAction::Inject { .. } => false,
        });
    }
    if actions.is_empty() {
        return;
    }
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

#[allow(
    clippy::too_many_arguments,
    reason = "duplicate-MAC recovery handling needs the key, timers, and actor state"
)]
pub(super) async fn recover_duplicate_macs(
    state: &mut OriginatorState,
    instances: &EvpnInstanceTable,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
    drained_esis: &BTreeSet<EthernetSegmentIdentifier>,
) {
    let recovered = state.duplicate_mac_detector.expire(Instant::now());
    let detector = &state.duplicate_mac_detector;
    state
        .known_duplicate_mac_keys
        .retain(|key| detector.has_state(*key));
    for key in recovered {
        state.known_duplicate_mac_keys.remove(&key);
        metrics.set_evpn_duplicate_mac_quarantine_active(
            key.vni.as_u32(),
            &key.mac.to_string(),
            false,
        );
        set_duplicate_mac_quarantine_active(state, key, false);
        info!(
            vni = ?key.vni,
            mac = ?key.mac,
            "EVPN duplicate-MAC local-origin suppression recovered"
        );
        replay_local_mac_after_recovery(
            key.vni,
            key.mac,
            state,
            instances,
            rib_tx,
            metrics,
            originated_local_mac_counts,
            vni_to_esi,
            drained_esis,
        )
        .await;
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "duplicate-MAC expiry handling needs the key, timers, and actor state"
)]
pub(super) async fn clear_duplicate_mac_quarantine(
    key: DuplicateMacKey,
    state: &mut OriginatorState,
    instances: &EvpnInstanceTable,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
    drained_esis: &BTreeSet<EthernetSegmentIdentifier>,
) -> ClearDuplicateMacQuarantineResult {
    if instances.get(key.vni).is_none() {
        return ClearDuplicateMacQuarantineResult::UnknownVni;
    }

    let was_active = state.active_duplicate_mac_quarantines.contains(&key);
    let had_state = state.duplicate_mac_detector.clear(key);
    if had_state {
        state.known_duplicate_mac_keys.remove(&key);
    }
    if !was_active {
        if had_state {
            debug!(
                vni = ?key.vni,
                mac = ?key.mac,
                "EVPN duplicate-MAC manual clear removed inactive move-window state"
            );
        }
        return ClearDuplicateMacQuarantineResult::NotActive;
    }

    metrics.set_evpn_duplicate_mac_quarantine_active(key.vni.as_u32(), &key.mac.to_string(), false);
    set_duplicate_mac_quarantine_active(state, key, false);
    info!(
        vni = ?key.vni,
        mac = ?key.mac,
        "EVPN duplicate-MAC local-origin suppression manually cleared"
    );
    replay_local_mac_after_recovery(
        key.vni,
        key.mac,
        state,
        instances,
        rib_tx,
        metrics,
        originated_local_mac_counts,
        vni_to_esi,
        drained_esis,
    )
    .await;
    ClearDuplicateMacQuarantineResult::Cleared
}

#[allow(
    clippy::too_many_arguments,
    reason = "duplicate-MAC publication needs the observed state and all actor outputs"
)]
pub(super) async fn replay_local_mac_after_recovery(
    vni: EvpnInstanceId,
    mac: MacAddress,
    state: &mut OriginatorState,
    instances: &EvpnInstanceTable,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
    drained_esis: &BTreeSet<EthernetSegmentIdentifier>,
) {
    // ADR-0084: the replay primitive is the single chokepoint for
    // re-origination from preserved caches — quarantine recovery,
    // manual clear, and runtime-model replays all land here. While the
    // VNI's mapped ESI is operator-drained, keep the caches but emit
    // nothing; the undrain replay re-runs this with the drain lifted.
    if super::vni_is_drained(vni, vni_to_esi, drained_esis) {
        debug!(
            ?vni,
            ?mac,
            "EVPN originator: suppressing local-MAC replay for drained Ethernet Segment"
        );
        return;
    }
    let Some(inst) = instances.get(vni) else {
        return;
    };
    let Some(ifindex) = state
        .local_macs
        .get(&vni)
        .and_then(|m| m.get(&mac).copied())
    else {
        return;
    };
    let sticky = sticky_for(instances, vni, mac);
    let live_ips: Vec<IpAddr> = state
        .live_mac_ip
        .get(&vni)
        .and_then(|m| m.get(&mac))
        .map(|ips| ips.iter().copied().collect())
        .unwrap_or_default();
    if live_ips.is_empty() {
        let Some(orig) = state.mac_originators.get_mut(&vni) else {
            return;
        };
        let view = state.remote_mac_view.get(&(vni, mac));
        let actions = orig.on_local_learned(mac, ifindex, sticky, view);
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
        return;
    }
    let Some(orig) = state.mac_ip_originators.get_mut(&vni) else {
        return;
    };
    for ip in live_ips {
        let view = state.remote_mac_ip_view.get(&(vni, mac, ip));
        let actions = orig.on_local_ip_learned(mac, ip, sticky, view);
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
