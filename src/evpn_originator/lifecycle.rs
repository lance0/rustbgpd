use super::{
    Arc, BTreeMap, BgpMetrics, DuplicateMacKey, EvpnInstanceId, LocalMacIpOriginator,
    LocalMacOriginator, LocalMacReplaySet, OriginatorRuntime, OriginatorRuntimeModel,
    OriginatorState, debug, warn,
};
use crate::evpn_originator::duplicate_mac::{
    duplicate_mac_is_quarantined, publish_duplicate_mac_quarantines,
    replay_local_mac_after_recovery,
};
use crate::evpn_originator::rib_polling::repoll_rib;
use crate::evpn_originator::rib_write::drain_vni_to_withdraws;

#[allow(clippy::too_many_lines)] // classification + drain + replay are one ordered sequence; splitting hurts the lifecycle story
pub(super) async fn apply_runtime_model(
    model: Arc<OriginatorRuntimeModel>,
    state: &mut OriginatorState,
    runtime: &mut OriginatorRuntime,
) {
    // Classify currently-known VNIs against the candidate model:
    //  - removed (instance gone from the candidate): full drain + state
    //    clear, the same as a delete.
    //  - redefined (instance present but content changed, e.g. a new RD):
    //    drain the stale routes under the old fields, then rebuild only the
    //    RD-bound originators while preserving the local observation caches so
    //    the routes re-originate under the new fields. Without this a redefine
    //    would withdraw the VNI's local Type 2 routes and never re-advertise
    //    them until the next kernel local-MAC event.
    //  - ESI-map changed only (instance identical, vni_to_esi differs):
    //    drain the stale routes but preserve and replay the cached local
    //    MAC/IP state so it re-originates under the new ESI.
    //  - drain-status changed only (ADR-0084; instance and ESI mapping
    //    identical, the mapped ESI entered/left the operator-drained set):
    //    newly drained → withdraw the advertised routes but PRESERVE the
    //    local observation caches and do NOT replay (this is the
    //    drain-without-replay primitive); newly undrained → replay the
    //    cached local MAC/IP state (nothing to drain — already withdrawn).
    let mut removed: Vec<EvpnInstanceId> = Vec::new();
    let mut redefined: Vec<EvpnInstanceId> = Vec::new();
    let mut esi_only_changed: Vec<EvpnInstanceId> = Vec::new();
    let mut newly_drained: Vec<EvpnInstanceId> = Vec::new();
    let mut newly_undrained: Vec<EvpnInstanceId> = Vec::new();
    for old in runtime.instances.iter() {
        let was_drained = super::vni_is_drained(old.id, &runtime.vni_to_esi, &runtime.drained_esis);
        let now_drained = super::vni_is_drained(old.id, &model.vni_to_esi, &model.drained_esis);
        match model.instances.get(old.id) {
            Some(next) if next == old => {
                if runtime.vni_to_esi.get(&old.id) != model.vni_to_esi.get(&old.id) {
                    esi_only_changed.push(old.id);
                } else if !was_drained && now_drained {
                    newly_drained.push(old.id);
                } else if was_drained && !now_drained {
                    newly_undrained.push(old.id);
                }
            }
            Some(_) => redefined.push(old.id),
            None => removed.push(old.id),
        }
    }

    // Snapshot replay keys before the drain clears each advertised route.
    // Redefine and ESI-only changes both keep the local observation caches
    // (local MAC/IP, pending IP bindings, remote views) and replay their local
    // MACs under the new instance fields. ESI-only changes also keep the
    // duplicate-MAC detector/quarantine state (the instance is identical); a
    // redefine drops it below as part of the ADR-0063 delete-old + add-new
    // contract. Only a true delete uses the full VNI state purge below.
    //
    // ADR-0084: a VNI that is drained under the NEW model never replays —
    // even when its instance was redefined or its ESI mapping changed in
    // the same publish. Undrained VNIs replay their preserved caches.
    let mut replay_local_macs: LocalMacReplaySet = BTreeMap::new();
    for &vni in redefined
        .iter()
        .chain(esi_only_changed.iter())
        .chain(newly_undrained.iter())
    {
        if super::vni_is_drained(vni, &model.vni_to_esi, &model.drained_esis) {
            debug!(
                ?vni,
                "EVPN originator: VNI drained under new model — withdrawing without replay"
            );
            continue;
        }
        let macs = state
            .local_macs
            .get(&vni)
            .map(|per_vni| per_vni.keys().copied().collect())
            .unwrap_or_default();
        replay_local_macs.insert(vni, macs);
    }

    // Drain advertised routes for every VNI that is leaving or changing,
    // using the still-current (old) instance table so withdraws carry the
    // committed RD.
    for vni in removed
        .iter()
        .chain(redefined.iter())
        .chain(esi_only_changed.iter())
        .chain(newly_drained.iter())
        .copied()
    {
        drain_vni_to_withdraws(
            state,
            runtime.instances.as_ref(),
            vni,
            &runtime.rib_tx,
            &runtime.metrics,
            &runtime.originated_local_mac_counts,
            runtime.vni_to_esi.as_ref(),
        )
        .await;
    }
    // A true delete drops every per-VNI state. A redefine keeps the local
    // observation caches (so the replay below re-originates the MACs) but
    // drops the RD-bound origination state machines (so they rebuild under the
    // candidate's new fields) and the duplicate-MAC detector / quarantine state
    // (delete-old + add-new per ADR-0063). Dropping the quarantine is also what
    // lets a redefine that disables suppression actually replay the MAC instead
    // of leaving it stuck quarantined.
    for vni in removed.iter().copied() {
        remove_vni_state(state, vni, &runtime.metrics);
    }
    for vni in &redefined {
        state.mac_originators.remove(vni);
        state.mac_ip_originators.remove(vni);
        clear_duplicate_mac_state(state, *vni, &runtime.metrics);
    }

    for inst in model.instances.iter() {
        state
            .mac_originators
            .entry(inst.id)
            .or_insert_with(|| LocalMacOriginator::new(inst.id, inst.rd));
        state
            .mac_ip_originators
            .entry(inst.id)
            .or_insert_with(|| LocalMacIpOriginator::new(inst.id, inst.rd));
    }

    runtime.instances = model.instances.clone();
    runtime.vni_to_esi = model.vni_to_esi.clone();
    runtime.drained_esis = model.drained_esis.clone();

    if let Err(e) = repoll_rib(
        runtime.instances.as_ref(),
        &runtime.rib_tx,
        state,
        &runtime.metrics,
        &runtime.originated_local_mac_counts,
        runtime.vni_to_esi.as_ref(),
    )
    .await
    {
        warn!(error = %e, "EVPN originator: runtime model repoll failed");
    }

    // Replay the preserved local MAC/IP state under the new ESI map. This
    // runs after `repoll_rib` so the remote contender view is current and
    // mobility sequencing is correct. Without this, an ESI-map change would
    // withdraw the member VNI's local Type 2 routes and never re-originate
    // them until the next kernel local-MAC event.
    for (vni, macs) in replay_local_macs {
        for mac in macs {
            if duplicate_mac_is_quarantined(state, vni, mac) {
                debug!(
                    ?vni,
                    ?mac,
                    "EVPN originator: preserving duplicate-MAC suppression across ESI-map change"
                );
                continue;
            }
            replay_local_mac_after_recovery(
                vni,
                mac,
                state,
                runtime.instances.as_ref(),
                &runtime.rib_tx,
                &runtime.metrics,
                &runtime.originated_local_mac_counts,
                runtime.vni_to_esi.as_ref(),
                runtime.drained_esis.as_ref(),
            )
            .await;
        }
    }
}

pub(super) fn remove_vni_state(
    state: &mut OriginatorState,
    vni: EvpnInstanceId,
    metrics: &BgpMetrics,
) {
    state.mac_originators.remove(&vni);
    state.mac_ip_originators.remove(&vni);
    state.local_macs.remove(&vni);
    state.live_mac_ip.remove(&vni);
    state
        .pending_ip_bindings
        .retain(|(binding_vni, _), _| *binding_vni != vni);
    state
        .remote_mac_view
        .retain(|(route_vni, _), _| *route_vni != vni);
    state
        .remote_mac_ip_view
        .retain(|(route_vni, _, _), _| *route_vni != vni);

    clear_duplicate_mac_state(state, vni, metrics);
}

/// Drop all RFC 7432 §15.1 duplicate-MAC detector windows, known keys, and
/// active local-origin quarantines for one VNI, decrementing the per-key
/// quarantine gauge and republishing the receive-side suppression set. Shared
/// by the full delete purge ([`remove_vni_state`]) and by L2VNI redefine,
/// which drops duplicate-MAC state (delete-old + add-new) while preserving the
/// local observation caches.
pub(super) fn clear_duplicate_mac_state(
    state: &mut OriginatorState,
    vni: EvpnInstanceId,
    metrics: &BgpMetrics,
) {
    let removed_duplicate_mac_keys: Vec<DuplicateMacKey> = state
        .known_duplicate_mac_keys
        .iter()
        .copied()
        .filter(|key| key.vni == vni)
        .collect();
    for key in removed_duplicate_mac_keys {
        state.duplicate_mac_detector.clear(key);
        state.known_duplicate_mac_keys.remove(&key);
        if state.active_duplicate_mac_quarantines.remove(&key) {
            metrics.set_evpn_duplicate_mac_quarantine_active(
                key.vni.as_u32(),
                &key.mac.to_string(),
                false,
            );
        }
    }
    publish_duplicate_mac_quarantines(
        &state.duplicate_mac_quarantine_tx,
        &state.active_duplicate_mac_quarantines,
    );
}
