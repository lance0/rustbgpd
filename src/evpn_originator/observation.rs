use super::{
    Arc, BgpMetrics, EthernetSegmentIdentifier, EvpnInstanceId, EvpnInstanceTable, IpAddr,
    LocalMacObservation, MacAddress, OriginatedLocalMacCounts, OriginatorState, RibUpdate, debug,
    mpsc,
};
use crate::evpn_originator::duplicate_mac::{
    apply_actions_with_duplicate_policy, duplicate_mac_is_quarantined,
    outstanding_route_keys_for_mac, sticky_for, suppress_local_originations_for_mac,
};
use crate::evpn_originator::rib_write::apply_actions;

/// Dispatch a single observation from the kernel observation feed.
///
/// Implements the FRR-style **replace model** for MAC vs MAC+IP
/// (Gate 7b+2): at any time at most one of `(MAC-only, MAC+IP)` is
/// advertising for a given MAC. Receiving an `IpAdded` for a MAC
/// that's currently MAC-only-advertising **withdraws** the MAC-only
/// route and emits a MAC+IP route in its place. Receiving the last
/// `IpRemoved` for a MAC drops it back to MAC-only.
///
/// See `docs/RFC_NOTES.md` for the RFC 9135 §7.2.3 framing and the
/// FRR mailing-list bugs that motivated this model.
#[allow(clippy::too_many_arguments)] // ADR-0084 drain gate nudged the count over the threshold; refactoring to a context struct is a separate slice.
pub(super) async fn handle_observation(
    obs: &LocalMacObservation,
    state: &mut OriginatorState,
    instances: &Arc<EvpnInstanceTable>,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
    drained_esis: &std::collections::BTreeSet<EthernetSegmentIdentifier>,
) {
    // ADR-0084: while a VNI's mapped Ethernet Segment is operator-
    // drained, fresh kernel events must not (re-)originate routes —
    // but the local observation caches must keep tracking them so an
    // undrain replays the latest kernel state, not a stale snapshot.
    let obs_vni = match *obs {
        LocalMacObservation::Learned { vni, .. }
        | LocalMacObservation::Aged { vni, .. }
        | LocalMacObservation::IpAdded { vni, .. }
        | LocalMacObservation::IpRemoved { vni, .. }
        | LocalMacObservation::ObservedOnVxlanPort { vni, .. } => vni,
    };
    if super::vni_is_drained(obs_vni, vni_to_esi, drained_esis) {
        debug!(
            vni = ?obs_vni,
            "EVPN originator: caching kernel observation for drained Ethernet Segment without origination"
        );
        handle_observation_while_drained(obs, state);
        return;
    }
    match *obs {
        LocalMacObservation::Learned { vni, mac, ifindex } => {
            handle_learned(
                vni,
                mac,
                ifindex,
                state,
                instances,
                rib_tx,
                metrics,
                originated_local_mac_counts,
                vni_to_esi,
            )
            .await;
        }
        LocalMacObservation::Aged { vni, mac } => {
            handle_aged(
                vni,
                mac,
                state,
                instances,
                rib_tx,
                metrics,
                originated_local_mac_counts,
                vni_to_esi,
            )
            .await;
        }
        LocalMacObservation::IpAdded { vni, mac, ip } => {
            handle_ip_added(
                vni,
                mac,
                ip,
                state,
                instances,
                rib_tx,
                metrics,
                originated_local_mac_counts,
                vni_to_esi,
            )
            .await;
        }
        LocalMacObservation::IpRemoved { vni, mac, ip } => {
            handle_ip_removed(
                vni,
                mac,
                ip,
                state,
                instances,
                rib_tx,
                metrics,
                originated_local_mac_counts,
                vni_to_esi,
            )
            .await;
        }
        LocalMacObservation::ObservedOnVxlanPort { vni, mac } => {
            // Only meaningful for a MAC we currently claim as local:
            // the bridge FDB holds one row per (bridge, MAC, VLAN),
            // so the kernel moving the row to the VXLAN port means
            // it no longer holds the MAC on the AC port — the local
            // claim is stale and the Type 2 must come down. Rows for
            // MACs we never claimed are remote-MAC programming
            // (ours or a foreign controller's, stamped or not) and
            // are not a local state change — acting on them would
            // misread foreign state (ADR-0054).
            if !state
                .local_macs
                .get(&vni)
                .is_some_and(|m| m.contains_key(&mac))
            {
                return;
            }
            debug!(
                ?vni,
                ?mac,
                "EVPN originator: locally-claimed MAC moved to the VXLAN port in place — \
                 treating as local-gone"
            );
            // Same effect as a kernel age/delete: withdraw MAC-only
            // and MAC+IP routes, drop the local caches. The
            // originator's per-MAC entry survives, so a later
            // re-learn on the AC port keeps the RFC 7432 §15
            // mobility-sequence ratchet.
            handle_aged(
                vni,
                mac,
                state,
                instances,
                rib_tx,
                metrics,
                originated_local_mac_counts,
                vni_to_esi,
            )
            .await;
        }
    }
}

/// Cache-only observation handling for a drained VNI (ADR-0084):
/// mirrors the cache bookkeeping of the live handlers without ever
/// touching the origination state machines (they hold no outstanding
/// routes while drained, and must stay that way).
fn handle_observation_while_drained(obs: &LocalMacObservation, state: &mut OriginatorState) {
    match *obs {
        LocalMacObservation::Learned { vni, mac, ifindex } => {
            state
                .local_macs
                .entry(vni)
                .or_default()
                .insert(mac, ifindex);
            // Drain pending IP bindings straight into the live cache —
            // the live handler would have advertised MAC+IP for them;
            // the undrain replay will.
            if let Some(pending) = state.pending_ip_bindings.remove(&(vni, mac)) {
                state
                    .live_mac_ip
                    .entry(vni)
                    .or_default()
                    .entry(mac)
                    .or_default()
                    .extend(pending);
            }
        }
        LocalMacObservation::Aged { vni, mac } => {
            drop_local_mac_caches(state, vni, mac);
        }
        LocalMacObservation::ObservedOnVxlanPort { vni, mac } => {
            // The M66 incident shape: while the VNI's ES is drained,
            // the ES peer's Type 2 for a still-cached local MAC gets
            // programmed onto our bridge, and the kernel moves the
            // FDB row to the VXLAN port in place. The kernel no
            // longer holds the MAC locally, so the cache must drop
            // it — otherwise a later undrain replays a Type 2 for a
            // MAC we don't have (a stale claim, violating ADR-0084
            // decision 1's "undrain replays the latest kernel
            // state"). MACs we never claimed stay untouched (foreign
            // or plain remote programming, not a local change).
            let claimed = state
                .local_macs
                .get(&vni)
                .is_some_and(|m| m.contains_key(&mac));
            if claimed {
                drop_local_mac_caches(state, vni, mac);
            }
        }
        LocalMacObservation::IpAdded { vni, mac, ip } => {
            let mac_is_local = state
                .local_macs
                .get(&vni)
                .is_some_and(|m| m.contains_key(&mac));
            if mac_is_local {
                state
                    .live_mac_ip
                    .entry(vni)
                    .or_default()
                    .entry(mac)
                    .or_default()
                    .insert(ip);
            } else {
                state
                    .pending_ip_bindings
                    .entry((vni, mac))
                    .or_default()
                    .insert(ip);
            }
        }
        LocalMacObservation::IpRemoved { vni, mac, ip } => {
            if let Some(set) = state.pending_ip_bindings.get_mut(&(vni, mac)) {
                set.remove(&ip);
                if set.is_empty() {
                    state.pending_ip_bindings.remove(&(vni, mac));
                }
            }
            if let Some(per_vni) = state.live_mac_ip.get_mut(&vni)
                && let Some(ips) = per_vni.get_mut(&mac)
            {
                ips.remove(&ip);
                if ips.is_empty() {
                    per_vni.remove(&mac);
                }
            }
        }
    }
}

/// Drop every local-claim cache entry for `(vni, mac)`: the kernel no
/// longer holds the MAC on a local AC port. Shared by [`handle_aged`]
/// and the drained `Aged` / drained `ObservedOnVxlanPort` arms.
fn drop_local_mac_caches(state: &mut OriginatorState, vni: EvpnInstanceId, mac: MacAddress) {
    if let Some(per_vni) = state.local_macs.get_mut(&vni) {
        per_vni.remove(&mac);
    }
    state.pending_ip_bindings.remove(&(vni, mac));
    if let Some(per_vni) = state.live_mac_ip.get_mut(&vni) {
        per_vni.remove(&mac);
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) async fn handle_learned(
    vni: EvpnInstanceId,
    mac: MacAddress,
    ifindex: u32,
    state: &mut OriginatorState,
    instances: &Arc<EvpnInstanceTable>,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
) {
    let Some(inst) = instances.get(vni) else {
        debug!(?vni, ?mac, "Learned for unknown VNI — dropping");
        return;
    };
    state
        .local_macs
        .entry(vni)
        .or_default()
        .insert(mac, ifindex);
    let sticky = sticky_for(instances, vni, mac);

    // Drain any pending IP bindings for this MAC. Their presence
    // bypasses the MAC-only inject — we go straight to MAC+IP per
    // the FRR replace model.
    let pending_ips: Vec<IpAddr> = state
        .pending_ip_bindings
        .remove(&(vni, mac))
        .map(|s| s.into_iter().collect())
        .unwrap_or_default();
    let quarantined = duplicate_mac_is_quarantined(state, vni, mac);

    if pending_ips.is_empty() {
        // No IP bindings yet. Two sub-cases:
        //
        //   1. MAC was previously MAC-only (or never advertised) —
        //      re-emit MAC-only via the originator. `on_local_learned`
        //      is idempotent on identity and handles the port-move
        //      ratchet bump if `ifindex` differs from the prior call.
        //   2. MAC is currently MAC+IP-advertising. The kernel re-emit
        //      is just AF_BRIDGE FDB churn; emitting a MAC-only Inject would
        //      re-introduce the route the IpAdded handler explicitly
        //      withdrew, breaking the replace invariant ("at any time
        //      at most one of {MAC-only, MAC+IP} is advertising").
        //      The `local_macs[vni][mac] = ifindex` update above is
        //      what matters — a future downgrade replays it.
        if state.is_mac_ip_advertising(vni, mac) || state.has_live_mac_ip_bindings(vni, mac) {
            return;
        }
        if quarantined {
            suppress_local_originations_for_mac(
                vni,
                mac,
                state,
                inst,
                None,
                rib_tx,
                metrics,
                originated_local_mac_counts,
                vni_to_esi,
            )
            .await;
            return;
        }
        let preexisting_keys = outstanding_route_keys_for_mac(state, vni, mac);
        let Some(orig) = state.mac_originators.get_mut(&vni) else {
            return;
        };
        let view = state.remote_mac_view.get(&(vni, mac));
        let actions = orig.on_local_learned(mac, ifindex, sticky, view);
        apply_actions_with_duplicate_policy(
            actions,
            view.is_some(),
            preexisting_keys,
            vni,
            mac,
            state,
            inst,
            rib_tx,
            metrics,
            originated_local_mac_counts,
            vni_to_esi,
        )
        .await;
    } else {
        if quarantined {
            for ip in pending_ips {
                state
                    .live_mac_ip
                    .entry(vni)
                    .or_default()
                    .entry(mac)
                    .or_default()
                    .insert(ip);
            }
            suppress_local_originations_for_mac(
                vni,
                mac,
                state,
                inst,
                None,
                rib_tx,
                metrics,
                originated_local_mac_counts,
                vni_to_esi,
            )
            .await;
            return;
        }
        // Pending IPs exist — go straight to MAC+IP. Drop any stale
        // MAC-only from the originator state (idempotent if we never
        // advertised MAC-only).
        let Some(mac_orig) = state.mac_originators.get_mut(&vni) else {
            return;
        };
        let mac_only_actions = mac_orig.on_local_aged(mac);
        apply_actions(
            mac_only_actions,
            inst,
            rib_tx,
            metrics,
            originated_local_mac_counts,
            vni_to_esi,
        )
        .await;

        for ip in pending_ips {
            if duplicate_mac_is_quarantined(state, vni, mac) {
                state
                    .live_mac_ip
                    .entry(vni)
                    .or_default()
                    .entry(mac)
                    .or_default()
                    .insert(ip);
                continue;
            }
            let view_present = state.remote_mac_ip_view.contains_key(&(vni, mac, ip));
            let preexisting_keys = outstanding_route_keys_for_mac(state, vni, mac);
            let actions = {
                let view = state.remote_mac_ip_view.get(&(vni, mac, ip));
                let Some(mac_ip_orig) = state.mac_ip_originators.get_mut(&vni) else {
                    return;
                };
                mac_ip_orig.on_local_ip_learned(mac, ip, sticky, view)
            };
            apply_actions_with_duplicate_policy(
                actions,
                view_present,
                preexisting_keys,
                vni,
                mac,
                state,
                inst,
                rib_tx,
                metrics,
                originated_local_mac_counts,
                vni_to_esi,
            )
            .await;
            state
                .live_mac_ip
                .entry(vni)
                .or_default()
                .entry(mac)
                .or_default()
                .insert(ip);
        }
    }
}

#[allow(clippy::too_many_arguments)] // ESI-aware origination nudged the count over the threshold; refactoring to a context struct is a separate slice.
pub(super) async fn handle_aged(
    vni: EvpnInstanceId,
    mac: MacAddress,
    state: &mut OriginatorState,
    instances: &Arc<EvpnInstanceTable>,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
) {
    let Some(inst) = instances.get(vni) else {
        return;
    };
    drop_local_mac_caches(state, vni, mac);

    // Withdraw both MAC-only and any MAC+IP routes for this MAC.
    // At most one set is non-empty under the replace model, but
    // cascading both is safe (each emits empty if not advertising).
    if let Some(mac_orig) = state.mac_originators.get_mut(&vni) {
        let actions = mac_orig.on_local_aged(mac);
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
    if let Some(mac_ip_orig) = state.mac_ip_originators.get_mut(&vni) {
        let actions = mac_ip_orig.on_local_mac_aged(mac);
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

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_ip_added(
    vni: EvpnInstanceId,
    mac: MacAddress,
    ip: IpAddr,
    state: &mut OriginatorState,
    instances: &Arc<EvpnInstanceTable>,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
) {
    let Some(inst) = instances.get(vni) else {
        return;
    };
    let mac_is_local = state
        .local_macs
        .get(&vni)
        .is_some_and(|m| m.contains_key(&mac));
    if !mac_is_local {
        // Park until the MAC surfaces. AF_INET / AF_INET6 NEIGH
        // can race AF_BRIDGE FDB during cold start.
        debug!(
            ?vni,
            ?mac,
            ?ip,
            "IpAdded for MAC not yet locally learned — parking in pending_ip_bindings"
        );
        state
            .pending_ip_bindings
            .entry((vni, mac))
            .or_default()
            .insert(ip);
        return;
    }

    let sticky = sticky_for(instances, vni, mac);
    let was_mac_only = !state.is_mac_ip_advertising(vni, mac);
    if duplicate_mac_is_quarantined(state, vni, mac) {
        state
            .live_mac_ip
            .entry(vni)
            .or_default()
            .entry(mac)
            .or_default()
            .insert(ip);
        suppress_local_originations_for_mac(
            vni,
            mac,
            state,
            inst,
            None,
            rib_tx,
            metrics,
            originated_local_mac_counts,
            vni_to_esi,
        )
        .await;
        return;
    }

    // Replace model: if MAC-only is currently advertising, withdraw
    // it before emitting MAC+IP. on_local_aged is idempotent if not
    // advertising.
    if was_mac_only && let Some(mac_orig) = state.mac_originators.get_mut(&vni) {
        let actions = mac_orig.on_local_aged(mac);
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

    let view_present = state.remote_mac_ip_view.contains_key(&(vni, mac, ip));
    let preexisting_keys = outstanding_route_keys_for_mac(state, vni, mac);
    let actions = {
        let view = state.remote_mac_ip_view.get(&(vni, mac, ip));
        let Some(mac_ip_orig) = state.mac_ip_originators.get_mut(&vni) else {
            return;
        };
        mac_ip_orig.on_local_ip_learned(mac, ip, sticky, view)
    };
    apply_actions_with_duplicate_policy(
        actions,
        view_present,
        preexisting_keys,
        vni,
        mac,
        state,
        inst,
        rib_tx,
        metrics,
        originated_local_mac_counts,
        vni_to_esi,
    )
    .await;
    state
        .live_mac_ip
        .entry(vni)
        .or_default()
        .entry(mac)
        .or_default()
        .insert(ip);
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_ip_removed(
    vni: EvpnInstanceId,
    mac: MacAddress,
    ip: IpAddr,
    state: &mut OriginatorState,
    instances: &Arc<EvpnInstanceTable>,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
) {
    let Some(inst) = instances.get(vni) else {
        return;
    };

    // Drop pending entry if the MAC never surfaced — there's no
    // route to withdraw.
    if let Some(set) = state.pending_ip_bindings.get_mut(&(vni, mac)) {
        set.remove(&ip);
        if set.is_empty() {
            state.pending_ip_bindings.remove(&(vni, mac));
        }
    }

    // Withdraw the MAC+IP route for this specific (mac, ip).
    let Some(mac_ip_orig) = state.mac_ip_originators.get_mut(&vni) else {
        return;
    };
    let actions = mac_ip_orig.on_local_ip_aged(mac, ip);
    apply_actions(
        actions,
        inst,
        rib_tx,
        metrics,
        originated_local_mac_counts,
        vni_to_esi,
    )
    .await;

    // Update live cache. If this was the last IP for the MAC AND the
    // MAC is still locally learned, downgrade back to MAC-only by
    // re-emitting via the MAC-only originator.
    let mut empty_after = false;
    if let Some(per_vni) = state.live_mac_ip.get_mut(&vni)
        && let Some(ips) = per_vni.get_mut(&mac)
    {
        ips.remove(&ip);
        if ips.is_empty() {
            per_vni.remove(&mac);
            empty_after = true;
        }
    }

    let ifindex_for_mac = state
        .local_macs
        .get(&vni)
        .and_then(|m| m.get(&mac).copied());
    if empty_after && let Some(ifindex) = ifindex_for_mac {
        if duplicate_mac_is_quarantined(state, vni, mac) {
            suppress_local_originations_for_mac(
                vni,
                mac,
                state,
                inst,
                None,
                rib_tx,
                metrics,
                originated_local_mac_counts,
                vni_to_esi,
            )
            .await;
            return;
        }
        let sticky = sticky_for(instances, vni, mac);
        let view_present = state.remote_mac_view.contains_key(&(vni, mac));
        let preexisting_keys = outstanding_route_keys_for_mac(state, vni, mac);
        let actions = {
            let view = state.remote_mac_view.get(&(vni, mac));
            let Some(mac_orig) = state.mac_originators.get_mut(&vni) else {
                return;
            };
            // Replay the original ifindex so MAC-only's port-move
            // detection stays anchored to the real bridge port —
            // a downgrade isn't a port move and shouldn't ratchet up.
            mac_orig.on_local_learned(mac, ifindex, sticky, view)
        };
        apply_actions_with_duplicate_policy(
            actions,
            view_present,
            preexisting_keys,
            vni,
            mac,
            state,
            inst,
            rib_tx,
            metrics,
            originated_local_mac_counts,
            vni_to_esi,
        )
        .await;
    }
}
