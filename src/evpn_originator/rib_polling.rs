use super::{
    BTreeMap, BTreeSet, BgpMetrics, EthernetSegmentIdentifier, EvpnInstanceId, EvpnInstanceTable,
    EvpnRibRoute, EvpnRoute, EvpnRouteEvent, EvpnRouteKey, IpAddr, MacAddress,
    OriginatedLocalMacCounts, OriginatorState, PathAttribute, ProjectedEvpnRoute, RemoteMacIpView,
    RemoteMacIpViewMap, RemoteMacView, RemoteMacViewMap, RibQueryError, RibUpdate, broadcast, mpsc,
    oneshot, project_evpn_routes, warn,
};
use crate::evpn_originator::duplicate_mac::{
    apply_actions_with_duplicate_policy, outstanding_route_keys_for_mac,
    remote_route_processing_suppressed, suppress_local_originations_for_mac,
};

type StickyMacWinnerKey = (EvpnInstanceId, MacAddress, IpAddr, Option<u32>);

/// Subscribe to the RIB's EVPN route-event broadcast. Returns `None`
/// if the RIB channel is full / closed or if the reply was dropped —
/// the originator's 5 s poll backstop covers both cases.
pub(super) async fn subscribe_evpn_events(
    rib_tx: &mpsc::Sender<RibUpdate>,
) -> Option<broadcast::Receiver<EvpnRouteEvent>> {
    let (reply_tx, reply_rx) = oneshot::channel();
    rib_tx
        .send(RibUpdate::SubscribeEvpnRouteEvents { reply: reply_tx })
        .await
        .ok()?;
    reply_rx.await.ok()
}

/// Receive next event, or park forever if we never got a subscription
/// (poll-only mode). Parking on `pending` lets the surrounding
/// `tokio::select!` continue to service the other arms.
pub(super) async fn recv_evpn_event(
    rx: &mut Option<broadcast::Receiver<EvpnRouteEvent>>,
) -> Result<EvpnRouteEvent, broadcast::error::RecvError> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct ReadyEvpnEventDrain {
    /// Ready events consumed from the broadcast receiver after the triggering
    /// event. The triggering event itself is not included.
    pub(super) drained_events: usize,
    /// Number of lagged events reported while draining.
    pub(super) lagged_events: u64,
    /// Whether the broadcast channel closed while draining.
    pub(super) closed: bool,
}

pub(super) fn evpn_event_requires_repoll(event: &EvpnRouteEvent) -> bool {
    matches!(event.key, EvpnRouteKey::MacIp { .. })
}

pub(super) fn drain_ready_evpn_events(
    rx: &mut broadcast::Receiver<EvpnRouteEvent>,
) -> ReadyEvpnEventDrain {
    let mut drain = ReadyEvpnEventDrain::default();
    loop {
        match rx.try_recv() {
            Ok(_event) => {
                drain.drained_events += 1;
            }
            Err(broadcast::error::TryRecvError::Empty) => break,
            Err(broadcast::error::TryRecvError::Lagged(skipped)) => {
                drain.lagged_events = drain.lagged_events.saturating_add(skipped);
            }
            Err(broadcast::error::TryRecvError::Closed) => {
                drain.closed = true;
                break;
            }
        }
    }
    drain
}

/// Re-poll the RIB, build fresh contender views (both MAC-only and
/// MAC+IP), diff against the cached state, and fire
/// `on_remote_changed` / `on_remote_ip_changed` for any tracked
/// `(MAC)` or `(MAC, IP)` whose view changed.
#[allow(clippy::too_many_lines)] // MAC-only and MAC+IP diffs intentionally stay adjacent for symmetry.
pub(super) async fn repoll_rib(
    instances: &EvpnInstanceTable,
    rib_tx: &mpsc::Sender<RibUpdate>,
    state: &mut OriginatorState,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
) -> Result<(), RibQueryError> {
    let routes = query_evpn_routes(rib_tx).await?;
    let (new_mac_view, new_mac_ip_view) = build_remote_views(instances, &routes);
    let mut suppressed_remote_diffs: BTreeSet<(EvpnInstanceId, MacAddress)> = BTreeSet::new();

    // --- MAC-only contender diff ---
    let mut mac_affected: Vec<(EvpnInstanceId, MacAddress)> = Vec::new();
    for k in new_mac_view.keys() {
        if state.remote_mac_view.get(k) != new_mac_view.get(k) {
            mac_affected.push(*k);
        }
    }
    for k in state.remote_mac_view.keys() {
        if !new_mac_view.contains_key(k) {
            mac_affected.push(*k);
        }
    }
    for (vni, mac) in mac_affected {
        let Some(inst) = instances.get(vni) else {
            continue;
        };
        if remote_route_processing_suppressed(state, vni, mac) {
            suppressed_remote_diffs.insert((vni, mac));
            continue;
        }
        let view_present = new_mac_view.contains_key(&(vni, mac));
        let preexisting_keys = outstanding_route_keys_for_mac(state, vni, mac);
        let actions = {
            let view = new_mac_view.get(&(vni, mac));
            let Some(orig) = state.mac_originators.get_mut(&vni) else {
                continue;
            };
            orig.on_remote_changed(mac, view)
        };
        if actions.is_empty() {
            continue;
        }
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

    // --- MAC+IP contender diff ---
    let mut mac_ip_affected: Vec<(EvpnInstanceId, MacAddress, IpAddr)> = Vec::new();
    for k in new_mac_ip_view.keys() {
        if state.remote_mac_ip_view.get(k) != new_mac_ip_view.get(k) {
            mac_ip_affected.push(*k);
        }
    }
    for k in state.remote_mac_ip_view.keys() {
        if !new_mac_ip_view.contains_key(k) {
            mac_ip_affected.push(*k);
        }
    }
    for (vni, mac, ip) in mac_ip_affected {
        let Some(inst) = instances.get(vni) else {
            continue;
        };
        if remote_route_processing_suppressed(state, vni, mac) {
            suppressed_remote_diffs.insert((vni, mac));
            continue;
        }
        let view_present = new_mac_ip_view.contains_key(&(vni, mac, ip));
        let preexisting_keys = outstanding_route_keys_for_mac(state, vni, mac);
        let actions = {
            let view = new_mac_ip_view.get(&(vni, mac, ip));
            let Some(orig) = state.mac_ip_originators.get_mut(&vni) else {
                continue;
            };
            orig.on_remote_ip_changed(mac, ip, view)
        };
        if actions.is_empty() {
            continue;
        }
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

    for (vni, mac) in suppressed_remote_diffs {
        let Some(inst) = instances.get(vni) else {
            continue;
        };
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
    }

    state.remote_mac_view = new_mac_view;
    state.remote_mac_ip_view = new_mac_ip_view;
    Ok(())
}

/// React to a push-notified EVPN best-path change.
///
/// Each [`EvpnRouteEvent`] is keyed by the full [`EvpnRouteKey`]
/// (which includes RD), but the originator's `remote_view` is keyed
/// by `(VNI, MAC)`. The two key spaces are not 1:1 — multiple
/// PEs may advertise the same `(VNI, MAC)` under their own RDs (RFC
/// 7432 §7.9.5), and `crates/evpn::project_evpn_routes` picks the
/// per-`(VNI, MAC)` winner across **all** of them by mobility
/// sequence + next-hop. Applying a single event as a delta would
/// silently get this wrong:
///
///   - PE-A advertises seq=10, PE-B advertises seq=1 under another
///     RD. A PE-B Added event would overwrite the cached view with
///     the worse candidate.
///   - PE-B is the projected winner and PE-A withdraws. A PE-A
///     Withdrawn event would clear the cached view even though
///     PE-B's path still wins.
///
/// The conservative fix is to use the event purely as a wakeup
/// signal: any Type 2 event triggers a full [`repoll_rib`], which
/// re-runs the projection from scratch and converges on the right
/// answer without the originator trying to reimplement projection
/// state. This still meets the Gate 7c sub-second goal — the event
/// fires synchronously off `recompute_and_distribute_evpn`, well
/// inside the previous 5 s `poll_tick` window — at the cost of one
/// `QueryEvpnRoutes` round-trip per Type 2 event.
///
/// A future optimization can cache `BTreeMap<EvpnRouteKey,
/// RemoteMacView>` and recompute the projected `(VNI, MAC)` winner
/// from that cache on each event without a RIB query, but that
/// reimplements projection state and is deferred until measured to
/// matter.
///
/// Non-Type-2 events return early — the originator does not react
/// to Type 1/3/4/5 best-path changes today.
#[cfg(test)]
pub(super) async fn handle_evpn_event(
    event: &EvpnRouteEvent,
    instances: &EvpnInstanceTable,
    state: &mut OriginatorState,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
) {
    if !evpn_event_requires_repoll(event) {
        return;
    }
    if let Err(e) = repoll_rib(
        instances,
        rib_tx,
        state,
        metrics,
        originated_local_mac_counts,
        vni_to_esi,
    )
    .await
    {
        warn!(error = %e, "EVPN originator: event-triggered repoll failed");
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_evpn_event_coalesced(
    event: EvpnRouteEvent,
    rx: &mut Option<broadcast::Receiver<EvpnRouteEvent>>,
    instances: &EvpnInstanceTable,
    state: &mut OriginatorState,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
) {
    if !evpn_event_requires_repoll(&event) {
        return;
    }
    let drain = rx.as_mut().map(drain_ready_evpn_events).unwrap_or_default();
    if drain.lagged_events > 0 {
        warn!(
            skipped = drain.lagged_events,
            "EVPN originator: event broadcast lagged while coalescing; skipped events are absorbed by the authoritative full repoll"
        );
    }
    if drain.closed {
        warn!("EVPN originator: RIB event broadcast closed; reverting to poll-only");
        *rx = None;
    }
    if let Err(e) = repoll_rib(
        instances,
        rib_tx,
        state,
        metrics,
        originated_local_mac_counts,
        vni_to_esi,
    )
    .await
    {
        warn!(
            error = %e,
            coalesced_events = drain.drained_events,
            lagged_events = drain.lagged_events,
            "EVPN originator: event-triggered repoll failed"
        );
    }
}

fn sticky_by_mac_winner(
    projected: &[(ProjectedEvpnRoute, bool)],
) -> BTreeMap<StickyMacWinnerKey, bool> {
    let mut sticky_by_winner = BTreeMap::new();
    for (route, sticky) in projected {
        let raw_vni = route.label1.as_vni();
        if raw_vni == 0 {
            continue;
        }
        let Ok(vni) = rustbgpd_evpn::EvpnInstanceId::new(raw_vni) else {
            continue;
        };
        sticky_by_winner
            .entry((vni, route.mac, route.next_hop, route.mobility_sequence))
            .or_insert(*sticky);
    }
    sticky_by_winner
}

/// Build both contender maps from a flat set of best-path
/// `EvpnRibRoute`s. Drops self-NH routes per the module-level
/// "self-origination filter" rule.
///
/// MAC-only and MAC+IP are independent advertisements per RFC 9135
/// §7.2.3, so the two maps are constructed independently:
///
/// - `RemoteMacViewMap` — the existing per-`(VNI, MAC)` view; reuses
///   `project_evpn_routes` which collapses by `(VNI, MAC)`.
/// - `RemoteMacIpViewMap` — per-`(VNI, MAC, IP)` view for MAC+IP
///   contention; built inline because `project_evpn_routes`
///   intentionally drops the IP. Same self-NH filter, same RFC §15.1
///   tiebreak (higher seq → lower `next_hop` on ties).
pub(super) fn build_remote_views(
    instances: &EvpnInstanceTable,
    routes: &[EvpnRibRoute],
) -> (RemoteMacViewMap, RemoteMacIpViewMap) {
    let projected: Vec<(ProjectedEvpnRoute, bool)> = routes
        .iter()
        .filter_map(|r| {
            let EvpnRoute::MacIp(macip) = &r.route else {
                return None;
            };
            let (sticky, seq) = extract_mac_mobility_full(&r.attributes);
            Some((
                ProjectedEvpnRoute {
                    rd: macip.rd,
                    mac: macip.mac,
                    host_ip: macip.ip,
                    label1: macip.label1,
                    next_hop: r.next_hop,
                    mobility_sequence: seq,
                    esi: macip.esi,
                    ethernet_tag: macip.ethernet_tag,
                },
                sticky,
            ))
        })
        .collect();
    let sticky_by_winner = sticky_by_mac_winner(&projected);

    // --- MAC-only map (collapses to per-(VNI, MAC) winner) ---
    let table = project_evpn_routes(instances, projected.iter().map(|(p, _)| p.clone()));
    let mut mac_view: RemoteMacViewMap = BTreeMap::new();
    for ((vni, mac), entry) in table.iter() {
        let sticky = sticky_by_winner
            .get(&(*vni, *mac, entry.remote_vtep_ip, entry.mobility_sequence))
            .copied()
            .unwrap_or(false);
        mac_view.insert(
            (*vni, *mac),
            RemoteMacView {
                mac: *mac,
                mobility_sequence: entry.mobility_sequence,
                sticky,
                next_hop: entry.remote_vtep_ip,
            },
        );
    }

    // --- MAC+IP map (per-(VNI, MAC, IP) winner) ---
    //
    // Walk the projected set, drop self-NH and IP-less rows, group
    // by (VNI, MAC, IP), keep the contender with the highest
    // mobility seq (None < Some(0); ties broken by lower next_hop).
    let mut staged: BTreeMap<(EvpnInstanceId, MacAddress, IpAddr), &(ProjectedEvpnRoute, bool)> =
        BTreeMap::new();
    for tup in &projected {
        let p = &tup.0;
        let Some(ip) = p.host_ip else {
            continue;
        };
        let raw_vni = p.label1.as_vni();
        if raw_vni == 0 {
            continue;
        }
        let Ok(vni) = rustbgpd_evpn::EvpnInstanceId::new(raw_vni) else {
            continue;
        };
        let Some(local_inst) = instances.get(vni) else {
            continue;
        };
        if p.next_hop == local_inst.local_vtep_ip {
            continue;
        }
        let key = (vni, p.mac, ip);
        match staged.get(&key) {
            None => {
                staged.insert(key, tup);
            }
            Some(existing) => {
                if prefer_mac_ip_new(p, &existing.0) {
                    staged.insert(key, tup);
                }
            }
        }
    }

    let mut mac_ip_view: RemoteMacIpViewMap = BTreeMap::new();
    for ((vni, mac, ip), tup) in staged {
        let p = &tup.0;
        let sticky = tup.1;
        mac_ip_view.insert(
            (vni, mac, ip),
            RemoteMacIpView {
                mac,
                ip,
                mobility_sequence: p.mobility_sequence,
                sticky,
                next_hop: p.next_hop,
            },
        );
    }

    (mac_view, mac_ip_view)
}

/// MAC+IP contender tiebreak — same shape as
/// `crates/evpn::projection::prefer_new`: higher mobility seq wins,
/// then lower `next_hop`. Inlined here because that function is
/// crate-private to `rustbgpd-evpn`.
pub(super) fn prefer_mac_ip_new(new: &ProjectedEvpnRoute, existing: &ProjectedEvpnRoute) -> bool {
    match new.mobility_sequence.cmp(&existing.mobility_sequence) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => new.next_hop < existing.next_hop,
    }
}

/// Extract `(sticky, mobility_seq)` from a route's path attributes.
pub(super) fn extract_mac_mobility_full(attrs: &[PathAttribute]) -> (bool, Option<u32>) {
    for attr in attrs {
        let PathAttribute::ExtendedCommunities(ecs) = attr else {
            continue;
        };
        for ec in ecs {
            if let Some((sticky, seq)) = ec.as_mac_mobility() {
                return (sticky, Some(seq));
            }
        }
    }
    (false, None)
}

pub(super) async fn query_evpn_routes(
    rib_tx: &mpsc::Sender<RibUpdate>,
) -> Result<Vec<EvpnRibRoute>, RibQueryError> {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    rib_tx
        .send(RibUpdate::QueryEvpnRoutes { reply: reply_tx })
        .await
        .map_err(|_| RibQueryError::SendFailed)?;
    reply_rx.await.map_err(|_| RibQueryError::ReplyDropped)
}
