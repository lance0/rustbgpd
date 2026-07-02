use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use rustbgpd_policy::{
    PolicyAction, PolicyChain, PolicyEvaluation, RouteContext, RouteType,
    evaluate_chain_with_attribution,
};
use rustbgpd_rpki::VrpTable;
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{
    AddressPrefixOrf, Afi, FlowSpecRule, OrfAction, OrfMatch, Prefix, RouteRefreshSubtype, Safi,
    WhenToRefresh,
};
use tracing::{debug, info, warn};

use super::helpers::{
    LOCAL_PEER, bgpls_routes_equal, evpn_routes_equal, gauge_val, prefix_family, routes_equal,
    rtc_routes_equal, should_suppress_ibgp_inner, validate_route_aspa, validate_route_rpki,
    vpn_routes_equal,
};
use super::{PendingRouteChunk, PendingRoutesReceived, PolicyFilteredRouteKey, RibManager};
use crate::adj_rib_in::AdjRibIn;
use crate::adj_rib_out::AdjRibOut;
use crate::event::{RouteEvent, RouteEventType};
use crate::loc_rib::LocRib;
use crate::update::{
    ExplainAdvertisedRoute, ExplainDecision, ExplainReason, NeighborPolicyStats,
    OutboundRouteUpdate, RibCommandError,
};

mod bgpls;
mod evpn;
mod flowspec;
mod rtc;
mod unicast;
mod vpn;

fn route_type(origin: crate::route::RouteOrigin) -> RouteType {
    match origin {
        crate::route::RouteOrigin::Local => RouteType::Local,
        crate::route::RouteOrigin::Ibgp => RouteType::Internal,
        crate::route::RouteOrigin::Ebgp => RouteType::External,
    }
}

fn route_type_label(route_type: RouteType) -> &'static str {
    match route_type {
        RouteType::Local => "local_route",
        RouteType::Internal => "ibgp_route",
        RouteType::External => "ebgp_route",
    }
}

fn route_type_message(route_type: RouteType) -> &'static str {
    match route_type {
        RouteType::Local => "best route is locally originated",
        RouteType::Internal => "best route was learned from an iBGP peer",
        RouteType::External => "best route was learned from an eBGP peer",
    }
}

fn record_export_policy_eval(
    metrics: &BgpMetrics,
    stats: &mut NeighborPolicyStats,
    peer_label: &str,
    evaluation: &PolicyEvaluation,
) {
    let policy = evaluation.matched_policy.as_deref().unwrap_or("inline");
    let action = match evaluation.action {
        PolicyAction::Permit => {
            stats.export_policy_routes_permitted =
                stats.export_policy_routes_permitted.saturating_add(1);
            "permit"
        }
        PolicyAction::Deny => {
            stats.export_policy_routes_denied = stats.export_policy_routes_denied.saturating_add(1);
            "deny"
        }
    };
    metrics.record_policy_routes(peer_label, policy, "export", action);
}

impl RibManager {
    #[expect(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "outbound commit needs all family queues for one atomic send"
    )]
    pub(super) fn try_send_and_commit_outbound_update(
        &mut self,
        peer: IpAddr,
        next_hop_override: Vec<Option<rustbgpd_policy::NextHopAction>>,
        announce: Vec<crate::route::Route>,
        withdraw: Vec<(Prefix, u32)>,
        end_of_rib: Vec<(Afi, Safi)>,
        refresh_markers: Vec<(Afi, Safi, RouteRefreshSubtype)>,
        flowspec_announce: Vec<crate::route::FlowSpecRoute>,
        flowspec_withdraw: Vec<FlowSpecRule>,
        evpn_announce: Vec<crate::route::EvpnRibRoute>,
        evpn_withdraw: Vec<rustbgpd_wire::EvpnRouteKey>,
        bgpls_announce: Vec<crate::route::BgpLsRibRoute>,
        bgpls_withdraw: Vec<crate::route::BgpLsRouteKey>,
        vpn_announce: Vec<crate::route::VpnRibRoute>,
        vpn_withdraw: Vec<crate::route::VpnRibRouteKey>,
        rtc_announce: Vec<crate::route::RtcRibRoute>,
        rtc_withdraw: Vec<crate::route::RtcRibRouteKey>,
    ) -> bool {
        let Some(tx) = self.outbound_peers.get(&peer).cloned() else {
            return false;
        };
        let Ok(permit) = tx.try_reserve() else {
            return false;
        };

        if !announce.is_empty()
            || !withdraw.is_empty()
            || !flowspec_announce.is_empty()
            || !flowspec_withdraw.is_empty()
            || !evpn_announce.is_empty()
            || !evpn_withdraw.is_empty()
            || !bgpls_announce.is_empty()
            || !bgpls_withdraw.is_empty()
            || !vpn_announce.is_empty()
            || !vpn_withdraw.is_empty()
            || !rtc_announce.is_empty()
            || !rtc_withdraw.is_empty()
        {
            let loc_rib_len = self.loc_rib.len();
            let rib_out = self
                .adj_ribs_out
                .entry(peer)
                .or_insert_with(|| AdjRibOut::with_capacity(peer, loc_rib_len));
            for route in &announce {
                rib_out.insert(route.clone());
            }
            for (prefix, path_id) in &withdraw {
                rib_out.withdraw(prefix, *path_id);
            }
            for route in &flowspec_announce {
                rib_out.insert_flowspec(route.clone());
            }
            for rule in &flowspec_withdraw {
                rib_out.remove_flowspec(rule);
            }
            for route in &evpn_announce {
                rib_out.insert_evpn(route.clone());
            }
            for key in &evpn_withdraw {
                rib_out.remove_evpn(key);
            }
            for route in &bgpls_announce {
                rib_out.insert_bgpls(route.clone());
            }
            for key in &bgpls_withdraw {
                rib_out.remove_bgpls(key);
            }
            for route in &vpn_announce {
                rib_out.insert_vpn(route.clone());
            }
            for key in &vpn_withdraw {
                rib_out.remove_vpn(key);
            }
            for route in &rtc_announce {
                rib_out.insert_rtc(route.clone());
            }
            for key in &rtc_withdraw {
                rib_out.remove_rtc(key);
            }
            self.metrics.set_adj_rib_out_prefixes(
                &peer.to_string(),
                "all",
                gauge_val(rib_out.len()),
            );
            self.metrics.set_adj_rib_out_prefixes(
                &peer.to_string(),
                "flowspec",
                gauge_val(rib_out.flowspec_len()),
            );
            self.metrics.set_adj_rib_out_prefixes(
                &peer.to_string(),
                "evpn",
                gauge_val(rib_out.evpn_len()),
            );
            self.metrics.set_adj_rib_out_prefixes(
                &peer.to_string(),
                "bgpls",
                gauge_val(rib_out.bgpls_len()),
            );
            self.metrics.set_adj_rib_out_prefixes(
                &peer.to_string(),
                "vpn",
                gauge_val(rib_out.vpn_len()),
            );
            self.metrics.set_adj_rib_out_prefixes(
                &peer.to_string(),
                "rtc",
                gauge_val(rib_out.rtc_len()),
            );
        }

        permit.send(OutboundRouteUpdate {
            announce,
            withdraw,
            end_of_rib,
            refresh_markers,
            next_hop_override,
            flowspec_announce,
            flowspec_withdraw,
            evpn_announce,
            evpn_withdraw,
            bgpls_announce,
            bgpls_withdraw,
            vpn_announce,
            vpn_withdraw,
            rtc_announce,
            rtc_withdraw,
            request_refresh_all_negotiated: false,
        });
        true
    }

    pub(super) fn handle_replace_peer_export_policy(
        &mut self,
        peer: IpAddr,
        export_policy: Option<PolicyChain>,
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    ) {
        if !self.outbound_peers.contains_key(&peer) {
            let _ = reply.send(Err(format!(
                "peer {peer} not registered for outbound updates"
            )));
            return;
        }

        self.peer_export_policies.insert(peer, export_policy);
        self.dirty_peers.insert(peer);
        self.distribute_changes(&HashSet::new(), &HashSet::new());
        let _ = reply.send(Ok(()));
    }

    /// Force re-emission of all currently-advertised routes to a peer
    /// without changing policy. The export-policy path already does
    /// the same thing as a side-effect of policy replacement; this
    /// variant exists for outbound *attribute* surface changes that
    /// don't go through policy (e.g. RFC 8326 `GShut` community attach
    /// toggle, where the toggle lives as a per-session bool but
    /// changing it must trigger a fresh outbound emission so peers
    /// see the updated wire form on routes already in `AdjRibOut`).
    pub(super) fn handle_refresh_peer_outbound(
        &mut self,
        peer: IpAddr,
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    ) {
        if !self.outbound_peers.contains_key(&peer) {
            let _ = reply.send(Err(format!(
                "peer {peer} not registered for outbound updates"
            )));
            return;
        }
        // `force_outbound_peers` (not `dirty_peers`) — a force-only
        // resync bypasses AdjRibOut equality suppression for currently-
        // advertised exportable routes, which is exactly what GShut and
        // similar outbound-attribute toggles need (the wire change is
        // applied later in transport, invisible to this RIB diff). The
        // distribution loop clears the entry on successful emission so
        // the force is one-shot.
        self.force_outbound_peers.insert(peer);
        self.distribute_changes(&HashSet::new(), &HashSet::new());
        let _ = reply.send(Ok(()));
    }

    /// Apply Address-Prefix ORF entries pushed by a peer (RFC 5291/5292).
    ///
    /// Installs/updates the per-`(peer, AFI, SAFI)` filter and lifts the
    /// initial-advertisement gate. The re-advertisement sweep runs for
    /// `IMMEDIATE` (or after a malformed-field reset, RFC 5291 §5.2); `DEFER`
    /// installs the filter only — it stays live for subsequent outbound churn
    /// and is swept on a later IMMEDIATE/plain ROUTE-REFRESH.
    pub(super) fn handle_peer_orf_update(
        &mut self,
        peer: IpAddr,
        afi: Afi,
        safi: Safi,
        when: rustbgpd_wire::WhenToRefresh,
        entries: &[rustbgpd_wire::AddressPrefixOrf],
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    ) {
        if !self.outbound_peers.contains_key(&peer) {
            let _ = reply.send(Err(format!(
                "peer {peer} not registered for outbound updates"
            )));
            return;
        }
        let family = (afi, safi);
        // The ORF message is itself a ROUTE-REFRESH (RFC 5291 §6) — lift the gate.
        if let Some(pending) = self.peer_orf_pending.get_mut(&peer) {
            pending.remove(&family);
        }
        let filter = self
            .peer_orf_filters
            .entry(peer)
            .or_default()
            .entry(family)
            .or_default();
        let unknown_when = matches!(when, WhenToRefresh::Unknown(_));
        let reset = match when {
            WhenToRefresh::Unknown(value) => {
                // RFC 5291 only defines IMMEDIATE and DEFER. Treat an unknown
                // value like a malformed negotiated ORF control field: clear the
                // installed list and force a safe resync instead of silently
                // installing peer state with defer-like behavior.
                let remove_all = AddressPrefixOrf {
                    action: OrfAction::RemoveAll,
                    match_: OrfMatch::Permit,
                    sequence: 0,
                    min_len: 0,
                    max_len: 0,
                    prefix: None,
                };
                let _ = filter.apply(&[remove_all]);
                warn!(
                    %peer,
                    ?family,
                    when_to_refresh = value,
                    "unknown ORF When-to-refresh — installed ORF list for this type reset"
                );
                true
            }
            _ => filter.apply(entries).is_err(),
        };
        let now_empty = filter.is_empty();
        if reset && !unknown_when {
            warn!(%peer, ?family, "malformed ORF entry — installed ORF list for this type reset");
        }
        // An emptied filter (REMOVE-ALL or a reset) means permit-all again —
        // drop the entry so the absent-filter fast path applies.
        if now_empty && let Some(by_family) = self.peer_orf_filters.get_mut(&peer) {
            by_family.remove(&family);
        }
        if reset || when == WhenToRefresh::Immediate {
            // If this peer's EoR for the family was withheld at `PeerUp`
            // (GR restarter + §6 gate, see `send_initial_table`), the forced
            // resync below is the gated flood: move the family into
            // `pending_eor` and mark the peer dirty so the resync piggybacks
            // the EoR behind the flooded routes (or flushes it standalone
            // when the filter yields no routes). A DEFER update lifts the
            // gate without flooding, so the deferral stays put and rides the
            // later plain ROUTE-REFRESH or IMMEDIATE update that actually
            // advertises the family.
            if let Some(families) = self.gr_deferred_eor.get_mut(&peer)
                && families.remove(&family)
            {
                if families.is_empty() {
                    self.gr_deferred_eor.remove(&peer);
                }
                self.pending_eor.entry(peer).or_default().insert(family);
                self.dirty_peers.insert(peer);
            }
            self.force_outbound_peers.insert(peer);
            self.distribute_changes(&HashSet::new(), &HashSet::new());
        }
        let _ = reply.send(Ok(()));
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "RIB update messages carry every supported family as one transaction"
    )]
    pub(super) fn enqueue_routes_received(
        &mut self,
        peer: IpAddr,
        announced: Vec<crate::route::Route>,
        withdrawn: Vec<(Prefix, u32)>,
        flowspec_announced: Vec<crate::route::FlowSpecRoute>,
        flowspec_withdrawn: Vec<FlowSpecRule>,
        evpn_announced: Vec<crate::route::EvpnRibRoute>,
        evpn_withdrawn: Vec<rustbgpd_wire::EvpnRouteKey>,
    ) {
        if let std::collections::hash_map::Entry::Vacant(entry) = self.ribs.entry(peer) {
            let pending = PendingRoutesReceived::new(
                peer,
                announced,
                withdrawn,
                flowspec_announced,
                flowspec_withdrawn,
                evpn_announced,
                evpn_withdrawn,
            );
            entry.insert(AdjRibIn::with_capacity(
                peer,
                pending.route_capacity_hint(),
                pending.flowspec_capacity_hint(),
            ));
            self.pending_route_batches.push_back(pending);
            return;
        }

        self.pending_route_batches
            .push_back(PendingRoutesReceived::new(
                peer,
                announced,
                withdrawn,
                flowspec_announced,
                flowspec_withdrawn,
                evpn_announced,
                evpn_withdrawn,
            ));
    }

    pub(super) fn process_next_route_chunk(&mut self) -> bool {
        let Some(mut pending) = self.pending_route_batches.pop_front() else {
            return false;
        };

        let peer = pending.peer();
        let Some(chunk) = pending.next_chunk() else {
            // Empty/exhausted batch — flush anything still accumulated
            // (defensive; normally the has_more() branch below flushes).
            self.flush_pending_distribute();
            return false;
        };

        match chunk {
            PendingRouteChunk::Withdrawn(withdrawn) => {
                self.process_withdraw_chunk(peer, withdrawn);
            }
            PendingRouteChunk::Announced(announced) => {
                self.process_announce_chunk(peer, announced);
            }
            PendingRouteChunk::FlowSpecWithdrawn(flowspec_withdrawn) => {
                self.process_flowspec_withdraw_chunk(peer, flowspec_withdrawn);
            }
            PendingRouteChunk::FlowSpecAnnounced(flowspec_announced) => {
                self.process_flowspec_announce_chunk(peer, flowspec_announced);
            }
            PendingRouteChunk::EvpnWithdrawn(evpn_withdrawn) => {
                self.process_evpn_withdraw_chunk(peer, evpn_withdrawn);
            }
            PendingRouteChunk::EvpnAnnounced(evpn_announced) => {
                self.process_evpn_announce_chunk(peer, evpn_announced);
            }
        }

        if pending.has_more() {
            self.pending_route_batches.push_front(pending);
        } else {
            // Batch fully drained — distribute the changes accumulated
            // across all its chunks in one coalesced outbound pass.
            self.flush_pending_distribute();
        }

        true
    }

    /// Distribute the best-path changes accumulated across the chunks of a
    /// route batch in a single pass, then clear the accumulator. Called when
    /// a batch drains (see [`Self::process_next_route_chunk`]); a no-op when
    /// nothing accumulated. Deferring distribution this way coalesces a
    /// multi-chunk initial-load flood into one outbound batch per peer
    /// instead of one per 1024-route chunk, while `recompute_best` still runs
    /// per chunk so Loc-RIB and route events stay live mid-batch.
    fn flush_pending_distribute(&mut self) {
        if self.pending_distribute_changed.is_empty() && self.pending_distribute_affected.is_empty()
        {
            return;
        }
        let changed = std::mem::take(&mut self.pending_distribute_changed);
        let affected = std::mem::take(&mut self.pending_distribute_affected);
        self.distribute_changes(&changed, &affected);
    }

    /// Recompute Loc-RIB best path for a set of affected prefixes.
    /// Returns the set of prefixes that actually changed.
    /// Also emits route events to the broadcast channel.
    pub(super) fn recompute_best(&mut self, affected: &HashSet<Prefix>) -> HashSet<Prefix> {
        let mut changed = HashSet::new();
        for prefix in affected {
            let previous_best = self.loc_rib.get(prefix).map(|r| (r.peer, r.path_id));
            let candidates = self.ribs.values().flat_map(|rib| rib.iter_prefix(prefix));
            let did_change = self.loc_rib.recompute(*prefix, candidates);
            if did_change {
                changed.insert(*prefix);
                let current_best = self.loc_rib.get(prefix);
                match (previous_best, current_best) {
                    (None, Some(best)) => {
                        debug!(%prefix, peer = %best.peer, "best path added");
                        self.publish_route_event(RouteEvent {
                            event_id: 0,
                            event_type: RouteEventType::Added,
                            prefix: *prefix,
                            peer: Some(best.peer),
                            previous_peer: None,
                            target_peer: None,
                            timestamp: crate::event::unix_timestamp_now(),
                            path_id: best.path_id,
                            reason: String::new(),
                        });
                    }
                    (Some((old_peer, old_path_id)), None) => {
                        debug!(%prefix, "best path removed");
                        self.publish_route_event(RouteEvent {
                            event_id: 0,
                            event_type: RouteEventType::Withdrawn,
                            prefix: *prefix,
                            peer: None,
                            previous_peer: Some(old_peer),
                            target_peer: None,
                            timestamp: crate::event::unix_timestamp_now(),
                            path_id: old_path_id,
                            reason: String::new(),
                        });
                    }
                    (Some((old_peer, _old_path_id)), Some(best)) => {
                        debug!(%prefix, peer = %best.peer, "best path changed");
                        self.publish_route_event(RouteEvent {
                            event_id: 0,
                            event_type: RouteEventType::BestChanged,
                            prefix: *prefix,
                            peer: Some(best.peer),
                            previous_peer: Some(old_peer),
                            target_peer: None,
                            timestamp: crate::event::unix_timestamp_now(),
                            path_id: best.path_id,
                            reason: String::new(),
                        });
                    }
                    (None, None) => {}
                }
            }
        }
        self.metrics
            .set_loc_rib_prefixes("all", gauge_val(self.loc_rib.len()));
        changed
    }

    /// Distribute Loc-RIB changes to all registered outbound peers.
    ///
    /// For clean peers, only `changed_prefixes` are evaluated. Dirty peers
    /// (those that failed a previous `try_send()`) get a full export resync:
    /// all Loc-RIB and `AdjRibOut` prefixes are diffed to bring the peer's
    /// view back in sync. `AdjRibOut` is only committed after a successful
    /// channel send; on failure the peer stays dirty for retry via the
    /// resync timer.
    ///
    /// Routes are filtered by `sendable_families` (set at `PeerUp` time)
    /// so that Adj-RIB-Out only contains routes the transport can actually
    /// serialize for this peer. The transport retains `is_family_negotiated`
    /// as a safety net.
    #[expect(
        clippy::too_many_lines,
        reason = "distribution loop coordinates dirty peers, forced resync, and all families"
    )]
    pub(super) fn distribute_changes(
        &mut self,
        best_changed: &HashSet<Prefix>,
        all_affected: &HashSet<Prefix>,
    ) {
        if best_changed.is_empty()
            && all_affected.is_empty()
            && self.dirty_peers.is_empty()
            && self.force_outbound_peers.is_empty()
        {
            return;
        }

        let peers: Vec<IpAddr> = self.outbound_peers.keys().copied().collect();
        for peer in peers {
            // For dirty peers, compute full prefix set from Loc-RIB + AdjRibOut
            let is_dirty = self.dirty_peers.contains(&peer);
            // `is_force` peers are dirty-equivalent for prefix enumeration AND
            // bypass the AdjRibOut equality suppression in the per-prefix
            // helpers — see `RibUpdate::RefreshPeerOutbound` rationale on
            // `force_outbound_peers`.
            let is_force = self.force_outbound_peers.contains(&peer);
            let resync = is_dirty || is_force;
            let effective_prefixes: HashSet<Prefix> = if resync {
                let mut all: HashSet<Prefix> = self.loc_rib.iter().map(|r| r.prefix).collect();
                // For multi-path dirty resync, also include all Adj-RIB-In prefixes
                if self.peer_has_any_add_path_send(peer) {
                    for rib in self.ribs.values() {
                        all.extend(rib.iter().map(|r| r.prefix));
                    }
                }
                if let Some(rib_out) = self.adj_ribs_out.get(&peer) {
                    all.extend(rib_out.iter().map(|r| r.prefix));
                }
                all
            } else {
                let mut prefixes = best_changed.clone();
                // An RFC 9107 ORR peer selects from the per-target
                // candidate set, not the Loc-RIB best — a candidate
                // change that leaves the Loc-RIB best untouched can
                // still flip the vantage best, so ORR peers stage every
                // affected prefix (same reasoning as Add-Path send).
                let peer_has_resolved_orr = self
                    .peer_orr_vantage
                    .get(&peer)
                    .is_some_and(|vantage| self.orr.spf.contains_key(vantage));
                for prefix in all_affected {
                    if peer_has_resolved_orr || self.add_path_send_max_for_prefix(peer, prefix) > 0
                    {
                        prefixes.insert(*prefix);
                    }
                }
                prefixes
            };
            let effective_flowspec_rules: HashSet<FlowSpecRule> = if resync {
                let mut all: HashSet<FlowSpecRule> = self
                    .loc_rib
                    .iter_flowspec()
                    .map(|route| route.rule.clone())
                    .collect();
                if let Some(rib_out) = self.adj_ribs_out.get(&peer) {
                    all.extend(rib_out.iter_flowspec().map(|route| route.rule.clone()));
                }
                all
            } else {
                HashSet::new()
            };

            let effective_evpn_keys: HashSet<rustbgpd_wire::EvpnRouteKey> = if resync {
                let mut all: HashSet<rustbgpd_wire::EvpnRouteKey> = self
                    .loc_rib
                    .iter_evpn()
                    .map(crate::route::EvpnRibRoute::key)
                    .collect();
                if let Some(rib_out) = self.adj_ribs_out.get(&peer) {
                    all.extend(rib_out.iter_evpn().map(crate::route::EvpnRibRoute::key));
                }
                all
            } else {
                HashSet::new()
            };

            let effective_bgpls_keys: HashSet<crate::route::BgpLsRouteKey> = if resync {
                let mut all: HashSet<crate::route::BgpLsRouteKey> = self
                    .loc_rib
                    .iter_bgpls()
                    .map(crate::route::BgpLsRibRoute::key)
                    .collect();
                if let Some(rib_out) = self.adj_ribs_out.get(&peer) {
                    all.extend(rib_out.iter_bgpls().map(crate::route::BgpLsRibRoute::key));
                }
                all
            } else {
                HashSet::new()
            };

            let effective_l3vpn_keys: HashSet<crate::route::VpnRibRouteKey> = if resync {
                let mut all: HashSet<crate::route::VpnRibRouteKey> = self
                    .loc_rib
                    .iter_vpn()
                    .map(crate::route::VpnRibRoute::key)
                    .collect();
                if let Some(rib_out) = self.adj_ribs_out.get(&peer) {
                    all.extend(rib_out.iter_vpn().map(crate::route::VpnRibRoute::key));
                }
                all
            } else {
                HashSet::new()
            };

            let effective_rtc_keys: HashSet<crate::route::RtcRibRouteKey> = if resync {
                let mut all: HashSet<crate::route::RtcRibRouteKey> = self
                    .loc_rib
                    .iter_rtc()
                    .map(crate::route::RtcRibRoute::key)
                    .collect();
                if let Some(rib_out) = self.adj_ribs_out.get(&peer) {
                    all.extend(rib_out.iter_rtc().map(crate::route::RtcRibRoute::key));
                }
                all
            } else {
                HashSet::new()
            };

            if effective_prefixes.is_empty()
                && effective_flowspec_rules.is_empty()
                && effective_evpn_keys.is_empty()
                && effective_bgpls_keys.is_empty()
                && effective_l3vpn_keys.is_empty()
                && effective_rtc_keys.is_empty()
            {
                self.clear_policy_filtered_routes_for_peer(peer);
                // Resync flags must clear here too — otherwise a
                // force-only refresh on a peer with no exportable
                // routes would leave `force_outbound_peers` populated,
                // and the next unrelated dirty resync (or another
                // RefreshPeerOutbound for a different reason) would
                // accidentally inherit the bypass-equality-suppression
                // semantics. Same shape for `dirty_peers` for symmetry.
                if is_dirty {
                    self.dirty_peers.remove(&peer);
                }
                if is_force {
                    self.force_outbound_peers.remove(&peer);
                }
                continue;
            }

            let mut announce = Vec::new();
            let mut withdraw = Vec::new();
            let mut nh_override_flags: Vec<Option<rustbgpd_policy::NextHopAction>> = Vec::new();
            let mut fs_announce = Vec::new();
            let mut fs_withdraw = Vec::new();
            let mut evpn_announce = Vec::new();
            let mut evpn_withdraw = Vec::new();
            let mut bgpls_announce = Vec::new();
            let mut bgpls_withdraw = Vec::new();
            let mut vpn_announce = Vec::new();
            let mut vpn_withdraw = Vec::new();
            let mut rtc_announce = Vec::new();
            let mut rtc_withdraw = Vec::new();
            let mut current_policy_filtered_routes: HashSet<PolicyFilteredRouteKey> =
                HashSet::new();

            // Resolve export policy, sendable families, and RR state before
            // borrowing rib_out (which holds a &mut to self.adj_ribs_out).
            let export_pol = self.export_policy_for(peer).cloned();
            let sendable = self.peer_sendable_families.get(&peer).cloned();
            let target_is_ebgp = self.peer_is_ebgp.get(&peer).copied().unwrap_or(true);
            let target_is_rr_client = self.peer_is_rr_client.get(&peer).copied().unwrap_or(false);
            let target_peer_asn = self.peer_asn.get(&peer).copied();
            let target_peer_group = self.peer_group.get(&peer).map(String::as_str);
            let cluster_id = self.cluster_id;
            let peer_add_path_send_max =
                self.peer_add_path_send_max.get(&peer).copied().unwrap_or(0);
            let peer_add_path_send_families = self
                .peer_add_path_send_families
                .get(&peer)
                .cloned()
                .unwrap_or_default();
            // ORF state, resolved before the &mut rib_out borrow below. Cloning
            // is cheap: ORF filters are small and present only for peers that
            // negotiated ORF (None for everyone else).
            let orf_filters = self.peer_orf_filters.get(&peer).cloned();
            // RFC 9107 ORR: a peer bound to a vantage that resolved this
            // pass takes the per-vantage best below; an unresolved
            // vantage silently falls back to the standard single-best
            // (the status is surfaced by `rbgp orr`).
            let orr_ctx = self
                .peer_orr_vantage
                .get(&peer)
                .and_then(|vantage| self.orr.spf.get(vantage))
                .map(|spf| (&self.orr.topology, spf));
            let rtc_filter = self.rtc_vpn_filter(peer, sendable.as_ref());
            let orf_gated = self
                .peer_orf_pending
                .get(&peer)
                .cloned()
                .unwrap_or_default();
            let loc_rib = &self.loc_rib;
            let loc_rib_len = loc_rib.len();
            let target_peer_label = peer.to_string();
            let metrics = self.metrics.clone();
            let policy_stats = self.export_policy_stats.entry(peer).or_default();

            let rib_out = self
                .adj_ribs_out
                .entry(peer)
                .or_insert_with(|| AdjRibOut::with_capacity(peer, loc_rib_len));

            // Stage: compute delta without mutating AdjRibOut
            for prefix in &effective_prefixes {
                let family = prefix_family(prefix);
                // RFC 5291 §6 gate: suppress this family's advertisement (incl.
                // ongoing churn) until the peer's first ROUTE-REFRESH lifts it.
                if orf_gated.contains(&family) {
                    continue;
                }
                let orf = orf_filters.as_ref().and_then(|m| m.get(&family));
                let prefix_send_max = if peer_add_path_send_max > 0
                    && peer_add_path_send_families.contains(&family)
                {
                    peer_add_path_send_max
                } else {
                    0
                };
                if prefix_send_max > 0 {
                    // Multi-path: collect all candidates, filter, sort, diff
                    let mut policy_filtered = Vec::new();
                    Self::distribute_multipath_prefix(
                        &self.ribs,
                        rib_out,
                        &self.peer_is_rr_client,
                        prefix,
                        peer,
                        target_peer_asn,
                        target_peer_group,
                        prefix_send_max,
                        target_is_ebgp,
                        target_is_rr_client,
                        cluster_id,
                        sendable.as_ref(),
                        export_pol.as_ref(),
                        orf,
                        orr_ctx,
                        &metrics,
                        policy_stats,
                        &target_peer_label,
                        &mut announce,
                        &mut withdraw,
                        &mut nh_override_flags,
                        &mut policy_filtered,
                        is_force,
                    );
                    current_policy_filtered_routes.extend(policy_filtered);
                } else if let Some((orr_topology, orr_spf)) = orr_ctx {
                    // ORR peer with a resolved vantage: per-vantage best.
                    let mut policy_filtered = Vec::new();
                    Self::distribute_orr_best_prefix(
                        &self.ribs,
                        rib_out,
                        &self.peer_is_rr_client,
                        orr_topology,
                        orr_spf,
                        prefix,
                        peer,
                        target_peer_asn,
                        target_peer_group,
                        target_is_ebgp,
                        target_is_rr_client,
                        cluster_id,
                        sendable.as_ref(),
                        export_pol.as_ref(),
                        orf,
                        &metrics,
                        policy_stats,
                        &target_peer_label,
                        &mut announce,
                        &mut withdraw,
                        &mut nh_override_flags,
                        &mut policy_filtered,
                        is_force,
                    );
                    current_policy_filtered_routes.extend(policy_filtered);
                } else {
                    let mut policy_filtered = Vec::new();
                    Self::distribute_single_best_prefix(
                        loc_rib,
                        rib_out,
                        &self.peer_is_rr_client,
                        prefix,
                        peer,
                        target_peer_asn,
                        target_peer_group,
                        target_is_ebgp,
                        target_is_rr_client,
                        cluster_id,
                        sendable.as_ref(),
                        export_pol.as_ref(),
                        orf,
                        &metrics,
                        policy_stats,
                        &target_peer_label,
                        &mut announce,
                        &mut withdraw,
                        &mut nh_override_flags,
                        &mut policy_filtered,
                        is_force,
                    );
                    current_policy_filtered_routes.extend(policy_filtered);
                }
            }

            if resync && !effective_flowspec_rules.is_empty() {
                Self::stage_flowspec_rules(
                    loc_rib,
                    rib_out,
                    &self.peer_is_rr_client,
                    &effective_flowspec_rules,
                    peer,
                    target_peer_asn,
                    target_peer_group,
                    target_is_ebgp,
                    target_is_rr_client,
                    cluster_id,
                    sendable.as_ref(),
                    export_pol.as_ref(),
                    &metrics,
                    policy_stats,
                    &target_peer_label,
                    &mut fs_announce,
                    &mut fs_withdraw,
                );
            }

            if resync && !effective_evpn_keys.is_empty() {
                Self::stage_evpn_routes(
                    loc_rib,
                    rib_out,
                    &self.peer_is_rr_client,
                    &effective_evpn_keys,
                    peer,
                    target_peer_asn,
                    target_peer_group,
                    target_is_ebgp,
                    target_is_rr_client,
                    cluster_id,
                    sendable.as_ref(),
                    export_pol.as_ref(),
                    &metrics,
                    policy_stats,
                    &target_peer_label,
                    &mut evpn_announce,
                    &mut evpn_withdraw,
                    is_force,
                );
            }

            if resync && !effective_bgpls_keys.is_empty() {
                Self::stage_bgpls_routes(
                    loc_rib,
                    rib_out,
                    &self.peer_is_rr_client,
                    &effective_bgpls_keys,
                    peer,
                    target_peer_asn,
                    target_peer_group,
                    target_is_ebgp,
                    target_is_rr_client,
                    cluster_id,
                    sendable.as_ref(),
                    export_pol.as_ref(),
                    &metrics,
                    policy_stats,
                    &target_peer_label,
                    &mut bgpls_announce,
                    &mut bgpls_withdraw,
                    is_force,
                );
            }

            if resync && !effective_l3vpn_keys.is_empty() {
                Self::stage_vpn_routes(
                    loc_rib,
                    &self.ribs,
                    rib_out,
                    &self.peer_is_rr_client,
                    &effective_l3vpn_keys,
                    peer,
                    target_peer_asn,
                    target_peer_group,
                    target_is_ebgp,
                    target_is_rr_client,
                    cluster_id,
                    sendable.as_ref(),
                    rtc_filter.as_ref(),
                    orr_ctx,
                    export_pol.as_ref(),
                    &metrics,
                    policy_stats,
                    &target_peer_label,
                    &mut vpn_announce,
                    &mut vpn_withdraw,
                    is_force,
                );
            }

            if resync && !effective_rtc_keys.is_empty() {
                Self::stage_rtc_routes(
                    loc_rib,
                    rib_out,
                    &self.peer_is_rr_client,
                    &effective_rtc_keys,
                    peer,
                    target_peer_asn,
                    target_peer_group,
                    target_is_ebgp,
                    target_is_rr_client,
                    cluster_id,
                    sendable.as_ref(),
                    export_pol.as_ref(),
                    &metrics,
                    policy_stats,
                    &target_peer_label,
                    &mut rtc_announce,
                    &mut rtc_withdraw,
                    is_force,
                );
            }

            if !announce.is_empty()
                || !withdraw.is_empty()
                || !fs_announce.is_empty()
                || !fs_withdraw.is_empty()
                || !evpn_announce.is_empty()
                || !evpn_withdraw.is_empty()
                || !bgpls_announce.is_empty()
                || !bgpls_withdraw.is_empty()
                || !vpn_announce.is_empty()
                || !vpn_withdraw.is_empty()
                || !rtc_announce.is_empty()
                || !rtc_withdraw.is_empty()
            {
                // If a prior initial dump / route-refresh EoR was deferred,
                // piggyback it on the successful dirty resync update so it
                // can't be starved behind the resync message on a small queue.
                // EoR piggyback only attaches to *dirty* resyncs (the
                // dump-deferral pattern). A force-only resync is a
                // GShut-style outbound-attribute refresh and never
                // carries pending EoR by definition.
                let pending_eor = if is_dirty {
                    self.pending_eor
                        .get(&peer)
                        .map(|families| families.iter().copied().collect())
                        .unwrap_or_default()
                } else {
                    vec![]
                };
                let announced_count = announce.len();
                let withdrawn_count = withdraw.len();
                if self.try_send_and_commit_outbound_update(
                    peer,
                    nh_override_flags,
                    announce,
                    withdraw,
                    pending_eor.clone(),
                    vec![],
                    fs_announce,
                    fs_withdraw,
                    evpn_announce,
                    evpn_withdraw,
                    bgpls_announce,
                    bgpls_withdraw,
                    vpn_announce,
                    vpn_withdraw,
                    rtc_announce,
                    rtc_withdraw,
                ) {
                    self.update_policy_filtered_routes_for_prefixes(
                        peer,
                        &effective_prefixes,
                        &current_policy_filtered_routes,
                    );
                    if resync {
                        info!(
                            %peer,
                            announced = announced_count,
                            withdrawn = withdrawn_count,
                            dirty = is_dirty,
                            force = is_force,
                            "outbound routes resynced"
                        );
                        if is_dirty {
                            self.dirty_peers.remove(&peer);
                            if pending_eor.is_empty() {
                                self.flush_pending_eor(peer);
                            } else {
                                self.pending_eor.remove(&peer);
                            }
                            self.retry_pending_refresh(peer);
                        }
                        // Force is one-shot: clear after a successful
                        // emission so a subsequent unrelated dirty
                        // resync doesn't re-bypass equality checks.
                        if is_force {
                            self.force_outbound_peers.remove(&peer);
                        }
                    }
                } else {
                    warn!(%peer, "outbound channel full or closed — marking dirty for resync");
                    self.metrics.record_outbound_route_drop(&peer.to_string());
                    self.dirty_peers.insert(peer);
                }
            } else {
                self.update_policy_filtered_routes_for_prefixes(
                    peer,
                    &effective_prefixes,
                    &current_policy_filtered_routes,
                );
                if resync {
                    // Resync triggered but no diff — already in sync.
                    debug!(%peer, "outbound routes unchanged after resync");
                    if is_dirty {
                        self.dirty_peers.remove(&peer);
                        self.flush_pending_eor(peer);
                        self.retry_pending_refresh(peer);
                    }
                    if is_force {
                        self.force_outbound_peers.remove(&peer);
                    }
                }
            }
        }
    }
}
