use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};

use rustbgpd_policy::{PolicyAction, PolicyChain, evaluate_chain};
use rustbgpd_wire::{Afi, FlowSpecRule, Prefix, Safi};
use tracing::{debug, warn};

use super::RibManager;
use super::helpers::{gauge_val, prefix_family, routes_equal, should_suppress_ibgp_inner};
use crate::adj_rib_in::AdjRibIn;
use crate::adj_rib_out::AdjRibOut;
use crate::event::{RouteEvent, RouteEventType};
use crate::loc_rib::LocRib;
use crate::update::OutboundRouteUpdate;

impl RibManager {
    /// Recompute Loc-RIB best path for a set of affected prefixes.
    /// Returns the set of prefixes that actually changed.
    /// Also emits route events to the broadcast channel.
    pub(super) fn recompute_best(&mut self, affected: &HashSet<Prefix>) -> HashSet<Prefix> {
        let mut changed = HashSet::new();
        for prefix in affected {
            let previous_best = self.loc_rib.get(prefix).map(|r| (r.peer, r.path_id));
            let candidates: Vec<_> = self
                .ribs
                .values()
                .flat_map(|rib| rib.iter_prefix(prefix))
                .collect();
            let did_change = self.loc_rib.recompute(*prefix, candidates.into_iter());
            if did_change {
                changed.insert(*prefix);
                let current_best = self.loc_rib.get(prefix);
                match (previous_best, current_best) {
                    (None, Some(best)) => {
                        debug!(%prefix, peer = %best.peer, "best path added");
                        let _ = self.route_events_tx.send(RouteEvent {
                            event_type: RouteEventType::Added,
                            prefix: *prefix,
                            peer: Some(best.peer),
                            previous_peer: None,
                            timestamp: crate::event::unix_timestamp_now(),
                            path_id: best.path_id,
                        });
                    }
                    (Some((old_peer, old_path_id)), None) => {
                        debug!(%prefix, "best path removed");
                        let _ = self.route_events_tx.send(RouteEvent {
                            event_type: RouteEventType::Withdrawn,
                            prefix: *prefix,
                            peer: None,
                            previous_peer: Some(old_peer),
                            timestamp: crate::event::unix_timestamp_now(),
                            path_id: old_path_id,
                        });
                    }
                    (Some((old_peer, _old_path_id)), Some(best)) => {
                        debug!(%prefix, peer = %best.peer, "best path changed");
                        let _ = self.route_events_tx.send(RouteEvent {
                            event_type: RouteEventType::BestChanged,
                            prefix: *prefix,
                            peer: Some(best.peer),
                            previous_peer: Some(old_peer),
                            timestamp: crate::event::unix_timestamp_now(),
                            path_id: best.path_id,
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

    /// Multi-path distribution for a single prefix to a single peer.
    ///
    /// Collects all candidates from all Adj-RIB-In entries, filters by
    /// split-horizon/iBGP/family/policy, sorts by best-path, takes top N,
    /// and diffs against `AdjRibOut` to produce announces and withdrawals.
    #[expect(clippy::too_many_arguments)]
    pub(super) fn distribute_multipath_prefix(
        ribs: &HashMap<IpAddr, AdjRibIn>,
        rib_out: &AdjRibOut,
        peer_is_rr_client: &HashMap<IpAddr, bool>,
        prefix: &Prefix,
        target_peer: IpAddr,
        send_max: u32,
        target_is_ebgp: bool,
        target_is_rr_client: bool,
        cluster_id: Option<Ipv4Addr>,
        sendable: Option<&Vec<(Afi, Safi)>>,
        export_pol: Option<&PolicyChain>,
        announce: &mut Vec<crate::route::Route>,
        withdraw: &mut Vec<(Prefix, u32)>,
        nh_override_flags: &mut Vec<Option<rustbgpd_policy::NextHopAction>>,
    ) {
        use crate::best_path::best_path_cmp;

        // Sendable family check
        let family = match prefix {
            Prefix::V4(_) => (Afi::Ipv4, Safi::Unicast),
            Prefix::V6(_) => (Afi::Ipv6, Safi::Unicast),
        };
        if !sendable.is_some_and(|f| f.contains(&family)) {
            // Withdraw all previously advertised paths for this prefix
            for path_id in rib_out.path_ids_for_prefix(prefix) {
                withdraw.push((*prefix, path_id));
            }
            return;
        }

        // Collect all candidates across all Adj-RIB-In entries
        let mut candidates: Vec<&crate::route::Route> = ribs
            .values()
            .flat_map(|rib| rib.iter_prefix(prefix))
            .filter(|route| {
                // Split horizon: exclude routes from the target peer
                if route.peer == target_peer {
                    return false;
                }
                // iBGP split-horizon / RFC 4456 reflection
                if should_suppress_ibgp_inner(
                    route,
                    target_is_ebgp,
                    target_is_rr_client,
                    cluster_id,
                    peer_is_rr_client,
                ) {
                    return false;
                }
                true
            })
            .collect();

        // Sort by best-path preference (best first)
        candidates.sort_by(|a, b| best_path_cmp(a, b));

        // Walk candidates, evaluate export policy, assign path_ids 1..N
        let mut next_rank: u32 = 1;
        let limit = if send_max == u32::MAX {
            usize::MAX
        } else {
            send_max as usize
        };
        for candidate in &candidates {
            if (next_rank as usize) > limit {
                break;
            }

            // Export policy check per-candidate
            let aspath_str = candidate
                .as_path()
                .map_or_else(String::new, rustbgpd_wire::AsPath::to_aspath_string);
            let result = evaluate_chain(
                export_pol,
                *prefix,
                candidate.extended_communities(),
                candidate.communities(),
                candidate.large_communities(),
                &aspath_str,
                candidate.validation_state,
            );
            if result.action != PolicyAction::Permit {
                continue;
            }

            // Apply export modifications
            let mut modified = (*candidate).clone();
            let nh_action = rustbgpd_policy::apply_modifications(
                &mut modified.attributes,
                &result.modifications,
            );
            if let Some(rustbgpd_policy::NextHopAction::Specific(addr)) = &nh_action {
                modified.next_hop = *addr;
            }
            modified.path_id = next_rank;

            // Only announce if different from what's already in AdjRibOut
            let changed = rib_out
                .get(prefix, next_rank)
                .is_none_or(|existing| !routes_equal(existing, &modified));
            if changed {
                nh_override_flags.push(nh_action);
                announce.push(modified);
            }

            next_rank += 1;
        }

        // Withdraw any previously advertised path_ids beyond the new set
        for path_id in rib_out.path_ids_for_prefix(prefix) {
            if path_id >= next_rank {
                withdraw.push((*prefix, path_id));
            }
        }
    }

    #[expect(clippy::too_many_arguments)]
    pub(super) fn distribute_single_best_prefix(
        loc_rib: &LocRib,
        rib_out: &AdjRibOut,
        peer_is_rr_client: &HashMap<IpAddr, bool>,
        prefix: &Prefix,
        target_peer: IpAddr,
        target_is_ebgp: bool,
        target_is_rr_client: bool,
        cluster_id: Option<Ipv4Addr>,
        sendable: Option<&Vec<(Afi, Safi)>>,
        export_pol: Option<&PolicyChain>,
        announce: &mut Vec<crate::route::Route>,
        withdraw: &mut Vec<(Prefix, u32)>,
        nh_override_flags: &mut Vec<Option<rustbgpd_policy::NextHopAction>>,
    ) {
        let existing_path_ids = rib_out.path_ids_for_prefix(prefix);

        let Some(best) = loc_rib.get(prefix) else {
            for path_id in existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        };

        // Split horizon: don't send route back to its source
        if best.peer == target_peer {
            for path_id in existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        }

        // iBGP split-horizon / RFC 4456 reflection rules
        if should_suppress_ibgp_inner(
            best,
            target_is_ebgp,
            target_is_rr_client,
            cluster_id,
            peer_is_rr_client,
        ) {
            for path_id in existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        }

        // Sendable family check
        let family = prefix_family(prefix);
        if !sendable.is_some_and(|f| f.contains(&family)) {
            for path_id in existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        }

        // Export policy check
        let aspath_str = best
            .as_path()
            .map_or_else(String::new, rustbgpd_wire::AsPath::to_aspath_string);
        let result = evaluate_chain(
            export_pol,
            *prefix,
            best.extended_communities(),
            best.communities(),
            best.large_communities(),
            &aspath_str,
            best.validation_state,
        );
        if result.action != PolicyAction::Permit {
            for path_id in existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        }

        // Apply export modifications to a clone
        let mut modified = best.clone();
        let nh_action =
            rustbgpd_policy::apply_modifications(&mut modified.attributes, &result.modifications);
        if let Some(rustbgpd_policy::NextHopAction::Specific(addr)) = &nh_action {
            modified.next_hop = *addr;
        }
        modified.path_id = 0;

        let changed = rib_out
            .get(prefix, 0)
            .is_none_or(|existing| !routes_equal(existing, &modified));
        if changed {
            nh_override_flags.push(nh_action);
            announce.push(modified);
        }

        // Clean up any stale multi-path entries if this prefix was previously
        // advertised via Add-Path and is now single-best.
        for path_id in existing_path_ids {
            if path_id != 0 {
                withdraw.push((*prefix, path_id));
            }
        }
    }

    /// Stage `FlowSpec` announces and withdrawals for a set of rules.
    ///
    /// Uses `loc_rib` as the current best-route source and diffs against the
    /// provided outbound view. Passing an empty `AdjRibOut` view causes a full
    /// re-advertisement of the current `FlowSpec` export set, which is useful
    /// for initial table dump and ROUTE-REFRESH responses.
    #[expect(clippy::too_many_arguments)]
    pub(super) fn stage_flowspec_rules(
        loc_rib: &LocRib,
        rib_out: &AdjRibOut,
        peer_is_rr_client: &HashMap<IpAddr, bool>,
        rules: &HashSet<FlowSpecRule>,
        target_is_ebgp: bool,
        target_is_rr_client: bool,
        cluster_id: Option<Ipv4Addr>,
        sendable: Option<&Vec<(Afi, Safi)>>,
        export_pol: Option<&PolicyChain>,
        fs_announce: &mut Vec<crate::route::FlowSpecRoute>,
        fs_withdraw: &mut Vec<FlowSpecRule>,
    ) {
        for rule in rules {
            if let Some(best) = loc_rib.get_flowspec(rule) {
                let fs_family = (best.afi, Safi::FlowSpec);
                if !sendable.is_some_and(|f| f.contains(&fs_family)) {
                    if rib_out.get_flowspec(rule).is_some() {
                        fs_withdraw.push(rule.clone());
                    }
                    continue;
                }

                // Reuse the existing iBGP split-horizon / RR check. Only
                // origin_type/peer/peer_router_id are relevant here.
                if should_suppress_ibgp_inner(
                    &crate::route::Route {
                        prefix: Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
                            Ipv4Addr::UNSPECIFIED,
                            0,
                        )),
                        next_hop: best.peer,
                        peer: best.peer,
                        attributes: vec![],
                        received_at: best.received_at,
                        origin_type: best.origin_type,
                        peer_router_id: best.peer_router_id,
                        is_stale: false,
                        is_llgr_stale: false,
                        path_id: 0,
                        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
                    },
                    target_is_ebgp,
                    target_is_rr_client,
                    cluster_id,
                    peer_is_rr_client,
                ) {
                    if rib_out.get_flowspec(rule).is_some() {
                        fs_withdraw.push(rule.clone());
                    }
                    continue;
                }

                let dest_prefix = best.rule.destination_prefix();
                let prefix_for_policy = dest_prefix.unwrap_or(Prefix::V4(
                    rustbgpd_wire::Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0),
                ));
                let aspath_str = best
                    .as_path()
                    .map_or_else(String::new, rustbgpd_wire::AsPath::to_aspath_string);
                let result = rustbgpd_policy::evaluate_chain(
                    export_pol,
                    prefix_for_policy,
                    best.extended_communities(),
                    best.communities(),
                    best.large_communities(),
                    &aspath_str,
                    rustbgpd_wire::RpkiValidation::NotFound,
                );
                if result.action == rustbgpd_policy::PolicyAction::Permit {
                    fs_announce.push(best.clone());
                } else if rib_out.get_flowspec(rule).is_some() {
                    fs_withdraw.push(rule.clone());
                }
            } else if rib_out.get_flowspec(rule).is_some() {
                fs_withdraw.push(rule.clone());
            }
        }
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
    #[expect(clippy::too_many_lines)]
    pub(super) fn distribute_changes(
        &mut self,
        best_changed: &HashSet<Prefix>,
        all_affected: &HashSet<Prefix>,
    ) {
        if best_changed.is_empty() && all_affected.is_empty() && self.dirty_peers.is_empty() {
            return;
        }

        let peers: Vec<IpAddr> = self.outbound_peers.keys().copied().collect();
        for peer in peers {
            // For dirty peers, compute full prefix set from Loc-RIB + AdjRibOut
            let is_dirty = self.dirty_peers.contains(&peer);
            let effective_prefixes: HashSet<Prefix> = if is_dirty {
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
                for prefix in all_affected {
                    if self.add_path_send_max_for_prefix(peer, prefix) > 0 {
                        prefixes.insert(*prefix);
                    }
                }
                prefixes
            };
            let effective_flowspec_rules: HashSet<FlowSpecRule> = if is_dirty {
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

            if effective_prefixes.is_empty() && effective_flowspec_rules.is_empty() {
                continue;
            }

            let mut announce = Vec::new();
            let mut withdraw = Vec::new();
            let mut nh_override_flags: Vec<Option<rustbgpd_policy::NextHopAction>> = Vec::new();
            let mut fs_announce = Vec::new();
            let mut fs_withdraw = Vec::new();

            // Resolve export policy, sendable families, and RR state before
            // borrowing rib_out (which holds a &mut to self.adj_ribs_out).
            let export_pol = self.export_policy_for(peer).cloned();
            let sendable = self.peer_sendable_families.get(&peer).cloned();
            let target_is_ebgp = self.peer_is_ebgp.get(&peer).copied().unwrap_or(true);
            let target_is_rr_client = self.peer_is_rr_client.get(&peer).copied().unwrap_or(false);
            let cluster_id = self.cluster_id;
            let peer_add_path_send_max =
                self.peer_add_path_send_max.get(&peer).copied().unwrap_or(0);
            let peer_add_path_send_families = self
                .peer_add_path_send_families
                .get(&peer)
                .cloned()
                .unwrap_or_default();
            let loc_rib = &self.loc_rib;

            let rib_out = self
                .adj_ribs_out
                .entry(peer)
                .or_insert_with(|| AdjRibOut::new(peer));

            // Stage: compute delta without mutating AdjRibOut
            for prefix in &effective_prefixes {
                let prefix_send_max = if peer_add_path_send_max > 0
                    && peer_add_path_send_families.contains(&prefix_family(prefix))
                {
                    peer_add_path_send_max
                } else {
                    0
                };
                if prefix_send_max > 0 {
                    // Multi-path: collect all candidates, filter, sort, diff
                    Self::distribute_multipath_prefix(
                        &self.ribs,
                        rib_out,
                        &self.peer_is_rr_client,
                        prefix,
                        peer,
                        prefix_send_max,
                        target_is_ebgp,
                        target_is_rr_client,
                        cluster_id,
                        sendable.as_ref(),
                        export_pol.as_ref(),
                        &mut announce,
                        &mut withdraw,
                        &mut nh_override_flags,
                    );
                } else {
                    Self::distribute_single_best_prefix(
                        loc_rib,
                        rib_out,
                        &self.peer_is_rr_client,
                        prefix,
                        peer,
                        target_is_ebgp,
                        target_is_rr_client,
                        cluster_id,
                        sendable.as_ref(),
                        export_pol.as_ref(),
                        &mut announce,
                        &mut withdraw,
                        &mut nh_override_flags,
                    );
                }
            }

            if is_dirty && !effective_flowspec_rules.is_empty() {
                Self::stage_flowspec_rules(
                    loc_rib,
                    rib_out,
                    &self.peer_is_rr_client,
                    &effective_flowspec_rules,
                    target_is_ebgp,
                    target_is_rr_client,
                    cluster_id,
                    sendable.as_ref(),
                    export_pol.as_ref(),
                    &mut fs_announce,
                    &mut fs_withdraw,
                );
            }

            if (!announce.is_empty()
                || !withdraw.is_empty()
                || !fs_announce.is_empty()
                || !fs_withdraw.is_empty())
                && let Some(tx) = self.outbound_peers.get(&peer)
            {
                // If a prior initial dump / route-refresh EoR was deferred,
                // piggyback it on the successful dirty resync update so it
                // can't be starved behind the resync message on a small queue.
                let pending_eor = if is_dirty {
                    self.pending_eor
                        .get(&peer)
                        .map(|families| families.iter().copied().collect())
                        .unwrap_or_default()
                } else {
                    vec![]
                };
                let update = OutboundRouteUpdate {
                    next_hop_override: nh_override_flags.clone(),
                    announce: announce.clone(),
                    withdraw: withdraw.clone(),
                    end_of_rib: pending_eor.clone(),
                    refresh_markers: vec![],
                    flowspec_announce: fs_announce.clone(),
                    flowspec_withdraw: fs_withdraw.clone(),
                };
                if tx.try_send(update).is_err() {
                    warn!(%peer, "outbound channel full or closed — marking dirty for resync");
                    self.metrics.record_outbound_route_drop(&peer.to_string());
                    self.dirty_peers.insert(peer);
                } else {
                    // Commit: apply staged mutations to AdjRibOut
                    let rib_out = self
                        .adj_ribs_out
                        .get_mut(&peer)
                        .expect("rib_out just accessed");
                    for route in &announce {
                        rib_out.insert(route.clone());
                    }
                    for &(ref prefix, path_id) in &withdraw {
                        rib_out.withdraw(prefix, path_id);
                    }
                    for route in &fs_announce {
                        rib_out.insert_flowspec(route.clone());
                    }
                    for rule in &fs_withdraw {
                        rib_out.remove_flowspec(rule);
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
                    if is_dirty {
                        self.dirty_peers.remove(&peer);
                        if pending_eor.is_empty() {
                            self.flush_pending_eor(peer);
                        } else {
                            self.pending_eor.remove(&peer);
                        }
                        self.retry_pending_refresh(peer);
                    }
                }
            } else if is_dirty
                && announce.is_empty()
                && withdraw.is_empty()
                && fs_announce.is_empty()
                && fs_withdraw.is_empty()
            {
                // Dirty peer with no diff — already in sync
                self.dirty_peers.remove(&peer);
                self.flush_pending_eor(peer);
                self.retry_pending_refresh(peer);
            }
        }
    }

    /// Recompute `FlowSpec` Loc-RIB best routes for affected rules and
    /// distribute changes to all outbound peers.
    pub(super) fn recompute_and_distribute_flowspec(
        &mut self,
        affected: &HashSet<rustbgpd_wire::FlowSpecRule>,
    ) {
        use crate::route::FlowSpecRoute;

        let mut changed_rules: HashSet<rustbgpd_wire::FlowSpecRule> = HashSet::new();

        for rule in affected {
            let candidates: Vec<&FlowSpecRoute> = self
                .ribs
                .values()
                .flat_map(|rib| rib.iter_flowspec_rule(rule))
                .collect();
            let did_change = self
                .loc_rib
                .recompute_flowspec(rule.clone(), candidates.into_iter());
            if did_change {
                changed_rules.insert(rule.clone());
            }
        }

        if changed_rules.is_empty() {
            return;
        }

        self.metrics
            .set_loc_rib_prefixes("flowspec", gauge_val(self.loc_rib.flowspec_len()));

        // Distribute FlowSpec changes to outbound peers
        let peers: Vec<IpAddr> = self.outbound_peers.keys().copied().collect();
        for peer in peers {
            let sendable = self.peer_sendable_families.get(&peer).cloned();
            let has_fs = sendable.as_ref().is_some_and(|families| {
                families.contains(&(rustbgpd_wire::Afi::Ipv4, rustbgpd_wire::Safi::FlowSpec))
                    || families.contains(&(rustbgpd_wire::Afi::Ipv6, rustbgpd_wire::Safi::FlowSpec))
            });
            if !has_fs {
                continue;
            }

            let target_is_ebgp = self.peer_is_ebgp.get(&peer).copied().unwrap_or(true);
            let target_is_rr_client = self.peer_is_rr_client.get(&peer).copied().unwrap_or(false);
            let export_pol = self.export_policy_for(peer).cloned();

            let rib_out = self
                .adj_ribs_out
                .entry(peer)
                .or_insert_with(|| crate::adj_rib_out::AdjRibOut::new(peer));

            let mut fs_announce = Vec::new();
            let mut fs_withdraw = Vec::new();
            Self::stage_flowspec_rules(
                &self.loc_rib,
                rib_out,
                &self.peer_is_rr_client,
                &changed_rules,
                target_is_ebgp,
                target_is_rr_client,
                self.cluster_id,
                sendable.as_ref(),
                export_pol.as_ref(),
                &mut fs_announce,
                &mut fs_withdraw,
            );

            if (!fs_announce.is_empty() || !fs_withdraw.is_empty())
                && let Some(tx) = self.outbound_peers.get(&peer)
            {
                let update = OutboundRouteUpdate {
                    announce: vec![],
                    withdraw: vec![],
                    end_of_rib: vec![],
                    refresh_markers: vec![],
                    next_hop_override: vec![],
                    flowspec_announce: fs_announce.clone(),
                    flowspec_withdraw: fs_withdraw.clone(),
                };
                if tx.try_send(update).is_err() {
                    warn!(%peer, "outbound channel full — FlowSpec update deferred");
                    self.dirty_peers.insert(peer);
                } else {
                    // Commit to AdjRibOut
                    let rib_out = self
                        .adj_ribs_out
                        .get_mut(&peer)
                        .expect("rib_out just accessed");
                    for route in &fs_announce {
                        rib_out.insert_flowspec(route.clone());
                    }
                    for rule in &fs_withdraw {
                        rib_out.remove_flowspec(rule);
                    }
                    self.metrics.set_adj_rib_out_prefixes(
                        &peer.to_string(),
                        "flowspec",
                        gauge_val(rib_out.flowspec_len()),
                    );
                }
            }
        }
    }
}
