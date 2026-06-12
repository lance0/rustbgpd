use std::collections::HashSet;
use std::net::IpAddr;

use rustbgpd_wire::{Afi, EvpnRouteKey, FlowSpecRule, Prefix, RouteRefreshSubtype, Safi};
use tracing::{debug, info, warn};

use super::helpers::{ERR_REFRESH_TIMEOUT, afi_safi_label, gauge_val, prefix_family};
use super::{PolicyFilteredRouteKey, RibManager};
use crate::adj_rib_out::AdjRibOut;
use crate::update::OutboundRouteUpdate;

impl RibManager {
    pub(super) fn update_peer_refresh_metrics(&self, peer: IpAddr) {
        if let Some(families) = self.refresh_in_progress.get(&peer) {
            for &(afi, safi) in families {
                self.update_refresh_metrics(peer, afi, safi);
            }
        }
    }

    pub(super) fn clear_peer_refresh_metrics(&self, peer: IpAddr) {
        if let Some(families) = self.refresh_in_progress.get(&peer) {
            let peer_label = peer.to_string();
            for &(afi, safi) in families {
                let family_label = afi_safi_label(afi, safi);
                self.metrics
                    .set_route_refresh_in_progress(&peer_label, family_label, false);
                self.metrics
                    .set_route_refresh_stale_entries(&peer_label, family_label, 0);
            }
        }
    }

    fn update_refresh_metrics(&self, peer: IpAddr, afi: Afi, safi: Safi) {
        let active = self
            .refresh_in_progress
            .get(&peer)
            .is_some_and(|families| families.contains(&(afi, safi)));
        let stale_count = if active {
            self.refresh_stale_counts
                .get(&(peer, afi, safi))
                .copied()
                .unwrap_or(0)
        } else {
            0
        };
        let peer_label = peer.to_string();
        let family_label = afi_safi_label(afi, safi);
        self.metrics
            .set_route_refresh_in_progress(&peer_label, family_label, active);
        self.metrics.set_route_refresh_stale_entries(
            &peer_label,
            family_label,
            gauge_val(stale_count),
        );
    }

    pub(super) fn set_refresh_stale_count(
        &mut self,
        peer: IpAddr,
        afi: Afi,
        safi: Safi,
        count: usize,
    ) {
        if count == 0 {
            self.refresh_stale_counts.remove(&(peer, afi, safi));
        } else {
            self.refresh_stale_counts.insert((peer, afi, safi), count);
        }
    }

    pub(super) fn decrement_refresh_stale_count(
        &mut self,
        peer: IpAddr,
        afi: Afi,
        safi: Safi,
        count: usize,
    ) {
        if count == 0 {
            return;
        }
        let Some(stale_count) = self.refresh_stale_counts.get_mut(&(peer, afi, safi)) else {
            return;
        };
        *stale_count = stale_count.saturating_sub(count);
        if *stale_count == 0 {
            self.refresh_stale_counts.remove(&(peer, afi, safi));
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "End-of-RIB handler covers GR and LLGR branches for all three families (unicast, FlowSpec, EVPN)"
    )]
    pub(super) fn handle_end_of_rib(&mut self, peer: IpAddr, afi: Afi, safi: Safi) {
        info!(%peer, ?afi, ?safi, "received End-of-RIB");
        let is_gr_peer = self.gr_peers.contains_key(&peer);
        let is_llgr_peer = self.llgr_peers.contains_key(&peer);
        if !is_gr_peer && !is_llgr_peer {
            debug!(%peer, ?afi, ?safi, "End-of-RIB received without active GR/LLGR state, ignoring");
        }
        if is_gr_peer {
            if let Some(awaiting) = self.gr_peers.get_mut(&peer) {
                awaiting.remove(&(afi, safi));
            }

            let fs_affected: HashSet<FlowSpecRule> = self
                .ribs
                .get(&peer)
                .map(|rib| {
                    rib.iter_flowspec()
                        .filter(|route| route.afi == afi)
                        .map(|route| route.rule.clone())
                        .collect()
                })
                .unwrap_or_default();

            let evpn_affected: HashSet<EvpnRouteKey> = if (afi, safi) == (Afi::L2Vpn, Safi::Evpn) {
                self.ribs
                    .get(&peer)
                    .map(|rib| {
                        rib.iter_evpn()
                            .map(crate::route::EvpnRibRoute::key)
                            .collect()
                    })
                    .unwrap_or_default()
            } else {
                HashSet::new()
            };

            if let Some(rib) = self.ribs.get_mut(&peer) {
                rib.clear_stale((afi, safi));
                rib.clear_stale_flowspec((afi, safi));
                rib.clear_stale_evpn((afi, safi));
            }

            let affected: HashSet<Prefix> = self
                .ribs
                .get(&peer)
                .map(|rib| rib.iter().map(|r| r.prefix).collect())
                .unwrap_or_default();
            let changed = self.recompute_best(&affected);
            self.distribute_changes(&changed, &affected);
            if !fs_affected.is_empty() {
                self.recompute_and_distribute_flowspec(&fs_affected);
            }
            if !evpn_affected.is_empty() {
                self.recompute_and_distribute_evpn(&evpn_affected);
            }

            let peer_label = peer.to_string();
            let stale_count = self.ribs.get(&peer).map_or(0, |rib| {
                rib.iter().filter(|r| r.is_stale).count()
                    + rib.iter_flowspec().filter(|r| r.is_stale).count()
                    + rib.iter_evpn().filter(|r| r.is_stale).count()
            });
            self.metrics
                .set_gr_stale_routes(&peer_label, gauge_val(stale_count));

            let all_done = self.gr_peers.get(&peer).is_some_and(HashSet::is_empty);
            if all_done {
                info!(%peer, "graceful restart complete — all End-of-RIB received");
                self.gr_peers.remove(&peer);
                self.gr_stale_deadlines.remove(&peer);
                self.gr_stale_routes_time.remove(&peer);
                self.llgr_peer_config.remove(&peer);
                self.metrics.set_gr_active(&peer_label, false);
                self.metrics.set_gr_stale_routes(&peer_label, 0);
            }
        } else if is_llgr_peer {
            if let Some(awaiting) = self.llgr_peers.get_mut(&peer) {
                awaiting.remove(&(afi, safi));
            }

            let fs_affected: HashSet<FlowSpecRule> = self
                .ribs
                .get(&peer)
                .map(|rib| {
                    rib.iter_flowspec()
                        .filter(|route| route.afi == afi)
                        .map(|route| route.rule.clone())
                        .collect()
                })
                .unwrap_or_default();

            let evpn_affected: HashSet<EvpnRouteKey> = if (afi, safi) == (Afi::L2Vpn, Safi::Evpn) {
                self.ribs
                    .get(&peer)
                    .map(|rib| {
                        rib.iter_evpn()
                            .map(crate::route::EvpnRibRoute::key)
                            .collect()
                    })
                    .unwrap_or_default()
            } else {
                HashSet::new()
            };

            if let Some(rib) = self.ribs.get_mut(&peer) {
                rib.clear_llgr_stale((afi, safi));
                rib.clear_llgr_stale_flowspec((afi, safi));
                rib.clear_llgr_stale_evpn((afi, safi));
            }

            let affected: HashSet<Prefix> = self
                .ribs
                .get(&peer)
                .map(|rib| rib.iter().map(|r| r.prefix).collect())
                .unwrap_or_default();
            let changed = self.recompute_best(&affected);
            self.distribute_changes(&changed, &affected);
            if !fs_affected.is_empty() {
                self.recompute_and_distribute_flowspec(&fs_affected);
            }
            if !evpn_affected.is_empty() {
                self.recompute_and_distribute_evpn(&evpn_affected);
            }

            let peer_label = peer.to_string();
            let llgr_stale_count = self.ribs.get(&peer).map_or(0, |rib| {
                rib.iter().filter(|r| r.is_llgr_stale).count()
                    + rib.iter_flowspec().filter(|r| r.is_llgr_stale).count()
                    + rib.iter_evpn().filter(|r| r.is_llgr_stale).count()
            });
            self.metrics
                .set_gr_stale_routes(&peer_label, gauge_val(llgr_stale_count));

            let all_done = self.llgr_peers.get(&peer).is_some_and(HashSet::is_empty);
            if all_done {
                info!(%peer, "LLGR complete — all End-of-RIB received");
                self.llgr_peers.remove(&peer);
                self.llgr_stale_deadlines.remove(&peer);
                // The LLGR config outlives GR→LLGR promotion; LLGR
                // completion is a terminal point, mirror the GR arm above.
                self.llgr_peer_config.remove(&peer);
                self.metrics.set_gr_active(&peer_label, false);
                self.metrics.set_gr_stale_routes(&peer_label, 0);
            }
        }
    }

    pub(super) fn handle_route_refresh_request(&mut self, peer: IpAddr, afi: Afi, safi: Safi) {
        info!(%peer, ?afi, ?safi, "handling route refresh request");
        self.send_route_refresh_response(peer, afi, safi);
    }

    pub(super) fn handle_begin_route_refresh(&mut self, peer: IpAddr, afi: Afi, safi: Safi) {
        info!(%peer, ?afi, ?safi, "beginning enhanced route refresh");
        self.refresh_in_progress
            .entry(peer)
            .or_default()
            .insert((afi, safi));
        self.refresh_deadlines.insert(
            (peer, afi, safi),
            tokio::time::Instant::now() + ERR_REFRESH_TIMEOUT,
        );
        let mut stale_count = 0usize;
        if let Some(rib) = self.ribs.get(&peer) {
            if safi == Safi::FlowSpec {
                let stale = self.refresh_stale_flowspec.entry(peer).or_default();
                stale.retain(|(stale_afi, _, _)| *stale_afi != afi);
                for route in rib.iter_flowspec().filter(|route| route.afi == afi) {
                    if stale.insert((route.afi, route.rule.clone(), route.path_id)) {
                        stale_count += 1;
                    }
                }
            } else if (afi, safi) == (Afi::L2Vpn, Safi::Evpn) {
                let stale = self.refresh_stale_evpn.entry(peer).or_default();
                stale.clear();
                for route in rib.iter_evpn() {
                    if stale.insert(route.key()) {
                        stale_count += 1;
                    }
                }
            } else {
                let stale = self.refresh_stale_routes.entry(peer).or_default();
                stale.retain(|(prefix, _)| prefix_family(prefix) != (afi, safi));
                for route in rib
                    .iter()
                    .filter(|route| prefix_family(&route.prefix) == (afi, safi))
                {
                    if stale.insert((route.prefix, route.path_id)) {
                        stale_count += 1;
                    }
                }
            }
        }
        self.set_refresh_stale_count(peer, afi, safi, stale_count);
        self.update_refresh_metrics(peer, afi, safi);
    }

    pub(super) fn handle_end_route_refresh(&mut self, peer: IpAddr, afi: Afi, safi: Safi) {
        self.finish_route_refresh(peer, afi, safi, false);
    }

    /// Re-advertise the Loc-RIB for a given family to a peer, followed by `EoR`.
    /// Called when a peer sends ROUTE-REFRESH (RFC 2918).
    #[expect(clippy::too_many_lines)]
    pub(super) fn send_route_refresh_response(&mut self, peer: IpAddr, afi: Afi, safi: Safi) {
        let family = (afi, safi);
        // RFC 5291 §6: a ROUTE-REFRESH (plain or ORF-carrying) for this family
        // lifts the initial-advertisement gate, so this response is the first
        // advertisement of the family — filtered through any installed ORF.
        if let Some(pending) = self.peer_orf_pending.get_mut(&peer) {
            pending.remove(&family);
        }
        // A GR restarter's EoR for this family may have been withheld at
        // `PeerUp` (`send_initial_table`) because the family was ORF-gated:
        // this refresh response IS the gated flood, so the deferred EoR must
        // follow it — as a genuine EoR UPDATE, not this response's own
        // `end_of_rib` entry, which transport substitutes with an EoRR
        // demarcation when enhanced route refresh is negotiated. A restarter
        // ends its RFC 4724 deferral on EoR, not on the RFC 7313 markers.
        let deferred_eor = self
            .gr_deferred_eor
            .get(&peer)
            .is_some_and(|families| families.contains(&family));
        let orf_filter = self
            .peer_orf_filters
            .get(&peer)
            .and_then(|m| m.get(&family))
            .cloned();
        let mut announce = Vec::new();
        let mut withdraw = Vec::new();
        let mut nh_override_flags: Vec<Option<rustbgpd_policy::NextHopAction>> = Vec::new();
        let mut fs_announce = Vec::new();
        let mut fs_withdraw = Vec::new();
        let mut evpn_announce = Vec::new();
        let mut evpn_withdraw = Vec::new();
        let export_pol = self.export_policy_for(peer).cloned();
        let sendable = self.peer_sendable_families.get(&peer).cloned();
        let target_is_ebgp = self.peer_is_ebgp.get(&peer).copied().unwrap_or(true);
        let target_is_rr_client = self.peer_is_rr_client.get(&peer).copied().unwrap_or(false);
        let target_peer_asn = self.peer_asn.get(&peer).copied();
        let target_peer_group = self.peer_group.get(&peer).map(String::as_str);
        let cluster_id = self.cluster_id;
        let peer_add_path_send_max = self.peer_add_path_send_max.get(&peer).copied().unwrap_or(0);
        let peer_add_path_send_families = self
            .peer_add_path_send_families
            .get(&peer)
            .cloned()
            .unwrap_or_default();
        let loc_rib = &self.loc_rib;
        let target_peer_label = peer.to_string();
        let metrics = self.metrics.clone();
        let policy_stats = self.export_policy_stats.entry(peer).or_default();

        let mut all_prefixes: HashSet<Prefix> = self
            .loc_rib
            .iter()
            .map(|r| r.prefix)
            .filter(|p| prefix_family(p) == family)
            .collect();
        for rib in self.ribs.values() {
            all_prefixes.extend(
                rib.iter()
                    .map(|r| r.prefix)
                    .filter(|p| prefix_family(p) == family),
            );
        }

        // Stage against an empty outbound view so ROUTE-REFRESH
        // re-advertises the current export set for this family rather than
        // diffing against what was already sent.
        let refresh_view = AdjRibOut::new(peer);
        let mut current_policy_filtered_routes: HashSet<PolicyFilteredRouteKey> = HashSet::new();

        if safi == Safi::FlowSpec {
            let flow_rules: HashSet<FlowSpecRule> = self
                .loc_rib
                .iter_flowspec()
                .filter(|route| route.afi == afi)
                .map(|route| route.rule.clone())
                .collect();
            if !flow_rules.is_empty() {
                Self::stage_flowspec_rules(
                    loc_rib,
                    &refresh_view,
                    &self.peer_is_rr_client,
                    &flow_rules,
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
        } else if (afi, safi) == (Afi::L2Vpn, Safi::Evpn) {
            let evpn_keys: HashSet<EvpnRouteKey> = self
                .loc_rib
                .iter_evpn()
                .map(crate::route::EvpnRibRoute::key)
                .collect();
            if !evpn_keys.is_empty() {
                Self::stage_evpn_routes(
                    loc_rib,
                    &refresh_view,
                    &self.peer_is_rr_client,
                    &evpn_keys,
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
                    false, // route refresh re-emits via empty refresh_view
                );
            }
        } else {
            for prefix in &all_prefixes {
                let prefix_send_max = if peer_add_path_send_max > 0
                    && peer_add_path_send_families.contains(&prefix_family(prefix))
                {
                    peer_add_path_send_max
                } else {
                    0
                };
                if prefix_send_max > 0 {
                    let mut policy_filtered = Vec::new();
                    Self::distribute_multipath_prefix(
                        &self.ribs,
                        &refresh_view,
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
                        orf_filter.as_ref(),
                        &metrics,
                        policy_stats,
                        &target_peer_label,
                        &mut announce,
                        &mut withdraw,
                        &mut nh_override_flags,
                        &mut policy_filtered,
                        false, // route refresh re-emits all anyway via empty refresh_view
                    );
                    current_policy_filtered_routes.extend(policy_filtered);
                } else {
                    let mut policy_filtered = Vec::new();
                    Self::distribute_single_best_prefix(
                        loc_rib,
                        &refresh_view,
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
                        orf_filter.as_ref(),
                        &metrics,
                        policy_stats,
                        &target_peer_label,
                        &mut announce,
                        &mut withdraw,
                        &mut nh_override_flags,
                        &mut policy_filtered,
                        false,
                    );
                    current_policy_filtered_routes.extend(policy_filtered);
                }
            }
            // The refresh view is intentionally empty so permitted routes are
            // re-advertised for ROUTE-REFRESH. That empty view cannot discover
            // routes that were advertised before a deferred ORF update and are
            // now denied by the installed filter, so withdraw those explicitly
            // from the real Adj-RIB-Out.
            if let (Some(filter), Some(rib_out)) =
                (orf_filter.as_ref(), self.adj_ribs_out.get(&peer))
            {
                for route in rib_out
                    .iter()
                    .filter(|r| prefix_family(&r.prefix) == family && !filter.permits(&r.prefix))
                {
                    withdraw.push((route.prefix, route.path_id));
                }
            }
        }

        if self.outbound_peers.contains_key(&peer) {
            if !self.try_send_and_commit_outbound_update(
                peer,
                nh_override_flags,
                announce,
                withdraw,
                if deferred_eor { vec![] } else { vec![family] },
                vec![
                    (afi, safi, RouteRefreshSubtype::BoRR),
                    (afi, safi, RouteRefreshSubtype::EoRR),
                ],
                fs_announce,
                fs_withdraw,
                evpn_announce,
                evpn_withdraw,
            ) {
                warn!(%peer, ?family, "outbound channel full during route refresh response");
                self.metrics.record_outbound_route_drop(&peer.to_string());
                self.pending_refresh.entry(peer).or_default().insert(family);
                self.dirty_peers.insert(peer);
                return;
            }
            self.update_policy_filtered_routes_for_prefixes(
                peer,
                &all_prefixes,
                &current_policy_filtered_routes,
            );
            self.pending_refresh
                .entry(peer)
                .or_default()
                .remove(&family);
            if deferred_eor {
                if let Some(families) = self.gr_deferred_eor.get_mut(&peer) {
                    families.remove(&family);
                    if families.is_empty() {
                        self.gr_deferred_eor.remove(&peer);
                    }
                }
                self.pending_eor.entry(peer).or_default().insert(family);
                // The gated flood was just enqueued above; flushing now keeps
                // the EoR behind it on the channel. A dirty peer defers to the
                // resync paths instead — they flush pending EoR only AFTER a
                // successful resync, and flushing here would emit any OTHER
                // deferred families' EoR ahead of the resync that replays
                // their table.
                if !self.dirty_peers.contains(&peer) {
                    self.flush_pending_eor(peer);
                }
            }
        }
    }

    /// Try to send any deferred `EoR` markers for a peer.
    ///
    /// Called after a successful dirty-peer resync. If the send fails again,
    /// the peer is re-marked dirty for another attempt.
    pub(super) fn flush_pending_eor(&mut self, peer: IpAddr) {
        let Some(families) = self.pending_eor.remove(&peer) else {
            return;
        };
        if families.is_empty() {
            return;
        }
        let Some(tx) = self.outbound_peers.get(&peer) else {
            return;
        };
        let eor = OutboundRouteUpdate {
            next_hop_override: vec![],
            announce: vec![],
            withdraw: vec![],
            end_of_rib: families.iter().copied().collect(),
            refresh_markers: vec![],
            flowspec_announce: vec![],
            flowspec_withdraw: vec![],
            evpn_announce: vec![],
            evpn_withdraw: vec![],
            request_refresh: vec![],
        };
        if tx.try_send(eor).is_err() {
            warn!(%peer, "outbound channel full — `EoR` still deferred");
            self.pending_eor.insert(peer, families);
            self.dirty_peers.insert(peer);
        }
    }

    /// Retry any deferred enhanced route refresh responses for a peer.
    pub(super) fn retry_pending_refresh(&mut self, peer: IpAddr) {
        let Some(families) = self.pending_refresh.remove(&peer) else {
            return;
        };
        for (afi, safi) in families {
            self.send_route_refresh_response(peer, afi, safi);
        }
    }

    /// Finish an active inbound enhanced route refresh window for a peer/family.
    ///
    /// When `timed_out` is true, treats the timeout as an implicit end-of-
    /// refresh sweep and logs a warning before cleaning up unreplaced state.
    #[expect(
        clippy::too_many_lines,
        reason = "refresh finisher sweeps unreplaced unicast, FlowSpec, and EVPN routes and clears per-family tracking state"
    )]
    pub(super) fn finish_route_refresh(
        &mut self,
        peer: IpAddr,
        afi: Afi,
        safi: Safi,
        timed_out: bool,
    ) {
        let family = (afi, safi);
        self.refresh_deadlines.remove(&(peer, afi, safi));

        let active = self
            .refresh_in_progress
            .get(&peer)
            .is_some_and(|families| families.contains(&family));
        if !active {
            debug!(%peer, ?afi, ?safi, "End-of-RIB-Refresh without active refresh state, ignoring");
            return;
        }
        if timed_out {
            warn!(
                %peer,
                ?afi,
                ?safi,
                timeout_secs = ERR_REFRESH_TIMEOUT.as_secs(),
                "enhanced route refresh timed out — sweeping unreplaced routes"
            );
        }

        let stale_route_keys: Vec<(Prefix, u32)> = self
            .refresh_stale_routes
            .get(&peer)
            .map(|stale| {
                stale
                    .iter()
                    .copied()
                    .filter(|(prefix, _)| prefix_family(prefix) == family)
                    .collect()
            })
            .unwrap_or_default();
        let stale_flowspec_keys: Vec<(FlowSpecRule, u32)> = self
            .refresh_stale_flowspec
            .get(&peer)
            .map(|stale| {
                stale
                    .iter()
                    .filter(|(stale_afi, _, _)| *stale_afi == afi && safi == Safi::FlowSpec)
                    .map(|(_, rule, path_id)| (rule.clone(), *path_id))
                    .collect()
            })
            .unwrap_or_default();
        let stale_evpn_keys: Vec<EvpnRouteKey> = if family == (Afi::L2Vpn, Safi::Evpn) {
            self.refresh_stale_evpn
                .get(&peer)
                .map(|stale| stale.iter().copied().collect())
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        let mut affected = HashSet::new();
        let mut fs_affected = HashSet::new();
        let mut evpn_affected: HashSet<EvpnRouteKey> = HashSet::new();
        if let Some(rib) = self.ribs.get_mut(&peer) {
            for (prefix, path_id) in &stale_route_keys {
                if rib.withdraw(prefix, *path_id) {
                    affected.insert(*prefix);
                }
            }
            for (rule, path_id) in &stale_flowspec_keys {
                if rib.withdraw_flowspec(rule, *path_id) {
                    fs_affected.insert(rule.clone());
                }
            }
            for key in &stale_evpn_keys {
                if rib.withdraw_evpn(key) {
                    evpn_affected.insert(*key);
                }
            }
            // Reclaim attribute interns dropped by the bulk withdraw —
            // each withdraw above can leave a `strong_count==1` Arc in
            // the intern table that wouldn't otherwise be GC'd until
            // some unrelated future withdraw on this peer.
            if !affected.is_empty() || !fs_affected.is_empty() || !evpn_affected.is_empty() {
                rib.gc_intern_table();
            }
            self.metrics
                .set_rib_prefixes(&peer.to_string(), "all", gauge_val(rib.len()));
            self.metrics.set_rib_prefixes(
                &peer.to_string(),
                "flowspec",
                gauge_val(rib.flowspec_len()),
            );
            self.metrics
                .set_rib_prefixes(&peer.to_string(), "evpn", gauge_val(rib.evpn_len()));
        }

        let clear_route_stale_entry = if let Some(stale) = self.refresh_stale_routes.get_mut(&peer)
        {
            stale.retain(|(prefix, _)| prefix_family(prefix) != family);
            stale.is_empty()
        } else {
            false
        };
        if clear_route_stale_entry {
            self.refresh_stale_routes.remove(&peer);
        }

        let clear_flowspec_stale_entry =
            if let Some(stale) = self.refresh_stale_flowspec.get_mut(&peer) {
                stale.retain(|(stale_afi, _, _)| !(*stale_afi == afi && safi == Safi::FlowSpec));
                stale.is_empty()
            } else {
                false
            };
        if clear_flowspec_stale_entry {
            self.refresh_stale_flowspec.remove(&peer);
        }

        if family == (Afi::L2Vpn, Safi::Evpn) {
            self.refresh_stale_evpn.remove(&peer);
        }
        self.refresh_stale_counts.remove(&(peer, afi, safi));

        let clear_refresh_entry = if let Some(families) = self.refresh_in_progress.get_mut(&peer) {
            families.remove(&family);
            families.is_empty()
        } else {
            false
        };
        if clear_refresh_entry {
            self.refresh_in_progress.remove(&peer);
        }
        self.update_refresh_metrics(peer, afi, safi);

        let changed = self.recompute_best(&affected);
        self.distribute_changes(&changed, &affected);
        if !fs_affected.is_empty() {
            self.recompute_and_distribute_flowspec(&fs_affected);
        }
        if !evpn_affected.is_empty() {
            self.recompute_and_distribute_evpn(&evpn_affected);
        }
    }
}
