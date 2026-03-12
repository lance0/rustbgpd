use std::collections::HashSet;
use std::net::IpAddr;

use rustbgpd_wire::{Afi, FlowSpecRule, Prefix, RouteRefreshSubtype, Safi};
use tracing::{debug, info, warn};

use super::RibManager;
use super::helpers::{ERR_REFRESH_TIMEOUT, gauge_val, prefix_family};
use crate::adj_rib_out::AdjRibOut;
use crate::update::OutboundRouteUpdate;

impl RibManager {
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

            if let Some(rib) = self.ribs.get_mut(&peer) {
                rib.clear_stale((afi, safi));
                rib.clear_stale_flowspec((afi, safi));
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

            let peer_label = peer.to_string();
            let stale_count = self
                .ribs
                .get(&peer)
                .map_or(0, |rib| rib.iter().filter(|r| r.is_stale).count());
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

            if let Some(rib) = self.ribs.get_mut(&peer) {
                rib.clear_llgr_stale((afi, safi));
                rib.clear_llgr_stale_flowspec((afi, safi));
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

            let peer_label = peer.to_string();
            let llgr_stale_count = self
                .ribs
                .get(&peer)
                .map_or(0, |rib| rib.iter().filter(|r| r.is_llgr_stale).count());
            self.metrics
                .set_gr_stale_routes(&peer_label, gauge_val(llgr_stale_count));

            let all_done = self.llgr_peers.get(&peer).is_some_and(HashSet::is_empty);
            if all_done {
                info!(%peer, "LLGR complete — all End-of-RIB received");
                self.llgr_peers.remove(&peer);
                self.llgr_stale_deadlines.remove(&peer);
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
        if let Some(rib) = self.ribs.get(&peer) {
            if safi == Safi::FlowSpec {
                let stale = self.refresh_stale_flowspec.entry(peer).or_default();
                stale.retain(|(stale_afi, _, _)| *stale_afi != afi);
                for route in rib.iter_flowspec().filter(|route| route.afi == afi) {
                    stale.insert((route.afi, route.rule.clone(), route.path_id));
                }
            } else {
                let stale = self.refresh_stale_routes.entry(peer).or_default();
                stale.retain(|(prefix, _)| prefix_family(prefix) != (afi, safi));
                for route in rib
                    .iter()
                    .filter(|route| prefix_family(&route.prefix) == (afi, safi))
                {
                    stale.insert((route.prefix, route.path_id));
                }
            }
        }
    }

    pub(super) fn handle_end_route_refresh(&mut self, peer: IpAddr, afi: Afi, safi: Safi) {
        self.finish_route_refresh(peer, afi, safi, false);
    }

    /// Re-advertise the Loc-RIB for a given family to a peer, followed by `EoR`.
    /// Called when a peer sends ROUTE-REFRESH (RFC 2918).
    #[expect(clippy::too_many_lines)]
    pub(super) fn send_route_refresh_response(&mut self, peer: IpAddr, afi: Afi, safi: Safi) {
        let family = (afi, safi);
        let mut announce = Vec::new();
        let mut withdraw = Vec::new();
        let mut nh_override_flags: Vec<Option<rustbgpd_policy::NextHopAction>> = Vec::new();
        let mut fs_announce = Vec::new();
        let mut fs_withdraw = Vec::new();
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
                    &mut fs_announce,
                    &mut fs_withdraw,
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
                        &mut announce,
                        &mut withdraw,
                        &mut nh_override_flags,
                    );
                } else {
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
                        &mut announce,
                        &mut withdraw,
                        &mut nh_override_flags,
                    );
                }
            }
        }

        if self.outbound_peers.contains_key(&peer) {
            if !self.try_send_and_commit_outbound_update(
                peer,
                nh_override_flags,
                announce,
                withdraw,
                vec![family],
                vec![
                    (afi, safi, RouteRefreshSubtype::BoRR),
                    (afi, safi, RouteRefreshSubtype::EoRR),
                ],
                fs_announce,
                fs_withdraw,
            ) {
                warn!(%peer, ?family, "outbound channel full during route refresh response");
                self.metrics.record_outbound_route_drop(&peer.to_string());
                self.pending_refresh.entry(peer).or_default().insert(family);
                self.dirty_peers.insert(peer);
                return;
            }
            self.pending_refresh
                .entry(peer)
                .or_default()
                .remove(&family);
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

        let mut affected = HashSet::new();
        let mut fs_affected = HashSet::new();
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
            self.metrics
                .set_rib_prefixes(&peer.to_string(), "all", gauge_val(rib.len()));
            self.metrics.set_rib_prefixes(
                &peer.to_string(),
                "flowspec",
                gauge_val(rib.flowspec_len()),
            );
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

        let clear_refresh_entry = if let Some(families) = self.refresh_in_progress.get_mut(&peer) {
            families.remove(&family);
            families.is_empty()
        } else {
            false
        };
        if clear_refresh_entry {
            self.refresh_in_progress.remove(&peer);
        }

        let changed = self.recompute_best(&affected);
        self.distribute_changes(&changed, &affected);
        if !fs_affected.is_empty() {
            self.recompute_and_distribute_flowspec(&fs_affected);
        }
    }
}
