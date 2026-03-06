use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};

use rustbgpd_policy::PolicyChain;
use rustbgpd_wire::{FlowSpecRule, Prefix};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::RibManager;
use super::helpers::{gauge_val, prefix_family};
use crate::adj_rib_out::AdjRibOut;
use crate::update::OutboundRouteUpdate;

impl RibManager {
    pub(super) fn handle_peer_down(&mut self, peer: IpAddr) {
        if self.gr_peers.remove(&peer).is_some() {
            self.gr_stale_deadlines.remove(&peer);
            self.gr_stale_routes_time.remove(&peer);
            self.llgr_peer_config.remove(&peer);
            info!(%peer, "peer down during graceful restart — aborting GR");
            let peer_label = peer.to_string();
            self.metrics.set_gr_active(&peer_label, false);
            self.metrics.set_gr_stale_routes(&peer_label, 0);
        }

        if self.llgr_peers.remove(&peer).is_some() {
            self.llgr_stale_deadlines.remove(&peer);
            info!(%peer, "peer down during LLGR — aborting LLGR");
            let peer_label = peer.to_string();
            self.metrics.set_gr_active(&peer_label, false);
            self.metrics.set_gr_stale_routes(&peer_label, 0);
        }

        if let Some(rib) = self.ribs.get_mut(&peer) {
            let affected: HashSet<Prefix> = rib.iter().map(|r| r.prefix).collect();
            let count = rib.len();
            let fs_affected: HashSet<FlowSpecRule> =
                rib.iter_flowspec().map(|r| r.rule.clone()).collect();
            rib.clear();
            rib.clear_flowspec();
            debug!(%peer, cleared = count, "peer down — rib cleared");
            self.metrics.set_rib_prefixes(&peer.to_string(), "all", 0);
            let changed = self.recompute_best(&affected);
            self.distribute_changes(&changed, &affected);
            if !fs_affected.is_empty() {
                self.recompute_and_distribute_flowspec(&fs_affected);
            }
        }

        self.adj_ribs_out.remove(&peer);
        self.metrics
            .set_adj_rib_out_prefixes(&peer.to_string(), "all", 0);
        self.outbound_peers.remove(&peer);
        self.peer_export_policies.remove(&peer);
        self.peer_sendable_families.remove(&peer);
        self.peer_is_ebgp.remove(&peer);
        self.peer_is_rr_client.remove(&peer);
        self.peer_add_path_send_max.remove(&peer);
        self.peer_add_path_send_families.remove(&peer);
        self.peer_asn.remove(&peer);
        self.peer_group.remove(&peer);
        self.peer_bgp_id.remove(&peer);
        self.dirty_peers.remove(&peer);
        self.pending_eor.remove(&peer);
        self.clear_peer_refresh_state(peer);
    }

    #[expect(clippy::too_many_arguments)]
    pub(super) fn handle_peer_up(
        &mut self,
        peer: IpAddr,
        peer_asn: u32,
        peer_router_id: Ipv4Addr,
        outbound_tx: mpsc::Sender<OutboundRouteUpdate>,
        export_policy: Option<PolicyChain>,
        sendable_families: Vec<(rustbgpd_wire::Afi, rustbgpd_wire::Safi)>,
        is_ebgp: bool,
        route_reflector_client: bool,
        add_path_send_families: Vec<(rustbgpd_wire::Afi, rustbgpd_wire::Safi)>,
        add_path_send_max: u32,
    ) {
        self.peer_asn.insert(peer, peer_asn);
        self.peer_bgp_id.insert(peer, peer_router_id);

        if self.gr_peers.contains_key(&peer) {
            if let Some(&srt) = self.gr_stale_routes_time.get(&peer) {
                let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(srt);
                self.gr_stale_deadlines.insert(peer, deadline);
            }
            info!(%peer, "peer re-established during GR — waiting for End-of-RIB");
        } else if self.llgr_peers.contains_key(&peer)
            && let Some(llgr_families) = self.llgr_peers.remove(&peer)
        {
            self.llgr_stale_deadlines.remove(&peer);
            let srt = self
                .llgr_peer_config
                .get(&peer)
                .map_or(360, |c| c.stale_routes_time);
            self.gr_stale_routes_time.insert(peer, srt);
            self.gr_peers.insert(peer, llgr_families);
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(srt);
            self.gr_stale_deadlines.insert(peer, deadline);
            info!(%peer, stale_routes_time = srt, "peer re-established during LLGR — waiting for End-of-RIB");
        }

        debug!(%peer, "peer up — registering for outbound updates");
        let peer_label = peer.to_string();
        self.metrics.set_rib_prefixes(&peer_label, "all", 0);
        self.metrics.set_adj_rib_out_prefixes(&peer_label, "all", 0);
        self.outbound_peers.insert(peer, outbound_tx);
        self.peer_export_policies
            .insert(peer, export_policy.or_else(|| self.export_policy.clone()));
        self.peer_sendable_families.insert(peer, sendable_families);
        self.peer_is_ebgp.insert(peer, is_ebgp);
        self.peer_is_rr_client.insert(peer, route_reflector_client);
        self.peer_add_path_send_families
            .insert(peer, add_path_send_families);
        self.peer_add_path_send_max.insert(peer, add_path_send_max);
        self.send_initial_table(peer);
    }

    pub(super) fn handle_set_peer_policy_context(
        &mut self,
        peer: IpAddr,
        peer_group: Option<String>,
    ) {
        if let Some(peer_group) = peer_group {
            self.peer_group.insert(peer, peer_group);
        } else {
            self.peer_group.remove(&peer);
        }
    }

    /// Send the full Loc-RIB to a newly established peer (initial table dump).
    ///
    /// `AdjRibOut` is only populated after a successful channel send. On
    /// failure the peer is marked dirty so `distribute_changes()` will
    /// retry a full resync via the resync timer.
    #[expect(clippy::too_many_lines)]
    pub(super) fn send_initial_table(&mut self, peer: IpAddr) {
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

        let mut all_prefixes: HashSet<Prefix> = self.loc_rib.iter().map(|r| r.prefix).collect();
        for rib in self.ribs.values() {
            all_prefixes.extend(rib.iter().map(|r| r.prefix));
        }

        // Stage against an empty outbound view so initial dump always
        // re-sends the full current table for this peer.
        let initial_view = AdjRibOut::new(peer);

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
                    &initial_view,
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
                    &initial_view,
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

        let all_flowspec_rules: HashSet<FlowSpecRule> = self
            .loc_rib
            .iter_flowspec()
            .map(|route| route.rule.clone())
            .collect();
        if !all_flowspec_rules.is_empty() {
            Self::stage_flowspec_rules(
                loc_rib,
                &initial_view,
                &self.peer_is_rr_client,
                &all_flowspec_rules,
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

        // Determine EoR families from this peer's sendable families
        let eor_families = self
            .peer_sendable_families
            .get(&peer)
            .cloned()
            .unwrap_or_default();

        if let Some(tx) = self.outbound_peers.get(&peer) {
            if !announce.is_empty()
                || !withdraw.is_empty()
                || !fs_announce.is_empty()
                || !fs_withdraw.is_empty()
            {
                let update = OutboundRouteUpdate {
                    next_hop_override: nh_override_flags.clone(),
                    announce: announce.clone(),
                    withdraw: withdraw.clone(),
                    end_of_rib: vec![],
                    refresh_markers: vec![],
                    flowspec_announce: fs_announce.clone(),
                    flowspec_withdraw: fs_withdraw.clone(),
                };
                if tx.try_send(update).is_err() {
                    warn!(%peer, "outbound channel full or closed during initial dump — marking dirty");
                    self.metrics.record_outbound_route_drop(&peer.to_string());
                    for f in &eor_families {
                        self.pending_eor.entry(peer).or_default().insert(*f);
                    }
                    self.dirty_peers.insert(peer);
                    return;
                }
                // Commit: populate AdjRibOut with what was actually sent
                let rib_out = self
                    .adj_ribs_out
                    .entry(peer)
                    .or_insert_with(|| AdjRibOut::new(peer));
                for route in &announce {
                    rib_out.insert(route.clone());
                }
                for (prefix, path_id) in &withdraw {
                    rib_out.withdraw(prefix, *path_id);
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
            }

            // Send End-of-RIB markers for all sendable families
            if !eor_families.is_empty() {
                let eor = OutboundRouteUpdate {
                    next_hop_override: vec![],
                    announce: vec![],
                    withdraw: vec![],
                    end_of_rib: eor_families.clone(),
                    refresh_markers: vec![],
                    flowspec_announce: vec![],
                    flowspec_withdraw: vec![],
                };
                if tx.try_send(eor).is_err() {
                    warn!(%peer, "outbound channel full — `EoR` deferred");
                    for f in &eor_families {
                        self.pending_eor.entry(peer).or_default().insert(*f);
                    }
                    self.dirty_peers.insert(peer);
                }
            }
        }
    }
}
