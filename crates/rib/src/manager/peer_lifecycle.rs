use std::collections::HashSet;
use std::net::IpAddr;

use rustbgpd_wire::{FlowSpecRule, Prefix};
use tracing::warn;

use super::helpers::{gauge_val, prefix_family};
use super::RibManager;
use crate::adj_rib_out::AdjRibOut;
use crate::update::OutboundRouteUpdate;

impl RibManager {
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
