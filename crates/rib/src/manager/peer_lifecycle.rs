use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};

use rustbgpd_policy::PolicyChain;
use rustbgpd_wire::{EvpnRouteKey, FlowSpecRule, Prefix};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::helpers::prefix_family;
use super::{PolicyFilteredRouteKey, RibManager};
use crate::adj_rib_out::AdjRibOut;
use crate::update::OutboundRouteUpdate;

impl RibManager {
    pub(super) fn handle_peer_down(&mut self, peer: IpAddr) {
        self.clear_policy_filtered_routes_for_peer(peer);
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
            // The LLGR config survives GR→LLGR promotion (handle_peer_up
            // reads it on re-establishment), so an LLGR abort must drop it
            // here — the GR arm above won't fire for a peer already
            // promoted out of gr_peers.
            self.llgr_peer_config.remove(&peer);
            info!(%peer, "peer down during LLGR — aborting LLGR");
            let peer_label = peer.to_string();
            self.metrics.set_gr_active(&peer_label, false);
            self.metrics.set_gr_stale_routes(&peer_label, 0);
        }

        if let Some(rib) = self.ribs.remove(&peer) {
            let affected: HashSet<Prefix> = rib.iter().map(|r| r.prefix).collect();
            let count = rib.len();
            let fs_affected: HashSet<FlowSpecRule> =
                rib.iter_flowspec().map(|r| r.rule.clone()).collect();
            let evpn_affected: HashSet<EvpnRouteKey> = rib
                .iter_evpn()
                .map(crate::route::EvpnRibRoute::key)
                .collect();
            debug!(%peer, cleared = count, "peer down — rib cleared");
            self.metrics.set_rib_prefixes(&peer.to_string(), "all", 0);
            self.metrics.set_rib_prefixes(&peer.to_string(), "evpn", 0);
            let changed = self.recompute_best(&affected);
            self.distribute_changes(&changed, &affected);
            if !fs_affected.is_empty() {
                self.recompute_and_distribute_flowspec(&fs_affected);
            }
            if !evpn_affected.is_empty() {
                self.recompute_and_distribute_evpn(&evpn_affected);
            }
        }

        self.metrics
            .set_adj_rib_out_prefixes(&peer.to_string(), "all", 0);
        self.metrics
            .set_adj_rib_out_prefixes(&peer.to_string(), "evpn", 0);
        self.clear_outbound_peer_state(peer);
        self.peer_asn.remove(&peer);
        self.peer_group.remove(&peer);
        self.peer_bgp_id.remove(&peer);
        self.force_outbound_peers.remove(&peer);
        self.clear_peer_refresh_metrics(peer);
    }

    /// Handle a peer *deletion* (the neighbor was removed from the
    /// configuration — not a session flap, which keeps its series).
    ///
    /// The delete path queues this after the session's own `PeerDown`,
    /// so the per-peer teardown above (zeroed gauges, cleared maps) has
    /// already run when this arrives; re-running it here is a cheap
    /// no-op safety net for a peer that was deleted while never
    /// established. Afterwards, remove the deleted peer's metric label
    /// sets entirely — gauges frozen at their last value would
    /// otherwise keep advertising a peer that no longer exists.
    pub(super) fn handle_peer_deleted(&mut self, peer: IpAddr) {
        self.handle_peer_down(peer);
        self.metrics.reap_peer_series(&peer.to_string());
    }

    /// Clear the per-session outbound state shared by the `PeerDown` and
    /// graceful-restart teardown paths. Keeping ONE list prevents the two
    /// cleanup sites from drifting — the GR path historically missed maps
    /// added later (the ORF filter/gate leak). Peer-identity maps
    /// (`peer_asn`/`peer_group`/`peer_bgp_id`) stay out: GR keeps them for
    /// the returning peer; `PeerDown` removes them at its call site.
    pub(super) fn clear_outbound_peer_state(&mut self, peer: IpAddr) {
        self.outbound_peers.remove(&peer);
        self.adj_ribs_out.remove(&peer);
        self.peer_export_policies.remove(&peer);
        self.peer_sendable_families.remove(&peer);
        self.peer_is_ebgp.remove(&peer);
        self.peer_is_rr_client.remove(&peer);
        self.peer_add_path_send_max.remove(&peer);
        self.peer_add_path_send_families.remove(&peer);
        // ORF state is per-session (RFC 5291): a surviving §6 gate can never
        // be lifted by a reconnecting session that didn't negotiate ORF
        // (suppressing the family's flood indefinitely), and a surviving
        // filter keeps constraining churn the new session never asked to
        // filter. `handle_peer_up` re-arms the gate from the new session's
        // `negotiated_orf_recv`.
        self.peer_orf_filters.remove(&peer);
        self.peer_orf_pending.remove(&peer);
        // The GR-deferred EoR is per-session too: the deferral pairs with
        // THIS session's §6 gate; a new session re-derives it on `PeerUp`.
        self.gr_deferred_eor.remove(&peer);
        self.dirty_peers.remove(&peer);
        self.pending_eor.remove(&peer);
        self.pending_route_batches.retain(|prb| prb.peer() != peer);
        // Drop per-peer export-policy counters alongside the rest of the
        // per-peer state. Without this the HashMap grows unbounded as
        // peers come and go (especially under dynamic neighbors), and
        // stale aggregates leak across peer-identity reuse. The reset
        // also gives operators consistent semantics: the import-side
        // counters reset on session-down (they live on PeerSessionState),
        // and the export-side aggregates do too — same per-session
        // contract in both directions. Operators that need across-flap
        // totals can subtract Prometheus snapshots
        // (`bgp_policy_routes_total` is monotonic per process).
        self.export_policy_stats.remove(&peer);
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
        negotiated_orf_recv: Vec<(rustbgpd_wire::Afi, rustbgpd_wire::Safi)>,
    ) {
        self.peer_asn.insert(peer, peer_asn);
        self.peer_bgp_id.insert(peer, peer_router_id);

        // RFC 5291 §6: gate the initial advertisement for ORF-receive families
        // until the peer sends a ROUTE-REFRESH, so we don't flood the full
        // table before its filter arrives. The gate is lifted in
        // `handle_route_refresh_request` / `handle_peer_orf_update`.
        if !negotiated_orf_recv.is_empty() {
            self.peer_orf_pending
                .insert(peer, negotiated_orf_recv.into_iter().collect());
        }

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
        let mut evpn_announce = Vec::new();
        let mut evpn_withdraw = Vec::new();
        let mut current_policy_filtered_routes: HashSet<PolicyFilteredRouteKey> = HashSet::new();
        let export_pol = self.export_policy_for(peer).cloned();
        let sendable = self.peer_sendable_families.get(&peer).cloned();
        // RFC 5291 §6 initial-advertisement gate: suppress route advertisement
        // for families still awaiting the peer's first ROUTE-REFRESH. For a
        // non-GR peer the EoR is still emitted (an honest "empty table so
        // far"); for a GR restarter the EoR is deferred until the gated flood
        // is sent (see the `eor_families` carve-out below). The filtered flood
        // follows once the gate is lifted.
        let orf_gated = self
            .peer_orf_pending
            .get(&peer)
            .cloned()
            .unwrap_or_default();
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

        let mut all_prefixes: HashSet<Prefix> = self.loc_rib.iter().map(|r| r.prefix).collect();
        for rib in self.ribs.values() {
            all_prefixes.extend(rib.iter().map(|r| r.prefix));
        }

        // Stage against an empty outbound view so initial dump always
        // re-sends the full current table for this peer.
        let initial_view = AdjRibOut::new(peer);

        for prefix in &all_prefixes {
            if orf_gated.contains(&prefix_family(prefix)) {
                continue;
            }
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
                    // ORF: gated families are skipped above; a non-gated family
                    // has no installed filter during the initial dump.
                    None,
                    &metrics,
                    policy_stats,
                    &target_peer_label,
                    &mut announce,
                    &mut withdraw,
                    &mut nh_override_flags,
                    &mut policy_filtered,
                    false, // initial dump — equality check is correct
                );
                current_policy_filtered_routes.extend(policy_filtered);
            } else {
                let mut policy_filtered = Vec::new();
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
                    // ORF: gated families are skipped above; a non-gated family
                    // has no installed filter during the initial dump.
                    None,
                    &metrics,
                    policy_stats,
                    &target_peer_label,
                    &mut announce,
                    &mut withdraw,
                    &mut nh_override_flags,
                    &mut policy_filtered,
                    false, // initial dump — equality check is correct
                );
                current_policy_filtered_routes.extend(policy_filtered);
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
                &metrics,
                policy_stats,
                &target_peer_label,
                &mut fs_announce,
                &mut fs_withdraw,
            );
        }

        // EVPN initial dump — without this, peers that join after the
        // fabric has converged see an EoR with zero EVPN routes and
        // operate with no EVPN reachability until unrelated RIB churn
        // forces redistribution. Mirrors the FlowSpec staging block.
        let all_evpn_keys: HashSet<rustbgpd_wire::EvpnRouteKey> = self
            .loc_rib
            .iter_evpn()
            .map(crate::route::EvpnRibRoute::key)
            .collect();
        if !all_evpn_keys.is_empty() {
            Self::stage_evpn_routes(
                loc_rib,
                &initial_view,
                &self.peer_is_rr_client,
                &all_evpn_keys,
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
                false, // initial dump — equality check is correct
            );
        }

        // Determine EoR families from this peer's sendable families
        let mut eor_families = self
            .peer_sendable_families
            .get(&peer)
            .cloned()
            .unwrap_or_default();
        // RFC 4724: a GR RESTARTER takes our EoR as "this peer's initial
        // update is complete", proceeds with route selection, and sweeps the
        // stale routes it retained from our previous session. For an
        // ORF-gated family that EoR would arrive BEFORE the gated flood
        // (which waits on the peer's first ROUTE-REFRESH, RFC 5291 §6) —
        // sweeping everything we are about to re-announce, a self-inflicted
        // blackhole window. Withhold those families' EoR; it is emitted once
        // the gate lifts and the gated flood is sent
        // (`send_route_refresh_response` / `handle_peer_orf_update`). Non-GR
        // ORF peers keep the immediate EoR — a client that never sends
        // ROUTE-REFRESH must still see EoR. This runs after `handle_peer_up`'s
        // LLGR arm has moved a peer re-establishing during LLGR back into
        // `gr_peers`, so that restarter is covered too.
        if !orf_gated.is_empty() && self.gr_peers.contains_key(&peer) {
            let deferred: HashSet<(rustbgpd_wire::Afi, rustbgpd_wire::Safi)> = eor_families
                .iter()
                .copied()
                .filter(|family| orf_gated.contains(family))
                .collect();
            if !deferred.is_empty() {
                eor_families.retain(|family| !deferred.contains(family));
                self.gr_deferred_eor.insert(peer, deferred);
            }
        }

        let has_outbound_diff = !announce.is_empty()
            || !withdraw.is_empty()
            || !fs_announce.is_empty()
            || !fs_withdraw.is_empty()
            || !evpn_announce.is_empty()
            || !evpn_withdraw.is_empty();
        let sent = !has_outbound_diff
            || self.try_send_and_commit_outbound_update(
                peer,
                nh_override_flags,
                announce,
                withdraw,
                vec![],
                vec![],
                fs_announce,
                fs_withdraw,
                evpn_announce,
                evpn_withdraw,
            );
        if !sent {
            warn!(%peer, "outbound channel full or closed during initial dump — marking dirty");
            self.metrics.record_outbound_route_drop(&peer.to_string());
            for f in &eor_families {
                self.pending_eor.entry(peer).or_default().insert(*f);
            }
            self.dirty_peers.insert(peer);
            return;
        }
        self.update_policy_filtered_routes_for_prefixes(
            peer,
            &all_prefixes,
            &current_policy_filtered_routes,
        );

        // Send End-of-RIB markers for all sendable families
        if !eor_families.is_empty()
            && let Some(tx) = self.outbound_peers.get(&peer)
        {
            let eor = OutboundRouteUpdate {
                next_hop_override: vec![],
                announce: vec![],
                withdraw: vec![],
                end_of_rib: eor_families.clone(),
                refresh_markers: vec![],
                flowspec_announce: vec![],
                flowspec_withdraw: vec![],
                evpn_announce: vec![],
                evpn_withdraw: vec![],
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
