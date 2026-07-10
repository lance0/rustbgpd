use super::{
    AdjRibOut, Afi, BgpMetrics, HashMap, HashSet, IpAddr, Ipv4Addr, LocRib, NeighborPolicyStats,
    PolicyChain, Prefix, RibManager, RouteContext, Safi, gauge_val, record_export_policy_eval,
    route_type, rtc_routes_equal, should_suppress_ibgp_inner, warn,
};

impl RibManager {
    /// Resolve the RFC 4684 VPN outbound filter for `peer`: `Some` iff the
    /// peer negotiated `(IPv4, RtConstrain)`; a somehow-absent membership
    /// entry resolves to the strict empty filter (advertise nothing) rather
    /// than fail-open. Returns an owned clone because every caller holds a
    /// `&mut` Adj-RIB-Out borrow through `self` while staging (the ORF
    /// precedent) — memberships are small, present only for RTC peers.
    pub(in crate::manager) fn rtc_vpn_filter(
        &self,
        peer: IpAddr,
        sendable: Option<&Vec<(Afi, Safi)>>,
    ) -> Option<crate::manager::RtcMembership> {
        if sendable.is_some_and(|f| f.contains(&crate::route::RtcRibRouteKey::afi_safi())) {
            Some(
                self.peer_rt_membership
                    .get(&peer)
                    .cloned()
                    .unwrap_or_default(),
            )
        } else {
            None
        }
    }

    /// Stage RT-Constrain announces and withdrawals for a set of affected
    /// keys. Mirrors [`Self::stage_vpn_routes`] minus labels; like BGP-LS,
    /// the export-policy context carries no prefix (`prefix: None`) — an RT
    /// membership NLRI has no IP prefix to match on.
    #[expect(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "RTC staging mirrors VPN/BGP-LS distribution context for RR/export parity"
    )]
    pub(in crate::manager) fn stage_rtc_routes(
        loc_rib: &LocRib,
        rib_out: &AdjRibOut,
        peer_is_rr_client: &HashMap<IpAddr, bool>,
        keys: &HashSet<crate::route::RtcRibRouteKey>,
        target_peer: IpAddr,
        target_peer_asn: Option<u32>,
        target_peer_group: Option<&str>,
        target_is_ebgp: bool,
        target_is_rr_client: bool,
        cluster_id: Option<Ipv4Addr>,
        sendable: Option<&Vec<(Afi, Safi)>>,
        llgr: Option<&Vec<(Afi, Safi)>>,
        export_pol: Option<&PolicyChain>,
        metrics: &BgpMetrics,
        policy_stats: &mut NeighborPolicyStats,
        target_peer_label: &str,
        rtc_announce: &mut Vec<crate::route::RtcRibRoute>,
        rtc_withdraw: &mut Vec<crate::route::RtcRibRouteKey>,
        force: bool,
    ) {
        let needs_as_path_string = export_pol.is_some_and(PolicyChain::requires_as_path_string);
        let family = crate::route::RtcRibRouteKey::afi_safi();
        let family_sendable = sendable.is_some_and(|f| f.contains(&family));
        for key in keys {
            if !family_sendable {
                if rib_out.get_rtc(key).is_some() {
                    rtc_withdraw.push(key.clone());
                }
                continue;
            }

            let Some(best) = loc_rib.get_rtc(key) else {
                if rib_out.get_rtc(key).is_some() {
                    rtc_withdraw.push(key.clone());
                }
                continue;
            };

            // RFC 9494 §4.4: LLGR-stale toward a non-LLGR eBGP peer is
            // suppressed. See `llgr_stale_export_suppressed`.
            if super::llgr_stale_export_suppressed(
                best.is_llgr_stale,
                best.communities(),
                family,
                target_is_ebgp,
                llgr,
            ) {
                if rib_out.get_rtc(key).is_some() {
                    rtc_withdraw.push(key.clone());
                }
                continue;
            }

            if best.peer == target_peer {
                if rib_out.get_rtc(key).is_some() {
                    rtc_withdraw.push(key.clone());
                }
                continue;
            }

            let probe = crate::route::Route {
                prefix: Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0)),
                next_hop: best.next_hop,
                link_local_next_hop: None,
                next_hop_scope: None,
                peer: best.peer,
                attributes: std::sync::Arc::new(vec![]),
                received_at: best.received_at,
                origin_type: best.origin_type,
                peer_router_id: best.peer_router_id,
                is_stale: false,
                is_llgr_stale: false,
                path_id: 0,
                validation_state: rustbgpd_wire::RpkiValidation::NotFound,
                aspa_state: rustbgpd_wire::AspaValidation::Unknown,
                aspa_context: rustbgpd_wire::AspaValidationContext::default(),
            };
            if should_suppress_ibgp_inner(
                &probe,
                target_is_ebgp,
                target_is_rr_client,
                cluster_id,
                peer_is_rr_client,
            ) {
                if rib_out.get_rtc(key).is_some() {
                    rtc_withdraw.push(key.clone());
                }
                continue;
            }

            let aspath_str = if needs_as_path_string {
                best.as_path()
                    .map_or_else(String::new, rustbgpd_wire::AsPath::to_aspath_string)
            } else {
                String::new()
            };
            let aspath_len = best.as_path().map_or(0, rustbgpd_wire::AsPath::len);
            let origin_asn = best.as_path().and_then(rustbgpd_wire::AsPath::origin_asn);
            let ctx = RouteContext {
                prefix: None,
                next_hop: Some(best.next_hop),
                extended_communities: best.extended_communities(),
                communities: best.communities(),
                large_communities: best.large_communities(),
                as_path_str: &aspath_str,
                as_path_len: aspath_len,
                origin_asn,
                validation_state: rustbgpd_wire::RpkiValidation::NotFound,
                aspa_state: rustbgpd_wire::AspaValidation::Unknown,
                peer_address: Some(target_peer),
                peer_asn: target_peer_asn,
                peer_group: target_peer_group,
                route_type: Some(route_type(best.origin_type)),
                evpn_route_type: None,
                local_pref: best.local_pref_attr(),
                med: best.med_attr(),
            };
            let (result, evaluation) =
                rustbgpd_policy::evaluate_chain_with_attribution(export_pol, &ctx);
            record_export_policy_eval(metrics, policy_stats, target_peer_label, &evaluation);
            if result.action != rustbgpd_policy::PolicyAction::Permit {
                if rib_out.get_rtc(key).is_some() {
                    rtc_withdraw.push(key.clone());
                }
                continue;
            }

            let mut modified = best.clone();
            if !result.modifications.is_empty() {
                let nh = rustbgpd_policy::apply_modifications(
                    std::sync::Arc::make_mut(&mut modified.attributes),
                    &result.modifications,
                );
                if let Some(rustbgpd_policy::NextHopAction::Specific(addr)) = nh {
                    modified.next_hop = addr;
                }
            }
            modified.path_id = 0;

            if !force
                && rib_out
                    .get_rtc(key)
                    .is_some_and(|existing| rtc_routes_equal(existing, &modified))
            {
                continue;
            }
            rtc_announce.push(modified);
        }
    }

    /// Recompute Loc-RIB best path and distribute changes for RT-Constrain
    /// routes (RFC 4684 §3.2). Reflection semantics mirror VPN: the NLRI and
    /// stored next-hop pass through unchanged.
    pub(in crate::manager) fn recompute_and_distribute_rtc(
        &mut self,
        affected: &HashSet<crate::route::RtcRibRouteKey>,
    ) {
        use crate::route::RtcRibRoute;

        let mut changed_keys: HashSet<crate::route::RtcRibRouteKey> = HashSet::new();
        for key in affected {
            let candidates: Vec<RtcRibRoute> = self
                .ribs
                .values()
                .filter_map(|rib| rib.get_rtc(key).cloned())
                .collect();
            if self.loc_rib.recompute_rtc(key.clone(), candidates.iter()) {
                changed_keys.insert(key.clone());
            }
        }

        if changed_keys.is_empty() {
            return;
        }

        self.metrics
            .set_loc_rib_prefixes("rtc", gauge_val(self.loc_rib.rtc_len()));

        let rtc_family = crate::route::RtcRibRouteKey::afi_safi();
        let peers: Vec<IpAddr> = self.outbound_peers.keys().copied().collect();
        for peer in peers {
            let sendable = self.peer_sendable_families.get(&peer).cloned();
            let llgr = self.peer_advertised_llgr_families.get(&peer).cloned();
            if !sendable
                .as_ref()
                .is_some_and(|families| families.contains(&rtc_family))
            {
                continue;
            }

            let target_is_ebgp = self.peer_is_ebgp.get(&peer).copied().unwrap_or(true);
            let target_is_rr_client = self.peer_is_rr_client.get(&peer).copied().unwrap_or(false);
            let target_peer_asn = self.peer_asn.get(&peer).copied();
            let target_peer_group = self.peer_group.get(&peer).map(String::as_str);
            let export_pol = self
                .export_policy_for(peer)
                .map(rustbgpd_policy::PolicyChain::share);
            let target_peer_label = peer.to_string();
            let metrics = self.metrics.clone();

            let loc_rib_len = self.loc_rib.len();
            let rib_out = self
                .adj_ribs_out
                .entry(peer)
                .or_insert_with(|| crate::adj_rib_out::AdjRibOut::with_capacity(peer, loc_rib_len));
            let policy_stats = self.export_policy_stats.entry(peer).or_default();

            let mut rtc_announce = Vec::new();
            let mut rtc_withdraw = Vec::new();
            Self::stage_rtc_routes(
                &self.loc_rib,
                rib_out,
                &self.peer_is_rr_client,
                &changed_keys,
                peer,
                target_peer_asn,
                target_peer_group,
                target_is_ebgp,
                target_is_rr_client,
                self.cluster_id,
                sendable.as_ref(),
                llgr.as_ref(),
                export_pol.as_ref(),
                &metrics,
                policy_stats,
                &target_peer_label,
                &mut rtc_announce,
                &mut rtc_withdraw,
                false,
            );

            if (!rtc_announce.is_empty() || !rtc_withdraw.is_empty())
                && !self.try_send_and_commit_outbound_update(
                    peer,
                    vec![].into(),
                    vec![].into(),
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                    rtc_announce,
                    rtc_withdraw,
                )
            {
                warn!(%peer, "outbound channel full — RTC update deferred");
                self.mark_outbound_dirty(peer);
            }
        }
    }
}
