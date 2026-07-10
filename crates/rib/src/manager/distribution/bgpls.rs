use super::{
    AdjRibOut, Afi, BgpMetrics, HashMap, HashSet, IpAddr, Ipv4Addr, LocRib, NeighborPolicyStats,
    PolicyChain, Prefix, RibManager, RouteContext, Safi, bgpls_routes_equal, gauge_val,
    record_export_policy_eval, route_type, should_suppress_ibgp_inner, warn,
};

impl RibManager {
    /// Stage BGP-LS announces and withdrawals for a set of affected opaque keys.
    ///
    /// BGP-LS remains opaque to the RIB: selection and reflection use the
    /// BGP attributes and the route key, not semantic TLV parsing. Policy gets
    /// the same placeholder-prefix treatment as non-Type-5 EVPN; operators can
    /// match communities, large communities, `AS_PATH`, peer, and route type, but
    /// BGP-LS-specific predicates are intentionally deferred.
    #[expect(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "BGP-LS staging mirrors EVPN distribution context for RR/export parity"
    )]
    pub(in crate::manager) fn stage_bgpls_routes(
        loc_rib: &LocRib,
        rib_out: &AdjRibOut,
        peer_is_rr_client: &HashMap<IpAddr, bool>,
        keys: &HashSet<crate::route::BgpLsRouteKey>,
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
        bgpls_announce: &mut Vec<crate::route::BgpLsRibRoute>,
        bgpls_withdraw: &mut Vec<crate::route::BgpLsRouteKey>,
        force: bool,
    ) {
        let needs_as_path_string = export_pol.is_some_and(PolicyChain::requires_as_path_string);
        for key in keys {
            let family = key.family.to_afi_safi();
            if !sendable.is_some_and(|f| f.contains(&family)) {
                if rib_out.get_bgpls(key).is_some() {
                    bgpls_withdraw.push(key.clone());
                }
                continue;
            }

            let Some(best) = loc_rib.get_bgpls(key) else {
                if rib_out.get_bgpls(key).is_some() {
                    bgpls_withdraw.push(key.clone());
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
                if rib_out.get_bgpls(key).is_some() {
                    bgpls_withdraw.push(key.clone());
                }
                continue;
            }

            if best.peer == target_peer {
                if rib_out.get_bgpls(key).is_some() {
                    bgpls_withdraw.push(key.clone());
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
                if rib_out.get_bgpls(key).is_some() {
                    bgpls_withdraw.push(key.clone());
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
                if rib_out.get_bgpls(key).is_some() {
                    bgpls_withdraw.push(key.clone());
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
                    .get_bgpls(key)
                    .is_some_and(|existing| bgpls_routes_equal(existing, &modified))
            {
                continue;
            }
            bgpls_announce.push(modified);
        }
    }

    /// Recompute Loc-RIB best path and distribute changes for BGP-LS routes.
    ///
    /// BGP-LS remains opaque: the selected route is reflected as received with
    /// ordinary BGP attribute handling, and no LSDB/TLV semantics are parsed.
    pub(in crate::manager) fn recompute_and_distribute_bgpls(
        &mut self,
        affected: &HashSet<crate::route::BgpLsRouteKey>,
    ) {
        use crate::route::BgpLsRibRoute;

        let mut changed_keys: HashSet<crate::route::BgpLsRouteKey> = HashSet::new();
        for key in affected {
            let candidates: Vec<BgpLsRibRoute> = self
                .ribs
                .values()
                .filter_map(|rib| rib.get_bgpls(key).cloned())
                .collect();
            if self.loc_rib.recompute_bgpls(key.clone(), candidates.iter()) {
                changed_keys.insert(key.clone());
            }
        }

        if changed_keys.is_empty() {
            return;
        }

        self.metrics
            .set_loc_rib_prefixes("bgpls", gauge_val(self.loc_rib.bgpls_len()));

        let peers: Vec<IpAddr> = self.outbound_peers.keys().copied().collect();
        for peer in peers {
            let sendable = self.peer_sendable_families.get(&peer).cloned();
            let llgr = self.peer_advertised_llgr_families.get(&peer).cloned();
            if !changed_keys.iter().any(|key| {
                sendable
                    .as_ref()
                    .is_some_and(|families| families.contains(&key.family.to_afi_safi()))
            }) {
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

            let mut bgpls_announce = Vec::new();
            let mut bgpls_withdraw = Vec::new();
            Self::stage_bgpls_routes(
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
                &mut bgpls_announce,
                &mut bgpls_withdraw,
                false,
            );

            if (!bgpls_announce.is_empty() || !bgpls_withdraw.is_empty())
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
                    bgpls_announce,
                    bgpls_withdraw,
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                )
            {
                warn!(%peer, "outbound channel full — BGP-LS update deferred");
                self.mark_outbound_dirty(peer);
            }
        }
    }
}
