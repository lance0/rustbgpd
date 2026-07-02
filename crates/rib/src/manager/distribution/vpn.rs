use super::{
    AdjRibOut, Afi, BgpMetrics, HashMap, HashSet, IpAddr, Ipv4Addr, LocRib, NeighborPolicyStats,
    PolicyChain, RibManager, RouteContext, Safi, gauge_val, record_export_policy_eval, route_type,
    should_suppress_ibgp_inner, vpn_routes_equal, warn,
};

impl RibManager {
    /// Stage VPNv4/VPNv6 announces and withdrawals for a set of affected keys.
    ///
    /// ADR-0077 §6 guardrail: the next-hop, MPLS label stack, and Route
    /// Distinguisher pass through reflection unchanged — the staged route
    /// carries the original `VpnNlri` verbatim and transport never rewrites
    /// the VPN next-hop. Export policy matches on the RD-scoped inner prefix
    /// (honest, unlike the prefixless BGP-LS placeholder) plus communities,
    /// large communities, `AS_PATH`, peer, and route type.
    #[expect(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "VPN staging mirrors EVPN/BGP-LS distribution context for RR/export parity"
    )]
    pub(in crate::manager) fn stage_vpn_routes(
        loc_rib: &LocRib,
        rib_out: &AdjRibOut,
        peer_is_rr_client: &HashMap<IpAddr, bool>,
        keys: &HashSet<crate::route::VpnRibRouteKey>,
        target_peer: IpAddr,
        target_peer_asn: Option<u32>,
        target_peer_group: Option<&str>,
        target_is_ebgp: bool,
        target_is_rr_client: bool,
        cluster_id: Option<Ipv4Addr>,
        sendable: Option<&Vec<(Afi, Safi)>>,
        rtc_filter: Option<&crate::manager::RtcMembership>,
        export_pol: Option<&PolicyChain>,
        metrics: &BgpMetrics,
        policy_stats: &mut NeighborPolicyStats,
        target_peer_label: &str,
        vpn_announce: &mut Vec<crate::route::VpnRibRoute>,
        vpn_withdraw: &mut Vec<crate::route::VpnRibRouteKey>,
        force: bool,
    ) {
        let needs_as_path_string = export_pol.is_some_and(PolicyChain::requires_as_path_string);
        for key in keys {
            let family = key.afi_safi();
            if !sendable.is_some_and(|f| f.contains(&family)) {
                if rib_out.get_vpn(key).is_some() {
                    vpn_withdraw.push(key.clone());
                }
                continue;
            }

            let Some(best) = loc_rib.get_vpn(key) else {
                if rib_out.get_vpn(key).is_some() {
                    vpn_withdraw.push(key.clone());
                }
                continue;
            };

            // RFC 4684 outbound gate: a peer that negotiated RT-Constrain
            // only receives VPN routes whose Route Targets fall inside its
            // advertised membership (`None` = SAFI 132 not negotiated ⇒
            // unfiltered). Membership is per-peer, so the one gate covers
            // both VPNv4 and VPNv6 keys. Miss ⇒ withdraw-if-present,
            // exactly the sendable-family gate shape above.
            if let Some(membership) = rtc_filter
                && !membership.matches_any(best.extended_communities())
            {
                if rib_out.get_vpn(key).is_some() {
                    vpn_withdraw.push(key.clone());
                }
                continue;
            }

            if best.peer == target_peer {
                if rib_out.get_vpn(key).is_some() {
                    vpn_withdraw.push(key.clone());
                }
                continue;
            }

            let probe = crate::route::Route {
                prefix: best.inner_prefix(),
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
                if rib_out.get_vpn(key).is_some() {
                    vpn_withdraw.push(key.clone());
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
            let ctx = RouteContext {
                prefix: Some(best.inner_prefix()),
                next_hop: Some(best.next_hop),
                extended_communities: best.extended_communities(),
                communities: best.communities(),
                large_communities: best.large_communities(),
                as_path_str: &aspath_str,
                as_path_len: aspath_len,
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
                if rib_out.get_vpn(key).is_some() {
                    vpn_withdraw.push(key.clone());
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
                    .get_vpn(key)
                    .is_some_and(|existing| vpn_routes_equal(existing, &modified))
            {
                continue;
            }
            vpn_announce.push(modified);
        }
    }

    /// Recompute Loc-RIB best path and distribute changes for VPNv4/VPNv6
    /// routes.
    ///
    /// The selected route is reflected as received: Route Distinguisher,
    /// MPLS label stack, and next-hop pass through unchanged (ADR-0077 §6),
    /// with ordinary BGP attribute handling applied by transport.
    pub(in crate::manager) fn recompute_and_distribute_vpn(
        &mut self,
        affected: &HashSet<crate::route::VpnRibRouteKey>,
    ) {
        use crate::route::VpnRibRoute;

        let mut changed_keys: HashSet<crate::route::VpnRibRouteKey> = HashSet::new();
        for key in affected {
            let candidates: Vec<VpnRibRoute> = self
                .ribs
                .values()
                .filter_map(|rib| rib.get_vpn(key).cloned())
                .collect();
            if self.loc_rib.recompute_vpn(key.clone(), candidates.iter()) {
                changed_keys.insert(key.clone());
            }
        }

        if changed_keys.is_empty() {
            return;
        }

        self.metrics
            .set_loc_rib_prefixes("vpn", gauge_val(self.loc_rib.vpn_len()));

        let peers: Vec<IpAddr> = self.outbound_peers.keys().copied().collect();
        for peer in peers {
            let sendable = self.peer_sendable_families.get(&peer).cloned();
            if !changed_keys.iter().any(|key| {
                sendable
                    .as_ref()
                    .is_some_and(|families| families.contains(&key.afi_safi()))
            }) {
                continue;
            }

            let target_is_ebgp = self.peer_is_ebgp.get(&peer).copied().unwrap_or(true);
            let target_is_rr_client = self.peer_is_rr_client.get(&peer).copied().unwrap_or(false);
            let target_peer_asn = self.peer_asn.get(&peer).copied();
            let target_peer_group = self.peer_group.get(&peer).map(String::as_str);
            let export_pol = self.export_policy_for(peer).cloned();
            let rtc_filter = self.rtc_vpn_filter(peer, sendable.as_ref());
            let target_peer_label = peer.to_string();
            let metrics = self.metrics.clone();

            let loc_rib_len = self.loc_rib.len();
            let rib_out = self
                .adj_ribs_out
                .entry(peer)
                .or_insert_with(|| crate::adj_rib_out::AdjRibOut::with_capacity(peer, loc_rib_len));
            let policy_stats = self.export_policy_stats.entry(peer).or_default();

            let mut vpn_announce = Vec::new();
            let mut vpn_withdraw = Vec::new();
            Self::stage_vpn_routes(
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
                rtc_filter.as_ref(),
                export_pol.as_ref(),
                &metrics,
                policy_stats,
                &target_peer_label,
                &mut vpn_announce,
                &mut vpn_withdraw,
                false,
            );

            if (!vpn_announce.is_empty() || !vpn_withdraw.is_empty())
                && !self.try_send_and_commit_outbound_update(
                    peer,
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
                    vpn_announce,
                    vpn_withdraw,
                    vec![],
                    vec![],
                )
            {
                warn!(%peer, "outbound channel full — VPN update deferred");
                self.dirty_peers.insert(peer);
            }
        }
    }
}
