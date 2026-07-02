use super::{
    AdjRibIn, AdjRibOut, Afi, BgpMetrics, HashMap, HashSet, IpAddr, Ipv4Addr, LocRib,
    NeighborPolicyStats, PolicyChain, RibManager, RouteContext, Safi, gauge_val,
    record_export_policy_eval, route_type, should_suppress_ibgp_inner, vpn_routes_equal, warn,
};
use crate::loc_rib::vpn_tiebreak_orr;

/// A unicast-shaped probe of a VPN route for the shared RFC 4456
/// suppression helper: `should_suppress_ibgp_inner` only reads
/// peer/origin identity, so the inner prefix stands in and the
/// attributes stay empty (same shape the pre-ORR staging used).
fn vpn_suppression_probe(route: &crate::route::VpnRibRoute) -> crate::route::Route {
    crate::route::Route {
        prefix: route.inner_prefix(),
        next_hop: route.next_hop,
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: route.peer,
        attributes: std::sync::Arc::new(vec![]),
        received_at: route.received_at,
        origin_type: route.origin_type,
        peer_router_id: route.peer_router_id,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    }
}

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
        ribs: &HashMap<IpAddr, AdjRibIn>,
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
        orr_ctx: Option<(&crate::orr::OrrTopology, &crate::orr::SpfResult)>,
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

            // Per-key best. An RFC 9107 ORR peer with a resolved vantage
            // does NOT take the Loc-RIB best: the per-target candidate
            // set (every Adj-RIB-In entry for the key that survives split
            // horizon and RFC 4456 reflection — the unicast
            // `orr_candidates` filter adapted to `VpnRibRoute`) is ranked
            // with the vantage's interior cost to each candidate's
            // next-hop. A plain peer keeps the Loc-RIB best, unchanged.
            let best = if let Some((orr_topology, orr_spf)) = orr_ctx {
                let winner = ribs
                    .values()
                    .filter_map(|rib| rib.get_vpn(key))
                    .filter(|candidate| {
                        candidate.peer != target_peer
                            && !should_suppress_ibgp_inner(
                                &vpn_suppression_probe(candidate),
                                target_is_ebgp,
                                target_is_rr_client,
                                cluster_id,
                                peer_is_rr_client,
                            )
                    })
                    .min_by(|a, b| {
                        vpn_tiebreak_orr(
                            a,
                            b,
                            orr_spf.cost_to(orr_topology, a.next_hop),
                            orr_spf.cost_to(orr_topology, b.next_hop),
                        )
                    });
                let Some(winner) = winner else {
                    if rib_out.get_vpn(key).is_some() {
                        vpn_withdraw.push(key.clone());
                    }
                    continue;
                };
                winner
            } else {
                let Some(best) = loc_rib.get_vpn(key) else {
                    if rib_out.get_vpn(key).is_some() {
                        vpn_withdraw.push(key.clone());
                    }
                    continue;
                };
                best
            };

            // RFC 4684 outbound gate: a peer that negotiated RT-Constrain
            // only receives VPN routes whose Route Targets fall inside its
            // advertised membership (`None` = SAFI 132 not negotiated ⇒
            // unfiltered). Membership is per-peer, so the one gate covers
            // both VPNv4 and VPNv6 keys. Miss ⇒ withdraw-if-present,
            // exactly the sendable-family gate shape above. For an ORR
            // peer the gate applies to the vantage WINNER's extended
            // communities — the route actually being advertised — not the
            // Loc-RIB best's.
            if let Some(membership) = rtc_filter
                && !membership.matches_any(best.extended_communities())
            {
                if rib_out.get_vpn(key).is_some() {
                    vpn_withdraw.push(key.clone());
                }
                continue;
            }

            // The two suppression checks below are no-ops for an ORR
            // winner (its candidate set is pre-filtered above); they
            // decide only for the Loc-RIB best of a plain peer.
            if best.peer == target_peer {
                if rib_out.get_vpn(key).is_some() {
                    vpn_withdraw.push(key.clone());
                }
                continue;
            }

            if should_suppress_ibgp_inner(
                &vpn_suppression_probe(best),
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
    #[expect(
        clippy::too_many_lines,
        reason = "VPN recompute keeps loc-rib selection and per-peer ORR staging together"
    )]
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

        // An RFC 9107 ORR peer selects from the per-target candidate set,
        // not the Loc-RIB best — a candidate change that leaves the
        // Loc-RIB best untouched can still flip a vantage best, so
        // ORR-bound peers stage every affected key (the VPN parallel of
        // the unicast `all_affected` inclusion in `distribute_changes`).
        let any_resolved_orr_peer = self.outbound_peers.keys().any(|peer| {
            self.peer_orr_vantage
                .get(peer)
                .is_some_and(|vantage| self.orr.spf.contains_key(vantage))
        });
        if changed_keys.is_empty() && !any_resolved_orr_peer {
            return;
        }

        if !changed_keys.is_empty() {
            self.metrics
                .set_loc_rib_prefixes("vpn", gauge_val(self.loc_rib.vpn_len()));
        }

        let peers: Vec<IpAddr> = self.outbound_peers.keys().copied().collect();
        for peer in peers {
            // A peer bound to a vantage that resolved this pass takes the
            // per-vantage best; an unresolved vantage silently falls back
            // to the standard Loc-RIB best (same shape as unicast).
            let orr_ctx = self
                .peer_orr_vantage
                .get(&peer)
                .and_then(|vantage| self.orr.spf.get(vantage))
                .map(|spf| (&self.orr.topology, spf));
            let staged_keys = if orr_ctx.is_some() {
                affected
            } else {
                &changed_keys
            };
            let sendable = self.peer_sendable_families.get(&peer).cloned();
            if !staged_keys.iter().any(|key| {
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
                &self.ribs,
                rib_out,
                &self.peer_is_rr_client,
                staged_keys,
                peer,
                target_peer_asn,
                target_peer_group,
                target_is_ebgp,
                target_is_rr_client,
                self.cluster_id,
                sendable.as_ref(),
                rtc_filter.as_ref(),
                orr_ctx,
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
