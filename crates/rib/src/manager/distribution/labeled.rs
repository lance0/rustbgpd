use super::{
    AdjRibIn, AdjRibOut, Afi, BgpMetrics, HashMap, HashSet, IpAddr, Ipv4Addr, LocRib,
    NeighborPolicyStats, PolicyChain, RibManager, RouteContext, Safi, gauge_val,
    labeled_route_family, labeled_routes_equal, record_export_policy_eval, route_type,
    should_suppress_ibgp_inner, warn,
};
use crate::loc_rib::labeled_tiebreak_orr;
use crate::route::{LabeledRibRoute, LabeledRibRouteKey};
use rustbgpd_wire::Prefix;

/// A unicast-shaped probe of a labeled route for the shared RFC 4456
/// suppression helper: `should_suppress_ibgp_inner` only reads
/// peer/origin identity, so the prefix stands in and the attributes
/// stay empty (same shape as the VPN sibling).
fn labeled_suppression_probe(route: &crate::route::LabeledRibRoute) -> crate::route::Route {
    crate::route::Route {
        prefix: route.nlri.prefix,
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

/// The wire AFI/SAFI pair for a labeled prefix identity.
fn labeled_afi_safi(key: &Prefix) -> (Afi, Safi) {
    let afi = match key {
        Prefix::V4(_) => Afi::Ipv4,
        Prefix::V6(_) => Afi::Ipv6,
    };
    (afi, Safi::LabeledUnicast)
}

impl RibManager {
    /// Whether Add-Path send is negotiated with `peer` for any
    /// labeled-unicast family (SAFI 4) with a non-zero configured `send_max`.
    pub(in crate::manager) fn peer_labeled_add_path_send(&self, peer: IpAddr) -> bool {
        self.peer_add_path_send_max.get(&peer).copied().unwrap_or(0) > 0
            && self
                .peer_add_path_send_families
                .get(&peer)
                .is_some_and(|families| {
                    families
                        .iter()
                        .any(|(_, safi)| *safi == Safi::LabeledUnicast)
                })
    }

    /// Stage labeled-unicast announces and withdrawals for a set of
    /// affected prefix identities.
    ///
    /// ADR-0077 §4/§6 guardrail: the next-hop and MPLS label stack pass
    /// through reflection unchanged — the staged route carries the original
    /// `LabeledNlri` verbatim and transport never rewrites the labeled
    /// next-hop. Export policy matches on the IP prefix (honest — a labeled
    /// route IS an IP prefix) plus communities, large communities,
    /// `AS_PATH`, peer, and route type.
    ///
    /// When the target negotiated Add-Path send for the key's family (RFC
    /// 7911), up to `add_path_send_max` candidates per key are ranked — with
    /// the ORR vantage comparator when a vantage is resolved — and staged
    /// with outbound path IDs `1..=N`. Otherwise the single best is staged
    /// with `path_id = 0`.
    #[expect(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "labeled staging mirrors the VPN multipath/single-best distribution context for RR/export parity"
    )]
    pub(in crate::manager) fn stage_labeled_routes(
        loc_rib: &LocRib,
        ribs: &HashMap<IpAddr, AdjRibIn>,
        rib_out: &AdjRibOut,
        peer_is_rr_client: &HashMap<IpAddr, bool>,
        keys: &HashSet<Prefix>,
        target_peer: IpAddr,
        target_peer_asn: Option<u32>,
        target_peer_group: Option<&str>,
        target_is_ebgp: bool,
        target_is_rr_client: bool,
        cluster_id: Option<Ipv4Addr>,
        sendable: Option<&Vec<(Afi, Safi)>>,
        llgr: Option<&Vec<(Afi, Safi)>>,
        orr_ctx: Option<(&crate::orr::OrrTopology, &crate::orr::SpfResult)>,
        add_path_send_max: u32,
        add_path_send_families: &[(Afi, Safi)],
        export_pol: Option<&PolicyChain>,
        metrics: &BgpMetrics,
        policy_stats: &mut NeighborPolicyStats,
        target_peer_label: &str,
        labeled_announce: &mut Vec<LabeledRibRoute>,
        labeled_withdraw: &mut Vec<LabeledRibRouteKey>,
        force: bool,
    ) {
        let needs_as_path_string = export_pol.is_some_and(PolicyChain::requires_as_path_string);
        for key in keys {
            let family = labeled_afi_safi(key);
            // Path IDs currently advertised for this identity — the diff
            // baseline for every withdraw decision below.
            let existing_path_ids = rib_out.labeled_path_ids_for_key(key);
            let withdraw_existing = |labeled_withdraw: &mut Vec<LabeledRibRouteKey>,
                                     existing: &[u32]| {
                for &path_id in existing {
                    labeled_withdraw.push(LabeledRibRouteKey {
                        prefix: *key,
                        path_id,
                    });
                }
            };

            if !sendable.is_some_and(|f| f.contains(&family)) {
                withdraw_existing(labeled_withdraw, existing_path_ids);
                continue;
            }

            let key_send_max = if add_path_send_max > 0 && add_path_send_families.contains(&family)
            {
                add_path_send_max
            } else {
                0
            };

            if key_send_max > 0 {
                // Multi-path: collect the per-target candidate set (every
                // Adj-RIB-In entry for the identity, any received path ID,
                // that survives split horizon and RFC 4456 reflection),
                // rank it, and stage the top N with path IDs 1..=N.
                let mut candidates: Vec<&LabeledRibRoute> = ribs
                    .values()
                    .flat_map(|rib| rib.iter_labeled_for_prefix(key))
                    .filter(|candidate| {
                        candidate.peer != target_peer
                            && !should_suppress_ibgp_inner(
                                &labeled_suppression_probe(candidate),
                                target_is_ebgp,
                                target_is_rr_client,
                                cluster_id,
                                peer_is_rr_client,
                            )
                    })
                    .collect();
                // Rank by the labeled best-path chain; an RFC 9107 ORR peer
                // with a resolved vantage ranks by the vantage's interior
                // cost to each candidate's next-hop (comparator swap only).
                match orr_ctx {
                    Some((orr_topology, orr_spf)) => candidates.sort_by(|a, b| {
                        labeled_tiebreak_orr(
                            a,
                            b,
                            orr_spf.cost_to(orr_topology, a.next_hop),
                            orr_spf.cost_to(orr_topology, b.next_hop),
                        )
                    }),
                    None => candidates.sort_by(|a, b| crate::loc_rib::labeled_tiebreak(a, b)),
                }

                let mut next_rank: u32 = 1;
                let limit = if key_send_max == u32::MAX {
                    usize::MAX
                } else {
                    key_send_max as usize
                };
                for candidate in &candidates {
                    if (next_rank as usize) > limit {
                        break;
                    }

                    // RFC 9494 §4.4, per candidate — an LLGR-stale path
                    // must not occupy an Add-Path rank toward a non-LLGR
                    // eBGP peer. See `llgr_stale_export_suppressed`.
                    if super::llgr_stale_export_suppressed(
                        candidate.is_llgr_stale,
                        candidate.communities(),
                        family,
                        target_is_ebgp,
                        llgr,
                    ) {
                        continue;
                    }

                    let aspath_str = if needs_as_path_string {
                        candidate
                            .as_path()
                            .map_or_else(String::new, rustbgpd_wire::AsPath::to_aspath_string)
                    } else {
                        String::new()
                    };
                    let aspath_len = candidate.as_path().map_or(0, rustbgpd_wire::AsPath::len);
                    let origin_asn = candidate
                        .as_path()
                        .and_then(rustbgpd_wire::AsPath::origin_asn);
                    let ctx = RouteContext {
                        prefix: Some(candidate.nlri.prefix),
                        next_hop: Some(candidate.next_hop),
                        extended_communities: candidate.extended_communities(),
                        communities: candidate.communities(),
                        large_communities: candidate.large_communities(),
                        as_path_str: &aspath_str,
                        as_path_len: aspath_len,
                        origin_asn,
                        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
                        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
                        peer_address: Some(target_peer),
                        peer_asn: target_peer_asn,
                        peer_group: target_peer_group,
                        route_type: Some(route_type(candidate.origin_type)),
                        family: Some(labeled_route_family(&candidate.nlri.prefix)),
                        evpn_route_type: None,
                        local_pref: candidate.local_pref_attr(),
                        med: candidate.med_attr(),
                    };
                    let (result, evaluation) =
                        rustbgpd_policy::evaluate_chain_with_attribution(export_pol, &ctx);
                    record_export_policy_eval(
                        metrics,
                        policy_stats,
                        target_peer_label,
                        &evaluation,
                    );
                    if result.action != rustbgpd_policy::PolicyAction::Permit {
                        continue;
                    }

                    let mut modified = (*candidate).clone();
                    if !result.modifications.is_empty() {
                        let nh = rustbgpd_policy::apply_modifications(
                            std::sync::Arc::make_mut(&mut modified.attributes),
                            &result.modifications,
                        );
                        if let Some(rustbgpd_policy::NextHopAction::Specific(addr)) = nh {
                            modified.next_hop = addr;
                        }
                    }
                    modified.path_id = next_rank;

                    let out_key = LabeledRibRouteKey {
                        prefix: *key,
                        path_id: next_rank,
                    };
                    if force
                        || rib_out
                            .get_labeled(&out_key)
                            .is_none_or(|existing| !labeled_routes_equal(existing, &modified))
                    {
                        labeled_announce.push(modified);
                    }
                    next_rank += 1;
                }

                // Withdraw previously advertised path IDs outside the new
                // 1..next_rank set (including a stale single-best 0 entry).
                for &path_id in existing_path_ids {
                    if path_id == 0 || path_id >= next_rank {
                        labeled_withdraw.push(LabeledRibRouteKey {
                            prefix: *key,
                            path_id,
                        });
                    }
                }
                continue;
            }

            // Single-best. An RFC 9107 ORR peer with a resolved vantage
            // does NOT take the Loc-RIB best: the per-target candidate
            // set (every Adj-RIB-In entry for the key that survives split
            // horizon and RFC 4456 reflection) is ranked with the
            // vantage's interior cost to each candidate's next-hop. A
            // plain peer keeps the Loc-RIB best, unchanged.
            let best = if let Some((orr_topology, orr_spf)) = orr_ctx {
                let winner = ribs
                    .values()
                    .flat_map(|rib| rib.iter_labeled_for_prefix(key))
                    .filter(|candidate| {
                        candidate.peer != target_peer
                            && !should_suppress_ibgp_inner(
                                &labeled_suppression_probe(candidate),
                                target_is_ebgp,
                                target_is_rr_client,
                                cluster_id,
                                peer_is_rr_client,
                            )
                    })
                    .min_by(|a, b| {
                        labeled_tiebreak_orr(
                            a,
                            b,
                            orr_spf.cost_to(orr_topology, a.next_hop),
                            orr_spf.cost_to(orr_topology, b.next_hop),
                        )
                    });
                let Some(winner) = winner else {
                    withdraw_existing(labeled_withdraw, existing_path_ids);
                    continue;
                };
                winner
            } else {
                let Some(best) = loc_rib.get_labeled(key) else {
                    withdraw_existing(labeled_withdraw, existing_path_ids);
                    continue;
                };
                best
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
                withdraw_existing(labeled_withdraw, existing_path_ids);
                continue;
            }

            // The two suppression checks below are no-ops for an ORR
            // winner (its candidate set is pre-filtered above); they
            // decide only for the Loc-RIB best of a plain peer.
            if best.peer == target_peer {
                withdraw_existing(labeled_withdraw, existing_path_ids);
                continue;
            }

            if should_suppress_ibgp_inner(
                &labeled_suppression_probe(best),
                target_is_ebgp,
                target_is_rr_client,
                cluster_id,
                peer_is_rr_client,
            ) {
                withdraw_existing(labeled_withdraw, existing_path_ids);
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
                prefix: Some(best.nlri.prefix),
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
                family: Some(labeled_route_family(&best.nlri.prefix)),
                evpn_route_type: None,
                local_pref: best.local_pref_attr(),
                med: best.med_attr(),
            };
            let (result, evaluation) =
                rustbgpd_policy::evaluate_chain_with_attribution(export_pol, &ctx);
            record_export_policy_eval(metrics, policy_stats, target_peer_label, &evaluation);
            if result.action != rustbgpd_policy::PolicyAction::Permit {
                withdraw_existing(labeled_withdraw, existing_path_ids);
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

            let out_key = LabeledRibRouteKey {
                prefix: *key,
                path_id: 0,
            };
            if force
                || rib_out
                    .get_labeled(&out_key)
                    .is_none_or(|existing| !labeled_routes_equal(existing, &modified))
            {
                labeled_announce.push(modified);
            }

            // Clean up stale multi-path entries if this identity was
            // previously advertised via Add-Path and is now single-best.
            for &path_id in existing_path_ids {
                if path_id != 0 {
                    labeled_withdraw.push(LabeledRibRouteKey {
                        prefix: *key,
                        path_id,
                    });
                }
            }
        }
    }

    /// Recompute Loc-RIB best path and distribute changes for
    /// labeled-unicast routes.
    ///
    /// The selected route is reflected as received: MPLS label stack and
    /// next-hop pass through unchanged (ADR-0077 §4/§6), with ordinary BGP
    /// attribute handling applied by transport. Selection and staging
    /// operate per prefix identity — received Add-Path path IDs are
    /// distinct Adj-RIB-In entries but collapse into one candidate set per
    /// identity.
    #[expect(
        clippy::too_many_lines,
        reason = "labeled recompute keeps loc-rib selection and per-peer ORR/Add-Path staging together"
    )]
    pub(in crate::manager) fn recompute_and_distribute_labeled(
        &mut self,
        affected: &HashSet<LabeledRibRouteKey>,
    ) {
        let affected_nlri: HashSet<Prefix> = affected.iter().map(|key| key.prefix).collect();

        let mut changed_keys: HashSet<Prefix> = HashSet::new();
        for key in &affected_nlri {
            let candidates: Vec<LabeledRibRoute> = self
                .ribs
                .values()
                .flat_map(|rib| rib.iter_labeled_for_prefix(key).cloned())
                .collect();
            if self.loc_rib.recompute_labeled(*key, candidates.iter()) {
                changed_keys.insert(*key);
            }
        }

        // An RFC 9107 ORR peer selects from the per-target candidate set,
        // not the Loc-RIB best — a candidate change that leaves the
        // Loc-RIB best untouched can still flip a vantage best, so
        // ORR-bound peers stage every affected key (the labeled parallel
        // of the unicast `all_affected` inclusion in `distribute_changes`).
        // Add-Path-send peers need the same widening: a non-best candidate
        // change can alter the staged top-N set.
        let any_widened_peer = self.outbound_peers.keys().any(|peer| {
            self.peer_orr_vantage
                .get(peer)
                .is_some_and(|vantage| self.orr.spf.contains_key(vantage))
                || self.peer_labeled_add_path_send(*peer)
        });
        if changed_keys.is_empty() && !any_widened_peer {
            return;
        }

        if !changed_keys.is_empty() {
            self.metrics
                .set_loc_rib_prefixes("labeled", gauge_val(self.loc_rib.labeled_len()));
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
            let peer_add_path = self.peer_labeled_add_path_send(peer);
            let staged_keys = if orr_ctx.is_some() || peer_add_path {
                &affected_nlri
            } else {
                &changed_keys
            };
            let sendable = self.peer_sendable_families.get(&peer).cloned();
            let llgr = self.peer_advertised_llgr_families.get(&peer).cloned();
            if !staged_keys.iter().any(|key| {
                sendable
                    .as_ref()
                    .is_some_and(|families| families.contains(&labeled_afi_safi(key)))
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
            let add_path_send_max = if peer_add_path {
                self.peer_add_path_send_max.get(&peer).copied().unwrap_or(0)
            } else {
                0
            };
            let add_path_send_families = self
                .peer_add_path_send_families
                .get(&peer)
                .cloned()
                .unwrap_or_default();
            let target_peer_label = peer.to_string();
            let metrics = self.metrics.clone();

            let loc_rib_len = self.loc_rib.len();
            let rib_out = self
                .adj_ribs_out
                .entry(peer)
                .or_insert_with(|| crate::adj_rib_out::AdjRibOut::with_capacity(peer, loc_rib_len));
            let policy_stats = self.export_policy_stats.entry(peer).or_default();

            let mut labeled_announce = Vec::new();
            let mut labeled_withdraw = Vec::new();
            Self::stage_labeled_routes(
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
                llgr.as_ref(),
                orr_ctx,
                add_path_send_max,
                &add_path_send_families,
                export_pol.as_ref(),
                &metrics,
                policy_stats,
                &target_peer_label,
                &mut labeled_announce,
                &mut labeled_withdraw,
                false,
            );

            if (!labeled_announce.is_empty() || !labeled_withdraw.is_empty())
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
                    labeled_announce,
                    labeled_withdraw,
                    vec![],
                    vec![],
                )
            {
                warn!(%peer, "outbound channel full — labeled update deferred");
                self.mark_outbound_dirty(peer);
            }
        }
    }
}
