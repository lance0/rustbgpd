use super::{
    AdjRibIn, AdjRibOut, Afi, Arc, BgpMetrics, ExplainAdvertisedRoute, ExplainDecision,
    ExplainReason, HashMap, HashSet, IpAddr, Ipv4Addr, LOCAL_PEER, LocRib, NeighborPolicyStats,
    PolicyAction, PolicyChain, PolicyFilteredRouteKey, Prefix, RibCommandError, RibManager,
    RouteContext, Safi, VrpTable, debug, evaluate_chain_with_attribution, gauge_val, prefix_family,
    record_export_policy_eval, route_type, route_type_label, route_type_message, routes_equal,
    should_suppress_ibgp_inner, validate_route_aspa, validate_route_rpki,
};

/// Candidate paths for `prefix` visible to `target_peer` under RFC 9107
/// ORR: every Adj-RIB-In entry that survives split horizon and the
/// iBGP / RFC 4456 reflection rules. Shared by the ORR distribution and
/// explain paths so both rank the exact same set.
fn orr_candidates<'a>(
    ribs: &'a HashMap<IpAddr, AdjRibIn>,
    peer_is_rr_client: &'a HashMap<IpAddr, bool>,
    prefix: &'a Prefix,
    target_peer: IpAddr,
    target_is_ebgp: bool,
    target_is_rr_client: bool,
    cluster_id: Option<Ipv4Addr>,
) -> impl Iterator<Item = &'a crate::route::Route> {
    ribs.values()
        .flat_map(move |rib| rib.iter_prefix(prefix))
        .filter(move |route| {
            // Split horizon: exclude routes from the target peer
            if route.peer == target_peer {
                return false;
            }
            // iBGP split-horizon / RFC 4456 reflection
            !should_suppress_ibgp_inner(
                route,
                target_is_ebgp,
                target_is_rr_client,
                cluster_id,
                peer_is_rr_client,
            )
        })
}

impl RibManager {
    #[expect(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "explain mirrors live single-best export inputs for policy parity"
    )]
    pub(in crate::manager) fn explain_single_best_prefix(
        loc_rib: &LocRib,
        ribs: &HashMap<IpAddr, AdjRibIn>,
        peer_is_rr_client: &HashMap<IpAddr, bool>,
        prefix: Prefix,
        target_peer: IpAddr,
        target_peer_asn: Option<u32>,
        target_peer_group: Option<&str>,
        target_is_ebgp: bool,
        target_is_rr_client: bool,
        cluster_id: Option<Ipv4Addr>,
        sendable: Option<&Vec<(Afi, Safi)>>,
        export_pol: Option<&PolicyChain>,
        orr: Option<(&crate::orr::OrrTopology, &crate::orr::SpfResult, IpAddr)>,
    ) -> ExplainAdvertisedRoute {
        use crate::best_path::{
            BestPathReason, best_path_cmp_orr, best_path_cmp_orr_with_reason,
            best_path_reason_detail, orr_interior_cost_detail,
        };

        let mut explain = ExplainAdvertisedRoute {
            decision: ExplainDecision::NoBestRoute,
            peer: target_peer,
            prefix,
            next_hop: None,
            path_id: 0,
            route_peer: None,
            route_type: None,
            reasons: Vec::new(),
            modifications: rustbgpd_policy::RouteModifications::default(),
            orr_vantage: None,
            orr_candidates: Vec::new(),
        };

        // Select the route to explain. An ORR-bound peer's best is NOT
        // the Loc-RIB best: rank the per-target candidate set with the
        // vantage's interior costs, exactly like
        // `distribute_orr_best_prefix` (same collection via
        // `orr_candidates`, same comparator). A plain peer explains the
        // Loc-RIB best, unchanged.
        let best = if let Some((topology, spf, vantage)) = orr {
            explain.orr_vantage = Some(vantage);
            let mut ranked: Vec<&crate::route::Route> = orr_candidates(
                ribs,
                peer_is_rr_client,
                &prefix,
                target_peer,
                target_is_ebgp,
                target_is_rr_client,
                cluster_id,
            )
            .collect();
            ranked.sort_by(|a, b| {
                best_path_cmp_orr(
                    a,
                    b,
                    spf.cost_to(topology, a.next_hop),
                    spf.cost_to(topology, b.next_hop),
                )
            });
            explain.orr_candidates = ranked
                .iter()
                .enumerate()
                .map(|(i, route)| crate::update::OrrExplainCandidate {
                    peer: route.peer,
                    path_id: route.path_id,
                    next_hop: route.next_hop,
                    cost: spf.cost_to(topology, route.next_hop),
                    selected: i == 0,
                })
                .collect();
            let Some(&winner) = ranked.first() else {
                explain.reasons.push(ExplainReason {
                    code: "no_orr_candidate",
                    message: "no candidate for this prefix survives split-horizon / \
                              reflection filtering for this ORR peer"
                        .to_string(),
                });
                return explain;
            };
            // The decision the winner had to survive vs the runner-up —
            // the per-vantage counterpart of ExplainBestPath's
            // best_reason. Rendered with the compared vantage costs when
            // the interior-cost step decided.
            if let Some(&runner_up) = ranked.get(1) {
                let (cost_w, cost_r) = (
                    spf.cost_to(topology, winner.next_hop),
                    spf.cost_to(topology, runner_up.next_hop),
                );
                let (_, reason) = best_path_cmp_orr_with_reason(winner, runner_up, cost_w, cost_r);
                let detail = if reason == BestPathReason::OrrInteriorCost {
                    orr_interior_cost_detail(cost_w, cost_r)
                } else {
                    best_path_reason_detail(reason, winner, runner_up)
                };
                explain.reasons.push(ExplainReason {
                    code: reason.code(),
                    message: format!("selected over runner-up: {detail}"),
                });
            }
            winner
        } else {
            let Some(best) = loc_rib.get(&prefix) else {
                explain.reasons.push(ExplainReason {
                    code: "no_best_route",
                    message: "no best route exists for this prefix".to_string(),
                });
                return explain;
            };
            best
        };

        explain.route_peer = Some(best.peer);
        explain.route_type = Some(route_type(best.origin_type));

        // The two suppression checks below are no-ops for an ORR winner
        // (its candidate set is pre-filtered by `orr_candidates`); they
        // decide only for the Loc-RIB best of a plain peer.
        if best.peer == target_peer {
            explain.decision = ExplainDecision::Deny;
            explain.reasons.push(ExplainReason {
                code: "ibgp_split_horizon",
                message: "route is suppressed by split horizon because it originated from the target peer".to_string(),
            });
            return explain;
        }

        if should_suppress_ibgp_inner(
            best,
            target_is_ebgp,
            target_is_rr_client,
            cluster_id,
            peer_is_rr_client,
        ) {
            explain.decision = ExplainDecision::Deny;
            let code = if !target_is_ebgp
                && !best.is_ebgp()
                && cluster_id.is_some()
                && !peer_is_rr_client.get(&best.peer).copied().unwrap_or(false)
                && !target_is_rr_client
            {
                "rr_non_client_to_non_client"
            } else {
                "ibgp_split_horizon"
            };
            let message = if code == "rr_non_client_to_non_client" {
                "route reflector will not reflect a non-client iBGP route to another non-client"
                    .to_string()
            } else {
                "iBGP split horizon suppresses advertisement of this route".to_string()
            };
            explain.reasons.push(ExplainReason { code, message });
            return explain;
        }

        let family = prefix_family(&prefix);
        if !sendable.is_some_and(|f| f.contains(&family)) {
            explain.decision = ExplainDecision::UnsupportedFamily;
            explain.reasons.push(ExplainReason {
                code: "family_not_sendable",
                message: format!(
                    "peer cannot receive {} {} routes",
                    match family.0 {
                        Afi::Ipv4 => "ipv4",
                        Afi::Ipv6 => "ipv6",
                        Afi::L2Vpn => "l2vpn",
                        Afi::BgpLs => "bgpls",
                    },
                    match family.1 {
                        Safi::Unicast => "unicast",
                        Safi::FlowSpec => "flowspec",
                        Safi::Multicast => "multicast",
                        Safi::Evpn => "evpn",
                        Safi::BgpLs => "bgpls",
                        Safi::BgpLsVpn => "bgpls_vpn",
                        Safi::MplsVpn => "mpls_vpn",
                        Safi::RtConstrain => "rtc",
                    }
                ),
            });
            return explain;
        }

        let aspath_str = if export_pol.is_some_and(PolicyChain::requires_as_path_string) {
            best.as_path()
                .map_or_else(String::new, rustbgpd_wire::AsPath::to_aspath_string)
        } else {
            String::new()
        };
        let aspath_len = best.as_path().map_or(0, rustbgpd_wire::AsPath::len);
        let ctx = RouteContext {
            prefix: Some(prefix),
            next_hop: Some(best.next_hop),
            extended_communities: best.extended_communities(),
            communities: best.communities(),
            large_communities: best.large_communities(),
            as_path_str: &aspath_str,
            as_path_len: aspath_len,
            validation_state: best.validation_state,
            aspa_state: best.aspa_state,
            peer_address: Some(target_peer),
            peer_asn: target_peer_asn,
            peer_group: target_peer_group,
            route_type: explain.route_type,
            evpn_route_type: None,
            local_pref: best.local_pref_attr(),
            med: best.med_attr(),
        };
        // Explain is a one-shot operator query path: enrich the deny /
        // permit reason with the terminal-decision policy name but do
        // NOT increment bgp_policy_routes_total here — the actual
        // distribution path counts each route once, and double-counting
        // explain calls would skew the metric.
        let (result, evaluation) = evaluate_chain_with_attribution(export_pol, &ctx);
        let policy_label = evaluation.matched_policy.as_deref().unwrap_or("inline");
        if result.action != PolicyAction::Permit {
            explain.decision = ExplainDecision::Deny;
            explain.reasons.push(ExplainReason {
                code: "policy_denied",
                message: format!("export policy {policy_label:?} denied this route"),
            });
            return explain;
        }

        explain.decision = ExplainDecision::Advertise;
        explain.modifications = result.modifications.clone();
        if let Some(route_type) = explain.route_type {
            explain.reasons.push(ExplainReason {
                code: route_type_label(route_type),
                message: route_type_message(route_type).to_string(),
            });
        }
        if export_pol.is_some() {
            explain.reasons.push(ExplainReason {
                code: "policy_permitted",
                message: format!("export policy {policy_label:?} permitted this route"),
            });
        }

        let mut next_hop = best.next_hop;
        if let Some(rustbgpd_policy::NextHopAction::Specific(addr)) =
            explain.modifications.set_next_hop.clone()
        {
            next_hop = addr;
        }
        explain.next_hop = Some(next_hop);
        explain
    }

    pub(super) fn process_withdraw_chunk(&mut self, peer: IpAddr, withdrawn: Vec<(Prefix, u32)>) {
        let active_refresh = self
            .refresh_in_progress
            .get(&peer)
            .cloned()
            .unwrap_or_default();
        let mut affected = HashSet::new();
        let mut removed_stale_counts: HashMap<(Afi, Safi), usize> = HashMap::new();

        let (rib_len, flowspec_len) = {
            let rib = self
                .ribs
                .get_mut(&peer)
                .expect("peer rib must exist before chunk processing");

            for (prefix, path_id) in withdrawn {
                if rib.withdraw(&prefix, path_id) {
                    debug!(%peer, %prefix, path_id, "withdrawn");
                    affected.insert(prefix);
                }
                let family = prefix_family(&prefix);
                if active_refresh.contains(&family)
                    && let Some(stale) = self.refresh_stale_routes.get_mut(&peer)
                    && stale.remove(&(prefix, path_id))
                {
                    *removed_stale_counts.entry(family).or_default() += 1;
                }
            }
            debug!(%peer, routes = rib.len(), "rib updated");
            (rib.len(), rib.flowspec_len())
        };

        let peer_label = peer.to_string();
        self.metrics
            .set_rib_prefixes(&peer_label, "all", gauge_val(rib_len));
        self.metrics
            .set_rib_prefixes(&peer_label, "flowspec", gauge_val(flowspec_len));
        for ((afi, safi), count) in removed_stale_counts {
            self.decrement_refresh_stale_count(peer, afi, safi, count);
        }
        self.update_peer_refresh_metrics(peer);
        if !affected.is_empty() {
            // Recompute Loc-RIB now — best-path, route events, and
            // partial-progress queries stay live mid-batch — but accumulate
            // the distribution and flush it once when the batch drains, so a
            // multi-chunk flood coalesces into one outbound pass per peer.
            let changed = self.recompute_best(&affected);
            self.pending_distribute_changed.extend(changed);
            self.pending_distribute_affected.extend(affected);
            if let Some(rib) = self.ribs.get_mut(&peer) {
                rib.gc_intern_table();
            }
        }
    }

    pub(in crate::manager) fn process_announce_chunk(
        &mut self,
        peer: IpAddr,
        announced: Vec<crate::route::Route>,
    ) {
        let active_refresh = self
            .refresh_in_progress
            .get(&peer)
            .cloned()
            .unwrap_or_default();
        let vrp_table: Option<Arc<VrpTable>> = self.vrp_table.as_ref().map(Arc::clone);
        let mut affected = HashSet::new();
        let mut removed_stale_counts: HashMap<(Afi, Safi), usize> = HashMap::new();
        let mut any_replaced = false;

        let (rib_len, flowspec_len) = {
            let rib = self
                .ribs
                .get_mut(&peer)
                .expect("peer rib must exist before chunk processing");

            for mut route in announced {
                if let Some(ref table) = vrp_table {
                    route.validation_state = validate_route_rpki(&route, table);
                }
                if let Some(ref table) = self.aspa_table {
                    route.aspa_state = validate_route_aspa(&route, table);
                }
                debug!(%peer, prefix = %route.prefix, "announced");
                affected.insert(route.prefix);
                let prefix = route.prefix;
                let path_id = route.path_id;
                any_replaced |= rib.insert(route);
                let family = prefix_family(&prefix);
                if active_refresh.contains(&family)
                    && let Some(stale) = self.refresh_stale_routes.get_mut(&peer)
                    && stale.remove(&(prefix, path_id))
                {
                    *removed_stale_counts.entry(family).or_default() += 1;
                }
            }
            debug!(%peer, routes = rib.len(), "rib updated");
            (rib.len(), rib.flowspec_len())
        };

        let peer_label = peer.to_string();
        self.metrics
            .set_rib_prefixes(&peer_label, "all", gauge_val(rib_len));
        self.metrics
            .set_rib_prefixes(&peer_label, "flowspec", gauge_val(flowspec_len));
        for ((afi, safi), count) in removed_stale_counts {
            self.decrement_refresh_stale_count(peer, afi, safi, count);
        }
        self.update_peer_refresh_metrics(peer);
        if !affected.is_empty() {
            // Recompute Loc-RIB now — best-path, route events, and
            // partial-progress queries stay live mid-batch — but accumulate
            // the distribution and flush it once when the batch drains, so a
            // multi-chunk flood coalesces into one outbound pass per peer.
            let changed = self.recompute_best(&affected);
            self.pending_distribute_changed.extend(changed);
            self.pending_distribute_affected.extend(affected);
            if any_replaced && let Some(rib) = self.ribs.get_mut(&peer) {
                rib.gc_intern_table();
            }
        }
    }

    pub(in crate::manager) fn handle_inject_route(
        &mut self,
        route: crate::route::Route,
        reply: tokio::sync::oneshot::Sender<Result<(), RibCommandError>>,
    ) {
        let prefix = route.prefix;
        let rib = self
            .ribs
            .entry(LOCAL_PEER)
            .or_insert_with(|| AdjRibIn::new(LOCAL_PEER));
        let replaced = rib.insert(route);
        debug!(%prefix, "injected local route");
        self.metrics
            .set_rib_prefixes(&LOCAL_PEER.to_string(), "all", gauge_val(rib.len()));

        let mut affected = HashSet::new();
        affected.insert(prefix);
        let changed = self.recompute_best(&affected);
        self.distribute_changes(&changed, &affected);
        if replaced && let Some(rib) = self.ribs.get_mut(&LOCAL_PEER) {
            rib.gc_intern_table();
        }

        let _ = reply.send(Ok(()));
    }

    pub(in crate::manager) fn handle_withdraw_injected(
        &mut self,
        prefix: Prefix,
        path_id: u32,
        reply: tokio::sync::oneshot::Sender<Result<(), RibCommandError>>,
    ) {
        let rib = self
            .ribs
            .entry(LOCAL_PEER)
            .or_insert_with(|| AdjRibIn::new(LOCAL_PEER));
        if rib.withdraw(&prefix, path_id) {
            debug!(%prefix, "withdrawn injected route");
            self.metrics
                .set_rib_prefixes(&LOCAL_PEER.to_string(), "all", gauge_val(rib.len()));
            let mut affected = HashSet::new();
            affected.insert(prefix);
            let changed = self.recompute_best(&affected);
            self.distribute_changes(&changed, &affected);
            if let Some(rib) = self.ribs.get_mut(&LOCAL_PEER) {
                rib.gc_intern_table();
            }
            let _ = reply.send(Ok(()));
        } else {
            let _ = reply.send(Err(RibCommandError::not_found(format!(
                "prefix {prefix} not found"
            ))));
        }
    }

    /// Multi-path distribution for a single prefix to a single peer.
    ///
    /// Collects all candidates from all Adj-RIB-In entries, filters by
    /// split-horizon/iBGP/family/policy, sorts by best-path, takes top N,
    /// and diffs against `AdjRibOut` to produce announces and withdrawals.
    #[expect(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "multipath export keeps peer, policy, and Adj-RIB-Out diff state together"
    )]
    pub(in crate::manager) fn distribute_multipath_prefix(
        ribs: &HashMap<IpAddr, AdjRibIn>,
        rib_out: &AdjRibOut,
        peer_is_rr_client: &HashMap<IpAddr, bool>,
        prefix: &Prefix,
        target_peer: IpAddr,
        target_peer_asn: Option<u32>,
        target_peer_group: Option<&str>,
        send_max: u32,
        target_is_ebgp: bool,
        target_is_rr_client: bool,
        cluster_id: Option<Ipv4Addr>,
        sendable: Option<&Vec<(Afi, Safi)>>,
        export_pol: Option<&PolicyChain>,
        orf_filter: Option<&crate::orf::OrfFilterSet>,
        orr: Option<(&crate::orr::OrrTopology, &crate::orr::SpfResult)>,
        metrics: &BgpMetrics,
        policy_stats: &mut NeighborPolicyStats,
        target_peer_label: &str,
        announce: &mut Vec<crate::route::Route>,
        withdraw: &mut Vec<(Prefix, u32)>,
        nh_override_flags: &mut Vec<Option<rustbgpd_policy::NextHopAction>>,
        policy_filtered: &mut Vec<PolicyFilteredRouteKey>,
        force: bool,
    ) {
        use crate::best_path::{best_path_cmp, best_path_cmp_orr};

        // Sendable family check
        let family = match prefix {
            Prefix::V4(_) => (Afi::Ipv4, Safi::Unicast),
            Prefix::V6(_) => (Afi::Ipv6, Safi::Unicast),
        };
        if !sendable.is_some_and(|f| f.contains(&family)) {
            // Withdraw all previously advertised paths for this prefix
            for &path_id in rib_out.path_ids_for_prefix(prefix) {
                withdraw.push((*prefix, path_id));
            }
            return;
        }

        // ORF check (RFC 5291): filters the prefix, not individual Add-Path
        // path-ids — gate the whole prefix once, before collecting candidates.
        if orf_filter.is_some_and(|f| !f.permits(prefix)) {
            for &path_id in rib_out.path_ids_for_prefix(prefix) {
                withdraw.push((*prefix, path_id));
            }
            return;
        }

        // Collect all candidates across all Adj-RIB-In entries
        let mut candidates: Vec<&crate::route::Route> = ribs
            .values()
            .flat_map(|rib| rib.iter_prefix(prefix))
            .filter(|route| {
                // Split horizon: exclude routes from the target peer
                if route.peer == target_peer {
                    return false;
                }
                // iBGP split-horizon / RFC 4456 reflection
                if should_suppress_ibgp_inner(
                    route,
                    target_is_ebgp,
                    target_is_rr_client,
                    cluster_id,
                    peer_is_rr_client,
                ) {
                    return false;
                }
                true
            })
            .collect();

        // Sort by best-path preference (best first). A target bound to a
        // resolved ORR vantage ranks by the vantage's interior cost to
        // each NEXT_HOP first (RFC 9107 §3.1) — comparator swap only.
        match orr {
            Some((topology, spf)) => candidates.sort_by(|a, b| {
                best_path_cmp_orr(
                    a,
                    b,
                    spf.cost_to(topology, a.next_hop),
                    spf.cost_to(topology, b.next_hop),
                )
            }),
            None => candidates.sort_by(|a, b| best_path_cmp(a, b)),
        }

        // Walk candidates, evaluate export policy, assign path_ids 1..N
        let needs_as_path_string = export_pol.is_some_and(PolicyChain::requires_as_path_string);
        let mut next_rank: u32 = 1;
        let limit = if send_max == u32::MAX {
            usize::MAX
        } else {
            send_max as usize
        };
        for candidate in &candidates {
            if (next_rank as usize) > limit {
                break;
            }

            // Export policy check per-candidate
            let aspath_str = if needs_as_path_string {
                candidate
                    .as_path()
                    .map_or_else(String::new, rustbgpd_wire::AsPath::to_aspath_string)
            } else {
                String::new()
            };
            let aspath_len = candidate.as_path().map_or(0, rustbgpd_wire::AsPath::len);
            let ctx = RouteContext {
                prefix: Some(*prefix),
                next_hop: Some(candidate.next_hop),
                extended_communities: candidate.extended_communities(),
                communities: candidate.communities(),
                large_communities: candidate.large_communities(),
                as_path_str: &aspath_str,
                as_path_len: aspath_len,
                validation_state: candidate.validation_state,
                aspa_state: candidate.aspa_state,
                peer_address: Some(target_peer),
                peer_asn: target_peer_asn,
                peer_group: target_peer_group,
                route_type: Some(route_type(candidate.origin_type)),
                evpn_route_type: None,
                local_pref: candidate.local_pref_attr(),
                med: candidate.med_attr(),
            };
            let (result, evaluation) = evaluate_chain_with_attribution(export_pol, &ctx);
            record_export_policy_eval(metrics, policy_stats, target_peer_label, &evaluation);
            if result.action != PolicyAction::Permit {
                policy_filtered.push(PolicyFilteredRouteKey {
                    target_peer,
                    source_peer: candidate.peer,
                    prefix: *prefix,
                    path_id: candidate.path_id,
                });
                continue;
            }

            // Apply export modifications — skip deep clone when no mods needed
            let mut modified = (*candidate).clone();
            let nh_action = if result.modifications.is_empty() {
                None
            } else {
                let nh = rustbgpd_policy::apply_modifications(
                    std::sync::Arc::make_mut(&mut modified.attributes),
                    &result.modifications,
                );
                if let Some(rustbgpd_policy::NextHopAction::Specific(addr)) = &nh {
                    modified.next_hop = *addr;
                }
                nh
            };
            modified.path_id = next_rank;

            // Only announce if different from what's already in AdjRibOut.
            // `force` mode bypasses the equality check — see
            // `distribute_single_best_prefix` for the GShut rationale.
            let changed = force
                || rib_out
                    .get(prefix, next_rank)
                    .is_none_or(|existing| !routes_equal(existing, &modified));
            if changed {
                nh_override_flags.push(nh_action);
                announce.push(modified);
            }

            next_rank += 1;
        }

        // Withdraw any previously advertised path_ids beyond the new set
        for &path_id in rib_out.path_ids_for_prefix(prefix) {
            if path_id >= next_rank {
                withdraw.push((*prefix, path_id));
            }
        }
    }

    #[expect(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "single-best export keeps peer, policy, and Adj-RIB-Out diff state together"
    )]
    pub(in crate::manager) fn distribute_single_best_prefix(
        loc_rib: &LocRib,
        rib_out: &AdjRibOut,
        peer_is_rr_client: &HashMap<IpAddr, bool>,
        prefix: &Prefix,
        target_peer: IpAddr,
        target_peer_asn: Option<u32>,
        target_peer_group: Option<&str>,
        target_is_ebgp: bool,
        target_is_rr_client: bool,
        cluster_id: Option<Ipv4Addr>,
        sendable: Option<&Vec<(Afi, Safi)>>,
        export_pol: Option<&PolicyChain>,
        orf_filter: Option<&crate::orf::OrfFilterSet>,
        metrics: &BgpMetrics,
        policy_stats: &mut NeighborPolicyStats,
        target_peer_label: &str,
        announce: &mut Vec<crate::route::Route>,
        withdraw: &mut Vec<(Prefix, u32)>,
        nh_override_flags: &mut Vec<Option<rustbgpd_policy::NextHopAction>>,
        policy_filtered: &mut Vec<PolicyFilteredRouteKey>,
        force: bool,
    ) {
        let existing_path_ids = rib_out.path_ids_for_prefix(prefix);

        let Some(best) = loc_rib.get(prefix) else {
            for &path_id in existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        };

        // Split horizon: don't send route back to its source
        if best.peer == target_peer {
            for &path_id in existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        }

        // iBGP split-horizon / RFC 4456 reflection rules
        if should_suppress_ibgp_inner(
            best,
            target_is_ebgp,
            target_is_rr_client,
            cluster_id,
            peer_is_rr_client,
        ) {
            for &path_id in existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        }

        // Sendable family check
        let family = prefix_family(prefix);
        if !sendable.is_some_and(|f| f.contains(&family)) {
            for &path_id in existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        }

        // Outbound Route Filter check (RFC 5291): a peer-pushed prefix filter
        // applied *before* export policy. ORF denial is a silent withdraw —
        // not a policy denial — so it is deliberately not recorded in the
        // `policy_filtered` set or the export-policy counters.
        if orf_filter.is_some_and(|f| !f.permits(prefix)) {
            for &path_id in existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        }

        // Export policy check
        let aspath_str = if export_pol.is_some_and(PolicyChain::requires_as_path_string) {
            best.as_path()
                .map_or_else(String::new, rustbgpd_wire::AsPath::to_aspath_string)
        } else {
            String::new()
        };
        let aspath_len = best.as_path().map_or(0, rustbgpd_wire::AsPath::len);
        let ctx = RouteContext {
            prefix: Some(*prefix),
            next_hop: Some(best.next_hop),
            extended_communities: best.extended_communities(),
            communities: best.communities(),
            large_communities: best.large_communities(),
            as_path_str: &aspath_str,
            as_path_len: aspath_len,
            validation_state: best.validation_state,
            aspa_state: best.aspa_state,
            peer_address: Some(target_peer),
            peer_asn: target_peer_asn,
            peer_group: target_peer_group,
            route_type: Some(route_type(best.origin_type)),
            evpn_route_type: None,
            local_pref: best.local_pref_attr(),
            med: best.med_attr(),
        };
        let (result, evaluation) = evaluate_chain_with_attribution(export_pol, &ctx);
        record_export_policy_eval(metrics, policy_stats, target_peer_label, &evaluation);
        if result.action != PolicyAction::Permit {
            policy_filtered.push(PolicyFilteredRouteKey {
                target_peer,
                source_peer: best.peer,
                prefix: *prefix,
                path_id: best.path_id,
            });
            for &path_id in existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        }

        // Apply export modifications to a clone — skip the deep clone of
        // the Arc<Vec<PathAttribute>> when no modifications are needed.
        let mut modified = best.clone();
        let nh_action = if result.modifications.is_empty() {
            None
        } else {
            let nh = rustbgpd_policy::apply_modifications(
                std::sync::Arc::make_mut(&mut modified.attributes),
                &result.modifications,
            );
            if let Some(rustbgpd_policy::NextHopAction::Specific(addr)) = &nh {
                modified.next_hop = *addr;
            }
            nh
        };
        modified.path_id = 0;

        // `force` mode: bypass the AdjRibOut equality suppression so
        // currently-advertised routes re-emit even when the RIB-level
        // attribute set is unchanged. Used by RFC 8326 GShut toggle
        // where the wire change is applied in transport AFTER this
        // diff. Without `force` the dirty-peers resync would skip
        // every route that already lives in AdjRibOut, defeating the
        // whole point of `RefreshPeerOutbound`.
        let changed = force
            || rib_out
                .get(prefix, 0)
                .is_none_or(|existing| !routes_equal(existing, &modified));
        if changed {
            nh_override_flags.push(nh_action);
            announce.push(modified);
        }

        // Clean up any stale multi-path entries if this prefix was previously
        // advertised via Add-Path and is now single-best.
        for &path_id in existing_path_ids {
            if path_id != 0 {
                withdraw.push((*prefix, path_id));
            }
        }
    }

    /// RFC 9107 ORR single-best distribution for one prefix to one peer
    /// bound to a *resolved* vantage.
    ///
    /// The best is NOT the Loc-RIB best: the candidate set is collected
    /// and filtered per target peer exactly like
    /// [`Self::distribute_multipath_prefix`] (all Adj-RIB-Ins, split
    /// horizon, iBGP/RR suppression), then the winner is picked with
    /// [`crate::best_path::best_path_cmp_orr`] using the vantage's SPF
    /// cost to each candidate's `NEXT_HOP`. The export tail (policy,
    /// modifications, Adj-RIB-Out diff) mirrors
    /// [`Self::distribute_single_best_prefix`].
    ///
    /// Deliberately NO per-(vantage, prefix) winner memo — it would be
    /// unsound: the candidate set is per-target-peer (split horizon and
    /// RR suppression drop different routes for different targets), so a
    /// memoized winner could be a route the next target must never
    /// receive. The `SpfResult`'s internal NH-cost LRU is the sound
    /// cache.
    #[expect(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "ORR export keeps peer, policy, and Adj-RIB-Out diff state together"
    )]
    pub(in crate::manager) fn distribute_orr_best_prefix(
        ribs: &HashMap<IpAddr, AdjRibIn>,
        rib_out: &AdjRibOut,
        peer_is_rr_client: &HashMap<IpAddr, bool>,
        orr_topology: &crate::orr::OrrTopology,
        orr_spf: &crate::orr::SpfResult,
        prefix: &Prefix,
        target_peer: IpAddr,
        target_peer_asn: Option<u32>,
        target_peer_group: Option<&str>,
        target_is_ebgp: bool,
        target_is_rr_client: bool,
        cluster_id: Option<Ipv4Addr>,
        sendable: Option<&Vec<(Afi, Safi)>>,
        export_pol: Option<&PolicyChain>,
        orf_filter: Option<&crate::orf::OrfFilterSet>,
        metrics: &BgpMetrics,
        policy_stats: &mut NeighborPolicyStats,
        target_peer_label: &str,
        announce: &mut Vec<crate::route::Route>,
        withdraw: &mut Vec<(Prefix, u32)>,
        nh_override_flags: &mut Vec<Option<rustbgpd_policy::NextHopAction>>,
        policy_filtered: &mut Vec<PolicyFilteredRouteKey>,
        force: bool,
    ) {
        use crate::best_path::best_path_cmp_orr;

        let existing_path_ids = rib_out.path_ids_for_prefix(prefix);

        // Sendable family check
        let family = prefix_family(prefix);
        if !sendable.is_some_and(|f| f.contains(&family)) {
            for &path_id in existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        }

        // Outbound Route Filter check (RFC 5291): silent withdraw, not a
        // policy denial — see `distribute_single_best_prefix`.
        if orf_filter.is_some_and(|f| !f.permits(prefix)) {
            for &path_id in existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        }

        // Collect all candidates across all Adj-RIB-In entries —
        // verbatim the multipath collector's per-target filter set.
        // Shared with the ORR explain path (`explain_single_best_prefix`)
        // so explain ranks exactly what distribution ranks.
        let candidates = orr_candidates(
            ribs,
            peer_is_rr_client,
            prefix,
            target_peer,
            target_is_ebgp,
            target_is_rr_client,
            cluster_id,
        );

        // Per-vantage best (RFC 9107): the vantage's interior cost to
        // each NEXT_HOP breaks ties between step 5 and step 5.5.
        let Some(best) = candidates.min_by(|a, b| {
            best_path_cmp_orr(
                a,
                b,
                orr_spf.cost_to(orr_topology, a.next_hop),
                orr_spf.cost_to(orr_topology, b.next_hop),
            )
        }) else {
            for &path_id in existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        };

        // Export policy check — same tail as `distribute_single_best_prefix`.
        let aspath_str = if export_pol.is_some_and(PolicyChain::requires_as_path_string) {
            best.as_path()
                .map_or_else(String::new, rustbgpd_wire::AsPath::to_aspath_string)
        } else {
            String::new()
        };
        let aspath_len = best.as_path().map_or(0, rustbgpd_wire::AsPath::len);
        let ctx = RouteContext {
            prefix: Some(*prefix),
            next_hop: Some(best.next_hop),
            extended_communities: best.extended_communities(),
            communities: best.communities(),
            large_communities: best.large_communities(),
            as_path_str: &aspath_str,
            as_path_len: aspath_len,
            validation_state: best.validation_state,
            aspa_state: best.aspa_state,
            peer_address: Some(target_peer),
            peer_asn: target_peer_asn,
            peer_group: target_peer_group,
            route_type: Some(route_type(best.origin_type)),
            evpn_route_type: None,
            local_pref: best.local_pref_attr(),
            med: best.med_attr(),
        };
        let (result, evaluation) = evaluate_chain_with_attribution(export_pol, &ctx);
        record_export_policy_eval(metrics, policy_stats, target_peer_label, &evaluation);
        if result.action != PolicyAction::Permit {
            policy_filtered.push(PolicyFilteredRouteKey {
                target_peer,
                source_peer: best.peer,
                prefix: *prefix,
                path_id: best.path_id,
            });
            for &path_id in existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        }

        // Apply export modifications to a clone — skip the deep clone of
        // the Arc<Vec<PathAttribute>> when no modifications are needed.
        let mut modified = best.clone();
        let nh_action = if result.modifications.is_empty() {
            None
        } else {
            let nh = rustbgpd_policy::apply_modifications(
                std::sync::Arc::make_mut(&mut modified.attributes),
                &result.modifications,
            );
            if let Some(rustbgpd_policy::NextHopAction::Specific(addr)) = &nh {
                modified.next_hop = *addr;
            }
            nh
        };
        modified.path_id = 0;

        // `force` semantics as in `distribute_single_best_prefix`.
        let changed = force
            || rib_out
                .get(prefix, 0)
                .is_none_or(|existing| !routes_equal(existing, &modified));
        if changed {
            nh_override_flags.push(nh_action);
            announce.push(modified);
        }

        // Clean up any stale multi-path entries if this prefix was
        // previously advertised via Add-Path and is now single-best.
        for &path_id in existing_path_ids {
            if path_id != 0 {
                withdraw.push((*prefix, path_id));
            }
        }
    }
}
