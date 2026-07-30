use super::{
    AdjRibIn, AdjRibOut, Afi, Arc, BgpMetrics, ExplainAdvertisedRoute, ExplainDecision,
    ExplainReason, HashMap, HashSet, IpAddr, Ipv4Addr, LOCAL_PEER, LocRib, NeighborPolicyStats,
    PolicyAction, PolicyChain, PolicyFilteredRouteKey, Prefix, RibCommandError, RibManager,
    RouteContext, Safi, UnicastPrefixPeers, VrpTable, debug, evaluate_chain_with_attribution,
    family_label, gauge_val, policy_label_with_term, prefix_family, record_export_policy_eval,
    route_type, route_type_label, route_type_message, routes_equal, rr_suppression_reason,
    should_suppress_ibgp_inner, unicast_route_family, validate_route_aspa, validate_route_rpki,
};

#[cfg(any(test, feature = "bench-internals"))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::manager) struct AddPathSelectionStats {
    pub bounded_dispatches: usize,
    pub full_sort_dispatches: usize,
    pub sorted_tail_fallbacks: usize,
}

#[cfg(any(test, feature = "bench-internals"))]
std::thread_local! {
    static ADD_PATH_SELECTION_STATS: std::cell::Cell<AddPathSelectionStats> =
        const { std::cell::Cell::new(AddPathSelectionStats {
            bounded_dispatches: 0,
            full_sort_dispatches: 0,
            sorted_tail_fallbacks: 0,
        }) };
}

#[cfg(any(test, feature = "bench-internals"))]
#[allow(dead_code)]
pub(in crate::manager) fn reset_add_path_selection_stats() {
    ADD_PATH_SELECTION_STATS.set(AddPathSelectionStats::default());
}

#[cfg(any(test, feature = "bench-internals"))]
#[allow(dead_code)]
pub(in crate::manager) fn add_path_selection_stats() -> AddPathSelectionStats {
    ADD_PATH_SELECTION_STATS.get()
}

#[cfg(any(test, feature = "bench-internals"))]
fn record_add_path_selection(update: impl FnOnce(&mut AddPathSelectionStats)) {
    ADD_PATH_SELECTION_STATS.with(|cell| {
        let mut stats = cell.get();
        update(&mut stats);
        cell.set(stats);
    });
}

/// Gate code and message for an export-policy deny.
///
/// ADR-0112: a rejection by the reserved internal deny is a *missing* operator
/// policy, not an operator policy that rejected. It gets its own code so a
/// machine consumer never has to parse the message, and so an operator staring
/// at the ladder is not sent looking for a policy they never wrote. Config
/// validation refuses the reserved names to operator policies, so the deciding
/// member's name is proof rather than a heuristic.
fn export_deny_attribution(
    matched_policy: Option<&str>,
    policy_label: &str,
) -> (&'static str, String) {
    if matched_policy.is_some_and(rustbgpd_policy::is_rfc8212_reserved_policy_name) {
        (
            "rfc8212_missing_export_policy",
            "RFC 8212: no explicit export policy is configured for this eBGP peer, so the \
             reserved internal deny is installed and nothing enters its Adj-RIB-Out"
                .to_string(),
        )
    } else {
        (
            "policy_denied",
            format!("export policy {policy_label:?} denied this route"),
        )
    }
}

/// Candidate paths for `prefix` visible to `target_peer` under RFC 9107
/// ORR: every Adj-RIB-In entry that survives split horizon and the
/// iBGP / RFC 4456 reflection rules. Shared by the ORR distribution and
/// explain paths so both rank the exact same set. Collection goes through
/// the announcing-peers reverse index so only peers that actually hold the
/// prefix are probed.
#[expect(
    clippy::too_many_arguments,
    reason = "candidate collection mirrors the per-target reflection filter inputs"
)]
fn orr_candidates<'a>(
    ribs: &'a HashMap<IpAddr, AdjRibIn>,
    prefix_peers: &'a UnicastPrefixPeers,
    peer_is_rr_client: &'a HashMap<IpAddr, bool>,
    prefix: &'a Prefix,
    target_peer: IpAddr,
    target_is_ebgp: bool,
    target_is_rr_client: bool,
    cluster_id: Option<Ipv4Addr>,
) -> impl Iterator<Item = &'a crate::route::Route> {
    RibManager::unicast_candidates(ribs, prefix_peers, prefix).filter(move |route| {
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

/// Candidate paths for `prefix` visible to `target_peer` in the live
/// multipath / per-client-best collector: [`orr_candidates`]'
/// split-horizon and RFC 4456 reflection filter plus the per-candidate
/// RFC 1997 `NO_ADVERTISE` and RFC 9494 §4.4 LLGR export gates. Shared by
/// `distribute_multipath_prefix` and the per-client-best explain arm so
/// explain walks exactly the candidate set live staging walks.
#[expect(
    clippy::too_many_arguments,
    reason = "candidate collection mirrors the per-target reflection filter inputs"
)]
fn multipath_candidates<'a>(
    ribs: &'a HashMap<IpAddr, AdjRibIn>,
    prefix_peers: &'a UnicastPrefixPeers,
    peer_is_rr_client: &'a HashMap<IpAddr, bool>,
    prefix: &'a Prefix,
    target_peer: IpAddr,
    target_is_ebgp: bool,
    interpret_rfc1997: bool,
    rs_control: Option<(u32, u32)>,
    target_is_rr_client: bool,
    cluster_id: Option<Ipv4Addr>,
    family: (Afi, Safi),
    llgr: Option<&'a Vec<(Afi, Safi)>>,
) -> impl Iterator<Item = &'a crate::route::Route> {
    orr_candidates(
        ribs,
        prefix_peers,
        peer_is_rr_client,
        prefix,
        target_peer,
        target_is_ebgp,
        target_is_rr_client,
        cluster_id,
    )
    .filter(move |route| {
        // RFC 1997: NO_ADVERTISE is selection ineligibility, not a
        // post-policy attribute rewrite. A permit policy that removes
        // the community must not make the route exportable.
        if super::no_advertise_export_suppressed(route.communities()) {
            return false;
        }
        // RFC 1997: NO_EXPORT/NO_EXPORT_SUBCONFED are likewise source-route
        // ineligibility, but only toward eBGP targets in honor mode — see
        // `no_export_export_suppressed` for the source-only asymmetry.
        if super::no_export_export_suppressed(
            route.communities(),
            target_is_ebgp,
            interpret_rfc1997,
        ) {
            return false;
        }
        // RFC 7947 §2.3.2: a control community forbidding announcement
        // toward this target's ASN is candidate ineligibility — a
        // suppressed sibling must not hold an Add-Path rank (or the
        // per-client-best slot). `rs_control` is `(rs_asn, peer_asn)`
        // for sessions with `rs_control_communities`, `None` otherwise.
        if let Some((rs_asn, peer_asn)) = rs_control
            && super::rs_control::rs_control_export_suppressed(
                route.communities(),
                route.large_communities(),
                rs_asn,
                peer_asn,
            )
        {
            return false;
        }
        // RFC 9494 §4.4: each staged candidate is gated individually —
        // a stale candidate must not occupy an Add-Path rank (or the
        // filtered-best slot) toward a non-LLGR eBGP peer.
        !super::llgr_stale_export_suppressed(
            route.is_llgr_stale,
            route.communities(),
            family,
            target_is_ebgp,
            llgr,
        )
    })
}

impl RibManager {
    /// Explain the single-best export ladder for an RFC 9107 ORR peer,
    /// an Add-Path-send peer, or an RFC 7947 §2.3.2 per-client-best
    /// peer — the per-target selection shapes
    /// the [`super::ExportTarget::Explain`] dry run of
    /// `distribute_single_best_prefix` cannot serve (their best is not
    /// the Loc-RIB best / their staging is multipath). Candidate
    /// collection is shared with live distribution (`orr_candidates` /
    /// `multipath_candidates`), and every gate reuses the same helper
    /// the live bodies call (`no_advertise_export_suppressed`,
    /// `llgr_stale_export_suppressed`, `OrfFilterSet::permits`,
    /// `rr_suppression_reason`, `routes_equal`), in the live bodies'
    /// evaluation order (family → ORF → selection → LLGR /
    /// `NO_ADVERTISE` → policy → Adj-RIB-Out diff).
    ///
    /// `per_client_best` selects the RFC 7947 §2.3.2 arm: rank the live
    /// collector's candidate set with the Loc-RIB comparator and take
    /// the first export-policy-permitted candidate, recording one
    /// reason per denied candidate — the same walk
    /// `distribute_multipath_prefix(send_max = 1, stage_path_id_zero)`
    /// performs live. Ignored when Add-Path send is negotiated for the
    /// prefix's family (a negotiated capability outranks the fallback,
    /// exactly like the live mode ladder).
    #[expect(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        clippy::fn_params_excessive_bools,
        reason = "explain mirrors live single-best export inputs for policy parity"
    )]
    pub(in crate::manager) fn explain_single_best_prefix(
        loc_rib: &LocRib,
        ribs: &HashMap<IpAddr, AdjRibIn>,
        prefix_peers: &UnicastPrefixPeers,
        peer_is_rr_client: &HashMap<IpAddr, bool>,
        rib_out: Option<&AdjRibOut>,
        prefix: Prefix,
        target_peer: IpAddr,
        target_peer_asn: Option<u32>,
        target_peer_group: Option<&str>,
        target_is_ebgp: bool,
        interpret_rfc1997: bool,
        rs_control_asn: Option<u32>,
        target_is_rr_client: bool,
        target_local_role: Option<rustbgpd_wire::BgpRole>,
        cluster_id: Option<Ipv4Addr>,
        sendable: Option<&Vec<(Afi, Safi)>>,
        llgr: Option<&Vec<(Afi, Safi)>>,
        orf_filter: Option<&crate::orf::OrfFilterSet>,
        add_path_send_max: u32,
        export_pol: Option<&PolicyChain>,
        orr: Option<(&crate::orr::OrrTopology, &crate::orr::SpfResult, IpAddr)>,
        per_client_best: bool,
        source: Option<crate::update::RouteSourceIdentity>,
    ) -> ExplainAdvertisedRoute {
        use crate::best_path::{
            BestPathReason, best_path_cmp_orr, best_path_cmp_orr_with_reason,
            best_path_reason_detail, orr_interior_cost_detail,
        };
        use crate::update::ExportGateVerdict::{NotApplicable, Pass, Stop};

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
            gates: Vec::new(),
            update_group_id: None,
            already_advertised: false,
            rd: None,
            source,
        };
        let gate = |gates: &mut Vec<crate::update::ExportGateStep>,
                    g: &'static str,
                    code: &'static str,
                    verdict: crate::update::ExportGateVerdict,
                    detail: String| {
            gates.push(crate::update::ExportGateStep {
                gate: g,
                code,
                verdict,
                detail,
            });
        };

        // Sendable family — first in the live ORR/multipath bodies.
        let family = prefix_family(&prefix);
        if !sendable.is_some_and(|f| f.contains(&family)) {
            explain.decision = ExplainDecision::UnsupportedFamily;
            let message = format!("peer cannot receive {} routes", super::family_label(family));
            gate(
                &mut explain.gates,
                "family",
                "family_not_sendable",
                Stop,
                message.clone(),
            );
            explain.reasons.push(ExplainReason {
                code: "family_not_sendable",
                message,
            });
            return explain;
        }
        gate(
            &mut explain.gates,
            "family",
            "family",
            Pass,
            format!("peer negotiated {}", super::family_label(family)),
        );

        // Outbound Route Filter (RFC 5291) — before selection/policy,
        // exactly like the live bodies. Silent withdraw, not a policy
        // denial.
        if let Some(filter) = orf_filter {
            if !filter.permits(&prefix) {
                explain.decision = ExplainDecision::Deny;
                let message = "peer-pushed Outbound Route Filter (RFC 5291) does not permit \
                               this prefix"
                    .to_string();
                gate(
                    &mut explain.gates,
                    "orf",
                    "orf_filtered",
                    Stop,
                    message.clone(),
                );
                explain.reasons.push(ExplainReason {
                    code: "orf_filtered",
                    message,
                });
                return explain;
            }
            gate(
                &mut explain.gates,
                "orf",
                "orf",
                Pass,
                "peer-pushed Outbound Route Filter (RFC 5291) permits this prefix".to_string(),
            );
        } else {
            gate(
                &mut explain.gates,
                "orf",
                "orf",
                NotApplicable,
                "peer installed no Outbound Route Filter".to_string(),
            );
        }

        // Select the route to explain. An ORR-bound peer's best is NOT
        // the Loc-RIB best: rank the per-target candidate set with the
        // vantage's interior costs, exactly like
        // `distribute_orr_best_prefix` (same collection via
        // `orr_candidates`, same comparator). A plain peer explains the
        // Loc-RIB best, unchanged.
        let best = if let Some(source) = source {
            if let Some((_, _, vantage)) = orr {
                explain.orr_vantage = Some(vantage);
            }
            let selected = ribs
                .get(&source.peer)
                .and_then(|rib| {
                    rib.iter_prefix(&prefix)
                        .find(|route| route.path_id == source.path_id)
                })
                .expect("source identity was validated before export explain");
            gate(
                &mut explain.gates,
                "best_route",
                "source_selected",
                Pass,
                format!(
                    "selected Adj-RIB-In path from {} with inbound path ID {}",
                    source.peer, source.path_id
                ),
            );
            selected
        } else if let Some((topology, spf, vantage)) = orr {
            explain.orr_vantage = Some(vantage);
            let input_diagnostics = topology.input_diagnostics();
            if input_diagnostics.noteworthy() {
                explain.reasons.push(ExplainReason {
                    code: "orr_topology_input_diagnostics",
                    message: format!(
                        "aggregate non-decisive ORR input diagnostics; winner and decisive cost are unchanged; default-topology SPF uses {}",
                        input_diagnostics.summary()
                    ),
                });
            }
            let mut ranked: Vec<&crate::route::Route> = orr_candidates(
                ribs,
                prefix_peers,
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
                gate(
                    &mut explain.gates,
                    "best_route",
                    "no_orr_candidate",
                    Stop,
                    "no candidate for this prefix survives split-horizon / reflection \
                     filtering for this ORR peer"
                        .to_string(),
                );
                explain.reasons.push(ExplainReason {
                    code: "no_orr_candidate",
                    message: "no candidate for this prefix survives split-horizon / \
                              reflection filtering for this ORR peer"
                        .to_string(),
                });
                return explain;
            };
            gate(
                &mut explain.gates,
                "best_route",
                "orr_vantage_best",
                Pass,
                format!(
                    "per-vantage best from {} ({} candidate(s) ranked from vantage {vantage})",
                    winner.peer,
                    ranked.len()
                ),
            );
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
        } else if per_client_best && add_path_send_max == 0 {
            // RFC 7947 §2.3.2 per-client best-path: rank the exact
            // candidate set the live filtered-best collector walks
            // (`multipath_candidates` — split horizon, RFC 4456
            // reflection, per-candidate LLGR) with the Loc-RIB
            // comparator, then take the first export-policy-permitted
            // candidate — the same walk
            // `distribute_multipath_prefix(send_max = 1)` performs
            // live, with one recorded verdict per denied candidate.
            let mut ranked: Vec<&crate::route::Route> = multipath_candidates(
                ribs,
                prefix_peers,
                peer_is_rr_client,
                &prefix,
                target_peer,
                target_is_ebgp,
                interpret_rfc1997,
                rs_control_asn.zip(target_peer_asn),
                target_is_rr_client,
                cluster_id,
                family,
                llgr,
            )
            .collect();
            ranked.sort_by(|a, b| crate::best_path::best_path_cmp(a, b));
            if ranked.is_empty() {
                let message = "no candidate for this prefix survives split-horizon / \
                               reflection / NO_ADVERTISE / LLGR filtering for this per-client \
                               best-path peer"
                    .to_string();
                gate(
                    &mut explain.gates,
                    "best_route",
                    "no_per_client_candidate",
                    Stop,
                    message.clone(),
                );
                explain.reasons.push(ExplainReason {
                    code: "no_per_client_candidate",
                    message,
                });
                return explain;
            }
            let needs_as_path_string = export_pol.is_some_and(PolicyChain::requires_as_path_string);
            let total = ranked.len();
            let mut winner = None;
            let mut policy_memo = super::ExportMemo::default();
            let mut first_no_advertise_suppression = None;
            for (index, &candidate) in ranked.iter().enumerate() {
                // Per-candidate export-policy verdict — the same
                // context the live per-candidate walk builds, evaluated
                // without counters (explain is a one-shot query; see
                // the tail's non-counting rationale).
                let aspath_str = if needs_as_path_string {
                    candidate
                        .as_path()
                        .map_or_else(String::new, rustbgpd_wire::AsPath::to_aspath_string)
                } else {
                    String::new()
                };
                let ctx = RouteContext {
                    prefix: Some(prefix),
                    next_hop: Some(candidate.next_hop),
                    extended_communities: candidate.extended_communities(),
                    communities: candidate.communities(),
                    large_communities: candidate.large_communities(),
                    as_path_str: &aspath_str,
                    as_path: candidate.as_path(),
                    as_path_len: candidate.as_path().map_or(0, rustbgpd_wire::AsPath::len),
                    origin_asn: candidate
                        .as_path()
                        .and_then(rustbgpd_wire::AsPath::origin_asn),
                    validation_state: candidate.validation_state,
                    aspa_state: candidate.aspa_state,
                    peer_address: Some(target_peer),
                    peer_asn: target_peer_asn,
                    peer_group: target_peer_group,
                    route_type: Some(route_type(candidate.origin_type)),
                    family: Some(unicast_route_family(&prefix)),
                    evpn_route_type: None,
                    local_pref: candidate.local_pref_attr(),
                    med: candidate.med_attr(),
                };
                let permitted = match export_pol {
                    Some(chain) => {
                        let (result, evaluation) = chain.compiled().evaluate_with_attribution(&ctx);
                        if result.action == PolicyAction::Permit {
                            let (modified, _) = policy_memo.apply(candidate, &result.modifications);
                            if super::no_advertise_export_suppressed(modified.communities()) {
                                let label = super::policy_label_with_term(
                                    export_pol,
                                    &ctx,
                                    evaluation.matched_policy.as_deref(),
                                );
                                if first_no_advertise_suppression.is_none() {
                                    first_no_advertise_suppression =
                                        Some((result.modifications.clone(), label.clone()));
                                }
                                explain.reasons.push(ExplainReason {
                                    code: "per_client_candidate_no_advertise",
                                    message: format!(
                                        "candidate {rank} of {total} (from {peer}, next hop \
                                         {next_hop}) suppressed after export policy {label:?} \
                                         added NO_ADVERTISE",
                                        rank = index + 1,
                                        peer = candidate.peer,
                                        next_hop = candidate.next_hop,
                                    ),
                                });
                                false
                            } else {
                                true
                            }
                        } else {
                            let label = super::policy_label_with_term(
                                export_pol,
                                &ctx,
                                evaluation.matched_policy.as_deref(),
                            );
                            explain.reasons.push(ExplainReason {
                                code: "per_client_candidate_denied",
                                message: format!(
                                    "candidate {rank} of {total} (from {peer}, next hop \
                                     {next_hop}) denied by export policy {label:?}",
                                    rank = index + 1,
                                    peer = candidate.peer,
                                    next_hop = candidate.next_hop,
                                ),
                            });
                            false
                        }
                    }
                    None => true,
                };
                if permitted {
                    winner = Some((index, candidate));
                    break;
                }
            }
            if winner.is_none()
                && let Some((modifications, label)) = first_no_advertise_suppression
            {
                explain.decision = ExplainDecision::Deny;
                explain.modifications = modifications;
                gate(
                    &mut explain.gates,
                    "export_policy",
                    "policy_permitted",
                    Pass,
                    format!("export policy {label:?} permitted a ranked candidate"),
                );
                let message = "no candidate is exportable; at least one export-policy Permit \
                               result carried NO_ADVERTISE, which RFC 1997 forbids advertising \
                               to any BGP peer"
                    .to_string();
                gate(
                    &mut explain.gates,
                    "no_advertise",
                    "no_advertise_policy_suppressed",
                    Stop,
                    message.clone(),
                );
                explain.reasons.push(ExplainReason {
                    code: "no_advertise_policy_suppressed",
                    message,
                });
                return explain;
            }
            let Some((rank, winner)) = winner else {
                explain.decision = ExplainDecision::Deny;
                let message = format!(
                    "all {total} candidate(s) denied by export policy — per-client best-path \
                     (RFC 7947 §2.3.2) advertises nothing"
                );
                gate(
                    &mut explain.gates,
                    "best_route",
                    "per_client_all_denied",
                    Stop,
                    message.clone(),
                );
                explain.reasons.push(ExplainReason {
                    code: "per_client_all_denied",
                    message,
                });
                return explain;
            };
            gate(
                &mut explain.gates,
                "best_route",
                "per_client_best",
                Pass,
                format!(
                    "per-client best-path (RFC 7947 §2.3.2): candidate {} of {total} \
                     from {} is the first export-policy-permitted candidate",
                    rank + 1,
                    winner.peer
                ),
            );
            winner
        } else {
            let Some(best) = loc_rib.get(&prefix) else {
                gate(
                    &mut explain.gates,
                    "best_route",
                    "no_best_route",
                    Stop,
                    "no best route exists for this prefix".to_string(),
                );
                explain.reasons.push(ExplainReason {
                    code: "no_best_route",
                    message: "no best route exists for this prefix".to_string(),
                });
                return explain;
            };
            gate(
                &mut explain.gates,
                "best_route",
                route_type_label(route_type(best.origin_type)),
                Pass,
                format!(
                    "{} (Loc-RIB best from {})",
                    route_type_message(route_type(best.origin_type)),
                    best.peer
                ),
            );
            best
        };

        explain.route_peer = Some(best.peer);
        explain.route_type = Some(route_type(best.origin_type));

        // The two suppression checks below are no-ops for an ORR winner
        // (its candidate set is pre-filtered by `orr_candidates`); they
        // decide only for the Loc-RIB best of a plain peer.
        if best.peer == target_peer {
            explain.decision = ExplainDecision::Deny;
            let message = "route is suppressed by split horizon because it originated from \
                           the target peer"
                .to_string();
            gate(
                &mut explain.gates,
                "split_horizon",
                "ibgp_split_horizon",
                Stop,
                message.clone(),
            );
            explain.reasons.push(ExplainReason {
                code: "ibgp_split_horizon",
                message,
            });
            return explain;
        }
        gate(
            &mut explain.gates,
            "split_horizon",
            "split_horizon",
            Pass,
            "route did not originate from the target peer".to_string(),
        );

        if should_suppress_ibgp_inner(
            best,
            target_is_ebgp,
            target_is_rr_client,
            cluster_id,
            peer_is_rr_client,
        ) {
            explain.decision = ExplainDecision::Deny;
            let (code, message) = super::rr_suppression_reason(
                best,
                target_is_ebgp,
                target_is_rr_client,
                cluster_id,
                peer_is_rr_client,
            );
            gate(
                &mut explain.gates,
                "rr_reflection",
                code,
                Stop,
                message.to_string(),
            );
            explain.reasons.push(ExplainReason {
                code,
                message: message.to_string(),
            });
            return explain;
        }
        gate(
            &mut explain.gates,
            "rr_reflection",
            "rr_reflection",
            Pass,
            "iBGP split-horizon / RFC 4456 reflection rules permit this route".to_string(),
        );

        // RFC 9494 §4.4 — same helper the live bodies gate with.
        if super::llgr_stale_export_suppressed(
            best.is_llgr_stale,
            best.communities(),
            family,
            target_is_ebgp,
            llgr,
        ) {
            explain.decision = ExplainDecision::Deny;
            let message = "LLGR-stale route suppressed toward an eBGP peer that did not \
                           advertise the Long-Lived Graceful Restart capability for this \
                           family (RFC 9494 §4.4)"
                .to_string();
            gate(
                &mut explain.gates,
                "llgr",
                "llgr_stale_suppressed",
                Stop,
                message.clone(),
            );
            explain.reasons.push(ExplainReason {
                code: "llgr_stale_suppressed",
                message,
            });
            return explain;
        }
        gate(
            &mut explain.gates,
            "llgr",
            "llgr",
            Pass,
            "route is not suppressed by the RFC 9494 LLGR export restriction".to_string(),
        );

        // RFC 1997 — a route carrying NO_ADVERTISE is ineligible before
        // export policy, so a permit policy cannot remove the community
        // and bypass the well-known-community restriction.
        if super::no_advertise_export_suppressed(best.communities()) {
            explain.decision = ExplainDecision::Deny;
            let message = "route carries NO_ADVERTISE and RFC 1997 forbids advertisement to any \
                           BGP peer"
                .to_string();
            gate(
                &mut explain.gates,
                "no_advertise",
                "no_advertise_suppressed",
                Stop,
                message.clone(),
            );
            explain.reasons.push(ExplainReason {
                code: "no_advertise_suppressed",
                message,
            });
            return explain;
        }

        // RFC 1997 — NO_EXPORT/NO_EXPORT_SUBCONFED source-route
        // suppression toward an eBGP target in honor mode. Same
        // pre-policy placement as NO_ADVERTISE; the deliberate
        // difference is that no post-policy form exists (policy-added
        // NO_EXPORT is delivered).
        if super::no_export_export_suppressed(best.communities(), target_is_ebgp, interpret_rfc1997)
        {
            explain.decision = ExplainDecision::Deny;
            let message = "route carries NO_EXPORT (or NO_EXPORT_SUBCONFED) and RFC 1997 \
                           forbids advertisement to an eBGP peer"
                .to_string();
            gate(
                &mut explain.gates,
                "no_export",
                "no_export_suppressed",
                Stop,
                message.clone(),
            );
            explain.reasons.push(ExplainReason {
                code: "no_export_suppressed",
                message,
            });
            return explain;
        }
        if let Some((rs_asn, peer_asn)) = rs_control_asn.zip(target_peer_asn)
            && super::rs_control::rs_control_export_suppressed(
                best.communities(),
                best.large_communities(),
                rs_asn,
                peer_asn,
            )
        {
            explain.decision = ExplainDecision::Deny;
            let message = "route carries an RFC 7947 route-server control community that forbids announcing it toward this peer's ASN".to_string();
            gate(
                &mut explain.gates,
                "rs_control",
                "rs_control_suppressed",
                Stop,
                message.clone(),
            );
            explain.reasons.push(ExplainReason {
                code: "rs_control_suppressed",
                message,
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
        let origin_asn = best.as_path().and_then(rustbgpd_wire::AsPath::origin_asn);
        let ctx = RouteContext {
            prefix: Some(prefix),
            next_hop: Some(best.next_hop),
            extended_communities: best.extended_communities(),
            communities: best.communities(),
            large_communities: best.large_communities(),
            as_path_str: &aspath_str,
            as_path: best.as_path(),
            as_path_len: aspath_len,
            origin_asn,
            validation_state: best.validation_state,
            aspa_state: best.aspa_state,
            peer_address: Some(target_peer),
            peer_asn: target_peer_asn,
            peer_group: target_peer_group,
            route_type: explain.route_type,
            family: Some(unicast_route_family(&prefix)),
            evpn_route_type: None,
            local_pref: best.local_pref_attr(),
            med: best.med_attr(),
        };
        // Explain is a one-shot operator query path: enrich the deny /
        // permit reason with the terminal-decision policy name but do
        // NOT increment bgp_policy_routes_total or the ADR-0096
        // per-term hit counters here — the actual distribution path
        // counts each route once, and double-counting explain calls
        // would skew both metrics (hence the IR-level non-counting
        // evaluation instead of `PolicyChain::evaluate_with_attribution`).
        let (result, evaluation) = match export_pol {
            Some(chain) => chain.compiled().evaluate_with_attribution(&ctx),
            None => (
                rustbgpd_policy::PolicyResult::permit(),
                rustbgpd_policy::PolicyEvaluation {
                    action: PolicyAction::Permit,
                    matched_policy: None,
                    eval_error: None,
                },
            ),
        };
        let policy_label =
            super::policy_label_with_term(export_pol, &ctx, evaluation.matched_policy.as_deref());
        if result.action != PolicyAction::Permit {
            explain.decision = ExplainDecision::Deny;
            let (code, message) =
                export_deny_attribution(evaluation.matched_policy.as_deref(), &policy_label);
            gate(
                &mut explain.gates,
                "export_policy",
                code,
                Stop,
                message.clone(),
            );
            explain.reasons.push(ExplainReason { code, message });
            return explain;
        }
        if export_pol.is_some() {
            gate(
                &mut explain.gates,
                "export_policy",
                "policy_permitted",
                Pass,
                format!("export policy {policy_label:?} permitted this route"),
            );
        } else {
            gate(
                &mut explain.gates,
                "export_policy",
                "export_policy",
                NotApplicable,
                "no export policy configured (default permit)".to_string(),
            );
        }

        explain.modifications = result.modifications.clone();
        let mut post_policy_memo = super::ExportMemo::default();
        let (mut post_policy_candidate, _) = post_policy_memo.apply(best, &result.modifications);
        if super::no_advertise_export_suppressed(post_policy_candidate.communities()) {
            explain.decision = ExplainDecision::Deny;
            let message = "export policy produced a route carrying NO_ADVERTISE; RFC 1997 \
                           forbids advertisement to any BGP peer"
                .to_string();
            gate(
                &mut explain.gates,
                "no_advertise",
                "no_advertise_policy_suppressed",
                Stop,
                message.clone(),
            );
            explain.reasons.push(ExplainReason {
                code: "no_advertise_policy_suppressed",
                message,
            });
            return explain;
        }

        // RFC 7911 requires a re-advertiser to assign its own Path
        // Identifier. For a source-scoped query, derive that outbound ID
        // from the same best-first, policy-compacted walk as live Add-Path
        // distribution. Eligibility/policy failures above retain rank 0;
        // OTC and exact-wire rejection occur after assignment and therefore
        // retain the attempted outbound rank.
        if let Some(source) = source {
            let mut ranked: Vec<&crate::route::Route> = multipath_candidates(
                ribs,
                prefix_peers,
                peer_is_rr_client,
                &prefix,
                target_peer,
                target_is_ebgp,
                interpret_rfc1997,
                rs_control_asn.zip(target_peer_asn),
                target_is_rr_client,
                cluster_id,
                family,
                llgr,
            )
            .collect();
            match orr {
                Some((topology, spf, _)) => ranked.sort_by(|a, b| {
                    best_path_cmp_orr(
                        a,
                        b,
                        spf.cost_to(topology, a.next_hop),
                        spf.cost_to(topology, b.next_hop),
                    )
                }),
                None => ranked.sort_by(|a, b| crate::best_path::best_path_cmp(a, b)),
            }

            let needs_as_path_string = export_pol.is_some_and(PolicyChain::requires_as_path_string);
            let mut rank = 1_u32;
            let mut rank_memo = super::ExportMemo::default();
            let mut selected_rank = None;
            for candidate in ranked {
                let candidate_aspath = if needs_as_path_string {
                    candidate
                        .as_path()
                        .map_or_else(String::new, rustbgpd_wire::AsPath::to_aspath_string)
                } else {
                    String::new()
                };
                let candidate_ctx = RouteContext {
                    prefix: Some(prefix),
                    next_hop: Some(candidate.next_hop),
                    extended_communities: candidate.extended_communities(),
                    communities: candidate.communities(),
                    large_communities: candidate.large_communities(),
                    as_path_str: &candidate_aspath,
                    as_path: candidate.as_path(),
                    as_path_len: candidate.as_path().map_or(0, rustbgpd_wire::AsPath::len),
                    origin_asn: candidate
                        .as_path()
                        .and_then(rustbgpd_wire::AsPath::origin_asn),
                    validation_state: candidate.validation_state,
                    aspa_state: candidate.aspa_state,
                    peer_address: Some(target_peer),
                    peer_asn: target_peer_asn,
                    peer_group: target_peer_group,
                    route_type: Some(route_type(candidate.origin_type)),
                    family: Some(unicast_route_family(&prefix)),
                    evpn_route_type: None,
                    local_pref: candidate.local_pref_attr(),
                    med: candidate.med_attr(),
                };
                let candidate_result = match export_pol {
                    Some(chain) => chain.compiled().evaluate_with_attribution(&candidate_ctx).0,
                    None => rustbgpd_policy::PolicyResult::permit(),
                };
                if candidate_result.action != PolicyAction::Permit {
                    continue;
                }
                let (candidate_modified, _) =
                    rank_memo.apply(candidate, &candidate_result.modifications);
                if super::no_advertise_export_suppressed(candidate_modified.communities()) {
                    continue;
                }
                if candidate.peer == source.peer && candidate.path_id == source.path_id {
                    selected_rank = Some(rank);
                    break;
                }
                rank += 1;
            }
            let outbound_rank = selected_rank
                .expect("selected source passed the same eligibility and policy gates");
            if outbound_rank > add_path_send_max {
                explain.decision = ExplainDecision::Deny;
                let message = format!(
                    "source is eligible at outbound rank {outbound_rank}, beyond this peer's \
                     Add-Path send_max {add_path_send_max}"
                );
                gate(
                    &mut explain.gates,
                    "add_path_send_max",
                    "beyond_send_max",
                    Stop,
                    message.clone(),
                );
                explain.reasons.push(ExplainReason {
                    code: "beyond_send_max",
                    message,
                });
                return explain;
            }
            explain.path_id = outbound_rank;
            if let (Some(rs_asn), Some(peer_asn)) = (rs_control_asn, target_peer_asn) {
                let prepend = super::rs_control::rs_control_prepend_count(
                    best.large_communities(),
                    rs_asn,
                    peer_asn,
                );
                super::rs_control::apply_rs_control_egress(
                    &mut post_policy_candidate,
                    rs_asn,
                    prepend,
                );
            }
            post_policy_candidate.path_id = outbound_rank;
        }
        if super::otc_egress_blocked(&post_policy_candidate, target_local_role) {
            explain.decision = ExplainDecision::Deny;
            let message = "route already carries Only-To-Customer and RFC 9234 forbids propagation toward this Provider, Peer, or Route Server".to_string();
            gate(
                &mut explain.gates,
                "otc",
                "otc_egress_blocked",
                Stop,
                message.clone(),
            );
            explain.reasons.push(ExplainReason {
                code: "otc_egress_blocked",
                message,
            });
            return explain;
        }
        if matches!(
            target_local_role,
            Some(
                rustbgpd_wire::BgpRole::Customer
                    | rustbgpd_wire::BgpRole::Peer
                    | rustbgpd_wire::BgpRole::RouteServerClient
            )
        ) {
            gate(
                &mut explain.gates,
                "otc",
                "otc",
                Pass,
                "route carries no Only-To-Customer attribute that blocks this egress role"
                    .to_string(),
            );
        } else {
            gate(
                &mut explain.gates,
                "otc",
                "otc",
                NotApplicable,
                "RFC 9234 OTC egress suppression does not apply to this local role".to_string(),
            );
        }

        explain.decision = ExplainDecision::Advertise;
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

        // Advertised-state diff. An Add-Path-send peer's staged set is
        // the ranked multipath top-N — the single-best (path_id 0) diff
        // below would not describe it, so the diff is skipped with a
        // pointer at the per-candidate view.
        if source.is_some() {
            let existing = rib_out.and_then(|out| out.get(&prefix, explain.path_id));
            let in_sync =
                existing.is_some_and(|existing| routes_equal(existing, &post_policy_candidate));
            explain.already_advertised = in_sync;
            if in_sync {
                gate(
                    &mut explain.gates,
                    "adj_rib_out",
                    "already_advertised",
                    Pass,
                    "identical source path already occupies this outbound rank — Adj-RIB-Out in \
                     sync; remote acceptance is not observable"
                        .to_string(),
                );
            } else if existing.is_some() {
                gate(
                    &mut explain.gates,
                    "adj_rib_out",
                    "staged_announce",
                    Pass,
                    "selected source differs from the route at this outbound rank — would re-announce"
                        .to_string(),
                );
            } else {
                gate(
                    &mut explain.gates,
                    "adj_rib_out",
                    "staged_announce",
                    Pass,
                    "selected source is not present at this outbound rank — would announce"
                        .to_string(),
                );
            }
        } else if add_path_send_max > 0 {
            gate(
                &mut explain.gates,
                "adj_rib_out",
                "add_path_send",
                NotApplicable,
                format!(
                    "peer negotiated Add-Path send (up to {add_path_send_max} paths); \
                     per-candidate advertisement is shown by ExplainBestPath / \
                     `rbgp rib best <prefix> --explain --explain-peer`"
                ),
            );
        } else {
            // Same modification application + equality the live tail
            // uses (`ExportMemo::apply` + `routes_equal`).
            let mut memo = super::ExportMemo::default();
            let (mut modified, _nh_action) = memo.apply(best, &result.modifications);
            modified.path_id = 0;
            let existing = rib_out.and_then(|out| out.get(&prefix, 0));
            let in_sync = existing.is_some_and(|existing| routes_equal(existing, &modified));
            explain.already_advertised = in_sync;
            if in_sync {
                gate(
                    &mut explain.gates,
                    "adj_rib_out",
                    "already_advertised",
                    Pass,
                    "identical route already advertised — Adj-RIB-Out in sync, no \
                     re-announcement; remote acceptance is not observable"
                        .to_string(),
                );
            } else if existing.is_some() {
                gate(
                    &mut explain.gates,
                    "adj_rib_out",
                    "staged_announce",
                    Pass,
                    "staged route differs from the advertised state — would re-announce"
                        .to_string(),
                );
            } else {
                gate(
                    &mut explain.gates,
                    "adj_rib_out",
                    "staged_announce",
                    Pass,
                    "prefix not yet advertised to this peer — would announce".to_string(),
                );
            }
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
            // The withdraw fast path skips prefixes whose best provably
            // survived (only candidates were removed).
            let changed = self.recompute_best_after_withdraw(&affected);
            self.pending_distribute_changed.extend(changed);
            self.pending_distribute_affected.extend(affected);
            self.gc_attr_intern();
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
                self.attr_intern.intern(&mut route.attributes);
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
            // Every inserted prefix registers in the announcing-peers
            // reverse index BEFORE recompute — the index must never
            // under-count (see the `UnicastPrefixPeers` contract).
            for prefix in &affected {
                self.register_unicast_announcer(peer, *prefix);
            }
            // Recompute Loc-RIB now — best-path, route events, and
            // partial-progress queries stay live mid-batch — but accumulate
            // the distribution and flush it once when the batch drains, so a
            // multi-chunk flood coalesces into one outbound pass per peer.
            // The announce fast path skips prefixes where every candidate
            // of this peer provably loses to the current best.
            let changed = self.recompute_best_after_announce(peer, &affected);
            self.pending_distribute_changed.extend(changed);
            self.pending_distribute_affected.extend(affected);
            if any_replaced {
                self.attr_intern.gc();
            }
            self.sync_attr_intern_gauge();
        }
    }

    pub(in crate::manager) fn handle_inject_route(
        &mut self,
        route: crate::route::Route,
        reply: tokio::sync::oneshot::Sender<Result<(), RibCommandError>>,
    ) {
        let prefix = route.prefix;
        let mut route = route;
        self.attr_intern.intern(&mut route.attributes);
        let rib = self
            .ribs
            .entry(LOCAL_PEER)
            .or_insert_with(|| AdjRibIn::new(LOCAL_PEER));
        let replaced = rib.insert(route);
        debug!(%prefix, "injected local route");
        let rib_len = rib.len();
        self.register_unicast_announcer(LOCAL_PEER, prefix);
        self.metrics
            .set_rib_prefixes(&LOCAL_PEER.to_string(), "all", gauge_val(rib_len));

        let mut affected = HashSet::new();
        affected.insert(prefix);
        let changed = self.recompute_best(&affected);
        self.distribute_changes(&changed, &affected);
        if replaced {
            self.attr_intern.gc();
        }
        self.sync_attr_intern_gauge();

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
            self.gc_attr_intern();
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
    ///
    /// `stage_path_id_zero` is the RFC 7947 §2.3.2 per-client best-path
    /// mode (`send_max = 1`): the one permitted candidate is staged at
    /// `path_id 0` instead of rank 1, so Adj-RIB-Out, BMP RIB-Out, and
    /// `ListAdvertisedRoutes` present the ordinary single-best shape
    /// (the wire is already path-id-free — Add-Path send was not
    /// negotiated for this family).
    #[expect(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        clippy::fn_params_excessive_bools,
        reason = "multipath export keeps peer, policy, and Adj-RIB-Out diff state together; the bools are independent per-target mode/state flags threaded from the caller's ladder"
    )]
    pub(in crate::manager) fn distribute_multipath_prefix(
        ribs: &HashMap<IpAddr, AdjRibIn>,
        prefix_peers: &UnicastPrefixPeers,
        rib_out: &AdjRibOut,
        peer_is_rr_client: &HashMap<IpAddr, bool>,
        prefix: &Prefix,
        target_peer: IpAddr,
        target_peer_asn: Option<u32>,
        target_peer_group: Option<&str>,
        send_max: u32,
        stage_path_id_zero: bool,
        target_is_ebgp: bool,
        interpret_rfc1997: bool,
        rs_control_asn: Option<u32>,
        target_is_rr_client: bool,
        cluster_id: Option<Ipv4Addr>,
        sendable: Option<&Vec<(Afi, Safi)>>,
        llgr: Option<&Vec<(Afi, Safi)>>,
        export_pol: Option<&PolicyChain>,
        orf_filter: Option<&crate::orf::OrfFilterSet>,
        orr: Option<(&crate::orr::OrrTopology, &crate::orr::SpfResult)>,
        memo: &mut super::ExportMemo,
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
            for path_id in rib_out.path_ids_for_prefix(prefix) {
                withdraw.push((*prefix, path_id));
            }
            return;
        }

        // ORF check (RFC 5291): filters the prefix, not individual Add-Path
        // path-ids — gate the whole prefix once, before collecting candidates.
        if orf_filter.is_some_and(|f| !f.permits(prefix)) {
            for path_id in rib_out.path_ids_for_prefix(prefix) {
                withdraw.push((*prefix, path_id));
            }
            return;
        }

        // Collect all candidates across the announcing peers' Adj-RIB-Ins
        // (reverse-index probe, not an all-peers scan) — the collector is
        // shared with the per-client-best explain arm so explain walks
        // exactly this set.
        let mut candidates: Vec<&crate::route::Route> = multipath_candidates(
            ribs,
            prefix_peers,
            peer_is_rr_client,
            prefix,
            target_peer,
            target_is_ebgp,
            interpret_rfc1997,
            rs_control_asn.zip(target_peer_asn),
            target_is_rr_client,
            cluster_id,
            family,
            llgr,
        )
        .collect();

        // Rank by best-path preference (best first). A target bound to a
        // resolved ORR vantage ranks by the vantage's interior cost to each
        // NEXT_HOP first (RFC 9107 §3.1) — comparator swap only. For actual
        // finite Add-Path with a small ceiling and a large candidate set,
        // partition out and sort only a 2N window. Export policy is evaluated
        // lazily below; if denials exhaust that window, the remaining tail is
        // sorted before evaluation resumes.
        let mut compare = |a: &&crate::route::Route, b: &&crate::route::Route| match orr {
            Some((topology, spf)) => best_path_cmp_orr(
                a,
                b,
                spf.cost_to(topology, a.next_hop),
                spf.cost_to(topology, b.next_hop),
            ),
            None => best_path_cmp(a, b),
        };
        let bounded = !stage_path_id_zero && (1..=4).contains(&send_max) && candidates.len() >= 64;
        let mut ordered_len = candidates.len();
        if bounded {
            ordered_len = (send_max as usize) * 2;
            let (window, _, _) = candidates.select_nth_unstable_by(ordered_len, &mut compare);
            window.sort_by(&mut compare);
            #[cfg(any(test, feature = "bench-internals"))]
            record_add_path_selection(|stats| stats.bounded_dispatches += 1);
        } else {
            candidates.sort_by(&mut compare);
            #[cfg(any(test, feature = "bench-internals"))]
            record_add_path_selection(|stats| stats.full_sort_dispatches += 1);
        }

        // Walk candidates, evaluate export policy, assign path_ids 1..N
        let needs_as_path_string = export_pol.is_some_and(PolicyChain::requires_as_path_string);
        let mut next_rank: u32 = 1;
        let limit = if send_max == u32::MAX {
            usize::MAX
        } else {
            send_max as usize
        };
        let mut candidate_index = 0;
        while candidate_index < candidates.len() {
            if (next_rank as usize) > limit {
                break;
            }
            if candidate_index == ordered_len {
                debug_assert!(bounded, "only bounded selection leaves an unsorted tail");
                candidates[ordered_len..].sort_by(&mut compare);
                ordered_len = candidates.len();
                #[cfg(any(test, feature = "bench-internals"))]
                record_add_path_selection(|stats| stats.sorted_tail_fallbacks += 1);
            }
            let candidate = candidates[candidate_index];
            candidate_index += 1;

            // Export policy check per-candidate
            let aspath_str = needs_as_path_string.then(|| memo.aspath_str(candidate));
            let aspath_len = candidate.as_path().map_or(0, rustbgpd_wire::AsPath::len);
            let origin_asn = candidate
                .as_path()
                .and_then(rustbgpd_wire::AsPath::origin_asn);
            let ctx = RouteContext {
                prefix: Some(*prefix),
                next_hop: Some(candidate.next_hop),
                extended_communities: candidate.extended_communities(),
                communities: candidate.communities(),
                large_communities: candidate.large_communities(),
                as_path_str: aspath_str.as_deref().unwrap_or(""),
                as_path: candidate.as_path(),
                as_path_len: aspath_len,
                origin_asn,
                validation_state: candidate.validation_state,
                aspa_state: candidate.aspa_state,
                peer_address: Some(target_peer),
                peer_asn: target_peer_asn,
                peer_group: target_peer_group,
                route_type: Some(route_type(candidate.origin_type)),
                family: Some(unicast_route_family(prefix)),
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

            // Apply export modifications — the pass-scoped memo shares one
            // post-modification attribute Arc across every (route, peer)
            // with the same source attrs and equal modifications.
            let (mut modified, nh_action) = memo.apply(candidate, &result.modifications);
            if super::no_advertise_export_suppressed(modified.communities()) {
                // Export policy added NO_ADVERTISE: the route is suppressed
                // by policy, so surface it through the same policy-filtered
                // accounting as the deny arm above (export explain already
                // covers this seam; live observability must too).
                policy_filtered.push(PolicyFilteredRouteKey {
                    target_peer,
                    source_peer: candidate.peer,
                    prefix: *prefix,
                    path_id: candidate.path_id,
                });
                continue;
            }
            // RFC 7947 §2.3.2 outbound actions per staged candidate —
            // same prepend + control-community scrub as the single-best
            // body, before the Adj-RIB-Out diff below.
            if let (Some(rs_asn), Some(peer_asn)) = (rs_control_asn, target_peer_asn) {
                let prepend = super::rs_control::rs_control_prepend_count(
                    candidate.large_communities(),
                    rs_asn,
                    peer_asn,
                );
                super::rs_control::apply_rs_control_egress(&mut modified, rs_asn, prepend);
            }
            modified.path_id = if stage_path_id_zero { 0 } else { next_rank };

            // Only announce if different from what's already in AdjRibOut.
            // `force` mode bypasses the equality check — see
            // `distribute_single_best_prefix` for the GShut rationale.
            let changed = force
                || rib_out
                    .get(prefix, modified.path_id)
                    .is_none_or(|existing| !routes_equal(existing, &modified));
            if changed {
                nh_override_flags.push(nh_action);
                announce.push(modified);
            }

            next_rank += 1;
        }

        if stage_path_id_zero {
            // Per-client best: at most one route lives at path_id 0.
            // Withdraw any non-zero residue (e.g. a previous Add-Path
            // session's ranks), and 0 itself when no candidate was
            // permitted — an implicit replace otherwise (no spurious
            // withdraw+announce pair when the filtered best flips).
            let staged_winner = next_rank > 1;
            for path_id in rib_out.path_ids_for_prefix(prefix) {
                if path_id != 0 || !staged_winner {
                    withdraw.push((*prefix, path_id));
                }
            }
        } else {
            // Withdraw any previously advertised path_ids beyond the new set
            for path_id in rib_out.path_ids_for_prefix(prefix) {
                if path_id >= next_rank {
                    withdraw.push((*prefix, path_id));
                }
            }
        }
    }

    /// Single-best export tail for one prefix. `target` selects the
    /// consumer: a concrete peer (per-peer path) or an update group
    /// (shared staging with `rib_out` = the group table and split
    /// horizon lifted out to member-emit time). ONE body serves both —
    /// the per-peer path is the group path's correctness oracle
    /// (design risk 1: parameterized, never copied).
    #[expect(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        clippy::fn_params_excessive_bools,
        reason = "single-best export keeps target, policy, and Adj-RIB-Out diff state together"
    )]
    pub(in crate::manager) fn distribute_single_best_prefix(
        loc_rib: &LocRib,
        rib_out: &AdjRibOut,
        peer_is_rr_client: &HashMap<IpAddr, bool>,
        prefix: &Prefix,
        target: &mut super::ExportTarget<'_>,
        target_is_ebgp: bool,
        interpret_rfc1997: bool,
        rs_control_asn: Option<u32>,
        target_is_rr_client: bool,
        cluster_id: Option<Ipv4Addr>,
        sendable: Option<&Vec<(Afi, Safi)>>,
        llgr: Option<&Vec<(Afi, Safi)>>,
        export_pol: Option<&PolicyChain>,
        orf_filter: Option<&crate::orf::OrfFilterSet>,
        memo: &mut super::ExportMemo,
        announce: &mut Vec<crate::route::Route>,
        withdraw: &mut Vec<(Prefix, u32)>,
        nh_override_flags: &mut Vec<Option<rustbgpd_policy::NextHopAction>>,
        policy_filtered: &mut Vec<PolicyFilteredRouteKey>,
        force: bool,
    ) {
        use crate::update::ExportGateVerdict::{NotApplicable, Pass, Stop};

        let existing_path_ids = rib_out.path_ids_for_prefix(prefix);

        let Some(best) = loc_rib.get(prefix) else {
            target.gate("best_route", "no_best_route", Stop, || {
                "no best route exists for this prefix".to_string()
            });
            for &path_id in &existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        };
        if let Some(trace) = target.trace() {
            trace.best_peer = Some(best.peer);
            trace.best_route_type = Some(route_type(best.origin_type));
            trace.push(
                "best_route",
                route_type_label(route_type(best.origin_type)),
                crate::update::ExportGateVerdict::Pass,
                format!(
                    "{} (Loc-RIB best from {})",
                    route_type_message(route_type(best.origin_type)),
                    best.peer
                ),
            );
        }

        // Split horizon: don't send route back to its source. Group
        // staging has no single target — the source-flip matrix applies
        // this per member at emit time.
        if target.split_horizon_peer() == Some(best.peer) {
            target.gate("split_horizon", "ibgp_split_horizon", Stop, || {
                "route is suppressed by split horizon because it originated from the target peer"
                    .to_string()
            });
            for &path_id in &existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        }
        target.gate("split_horizon", "split_horizon", Pass, || {
            "route did not originate from the target peer".to_string()
        });

        // iBGP split-horizon / RFC 4456 reflection rules
        if should_suppress_ibgp_inner(
            best,
            target_is_ebgp,
            target_is_rr_client,
            cluster_id,
            peer_is_rr_client,
        ) {
            if let Some(trace) = target.trace() {
                let (code, detail) = rr_suppression_reason(
                    best,
                    target_is_ebgp,
                    target_is_rr_client,
                    cluster_id,
                    peer_is_rr_client,
                );
                trace.push("rr_reflection", code, Stop, detail.to_string());
            }
            for &path_id in &existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        }
        target.gate("rr_reflection", "rr_reflection", Pass, || {
            "iBGP split-horizon / RFC 4456 reflection rules permit this route".to_string()
        });

        // Sendable family check
        let family = prefix_family(prefix);
        if !sendable.is_some_and(|f| f.contains(&family)) {
            target.gate("family", "family_not_sendable", Stop, || {
                format!("peer cannot receive {} routes", family_label(family))
            });
            for &path_id in &existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        }
        target.gate("family", "family", Pass, || {
            format!("peer negotiated {}", family_label(family))
        });

        // RFC 9494 §4.4: LLGR-stale best toward a non-LLGR eBGP peer is
        // suppressed (withdraw-if-present). See `llgr_stale_export_suppressed`.
        if super::llgr_stale_export_suppressed(
            best.is_llgr_stale,
            best.communities(),
            family,
            target_is_ebgp,
            llgr,
        ) {
            target.gate("llgr", "llgr_stale_suppressed", Stop, || {
                "LLGR-stale route suppressed toward an eBGP peer that did not advertise the \
                 Long-Lived Graceful Restart capability for this family (RFC 9494 §4.4)"
                    .to_string()
            });
            for &path_id in &existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        }
        target.gate("llgr", "llgr", Pass, || {
            if best.is_llgr_stale
                || best
                    .communities()
                    .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)
            {
                "LLGR-stale route permitted (peer advertised the LLGR capability or is iBGP)"
                    .to_string()
            } else {
                "route is not LLGR-stale".to_string()
            }
        });

        // Outbound Route Filter check (RFC 5291): a peer-pushed prefix filter
        // applied *before* export policy. ORF denial is a silent withdraw —
        // not a policy denial — so it is deliberately not recorded in the
        // `policy_filtered` set or the export-policy counters.
        if let Some(filter) = orf_filter {
            if !filter.permits(prefix) {
                target.gate("orf", "orf_filtered", Stop, || {
                    "peer-pushed Outbound Route Filter (RFC 5291) does not permit this prefix"
                        .to_string()
                });
                for &path_id in &existing_path_ids {
                    withdraw.push((*prefix, path_id));
                }
                return;
            }
            target.gate("orf", "orf", Pass, || {
                "peer-pushed Outbound Route Filter (RFC 5291) permits this prefix".to_string()
            });
        } else {
            target.gate("orf", "orf", NotApplicable, || {
                "peer installed no Outbound Route Filter".to_string()
            });
        }

        // RFC 1997: NO_ADVERTISE is a pre-policy export restriction.
        // The group and private single-best paths share this body, so
        // both withdraw existing state before a policy can remove it.
        if super::no_advertise_export_suppressed(best.communities()) {
            target.gate("no_advertise", "no_advertise_suppressed", Stop, || {
                "route carries NO_ADVERTISE and RFC 1997 forbids advertisement to any BGP \
                     peer"
                    .to_string()
            });
            for &path_id in &existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        }
        // RFC 1997: NO_EXPORT/NO_EXPORT_SUBCONFED are the same pre-policy
        // source-route restriction toward an eBGP target in honor mode.
        // Deliberately no post-policy twin — policy-added NO_EXPORT is
        // delivered (see `no_export_export_suppressed`).
        if super::no_export_export_suppressed(best.communities(), target_is_ebgp, interpret_rfc1997)
        {
            target.gate("no_export", "no_export_suppressed", Stop, || {
                "route carries NO_EXPORT (or NO_EXPORT_SUBCONFED) and RFC 1997 forbids \
                     advertisement to an eBGP peer"
                    .to_string()
            });
            for &path_id in &existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        }
        // RFC 7947 §2.3.2: route-server control communities on the SOURCE
        // route (pre-policy, like the RFC 1997 gates above) decide
        // per-target announcement. Active only for sessions with
        // `rs_control_communities` (the RS-side local ASN arrives via
        // `SetPeerRsControl`); group staging passes `None` here and
        // defers to the member-emit seams, which make the same
        // source-based decision from the captured source attributes.
        // Every other session keeps full transparency.
        if let (Some(rs_asn), (_, Some(peer_asn), _)) = (rs_control_asn, target.ctx_peer())
            && super::rs_control::rs_control_export_suppressed(
                best.communities(),
                best.large_communities(),
                rs_asn,
                peer_asn,
            )
        {
            target.gate("rs_control", "rs_control_suppressed", Stop, || {
                "route carries an RFC 7947 route-server control community that forbids \
                     announcing it toward this peer's ASN"
                    .to_string()
            });
            for &path_id in &existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        }
        // Export policy check. Group staging passes no peer-context
        // fields: a chain that reads them disqualifies its peers from
        // grouping (`requires_peer_context`), so the verdict here is
        // target-independent by construction.
        let aspath_str = export_pol
            .is_some_and(PolicyChain::requires_as_path_string)
            .then(|| memo.aspath_str(best));
        let aspath_len = best.as_path().map_or(0, rustbgpd_wire::AsPath::len);
        let origin_asn = best.as_path().and_then(rustbgpd_wire::AsPath::origin_asn);
        let (peer_address, peer_asn, peer_group) = target.ctx_peer();
        let ctx = RouteContext {
            prefix: Some(*prefix),
            next_hop: Some(best.next_hop),
            extended_communities: best.extended_communities(),
            communities: best.communities(),
            large_communities: best.large_communities(),
            as_path_str: aspath_str.as_deref().unwrap_or(""),
            as_path: best.as_path(),
            as_path_len: aspath_len,
            origin_asn,
            validation_state: best.validation_state,
            aspa_state: best.aspa_state,
            peer_address,
            peer_asn,
            peer_group,
            route_type: Some(route_type(best.origin_type)),
            family: Some(unicast_route_family(prefix)),
            evpn_route_type: None,
            local_pref: best.local_pref_attr(),
            med: best.med_attr(),
        };
        let (result, evaluation) = target.evaluate_export_chain(export_pol, &ctx);
        target.record_eval(&evaluation, best.peer);
        if let Some(trace) = target.trace() {
            // Enrich the deciding chain member with the rpol term name
            // via the statement trace (explain-only re-walk, pinned to
            // agree with the evaluation by the policy crate's agreement
            // tests). TOML members carry no term name.
            trace.policy_label = export_pol.map(|chain| {
                policy_label_with_term(Some(chain), &ctx, evaluation.matched_policy.as_deref())
            });
        }
        if result.action != PolicyAction::Permit {
            if let Some(trace) = target.trace() {
                let label = trace.policy_label.clone().unwrap_or_default();
                let (code, message) =
                    export_deny_attribution(evaluation.matched_policy.as_deref(), &label);
                trace.push(
                    "export_policy",
                    code,
                    crate::update::ExportGateVerdict::Stop,
                    message,
                );
            }
            policy_filtered.push(PolicyFilteredRouteKey {
                target_peer: target.policy_filtered_target(),
                source_peer: best.peer,
                prefix: *prefix,
                path_id: best.path_id,
            });
            for &path_id in &existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        }
        if let Some(trace) = target.trace() {
            // Record staged modifications only after the Permit above — a
            // denied route carries no modifications (mirrors the
            // per-client-best arm, which sets `explain.modifications`
            // after its own deny early-return).
            trace.modifications = result.modifications.clone();
            match trace.policy_label.clone() {
                Some(label) => trace.push(
                    "export_policy",
                    "policy_permitted",
                    crate::update::ExportGateVerdict::Pass,
                    format!("export policy {label:?} permitted this route"),
                ),
                None => trace.push(
                    "export_policy",
                    "export_policy",
                    crate::update::ExportGateVerdict::NotApplicable,
                    "no export policy configured (default permit)".to_string(),
                ),
            }
        }

        // Apply export modifications to a clone. The pass-scoped memo
        // shares one post-modification attribute Arc across every
        // (route, peer) with the same source attribute set and equal
        // modifications; no-modification exports keep sharing the
        // source Arc as before.
        let (mut modified, nh_action) = memo.apply(best, &result.modifications);
        modified.path_id = 0;

        // Export policy may add NO_ADVERTISE to an otherwise eligible
        // route. Enforce the resulting RFC 1997 state before committing
        // grouped or private Adj-RIB-Out state.
        if super::no_advertise_export_suppressed(modified.communities()) {
            target.gate(
                "no_advertise",
                "no_advertise_policy_suppressed",
                Stop,
                || {
                    "export policy produced a route carrying NO_ADVERTISE; RFC 1997 forbids \
                     advertisement to any BGP peer"
                        .to_string()
                },
            );
            // Policy-added NO_ADVERTISE is a policy suppression: surface it
            // through the same policy-filtered accounting as the deny arm
            // above, matching the multipath body.
            policy_filtered.push(PolicyFilteredRouteKey {
                target_peer: target.policy_filtered_target(),
                source_peer: best.peer,
                prefix: *prefix,
                path_id: best.path_id,
            });
            for &path_id in &existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        }

        // RFC 7947 §2.3.2 outbound actions for an enabled target: prepend
        // the announcing client's ASN toward this peer (`RS:101|102|103:*`,
        // decided on the source route like the suppression gate) and scrub
        // the control communities from the wire-bound attribute set
        // (post-policy, so policy-added control communities are scrubbed
        // too). Runs before the Adj-RIB-Out diff so advertised state and
        // re-announcement suppression see the final form.
        if let (Some(rs_asn), (_, Some(peer_asn), _)) = (rs_control_asn, target.ctx_peer()) {
            let prepend = super::rs_control::rs_control_prepend_count(
                best.large_communities(),
                rs_asn,
                peer_asn,
            );
            super::rs_control::apply_rs_control_egress(&mut modified, rs_asn, prepend);
        }

        // RFC 9234 §5 egress enforcement belongs before the advertised-state
        // diff. Group staging and explain carry their group-uniform/local
        // role here; concrete peer staging has a central pre-commit backstop
        // in `try_send_and_commit_outbound_update` covering every selection
        // shape (single-best, ORR, Add-Path, and per-client-best).
        if super::otc_egress_blocked(&modified, target.local_role()) {
            target.gate("otc", "otc_egress_blocked", Stop, || {
                "route already carries Only-To-Customer and RFC 9234 forbids propagation toward this Provider, Peer, or Route Server"
                    .to_string()
            });
            target.record_otc_blocked(modified);
            for &path_id in &existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        }
        if matches!(
            target.local_role(),
            Some(
                rustbgpd_wire::BgpRole::Customer
                    | rustbgpd_wire::BgpRole::Peer
                    | rustbgpd_wire::BgpRole::RouteServerClient
            )
        ) {
            target.gate("otc", "otc", Pass, || {
                "route carries no Only-To-Customer attribute that blocks this egress role"
                    .to_string()
            });
        } else {
            target.gate("otc", "otc", NotApplicable, || {
                "RFC 9234 OTC egress suppression does not apply to this local role".to_string()
            });
        }

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
        if let Some(trace) = target.trace() {
            trace.staged_next_hop = Some(match nh_action {
                Some(rustbgpd_policy::NextHopAction::Specific(addr)) => addr,
                _ => modified.next_hop,
            });
            trace.staged_path_id = modified.path_id;
            trace.suppressed_identical = !changed;
            if changed {
                trace.push(
                    "adj_rib_out",
                    "staged_announce",
                    crate::update::ExportGateVerdict::Pass,
                    if rib_out.get(prefix, 0).is_some() {
                        "staged route differs from the advertised state — would re-announce"
                            .to_string()
                    } else {
                        "prefix not yet advertised to this peer — would announce".to_string()
                    },
                );
            } else {
                trace.push(
                    "adj_rib_out",
                    "already_advertised",
                    crate::update::ExportGateVerdict::Pass,
                    "identical route already advertised — Adj-RIB-Out in sync, no \
                     re-announcement; remote acceptance is not observable"
                        .to_string(),
                );
            }
        }
        if changed {
            nh_override_flags.push(nh_action);
            announce.push(modified);
        }

        // Clean up any stale multi-path entries if this prefix was previously
        // advertised via Add-Path and is now single-best.
        for &path_id in &existing_path_ids {
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
        clippy::fn_params_excessive_bools,
        reason = "ORR export keeps peer, policy, and Adj-RIB-Out diff state together"
    )]
    pub(in crate::manager) fn distribute_orr_best_prefix(
        ribs: &HashMap<IpAddr, AdjRibIn>,
        prefix_peers: &UnicastPrefixPeers,
        rib_out: &AdjRibOut,
        peer_is_rr_client: &HashMap<IpAddr, bool>,
        orr_topology: &crate::orr::OrrTopology,
        orr_spf: &crate::orr::SpfResult,
        prefix: &Prefix,
        target_peer: IpAddr,
        target_peer_asn: Option<u32>,
        target_peer_group: Option<&str>,
        target_is_ebgp: bool,
        interpret_rfc1997: bool,
        target_is_rr_client: bool,
        cluster_id: Option<Ipv4Addr>,
        sendable: Option<&Vec<(Afi, Safi)>>,
        llgr: Option<&Vec<(Afi, Safi)>>,
        export_pol: Option<&PolicyChain>,
        orf_filter: Option<&crate::orf::OrfFilterSet>,
        memo: &mut super::ExportMemo,
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
            for &path_id in &existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        }

        // Outbound Route Filter check (RFC 5291): silent withdraw, not a
        // policy denial — see `distribute_single_best_prefix`.
        if orf_filter.is_some_and(|f| !f.permits(prefix)) {
            for &path_id in &existing_path_ids {
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
            prefix_peers,
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
            for &path_id in &existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        };

        // RFC 9494 §4.4: a per-vantage winner can only be LLGR-stale when
        // every surviving candidate is (stale ranks below fresh in the
        // comparator), so gating the winner suppresses exactly the
        // stale-only case toward a non-LLGR eBGP peer.
        if super::llgr_stale_export_suppressed(
            best.is_llgr_stale,
            best.communities(),
            family,
            target_is_ebgp,
            llgr,
        ) {
            for &path_id in &existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        }

        // RFC 1997: select the per-vantage winner first, then suppress
        // that winner before policy. ORR does not fall back to its
        // runner-up merely because the selected best is NO_ADVERTISE.
        if super::no_advertise_export_suppressed(best.communities()) {
            for &path_id in &existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        }
        // RFC 1997: NO_EXPORT winner toward an eBGP target in honor mode
        // — same winner-first placement, no runner-up fallback.
        if super::no_export_export_suppressed(best.communities(), target_is_ebgp, interpret_rfc1997)
        {
            for &path_id in &existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        }

        // Export policy check — same tail as `distribute_single_best_prefix`.
        let aspath_str = export_pol
            .is_some_and(PolicyChain::requires_as_path_string)
            .then(|| memo.aspath_str(best));
        let aspath_len = best.as_path().map_or(0, rustbgpd_wire::AsPath::len);
        let origin_asn = best.as_path().and_then(rustbgpd_wire::AsPath::origin_asn);
        let ctx = RouteContext {
            prefix: Some(*prefix),
            next_hop: Some(best.next_hop),
            extended_communities: best.extended_communities(),
            communities: best.communities(),
            large_communities: best.large_communities(),
            as_path_str: aspath_str.as_deref().unwrap_or(""),
            as_path: best.as_path(),
            as_path_len: aspath_len,
            origin_asn,
            validation_state: best.validation_state,
            aspa_state: best.aspa_state,
            peer_address: Some(target_peer),
            peer_asn: target_peer_asn,
            peer_group: target_peer_group,
            route_type: Some(route_type(best.origin_type)),
            family: Some(unicast_route_family(prefix)),
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
            for &path_id in &existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        }

        // Apply export modifications to a clone — the pass-scoped memo
        // shares one post-modification attribute Arc across every
        // (route, peer) with the same source attrs and equal
        // modifications. NOTE: this is NOT the per-(vantage, prefix)
        // winner memo the doc comment above rejects — the key here is
        // (source attribute identity, modifications value), which is
        // independent of which candidate won.
        let (mut modified, nh_action) = memo.apply(best, &result.modifications);
        modified.path_id = 0;

        if super::no_advertise_export_suppressed(modified.communities()) {
            // Policy-added NO_ADVERTISE is a policy suppression: record the
            // policy-filtered entry, matching the multipath and single-best
            // bodies.
            policy_filtered.push(PolicyFilteredRouteKey {
                target_peer,
                source_peer: best.peer,
                prefix: *prefix,
                path_id: best.path_id,
            });
            for &path_id in &existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        }

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
        for &path_id in &existing_path_ids {
            if path_id != 0 {
                withdraw.push((*prefix, path_id));
            }
        }
    }
}
