use super::{
    AdjRibIn, AdjRibOut, Afi, HashMap, HashSet, IpAddr, Ipv4Addr, LocRib, PolicyChain, RibManager,
    RouteContext, Safi, gauge_val, route_type, should_suppress_ibgp_inner, vpn_route_family,
    vpn_routes_equal, warn,
};
use crate::loc_rib::vpn_tiebreak_orr;
use crate::route::{VpnRibRoute, VpnRibRouteKey};
use rustbgpd_wire::{VpnAddressFamily, VpnRouteKey};

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

/// The wire AFI/SAFI pair for a VPN RD+prefix identity.
fn vpn_afi_safi(key: &VpnRouteKey) -> (Afi, Safi) {
    let afi = match key.prefix.family() {
        VpnAddressFamily::V4 => Afi::Ipv4,
        VpnAddressFamily::V6 => Afi::Ipv6,
    };
    (afi, Safi::MplsVpn)
}

impl RibManager {
    /// Whether Add-Path send is negotiated with `peer` for any VPN family
    /// (SAFI 128) with a non-zero configured `send_max`.
    pub(in crate::manager) fn peer_vpn_add_path_send(&self, peer: IpAddr) -> bool {
        self.peer_add_path_send_max.get(&peer).copied().unwrap_or(0) > 0
            && self
                .peer_add_path_send_families
                .get(&peer)
                .is_some_and(|families| families.iter().any(|(_, safi)| *safi == Safi::MplsVpn))
    }

    /// Stage VPNv4/VPNv6 announces and withdrawals for a set of affected
    /// RD+prefix identities.
    ///
    /// ADR-0077 §6 guardrail: the next-hop, MPLS label stack, and Route
    /// Distinguisher pass through reflection unchanged — the staged route
    /// carries the original `VpnNlri` verbatim and transport never rewrites
    /// the VPN next-hop. Export policy matches on the RD-scoped inner prefix
    /// (honest, unlike the prefixless BGP-LS placeholder) plus communities,
    /// large communities, `AS_PATH`, peer, and route type.
    ///
    /// `target` selects the consumer (the unicast `ExportTarget` pattern —
    /// ONE body, never copied; the per-peer path stays the group path's
    /// correctness oracle): a concrete peer, or a whole update group with
    /// the group table as `rib_out`, split horizon lifted to member emit,
    /// peer-context `RouteContext` fields `None`, and evaluations
    /// accumulated for per-member counter replay. Group targets never
    /// carry `rtc_filter` (the RFC 4684 filter `Φ_m` is per-member and
    /// applied at emit by the RT-pass matrix), `orr_ctx`, or Add-Path —
    /// the latter two disqualify from grouping.
    ///
    /// When the target negotiated Add-Path send for the key's family (RFC
    /// 7911; RFC 9107 requires it between RRs), up to `add_path_send_max`
    /// candidates per key are ranked — with the ORR vantage comparator when
    /// a vantage is resolved — and staged with outbound path IDs `1..=N`.
    /// Otherwise the single best is staged with `path_id = 0`.
    #[expect(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "VPN staging mirrors unicast multipath/single-best distribution context for RR/export parity"
    )]
    pub(in crate::manager) fn stage_vpn_routes(
        loc_rib: &LocRib,
        ribs: &HashMap<IpAddr, AdjRibIn>,
        rib_out: &AdjRibOut,
        peer_is_rr_client: &HashMap<IpAddr, bool>,
        keys: &HashSet<VpnRouteKey>,
        target: &mut super::ExportTarget<'_>,
        target_is_ebgp: bool,
        target_is_rr_client: bool,
        cluster_id: Option<Ipv4Addr>,
        sendable: Option<&Vec<(Afi, Safi)>>,
        llgr: Option<&Vec<(Afi, Safi)>>,
        rtc_filter: Option<&crate::manager::RtcMembership>,
        orr_ctx: Option<(&crate::orr::OrrTopology, &crate::orr::SpfResult)>,
        add_path_send_max: u32,
        add_path_send_limits: Option<&HashMap<(Afi, Safi), u32>>,
        add_path_send_families: &[(Afi, Safi)],
        export_pol: Option<&PolicyChain>,
        vpn_announce: &mut Vec<VpnRibRoute>,
        vpn_withdraw: &mut Vec<VpnRibRouteKey>,
        force: bool,
    ) {
        let needs_as_path_string = export_pol.is_some_and(PolicyChain::requires_as_path_string);
        // `None` for group staging: split horizon is applied per member
        // at emit time by the VPN source-flip matrix.
        let split_horizon_peer = target.split_horizon_peer();
        for key in keys {
            let family = vpn_afi_safi(key);
            // Path IDs currently advertised for this identity — the diff
            // baseline for every withdraw decision below.
            let existing_path_ids = rib_out.vpn_path_ids_for_key(key);
            let withdraw_existing = |vpn_withdraw: &mut Vec<VpnRibRouteKey>, existing: &[u32]| {
                for &path_id in existing {
                    vpn_withdraw.push(VpnRibRouteKey {
                        nlri_key: *key,
                        path_id,
                    });
                }
            };

            if !sendable.is_some_and(|f| f.contains(&family)) {
                target.gate(
                    "family",
                    "family_not_sendable",
                    crate::update::ExportGateVerdict::Stop,
                    || format!("peer cannot receive {} routes", super::family_label(family)),
                );
                withdraw_existing(vpn_withdraw, existing_path_ids);
                continue;
            }
            target.gate(
                "family",
                "family",
                crate::update::ExportGateVerdict::Pass,
                || format!("peer negotiated {}", super::family_label(family)),
            );

            let key_send_max = if add_path_send_families.contains(&family) {
                add_path_send_limits
                    .and_then(|limits| limits.get(&family).copied())
                    .unwrap_or(add_path_send_max)
            } else {
                0
            };

            if key_send_max > 0 {
                // ponytail: the multipath arm stages a ranked top-N and is
                // not gate-traced per candidate — an explain dry run gets
                // this summary note instead of a per-rank ladder.
                target.gate(
                    "add_path",
                    "add_path_send",
                    crate::update::ExportGateVerdict::NotApplicable,
                    || {
                        format!(
                            "peer negotiated Add-Path send for this family (up to \
                             {key_send_max} paths); the gate ladder explains single-best \
                             export only"
                        )
                    },
                );
                // Multi-path: collect the per-target candidate set (every
                // Adj-RIB-In entry for the identity, any received path ID,
                // that survives split horizon and RFC 4456 reflection),
                // rank it, and stage the top N with path IDs 1..=N.
                let mut candidates: Vec<&VpnRibRoute> = ribs
                    .values()
                    .flat_map(|rib| rib.iter_vpn_for_nlri(key))
                    .filter(|candidate| {
                        split_horizon_peer != Some(candidate.peer)
                            && !should_suppress_ibgp_inner(
                                &vpn_suppression_probe(candidate),
                                target_is_ebgp,
                                target_is_rr_client,
                                cluster_id,
                                peer_is_rr_client,
                            )
                    })
                    .collect();
                // Rank by the VPN best-path chain; an RFC 9107 ORR peer with
                // a resolved vantage ranks by the vantage's interior cost to
                // each candidate's next-hop (comparator swap only).
                match orr_ctx {
                    Some((orr_topology, orr_spf)) => candidates.sort_by(|a, b| {
                        vpn_tiebreak_orr(
                            a,
                            b,
                            orr_spf.cost_to(orr_topology, a.next_hop),
                            orr_spf.cost_to(orr_topology, b.next_hop),
                        )
                    }),
                    None => candidates.sort_by(|a, b| crate::loc_rib::vpn_tiebreak(a, b)),
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

                    // RFC 4684 outbound gate, per candidate — the route
                    // actually being advertised must fall inside the peer's
                    // RT membership (consistent with the single-best gate).
                    if let Some(membership) = rtc_filter
                        && !membership.matches_any(candidate.extended_communities())
                    {
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
                    let (peer_address, peer_asn, peer_group) = target.ctx_peer();
                    let ctx = RouteContext {
                        prefix: Some(candidate.inner_prefix()),
                        next_hop: Some(candidate.next_hop),
                        extended_communities: candidate.extended_communities(),
                        communities: candidate.communities(),
                        large_communities: candidate.large_communities(),
                        as_path_str: &aspath_str,
                        as_path: candidate.as_path(),
                        as_path_len: aspath_len,
                        origin_asn,
                        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
                        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
                        peer_address,
                        peer_asn,
                        peer_group,
                        route_type: Some(route_type(candidate.origin_type)),
                        family: Some(vpn_route_family(key)),
                        evpn_route_type: None,
                        local_pref: candidate.local_pref_attr(),
                        med: candidate.med_attr(),
                    };
                    let (result, evaluation) = target.evaluate_export_chain(export_pol, &ctx);
                    target.record_eval(&evaluation, candidate.peer);
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

                    let out_key = VpnRibRouteKey {
                        nlri_key: *key,
                        path_id: next_rank,
                    };
                    if force
                        || rib_out
                            .get_vpn(&out_key)
                            .is_none_or(|existing| !vpn_routes_equal(existing, &modified))
                    {
                        vpn_announce.push(modified);
                    }
                    next_rank += 1;
                }

                // Withdraw previously advertised path IDs outside the new
                // 1..next_rank set (including a stale single-best 0 entry).
                for &path_id in existing_path_ids {
                    if path_id == 0 || path_id >= next_rank {
                        vpn_withdraw.push(VpnRibRouteKey {
                            nlri_key: *key,
                            path_id,
                        });
                    }
                }
                continue;
            }

            // Single-best. An RFC 9107 ORR peer with a resolved vantage
            // does NOT take the Loc-RIB best: the per-target candidate
            // set (every Adj-RIB-In entry for the key that survives split
            // horizon and RFC 4456 reflection — the unicast
            // `orr_candidates` filter adapted to `VpnRibRoute`) is ranked
            // with the vantage's interior cost to each candidate's
            // next-hop. A plain peer keeps the Loc-RIB best, unchanged.
            let best = if let Some((orr_topology, orr_spf)) = orr_ctx {
                let winner = ribs
                    .values()
                    .flat_map(|rib| rib.iter_vpn_for_nlri(key))
                    .filter(|candidate| {
                        split_horizon_peer != Some(candidate.peer)
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
                    target.gate(
                        "best_route",
                        "no_orr_candidate",
                        crate::update::ExportGateVerdict::Stop,
                        || {
                            "no candidate for this identity survives split-horizon / \
                             reflection filtering for this ORR peer"
                                .to_string()
                        },
                    );
                    withdraw_existing(vpn_withdraw, existing_path_ids);
                    continue;
                };
                target.gate(
                    "best_route",
                    "orr_vantage_best",
                    crate::update::ExportGateVerdict::Pass,
                    || format!("per-vantage best from {}", winner.peer),
                );
                winner
            } else {
                let Some(best) = loc_rib.get_vpn(key) else {
                    target.gate(
                        "best_route",
                        "no_best_route",
                        crate::update::ExportGateVerdict::Stop,
                        || "no best route exists for this RD+prefix identity".to_string(),
                    );
                    withdraw_existing(vpn_withdraw, existing_path_ids);
                    continue;
                };
                best
            };
            if let (Some(trace), None) = (target.trace(), orr_ctx) {
                trace.push(
                    "best_route",
                    super::route_type_label(route_type(best.origin_type)),
                    crate::update::ExportGateVerdict::Pass,
                    format!(
                        "{} (Loc-RIB best from {})",
                        super::route_type_message(route_type(best.origin_type)),
                        best.peer
                    ),
                );
            }
            if let Some(trace) = target.trace() {
                trace.best_peer = Some(best.peer);
                trace.best_route_type = Some(route_type(best.origin_type));
            }

            // RFC 9494 §4.4: LLGR-stale toward a non-LLGR eBGP peer is
            // suppressed. See `llgr_stale_export_suppressed`.
            if super::llgr_stale_export_suppressed(
                best.is_llgr_stale,
                best.communities(),
                family,
                target_is_ebgp,
                llgr,
            ) {
                target.gate(
                    "llgr",
                    "llgr_stale_suppressed",
                    crate::update::ExportGateVerdict::Stop,
                    || {
                        "LLGR-stale route suppressed toward an eBGP peer that did not \
                         advertise the Long-Lived Graceful Restart capability for this \
                         family (RFC 9494 §4.4)"
                            .to_string()
                    },
                );
                withdraw_existing(vpn_withdraw, existing_path_ids);
                continue;
            }
            target.gate(
                "llgr",
                "llgr",
                crate::update::ExportGateVerdict::Pass,
                || "route is not suppressed by the RFC 9494 LLGR export restriction".to_string(),
            );

            // RFC 4684 outbound gate: a peer that negotiated RT-Constrain
            // only receives VPN routes whose Route Targets fall inside its
            // advertised membership (`None` = SAFI 132 not negotiated ⇒
            // unfiltered). Membership is per-peer, so the one gate covers
            // both VPNv4 and VPNv6 keys. Miss ⇒ withdraw-if-present,
            // exactly the sendable-family gate shape above. For an ORR
            // peer the gate applies to the vantage WINNER's extended
            // communities — the route actually being advertised — not the
            // Loc-RIB best's.
            if let Some(membership) = rtc_filter {
                if !membership.matches_any(best.extended_communities()) {
                    target.gate(
                        "rt_membership",
                        "rt_membership_miss",
                        crate::update::ExportGateVerdict::Stop,
                        || {
                            "no Route Target of this route falls inside the peer's \
                             advertised RT-Constrain membership (RFC 4684)"
                                .to_string()
                        },
                    );
                    withdraw_existing(vpn_withdraw, existing_path_ids);
                    continue;
                }
                target.gate(
                    "rt_membership",
                    "rt_membership",
                    crate::update::ExportGateVerdict::Pass,
                    || {
                        "a Route Target of this route falls inside the peer's advertised \
                         RT-Constrain membership (RFC 4684)"
                            .to_string()
                    },
                );
            } else {
                target.gate(
                    "rt_membership",
                    "rt_membership",
                    crate::update::ExportGateVerdict::NotApplicable,
                    || "peer did not negotiate RT-Constrain — VPN export is unfiltered".to_string(),
                );
            }

            // The two suppression checks below are no-ops for an ORR
            // winner (its candidate set is pre-filtered above); they
            // decide only for the Loc-RIB best of a plain peer. Group
            // staging has no single target — the VPN source-flip matrix
            // applies split horizon per member at emit time.
            if split_horizon_peer == Some(best.peer) {
                target.gate(
                    "split_horizon",
                    "ibgp_split_horizon",
                    crate::update::ExportGateVerdict::Stop,
                    || {
                        "route is suppressed by split horizon because it originated from \
                         the target peer"
                            .to_string()
                    },
                );
                withdraw_existing(vpn_withdraw, existing_path_ids);
                continue;
            }
            target.gate(
                "split_horizon",
                "split_horizon",
                crate::update::ExportGateVerdict::Pass,
                || "route did not originate from the target peer".to_string(),
            );

            if should_suppress_ibgp_inner(
                &vpn_suppression_probe(best),
                target_is_ebgp,
                target_is_rr_client,
                cluster_id,
                peer_is_rr_client,
            ) {
                if let Some(trace) = target.trace() {
                    let (code, detail) = super::rr_suppression_reason(
                        &vpn_suppression_probe(best),
                        target_is_ebgp,
                        target_is_rr_client,
                        cluster_id,
                        peer_is_rr_client,
                    );
                    trace.push(
                        "rr_reflection",
                        code,
                        crate::update::ExportGateVerdict::Stop,
                        detail.to_string(),
                    );
                }
                withdraw_existing(vpn_withdraw, existing_path_ids);
                continue;
            }
            target.gate(
                "rr_reflection",
                "rr_reflection",
                crate::update::ExportGateVerdict::Pass,
                || "iBGP split-horizon / RFC 4456 reflection rules permit this route".to_string(),
            );

            let aspath_str = if needs_as_path_string {
                best.as_path()
                    .map_or_else(String::new, rustbgpd_wire::AsPath::to_aspath_string)
            } else {
                String::new()
            };
            let aspath_len = best.as_path().map_or(0, rustbgpd_wire::AsPath::len);
            let origin_asn = best.as_path().and_then(rustbgpd_wire::AsPath::origin_asn);
            // Group staging passes no peer-context fields: a chain that
            // reads them disqualifies its peers from grouping, so the
            // verdict is target-independent by construction.
            let (peer_address, peer_asn, peer_group) = target.ctx_peer();
            let ctx = RouteContext {
                prefix: Some(best.inner_prefix()),
                next_hop: Some(best.next_hop),
                extended_communities: best.extended_communities(),
                communities: best.communities(),
                large_communities: best.large_communities(),
                as_path_str: &aspath_str,
                as_path: best.as_path(),
                as_path_len: aspath_len,
                origin_asn,
                validation_state: rustbgpd_wire::RpkiValidation::NotFound,
                aspa_state: rustbgpd_wire::AspaValidation::Unknown,
                peer_address,
                peer_asn,
                peer_group,
                route_type: Some(route_type(best.origin_type)),
                family: Some(vpn_route_family(key)),
                evpn_route_type: None,
                local_pref: best.local_pref_attr(),
                med: best.med_attr(),
            };
            let (result, evaluation) = target.evaluate_export_chain(export_pol, &ctx);
            target.record_eval(&evaluation, best.peer);
            if let Some(trace) = target.trace() {
                trace.policy_label = export_pol.map(|chain| {
                    super::policy_label_with_term(
                        Some(chain),
                        &ctx,
                        evaluation.matched_policy.as_deref(),
                    )
                });
            }
            if result.action != rustbgpd_policy::PolicyAction::Permit {
                if let Some(trace) = target.trace() {
                    let label = trace.policy_label.clone().unwrap_or_default();
                    trace.push(
                        "export_policy",
                        "policy_denied",
                        crate::update::ExportGateVerdict::Stop,
                        format!("export policy {label:?} denied this route"),
                    );
                }
                withdraw_existing(vpn_withdraw, existing_path_ids);
                continue;
            }
            if let Some(trace) = target.trace() {
                // Record staged modifications only after the Permit above — a
                // denied route carries none (mirrors the unicast arm; #722).
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

            let out_key = VpnRibRouteKey {
                nlri_key: *key,
                path_id: 0,
            };
            if force
                || rib_out
                    .get_vpn(&out_key)
                    .is_none_or(|existing| !vpn_routes_equal(existing, &modified))
            {
                if let Some(trace) = target.trace() {
                    trace.staged_next_hop = Some(modified.next_hop);
                    trace.staged_path_id = modified.path_id;
                    trace.suppressed_identical = false;
                    trace.push(
                        "adj_rib_out",
                        "staged_announce",
                        crate::update::ExportGateVerdict::Pass,
                        if rib_out.get_vpn(&out_key).is_some() {
                            "staged route differs from the advertised state — would re-announce"
                                .to_string()
                        } else {
                            "identity not yet advertised to this peer — would announce".to_string()
                        },
                    );
                }
                vpn_announce.push(modified);
            } else if let Some(trace) = target.trace() {
                trace.staged_next_hop = Some(modified.next_hop);
                trace.staged_path_id = modified.path_id;
                trace.suppressed_identical = true;
                trace.push(
                    "adj_rib_out",
                    "already_advertised",
                    crate::update::ExportGateVerdict::Pass,
                    "identical route already advertised — peer is in sync, no re-announcement"
                        .to_string(),
                );
            }

            // Clean up stale multi-path entries if this identity was
            // previously advertised via Add-Path and is now single-best.
            for &path_id in existing_path_ids {
                if path_id != 0 {
                    vpn_withdraw.push(VpnRibRouteKey {
                        nlri_key: *key,
                        path_id,
                    });
                }
            }
        }
    }

    /// Recompute Loc-RIB best path and distribute changes for VPNv4/VPNv6
    /// routes.
    ///
    /// The selected route is reflected as received: Route Distinguisher,
    /// MPLS label stack, and next-hop pass through unchanged (ADR-0077 §6),
    /// with ordinary BGP attribute handling applied by transport. Selection
    /// and staging operate per RD+prefix identity — received Add-Path path
    /// IDs are distinct Adj-RIB-In entries but collapse into one candidate
    /// set per identity.
    #[expect(
        clippy::too_many_lines,
        reason = "VPN recompute keeps loc-rib selection and per-peer ORR/Add-Path staging together"
    )]
    pub(in crate::manager) fn recompute_and_distribute_vpn(
        &mut self,
        affected: &HashSet<VpnRibRouteKey>,
    ) {
        let affected_nlri: HashSet<VpnRouteKey> = affected.iter().map(|key| key.nlri_key).collect();

        let mut changed_keys: HashSet<VpnRouteKey> = HashSet::new();
        for key in &affected_nlri {
            // RFC 9069 Loc-RIB tap: keep the previous best's NLRI so a
            // disappeared best can be withdrawn with its full RD +
            // prefix identity. Cloned only when the tap is installed.
            let bmp_prev_nlri = self
                .bmp_tx
                .as_ref()
                .and_then(|_| self.loc_rib.get_vpn(key).map(|route| route.nlri.clone()));
            let candidates: Vec<VpnRibRoute> = self
                .ribs
                .values()
                .flat_map(|rib| rib.iter_vpn_for_nlri(key).cloned())
                .collect();
            if self.loc_rib.recompute_vpn(*key, candidates.iter()) {
                changed_keys.insert(*key);
                if self.bmp_tx.is_some() {
                    let (pdu, path_status) = match self.loc_rib.get_vpn(key) {
                        Some(best) => (
                            crate::bmp_sync::synthesize_vpn_announce(best),
                            // Status bits only: the VPN selection ladder
                            // (`vpn_tiebreak`) has no with-reason variant,
                            // and the Reason Code is optional.
                            Some(crate::bmp_sync::loc_rib_path_status(
                                best.is_stale || best.is_llgr_stale,
                                None,
                            )),
                        ),
                        None => (
                            bmp_prev_nlri
                                .as_ref()
                                .and_then(crate::bmp_sync::synthesize_vpn_withdraw),
                            None,
                        ),
                    };
                    // Announce timestamp = the stored Loc-RIB install
                    // time, so a later BMP table dump reports the exact
                    // same stamp for this route (LAN-193). Withdraws
                    // have no stored entry — event time is the honest
                    // stamp.
                    let timestamp = self
                        .loc_rib
                        .vpn_install_time(key)
                        .unwrap_or_else(std::time::SystemTime::now);
                    self.emit_bmp_loc_rib(pdu, path_status, timestamp);
                }
            }
        }

        // An RFC 9107 ORR peer selects from the per-target candidate set,
        // not the Loc-RIB best — a candidate change that leaves the
        // Loc-RIB best untouched can still flip a vantage best, so
        // ORR-bound peers stage every affected key (the VPN parallel of
        // the unicast `all_affected` inclusion in `distribute_changes`).
        // Add-Path-send peers need the same widening: a non-best candidate
        // change can alter the staged top-N set.
        let any_widened_peer = self.outbound_peers.keys().any(|peer| {
            self.peer_orr_vantage
                .get(peer)
                .is_some_and(|vantage| self.orr.spf.contains_key(vantage))
                || self.peer_vpn_add_path_send(*peer)
        });
        if changed_keys.is_empty() && !any_widened_peer {
            return;
        }

        if !changed_keys.is_empty() {
            self.metrics
                .set_loc_rib_prefixes("vpn", gauge_val(self.loc_rib.vpn_len()));
        }

        // Update-group shared VPN staging: ONE export-tail pass per
        // (VPN-staging group, changed identity), committed to the group
        // tables. The per-peer loop below emits the deltas per member via
        // the RT-pass source-flip matrix (Φ applied at emit for RTC
        // groups); ungrouped peers take the per-peer staging path exactly
        // as before.
        let vpn_group_stage = self.stage_vpn_update_groups(&changed_keys);

        let peers: Vec<IpAddr> = self.outbound_peers.keys().copied().collect();
        for peer in peers {
            if let Some(gid) = self.vpn_grouped_member_of(peer) {
                let Some(stage) = vpn_group_stage.get(&gid) else {
                    continue;
                };
                // Per-member export-policy counters from the group
                // verdict — integer adds, `totals − own-sourced`. RTC
                // note: the per-peer path's RT gate precedes its policy
                // eval, but group staging defers the gate to emit, so
                // the accumulator holds one eval per key regardless of
                // Φ — the per-key deviation for Φ-failing keys is the
                // documented ADR carve-out (counters are aggregates,
                // never compared by the oracle).
                self.apply_group_policy_counters(peer, &stage.evals);
                let member_filter = self.member_rt_filter(peer);
                let mut vpn_announce = Vec::new();
                let mut vpn_withdraw = Vec::new();
                let count_delta = crate::manager::update_groups::emit_vpn_group_deltas_for_member(
                    &stage.deltas,
                    peer,
                    member_filter.as_ref(),
                    &mut vpn_announce,
                    &mut vpn_withdraw,
                );
                if vpn_announce.is_empty() && vpn_withdraw.is_empty() {
                    continue;
                }
                // Optimistic per-member count maintenance (RTC groups
                // only): a failed send below marks the member dirty and
                // the resync recompute restores exactness.
                if let Some(group) = self.group_ribs.get_mut(&gid) {
                    group.apply_vpn_member_count_delta(peer, count_delta);
                }
                let rejected = self.peer_unexportable.get(&peer);
                let group_prior = stage
                    .deltas
                    .iter()
                    .filter_map(|delta| {
                        let key = crate::route::VpnRibRouteKey {
                            nlri_key: delta.key,
                            path_id: 0,
                        };
                        (delta.old.as_ref().is_some_and(|old| {
                            old.peer != peer
                                && crate::manager::update_groups::rt_passes(
                                    member_filter.as_ref(),
                                    old,
                                )
                        }) && !rejected.is_some_and(|keys| {
                            keys.contains(&crate::update::ExactExportKey::Vpn(key.clone()))
                        }))
                        .then_some(crate::update::ExactExportKey::Vpn(key))
                    })
                    .collect();
                if !self.try_send_and_commit_outbound_update_with_group_prior(
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
                    vpn_announce,
                    vpn_withdraw,
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                    group_prior,
                    None,
                ) {
                    warn!(%peer, "outbound channel full — VPN update deferred");
                    self.mark_outbound_dirty(peer);
                    // The member missed this pass's withdrawals: record
                    // them as VPN tombstones so its resync can
                    // (over-)withdraw them.
                    if let Some(group) = self.group_ribs.get_mut(&gid) {
                        group.vpn_tombstones.extend(
                            stage
                                .deltas
                                .iter()
                                .filter(|d| d.new.is_none())
                                .map(|d| d.key),
                        );
                    }
                    // Member-scoped withdraws (source flip onto this
                    // member / RT mutation out of its Φ) keep the key
                    // IN the table — invisible to tombstones. Ride the
                    // member's extra-withdraw residue instead.
                    let lost: Vec<VpnRouteKey> = stage
                        .member_scoped_withdraws(peer, member_filter.as_ref())
                        .collect();
                    if !lost.is_empty() {
                        self.pending_extra_withdraws
                            .entry(peer)
                            .or_default()
                            .vpn
                            .extend(lost);
                    }
                    self.refresh_group_residue_gauge();
                }
                continue;
            }
            // A peer bound to a vantage that resolved this pass takes the
            // per-vantage best; an unresolved vantage silently falls back
            // to the standard Loc-RIB best (same shape as unicast).
            let orr_ctx = self
                .peer_orr_vantage
                .get(&peer)
                .and_then(|vantage| self.orr.spf.get(vantage))
                .map(|spf| (&self.orr.topology, spf));
            let peer_add_path = self.peer_vpn_add_path_send(peer);
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
                    .is_some_and(|families| families.contains(&vpn_afi_safi(key)))
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
            let rtc_filter = self.rtc_vpn_filter(peer, sendable.as_ref());
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

            let mut vpn_announce = Vec::new();
            let mut vpn_withdraw = Vec::new();
            let mut target = super::ExportTarget::Peer {
                peer,
                peer_asn: target_peer_asn,
                peer_group: target_peer_group,
                metrics: &metrics,
                policy_stats: &mut *policy_stats,
                peer_label: &target_peer_label,
            };
            Self::stage_vpn_routes(
                &self.loc_rib,
                &self.ribs,
                rib_out,
                &self.peer_is_rr_client,
                staged_keys,
                &mut target,
                target_is_ebgp,
                target_is_rr_client,
                self.cluster_id,
                sendable.as_ref(),
                llgr.as_ref(),
                rtc_filter.as_ref(),
                orr_ctx,
                add_path_send_max,
                self.peer_add_path_send_limits.get(&peer),
                &add_path_send_families,
                export_pol.as_ref(),
                &mut vpn_announce,
                &mut vpn_withdraw,
                false,
            );

            if (!vpn_announce.is_empty() || !vpn_withdraw.is_empty())
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
                    vpn_announce,
                    vpn_withdraw,
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                )
            {
                warn!(%peer, "outbound channel full — VPN update deferred");
                self.mark_outbound_dirty(peer);
            }
        }
    }
}
