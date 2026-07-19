use super::{
    AdjRibIn, AdjRibOut, Afi, BgpMetrics, HashMap, HashSet, IpAddr, Ipv4Addr, LOCAL_PEER, LocRib,
    NeighborPolicyStats, PolicyChain, Prefix, RibCommandError, RibManager, RouteContext, Safi,
    debug, flowspec_route_family, gauge_val, record_export_policy_eval, route_type,
    should_suppress_ibgp_inner, warn,
};
use crate::route::{FlowSpecKey, FlowSpecRouteKey};

impl RibManager {
    pub(super) fn process_flowspec_withdraw_chunk(
        &mut self,
        peer: IpAddr,
        flowspec_withdrawn: Vec<FlowSpecKey>,
    ) {
        let active_refresh = self
            .refresh_in_progress
            .get(&peer)
            .cloned()
            .unwrap_or_default();
        let mut fs_affected: HashSet<FlowSpecKey> = HashSet::new();
        let mut removed_stale_counts: HashMap<(Afi, Safi), usize> = HashMap::new();

        let (rib_len, flowspec_len) = {
            let rib = self
                .ribs
                .get_mut(&peer)
                .expect("peer rib must exist before chunk processing");

            for key in flowspec_withdrawn {
                let route_key = FlowSpecRouteKey {
                    afi: key.afi,
                    rule: key.rule.clone(),
                    path_id: 0,
                };
                if rib.withdraw_flowspec(&route_key) {
                    debug!(%peer, afi = ?key.afi, rule = %key.rule, "flowspec withdrawn");
                    fs_affected.insert(key.clone());
                }
                if active_refresh.contains(&(key.afi, Safi::FlowSpec))
                    && let Some(stale) = self.refresh_stale_flowspec.get_mut(&peer)
                {
                    stale.retain(|stale_key| {
                        let keep = stale_key.afi != key.afi || stale_key.rule != key.rule;
                        if !keep {
                            *removed_stale_counts
                                .entry((stale_key.afi, Safi::FlowSpec))
                                .or_default() += 1;
                        }
                        keep
                    });
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
        if !fs_affected.is_empty() {
            self.recompute_and_distribute_flowspec(&fs_affected);
        }
    }

    pub(super) fn process_flowspec_announce_chunk(
        &mut self,
        peer: IpAddr,
        flowspec_announced: Vec<crate::route::FlowSpecRoute>,
    ) {
        let active_refresh = self
            .refresh_in_progress
            .get(&peer)
            .cloned()
            .unwrap_or_default();
        let mut fs_affected: HashSet<FlowSpecKey> = HashSet::new();
        let mut removed_stale_counts: HashMap<(Afi, Safi), usize> = HashMap::new();

        let (rib_len, flowspec_len) = {
            let rib = self
                .ribs
                .get_mut(&peer)
                .expect("peer rib must exist before chunk processing");

            for route in flowspec_announced {
                debug!(%peer, rule = %route.rule, "flowspec announced");
                let stale_key = route.key();
                fs_affected.insert(route.selection_key());
                rib.insert_flowspec(route);
                if active_refresh.contains(&(stale_key.afi, Safi::FlowSpec))
                    && let Some(stale) = self.refresh_stale_flowspec.get_mut(&peer)
                    && stale.remove(&stale_key)
                {
                    *removed_stale_counts
                        .entry((stale_key.afi, Safi::FlowSpec))
                        .or_default() += 1;
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
        if !fs_affected.is_empty() {
            self.recompute_and_distribute_flowspec(&fs_affected);
        }
    }

    pub(in crate::manager) fn handle_inject_flowspec(
        &mut self,
        route: crate::route::FlowSpecRoute,
        reply: tokio::sync::oneshot::Sender<Result<(), RibCommandError>>,
    ) {
        let key = route.selection_key();
        let rib = self
            .ribs
            .entry(LOCAL_PEER)
            .or_insert_with(|| AdjRibIn::new(LOCAL_PEER));
        rib.insert_flowspec(route);
        debug!(afi = ?key.afi, rule = %key.rule, "injected local FlowSpec route");
        let mut fs_affected = HashSet::new();
        fs_affected.insert(key);
        self.recompute_and_distribute_flowspec(&fs_affected);
        let _ = reply.send(Ok(()));
    }

    pub(in crate::manager) fn handle_withdraw_flowspec(
        &mut self,
        key: FlowSpecKey,
        reply: tokio::sync::oneshot::Sender<Result<(), RibCommandError>>,
    ) {
        let rib = self
            .ribs
            .entry(LOCAL_PEER)
            .or_insert_with(|| AdjRibIn::new(LOCAL_PEER));
        let route_key = FlowSpecRouteKey {
            afi: key.afi,
            rule: key.rule.clone(),
            path_id: 0,
        };
        if rib.withdraw_flowspec(&route_key) {
            debug!(afi = ?key.afi, rule = %key.rule, "withdrawn injected FlowSpec route");
            let mut fs_affected = HashSet::new();
            fs_affected.insert(key);
            self.recompute_and_distribute_flowspec(&fs_affected);
            let _ = reply.send(Ok(()));
        } else {
            let _ = reply.send(Err(RibCommandError::not_found(format!(
                "FlowSpec {:?} rule {} not found",
                key.afi, key.rule
            ))));
        }
    }

    /// Stage `FlowSpec` announces and withdrawals for a set of rules.
    ///
    /// Uses `loc_rib` as the current best-route source and diffs against the
    /// provided outbound view. Passing an empty `AdjRibOut` view causes a full
    /// re-advertisement of the current `FlowSpec` export set, which is useful
    /// for initial table dump and ROUTE-REFRESH responses.
    #[expect(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "FlowSpec staging keeps the family-local export ladder together"
    )]
    pub(in crate::manager) fn stage_flowspec_rules(
        loc_rib: &LocRib,
        rib_out: &AdjRibOut,
        peer_is_rr_client: &HashMap<IpAddr, bool>,
        keys: &HashSet<FlowSpecKey>,
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
        fs_announce: &mut Vec<crate::route::FlowSpecRoute>,
        fs_withdraw: &mut Vec<FlowSpecKey>,
    ) {
        let needs_as_path_string = export_pol.is_some_and(PolicyChain::requires_as_path_string);
        for key in keys {
            if let Some(best) = loc_rib.get_flowspec(key) {
                let fs_family = (best.afi, Safi::FlowSpec);
                if !sendable.is_some_and(|f| f.contains(&fs_family)) {
                    if rib_out.get_flowspec(key).is_some() {
                        fs_withdraw.push(key.clone());
                    }
                    continue;
                }

                // RFC 1997: NO_ADVERTISE is a pre-policy export restriction.
                // A permit policy cannot remove it to make the rule eligible.
                if super::no_advertise_export_suppressed(best.communities()) {
                    if rib_out.get_flowspec(key).is_some() {
                        fs_withdraw.push(key.clone());
                    }
                    continue;
                }

                // RFC 9494 §4.4: LLGR-stale toward a non-LLGR eBGP peer is
                // suppressed. See `llgr_stale_export_suppressed`.
                if super::llgr_stale_export_suppressed(
                    best.is_llgr_stale,
                    best.communities(),
                    fs_family,
                    target_is_ebgp,
                    llgr,
                ) {
                    if rib_out.get_flowspec(key).is_some() {
                        fs_withdraw.push(key.clone());
                    }
                    continue;
                }

                // Reuse the existing iBGP split-horizon / RR check. Only
                // origin_type/peer/peer_router_id are relevant here.
                if should_suppress_ibgp_inner(
                    &crate::route::Route {
                        prefix: Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
                            Ipv4Addr::UNSPECIFIED,
                            0,
                        )),
                        next_hop: best.peer,
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
                    },
                    target_is_ebgp,
                    target_is_rr_client,
                    cluster_id,
                    peer_is_rr_client,
                ) {
                    if rib_out.get_flowspec(key).is_some() {
                        fs_withdraw.push(key.clone());
                    }
                    continue;
                }

                // A rule without a destination-prefix component stays
                // `None` — fabricating `0.0.0.0/0` would spuriously match
                // prefix-based policy terms (same class as the BGP-LS fix).
                let dest_prefix = best.rule.destination_prefix();
                let aspath_str = if needs_as_path_string {
                    best.as_path()
                        .map_or_else(String::new, rustbgpd_wire::AsPath::to_aspath_string)
                } else {
                    String::new()
                };
                let aspath_len = best.as_path().map_or(0, rustbgpd_wire::AsPath::len);
                let origin_asn = best.as_path().and_then(rustbgpd_wire::AsPath::origin_asn);
                let ctx = RouteContext {
                    prefix: dest_prefix,
                    next_hop: None,
                    extended_communities: best.extended_communities(),
                    communities: best.communities(),
                    large_communities: best.large_communities(),
                    as_path_str: &aspath_str,
                    as_path: best.as_path(),
                    as_path_len: aspath_len,
                    origin_asn,
                    validation_state: rustbgpd_wire::RpkiValidation::NotFound,
                    aspa_state: rustbgpd_wire::AspaValidation::Unknown,
                    peer_address: Some(target_peer),
                    peer_asn: target_peer_asn,
                    peer_group: target_peer_group,
                    route_type: Some(route_type(best.origin_type)),
                    family: Some(flowspec_route_family(best.afi)),
                    evpn_route_type: None,
                    local_pref: best.local_pref_attr(),
                    med: best.med_attr(),
                };
                let (result, evaluation) =
                    rustbgpd_policy::evaluate_chain_with_attribution(export_pol, &ctx);
                record_export_policy_eval(metrics, policy_stats, target_peer_label, &evaluation);
                if result.action == rustbgpd_policy::PolicyAction::Permit {
                    let mut modified = best.clone();
                    if !result.modifications.is_empty() {
                        let mut modifications = result.modifications.clone();
                        // RFC 8955/8956 FlowSpec MP_REACH carries NH-Len 0.
                        // The shared helper's IPv4 next-hop support would
                        // otherwise insert a legacy NEXT_HOP path attribute.
                        modifications.set_next_hop = None;
                        if !modifications.is_empty() {
                            let next_hop = rustbgpd_policy::apply_modifications(
                                &mut modified.attributes,
                                &modifications,
                            );
                            debug_assert!(next_hop.is_none());
                        }
                    }
                    if super::no_advertise_export_suppressed(modified.communities()) {
                        if rib_out.get_flowspec(key).is_some() {
                            fs_withdraw.push(key.clone());
                        }
                        continue;
                    }
                    fs_announce.push(modified);
                } else if rib_out.get_flowspec(key).is_some() {
                    fs_withdraw.push(key.clone());
                }
            } else if rib_out.get_flowspec(key).is_some() {
                fs_withdraw.push(key.clone());
            }
        }
    }

    /// Recompute `FlowSpec` Loc-RIB best routes for affected rules and
    /// distribute changes to all outbound peers.
    #[expect(
        clippy::too_many_lines,
        reason = "FlowSpec recompute stages policy-aware changes for every outbound peer"
    )]
    pub(in crate::manager) fn recompute_and_distribute_flowspec(
        &mut self,
        affected: &HashSet<FlowSpecKey>,
    ) {
        use crate::route::FlowSpecRoute;

        self.record_deferred_flowspec(affected);
        let affected: HashSet<_> = affected
            .iter()
            .filter(|key| !self.selection_deferred((key.afi, Safi::FlowSpec)))
            .cloned()
            .collect();
        if affected.is_empty() {
            return;
        }

        let mut changed_keys: HashSet<FlowSpecKey> = HashSet::new();

        for key in &affected {
            let candidates: Vec<&FlowSpecRoute> = self
                .ribs
                .values()
                .flat_map(|rib| rib.iter_flowspec_key(key))
                .collect();
            let did_change = self
                .loc_rib
                .recompute_flowspec(key.clone(), candidates.into_iter());
            if did_change {
                changed_keys.insert(key.clone());
            }
        }

        if changed_keys.is_empty() {
            return;
        }

        self.metrics
            .set_loc_rib_prefixes("flowspec", gauge_val(self.loc_rib.flowspec_len()));

        // Distribute FlowSpec changes to outbound peers
        let peers: Vec<IpAddr> = self.outbound_peers.keys().copied().collect();
        for peer in peers {
            let sendable = self.peer_sendable_families.get(&peer).cloned();
            let llgr = self.peer_advertised_llgr_families.get(&peer).cloned();
            let has_fs = sendable.as_ref().is_some_and(|families| {
                families.contains(&(rustbgpd_wire::Afi::Ipv4, rustbgpd_wire::Safi::FlowSpec))
                    || families.contains(&(rustbgpd_wire::Afi::Ipv6, rustbgpd_wire::Safi::FlowSpec))
            });
            if !has_fs {
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

            let mut fs_announce = Vec::new();
            let mut fs_withdraw = Vec::new();
            Self::stage_flowspec_rules(
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
                &mut fs_announce,
                &mut fs_withdraw,
            );

            if (!fs_announce.is_empty() || !fs_withdraw.is_empty())
                && !self.try_send_and_commit_outbound_update(
                    peer,
                    vec![].into(),
                    vec![].into(),
                    vec![],
                    vec![],
                    vec![],
                    fs_announce,
                    fs_withdraw,
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
                )
            {
                warn!(%peer, "outbound channel full — FlowSpec update deferred");
                self.mark_outbound_dirty(peer);
            }
        }
    }
}
