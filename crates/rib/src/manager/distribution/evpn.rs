use super::{
    AdjRibIn, AdjRibOut, Afi, BgpMetrics, HashMap, HashSet, IpAddr, Ipv4Addr, LOCAL_PEER, LocRib,
    NeighborPolicyStats, PolicyChain, Prefix, RibCommandError, RibManager, RouteContext, Safi,
    debug, evpn_routes_equal, gauge_val, record_export_policy_eval, route_type,
    should_suppress_ibgp_inner, warn,
};

impl RibManager {
    pub(in crate::manager) fn process_evpn_withdraw_chunk(
        &mut self,
        peer: IpAddr,
        evpn_withdrawn: Vec<rustbgpd_wire::EvpnRouteKey>,
    ) {
        let active_refresh = self
            .refresh_in_progress
            .get(&peer)
            .cloned()
            .unwrap_or_default();
        let evpn_refresh_active = active_refresh.contains(&(Afi::L2Vpn, Safi::Evpn));
        let mut affected: HashSet<rustbgpd_wire::EvpnRouteKey> = HashSet::new();
        let mut removed_stale_count = 0usize;
        let evpn_len = {
            let rib = self
                .ribs
                .get_mut(&peer)
                .expect("peer rib must exist before chunk processing");
            for key in evpn_withdrawn {
                if rib.withdraw_evpn(&key) {
                    debug!(%peer, route_type = key.route_type(), "evpn withdrawn");
                    affected.insert(key);
                    if evpn_refresh_active
                        && let Some(stale) = self.refresh_stale_evpn.get_mut(&peer)
                        && stale.remove(&key)
                    {
                        removed_stale_count += 1;
                    }
                }
            }
            rib.evpn_len()
        };
        self.metrics
            .set_rib_prefixes(&peer.to_string(), "evpn", gauge_val(evpn_len));
        self.decrement_refresh_stale_count(peer, Afi::L2Vpn, Safi::Evpn, removed_stale_count);
        self.update_peer_refresh_metrics(peer);
        if !affected.is_empty() {
            self.recompute_and_distribute_evpn(&affected);
            if let Some(rib) = self.ribs.get_mut(&peer) {
                rib.gc_intern_table();
            }
        }
    }

    pub(in crate::manager) fn process_evpn_announce_chunk(
        &mut self,
        peer: IpAddr,
        evpn_announced: Vec<crate::route::EvpnRibRoute>,
    ) {
        let active_refresh = self
            .refresh_in_progress
            .get(&peer)
            .cloned()
            .unwrap_or_default();
        let evpn_refresh_active = active_refresh.contains(&(Afi::L2Vpn, Safi::Evpn));
        let mut affected: HashSet<rustbgpd_wire::EvpnRouteKey> = HashSet::new();
        let mut removed_stale_count = 0usize;
        let mut any_replaced = false;
        let evpn_len = {
            let rib = self
                .ribs
                .get_mut(&peer)
                .expect("peer rib must exist before chunk processing");
            for route in evpn_announced {
                debug!(%peer, route_type = route.route_type(), "evpn announced");
                let key = route.key();
                affected.insert(key);
                any_replaced |= rib.insert_evpn(route);
                // Enhanced Route Refresh: re-advertised key removes from
                // the stale set so EoRR's sweep doesn't withdraw it.
                if evpn_refresh_active
                    && let Some(stale) = self.refresh_stale_evpn.get_mut(&peer)
                    && stale.remove(&key)
                {
                    removed_stale_count += 1;
                }
            }
            rib.evpn_len()
        };
        self.metrics
            .set_rib_prefixes(&peer.to_string(), "evpn", gauge_val(evpn_len));
        self.decrement_refresh_stale_count(peer, Afi::L2Vpn, Safi::Evpn, removed_stale_count);
        self.update_peer_refresh_metrics(peer);
        if !affected.is_empty() {
            self.recompute_and_distribute_evpn(&affected);
            if any_replaced && let Some(rib) = self.ribs.get_mut(&peer) {
                rib.gc_intern_table();
            }
        }
    }

    pub(in crate::manager) fn handle_inject_evpn(
        &mut self,
        route: crate::route::EvpnRibRoute,
        reply: tokio::sync::oneshot::Sender<Result<(), RibCommandError>>,
    ) {
        let key = route.key();
        let rib = self
            .ribs
            .entry(LOCAL_PEER)
            .or_insert_with(|| AdjRibIn::new(LOCAL_PEER));
        let replaced = rib.insert_evpn(route);
        debug!(?key, "injected local EVPN route");
        let mut evpn_affected = HashSet::new();
        evpn_affected.insert(key);
        self.recompute_and_distribute_evpn(&evpn_affected);
        if replaced && let Some(rib) = self.ribs.get_mut(&LOCAL_PEER) {
            rib.gc_intern_table();
        }
        let _ = reply.send(Ok(()));
    }

    pub(in crate::manager) fn handle_withdraw_evpn(
        &mut self,
        key: rustbgpd_wire::EvpnRouteKey,
        reply: tokio::sync::oneshot::Sender<Result<(), RibCommandError>>,
    ) {
        let rib = self
            .ribs
            .entry(LOCAL_PEER)
            .or_insert_with(|| AdjRibIn::new(LOCAL_PEER));
        if rib.withdraw_evpn(&key) {
            debug!(?key, "withdrawn injected EVPN route");
            let mut evpn_affected = HashSet::new();
            evpn_affected.insert(key);
            self.recompute_and_distribute_evpn(&evpn_affected);
            if let Some(rib) = self.ribs.get_mut(&LOCAL_PEER) {
                rib.gc_intern_table();
            }
            let _ = reply.send(Ok(()));
        } else {
            let _ = reply.send(Err(RibCommandError::not_found(format!(
                "EVPN route key {key:?} not found"
            ))));
        }
    }

    /// Stage EVPN announces and withdrawals for a set of affected keys.
    ///
    /// Selection semantics match `stage_flowspec_rules`: for each key, if the
    /// `LocRib` has a best route, decide whether to advertise it to this peer
    /// based on RFC 4456 iBGP split-horizon and export policy. Reflection
    /// uses the same `should_suppress_ibgp_inner` helper with a synthetic
    /// placeholder `Route` carrying the EVPN route's peer metadata.
    ///
    /// Phase 1: policy uses a placeholder `0.0.0.0/0` prefix; RT / community
    /// matching works through the existing `RouteContext` fields.
    #[expect(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "EVPN staging mirrors unicast distribution context for policy parity"
    )]
    pub(in crate::manager) fn stage_evpn_routes(
        loc_rib: &LocRib,
        rib_out: &AdjRibOut,
        peer_is_rr_client: &HashMap<IpAddr, bool>,
        keys: &HashSet<rustbgpd_wire::EvpnRouteKey>,
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
        evpn_announce: &mut Vec<crate::route::EvpnRibRoute>,
        evpn_withdraw: &mut Vec<rustbgpd_wire::EvpnRouteKey>,
        force: bool,
    ) {
        let needs_as_path_string = export_pol.is_some_and(PolicyChain::requires_as_path_string);
        let evpn_family = (Afi::L2Vpn, Safi::Evpn);
        let peer_supports_evpn = sendable.is_some_and(|f| f.contains(&evpn_family));

        for key in keys {
            if !peer_supports_evpn {
                if rib_out.get_evpn(key).is_some() {
                    evpn_withdraw.push(*key);
                }
                continue;
            }

            let Some(best) = loc_rib.get_evpn(key) else {
                if rib_out.get_evpn(key).is_some() {
                    evpn_withdraw.push(*key);
                }
                continue;
            };

            // RFC 9494 §4.4: LLGR-stale toward a non-LLGR eBGP peer is
            // suppressed. See `llgr_stale_export_suppressed`.
            if super::llgr_stale_export_suppressed(
                best.is_llgr_stale,
                best.communities(),
                evpn_family,
                target_is_ebgp,
                llgr,
            ) {
                if rib_out.get_evpn(key).is_some() {
                    evpn_withdraw.push(*key);
                }
                continue;
            }

            // Split horizon: don't send an EVPN route back to its source peer.
            // Parallel to the unicast guard earlier in this module. Without
            // this, an RR client could receive its own Type 2/3/4/etc. route
            // back with ORIGINATOR_ID set to its own router-id — FRR and
            // others drop such reflections, but RFC 4456 hygiene says we
            // shouldn't emit them in the first place.
            if best.peer == target_peer {
                if rib_out.get_evpn(key).is_some() {
                    evpn_withdraw.push(*key);
                }
                continue;
            }

            // Split-horizon / RR suppression check via a synthetic Route that
            // carries only the fields should_suppress_ibgp_inner reads.
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
                if rib_out.get_evpn(key).is_some() {
                    evpn_withdraw.push(*key);
                }
                continue;
            }

            // Export policy evaluation. Type 5 EVPN (IP Prefix per RFC 9136)
            // carries a real IP prefix in its NLRI, so prefix-based policy
            // clauses can match against it directly. Types 1-4 don't carry
            // a prefix in any meaningful sense (they identify Ethernet
            // Segments, MAC addresses, or multicast tags), so prefix-based
            // predicates do not match them. Operators who need to filter
            // Types 1-4 should use RT- or community-based clauses.
            let policy_prefix = match &best.route {
                rustbgpd_wire::EvpnRoute::IpPrefix(t5) => match t5.prefix {
                    rustbgpd_wire::EvpnIpPrefixValue::V4(p) => Some(Prefix::V4(p)),
                    rustbgpd_wire::EvpnIpPrefixValue::V6(p) => Some(Prefix::V6(p)),
                },
                _ => None,
            };
            let aspath_str = if needs_as_path_string {
                best.as_path()
                    .map_or_else(String::new, rustbgpd_wire::AsPath::to_aspath_string)
            } else {
                String::new()
            };
            let aspath_len = best.as_path().map_or(0, rustbgpd_wire::AsPath::len);
            let ctx = RouteContext {
                prefix: policy_prefix,
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
                evpn_route_type: Some(best.route_type()),
                local_pref: best.local_pref_attr(),
                med: best.med_attr(),
            };
            let (result, evaluation) =
                rustbgpd_policy::evaluate_chain_with_attribution(export_pol, &ctx);
            record_export_policy_eval(metrics, policy_stats, target_peer_label, &evaluation);
            if result.action != rustbgpd_policy::PolicyAction::Permit {
                if rib_out.get_evpn(key).is_some() {
                    evpn_withdraw.push(*key);
                }
                continue;
            }

            // Apply export modifications (community add/remove, RT add/remove,
            // next-hop). Skip the deep attribute clone when nothing changes.
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
            // Skip the announce if rib_out already holds the same route —
            // the dirty-resync path in particular re-evaluates every
            // advertised key and would otherwise re-emit no-op announces
            // every cycle on a large fabric.
            //
            // `force` mode bypasses this so currently-advertised EVPN
            // routes re-emit even when the RIB-level attribute set is
            // unchanged — used for outbound-attribute toggles like the
            // RFC 8326 GShut community attach where the wire change is
            // applied later in transport.
            if !force
                && rib_out
                    .get_evpn(key)
                    .is_some_and(|existing| evpn_routes_equal(existing, &modified))
            {
                continue;
            }
            evpn_announce.push(modified);
        }
    }

    /// Recompute Loc-RIB best path and distribute changes for EVPN routes.
    ///
    /// Mirrors `recompute_and_distribute_flowspec`. For each affected key,
    /// gather candidates from all peer Adj-RIB-Ins, run best-path, and if
    /// the selection changed, stage announces/withdraws for each outbound
    /// peer that negotiated the L2VPN/EVPN family.
    #[expect(
        clippy::too_many_lines,
        reason = "EVPN recompute keeps best-path, events, and outbound staging consistent"
    )]
    pub(in crate::manager) fn recompute_and_distribute_evpn(
        &mut self,
        affected: &HashSet<rustbgpd_wire::EvpnRouteKey>,
    ) {
        use crate::route::EvpnRibRoute;

        let mut changed_keys: HashSet<rustbgpd_wire::EvpnRouteKey> = HashSet::new();
        for key in affected {
            let candidates: Vec<&EvpnRibRoute> = self
                .ribs
                .values()
                .flat_map(|rib| rib.iter_evpn().filter(|r| r.key() == *key))
                .collect();
            // Capture old state BEFORE recompute_evpn so the event-type
            // derivation below distinguishes Added / Withdrawn /
            // BestChanged precisely. Inferring from the `did_change`
            // bool alone collapses Added and BestChanged into one
            // signal — Gate 7c subscribers (the daemon originator)
            // need to know the difference to update their `last_seen
            // _remote_seq` ratchets correctly.
            let previous_best: Option<EvpnRibRoute> = self.loc_rib.get_evpn(key).cloned();
            let did_change = self.loc_rib.recompute_evpn(*key, candidates.into_iter());
            if did_change {
                let new_best: Option<EvpnRibRoute> = self.loc_rib.get_evpn(key).cloned();
                let event_type = match (&previous_best, &new_best) {
                    (None, Some(_)) => crate::event::RouteEventType::Added,
                    (Some(_), None) => crate::event::RouteEventType::Withdrawn,
                    (Some(_), Some(_)) => crate::event::RouteEventType::BestChanged,
                    // recompute returned `did_change=true` so at least
                    // one side is `Some`. (None, None) shouldn't fire
                    // — guard with debug_assert and skip silently.
                    (None, None) => {
                        debug_assert!(false, "recompute_evpn returned changed but both sides None");
                        continue;
                    }
                };
                let previous_peer = previous_best.as_ref().map(|r| r.peer);
                let peer = new_best.as_ref().map(|r| r.peer);
                self.publish_evpn_route_event(crate::event::EvpnRouteEvent {
                    event_type,
                    key: *key,
                    best: new_best,
                    previous_best,
                    peer,
                    previous_peer,
                    timestamp: crate::event::unix_timestamp_now(),
                });
                changed_keys.insert(*key);
            }
        }

        if changed_keys.is_empty() {
            return;
        }

        self.metrics
            .set_loc_rib_prefixes("evpn", gauge_val(self.loc_rib.evpn_len()));

        let peers: Vec<IpAddr> = self.outbound_peers.keys().copied().collect();
        for peer in peers {
            let sendable = self.peer_sendable_families.get(&peer).cloned();
            let llgr = self.peer_advertised_llgr_families.get(&peer).cloned();
            if !sendable.as_ref().is_some_and(|f| {
                f.contains(&(rustbgpd_wire::Afi::L2Vpn, rustbgpd_wire::Safi::Evpn))
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

            let mut evpn_announce = Vec::new();
            let mut evpn_withdraw = Vec::new();
            Self::stage_evpn_routes(
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
                &mut evpn_announce,
                &mut evpn_withdraw,
                false, // EVPN delta path — equality check is correct
            );

            if (!evpn_announce.is_empty() || !evpn_withdraw.is_empty())
                && !self.try_send_and_commit_outbound_update(
                    peer,
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                    evpn_announce,
                    evpn_withdraw,
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
                warn!(%peer, "outbound channel full — EVPN update deferred");
                self.mark_outbound_dirty(peer);
            }
        }
    }
}
