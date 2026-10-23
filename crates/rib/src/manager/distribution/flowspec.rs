use super::{
    AdjRibIn, AdjRibOut, Afi, BgpMetrics, HashMap, HashSet, Ipv4Addr, LOCAL_PEER, LocRib,
    NeighborPolicyStats, OutboundCommitBatch, PolicyChain, Prefix, RibCommandError, RibManager,
    RouteContext, Safi, debug, flowspec_route_family, record_export_policy_eval, route_type,
    should_suppress_ibgp_inner, warn,
};
use crate::PeerId;
use crate::attr_set::AttrSet;
use crate::injection_lease::{InjectedKey, LeaseGeneration};
use crate::route::{FlowSpecKey, FlowSpecRouteKey};
use crate::update::InjectOutcome;

impl RibManager {
    pub(super) fn process_flowspec_withdraw_chunk(
        &mut self,
        peer: PeerId,
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
            (rib.unicast_lens(), rib.flowspec_lens())
        };

        let peer_label = peer.label();
        crate::manager::helpers::set_rib_prefixes(
            &self.metrics,
            &peer_label,
            crate::manager::helpers::UNICAST_FAMILIES,
            rib_len,
        );
        crate::manager::helpers::set_rib_prefixes(
            &self.metrics,
            &peer_label,
            crate::manager::helpers::FLOWSPEC_FAMILIES,
            flowspec_len,
        );
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
        peer: PeerId,
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
            (rib.unicast_lens(), rib.flowspec_lens())
        };

        let peer_label = peer.label();
        crate::manager::helpers::set_rib_prefixes(
            &self.metrics,
            &peer_label,
            crate::manager::helpers::UNICAST_FAMILIES,
            rib_len,
        );
        crate::manager::helpers::set_rib_prefixes(
            &self.metrics,
            &peer_label,
            crate::manager::helpers::FLOWSPEC_FAMILIES,
            flowspec_len,
        );
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
        reply: tokio::sync::oneshot::Sender<Result<InjectOutcome, RibCommandError>>,
    ) {
        let result = self
            .inject_local_flowspec(route, None)
            .map(|(outcome, _)| outcome);
        let _ = reply.send(result);
    }

    pub(in crate::manager) fn handle_inject_leased_flowspec(
        &mut self,
        route: crate::route::FlowSpecRoute,
        owner: &str,
        lease_seconds: u32,
        reply: tokio::sync::oneshot::Sender<
            Result<(InjectOutcome, LeaseGeneration), RibCommandError>,
        >,
    ) {
        let result = self
            .inject_local_flowspec(route, Some((owner, lease_seconds)))
            .map(|(outcome, generation)| {
                (
                    outcome,
                    generation.expect("a leased add returns its generation"),
                )
            });
        let _ = reply.send(result);
    }

    /// Insert a local `FlowSpec` rule, unowned or under `lease`; see
    /// `inject_local_route` for the ownership contract (ADR-0141).
    fn inject_local_flowspec(
        &mut self,
        route: crate::route::FlowSpecRoute,
        lease: Option<(&str, u32)>,
    ) -> Result<(InjectOutcome, Option<LeaseGeneration>), RibCommandError> {
        let key = route.selection_key();
        let owned_key = InjectedKey::FlowSpec(key.clone());
        let present = self
            .ribs
            .get(&LOCAL_PEER)
            .is_some_and(|rib| rib.get_flowspec(&route.key()).is_some());
        let generation = if let Some((owner, lease_seconds)) = lease {
            Some(
                self.admit_injected_lease(&owned_key, present, owner, lease_seconds)?
                    .generation,
            )
        } else {
            self.check_injected_owner(&owned_key, "")?;
            None
        };
        let rib = self
            .ribs
            .entry(LOCAL_PEER)
            .or_insert_with(|| AdjRibIn::new(LOCAL_PEER));
        // Decide from the local Adj-RIB-In, not Loc-RIB: a received rule
        // that out-selects the local one leaves Loc-RIB unchanged even when
        // the local payload really was replaced. `received_at` is excluded,
        // matching the Loc-RIB change test, so an identical re-add distributes
        // nothing.
        let outcome = match rib.get_flowspec(&route.key()) {
            None => InjectOutcome::Created,
            Some(old)
                if old.attributes == route.attributes
                    && old.origin_type == route.origin_type
                    && old.peer_router_id == route.peer_router_id
                    && old.is_stale == route.is_stale
                    && old.is_llgr_stale == route.is_llgr_stale =>
            {
                InjectOutcome::Unchanged
            }
            Some(_) => InjectOutcome::Replaced,
        };
        rib.insert_flowspec(route);
        crate::manager::helpers::set_rib_prefixes(
            &self.metrics,
            &LOCAL_PEER.to_string(),
            crate::manager::helpers::FLOWSPEC_FAMILIES,
            rib.flowspec_lens(),
        );
        debug!(afi = ?key.afi, rule = %key.rule, ?outcome, "injected local FlowSpec route");
        let mut fs_affected = HashSet::new();
        fs_affected.insert(key);
        self.recompute_and_distribute_flowspec(&fs_affected);
        Ok((outcome, generation))
    }

    pub(in crate::manager) fn handle_withdraw_flowspec(
        &mut self,
        key: FlowSpecKey,
        allow_missing: bool,
        owner: &str,
        override_owner: bool,
        reply: tokio::sync::oneshot::Sender<
            Result<crate::update::InjectedRemoval, RibCommandError>,
        >,
    ) {
        let owned_key = InjectedKey::FlowSpec(key.clone());
        let route_key = FlowSpecRouteKey {
            afi: key.afi,
            rule: key.rule.clone(),
            path_id: 0,
        };
        let present = self
            .ribs
            .get(&LOCAL_PEER)
            .is_some_and(|rib| rib.get_flowspec(&route_key).is_some());
        if !override_owner
            && present
            && let Err(rejection) = self.check_injected_owner(&owned_key, owner)
        {
            let _ = reply.send(Err(rejection));
            return;
        }
        let rib = self
            .ribs
            .entry(LOCAL_PEER)
            .or_insert_with(|| AdjRibIn::new(LOCAL_PEER));
        let removed = rib.withdraw_flowspec(&route_key);
        crate::manager::helpers::set_rib_prefixes(
            &self.metrics,
            &LOCAL_PEER.to_string(),
            crate::manager::helpers::FLOWSPEC_FAMILIES,
            rib.flowspec_lens(),
        );
        if removed {
            let tag = self.forget_injected(&owned_key);
            debug!(afi = ?key.afi, rule = %key.rule, "withdrawn injected FlowSpec route");
            let mut fs_affected = HashSet::new();
            fs_affected.insert(key);
            self.recompute_and_distribute_flowspec(&fs_affected);
            let _ = reply.send(Ok(crate::update::InjectedRemoval { removed: true, tag }));
        } else if allow_missing {
            let _ = reply.send(Ok(crate::update::InjectedRemoval {
                removed: false,
                tag: None,
            }));
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
        reason = "FlowSpec staging keeps the family-local export ladder together"
    )]
    pub(in crate::manager) fn stage_flowspec_rules_with_checkpoint(
        loc_rib: &LocRib,
        rib_out: &AdjRibOut,
        peer_is_rr_client: &HashMap<PeerId, bool>,
        keys: &HashSet<FlowSpecKey>,
        target_peer: PeerId,
        target_peer_asn: Option<u32>,
        target_peer_group: Option<&str>,
        target_is_ebgp: bool,
        interpret_rfc1997: bool,
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
        checkpoint: &mut impl FnMut(),
    ) {
        let needs_as_path_string = export_pol.is_some_and(PolicyChain::requires_as_path_string);
        for key in keys {
            checkpoint();
            let Some(best) = loc_rib.get_flowspec(key) else {
                if rib_out.get_flowspec(key).is_some() {
                    fs_withdraw.push(key.clone());
                }
                continue;
            };
            if Self::flowspec_pre_policy_stop(
                best,
                peer_is_rr_client,
                target_is_ebgp,
                interpret_rfc1997,
                target_is_rr_client,
                cluster_id,
                sendable,
                llgr,
            )
            .is_some()
            {
                if rib_out.get_flowspec(key).is_some() {
                    fs_withdraw.push(key.clone());
                }
                continue;
            }
            let aspath_str = flowspec_as_path_string(best, needs_as_path_string);
            let ctx = flowspec_export_context(
                best,
                &aspath_str,
                target_peer,
                target_peer_asn,
                target_peer_group,
            );
            checkpoint();
            let (result, evaluation) =
                rustbgpd_policy::evaluate_chain_with_attribution(export_pol, &ctx);
            checkpoint();
            record_export_policy_eval(metrics, policy_stats, target_peer_label, &evaluation);
            if result.action == rustbgpd_policy::PolicyAction::Permit {
                let modified = flowspec_export_modified(best, &result, checkpoint);
                if super::no_advertise_export_suppressed(modified.communities()) {
                    if rib_out.get_flowspec(key).is_some() {
                        fs_withdraw.push(key.clone());
                    }
                    continue;
                }
                checkpoint();
                fs_announce.push(modified);
                checkpoint();
            } else if rib_out.get_flowspec(key).is_some() {
                fs_withdraw.push(key.clone());
            }
        }
    }

    /// The live export ladder for the Loc-RIB rule `best` toward the
    /// registered `peer`, without counting policy metrics: the rule as
    /// export would announce it, or the gate that stops it.
    pub(in crate::manager) fn explain_flowspec_export(
        &self,
        peer: PeerId,
        best: &crate::route::FlowSpecRoute,
    ) -> Result<crate::route::FlowSpecRoute, FlowSpecExportStop> {
        let stop = |code, detail: String| FlowSpecExportStop {
            code,
            detail,
            deny_validation: Vec::new(),
        };
        if let Some(code) = Self::flowspec_pre_policy_stop(
            best,
            &self.peer_is_rr_client,
            self.peer_is_ebgp.get(&peer).copied().unwrap_or(true),
            self.peer_interpret_rfc1997.contains(&peer),
            self.peer_is_rr_client.get(&peer).copied().unwrap_or(false),
            self.cluster_id,
            self.peer_sendable_families.get(&peer),
            self.peer_advertised_llgr_families.get(&peer),
        ) {
            return Err(stop(code, format!("export gate {code} stops this rule")));
        }
        let export_pol = self.export_policy_for(peer);
        let aspath_str = flowspec_as_path_string(
            best,
            export_pol.is_some_and(PolicyChain::requires_as_path_string),
        );
        let ctx = flowspec_export_context(
            best,
            &aspath_str,
            peer,
            self.peer_asn.get(&peer).copied(),
            self.peer_group.get(&peer).map(String::as_str),
        );
        let (result, evaluation, policy_label, deny_validation) =
            super::explain_export_evaluation(export_pol, &ctx);
        if result.action != rustbgpd_policy::PolicyAction::Permit {
            let (code, detail) = super::unicast::export_deny_attribution(
                evaluation.matched_policy.as_deref(),
                &policy_label,
            );
            return Err(FlowSpecExportStop {
                deny_validation: if code == "policy_denied" {
                    deny_validation
                } else {
                    Vec::new()
                },
                ..stop(code, detail)
            });
        }
        let modified = flowspec_export_modified(best, &result, &mut || {});
        if super::no_advertise_export_suppressed(modified.communities()) {
            return Err(stop(
                "no_advertise_policy_suppressed",
                "export policy added NO_ADVERTISE".to_string(),
            ));
        }
        Ok(modified)
    }

    /// The pre-policy export gate that stops the Loc-RIB rule `best` toward
    /// a peer, as its `ExplainAdvertisedRoute` stop code; `None` when the
    /// rule reaches export policy. Live staging and the export-disposition
    /// query both read this ladder.
    #[expect(
        clippy::too_many_arguments,
        reason = "the FlowSpec export ladder reads the target peer's session facts directly"
    )]
    pub(in crate::manager) fn flowspec_pre_policy_stop(
        best: &crate::route::FlowSpecRoute,
        peer_is_rr_client: &HashMap<PeerId, bool>,
        target_is_ebgp: bool,
        interpret_rfc1997: bool,
        target_is_rr_client: bool,
        cluster_id: Option<Ipv4Addr>,
        sendable: Option<&Vec<(Afi, Safi)>>,
        llgr: Option<&Vec<(Afi, Safi)>>,
    ) -> Option<&'static str> {
        let fs_family = (best.afi, Safi::FlowSpec);
        if !sendable.is_some_and(|f| f.contains(&fs_family)) {
            return Some("family_not_sendable");
        }
        // RFC 1997: NO_ADVERTISE is a pre-policy export restriction.
        // A permit policy cannot remove it to make the rule eligible.
        if super::no_advertise_export_suppressed(best.communities()) {
            return Some("no_advertise_suppressed");
        }
        // RFC 1997: source-route NO_EXPORT / NO_EXPORT_SUBCONFED is an eBGP
        // export restriction when this neighbor honors the well-known
        // communities. Evaluate before policy so a removal cannot bypass
        // it; policy-added communities remain deliverable.
        if super::no_export_export_suppressed(best.communities(), target_is_ebgp, interpret_rfc1997)
        {
            return Some("no_export_suppressed");
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
            return Some("llgr_stale_suppressed");
        }
        // Reuse the existing iBGP split-horizon / RR check. Only
        // origin_type/peer/peer_router_id are relevant here.
        should_suppress_ibgp_inner(
            &crate::route::Route {
                prefix: Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0)),
                next_hop: best.peer.addr(),
                link_local_next_hop: None,
                next_hop_scope: None,
                peer: best.peer,
                attributes: AttrSet::new(vec![]),
                received_at: crate::route::ReceivedAt::from_instant(best.received_at),
                origin_type: best.origin_type,
                peer_router_id: best.peer_router_id,
                is_stale: false,
                is_llgr_stale: false,
                path_id: 0,
                validation_state: rustbgpd_wire::RpkiValidation::NotFound,
                aspa_state: rustbgpd_wire::AspaValidation::Unknown,
                received_as_path: None,
                aspa_context: crate::route::AspaContextId::DEFAULT,
            },
            target_is_ebgp,
            target_is_rr_client,
            cluster_id,
            peer_is_rr_client,
        )
        .then_some("ibgp_split_horizon")
    }

    /// Recompute `FlowSpec` Loc-RIB best routes for affected rules and
    /// distribute changes to all outbound peers.
    pub(in crate::manager) fn recompute_and_distribute_flowspec(
        &mut self,
        affected: &HashSet<FlowSpecKey>,
    ) {
        self.with_selection_readiness(|manager| {
            manager.sync_flowspec_validation(affected);
            manager.recompute_validated_flowspec_inner(affected);
        });
    }

    pub(in crate::manager) fn recompute_validated_flowspec(
        &mut self,
        affected: &HashSet<FlowSpecKey>,
    ) {
        self.with_selection_readiness(|manager| {
            manager.recompute_validated_flowspec_inner(affected);
        });
    }

    #[expect(
        clippy::too_many_lines,
        reason = "family selection, checkpointed staging, and commit retain their shared mutation order"
    )]
    fn recompute_validated_flowspec_inner(&mut self, affected: &HashSet<FlowSpecKey>) {
        use crate::route::FlowSpecRoute;

        let readiness = self.replacement_readiness.clone();
        let mut checkpoint = || {
            super::super::replacement_readiness_checkpoint_at(
                &readiness,
                "selection_flowspec",
                false,
            );
        };
        checkpoint();
        self.record_deferred_flowspec(affected);
        let mut affected: HashSet<_> = affected
            .iter()
            .inspect(|_| checkpoint())
            .filter(|key| !self.selection_deferred((key.afi, Safi::FlowSpec)))
            .cloned()
            .collect();
        if affected.is_empty() {
            return;
        }

        let mut changed_keys: HashSet<FlowSpecKey> = HashSet::new();

        for key in &affected {
            checkpoint();
            let candidates: Vec<&FlowSpecRoute> = self.flowspec_validation.selection_candidates(
                key,
                &self.ribs,
                &self.loc_rib,
                &checkpoint,
            );
            let did_change = self
                .loc_rib
                .recompute_flowspec(key.clone(), candidates.into_iter());
            if did_change {
                changed_keys.insert(key.clone());
            }
        }

        if changed_keys.is_empty() {
            super::super::retire_hash_set(&mut affected, &mut checkpoint);
            return;
        }

        crate::manager::helpers::set_loc_rib_prefixes(
            &self.metrics,
            crate::manager::helpers::FLOWSPEC_FAMILIES,
            self.loc_rib.family_lens().flowspec,
        );

        // Distribute FlowSpec changes to outbound peers
        let peers: Vec<PeerId> = self
            .outbound_peers
            .keys()
            .inspect(|_| checkpoint())
            .copied()
            .collect();
        for peer in peers {
            checkpoint();
            if self.outbound_channel_gone(peer) {
                self.drop_gone_dirty_peer(peer);
                continue;
            }
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
            let interpret_rfc1997 = self.peer_interpret_rfc1997.contains(&peer);
            let target_is_rr_client = self.peer_is_rr_client.get(&peer).copied().unwrap_or(false);
            let target_peer_asn = self.peer_asn.get(&peer).copied();
            let target_peer_group = self.peer_group.get(&peer).map(String::as_str);
            let export_pol = self
                .export_policy_for(peer)
                .map(rustbgpd_policy::PolicyChain::share);
            let target_peer_label = peer.label();
            let metrics = self.metrics.clone();

            let loc_rib_len = self.loc_rib.len();
            let rib_out = self
                .adj_ribs_out
                .entry(peer)
                .or_insert_with(|| crate::adj_rib_out::AdjRibOut::with_capacity(peer, loc_rib_len));
            let mut export_tally = crate::update::NeighborPolicyStats::default();
            let policy_stats = &mut export_tally;

            let mut fs_announce = Vec::new();
            let mut fs_withdraw = Vec::new();
            Self::stage_flowspec_rules_with_checkpoint(
                &self.loc_rib,
                rib_out,
                &self.peer_is_rr_client,
                &changed_keys,
                peer,
                target_peer_asn,
                target_peer_group,
                target_is_ebgp,
                interpret_rfc1997,
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
                &mut checkpoint,
            );
            crate::manager::add_export_tally(&mut self.export_policy_counters, peer, export_tally);

            if (!fs_announce.is_empty() || !fs_withdraw.is_empty())
                && let Err(failure) = self.try_send_and_commit_outbound_update(
                    peer,
                    OutboundCommitBatch {
                        flowspec_announce: fs_announce,
                        flowspec_withdraw: fs_withdraw,
                        ..OutboundCommitBatch::default()
                    },
                )
                && self.mark_dirty_after_family_send_failure(peer, failure)
            {
                warn!(%peer, "outbound channel full — FlowSpec update deferred");
            }
        }
        super::super::retire_hash_set(&mut changed_keys, &mut checkpoint);
        super::super::retire_hash_set(&mut affected, &mut checkpoint);
    }
}

/// `best`'s `AS_PATH` as a policy regex subject, or empty when the chain
/// never reads one.
pub(in crate::manager) fn flowspec_as_path_string(
    best: &crate::route::FlowSpecRoute,
    needed: bool,
) -> String {
    if needed {
        best.as_path()
            .map_or_else(String::new, rustbgpd_wire::AsPath::to_aspath_string)
    } else {
        String::new()
    }
}

/// The export-policy context of the Loc-RIB rule `best` toward
/// `target_peer`. A rule without a destination-prefix component has no
/// prefix: fabricating `0.0.0.0/0` would spuriously match prefix-based
/// policy terms (same class as the BGP-LS fix).
pub(in crate::manager) fn flowspec_export_context<'a>(
    best: &'a crate::route::FlowSpecRoute,
    as_path_str: &'a str,
    target_peer: PeerId,
    target_peer_asn: Option<u32>,
    target_peer_group: Option<&'a str>,
) -> RouteContext<'a> {
    RouteContext {
        prefix: best.rule.destination_prefix(),
        next_hop: None,
        extended_communities: best.extended_communities(),
        communities: best.communities(),
        large_communities: best.large_communities(),
        as_path_str,
        as_path: best.as_path(),
        as_path_len: best.as_path().map_or(0, rustbgpd_wire::AsPath::len),
        origin_asn: best.as_path().and_then(rustbgpd_wire::AsPath::origin_asn),
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        peer_address: Some(target_peer.addr()),
        peer_asn: target_peer_asn,
        peer_group: target_peer_group,
        route_type: Some(route_type(best.origin_type)),
        family: Some(flowspec_route_family(best.afi)),
        evpn_route_type: None,
        local_pref: best.local_pref_attr(),
        med: best.med_attr(),
    }
}

/// `best` as export policy's permit `result` modifies it for one peer.
pub(in crate::manager) fn flowspec_export_modified(
    best: &crate::route::FlowSpecRoute,
    result: &rustbgpd_policy::PolicyResult,
    checkpoint: &mut impl FnMut(),
) -> crate::route::FlowSpecRoute {
    let mut modified = best.clone();
    if !result.modifications.is_empty() {
        let mut modifications = result.modifications.clone();
        // RFC 8955/8956 FlowSpec MP_REACH carries NH-Len 0. The shared
        // helper's IPv4 next-hop support would otherwise insert a legacy
        // NEXT_HOP path attribute.
        modifications.set_next_hop = None;
        if !modifications.is_empty() {
            checkpoint();
            let next_hop =
                rustbgpd_policy::apply_modifications(&mut modified.attributes, &modifications);
            checkpoint();
            debug_assert!(next_hop.is_none());
        }
    }
    modified
}

/// The export gate that stops a `FlowSpec` rule toward one peer.
#[derive(Debug)]
pub(in crate::manager) struct FlowSpecExportStop {
    /// Stop code in the `ExplainAdvertisedRoute` gate vocabulary.
    pub(in crate::manager) code: &'static str,
    /// Human-readable detail.
    pub(in crate::manager) detail: String,
    /// The deciding statement's validation codes for a `policy_denied` stop.
    pub(in crate::manager) deny_validation: Vec<String>,
}
