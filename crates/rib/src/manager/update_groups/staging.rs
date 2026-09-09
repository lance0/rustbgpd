use crate::manager::{replacement_readiness_checkpoint, retire_vec};

use super::{
    GroupDelta, GroupRibOut, GroupStageOutput, HashMap, HashSet, IpAddr, LaneDelta, PolicyAction,
    PolicyChain, PolicyFilteredRouteKey, PolicyLabel, Prefix, RibManager, RunnerUp,
    VpnDenialRecord, VpnGroupDelta, VpnGroupStageOutput, VpnRibRoute, VpnRibRouteKey, VpnRouteKey,
    capture_source_attrs, routes_equal, source_control_input,
};

impl RibManager {
    /// The group a staging pass read at its top, for the commit block
    /// at its bottom. `&mut self` held across the whole pass is the
    /// only thing that makes this lookup infallible; a future
    /// re-entrant (async) staging pass would break that exclusivity
    /// silently, so assert the invariant rather than only unwrap it.
    fn staged_group_mut(groups: &mut HashMap<usize, GroupRibOut>, gid: usize) -> &mut GroupRibOut {
        debug_assert!(
            groups.contains_key(&gid),
            "staging exclusivity: group {gid} read at the top of the pass must still exist at commit"
        );
        groups
            .get_mut(&gid)
            .expect("group staged above still exists")
    }

    /// Run the shared staging pass for every live group over the pass's
    /// changed prefixes. Deltas are committed to the group tables here;
    /// the per-peer loop emits them per member via the source-flip
    /// matrix. `memo` is the pass-scoped export memo shared with the
    /// ungrouped fallback staging.
    ///
    /// A plain group stages exactly `best_changed`: its input is
    /// Loc-RIB-best-or-nothing, so the narrow set is complete. A
    /// per-client-best group's winner walk reads the candidate list,
    /// not the Loc-RIB best — a candidate change can flip the winner
    /// or the lane while the best stands — so it stages the widened
    /// `best_changed ∪ all_affected` set, mirroring the ungrouped
    /// per-client-best enumeration. The union is built once, and only
    /// when such a group exists; winner-equality and lane suppression
    /// make the widened pass a no-op wherever neither slot moved.
    pub(in crate::manager) fn stage_update_groups(
        &mut self,
        best_changed: &HashSet<Prefix>,
        all_affected: &HashSet<Prefix>,
        memo: &mut crate::manager::distribution::ExportMemo,
    ) -> HashMap<usize, GroupStageOutput> {
        let mut staged = HashMap::new();
        if self.group_ribs.is_empty() || (best_changed.is_empty() && all_affected.is_empty()) {
            return staged;
        }
        self.replacement_checkpoint(true);
        let widened: Option<HashSet<Prefix>> = (!all_affected.is_empty()
            && self.group_ribs.values().any(|group| {
                self.replacement_checkpoint(false);
                group.per_client_best
            }))
        .then(|| {
            let mut widened = HashSet::with_capacity(best_changed.len() + all_affected.len());
            self.replacement_checkpoint(true);
            for prefix in best_changed.iter().chain(all_affected) {
                self.replacement_checkpoint(false);
                widened.insert(*prefix);
            }
            widened
        });
        self.replacement_checkpoint(true);
        let gids: Vec<usize> = self
            .group_ribs
            .keys()
            .map(|gid| {
                self.replacement_checkpoint(false);
                *gid
            })
            .collect();
        self.replacement_checkpoint(true);
        for gid in gids {
            self.replacement_checkpoint(false);
            let prefixes = match (&widened, self.group_ribs.get(&gid)) {
                (Some(widened), Some(group)) if group.per_client_best => widened,
                _ => best_changed,
            };
            if prefixes.is_empty() {
                continue;
            }
            let mut out = self.stage_group_prefixes(gid, prefixes, memo);
            // Built here (the fanout path) and not inside the staging
            // pass: `join_group`'s table-build pass discards its output.
            out.build_shared_emit(&mut |force| self.replacement_checkpoint(force));
            staged.insert(gid, out);
        }
        // The staging commit is the one lane mutation site outside the
        // membership lifecycle (which refreshes via the gauge sweep).
        self.refresh_lane_gauge();
        self.replacement_checkpoint(true);
        drop(widened);
        self.replacement_checkpoint(true);
        staged
    }

    /// One shared export-tail pass for `gid` over `prefixes`, reusing
    /// `distribute_single_best_prefix` with split horizon lifted out
    /// (`ExportTarget::Group`) and the group table as the diff baseline
    /// — the SAME body as the per-peer path, parameterized, never
    /// copied (design risk 1). Deltas are committed before returning;
    /// tombstones extend when a member is already dirty.
    #[expect(
        clippy::too_many_lines,
        reason = "one staging pass keeps the plain single-best arm and the ADR-0126 \
                  per-client-best arm over the same commit block"
    )]
    pub(super) fn stage_group_prefixes(
        &mut self,
        gid: usize,
        prefixes: &HashSet<Prefix>,
        memo: &mut crate::manager::distribution::ExportMemo,
    ) -> GroupStageOutput {
        self.replacement_checkpoint(true);
        let mut out = GroupStageOutput::default();
        out.deltas.reserve_exact(prefixes.len());
        self.replacement_checkpoint(true);
        let mut labeled_filtered: Vec<(PolicyFilteredRouteKey, Option<PolicyLabel>)> = Vec::new();
        let mut lane_updates: Vec<(Prefix, Option<RunnerUp>)> = Vec::new();
        let mut result = crate::manager::distribution::UnicastDistributionResult::default();
        let mut per_client_best_result =
            crate::manager::distribution::UnicastDistributionResult::default();
        let per_client_best;
        {
            let Some(group) = self.group_ribs.get(&gid) else {
                return out;
            };
            per_client_best = group.per_client_best;
            if per_client_best {
                self.replacement_checkpoint(true);
                lane_updates.reserve_exact(prefixes.len());
                self.replacement_checkpoint(true);
            }
            // `share()`, not `clone()`: evaluations through the group
            // handle must land in the installed chain's ADR-0096 term
            // hit counters, exactly like the per-peer path's handle.
            let chain = group.export_chain.as_ref().map(PolicyChain::share);
            for prefix in prefixes {
                self.replacement_checkpoint(false);
                let old_source = group.table.get(prefix, 0).map(|r| r.peer);
                if group.per_client_best {
                    // ADR-0126 Decision 2: first-permitted winner walk
                    // + runner-up lane.
                    let deltas_before = out.deltas.len();
                    let stage = Self::distribute_group_per_client_best_prefix(
                        &self.ribs,
                        &self.unicast_prefix_peers,
                        &group.table,
                        &self.peer_is_rr_client,
                        prefix,
                        group.is_ebgp,
                        group.interpret_rfc1997,
                        group.is_rr_client,
                        group.local_role,
                        self.cluster_id,
                        Some(&group.sendable),
                        Some(&group.llgr),
                        chain.as_ref(),
                        memo,
                        &mut out.evals,
                        &mut per_client_best_result,
                        &mut out.otc_blocked,
                    );
                    // The winner announce (at most one — the walk
                    // stages a single `path_id 0` winner), captured
                    // for the lane-transition supersession decision.
                    let winner_announce = per_client_best_result
                        .announce
                        .first()
                        .map(|route| route.peer);
                    for (route, nh) in per_client_best_result
                        .announce
                        .drain(..)
                        .zip(per_client_best_result.next_hop_override.drain(..))
                    {
                        out.deltas.push(GroupDelta {
                            prefix: *prefix,
                            path_id: route.path_id,
                            new: Some((route, nh)),
                            old_source,
                            policy_label: stage.winner_label.clone(),
                            source_attrs: stage.winner_source_attrs.clone(),
                            lane: stage.runner_up.clone(),
                        });
                    }
                    for (p, path_id) in per_client_best_result.withdraw.drain(..) {
                        out.deltas.push(GroupDelta {
                            prefix: p,
                            path_id,
                            new: None,
                            old_source,
                            policy_label: None,
                            source_attrs: None,
                            lane: None,
                        });
                    }
                    // Winner-side tag-only transition, mirroring the
                    // plain arm's hook below: the pass staged nothing
                    // for this prefix (winner equality-suppressed)
                    // while the WINNER's source control communities
                    // moved — rs-control members' verdicts on the
                    // staged entry may flip with no wire change.
                    if out.deltas.len() == deltas_before
                        && let Some(transition) =
                            group.rs_tag_transition(*prefix, stage.winner_source_attrs.as_ref())
                    {
                        if out.rs_transitions.capacity() == 0 {
                            self.replacement_checkpoint(true);
                            out.rs_transitions.reserve_exact(prefixes.len());
                            self.replacement_checkpoint(true);
                        }
                        out.rs_transitions.push(transition);
                    }
                    // Lane transition (ADR-0126 Decision 5), equality-
                    // suppressed against the PRIOR lane entry:
                    // `routes_equal` includes the source peer, so a
                    // content-equal same-source reinstall is suppressed
                    // while a source flip never is. The SOURCE control
                    // communities must also be equal: lane entries
                    // carry source attributes so rs-control tag
                    // transitions extend to them — a control-community
                    // change the chain erases post-policy would
                    // otherwise flip `source(w)`'s suppress/prepend
                    // verdict with no recorded transition. The
                    // recomputed lane commits below regardless
                    // (Decision 6).
                    let prior = group.runner_up.get(prefix);
                    let (content_unchanged, control_unchanged) = match (prior, &stage.runner_up) {
                        (Some(old), Some(new)) => (
                            routes_equal(&old.route, &new.route),
                            source_control_input(old.source_attrs.as_ref())
                                == source_control_input(new.source_attrs.as_ref()),
                        ),
                        (None, None) => (true, true),
                        _ => (false, true),
                    };
                    if !(content_unchanged && control_unchanged) {
                        // The member the transition emits toward: the
                        // new entry's winner source, or the REPLACED
                        // entry's for a retire (how the retire arm
                        // knows `source(w)` — lane-only when the
                        // winner is unchanged, the OLD winner source
                        // on all-candidates-gone). Cleared when the
                        // winner announce delta's own arms already
                        // rewrite the target's slot: toward its NEW
                        // source (which reads `GroupDelta::lane`
                        // directly), and toward any OTHER member as
                        // the flip-away `w'` announce.
                        let target = stage
                            .runner_up
                            .as_ref()
                            .map(|entry| entry.winner_source)
                            .or_else(|| prior.map(|entry| entry.winner_source));
                        let emit_target = target.filter(|target| match winner_announce {
                            Some(source) => {
                                if stage.runner_up.is_some() {
                                    // Announce lane arm: superseded
                                    // unless the winner source is
                                    // unchanged (same-source content
                                    // change — the winner arm skips
                                    // its own source's slot).
                                    old_source == Some(*target)
                                } else {
                                    // Retire arm: superseded when the
                                    // winner flipped away from the
                                    // target (it receives `w'`).
                                    source == *target
                                }
                            }
                            None => true,
                        });
                        if out.lane_deltas.capacity() == 0 {
                            self.replacement_checkpoint(true);
                            out.lane_deltas.reserve_exact(prefixes.len());
                            self.replacement_checkpoint(true);
                        }
                        out.lane_deltas.push(LaneDelta {
                            prefix: *prefix,
                            new: stage.runner_up.clone(),
                            old_source: prior.map(|entry| entry.route.peer),
                            emit_target,
                            prior_source_attrs: prior.and_then(|entry| entry.source_attrs.clone()),
                            content_unchanged,
                        });
                    }
                    lane_updates.push((*prefix, stage.runner_up));
                    continue;
                }
                // RFC 7947 decisions at the member-emit seams are made
                // on the pre-policy SOURCE (the Loc-RIB best this pass
                // stages from); capture its attributes for the deltas
                // and the table residue.
                let source_attrs = self.loc_rib.get(prefix).and_then(capture_source_attrs);
                let deltas_before = out.deltas.len();
                let mut target = crate::manager::distribution::ExportTarget::Group {
                    evals: &mut out.evals,
                    local_role: group.local_role,
                    otc_blocked: &mut out.otc_blocked,
                };
                Self::distribute_single_best_prefix(
                    &self.loc_rib,
                    &group.table,
                    &self.peer_is_rr_client,
                    prefix,
                    &mut target,
                    group.is_ebgp,
                    group.interpret_rfc1997,
                    // Group staging is rs-control-agnostic: control
                    // communities diverge per TARGET, so they are
                    // enforced at the member-emit seams (LAN-474 —
                    // matrix walk, resync, join/refresh replay), never
                    // against the shared staged winner.
                    None,
                    group.is_rr_client,
                    self.cluster_id,
                    Some(&group.sendable),
                    Some(&group.llgr),
                    chain.as_ref(),
                    None, // ORF disqualifies from grouping — never present here
                    memo,
                    &mut result,
                    false,
                );
                // Single-best stages at most one evaluation per prefix;
                // its decision-attribution label tags the staged entry (or
                // the denial residue) for join-time counter replay.
                let label = out.evals.take_last().and_then(|(label, _, _)| label);
                for (route, nh) in result
                    .announce
                    .drain(..)
                    .zip(result.next_hop_override.drain(..))
                {
                    out.deltas.push(GroupDelta {
                        prefix: *prefix,
                        path_id: route.path_id,
                        new: Some((route, nh)),
                        old_source,
                        policy_label: label.clone(),
                        source_attrs: source_attrs.clone(),
                        lane: None,
                    });
                }
                for (p, path_id) in result.withdraw.drain(..) {
                    out.deltas.push(GroupDelta {
                        prefix: p,
                        path_id,
                        new: None,
                        old_source,
                        policy_label: None,
                        source_attrs: None,
                        lane: None,
                    });
                }
                if out.deltas.len() == deltas_before
                    && let Some(transition) =
                        group.rs_tag_transition(*prefix, source_attrs.as_ref())
                {
                    if out.rs_transitions.capacity() == 0 {
                        self.replacement_checkpoint(true);
                        out.rs_transitions.reserve_exact(prefixes.len());
                        self.replacement_checkpoint(true);
                    }
                    out.rs_transitions.push(transition);
                }
                if labeled_filtered.capacity() == 0 && !result.policy_filtered.is_empty() {
                    self.replacement_checkpoint(true);
                    labeled_filtered.reserve_exact(prefixes.len());
                    self.replacement_checkpoint(true);
                }
                labeled_filtered.extend(
                    result
                        .policy_filtered
                        .drain(..)
                        .map(|key| (key, label.clone())),
                );
            }
        }
        if per_client_best {
            labeled_filtered = per_client_best_result.policy_filtered;
        }
        self.replacement_checkpoint(true);
        let readiness = &self.replacement_readiness;
        let mut checkpoint = || replacement_readiness_checkpoint(readiness, false);
        let group = Self::staged_group_mut(&mut self.group_ribs, gid);
        for delta in &out.deltas {
            checkpoint();
            group.apply_delta(delta);
        }
        // Lane commits live in this commit block ON PURPOSE: the
        // `join_group` table-build pass discards the returned output
        // but must still leave a fully populated lane behind.
        for (prefix, entry) in lane_updates {
            checkpoint();
            group.apply_lane(prefix, entry);
        }
        group.commit_rs_transitions(&out.rs_transitions, &mut checkpoint);
        group.record_otc_blocked(prefixes, &out.otc_blocked, &mut checkpoint);
        group.record_policy_filtered(prefixes, &labeled_filtered, &mut checkpoint);
        if !group.dirty_members.is_empty() {
            for delta in &out.deltas {
                checkpoint();
                if delta.new.is_none() {
                    group.tombstones.insert((delta.prefix, delta.path_id));
                }
            }
            // A member ALREADY dirty when a source flip stages onto it
            // never reaches the per-member matrix (its pass takes the
            // resync arm), so its member-scoped withdraw of the displaced
            // route would be lost: the key stays IN the table (invisible
            // to tombstones) and the resync announces table ∖ own-sourced.
            // Record it as an extra (over-)withdraw at staging; the
            // resync's `member_retains` guard drops it if the source
            // flips back before the resync runs.
            let dirty: Vec<IpAddr> = group
                .dirty_members
                .iter()
                .map(|member| {
                    checkpoint();
                    *member
                })
                .collect();
            replacement_readiness_checkpoint(readiness, true);
            for member in dirty {
                checkpoint();
                let lost: Vec<(Prefix, u32)> = out
                    .member_scoped_withdraws(member, || {
                        replacement_readiness_checkpoint(readiness, false);
                    })
                    .collect();
                if !lost.is_empty() {
                    self.pending_extra_withdraws
                        .entry(member)
                        .or_default()
                        .unicast
                        .extend(lost.into_iter().inspect(|_| checkpoint()));
                }
            }
            self.refresh_group_residue_gauge();
        }
        self.replacement_checkpoint(true);
        retire_vec(&mut labeled_filtered, &mut || {
            self.replacement_checkpoint(false);
        });
        self.replacement_checkpoint(true);
        out
    }

    /// Run the shared VPN staging pass for every VPN-staging group over
    /// the pass's changed RD+prefix identities. Deltas are committed to
    /// the group tables here; `recompute_and_distribute_vpn` emits them
    /// per member via the RT-pass source-flip matrix (Φ applied at emit
    /// for RTC-negotiated groups).
    pub(in crate::manager) fn stage_vpn_update_groups(
        &mut self,
        changed: &HashSet<VpnRouteKey>,
    ) -> HashMap<usize, VpnGroupStageOutput> {
        let mut staged = HashMap::new();
        if changed.is_empty() || self.group_ribs.is_empty() {
            return staged;
        }
        let gids: Vec<usize> = self
            .group_ribs
            .iter()
            .filter(|(_, group)| {
                self.replacement_checkpoint(false);
                group.stages_vpn()
            })
            .map(|(gid, _)| *gid)
            .collect();
        for gid in gids {
            self.replacement_checkpoint(false);
            staged.insert(gid, self.stage_group_vpn_keys(gid, changed));
        }
        staged
    }

    /// One shared VPN export-tail pass for `gid` over `keys`, reusing
    /// `stage_vpn_routes`'s single-best body with split horizon lifted
    /// out (`ExportTarget::Group`) and the group table's VPN maps as the
    /// diff baseline — the SAME body as the per-peer path, parameterized,
    /// never copied (design risk 1). Deltas are committed before
    /// returning; VPN tombstones extend when a member is already dirty.
    #[expect(
        clippy::too_many_lines,
        reason = "keep staging and its readiness-aware temporary retirement in one transaction"
    )]
    pub(super) fn stage_group_vpn_keys(
        &mut self,
        gid: usize,
        keys: &HashSet<VpnRouteKey>,
    ) -> VpnGroupStageOutput {
        self.replacement_checkpoint(true);
        let mut out = VpnGroupStageOutput {
            deltas: Vec::with_capacity(keys.len()),
            ..VpnGroupStageOutput::default()
        };
        self.replacement_checkpoint(true);
        let mut denials: Vec<(VpnRouteKey, VpnDenialRecord)> = Vec::new();
        {
            let Some(group) = self.group_ribs.get(&gid) else {
                return out;
            };
            // `share()`, not `clone()` — ADR-0096 term hit counters, as
            // in `stage_group_prefixes`.
            let chain = group.export_chain.as_ref().map(PolicyChain::share);
            let mut announce: Vec<VpnRibRoute> = Vec::new();
            let mut withdraw: Vec<VpnRibRouteKey> = Vec::new();
            let mut ignored_otc_blocked = Vec::new();
            let context = crate::manager::VpnLabeledStagingContext {
                loc_rib: &self.loc_rib,
                ribs: &self.ribs,
                rib_out: &group.table,
                peer_is_rr_client: &self.peer_is_rr_client,
                target_is_ebgp: group.is_ebgp,
                interpret_rfc1997: group.interpret_rfc1997,
                target_is_rr_client: group.is_rr_client,
                cluster_id: self.cluster_id,
                sendable: Some(&group.sendable),
                llgr: Some(&group.llgr),
                orr_ctx: None,              // ORR disqualifies from grouping.
                add_path_send_max: 0,       // Add-Path send disqualifies from grouping.
                add_path_send_limits: None, // Effective cap is inapplicable to grouped peers.
                add_path_send_families: &[],
                export_pol: chain.as_ref(),
                force: false,
            };
            // Reused single-key set: the staging body iterates a key set,
            // but the delta needs per-key `old` capture and eval labels.
            let mut key_set: HashSet<VpnRouteKey> = HashSet::with_capacity(1);
            for key in keys {
                self.replacement_checkpoint(false);
                key_set.clear();
                key_set.insert(*key);
                let mut target = crate::manager::distribution::ExportTarget::Group {
                    evals: &mut out.evals,
                    local_role: group.local_role,
                    otc_blocked: &mut ignored_otc_blocked,
                };
                Self::stage_vpn_routes(
                    &context,
                    &key_set,
                    &mut target,
                    // RT gate deferred to member emit: Φ is per-member
                    // state, applied by the RT-pass matrix (the delta
                    // carries `old` for exactly that).
                    None,
                    &mut announce,
                    &mut withdraw,
                );
                // Single-best stages at most one eval per key: a Permit
                // labels the staged entry; a Deny lands in the persistent
                // denial residue (join-time counter replay).
                let last = out.evals.take_last();
                let label = match &last {
                    Some((label, PolicyAction::Permit, _)) => label.clone(),
                    _ => None,
                };
                if let Some((label, PolicyAction::Deny, source)) = last {
                    // The evaluated route is the Loc-RIB best (group
                    // targets never carry ORR); its RTs let an RTC
                    // member's join replay Φ-gate the denial.
                    let rts = self
                        .loc_rib
                        .get_vpn(key)
                        .map(|best| best.extended_communities().to_vec())
                        .unwrap_or_default();
                    denials.push((*key, (source, label, rts)));
                }
                if announce.is_empty() && withdraw.is_empty() {
                    continue;
                }
                // Prior staged entry, cloned before commit — one clone
                // per delta, total (slice 2's Φ(old) input).
                let old = group
                    .table
                    .get_vpn(&VpnRibRouteKey {
                        nlri_key: *key,
                        path_id: 0,
                    })
                    .cloned();
                for route in announce.drain(..) {
                    out.deltas.push(VpnGroupDelta {
                        key: *key,
                        new: Some(route),
                        old: old.clone(),
                        policy_label: label.clone(),
                    });
                }
                for rib_key in withdraw.drain(..) {
                    debug_assert_eq!(rib_key.path_id, 0, "group table stages path 0 only");
                    out.deltas.push(VpnGroupDelta {
                        key: *key,
                        new: None,
                        old: old.clone(),
                        policy_label: None,
                    });
                }
            }
            retire_vec(&mut ignored_otc_blocked, &mut || {
                self.replacement_checkpoint(false);
            });
            self.replacement_checkpoint(true);
        }
        self.replacement_checkpoint(true);
        let readiness = &self.replacement_readiness;
        let checkpoint = || replacement_readiness_checkpoint(readiness, false);
        let group = Self::staged_group_mut(&mut self.group_ribs, gid);
        for delta in &out.deltas {
            checkpoint();
            group.apply_vpn_delta(delta);
        }
        // Denial-residue transition scope: this pass's keys replace their
        // prior records (the `record_policy_filtered` shape).
        group.vpn_policy_denied.retain(|key, _| {
            checkpoint();
            !keys.contains(key)
        });
        group
            .vpn_policy_denied
            .extend(denials.into_iter().inspect(|_| checkpoint()));
        if !group.dirty_members.is_empty() {
            group.vpn_tombstones.extend(
                out.deltas
                    .iter()
                    .filter(|d| {
                        checkpoint();
                        d.new.is_none()
                    })
                    .map(|d| d.key),
            );
            self.refresh_group_residue_gauge();
        }
        self.replacement_checkpoint(true);
        out
    }
}
