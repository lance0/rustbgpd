use super::{
    GroupDelta, GroupStageOutput, HashMap, HashSet, IpAddr, LaneDelta, NextHopAction, PolicyAction,
    PolicyChain, PolicyFilteredRouteKey, PolicyLabel, Prefix, RibManager, Route, RunnerUp,
    VpnDenialRecord, VpnGroupDelta, VpnGroupStageOutput, VpnRibRoute, VpnRibRouteKey, VpnRouteKey,
    capture_source_attrs, routes_equal, source_control_input,
};

impl RibManager {
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
        let widened: Option<HashSet<Prefix>> = (!all_affected.is_empty()
            && self.group_ribs.values().any(|group| group.per_client_best))
        .then(|| best_changed.union(all_affected).copied().collect());
        let gids: Vec<usize> = self.group_ribs.keys().copied().collect();
        for gid in gids {
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
            out.build_shared_emit();
            staged.insert(gid, out);
        }
        // The staging commit is the one lane mutation site outside the
        // membership lifecycle (which refreshes via the gauge sweep).
        self.refresh_lane_gauge();
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
        let mut out = GroupStageOutput::default();
        let mut labeled_filtered: Vec<(PolicyFilteredRouteKey, Option<PolicyLabel>)> = Vec::new();
        let mut lane_updates: Vec<(Prefix, Option<RunnerUp>)> = Vec::new();
        {
            let Some(group) = self.group_ribs.get(&gid) else {
                return out;
            };
            // `share()`, not `clone()`: evaluations through the group
            // handle must land in the installed chain's ADR-0096 term
            // hit counters, exactly like the per-peer path's handle.
            let chain = group.export_chain.as_ref().map(PolicyChain::share);
            let mut announce: Vec<Route> = Vec::new();
            let mut withdraw: Vec<(Prefix, u32)> = Vec::new();
            let mut nh_flags: Vec<Option<NextHopAction>> = Vec::new();
            let mut filtered: Vec<PolicyFilteredRouteKey> = Vec::new();
            for prefix in prefixes {
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
                        &mut announce,
                        &mut withdraw,
                        &mut nh_flags,
                        &mut labeled_filtered,
                        &mut out.otc_blocked,
                    );
                    // The winner announce (at most one — the walk
                    // stages a single `path_id 0` winner), captured
                    // for the lane-transition supersession decision.
                    let winner_announce = announce.first().map(|route| route.peer);
                    for (route, nh) in announce.drain(..).zip(nh_flags.drain(..)) {
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
                    for (p, path_id) in withdraw.drain(..) {
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
                    &mut announce,
                    &mut withdraw,
                    &mut nh_flags,
                    &mut filtered,
                    false,
                );
                // Single-best stages at most one evaluation per prefix;
                // its terminal-policy label tags the staged entry (or
                // the denial residue) for join-time counter replay.
                let label = out.evals.take_last().and_then(|(label, _, _)| label);
                for (route, nh) in announce.drain(..).zip(nh_flags.drain(..)) {
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
                for (p, path_id) in withdraw.drain(..) {
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
                    out.rs_transitions.push(transition);
                }
                labeled_filtered.extend(filtered.drain(..).map(|key| (key, label.clone())));
            }
        }
        let group = self
            .group_ribs
            .get_mut(&gid)
            .expect("group staged above still exists");
        for delta in &out.deltas {
            group.apply_delta(delta);
        }
        // Lane commits live in this commit block ON PURPOSE: the
        // `join_group` table-build pass discards the returned output
        // but must still leave a fully populated lane behind.
        for (prefix, entry) in lane_updates {
            group.apply_lane(prefix, entry);
        }
        group.commit_rs_transitions(&out.rs_transitions);
        group.record_otc_blocked(prefixes, &out.otc_blocked);
        group.record_policy_filtered(prefixes, &labeled_filtered);
        if !group.dirty_members.is_empty() {
            let withdrawn: Vec<(Prefix, u32)> = out.withdrawn_keys().collect();
            group.tombstones.extend(withdrawn);
            // A member ALREADY dirty when a source flip stages onto it
            // never reaches the per-member matrix (its pass takes the
            // resync arm), so its member-scoped withdraw of the displaced
            // route would be lost: the key stays IN the table (invisible
            // to tombstones) and the resync announces table ∖ own-sourced.
            // Record it as an extra (over-)withdraw at staging; the
            // resync's `member_retains` guard drops it if the source
            // flips back before the resync runs.
            let dirty: Vec<IpAddr> = group.dirty_members.iter().copied().collect();
            for member in dirty {
                let lost: Vec<(Prefix, u32)> = out.member_scoped_withdraws(member).collect();
                if !lost.is_empty() {
                    self.pending_extra_withdraws
                        .entry(member)
                        .or_default()
                        .unicast
                        .extend(lost);
                }
            }
            self.refresh_group_residue_gauge();
        }
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
            .filter(|(_, group)| group.stages_vpn())
            .map(|(gid, _)| *gid)
            .collect();
        for gid in gids {
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
    pub(super) fn stage_group_vpn_keys(
        &mut self,
        gid: usize,
        keys: &HashSet<VpnRouteKey>,
    ) -> VpnGroupStageOutput {
        let mut out = VpnGroupStageOutput::default();
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
            // Reused single-key set: the staging body iterates a key set,
            // but the delta needs per-key `old` capture and eval labels.
            let mut key_set: HashSet<VpnRouteKey> = HashSet::with_capacity(1);
            for key in keys {
                key_set.clear();
                key_set.insert(*key);
                let mut target = crate::manager::distribution::ExportTarget::Group {
                    evals: &mut out.evals,
                    local_role: group.local_role,
                    otc_blocked: &mut ignored_otc_blocked,
                };
                Self::stage_vpn_routes(
                    &self.loc_rib,
                    &self.ribs,
                    &group.table,
                    &self.peer_is_rr_client,
                    &key_set,
                    &mut target,
                    group.is_ebgp,
                    group.interpret_rfc1997,
                    group.is_rr_client,
                    self.cluster_id,
                    Some(&group.sendable),
                    Some(&group.llgr),
                    // RT gate deferred to member emit: Φ is per-member
                    // state, applied by the RT-pass matrix (the delta
                    // carries `old` for exactly that).
                    None,
                    None, // ORR disqualifies from grouping
                    0,    // Add-Path send disqualifies from grouping
                    None, // Effective cap is inapplicable to grouped peers.
                    &[],
                    chain.as_ref(),
                    &mut announce,
                    &mut withdraw,
                    false,
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
        }
        let group = self
            .group_ribs
            .get_mut(&gid)
            .expect("group staged above still exists");
        for delta in &out.deltas {
            group.apply_vpn_delta(delta);
        }
        // Denial-residue transition scope: this pass's keys replace their
        // prior records (the `record_policy_filtered` shape).
        group.vpn_policy_denied.retain(|key, _| !keys.contains(key));
        group.vpn_policy_denied.extend(denials);
        if !group.dirty_members.is_empty() {
            group
                .vpn_tombstones
                .extend(out.deltas.iter().filter(|d| d.new.is_none()).map(|d| d.key));
            self.refresh_group_residue_gauge();
        }
        out
    }
}
