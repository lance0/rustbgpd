use super::{
    BatchedMemberSupplement, BatchedTransitionCounters, BatchedTransitionInventory,
    CleanPolicyTransitionInventory, CleanPolicyTransitionInventoryBuilder, FxHashMap, GroupKey,
    GroupMembership, GroupRibOut, HashSet, IpAddr, LargeCommunity, NextHopAction, PolicyAction,
    PolicyChain, PolicyTransitionGroupStart, Prefix, RibManager, Route, UpdateGroupClassification,
    classify_update_group, routes_equal, source_control_input,
};

impl RibManager {
    /// Snapshot route identities for the strict clean transition inventory.
    /// Dirty state or private-family participation rejects the optimization
    /// before a member is moved or an envelope is emitted.
    pub(in crate::manager) fn begin_clean_policy_transition_inventory(
        &self,
        source: usize,
        destination: usize,
    ) -> Option<Vec<(Prefix, u32)>> {
        let clean = |group: &GroupRibOut| {
            // Per-client-best groups are excluded from the ADR-0105 narrow
            // fast path outright — its clean predicate (zero
            // policy-filtered routes on both sides) contradicts the
            // mitigation's reason to exist. Re-inclusion is demand-gated
            // (ADR-0126 Decision 8).
            !group.per_client_best
                && group.dirty_members.is_empty()
                && group.tombstones.is_empty()
                && group.vpn_tombstones.is_empty()
                && group.table.vpn_len() == 0
                && group.policy_filtered.is_empty()
                && group.vpn_policy_denied.is_empty()
                && group.otc_blocked.is_empty()
        };
        let old = self.group_ribs.get(&source)?;
        let new = self.group_ribs.get(&destination)?;
        if !clean(old) || !clean(new) || old.table.len() != new.table.len() {
            return None;
        }
        Some(
            new.table
                .iter()
                .map(|route| (route.prefix, route.path_id))
                .collect(),
        )
    }

    /// Accumulate one bounded key chunk. A withdrawal, source flip, or table
    /// drift rejects the complete optimized plan before emission — and so
    /// does a control-form community (RFC 7947 §2.3.2) for any of the
    /// cohort's RS ASNs (`rs_asns`), on EITHER side of policy: the source
    /// residue drives per-target suppression/prepend even when policy
    /// strips the tag from the post-policy route, and a policy-added tag
    /// needs the per-target scrub. Untagged (the overwhelming case) is
    /// proven in this same single walk, so rs-control members ride the
    /// shared cohort at zero extra passes; a tagged inventory hands the
    /// whole cohort to the authoritative per-peer path, whose emit seams
    /// apply the per-target filter.
    pub(in crate::manager) fn extend_clean_policy_transition_inventory(
        &self,
        source: usize,
        destination: usize,
        keys: &[(Prefix, u32)],
        rs_asns: &[u32],
        inventory: &mut CleanPolicyTransitionInventoryBuilder,
    ) -> Option<()> {
        use crate::manager::distribution::rs_control::rs_control_route_tagged;
        let old = self.group_ribs.get(&source)?;
        let new = self.group_ribs.get(&destination)?;
        // Fold permit counts per chunk keyed by borrowed labels, then merge
        // into the owned builder maps once: the per-route path used to clone
        // the `Option<String>` label twice per route, which dominated this
        // walk at reload-stall scale. The merge clones one label per
        // distinct (label) / (source, label) pair per chunk instead.
        let mut chunk_totals: FxHashMap<Option<&str>, u64> = FxHashMap::default();
        let mut chunk_by_source: FxHashMap<IpAddr, FxHashMap<Option<&str>, u64>> =
            FxHashMap::default();
        // Run-length fold for the permit counters: tables interleave far
        // fewer (source, label) flips than routes (contiguous prefix blocks
        // from one source are the common shape), so accumulate runs and
        // touch the maps once per flip instead of twice per route.
        let mut run: Option<(IpAddr, Option<&str>, u64)> = None;
        for &(prefix, path_id) in keys {
            let route = new.table.get(&prefix, path_id)?;
            let key = (prefix, path_id);
            let prior = old.table.get(&prefix, path_id)?;
            if prior.peer != route.peer {
                return None;
            }
            let next_hop = new.nh_override(key);
            if !routes_equal(prior, route) || old.nh_override(key) != next_hop {
                if !rs_asns.is_empty() {
                    let (old_communities, old_large) = old.source_control(key);
                    let (new_communities, new_large) = new.source_control(key);
                    let tagged = rs_asns.iter().any(|&rs_asn| {
                        rs_control_route_tagged(
                            route.communities(),
                            route.large_communities(),
                            rs_asn,
                        ) || rs_control_route_tagged(old_communities, old_large, rs_asn)
                            || rs_control_route_tagged(new_communities, new_large, rs_asn)
                    });
                    if tagged {
                        return None;
                    }
                }
                inventory.announce.push(route.clone());
                inventory.next_hop_override.push(next_hop);
            }

            let label = new
                .staged_labels
                .get(&key)
                .and_then(|label| label.as_deref());
            run = Some(match run {
                Some((peer, run_label, count)) if peer == route.peer && run_label == label => {
                    (peer, run_label, count + 1)
                }
                Some((peer, run_label, count)) => {
                    *chunk_totals.entry(run_label).or_default() += count;
                    *chunk_by_source
                        .entry(peer)
                        .or_default()
                        .entry(run_label)
                        .or_default() += count;
                    (route.peer, label, 1)
                }
                None => (route.peer, label, 1),
            });
        }
        if let Some((peer, run_label, count)) = run {
            *chunk_totals.entry(run_label).or_default() += count;
            *chunk_by_source
                .entry(peer)
                .or_default()
                .entry(run_label)
                .or_default() += count;
        }
        for (label, count) in chunk_totals {
            *inventory
                .permit_totals
                .entry(label.map(str::to_owned))
                .or_default() += count;
        }
        for (peer, counts) in chunk_by_source {
            let by_source = inventory.permit_by_source.entry(peer).or_default();
            for (label, count) in counts {
                *by_source.entry(label.map(str::to_owned)).or_default() += count;
            }
        }
        Some(())
    }

    /// Apply the inventory's pre-aggregated permit counts to one member after
    /// its writer slot has been reserved. This preserves the existing grouped
    /// split-horizon counter semantics without another full-table walk.
    pub(in crate::manager) fn apply_clean_policy_transition_counters(
        &mut self,
        peer: IpAddr,
        inventory: &CleanPolicyTransitionInventory,
    ) {
        let own = inventory.permit_by_source.get(&peer);
        let rows = inventory
            .permit_totals
            .iter()
            .filter_map(|(label, total)| {
                let count = total.saturating_sub(
                    own.and_then(|counts| counts.get(label))
                        .copied()
                        .unwrap_or(0),
                );
                (count > 0).then_some((label.clone(), PolicyAction::Permit, count))
            })
            .collect::<Vec<_>>();
        self.bump_export_counters(peer, &rows);
    }

    /// Whether a source/destination group pair qualifies for the shared
    /// batched authoritative transition: unicast-only on both sides and
    /// differing only in export-chain content (the clean transition's
    /// narrow shape, checked on the interned keys).
    pub(in crate::manager) fn batched_transition_keys_qualify(
        &self,
        source: usize,
        destination: usize,
    ) -> bool {
        let (Some(source_key), Some(destination_key)) = (
            self.update_groups.group_key(source),
            self.update_groups.group_key(destination),
        ) else {
            return false;
        };
        source_key.is_unicast_only()
            && destination_key.is_unicast_only()
            && source_key.same_staging_profile_except_chain(destination_key)
    }

    /// The fingerprint itself: disqualifiers first (design §1), then
    /// the group key from RIB-staging inputs.
    pub(in crate::manager) fn compute_update_group_membership(
        &mut self,
        peer: IpAddr,
    ) -> GroupMembership {
        let chain = self.export_policy_for(peer).cloned();
        self.compute_update_group_membership_for_policy(peer, chain.as_ref())
    }

    /// Classify a prospective policy without changing the peer's installed
    /// policy or runtime membership. Registry interning is append-only and
    /// observational; no group table or wire state is touched here.
    fn compute_update_group_membership_for_policy(
        &mut self,
        peer: IpAddr,
        chain: Option<&PolicyChain>,
    ) -> GroupMembership {
        // Differential-oracle hook: force every peer onto the per-peer
        // fallback path so identical scenarios can be compared grouped
        // vs ungrouped. Reuses the policy-peer-context reason label.
        #[cfg(test)]
        if self.test_force_ungrouped {
            return GroupMembership::PolicyPeerContext;
        }
        // Slow-peer isolation (LAN-470): a transport-flagged slow peer
        // stays on the per-peer path so its backlog cannot drag the
        // shared staging pass. Checked before the classifier — it
        // overrides an otherwise-groupable fingerprint.
        if self.slow_isolated_peers.contains(&peer) {
            return GroupMembership::SlowPeer;
        }
        // ORF-receive negotiated ⇒ ungrouped from the start (the RFC
        // 5291 §6 gate never meets grouping). Read from the live
        // session record — `peer_orf_pending` drains as gates lift, so
        // it can't answer "was ORF negotiated" later in the session.
        let orf_negotiated = self
            .live_sessions
            .get(&peer)
            .and_then(|sessions| sessions.last())
            .is_some_and(|record| !record.negotiated_orf_recv.is_empty());
        let input = self.update_group_classifier_input(
            peer,
            chain,
            orf_negotiated || self.peer_orf_filters.contains_key(&peer),
            false,
        );
        let fingerprint = match classify_update_group(input) {
            UpdateGroupClassification::PolicyPeerContext => {
                return GroupMembership::PolicyPeerContext;
            }
            UpdateGroupClassification::AddPathSend => return GroupMembership::AddPathSend,
            UpdateGroupClassification::PerClientBest => return GroupMembership::PerClientBest,
            UpdateGroupClassification::OrrVantage => return GroupMembership::OrrVantage,
            UpdateGroupClassification::OrfInstalled => return GroupMembership::OrfInstalled,
            UpdateGroupClassification::Groupable(fingerprint) => fingerprint,
        };

        // Clone released before the &mut intern below; chains are small
        // and this runs at config/session-lifecycle frequency only.
        let chain_idx = chain.map(|chain| self.update_groups.intern_chain(chain));
        let key = GroupKey {
            chain: chain_idx,
            target_is_ebgp: fingerprint.target_is_ebgp,
            target_is_rr_client: fingerprint.target_is_rr_client,
            target_local_role: fingerprint.target_local_role,
            interpret_rfc1997: fingerprint.interpret_rfc1997,
            sendable_ipv4_unicast: fingerprint.sendable_ipv4_unicast,
            sendable_ipv6_unicast: fingerprint.sendable_ipv6_unicast,
            sendable_vpnv4: fingerprint.sendable_vpnv4,
            sendable_vpnv6: fingerprint.sendable_vpnv6,
            rtc_negotiated: fingerprint.rtc_negotiated,
            per_client_best: fingerprint.per_client_best,
            llgr_families: fingerprint.llgr_families,
        };
        GroupMembership::Grouped(self.update_groups.group_for(key))
    }

    /// Preflight the prospective group id for a clean unicast-only policy
    /// transition and prove that only the chain dimension changes.
    pub(in crate::manager) fn clean_policy_transition_destination(
        &mut self,
        peer: IpAddr,
        policy: Option<&PolicyChain>,
    ) -> Option<(usize, usize)> {
        let GroupMembership::Grouped(source) = self.update_groups.members.get(&peer)? else {
            return None;
        };
        let source = *source;
        // A per-client-best source group never takes the ADR-0105 fast
        // path — nor its unfenced destination prestage, whose only
        // preflight is this function. Checked on the source cell: the
        // ADR-0126 `per_client_best` key bit keeps source and
        // destination in agreement, so rejecting the source here also
        // keeps every destination cell the prestage creates plain.
        // Re-inclusion is demand-gated (ADR-0126 Decision 8).
        if self
            .group_ribs
            .get(&source)
            .is_some_and(|group| group.per_client_best)
        {
            return None;
        }
        let GroupMembership::Grouped(destination) =
            self.compute_update_group_membership_for_policy(peer, policy)
        else {
            return None;
        };
        let source_key = self.update_groups.group_key(source)?;
        let destination_key = self.update_groups.group_key(destination)?;
        (source != destination
            && source_key.is_unicast_only()
            && destination_key.is_unicast_only()
            && source_key.same_staging_profile_except_chain(destination_key))
        .then_some((source, destination))
    }

    /// Create an unowned prospective destination group and return its prefix
    /// staging snapshot. An existing destination is already maintained and
    /// therefore needs no staging (`None`).
    pub(in crate::manager) fn begin_policy_transition_group(
        &mut self,
        gid: usize,
        peer: IpAddr,
        export_policy: Option<&PolicyChain>,
    ) -> PolicyTransitionGroupStart {
        if self.group_ribs.contains_key(&gid) {
            return PolicyTransitionGroupStart::Maintained;
        }
        let group = GroupRibOut::new(
            export_policy.map(PolicyChain::share),
            self.peer_is_ebgp.get(&peer).copied().unwrap_or(false),
            self.peer_interpret_rfc1997.contains(&peer),
            self.peer_is_rr_client.get(&peer).copied().unwrap_or(false),
            self.peer_local_roles.get(&peer).copied().flatten(),
            self.peer_sendable_families
                .get(&peer)
                .cloned()
                .unwrap_or_default(),
            self.peer_advertised_llgr_families
                .get(&peer)
                .cloned()
                .unwrap_or_default(),
            // ADR-0126 Decision 1: derived from the key bit. In
            // practice always false here — per-client-best SOURCE
            // groups never pass the fast-path preflight (Decision 8),
            // and the key bit keeps source and destination in
            // agreement.
            self.update_groups
                .group_key(gid)
                .is_some_and(|key| key.per_client_best),
            self.loc_rib.len(),
        );
        self.group_ribs.insert(gid, group);
        PolicyTransitionGroupStart::Created(
            self.loc_rib
                .iter()
                .map(|route| route.prefix)
                .collect::<HashSet<_>>()
                .into_iter()
                .collect(),
        )
    }

    /// Stage one bounded prefix chunk into an unowned destination group.
    pub(in crate::manager) fn stage_policy_transition_group_chunk(
        &mut self,
        gid: usize,
        prefixes: &[Prefix],
        memo: &mut crate::manager::distribution::ExportMemo,
    ) {
        let prefixes = prefixes.iter().copied().collect::<HashSet<_>>();
        let _ = self.stage_group_prefixes(gid, &prefixes, memo);
    }

    /// Remove a partially or fully staged, still-unowned destination before
    /// the caller hands the transition back to the authoritative per-peer path.
    pub(in crate::manager) fn discard_uncommitted_policy_transition_group(
        &mut self,
        gid: usize,
    ) -> bool {
        let removable = self
            .group_ribs
            .get(&gid)
            .is_none_or(|group| group.members.is_empty());
        if removable {
            self.group_ribs.remove(&gid);
        }
        removable
    }

    /// Commit a preflighted clean transition after every writer slot and exact
    /// snapshot has been validated. No regroup baseline is needed because the
    /// shared transition diff is already the authoritative old-to-new wire
    /// delta accepted by every target writer.
    pub(in crate::manager) fn commit_clean_policy_transition_member(
        &mut self,
        peer: IpAddr,
        source: usize,
        destination: usize,
    ) {
        self.leave_group_without_gauge_refresh(source, peer);
        self.update_groups
            .members
            .insert(peer, GroupMembership::Grouped(destination));
        self.install_group_member(destination, peer);
        self.metrics.record_update_group_regroup();
    }

    /// Publish cohort-wide gauges once after the synchronous membership commit.
    /// Refreshing them per member is both unobservable (queries cannot
    /// interleave in the commit section) and quadratic for large cohorts.
    pub(in crate::manager) fn finish_clean_policy_transition_commit(&mut self) {
        self.refresh_update_group_gauges();
        self.refresh_group_residue_gauge();
    }

    /// Build the shared old→new inventory for one batched authoritative
    /// cohort transition ([`crate::update::RibUpdate::ReplacePeerExportPoliciesAuthoritatively`]):
    /// every batch member of `source` moves to the freshly staged
    /// `destination` (same staging profile except the chain — validated
    /// by the caller). Returns `None` when the delta carries an RFC 7947
    /// control-form community for one of the cohort's rs-control ASNs on
    /// either side of policy — per-target suppress/prepend/scrub cannot
    /// ride a shared payload, so the caller degrades the cohort to the
    /// ordinary per-member machinery (the clean transition's
    /// tagged-inventory posture).
    ///
    /// The shared announce carries each destination entry whose wire
    /// form differs from the source entry at the same key
    /// (equality-suppressed — O(actual policy diff), a content-equal
    /// restage emits nothing); the shared withdraw carries the keys the
    /// destination no longer stages (over-withdraw safe toward members
    /// whose wire never held them). Per-member divergence is exactly the
    /// ADR-0126 Decision 4 emit-time exception set: split horizon rides
    /// the envelope's `announce_source_exclusion`, and the lane
    /// substitution toward each winner's source rides the member-scoped
    /// supplements built here. Counter aggregates are folded once so the
    /// per-member replay is O(labels), not O(table) — the same rows
    /// [`RibManager::apply_group_join_counters`] would derive per member.
    #[expect(
        clippy::too_many_lines,
        reason = "one walk keeps the shared delta, the lane supplements, the \
                  OTC/rs-control degrade gates, and the counter fold aligned"
    )]
    pub(in crate::manager) fn batched_transition_inventory(
        source: &GroupRibOut,
        destination: &GroupRibOut,
        rs_asns: &[u32],
    ) -> Option<BatchedTransitionInventory> {
        use crate::manager::distribution::rs_control::rs_control_route_tagged;
        // RFC 9234 OTC residue on either side means blocked staged
        // winners (or lane runner-ups) whose per-member diagnostics and
        // withdraw conversions belong to the pre-commit backstop this
        // shared emission does not run — the per-member path owns those.
        // A role-bearing fleet with no OTC-attributed routes (the
        // rendered route-server default) carries no residue and shares.
        if !source.otc_blocked.is_empty() || !destination.otc_blocked.is_empty() {
            return None;
        }
        let attrs_tagged = |attrs: (&[u32], &[LargeCommunity])| {
            rs_asns
                .iter()
                .any(|&rs_asn| rs_control_route_tagged(attrs.0, attrs.1, rs_asn))
        };
        let route_tagged = |route: &Route| {
            rs_asns.iter().any(|&rs_asn| {
                rs_control_route_tagged(route.communities(), route.large_communities(), rs_asn)
            })
        };
        // The pre-commit backstop strips an OTC-blocked route from every
        // emission; an emitted delta containing one cannot ride the
        // shared payload, so its cohort degrades to the per-member path
        // (which runs the backstop at its own seams).
        let blocked = |route: &Route| {
            crate::manager::distribution::otc_egress_blocked(route, destination.local_role)
        };
        let mut announce: Vec<Route> = Vec::new();
        let mut next_hop_override: Vec<Option<NextHopAction>> = Vec::new();
        let mut supplements: FxHashMap<IpAddr, BatchedMemberSupplement> = FxHashMap::default();
        let mut counters = BatchedTransitionCounters::default();
        for route in destination.table.iter() {
            let key = (route.prefix, route.path_id);
            let next_hop = destination.nh_override(key);
            let prior = source.table.get(&route.prefix, route.path_id);
            let changed = match prior {
                None => true,
                Some(prior_route) => {
                    !routes_equal(prior_route, route) || source.nh_override(key) != next_hop
                }
            };
            if changed {
                if blocked(route)
                    || (!rs_asns.is_empty()
                        && (route_tagged(route)
                            || attrs_tagged(destination.source_control(key))
                            || attrs_tagged(source.source_control(key))))
                {
                    return None;
                }
                next_hop_override.push(next_hop);
                announce.push(route.clone());
            }
            // Counter fold: one permit per staged entry, labelled by its
            // retained terminal policy; per-source rows feed the
            // Decision 4 `totals − own + lane` synthesis below.
            let label = destination.staged_labels.get(&key).cloned().unwrap_or(None);
            counters.record_permit(route.peer, label);
            // Member-scoped correction for the slot's own source — the
            // one member the shared exclusion silences at this key. Its
            // wire held `adv_source(m)` (the source group's lane
            // substitution when it also sourced the old winner, the old
            // entry otherwise); its target is the destination lane's
            // substitution or nothing (ADR-0126 Decision 4).
            let lane_new = destination.runner_up.get(&route.prefix);
            let prior_source = prior.map(|prior_route| prior_route.peer);
            let lane_old = source.runner_up.get(&route.prefix);
            if let Some(entry) = lane_new {
                let suppressed = prior_source == Some(route.peer)
                    && lane_old.is_some_and(|prev| {
                        routes_equal(&prev.route, &entry.route) && prev.nh == entry.nh
                    });
                if !suppressed {
                    if blocked(&entry.route)
                        || (!rs_asns.is_empty()
                            && (route_tagged(&entry.route)
                                || attrs_tagged(source_control_input(entry.source_attrs.as_ref()))
                                || lane_old.is_some_and(|prev| {
                                    attrs_tagged(source_control_input(prev.source_attrs.as_ref()))
                                })))
                    {
                        return None;
                    }
                    supplements
                        .entry(route.peer)
                        .or_default()
                        .announce
                        .push((entry.route.clone(), entry.nh.clone()));
                }
            } else {
                // Over-withdraw-safe: emit whenever the source group
                // staged the key and the member's wire could hold
                // anything there (a displaced other-sourced entry — the
                // source-flip arm — or a retired substitution). A no-op
                // when the wire was already empty.
                let had_wire =
                    prior.is_some() && (prior_source != Some(route.peer) || lane_old.is_some());
                if had_wire {
                    supplements
                        .entry(route.peer)
                        .or_default()
                        .withdraw
                        .push(key);
                }
            }
        }
        let mut withdraw: Vec<(Prefix, u32)> = Vec::new();
        for route in source.table.iter() {
            if destination
                .table
                .get(&route.prefix, route.path_id)
                .is_none()
            {
                withdraw.push((route.prefix, route.path_id));
            }
        }
        for entry in destination.runner_up.values() {
            counters.record_lane(entry.winner_source, entry.policy_label.clone());
        }
        for denials in destination.policy_filtered.values() {
            for (&(source_peer, _), label) in denials {
                counters.record_deny(source_peer, label.clone());
            }
        }
        Some(BatchedTransitionInventory {
            announce: announce.into(),
            next_hop_override: next_hop_override.into(),
            withdraw,
            supplements,
            counters,
        })
    }

    /// Replay one cohort member's export counters from the batched
    /// inventory's pre-aggregated rows — the exact rows
    /// [`Self::apply_group_join_counters`] would fold from a full table
    /// walk (`totals − own-sourced + lane substitutions` on the permit
    /// side, `totals − own-sourced` on the denial side), at O(labels)
    /// per member instead of O(table).
    pub(in crate::manager) fn apply_batched_transition_counters(
        &mut self,
        peer: IpAddr,
        inventory: &BatchedTransitionInventory,
    ) {
        let rows = inventory.counters.rows_for(peer);
        if !rows.is_empty() {
            self.bump_export_counters(peer, &rows);
        }
    }
}
