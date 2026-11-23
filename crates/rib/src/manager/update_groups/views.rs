use crate::PeerId;
use crate::fast_hash::FastSet;

use super::{
    Afi, ExactExportKey, FastMap, GroupEvalAccumulator, GroupRibOut, HashSet, NextHopAction,
    PolicyAction, PolicyLabel, Prefix, RibManager, Route, RouteQueryKey, RtcMembership, Safi,
    VpnAddressFamily, VpnRibRoute, VpnRibRouteKey, VpnRouteKey, bump_counter_row, route_query_key,
    rt_passes, vpn_routes_equal,
};

/// The overlay may be detached while its keys retire, so a drifted counter
/// cannot be recounted here. Clamp it rather than wrap or stop the actor.
pub(super) fn decrement_refused_count(count: &mut usize, gid: usize, peer: PeerId, slot: usize) {
    if let Some(next) = count.checked_sub(1) {
        *count = next;
    } else {
        debug_assert!(
            false,
            "refused-view count underflow for {peer} at slot {slot}"
        );
        tracing::error!(
            group = gid,
            %peer,
            slot,
            counter = "visible_rejections",
            "refused-view count underflow; clamped at zero"
        );
    }
}

impl GroupRibOut {
    pub(super) fn visible_rejected_slot(
        &self,
        peer: PeerId,
        key: &ExactExportKey,
        rs_control: Option<(u32, u32)>,
        filter: Option<&RtcMembership>,
    ) -> Option<usize> {
        match key {
            ExactExportKey::Unicast(prefix, path_id) => self
                .adv_entry_post_backstop_for(peer, prefix, *path_id, rs_control)
                .map(|_| Self::count_slot(prefix)),
            ExactExportKey::Vpn(key) => self
                .table
                .get_vpn(key)
                .filter(|route| route.peer != peer && rt_passes(filter, route))
                .map(|_| Self::vpn_count_slot(&key.nlri_key)),
            _ => None,
        }
    }

    fn rejected_counts(&self, peer: PeerId) -> [usize; 4] {
        self.visible_rejections
            .get(&peer)
            .copied()
            .unwrap_or_default()
    }
}

impl RibManager {
    /// Test oracle for the maintained refused-view counters: recount the
    /// member's overlay against the current view, as the readers used to.
    #[cfg(test)]
    fn assert_refused_view_counts(&self, peer: PeerId, group: &GroupRibOut, reader: &str) {
        let filter = self.rtc_export_filter(peer, self.peer_sendable_families.get(&peer));
        let rs_control = self.rs_control_context(peer);
        let mut expected = [0_usize; 4];
        for key in self.peer_unexportable.get(&peer).into_iter().flatten() {
            if let Some(slot) = group.visible_rejected_slot(peer, key, rs_control, filter.as_ref())
            {
                expected[slot] += 1;
            }
        }
        assert_eq!(
            group.rejected_counts(peer),
            expected,
            "refused-view counts drifted for {peer} at {reader}"
        );
    }

    /// Only the overlay writer changes the refused set. The group tracks its
    /// intersection with the staged post-backstop view separately.
    pub(in crate::manager) fn set_exact_export_rejection(
        &mut self,
        peer: PeerId,
        key: ExactExportKey,
        rejected: bool,
    ) {
        self.set_exact_export_rejection_with_view(peer, key, rejected, None);
    }

    pub(in crate::manager) fn set_exact_export_rejection_with_view(
        &mut self,
        peer: PeerId,
        key: ExactExportKey,
        rejected: bool,
        staged_unicast: Option<(usize, bool)>,
    ) {
        if rejected {
            if self
                .peer_unexportable
                .get(&peer)
                .is_some_and(|keys| keys.contains(&key))
            {
                return;
            }
            self.adjust_group_rejection(peer, &key, true, staged_unicast);
            self.unicast_release.rejections.record(peer, &key, true);
            self.peer_unexportable.entry(peer).or_default().insert(key);
        } else if let Some(keys) = self.peer_unexportable.get_mut(&peer)
            && keys.remove(&key)
        {
            let empty = keys.is_empty();
            self.adjust_group_rejection(peer, &key, false, staged_unicast);
            self.unicast_release.rejections.record(peer, &key, false);
            if empty {
                self.peer_unexportable.remove(&peer);
                self.clear_group_rejections(peer);
            }
        }
    }

    pub(in crate::manager) fn clear_group_rejections(&mut self, peer: PeerId) {
        if let Some(group) = self
            .grouped_member_of(peer)
            .and_then(|gid| self.group_ribs.get_mut(&gid))
        {
            group.visible_rejections.remove(&peer);
        }
    }

    pub(in crate::manager) fn adjust_group_rejection(
        &mut self,
        peer: PeerId,
        key: &ExactExportKey,
        added: bool,
        staged_unicast: Option<(usize, bool)>,
    ) {
        let Some(gid) = staged_unicast
            .map(|(gid, _)| gid)
            .or_else(|| self.grouped_member_of(peer))
        else {
            return;
        };
        let rs_control = self.rs_control_context(peer);
        let Some(group) = self.group_ribs.get_mut(&gid) else {
            return;
        };
        let slot = if let (Some((_, visible)), ExactExportKey::Unicast(prefix, _)) =
            (staged_unicast, key)
        {
            visible.then(|| GroupRibOut::count_slot(prefix))
        } else {
            let empty = RtcMembership::default();
            let filter = group
                .rtc_negotiated()
                .then(|| self.peer_rt_membership.get(&peer).unwrap_or(&empty));
            #[cfg(test)]
            if matches!(key, ExactExportKey::Unicast(..)) {
                crate::manager::source_departure::inspect_receiver_row();
            }
            group.visible_rejected_slot(peer, key, rs_control, filter)
        };
        if added {
            let counts = group.visible_rejections.entry(peer).or_default();
            if let Some(slot) = slot {
                counts[slot] += 1;
            }
        } else if let (Some(slot), Some(counts)) = (slot, group.visible_rejections.get_mut(&peer)) {
            decrement_refused_count(&mut counts[slot], gid, peer, slot);
        }
    }

    /// Unicast portion of a grouped member's resync update, assembled
    /// from the group table with NO policy re-evaluation:
    ///
    /// - plain dirty: announce the member's derived view — `adv(m)`
    ///   per staged key ([`GroupRibOut::adv_entry`], ADR-0126
    ///   Decision 4: the staged winner for a non-source member, the
    ///   lane runner-up substituting for the winner's own source —
    ///   with the resolved entry's own nh/source-attr residue) —
    ///   withdraw actually admitted keys no longer retained;
    /// - regroup (baseline present): one-shot diff — announce entries
    ///   not `routes_equal` to the baseline, withdraw baseline keys the
    ///   member no longer retains;
    /// - force-only (RFC 8326 `GShut` refresh): re-announce everything,
    ///   bypassing the equality diff, withdraw nothing.
    ///
    /// `rs_control` is `(rs_asn, member_asn)` for an
    /// `rs_control_communities` member (LAN-474): table entries whose
    /// captured SOURCE communities ([`GroupRibOut::source_control`])
    /// suppress them toward this member are skipped — and withdrawn
    /// when the member may have them on the wire (plain dirty, or a
    /// baseline that records the key) — and announced entries are
    /// rewritten (prepend from the source, scrub post-policy) per
    /// target. Baselines snapshot through the same filter
    /// ([`GroupRibOut::member_view_snapshot_with_checkpoint`]), so the
    /// regroup one-shot diff compares wire state to wire state.
    #[expect(
        clippy::too_many_arguments,
        reason = "the resync assembly takes the member's full pending-withdraw context"
    )]
    pub(in crate::manager) fn assemble_group_resync(
        group: &GroupRibOut,
        member: PeerId,
        rs_control: Option<(u32, u32)>,
        is_dirty: bool,
        is_force: bool,
        baseline: Option<&FastMap<(Prefix, u32), Route>>,
        baseline_actions: Option<&FastMap<(Prefix, u32), NextHopAction>>,
        extras: Option<&HashSet<(Prefix, u32)>>,
        admitted: Option<super::admitted_recovery::AdmittedKeyView<'_>>,
        announce: &mut Vec<Route>,
        withdraw: &mut Vec<(Prefix, u32)>,
        nh_override_flags: &mut Vec<Option<NextHopAction>>,
        checkpoint: &mut impl FnMut(bool),
    ) {
        use crate::manager::distribution::rs_control::rs_control_route_rewrite;
        checkpoint(true);
        let mut suppressed_withdraws: HashSet<(Prefix, u32)> = HashSet::new();
        for staged in group.table.iter() {
            checkpoint(false);
            let key = (staged.prefix, staged.path_id);
            // adv(m) resolves the slot ([`GroupRibOut::adv_entry`]):
            // the staged winner for a non-source member, the lane
            // runner-up for the winner's own source, nothing when the
            // lane is empty — the substitution is never restated here
            // (ADR-0126 Decision 6). The rs-control decision and the
            // nh residue come from the RESOLVED entry: a substituted
            // slot reads the lane's captured source attributes, not
            // the staged winner's.
            // An rs-control member resolves past suppressed candidates
            // (`adv_entry_for`); a slot left with none of them is never on
            // its wire.
            let Some(entry) =
                group.adv_entry_for(member, &staged.prefix, staged.path_id, rs_control)
            else {
                // Add a candidate; the admitted proof below decides whether
                // this receiver actually needs a withdrawal.
                if !is_force
                    && (is_dirty || baseline.is_some_and(|base| base.contains_key(&key)))
                    && group
                        .adv_entry(member, &staged.prefix, staged.path_id)
                        .is_some()
                {
                    suppressed_withdraws.insert(key);
                }
                continue;
            };
            let (_, source_large_communities) =
                group.source_control_for_route(entry.route, entry.source_attrs);
            let mut route = entry.route.clone();
            rs_control_route_rewrite(&mut route, source_large_communities, rs_control);
            if !is_force
                && let Some(base) = baseline
                && base.get(&key).is_some_and(|old| {
                    crate::manager::helpers::unicast_routes_equal_for_profile(
                        old,
                        baseline_actions.and_then(|actions| actions.get(&key)),
                        &route,
                        entry.nh,
                        group.is_ebgp,
                        None,
                    )
                })
            {
                continue;
            }
            nh_override_flags.push(entry.nh.cloned());
            announce.push(route);
        }
        // A key the member still retains — its derived view
        // ([`GroupRibOut::adv_entry`]) holds a non-source-suppressed
        // route there — must not be withdrawn; everything else in the
        // candidate sets needs the admitted-key proof before withdrawal.
        // Routing retention through `adv_entry` makes a lane
        // substitution retain exactly like a staged entry: a recorded
        // lane withdraw survives the filter while the lane is empty
        // (it must be delivered) and drops once the lane refills (the
        // substituted announce above replaces it without a transient).
        let member_retains =
            |key: &(Prefix, u32)| group.member_retains(member, &key.0, key.1, rs_control);
        let mut keys: HashSet<(Prefix, u32)> = suppressed_withdraws;
        if let Some(base) = baseline {
            checkpoint(true);
            keys.extend(base.keys().filter(|key| {
                checkpoint(false);
                !member_retains(key)
            }));
            checkpoint(true);
        }
        if is_dirty {
            checkpoint(true);
            keys.extend(group.tombstones.iter().filter(|key| {
                checkpoint(false);
                !member_retains(key)
            }));
            checkpoint(true);
        }
        if let Some(extra) = extras {
            checkpoint(true);
            keys.extend(extra.iter().filter(|key| {
                checkpoint(false);
                !member_retains(key)
            }));
            checkpoint(true);
        }
        if let Some(admitted) = admitted {
            checkpoint(true);
            {
                let checkpoint = std::cell::RefCell::new(&mut *checkpoint);
                keys.extend(
                    admitted
                        .iter_with_checkpoint(|force| checkpoint.borrow_mut()(force))
                        .filter_map(|key| {
                            checkpoint.borrow_mut()(false);
                            match key {
                                ExactExportKey::Unicast(prefix, path_id)
                                    if !member_retains(&(prefix, path_id)) =>
                                {
                                    Some((prefix, path_id))
                                }
                                _ => None,
                            }
                        }),
                );
            }
            checkpoint(true);
            keys.retain(|(prefix, path_id)| {
                checkpoint(false);
                admitted.contains(&ExactExportKey::Unicast(*prefix, *path_id))
            });
        }
        checkpoint(true);
        withdraw.extend(keys.into_iter().inspect(|_| checkpoint(false)));
        checkpoint(true);
    }

    /// VPN portion of a grouped member's resync update — the VPN sibling
    /// of [`Self::assemble_group_resync`], same three shapes (plain
    /// dirty / regroup one-shot diff / force), assembled from the group
    /// table's VPN maps with NO policy re-evaluation, under the member's
    /// CURRENT Φ (`filter`). Only called for groups that stage VPN.
    ///
    /// The Φ dimension (design §2.4): announce = table entries passing
    /// `pass_m`, and retention is Φ-aware (a staged key failing Φ is
    /// NOT retained). A membership delta missed while dirty is healed
    /// through `extras`: the Φ-write seam records the keys leaving Φ as
    /// candidate withdrawals, intersected with actually admitted keys. A
    /// blanket failing-Φ withdrawal would include never-advertised keys.
    #[expect(
        clippy::too_many_arguments,
        reason = "the resync assembly takes the member's full pending-withdraw context"
    )]
    pub(in crate::manager) fn assemble_group_vpn_resync(
        group: &GroupRibOut,
        member: PeerId,
        filter: Option<&RtcMembership>,
        is_dirty: bool,
        is_force: bool,
        baseline: Option<&FastMap<VpnRouteKey, VpnRibRoute>>,
        extras: Option<&HashSet<VpnRouteKey>>,
        admitted: Option<super::admitted_recovery::AdmittedKeyView<'_>>,
        vpn_announce: &mut Vec<VpnRibRoute>,
        vpn_withdraw: &mut Vec<VpnRibRouteKey>,
        checkpoint: &mut impl FnMut(bool),
    ) {
        checkpoint(true);
        // Without Φ or a baseline diff the announce is exactly the table
        // minus the member's own-sourced entries, which a non-RTC group
        // counts in O(1). Grow-by-doubling would copy a full-table Vec
        // several times, each copy one uncheckpointed unit. An RTC
        // member's maintained count can be stale while it is dirty, so
        // its buffer grows on demand.
        if filter.is_none() && (is_force || baseline.is_none()) {
            vpn_announce.reserve(group.vpn_advertised_count_for(member));
            checkpoint(true);
        }
        for route in group.table.iter_vpn() {
            checkpoint(false);
            if route.peer == member || !rt_passes(filter, route) {
                continue;
            }
            if !is_force
                && let Some(base) = baseline
                && base
                    .get(&route.nlri.key())
                    .is_some_and(|old| vpn_routes_equal(old, route))
            {
                continue;
            }
            vpn_announce.push(route.clone());
        }
        let member_retains = |key: &VpnRouteKey| {
            group
                .table
                .get_vpn(&VpnRibRouteKey {
                    nlri_key: *key,
                    path_id: 0,
                })
                .is_some_and(|route| route.peer != member && rt_passes(filter, route))
        };
        let mut keys: FastSet<VpnRouteKey> = FastSet::default();
        if let Some(base) = baseline {
            checkpoint(true);
            keys.extend(base.keys().filter(|key| {
                checkpoint(false);
                !member_retains(key)
            }));
            checkpoint(true);
        }
        if is_dirty {
            checkpoint(true);
            keys.extend(group.vpn_tombstones.iter().filter(|key| {
                checkpoint(false);
                !member_retains(key)
            }));
            checkpoint(true);
        }
        if let Some(extra) = extras {
            checkpoint(true);
            keys.extend(extra.iter().filter(|key| {
                checkpoint(false);
                !member_retains(key)
            }));
            checkpoint(true);
        }
        if let Some(admitted) = admitted {
            checkpoint(true);
            {
                let checkpoint = std::cell::RefCell::new(&mut *checkpoint);
                keys.extend(
                    admitted
                        .iter_with_checkpoint(|force| checkpoint.borrow_mut()(force))
                        .filter_map(|key| {
                            checkpoint.borrow_mut()(false);
                            match key {
                                ExactExportKey::Vpn(key) if !member_retains(&key.nlri_key) => {
                                    Some(key.nlri_key)
                                }
                                _ => None,
                            }
                        }),
                );
            }
            checkpoint(true);
            keys.retain(|nlri_key| {
                checkpoint(false);
                admitted.contains(&ExactExportKey::Vpn(VpnRibRouteKey {
                    nlri_key: *nlri_key,
                    path_id: 0,
                }))
            });
        }
        checkpoint(true);
        vpn_withdraw.extend(keys.into_iter().inspect(|_| checkpoint(false)).map(|key| {
            VpnRibRouteKey {
                nlri_key: key,
                path_id: 0,
            }
        }));
        checkpoint(true);
    }

    /// Bump a member's export-policy counters by the group verdict:
    /// `totals − own-sourced` per (policy, action), as integer adds —
    /// identical totals to the per-peer path, which skips the eval for
    /// routes the target itself sourced (split horizon precedes the
    /// policy check).
    pub(in crate::manager) fn apply_group_policy_counters(
        &mut self,
        peer: PeerId,
        evals: &GroupEvalAccumulator,
    ) {
        if evals.totals.is_empty() {
            return;
        }
        let own = evals.per_source.get(&peer);
        let rows: Vec<(Option<String>, PolicyAction, u64)> = evals
            .totals
            .iter()
            .map(|(policy, action, total)| {
                let own_n = own
                    .and_then(|rows| {
                        rows.iter()
                            .find(|(p, a, _)| a == action && p == policy)
                            .map(|(_, _, n)| *n)
                    })
                    .unwrap_or(0);
                (
                    policy.as_ref().map(ToString::to_string),
                    *action,
                    total.saturating_sub(own_n),
                )
            })
            .collect();
        self.bump_export_counters(peer, &rows);
    }

    /// Count one permit per eligible adv(m) slot. For an own-sourced winner
    /// this uses the runner-up and its decision label, when the lane has one.
    fn walk_replay_permits(
        &self,
        group: &GroupRibOut,
        peer: PeerId,
        family: Option<(Afi, Safi)>,
        held: [bool; 2],
        rows: &mut Vec<(Option<String>, PolicyAction, u64)>,
    ) {
        for route in group.table.iter() {
            self.replacement_checkpoint(false);
            if family.is_some_and(|f| f != crate::manager::helpers::prefix_family(&route.prefix)) {
                continue;
            }
            let Some(adv) = group.adv_entry(peer, &route.prefix, route.path_id) else {
                continue;
            };
            if !held[usize::from(matches!(route.prefix, Prefix::V6(_)))]
                || adv
                    .local_source
                    .is_some_and(|source| source.deferral_exempt)
            {
                bump_counter_row(rows, adv.policy_label, PolicyAction::Permit);
            }
        }
    }

    fn plain_replay_permits(
        &self,
        group: &GroupRibOut,
        peer: PeerId,
        family: Option<(Afi, Safi)>,
        held: [bool; 2],
    ) -> u64 {
        if held == [false; 2] {
            return group.plain_permit_count(peer, family);
        }
        // Open families use the staged counts. Held families evaluate only
        // exempt local sources, indexed independently of the received table.
        let open: u64 = [Afi::Ipv4, Afi::Ipv6]
            .into_iter()
            .zip(held)
            .filter(|(afi, held)| !*held && family.is_none_or(|f| f == (*afi, Safi::Unicast)))
            .map(|(afi, _)| group.plain_permit_count(peer, Some((afi, Safi::Unicast))))
            .sum();
        open + group
            .table
            .local_export_sources()
            .filter(|((prefix, _), source)| {
                self.replacement_checkpoint(false);
                let source_family = crate::manager::helpers::prefix_family(prefix);
                held[usize::from(source_family.0 == Afi::Ipv6)]
                    && family.is_none_or(|f| f == source_family)
                    && source.deferral_exempt
            })
            .count() as u64
    }

    pub(in crate::manager) fn initial_unicast_denial_evaluated(
        &self,
        held: [bool; 2],
        prefix: Prefix,
        source: PeerId,
        path_id: u32,
    ) -> bool {
        !held[usize::from(matches!(prefix, Prefix::V6(_)))]
            || (source == PeerId::LOCAL
                && self
                    .ribs
                    .get(&source)
                    .and_then(|rib| rib.get(&prefix, path_id))
                    .is_some_and(crate::manager::helpers::unicast_deferral_exempt))
    }

    /// Read the policy snapshot at registration. Live distribution accounts
    /// subsequent evaluations even when the receiver is waiting for a page.
    pub(in crate::manager) fn start_initial_replay_policy(&mut self, peer: PeerId, gid: usize) {
        let group = &self.group_ribs[&gid];
        debug_assert!(!group.per_client_best);
        let permits = group.plain_permit_count(peer, None);
        let mut rows = Vec::with_capacity(1 + group.single_best_denials.labels.len());
        if permits != 0 {
            rows.push((
                group.permit_policy_label.as_deref().map(str::to_owned),
                PolicyAction::Permit,
                permits,
            ));
        }
        for (label, (total, by_source)) in &group.single_best_denials.labels {
            let count = total - by_source.get(&peer).copied().unwrap_or_default();
            if count != 0 {
                rows.push((
                    label.as_deref().map(str::to_owned),
                    PolicyAction::Deny,
                    count,
                ));
            }
        }
        self.bump_export_counters(peer, &rows);
    }

    /// The same reconciliation as a one-turn join, scoped to this replay
    /// page or intervening change. Repeated keys only publish new denials.
    pub(in crate::manager) fn apply_initial_replay_page_policy(
        &mut self,
        peer: PeerId,
        gid: usize,
        prefixes: &HashSet<Prefix>,
    ) {
        let group = &self.group_ribs[&gid];
        if !group.has_policy_filtered_routes() && !self.policy_filtered_routes.contains_key(&peer) {
            return;
        }
        let current = group
            .policy_filtered_for_member_with_checkpoint(peer, prefixes, &mut || {
                self.replacement_checkpoint(false);
            })
            .into_iter()
            .collect();
        self.update_policy_filtered_routes_for_prefixes(peer, prefixes, &current);
    }

    /// Reconstruct a joining member's export counters from the group's
    /// staged residue: one permit per `adv(m)` slot (labelled by its
    /// retained decision attribution — the lane entry's where the member
    /// sourced the winner of a per-client-best prefix), one deny per
    /// persistent denial — own-sourced excluded on the denial side and
    /// substituted-or-excluded on the permit side. Private PCB staging also
    /// evaluates candidates skipped for OTC. Replay counts the stored
    /// eligible slot without re-running policy. A route-refresh passes its `family` so
    /// only the refreshed family's entries count (the per-peer path
    /// re-evaluates only that family).
    pub(in crate::manager) fn apply_group_join_counters(
        &mut self,
        peer: PeerId,
        gid: usize,
        family: Option<(Afi, Safi)>,
    ) {
        self.apply_group_replay_counters(peer, gid, family, [false; 2]);
    }

    pub(in crate::manager) fn apply_group_replay_counters(
        &mut self,
        peer: PeerId,
        gid: usize,
        family: Option<(Afi, Safi)>,
        held: [bool; 2],
    ) {
        self.replacement_checkpoint(true);
        // The member's Φ: the per-peer path's RT gate precedes the policy
        // evaluation, so an RT-failed entry records NO eval — the replay
        // must count only Φ-passing permits and denials (design §2.4).
        let vpn_filter = self.rtc_export_filter(peer, self.peer_sendable_families.get(&peer));
        let mut rows: Vec<(Option<String>, PolicyAction, u64)> = Vec::new();
        {
            let Some(group) = self.group_ribs.get(&gid) else {
                return;
            };
            let in_family = |prefix: &Prefix| {
                family.is_none_or(|f| crate::manager::helpers::prefix_family(prefix) == f)
            };
            if group.per_client_best {
                self.walk_replay_permits(group, peer, family, held, &mut rows);
            } else {
                // A plain group has no lane and stages every slot with its
                // one permit label, so the member's permits are the staged
                // count minus its own-sourced slots (the O(1)
                // `family_counts_for` synthesis) — no table walk per joining
                // member.
                let permits = self.plain_replay_permits(group, peer, family, held);
                if permits > 0 {
                    rows.push((
                        group.permit_policy_label.as_ref().map(ToString::to_string),
                        PolicyAction::Permit,
                        permits,
                    ));
                }
                #[cfg(test)]
                {
                    let mut walked = Vec::new();
                    self.walk_replay_permits(group, peer, family, held, &mut walked);
                    assert_eq!(
                        rows, walked,
                        "plain-group permit synthesis diverged from the adv(m) walk"
                    );
                }
            }
            let mut bump = |policy: &Option<PolicyLabel>, action: PolicyAction| {
                bump_counter_row(&mut rows, policy.as_ref(), action);
            };
            for (prefix, denials) in group.policy_filtered.iter() {
                self.replacement_checkpoint(false);
                if !in_family(prefix) {
                    continue;
                }
                for (&(source_peer, path_id), label) in denials {
                    self.replacement_checkpoint(false);
                    if source_peer == peer
                        || !self.initial_unicast_denial_evaluated(
                            held,
                            *prefix,
                            source_peer,
                            path_id,
                        )
                    {
                        continue;
                    }
                    bump(label, PolicyAction::Deny);
                }
            }
            // VPN dimension (only staged for non-RTC groups): permits
            // from the staged labels, denies from the denial residue —
            // own-sourced excluded on both sides (the per-peer path's
            // split horizon returns before the policy evaluation).
            let in_vpn_family = |key: &VpnRouteKey| {
                family.is_none_or(|f| {
                    let afi = match key.prefix.family() {
                        VpnAddressFamily::V4 => Afi::Ipv4,
                        VpnAddressFamily::V6 => Afi::Ipv6,
                    };
                    (afi, Safi::MplsVpn) == f
                })
            };
            for route in group.table.iter_vpn() {
                self.replacement_checkpoint(false);
                if route.peer == peer
                    || !in_vpn_family(&route.nlri.key())
                    || !rt_passes(vpn_filter.as_ref(), route)
                {
                    continue;
                }
                let label = group.permit_policy_label.clone();
                bump(&label, PolicyAction::Permit);
            }
            for (key, (source, label, rts)) in group.vpn_policy_denied.iter() {
                self.replacement_checkpoint(false);
                if *source == peer
                    || !in_vpn_family(key)
                    || !vpn_filter.as_ref().is_none_or(|m| m.matches_any(rts))
                {
                    continue;
                }
                bump(label, PolicyAction::Deny);
            }
        }
        self.replacement_checkpoint(true);
        self.bump_export_counters(peer, &rows);
        crate::manager::retire_vec(&mut rows, &mut || self.replacement_checkpoint(false));
        self.replacement_checkpoint(true);
    }

    /// Borrowed synthesized advertised-route view for a grouped peer
    /// (`adv(m)` per staged key — the table entry or its lane
    /// substitution, minus the slots the RFC 9234 backstop strips,
    /// [`GroupRibOut::adv_entry_post_backstop`] — minus this member's
    /// exact-export rejections, intersected with what its outbound
    /// maxima admitted); `None` for ungrouped peers.
    pub(in crate::manager) fn grouped_advertised_routes_iter(
        &self,
        peer: PeerId,
    ) -> Option<impl Iterator<Item = &Route>> {
        self.grouped_advertised_routes_for_prefix(peer, None)
    }

    pub(in crate::manager) fn grouped_advertised_routes_for_prefix(
        &self,
        peer: PeerId,
        prefix: Option<Prefix>,
    ) -> Option<impl Iterator<Item = &Route>> {
        let group = self.group_ribs.get(&self.grouped_member_of(peer)?)?;
        let rejected = self.peer_unexportable.get(&peer);
        let limits = self.outbound_prefix_limits.get(&peer);
        let initial = self.initial_group_admitted(peer);
        // RFC 7947: the member's own wire slot, past control-community
        // suppression (and onto a per-client-best fallback).
        let rs_control = self.rs_control_context(peer);
        Some(
            group
                .table
                .iter()
                .take(if prefix.is_none() { usize::MAX } else { 0 })
                .chain(
                    prefix
                        .into_iter()
                        .flat_map(|prefix| group.table.iter_prefix(&prefix)),
                )
                .inspect(move |_| self.replacement_checkpoint_at("grouped_advertised_input", false))
                .filter_map(move |staged| {
                    // The substitution sits at the same (prefix, path_id 0)
                    // slot, so the member-local overlays key identically for
                    // the staged entry and its lane replacement.
                    let route = group
                        .adv_entry_post_backstop_for(
                            peer,
                            &staged.prefix,
                            staged.path_id,
                            rs_control,
                        )?
                        .route;
                    (initial.is_none_or(|admitted| {
                        admitted.contains(&ExactExportKey::Unicast(route.prefix, route.path_id))
                    }) && !rejected.is_some_and(|keys| {
                        keys.contains(&ExactExportKey::Unicast(route.prefix, route.path_id))
                    }) && limits.is_none_or(|limits| limits.admits_grouped(&route.prefix)))
                    .then_some(route)
                }),
        )
    }

    /// Borrowed VPN advertised view for group-owned members, with current RTC
    /// membership, split horizon and member-local encoder rejection applied.
    pub(in crate::manager) fn grouped_advertised_vpn_routes_iter(
        &self,
        peer: PeerId,
    ) -> Option<impl Iterator<Item = &crate::route::VpnRibRoute>> {
        let group = self.group_ribs.get(&self.vpn_grouped_member_of(peer)?)?;
        let rtc = group.rtc_negotiated();
        let filter = self.peer_rt_membership.get(&peer);
        let rejected = self.peer_unexportable.get(&peer);
        let initial = self.initial_group_admitted(peer);
        Some(group.table.iter_vpn().filter(move |route| {
            route.peer != peer
                && initial
                    .is_none_or(|admitted| admitted.contains(&ExactExportKey::Vpn(route.key())))
                && (!rtc || filter.is_some_and(|filter| super::rt_passes(Some(filter), route)))
                && !rejected.is_some_and(|keys| keys.contains(&ExactExportKey::Vpn(route.key())))
        }))
    }

    /// The RFC 7947 per-target wire form (prepend, control-community scrub)
    /// of a grouped rs-control member's listed rows, as its own Adj-RIB-Out
    /// would hold them. The listing iterators borrow the shared rows; a
    /// page rewrites only the rows it returns. A no-op for other members.
    pub(in crate::manager) fn rewrite_grouped_advertised_rows(
        &self,
        peer: PeerId,
        routes: &mut [Route],
    ) {
        use crate::manager::distribution::rs_control::rs_control_route_rewrite;
        let Some(rs_control) = self.rs_control_context(peer) else {
            return;
        };
        let Some(group) = self
            .grouped_member_of(peer)
            .and_then(|gid| self.group_ribs.get(&gid))
        else {
            return;
        };
        for route in routes {
            self.replacement_checkpoint(false);
            let Some(entry) =
                group.adv_entry_for(peer, &route.prefix, route.path_id, Some(rs_control))
            else {
                continue;
            };
            let (_, large) = group.source_control_for_route(entry.route, entry.source_attrs);
            rs_control_route_rewrite(route, large, Some(rs_control));
        }
    }

    /// Ordered sibling used by resumable route listings. The group table's
    /// persistent prefix index resumes at the cursor; member-local split
    /// horizon and exact-export rejection remain streaming filters. A page
    /// clones only yielded rows, but a high-exclusion member may inspect more
    /// underlying group rows before filling that page.
    #[cfg(test)]
    pub(in crate::manager) fn grouped_advertised_routes_ordered_iter(
        &self,
        peer: PeerId,
        after: Option<RouteQueryKey>,
    ) -> Option<impl Iterator<Item = &Route>> {
        self.grouped_advertised_routes_ordered_family_iter(peer, after, None)
    }

    pub(in crate::manager) fn grouped_advertised_routes_ordered_family_iter(
        &self,
        peer: PeerId,
        after: Option<RouteQueryKey>,
        family: Option<Afi>,
    ) -> Option<impl Iterator<Item = &Route>> {
        let group = self.group_ribs.get(&self.grouped_member_of(peer)?)?;
        let rejected = self.peer_unexportable.get(&peer);
        let limits = self.outbound_prefix_limits.get(&peer);
        let initial = self.initial_group_admitted(peer);
        // RFC 7947: the member's own wire slot, past control-community
        // suppression (and onto a per-client-best fallback).
        let rs_control = self.rs_control_context(peer);
        Some(
            group
                .table
                .iter_ordered_family_from(after, family)
                .filter_map(move |staged| {
                    let route = group
                        .adv_entry_post_backstop_for(
                            peer,
                            &staged.prefix,
                            staged.path_id,
                            rs_control,
                        )?
                        .route;
                    // A lane substitution keeps the staged entry's prefix
                    // position, so the persistent prefix-index ordering is
                    // unchanged — but the cursor a caller resumes with
                    // carries the YIELDED route's source peer, which
                    // differs from the staged entry's at a substituted
                    // slot. Re-filter on the yielded key so a page
                    // boundary landing on a substitution resumes without
                    // duplicating its prefix (the underlying iterator
                    // filters on staged keys only).
                    (after.is_none_or(|cursor| route_query_key(route) > cursor)
                        && initial.is_none_or(|admitted| {
                            admitted.contains(&ExactExportKey::Unicast(route.prefix, route.path_id))
                        })
                        && !rejected.is_some_and(|keys| {
                            keys.contains(&ExactExportKey::Unicast(route.prefix, route.path_id))
                        })
                        && limits.is_none_or(|limits| limits.admits_grouped(&route.prefix)))
                    .then_some(route)
                }),
        )
    }

    /// Materialized sibling of [`Self::grouped_advertised_routes_iter`] for
    /// legacy full-snapshot and route-refresh callers.
    pub(in crate::manager) fn grouped_advertised_routes(&self, peer: PeerId) -> Option<Vec<Route>> {
        self.replacement_checkpoint(true);
        let capacity = self
            .group_ribs
            .get(&self.grouped_member_of(peer)?)?
            .table
            .len();
        let routes = self.grouped_advertised_routes_iter(peer)?;
        let mut result = Vec::with_capacity(capacity);
        self.replacement_checkpoint(true);
        result.extend(routes.cloned());
        self.replacement_checkpoint(true);
        Some(result)
    }

    /// Synthesized advertised-route count for a grouped peer; `None`
    /// for ungrouped peers.
    pub(in crate::manager) fn grouped_advertised_count(&self, peer: PeerId) -> Option<usize> {
        #[cfg(test)]
        self.grouped_advertised_count_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let group = self.group_ribs.get(&self.grouped_member_of(peer)?)?;
        if let Some(counts) = self.initial_group_admitted_counts(peer) {
            return Some(counts[0] + counts[1]);
        }
        if self.outbound_prefix_limits.contains_key(&peer) {
            // A limited member advertises its admitted projection, and that
            // is decided per family — so reuse the single definition of
            // usage rather than deriving the same quantity a second way.
            return Some(
                crate::manager::outbound_prefix_limits::LIMITED_FAMILIES
                    .into_iter()
                    .map(|afi| self.outbound_family_usage(peer, afi, true))
                    .sum(),
            );
        }
        #[cfg(test)]
        self.assert_refused_view_counts(peer, group, "count");
        let [v4, v6, _, _] = group.rejected_counts(peer);
        Some(group.advertised_count_for(peer).saturating_sub(v4 + v6))
    }

    /// [`Self::grouped_advertised_count`] split `[IPv4, IPv6]` for the
    /// per-family Adj-RIB-Out gauge; `None` for ungrouped peers.
    pub(in crate::manager) fn grouped_advertised_unicast_lens(
        &self,
        peer: PeerId,
    ) -> Option<[usize; 2]> {
        let group = self.group_ribs.get(&self.grouped_member_of(peer)?)?;
        if let Some(counts) = self.initial_group_admitted_counts(peer) {
            return Some([counts[0], counts[1]]);
        }
        if self.outbound_prefix_limits.contains_key(&peer) {
            return Some(
                crate::manager::outbound_prefix_limits::LIMITED_FAMILIES
                    .map(|afi| self.outbound_family_usage(peer, afi, true)),
            );
        }
        let mut lens = [0_usize; 2];
        for ((afi, safi), count) in group.family_counts_for(peer) {
            if safi == Safi::Unicast {
                lens[usize::from(afi == Afi::Ipv6)] = usize::try_from(count).unwrap_or(usize::MAX);
            }
        }
        #[cfg(test)]
        self.assert_refused_view_counts(peer, group, "unicast_lens");
        let [v4, v6, _, _] = group.rejected_counts(peer);
        Some([lens[0].saturating_sub(v4), lens[1].saturating_sub(v6)])
    }

    /// [`Self::grouped_vpn_advertised_count`] split `[VPN-IPv4, VPN-IPv6]`
    /// for the per-family Adj-RIB-Out gauge; `None` for ungrouped peers.
    pub(in crate::manager) fn grouped_vpn_advertised_lens(
        &self,
        peer: PeerId,
    ) -> Option<[usize; 2]> {
        let gid = self.vpn_grouped_member_of(peer)?;
        let group = self.group_ribs.get(&gid)?;
        if let Some(counts) = self.initial_group_admitted_counts(peer) {
            return Some([counts[2], counts[3]]);
        }
        let mut lens = [0_usize; 2];
        for ((afi, safi), count) in group.family_counts_for(peer) {
            if safi == Safi::MplsVpn {
                lens[usize::from(afi == Afi::Ipv6)] = usize::try_from(count).unwrap_or(usize::MAX);
            }
        }
        #[cfg(test)]
        self.assert_refused_view_counts(peer, group, "vpn_lens");
        let [_, _, v4, v6] = group.rejected_counts(peer);
        Some([lens[0].saturating_sub(v4), lens[1].saturating_sub(v6)])
    }

    /// Synthesized VPN count for a grouped member after applying its sparse
    /// exact-export rejection overlay. The group table and RTC membership
    /// counters remain shared truths; only this member-local projection is
    /// reduced.
    pub(in crate::manager) fn grouped_vpn_advertised_count(&self, peer: PeerId) -> Option<usize> {
        let gid = self.vpn_grouped_member_of(peer)?;
        let group = self.group_ribs.get(&gid)?;
        if let Some(counts) = self.initial_group_admitted_counts(peer) {
            return Some(counts[2] + counts[3]);
        }
        #[cfg(test)]
        self.assert_refused_view_counts(peer, group, "vpn_count");
        let [_, _, v4, v6] = group.rejected_counts(peer);
        Some(group.vpn_advertised_count_for(peer).saturating_sub(v4 + v6))
    }

    /// Per-family grouped advertised counts after subtracting the member's
    /// sparse exact-export rejection overlay. Used by BMP stat 17 and the
    /// public count query so neither reports the shared group table as wire
    /// truth for a classic-message peer that rejected an oversized route.
    pub(in crate::manager) fn grouped_family_counts(
        &self,
        peer: PeerId,
    ) -> Option<Vec<((Afi, Safi), u64)>> {
        let gid = self.grouped_member_of(peer)?;
        let group = self.group_ribs.get(&gid)?;
        if let Some(admitted) = self.initial_group_admitted_counts(peer) {
            let families = [
                (Afi::Ipv4, Safi::Unicast),
                (Afi::Ipv6, Safi::Unicast),
                (Afi::Ipv4, Safi::MplsVpn),
                (Afi::Ipv6, Safi::MplsVpn),
            ];
            return Some(
                families
                    .into_iter()
                    .zip(admitted)
                    .filter(|((_, safi), count)| {
                        *count != 0 && (*safi == Safi::Unicast || group.stages_vpn())
                    })
                    .map(|(family, count)| (family, u64::try_from(count).unwrap_or(u64::MAX)))
                    .collect(),
            );
        }
        let mut counts = group.family_counts_for(peer);
        #[cfg(test)]
        self.assert_refused_view_counts(peer, group, "family_counts");
        let rejected = group.rejected_counts(peer);
        for ((afi, safi), count) in &mut counts {
            let slot = usize::from(*afi == Afi::Ipv6) + 2 * usize::from(*safi == Safi::MplsVpn);
            *count = count.saturating_sub(u64::try_from(rejected[slot]).unwrap_or(u64::MAX));
        }
        counts.retain(|(_, count)| *count != 0);
        Some(counts)
    }
}
