use super::{
    Afi, ExactExportKey, FxHashMap, GroupEvalAccumulator, GroupRibOut, HashSet, IpAddr,
    NextHopAction, PolicyAction, PolicyLabel, Prefix, RibManager, Route, RouteQueryKey,
    RtcMembership, Safi, VpnAddressFamily, VpnRibRoute, VpnRibRouteKey, VpnRouteKey,
    bump_counter_row, route_query_key, routes_equal, rt_passes, source_control_input,
    vpn_routes_equal,
};

impl RibManager {
    /// Unicast portion of a grouped member's resync update, assembled
    /// from the group table with NO policy re-evaluation:
    ///
    /// - plain dirty: announce the member's derived view — `adv(m)`
    ///   per staged key ([`GroupRibOut::adv_entry`], ADR-0126
    ///   Decision 4: the staged winner for a non-source member, the
    ///   lane runner-up substituting for the winner's own source —
    ///   with the resolved entry's own nh/source-attr residue) —
    ///   withdraw `tombstones ∖ still-retained` (over-withdraw is the
    ///   safe direction — the member's missed sends are unknown);
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
    /// ([`GroupRibOut::member_view_snapshot`]), so the regroup one-shot
    /// diff compares wire state to wire state.
    #[expect(
        clippy::too_many_arguments,
        reason = "the resync assembly takes the member's full pending-withdraw context"
    )]
    pub(in crate::manager) fn assemble_group_resync(
        group: &GroupRibOut,
        member: IpAddr,
        rs_control: Option<(u32, u32)>,
        is_dirty: bool,
        is_force: bool,
        baseline: Option<&FxHashMap<(Prefix, u32), Route>>,
        extras: Option<&HashSet<(Prefix, u32)>>,
        announce: &mut Vec<Route>,
        withdraw: &mut Vec<(Prefix, u32)>,
        nh_override_flags: &mut Vec<Option<NextHopAction>>,
    ) {
        use crate::manager::distribution::rs_control::{
            rs_control_route_rewrite, rs_control_suppressed,
        };
        let mut suppressed_withdraws: HashSet<(Prefix, u32)> = HashSet::new();
        for staged in group.table.iter() {
            let key = (staged.prefix, staged.path_id);
            // adv(m) resolves the slot ([`GroupRibOut::adv_entry`]):
            // the staged winner for a non-source member, the lane
            // runner-up for the winner's own source, nothing when the
            // lane is empty — the substitution is never restated here
            // (ADR-0126 Decision 6). The rs-control decision and the
            // nh residue come from the RESOLVED entry: a substituted
            // slot reads the lane's captured source attributes, not
            // the staged winner's.
            let Some(entry) = group.adv_entry(member, &staged.prefix, staged.path_id) else {
                continue;
            };
            let (source_communities, source_large_communities) =
                source_control_input(entry.source_attrs);
            if rs_control_suppressed(source_communities, source_large_communities, rs_control) {
                // Not on this member's wire going forward. Withdraw when
                // it may be there now: always on a plain dirty resync
                // (missed sends are unknown — over-withdraw is the safe
                // direction), on a regroup diff only when the baseline
                // proves the key was sent. Force-only re-announces and
                // never withdraws.
                if !is_force && (is_dirty || baseline.is_some_and(|base| base.contains_key(&key))) {
                    suppressed_withdraws.insert(key);
                }
                continue;
            }
            let mut route = entry.route.clone();
            rs_control_route_rewrite(&mut route, source_large_communities, rs_control);
            if !is_force
                && let Some(base) = baseline
                && base.get(&key).is_some_and(|old| routes_equal(old, &route))
            {
                continue;
            }
            nh_override_flags.push(entry.nh.cloned());
            announce.push(route);
        }
        // A key the member still retains — its derived view
        // ([`GroupRibOut::adv_entry`]) holds a non-source-suppressed
        // route there — must not be withdrawn; everything else in the
        // candidate sets is a safe (possibly spurious) withdraw.
        // Routing retention through `adv_entry` makes a lane
        // substitution retain exactly like a staged entry: a recorded
        // lane withdraw survives the filter while the lane is empty
        // (it must be delivered) and drops once the lane refills (the
        // substituted announce above replaces it — over-withdraw and
        // over-announce compose safely, announce+withdraw of one key
        // does not).
        let member_retains = |key: &(Prefix, u32)| {
            group.adv_entry(member, &key.0, key.1).is_some_and(|entry| {
                let (communities, large_communities) = source_control_input(entry.source_attrs);
                !rs_control_suppressed(communities, large_communities, rs_control)
            })
        };
        let mut keys: HashSet<(Prefix, u32)> = suppressed_withdraws;
        if let Some(base) = baseline {
            keys.extend(base.keys().filter(|key| !member_retains(key)));
        }
        if is_dirty {
            keys.extend(group.tombstones.iter().filter(|key| !member_retains(key)));
        }
        if let Some(extra) = extras {
            keys.extend(extra.iter().filter(|key| !member_retains(key)));
        }
        withdraw.extend(keys);
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
    /// extra (over-)withdraws — exact, instead of the design's blanket
    /// failing-Φ withdraw term, which would put spurious withdraws on
    /// clean regroup diffs too (spurious withdraws are RFC 4271 no-ops,
    /// but the regroup one-shot diff is held to exact-stream parity).
    #[expect(
        clippy::too_many_arguments,
        reason = "the resync assembly takes the member's full pending-withdraw context"
    )]
    pub(in crate::manager) fn assemble_group_vpn_resync(
        group: &GroupRibOut,
        member: IpAddr,
        filter: Option<&RtcMembership>,
        is_dirty: bool,
        is_force: bool,
        baseline: Option<&FxHashMap<VpnRouteKey, VpnRibRoute>>,
        extras: Option<&HashSet<VpnRouteKey>>,
        vpn_announce: &mut Vec<VpnRibRoute>,
        vpn_withdraw: &mut Vec<VpnRibRouteKey>,
    ) {
        for route in group.table.iter_vpn() {
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
        let mut keys: HashSet<VpnRouteKey> = HashSet::new();
        if let Some(base) = baseline {
            keys.extend(base.keys().filter(|key| !member_retains(key)));
        }
        if is_dirty {
            keys.extend(
                group
                    .vpn_tombstones
                    .iter()
                    .filter(|key| !member_retains(key)),
            );
        }
        if let Some(extra) = extras {
            keys.extend(extra.iter().filter(|key| !member_retains(key)));
        }
        vpn_withdraw.extend(keys.into_iter().map(|key| VpnRibRouteKey {
            nlri_key: key,
            path_id: 0,
        }));
    }

    /// Bump a member's export-policy counters by the group verdict:
    /// `totals − own-sourced` per (policy, action), as integer adds —
    /// identical totals to the per-peer path, which skips the eval for
    /// routes the target itself sourced (split horizon precedes the
    /// policy check).
    pub(in crate::manager) fn apply_group_policy_counters(
        &mut self,
        peer: IpAddr,
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

    /// Reconstruct a joining member's export counters from the group's
    /// staged residue: one permit per `adv(m)` slot (labelled by its
    /// retained terminal policy — the lane entry's where the member
    /// sourced the winner of a per-client-best prefix), one deny per
    /// persistent denial — own-sourced excluded on the denial side and
    /// substituted-or-excluded on the permit side, exactly what the
    /// per-peer initial-dump staging would have recorded, without
    /// re-running policy. A route-refresh replay passes its `family` so
    /// only the refreshed family's entries count (the per-peer path
    /// re-evaluates only that family).
    pub(in crate::manager) fn apply_group_join_counters(
        &mut self,
        peer: IpAddr,
        gid: usize,
        family: Option<(Afi, Safi)>,
    ) {
        // The member's Φ: the per-peer path's RT gate precedes the policy
        // evaluation, so an RT-failed entry records NO eval — the replay
        // must count only Φ-passing permits and denials (design §2.4).
        let vpn_filter = self.rtc_vpn_filter(peer, self.peer_sendable_families.get(&peer));
        let mut rows: Vec<(Option<String>, PolicyAction, u64)> = Vec::new();
        {
            let Some(group) = self.group_ribs.get(&gid) else {
                return;
            };
            let mut bump = |policy: &Option<PolicyLabel>, action: PolicyAction| {
                bump_counter_row(&mut rows, policy.as_ref(), action);
            };
            let in_family = |prefix: &Prefix| {
                family.is_none_or(|f| crate::manager::helpers::prefix_family(prefix) == f)
            };
            // One permit per `adv(m)` slot (`adv_entry`, ADR-0126
            // Decision 4): the staged entry's label for a non-own
            // slot; the LANE entry's label where the member sourced
            // the winner — the runner-up's permit WAS evaluated
            // (Decision 2's over-replay posture), and its retained
            // terminal label is exactly what the walk recorded.
            // Nothing for an own-sourced slot with no substitution.
            for route in group.table.iter() {
                if !in_family(&route.prefix) {
                    continue;
                }
                let Some(adv) = group.adv_entry(peer, &route.prefix, route.path_id) else {
                    continue;
                };
                bump(&adv.policy_label.cloned(), PolicyAction::Permit);
            }
            for (prefix, denials) in &group.policy_filtered {
                if !in_family(prefix) {
                    continue;
                }
                for (&(source_peer, _), label) in denials {
                    if source_peer == peer {
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
                if route.peer == peer
                    || !in_vpn_family(&route.nlri.key())
                    || !rt_passes(vpn_filter.as_ref(), route)
                {
                    continue;
                }
                let label = group
                    .vpn_staged_labels
                    .get(&route.nlri.key())
                    .cloned()
                    .unwrap_or(None);
                bump(&label, PolicyAction::Permit);
            }
            for (key, (source, label, rts)) in &group.vpn_policy_denied {
                if *source == peer
                    || !in_vpn_family(key)
                    || !vpn_filter.as_ref().is_none_or(|m| m.matches_any(rts))
                {
                    continue;
                }
                bump(label, PolicyAction::Deny);
            }
        }
        self.bump_export_counters(peer, &rows);
    }

    /// Borrowed synthesized advertised-route view for a grouped peer
    /// (`adv(m)` per staged key — the table entry or its lane
    /// substitution, minus the slots the RFC 9234 backstop strips,
    /// [`GroupRibOut::adv_entry_post_backstop`] — minus this member's
    /// exact-export rejections, intersected with what its outbound
    /// maxima admitted); `None` for ungrouped peers.
    pub(in crate::manager) fn grouped_advertised_routes_iter(
        &self,
        peer: IpAddr,
    ) -> Option<impl Iterator<Item = &Route>> {
        let group = self.group_ribs.get(&self.grouped_member_of(peer)?)?;
        let rejected = self.peer_unexportable.get(&peer);
        let limits = self.outbound_prefix_limits.get(&peer);
        Some(group.table.iter().filter_map(move |staged| {
            // The substitution sits at the same (prefix, path_id 0)
            // slot, so the member-local overlays key identically for
            // the staged entry and its lane replacement.
            let route = group
                .adv_entry_post_backstop(peer, &staged.prefix, staged.path_id)?
                .route;
            (!rejected.is_some_and(|keys| {
                keys.contains(&ExactExportKey::Unicast(route.prefix, route.path_id))
            }) && limits.is_none_or(|limits| limits.admits_grouped(&route.prefix)))
            .then_some(route)
        }))
    }

    /// Ordered sibling used by resumable route listings. The group table's
    /// persistent prefix index resumes at the cursor; member-local split
    /// horizon and exact-export rejection remain streaming filters. A page
    /// clones only yielded rows, but a high-exclusion member may inspect more
    /// underlying group rows before filling that page.
    pub(in crate::manager) fn grouped_advertised_routes_ordered_iter(
        &self,
        peer: IpAddr,
        after: Option<RouteQueryKey>,
    ) -> Option<impl Iterator<Item = &Route>> {
        let group = self.group_ribs.get(&self.grouped_member_of(peer)?)?;
        let rejected = self.peer_unexportable.get(&peer);
        let limits = self.outbound_prefix_limits.get(&peer);
        Some(
            group
                .table
                .iter_ordered_from(after)
                .filter_map(move |staged| {
                    let route = group
                        .adv_entry_post_backstop(peer, &staged.prefix, staged.path_id)?
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
    pub(in crate::manager) fn grouped_advertised_routes(&self, peer: IpAddr) -> Option<Vec<Route>> {
        self.grouped_advertised_routes_iter(peer)
            .map(|routes| routes.cloned().collect())
    }

    /// Synthesized advertised-route count for a grouped peer; `None`
    /// for ungrouped peers.
    pub(in crate::manager) fn grouped_advertised_count(&self, peer: IpAddr) -> Option<usize> {
        let group = self.group_ribs.get(&self.grouped_member_of(peer)?)?;
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
        let rejected = self.peer_unexportable.get(&peer).map_or(0, |keys| {
            keys.iter()
                .filter(|key| match key {
                    // A rejected key reduces the count only while the
                    // member's derived view holds a route at that slot
                    // — staged or lane-substituted — that the RFC 9234
                    // backstop delivers: a slot the backstop strips was
                    // already subtracted by the synthesis's OTC term,
                    // so subtracting its rejection too would count the
                    // one missing slot twice.
                    ExactExportKey::Unicast(prefix, path_id) => group
                        .adv_entry_post_backstop(peer, prefix, *path_id)
                        .is_some(),
                    _ => false,
                })
                .count()
        });
        Some(group.advertised_count_for(peer).saturating_sub(rejected))
    }

    /// Synthesized VPN count for a grouped member after applying its sparse
    /// exact-export rejection overlay. The group table and RTC membership
    /// counters remain shared truths; only this member-local projection is
    /// reduced.
    pub(in crate::manager) fn grouped_vpn_advertised_count(&self, peer: IpAddr) -> Option<usize> {
        let gid = self.vpn_grouped_member_of(peer)?;
        let group = self.group_ribs.get(&gid)?;
        let filter = self.rtc_vpn_filter(peer, self.peer_sendable_families.get(&peer));
        let rejected = self.peer_unexportable.get(&peer).map_or(0, |keys| {
            keys.iter()
                .filter(|key| match key {
                    ExactExportKey::Vpn(key) => group.table.get_vpn(key).is_some_and(|route| {
                        route.peer != peer && rt_passes(filter.as_ref(), route)
                    }),
                    _ => false,
                })
                .count()
        });
        Some(
            group
                .vpn_advertised_count_for(peer)
                .saturating_sub(rejected),
        )
    }

    /// Per-family grouped advertised counts after subtracting the member's
    /// sparse exact-export rejection overlay. Used by BMP stat 17 and the
    /// public count query so neither reports the shared group table as wire
    /// truth for a classic-message peer that rejected an oversized route.
    pub(in crate::manager) fn grouped_family_counts(
        &self,
        peer: IpAddr,
    ) -> Option<Vec<((Afi, Safi), u64)>> {
        let gid = self.grouped_member_of(peer)?;
        let group = self.group_ribs.get(&gid)?;
        let mut counts = group.family_counts_for(peer);
        let filter = self.rtc_vpn_filter(peer, self.peer_sendable_families.get(&peer));
        if let Some(rejected) = self.peer_unexportable.get(&peer) {
            for key in rejected {
                let family = match key {
                    // Subtract only while the member's derived view
                    // holds a backstop-delivered route at the rejected
                    // slot — the lane substitution shares the staged
                    // key's prefix, so the family is identical either
                    // way, and a backstop-stripped slot was already
                    // subtracted by the synthesis's OTC term (the
                    // `grouped_advertised_count` double-subtraction
                    // rule, per family).
                    ExactExportKey::Unicast(prefix, path_id)
                        if group
                            .adv_entry_post_backstop(peer, prefix, *path_id)
                            .is_some() =>
                    {
                        Some(crate::manager::helpers::prefix_family(prefix))
                    }
                    ExactExportKey::Vpn(key)
                        if group.table.get_vpn(key).is_some_and(|route| {
                            route.peer != peer && rt_passes(filter.as_ref(), route)
                        }) =>
                    {
                        Some(key.afi_safi())
                    }
                    _ => None,
                };
                let Some(family) = family else {
                    continue;
                };
                if let Some((_, count)) = counts.iter_mut().find(|(entry, _)| *entry == family) {
                    *count = count.saturating_sub(1);
                }
            }
        }
        counts.retain(|(_, count)| *count != 0);
        Some(counts)
    }
}
