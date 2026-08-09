use super::{
    AdjRibOut, FxHashMap, GroupMembership, GroupRibOut, HashSet, IpAddr, PolicyChain, Prefix,
    RegroupBaseline, RibManager, VpnRouteKey,
};

impl RibManager {
    /// Compute (or recompute) a registered peer's update-group
    /// membership from the fingerprint inputs already in hand, and run
    /// the membership lifecycle (design §4): join = lookup-or-create
    /// the group (building its table with one shared staging pass when
    /// new); leave = drop membership (last member drops the table);
    /// regroup = leave + join with a baseline snapshot of the member's
    /// old advertised view for the one-shot resync diff. Called at the
    /// session registration seam and the export-policy replacement seam
    /// (per-peer gRPC edits, ADR-0076 live-impact txns, SIGHUP rpol
    /// overlays). A key-stable recompute (content-equal chain
    /// reinstall) is a strict no-op.
    #[expect(
        clippy::too_many_lines,
        reason = "the membership lifecycle keeps every residue-carry rule at one seam"
    )]
    pub(in crate::manager) fn recompute_update_group(&mut self, peer: IpAddr) {
        let membership = self.compute_update_group_membership(peer);
        let previous = self.update_groups.members.get(&peer).cloned();
        if previous.as_ref() == Some(&membership) {
            // Key-stable fast path: nothing moved, no regroup counted —
            // this is what keeps a 1000-peer txn installing
            // content-identical chains from shattering anything.
            return;
        }
        let prev_gid = match previous {
            Some(GroupMembership::Grouped(id)) => Some(id),
            _ => None,
        };
        let new_gid = match membership {
            GroupMembership::Grouped(id) => Some(id),
            _ => None,
        };
        self.update_groups.members.insert(peer, membership);
        // A regroup is an already-registered peer whose membership
        // moved; first registration doesn't count.
        if previous.is_some() {
            self.metrics.record_update_group_regroup();
        }
        if prev_gid != new_gid {
            // Whether the peer's VPN advertised state is group-owned
            // whenever it is grouped. Sendable families are fixed per
            // session, so this answers for source AND destination.
            let vpn_groupable = self.peer_vpn_groupable(peer);
            // Snapshot the member's currently-advertised view before the
            // move: the destination side diffs against it so only genuine
            // changes reach the wire (design §4 one-shot diff). First
            // registration has no view — the initial dump replays the
            // destination group table.
            // The member's Φ at snapshot time (a regroup never changes
            // Φ — it is keyed by peer, not group).
            let rt_filter = self.member_rt_filter(peer);
            let rejected = self
                .peer_unexportable
                .get(&peer)
                .cloned()
                .unwrap_or_default();
            let rs_control = self
                .peer_rs_control
                .get(&peer)
                .copied()
                .zip(self.peer_asn.get(&peer).copied());
            let baseline: Option<RegroupBaseline> = match prev_gid {
                Some(gid) => {
                    let group = self.group_ribs.get(&gid);
                    let base = group.map(|g| RegroupBaseline {
                        unicast: g.member_view_snapshot(peer, rs_control, &rejected),
                        vpn: g.member_vpn_view_snapshot(peer, rt_filter.as_ref(), &rejected),
                    });
                    // A member that leaves while dirty may have missed
                    // withdrawals; carry the group tombstones along as
                    // extra (over-)withdraws for the destination resync.
                    if let Some(g) = group
                        && g.dirty_members.contains(&peer)
                        && (!g.tombstones.is_empty() || !g.vpn_tombstones.is_empty())
                    {
                        let extras = self.pending_extra_withdraws.entry(peer).or_default();
                        extras.unicast.extend(g.tombstones.iter().copied());
                        extras.vpn.extend(g.vpn_tombstones.iter().copied());
                    }
                    base
                }
                None if previous.is_some() => Some(
                    self.adj_ribs_out
                        .get(&peer)
                        .map(|rib_out| RegroupBaseline {
                            unicast: rib_out
                                .iter()
                                .map(|route| ((route.prefix, route.path_id), route.clone()))
                                .collect(),
                            // VPN moves to group ownership only for a
                            // VPN-groupable peer; an RTC peer's VPN state
                            // stays per-peer and must not be captured.
                            vpn: if vpn_groupable {
                                rib_out
                                    .iter_vpn()
                                    .map(|route| (route.nlri.key(), route.clone()))
                                    .collect()
                            } else {
                                FxHashMap::default()
                            },
                        })
                        .unwrap_or_default(),
                ),
                None => None,
            };
            if let Some(gid) = prev_gid {
                self.leave_group(gid, peer);
            } else if previous.is_some() {
                // Moving off the per-peer path: the unicast (and, for a
                // VPN-groupable peer, VPN) advertised state becomes
                // group-owned (captured in the baseline); other families
                // stay per-peer.
                // ADR-0113: the private prefix index is a limited peer's
                // admitted set, and it is about to be cleared — transfer that
                // ownership into the bounded member set first.
                self.carry_outbound_admitted_across_regroup(peer, true);
                if let Some(rib_out) = self.adj_ribs_out.get_mut(&peer) {
                    rib_out.clear_unicast();
                    if vpn_groupable {
                        rib_out.clear_vpn();
                    }
                }
            }
            if prev_gid.is_some() && new_gid.is_none() {
                // Leaving for the per-peer path: the private Adj-RIB-Out is
                // re-seeded below and becomes authoritative again, so the
                // bounded member set is released rather than double-counted.
                self.carry_outbound_admitted_across_regroup(peer, false);
            }
            if let Some(gid) = new_gid {
                self.join_group(gid, peer);
            }
            match (baseline, new_gid) {
                // A member leaving a group DIRTY has a baseline that is
                // INTENDED state, not wire state: the group table
                // advances before the send that then fails, so the
                // snapshot can hold announces the member never received.
                // Using it for equality suppression would silently drop
                // those announces from the resync — an under-advertise
                // that nothing later heals (LAN-346). Keep only the
                // baseline's withdraw duty: ride its keys (plus any
                // retained baseline from an earlier unfinished regroup)
                // as extra (over-)withdraw residue — the resync's
                // retention guards filter them exactly — and let the
                // dirty resync take the suppression-free arm
                // (over-announce, the plain-dirty safe direction;
                // announces are idempotent). Applies to both grouped and
                // per-peer destinations: neither gets a baseline /
                // seeded Adj-RIB-Out to suppress against.
                (Some(base), _) if prev_gid.is_some() && self.dirty_peers.contains(&peer) => {
                    let extras = self.pending_extra_withdraws.entry(peer).or_default();
                    if let Some(prev) = self.pending_regroup_baseline.remove(&peer) {
                        extras.unicast.extend(prev.unicast.into_keys());
                        extras.vpn.extend(prev.vpn.into_keys());
                    }
                    extras.unicast.extend(base.unicast.into_keys());
                    extras.vpn.extend(base.vpn.into_keys());
                }
                (Some(mut base), Some(_)) => {
                    // A grouped member keeps no per-family record of its
                    // unicast/VPN wire state in `adj_ribs_out` (join clears
                    // it), so its `pending_regroup_baseline` entry is the
                    // ONLY record of what is on its wire. If the member's
                    // prior resync never committed (still dirty), that entry
                    // is the true wire state, while `base` is a snapshot of a
                    // group view the member was never advertised — UNION them
                    // (existing/wire values win on conflict) rather than blind
                    // overwrite. A blind overwrite drops wire keys absent from
                    // BOTH the new snapshot and the new group's table: they
                    // would never be withdrawn and leak as stale routes. One
                    // baseline covers unicast AND VPN, so this covers both.
                    if self.dirty_peers.contains(&peer)
                        && let Some(prev) = self.pending_regroup_baseline.remove(&peer)
                    {
                        base.unicast.extend(prev.unicast);
                        base.vpn.extend(prev.vpn);
                    }
                    self.pending_regroup_baseline.insert(peer, base);
                }
                (Some(mut base), None) => {
                    // Back on the per-peer path: seed Adj-RIB-Out with
                    // the old advertised view so the dirty resync diffs
                    // against it instead of re-flooding the table.
                    // Same union rule as the grouped arm above: a
                    // still-dirty leaver's retained baseline is the
                    // only record of its true wire state — fold it
                    // into the seed (wire values win on conflict) and
                    // consume the entry, or its keys could never be
                    // withdrawn from the per-peer path.
                    if self.dirty_peers.contains(&peer)
                        && let Some(prev) = self.pending_regroup_baseline.remove(&peer)
                    {
                        base.unicast.extend(prev.unicast);
                        base.vpn.extend(prev.vpn);
                    }
                    let loc_rib_len = self.loc_rib.len();
                    let rib_out = self
                        .adj_ribs_out
                        .entry(peer)
                        .or_insert_with(|| AdjRibOut::with_capacity(peer, loc_rib_len));
                    for route in base.unicast.into_values() {
                        rib_out.insert(route);
                    }
                    for route in base.vpn.into_values() {
                        rib_out.insert_vpn(route);
                    }
                }
                (None, _) => {}
            }
        }
        self.refresh_update_group_gauges();
        // The regroup carry (a dirty leaver's tombstones riding into
        // its extra withdraws) mutates residue on this path too.
        self.refresh_group_residue_gauge();
    }

    /// Add a member; a group seen for the first time snapshots its
    /// group-uniform staging inputs from the joining peer (all members
    /// are key-equal) and builds the shared table with one staging pass
    /// — the policy work every subsequent join replays for free.
    pub(super) fn join_group(&mut self, gid: usize, peer: IpAddr) {
        // Every membership seam funnels through here (registration,
        // recompute, per-peer policy install): a join landing on the gid
        // of a mid-walk destination prestage must discard the prestage
        // BEFORE the member replays any table — adopting the partial
        // table would record the remaining walk's routes as advertised
        // without ever emitting them (LAN-463). The discard makes the
        // group absent again, so the ordinary rebuild below runs.
        self.discard_destination_prestage_on_membership(gid);
        self.ensure_group_table(gid, peer);
        self.install_group_member(gid, peer);
    }

    /// Build the group's staged table when it does not exist yet — the
    /// join-time build pass (one shared staging walk, deltas discarded:
    /// correct only while the group is memberless). `peer` is the
    /// exemplar whose group-uniform staging inputs seed the profile.
    pub(in crate::manager) fn ensure_group_table(&mut self, gid: usize, peer: IpAddr) {
        if !self.group_ribs.contains_key(&gid) {
            let group = GroupRibOut::new(
                // `share()`, not `clone()`: the snapshot must keep
                // feeding the installed chain's ADR-0096 hit counters.
                self.export_policy_for(peer).map(PolicyChain::share),
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
                // ADR-0126 Decision 1: the staging mode derives from
                // the group key's `per_client_best` bit.
                self.update_groups
                    .group_key(gid)
                    .is_some_and(|key| key.per_client_best),
                self.loc_rib.len(),
            );
            self.group_ribs.insert(gid, group);
            let prefixes: HashSet<Prefix> = self.loc_rib.iter().map(|r| r.prefix).collect();
            let mut memo = crate::manager::distribution::ExportMemo::default();
            // Deltas of the build passes are discarded: there are no
            // members yet, and the joining member replays the whole
            // table anyway.
            let _ = self.stage_group_prefixes(gid, &prefixes, &mut memo);
            if self
                .group_ribs
                .get(&gid)
                .is_some_and(GroupRibOut::stages_vpn)
            {
                let keys: HashSet<VpnRouteKey> =
                    self.loc_rib.iter_vpn().map(|r| r.nlri.key()).collect();
                if !keys.is_empty() {
                    let _ = self.stage_group_vpn_keys(gid, &keys);
                }
            }
        }
    }

    /// Install one peer into an already-created group and make the peer's
    /// operator-visible policy handle share the group's actual counter
    /// instance. Every grouped membership path uses this seam: ordinary
    /// recompute/fallback, rollback to a prior group, and the optimized clean
    /// transition commit. Ungrouped peers never pass through it and retain
    /// their independently installed chain.
    pub(super) fn install_group_member(&mut self, gid: usize, peer: IpAddr) {
        // Grouped unicast state belongs to GroupRibOut. Install the private
        // multi-family table with no unicast reservation before any family
        // can become its first creator; non-unicast state still lives here,
        // and an eventual ungroup grows the slab while seeding its baseline.
        self.adj_ribs_out
            .entry(peer)
            .or_insert_with(|| AdjRibOut::new(peer));

        let export_chain = self
            .group_ribs
            .get(&gid)
            .expect("group must exist before installing a member")
            .export_chain
            .as_ref()
            .map(PolicyChain::share);
        self.peer_export_policies.insert(peer, export_chain);

        // The joining member's advertised-count seed (RTC groups only):
        // the O(table) walk rides the join replay's existing cost.
        let filter = self.member_rt_filter(peer);
        if let Some(group) = self.group_ribs.get_mut(&gid) {
            group.members.insert(peer);
            group.recompute_vpn_member_counts(peer, filter.as_ref());
        }
    }
}
