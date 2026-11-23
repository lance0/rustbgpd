use super::{
    AdjRibOut, ExactExportKey, FastMap, GroupMembership, GroupRibOut, HashSet, PolicyChain,
    RegroupBaseline, RibManager, VpnRibRouteKey,
};
use crate::PeerId;

impl RibManager {
    /// Planning and allocation share one ownership decision without installing
    /// the destination table before the last OLD member has left.
    pub(in crate::manager) fn planned_group_owns_evpn(&self, gid: usize) -> bool {
        self.group_ribs.get(&gid).map_or_else(
            || {
                self.update_groups
                    .group_key(gid)
                    .is_some_and(|key| key.owns_evpn)
            },
            GroupRibOut::owns_evpn_routes,
        )
    }

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
    ///
    /// The returned feed may be dropped: a member that leaves an owned EVPN
    /// group holds a proof of actual OLD before anything moves.
    pub(in crate::manager) fn recompute_update_group(
        &mut self,
        peer: PeerId,
    ) -> Option<super::super::evpn_recovery::EvpnCompleteFeed> {
        let membership = self.compute_update_group_membership(peer);
        self.recompute_update_group_inner(peer, false, membership)
    }

    /// [`Self::recompute_update_group`] for a caller that hands the returned
    /// feed to a distribution pass in the same actor turn. A clean member
    /// moving between two owned EVPN groups then captures no proof: the pass
    /// settles its feed, and captures actual OLD from the feed's basis only
    /// if the admission is missed
    /// ([`RibManager::settle_clean_evpn_regroup`]).
    pub(in crate::manager) fn recompute_update_group_for_pass(
        &mut self,
        peer: PeerId,
    ) -> Option<super::super::evpn_recovery::EvpnCompleteFeed> {
        let membership = self.compute_update_group_membership(peer);
        self.recompute_update_group_inner(peer, true, membership)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the membership lifecycle keeps every residue-carry rule at one seam"
    )]
    pub(in crate::manager) fn recompute_update_group_inner(
        &mut self,
        peer: PeerId,
        feeds_pass: bool,
        membership: GroupMembership,
    ) -> Option<super::super::evpn_recovery::EvpnCompleteFeed> {
        self.replacement_checkpoint(false);
        let previous = self.update_groups.members.get(&peer).cloned();
        if previous.as_ref() == Some(&membership) {
            // Key-stable fast path: nothing moved, no regroup counted —
            // this is what keeps a 1000-peer txn installing
            // content-identical chains from shattering anything.
            return None;
        }
        // Owed keys were recorded against the old ownership. Capture admitted
        // OLD before marking dirty so regroup recovery retains its withdrawals.
        if self.drop_peer_owing(peer) {
            self.mark_outbound_dirty(peer);
        }
        let prev_gid = match previous {
            Some(GroupMembership::Grouped(id)) => Some(id),
            _ => None,
        };
        let new_gid = match membership {
            GroupMembership::Grouped(id) => Some(id),
            _ => None,
        };
        let old_evpn_owned = prev_gid.is_some_and(|gid| {
            self.group_ribs
                .get(&gid)
                .is_some_and(GroupRibOut::owns_evpn_routes)
        });
        // A clean member bound for an installed owned table skips the
        // capture: its feed carries the basis of actual OLD instead.
        let clean_evpn_regroup = feeds_pass
            && old_evpn_owned
            && new_gid.is_some_and(|gid| self.clean_evpn_regroup_eligible(peer, gid));
        // Capture actual OLD before any registry change or last-member leave.
        // A failed capture retains the old owner until its fenced reset.
        if old_evpn_owned && !clean_evpn_regroup && !self.capture_shared_evpn_admitted(peer) {
            self.invalidate_evpn_feed_completion(peer);
            self.mark_outbound_dirty_inner(peer, false);
            return None;
        }
        let old_evpn_clean = (!self.dirty_peers.contains(&peer)
            && (!old_evpn_owned
                || prev_gid
                    .is_some_and(|gid| !self.group_ribs[&gid].dirty_members.contains(&peer))))
            || (old_evpn_owned && self.evpn_feed_is_current(peer));
        let new_evpn_owned = new_gid.is_some_and(|gid| self.planned_group_owns_evpn(gid));
        let deferred_evpn_destination =
            new_evpn_owned && new_gid.is_some_and(|gid| !self.group_ribs.contains_key(&gid));
        if new_evpn_owned
            && !old_evpn_owned
            && !self.capture_private_evpn_before_join(peer, new_gid.expect("owned destination"))
        {
            self.invalidate_evpn_feed_completion(peer);
            self.mark_outbound_dirty_inner(peer, false);
            return None;
        }
        let private_evpn_seed = if old_evpn_owned && (!new_evpn_owned || deferred_evpn_destination)
        {
            let gid = prev_gid.expect("owned OLD has a group");
            let old = &self.group_ribs[&gid];
            let filter = self.rtc_export_filter(peer, Some(&old.sendable));
            let proof = self
                .evpn_recovery_handle(peer)
                .and_then(|handle| self.evpn_recovery.proof(handle).ok().flatten());
            let complete_proof = proof.is_some();
            let count = if old_evpn_clean
                && old.evpn_projection_complete_with_checkpoint(&mut || {
                    self.replacement_checkpoint(false)
                })
                && self
                    .adj_ribs_out
                    .get(&peer)
                    .is_none_or(|private| private.evpn_len() == 0)
            {
                proof.and_then(|proof| {
                    old.evpn_member_projection_with_checkpoint(
                        peer,
                        self.cluster_id,
                        filter.as_ref(),
                        self.peer_unexportable.get(&peer),
                        &|| self.replacement_checkpoint(false),
                    )
                    .try_fold(0usize, |count, route| {
                        proof.contains(&route.key()).then_some(count + 1)
                    })
                    .filter(|count| *count == proof.len())
                })
            } else {
                None
            };
            if !complete_proof || (old_evpn_clean && count.is_none()) {
                // An incomplete proof cannot transfer its OLD duties. A
                // complete dirty proof instead heals through destination resync.
                if let Some(handle) = self.evpn_recovery_handle(peer) {
                    self.evpn_recovery.fail_admission(handle);
                }
                self.invalidate_evpn_feed_completion(peer);
                self.mark_outbound_dirty_inner(peer, false);
                self.retry_evpn_recovery_reset(peer);
                return None;
            }
            count.map(|count| (gid, count))
        } else {
            None
        };
        // The existing private store carries actual OLD across retirement;
        // complete mixed admission releases it after an owned destination joins.
        if let Some((gid, count)) = private_evpn_seed {
            let old = &self.group_ribs[&gid];
            let filter = self.rtc_export_filter(peer, Some(&old.sendable));
            let rejected = self.peer_unexportable.get(&peer);
            let readiness = &self.replacement_readiness;
            let cluster_id = self.cluster_id;
            let seed = |private: &mut AdjRibOut, live| {
                let mut checkpoint =
                    || crate::manager::checkpoint_with_summary_reader(readiness, None, false, live);
                private.reserve_evpn_with(count, &mut checkpoint);
                for route in old.evpn_member_projection_with_checkpoint(
                    peer,
                    cluster_id,
                    filter.as_ref(),
                    rejected,
                    &checkpoint,
                ) {
                    private.insert_evpn(route.clone());
                }
            };
            if self.can_detach_summary_peer(peer) {
                let mut private = self
                    .adj_ribs_out
                    .remove(&peer)
                    .unwrap_or_else(|| AdjRibOut::new(peer));
                seed(&mut private, Some(self));
                self.adj_ribs_out.insert(peer, private);
            } else {
                seed(
                    self.adj_ribs_out
                        .entry(peer)
                        .or_insert_with(|| AdjRibOut::new(peer)),
                    None,
                );
            }
        }
        self.invalidate_evpn_feed_completion(peer);
        let clean_evpn_feed = if clean_evpn_regroup {
            self.prepare_clean_regroup_evpn_feed(
                peer,
                new_gid.expect("eligible destination"),
                prev_gid.expect("owned OLD has a group"),
            )
        } else {
            None
        };
        // No feed, so no basis: OLD is still installed. Capture it and go
        // on exactly as a member that was never eligible.
        if clean_evpn_regroup
            && clean_evpn_feed.is_none()
            && !self.capture_shared_evpn_admitted(peer)
        {
            self.invalidate_evpn_feed_completion(peer);
            self.mark_outbound_dirty_inner(peer, false);
            return None;
        }
        let mut evpn_feed = if clean_evpn_feed.is_some() {
            clean_evpn_feed
        } else if new_evpn_owned {
            new_gid
                .filter(|_| !deferred_evpn_destination && !self.complete_feed_deferred(peer))
                .and_then(|gid| {
                    self.prepare_complete_evpn_feed(
                        peer,
                        gid,
                        prev_gid.filter(|_| old_evpn_owned),
                        old_evpn_clean,
                    )
                })
        } else {
            if old_evpn_owned && !self.begin_private_evpn_handoff(peer) {
                if let Some(handle) = self.evpn_recovery_handle(peer) {
                    self.evpn_recovery.fail_admission(handle);
                }
                self.mark_outbound_dirty_inner(peer, false);
                self.retry_evpn_recovery_reset(peer);
                return None;
            }
            None
        };
        if previous.is_some() && (prev_gid.is_some() || new_gid.is_some()) {
            self.capture_group_admitted_keys(peer);
        }
        self.update_groups.members.insert(peer, membership);
        // A regroup is an already-registered peer whose membership
        // moved; first registration doesn't count.
        if previous.is_some() {
            self.metrics.record_update_group_regroup();
        }
        if prev_gid != new_gid {
            self.set_selection_partial_caught_up(peer, false);
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
            let mut baseline: Option<RegroupBaseline> = match prev_gid {
                Some(gid) => {
                    let group = self.group_ribs.get(&gid);
                    let base = group.map(|g| {
                        let mut base = g.member_view_snapshot_with_checkpoint(
                            peer,
                            rs_control,
                            &rejected,
                            &mut |force| {
                                if force {
                                    self.replacement_checkpoint(true);
                                } else {
                                    self.replacement_checkpoint_at("fallback_baseline", false);
                                }
                            },
                        );
                        base.vpn = g.member_vpn_view_snapshot_with_checkpoint(
                            peer,
                            rt_filter.as_ref(),
                            &rejected,
                            &mut |force| {
                                if force {
                                    self.replacement_checkpoint(true);
                                } else {
                                    self.replacement_checkpoint_at("fallback_baseline", false);
                                }
                            },
                        );
                        base
                    });
                    // A member that leaves while dirty may have missed
                    // withdrawals; carry the group tombstones along as
                    // candidate withdrawals for the destination resync.
                    if let Some(g) = group
                        && g.dirty_members.contains(&peer)
                        && (!g.tombstones.is_empty() || !g.vpn_tombstones.is_empty())
                    {
                        let mut extras = self
                            .pending_extra_withdraws
                            .remove(&peer)
                            .unwrap_or_default();
                        extras.unicast.extend(
                            g.tombstones
                                .iter()
                                .inspect(|_| self.replacement_checkpoint(false))
                                .copied(),
                        );
                        extras.vpn.extend(
                            g.vpn_tombstones
                                .iter()
                                .inspect(|_| self.replacement_checkpoint(false))
                                .copied(),
                        );
                        self.pending_extra_withdraws.insert(peer, extras);
                    }
                    base
                }
                None if previous.is_some() => Some(
                    self.adj_ribs_out
                        .get(&peer)
                        .map(|rib_out| {
                            let mut unicast = FastMap::with_capacity_and_hasher(
                                rib_out.len(),
                                crate::fast_hash::FastState::default(),
                            );
                            self.replacement_checkpoint(false);
                            for route in rib_out.iter() {
                                self.replacement_checkpoint_at("fallback_baseline", false);
                                unicast.insert((route.prefix, route.path_id), route.clone());
                            }
                            let next_hop_overrides = rib_out
                                .iter()
                                .filter_map(|route| {
                                    self.replacement_checkpoint_at("fallback_baseline", false);
                                    rib_out.next_hop_override(&route.prefix, route.path_id).map(
                                        |action| ((route.prefix, route.path_id), action.clone()),
                                    )
                                })
                                .collect();
                            let mut vpn = FastMap::default();
                            if vpn_groupable {
                                vpn = FastMap::with_capacity_and_hasher(
                                    rib_out.vpn_len(),
                                    crate::fast_hash::FastState::default(),
                                );
                                self.replacement_checkpoint(false);
                                for route in rib_out.iter_vpn() {
                                    self.replacement_checkpoint_at("fallback_baseline", false);
                                    vpn.insert(route.nlri.key(), route.clone());
                                }
                            }
                            RegroupBaseline {
                                unicast,
                                next_hop_overrides,
                                vpn,
                            }
                        })
                        .unwrap_or_default(),
                ),
                None => None,
            };
            if let Some(base) = baseline.as_mut()
                && let Some(admitted) = self.pending_group_admitted.get(&peer)
            {
                base.unicast.retain(|(prefix, path_id), _| {
                    self.replacement_checkpoint(false);
                    admitted.contains(&ExactExportKey::Unicast(*prefix, *path_id))
                });
                base.next_hop_overrides.retain(|key, _| {
                    self.replacement_checkpoint(false);
                    base.unicast.contains_key(key)
                });
                base.vpn.retain(|nlri_key, _| {
                    self.replacement_checkpoint(false);
                    admitted.contains(&ExactExportKey::Vpn(VpnRibRouteKey {
                        nlri_key: *nlri_key,
                        path_id: 0,
                    }))
                });
            }
            if let Some(base) = &baseline {
                self.replacement_capacity(
                    "transient_baseline_unicast",
                    base.unicast.len(),
                    base.unicast.capacity(),
                );
                self.replacement_capacity(
                    "transient_baseline_vpn",
                    base.vpn.len(),
                    base.vpn.capacity(),
                );
            }
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
                let readiness = &self.replacement_readiness;
                let release = |rib: &mut AdjRibOut, live| {
                    let mut checkpoint = || {
                        crate::manager::checkpoint_with_summary_reader(readiness, None, true, live)
                    };
                    rib.release_unicast_with(&mut checkpoint);
                    if vpn_groupable {
                        rib.release_vpn_with(&mut checkpoint);
                    }
                };
                if self.can_detach_summary_peer(peer) {
                    if let Some(mut rib) = self.adj_ribs_out.remove(&peer) {
                        release(&mut rib, Some(self));
                        self.adj_ribs_out.insert(peer, rib);
                    }
                } else if let Some(rib) = self.adj_ribs_out.get_mut(&peer) {
                    release(rib, None);
                }
            }
            if prev_gid.is_some() && new_gid.is_none() {
                // Leaving for the per-peer path: the private Adj-RIB-Out is
                // re-seeded below and becomes authoritative again, so the
                // bounded member set is released rather than double-counted.
                if !self.retain_initial_group_admitted(peer) {
                    self.carry_outbound_admitted_across_regroup(peer, false);
                }
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
                // baseline's candidate keys: ride its keys (plus any
                // retained baseline from an earlier unfinished regroup)
                // as candidate withdrawal residue — the resync's
                // retention guards filter them exactly — and let the
                // dirty resync take the suppression-free arm
                // (over-announce, the plain-dirty safe direction;
                // announces are idempotent). Applies to both grouped and
                // per-peer destinations: neither gets a baseline /
                // seeded Adj-RIB-Out to suppress against.
                (Some(base), _) if prev_gid.is_some() && self.dirty_peers.contains(&peer) => {
                    let previous = self.pending_regroup_baseline.remove(&peer);
                    if let Some(prev) = &previous {
                        self.replacement_capacity(
                            "transient_baseline_unicast",
                            prev.unicast.len(),
                            prev.unicast.capacity(),
                        );
                        self.replacement_capacity(
                            "transient_baseline_vpn",
                            prev.vpn.len(),
                            prev.vpn.capacity(),
                        );
                    }
                    let mut extras = self
                        .pending_extra_withdraws
                        .remove(&peer)
                        .unwrap_or_default();
                    for mut baseline in previous.into_iter().chain(std::iter::once(base)) {
                        crate::adj_rib_out::release_hash_map(
                            &mut baseline.next_hop_overrides,
                            &mut || self.replacement_checkpoint(false),
                        );
                        let mut unicast = baseline.unicast.into_keys();
                        extras.unicast.extend(
                            unicast
                                .by_ref()
                                .inspect(|_| self.replacement_checkpoint(false)),
                        );
                        self.replacement_checkpoint(true);
                        drop(unicast);
                        self.replacement_checkpoint(true);
                        let mut vpn = baseline.vpn.into_keys();
                        extras
                            .vpn
                            .extend(vpn.by_ref().inspect(|_| self.replacement_checkpoint(false)));
                        self.replacement_checkpoint(true);
                        drop(vpn);
                        self.replacement_checkpoint(true);
                    }
                    // Empty baselines carry no withdraw duty: never leave an
                    // empty residue entry behind (readers check the key).
                    if !extras.unicast.is_empty() || !extras.vpn.is_empty() {
                        self.pending_extra_withdraws.insert(peer, extras);
                    }
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
                        base.merge_prior(prev, &mut || self.replacement_checkpoint(false));
                    }
                    self.replacement_capacity(
                        "transient_baseline_unicast",
                        base.unicast.len(),
                        base.unicast.capacity(),
                    );
                    self.replacement_capacity(
                        "transient_baseline_vpn",
                        base.vpn.len(),
                        base.vpn.capacity(),
                    );
                    if let Some(mut replaced) = self.pending_regroup_baseline.insert(peer, base) {
                        replaced.retire_with(&mut || self.replacement_checkpoint(false));
                    }
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
                        base.merge_prior(prev, &mut || self.replacement_checkpoint(false));
                    }
                    self.replacement_capacity(
                        "transient_baseline_unicast",
                        base.unicast.len(),
                        base.unicast.capacity(),
                    );
                    self.replacement_capacity(
                        "transient_baseline_vpn",
                        base.vpn.len(),
                        base.vpn.capacity(),
                    );
                    let loc_rib_len = self.loc_rib.len().max(base.unicast.len());
                    let readiness = &self.replacement_readiness;
                    let seed = |rib_out: &mut AdjRibOut, live| {
                        let checkpoint = |force| {
                            crate::manager::checkpoint_with_summary_reader(
                                readiness, None, force, live,
                            )
                        };
                        rib_out.reserve_unicast_with(base.unicast.len(), &mut || checkpoint(false));
                        rib_out.reserve_vpn_with(base.vpn.values(), &mut || checkpoint(false));
                        let mut unicast = base.unicast.into_values();
                        for route in unicast.by_ref() {
                            checkpoint(false);
                            let action = base
                                .next_hop_overrides
                                .remove(&(route.prefix, route.path_id));
                            rib_out.insert_with_next_hop(route, action, &mut || checkpoint(false));
                        }
                        checkpoint(true);
                        drop(unicast);
                        checkpoint(true);
                        crate::adj_rib_out::release_hash_map(
                            &mut base.next_hop_overrides,
                            &mut || checkpoint(false),
                        );
                        let mut vpn = base.vpn.into_values();
                        for route in vpn.by_ref() {
                            checkpoint(false);
                            rib_out.insert_vpn(route);
                        }
                        checkpoint(true);
                        drop(vpn);
                        checkpoint(true);
                    };
                    if self.can_detach_summary_peer(peer) {
                        let mut rib = self
                            .adj_ribs_out
                            .remove(&peer)
                            .unwrap_or_else(|| AdjRibOut::with_capacity(peer, loc_rib_len));
                        seed(&mut rib, Some(self));
                        self.adj_ribs_out.insert(peer, rib);
                    } else {
                        seed(
                            self.adj_ribs_out
                                .entry(peer)
                                .or_insert_with(|| AdjRibOut::with_capacity(peer, loc_rib_len)),
                            None,
                        );
                    }
                }
                (None, _) => {}
            }
        }
        self.refresh_update_group_gauges();
        // The regroup carry (a dirty leaver's tombstones riding into
        // its extra withdraws) mutates residue on this path too.
        self.refresh_group_residue_gauge();
        if new_gid.is_none()
            && !self.dirty_peers.contains(&peer)
            && !self.retain_initial_group_admitted(peer)
        {
            self.release_group_admitted_keys(peer);
        }
        if deferred_evpn_destination {
            evpn_feed = new_gid
                .filter(|_| !self.complete_feed_deferred(peer))
                .and_then(|gid| self.prepare_complete_evpn_feed(peer, gid, None, old_evpn_clean));
        }
        evpn_feed
    }

    /// Add a member; a group seen for the first time snapshots its
    /// group-uniform staging inputs from the joining peer (all members
    /// are key-equal) and builds the shared table with one staging pass
    /// — the policy work every subsequent join replays for free.
    pub(super) fn join_group(&mut self, gid: usize, peer: PeerId) {
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

    /// The group installation will select for this waiting, policy-free session.
    /// Some per-member features, including RS control, affect replay but do not
    /// distinguish the shared unicast table.
    fn pending_registration_key(
        &self,
        peer: PeerId,
        record: &super::super::LiveSessionRecord,
    ) -> Option<super::GroupKey> {
        record.registration_wait_since?;
        if self.outbound_peers.contains_key(&peer) || record.export_policy.is_some() {
            return None;
        }
        let input = self.update_group_classifier_input(
            peer,
            None,
            !record.negotiated_orf_recv.is_empty() || self.peer_orf_filters.contains_key(&peer),
            false,
            Some(record),
        );
        self.no_policy_group_key(peer, input, false)
    }

    /// Match the actual staging profile, including the bench-only EVPN owner
    /// dimension, for a proposed no-policy membership.
    pub(super) fn no_policy_group_key(
        &self,
        peer: PeerId,
        input: super::UpdateGroupClassifierInput,
        slow_recovery: bool,
    ) -> Option<super::GroupKey> {
        #[cfg(test)]
        if self.test_force_ungrouped {
            return None;
        }
        if !slow_recovery && self.slow_isolated_peers.contains(&peer) {
            return None;
        }
        #[cfg(feature = "bench-internals")]
        let owns_evpn = self.bench_evpn_group_ownership
            && !input.per_client_best
            && input
                .sendable_families
                .contains(&(super::Afi::L2Vpn as u16, super::Safi::Evpn as u8))
            && !input
                .sendable_families
                .contains(&(super::Afi::Ipv4 as u16, super::Safi::RtConstrain as u8));
        let super::UpdateGroupClassification::Groupable(fingerprint) =
            super::classify_update_group(input)
        else {
            return None;
        };
        #[cfg(not(feature = "bench-internals"))]
        let owns_evpn = false;
        Some(super::GroupKey::from_fingerprint(
            fingerprint,
            None,
            owns_evpn,
        ))
    }

    /// A returning session can match a legacy preparation with any groupable
    /// export chain. Its retained record supplies the inputs not yet installed.
    pub(in crate::manager) fn pending_registration_matches_group(
        &self,
        peer: PeerId,
        gid: usize,
        prepared_policy: Option<&PolicyChain>,
    ) -> bool {
        let Some(record) = self
            .live_sessions
            .get(&peer)
            .and_then(|sessions| sessions.last())
        else {
            return false;
        };
        let Some(expected) = self.update_groups.group_key(gid) else {
            return false;
        };
        if record.registration_wait_since.is_none()
            || record.export_policy.as_ref() != prepared_policy
        {
            return false;
        }
        let input = self.update_group_classifier_input(
            peer,
            prepared_policy,
            !record.negotiated_orf_recv.is_empty() || self.peer_orf_filters.contains_key(&peer),
            false,
            Some(record),
        );
        self.no_policy_group_key(peer, input, false)
            .is_some_and(|mut key| {
                // The prepared chain was compared above, including its content if
                // the historical intern entry has since been reclaimed.
                key.chain = expected.chain;
                &key == expected
            })
    }

    pub(in crate::manager) fn registration_matches_first_group(
        &self,
        peer: PeerId,
        gid: usize,
    ) -> bool {
        let Some(key) = self
            .live_sessions
            .get(&peer)
            .and_then(|sessions| sessions.last())
            .and_then(|record| self.pending_registration_key(peer, record))
        else {
            return false;
        };
        self.update_groups.group_key(gid) == Some(&key)
    }

    /// Only plain registrations may start a private build.
    pub(in crate::manager) fn prospective_first_group(
        &mut self,
        peer: PeerId,
        expected_gid: Option<usize>,
    ) -> Option<(
        usize,
        u64,
        tokio::sync::mpsc::Sender<crate::update::OutboundRouteUpdate>,
    )> {
        use rustbgpd_wire::{Afi, Safi};

        let record = self.live_sessions.get(&peer)?.last()?;
        if record.local_role.is_some()
            || record.rs_control_asn.is_some()
            || record.per_client_best
            || record.sendable_families.is_empty()
            || record.sendable_families.iter().any(|&family| {
                !matches!(family, (Afi::Ipv4 | Afi::Ipv6, Safi::Unicast))
                    || self.selection_deferral.as_ref().is_some_and(|state| state.may_hold_family(family))
            })
            // With a local RR, export to a non-client depends on each source's
            // current client status, which can change without a Loc-RIB write.
            || (self.cluster_id.is_some() && !record.is_ebgp && !record.route_reflector_client)
        {
            return None;
        }
        let key = self.pending_registration_key(peer, record)?;
        let session_id = record.session_id;
        let sender = record.outbound_tx.clone();
        let gid = match expected_gid {
            Some(id) if self.update_groups.group_key(id) == Some(&key) => id,
            Some(_) => return None,
            None => self.update_groups.group_for(key),
        };
        Some((gid, session_id, sender))
    }

    /// Take the pending session's eligible profile. The segmented table grows
    /// as rows stage, avoiding a Loc-RIB-sized reservation at admission.
    pub(in crate::manager) fn first_group_table(&self, peer: PeerId, gid: usize) -> GroupRibOut {
        let record = self.live_sessions[&peer]
            .last()
            .expect("registration just classified");
        let key = self
            .update_groups
            .group_key(gid)
            .expect("registration just classified");
        GroupRibOut::new(
            None,
            key.target_is_ebgp,
            key.interpret_rfc1997,
            key.target_is_rr_client,
            None,
            record.sendable_families.clone(),
            record.negotiated_llgr_families.clone(),
            false,
            0,
        )
    }

    /// A table installed by an intervening join or policy preparation wins.
    /// Return the losing table to its owner for bounded retirement.
    pub(in crate::manager) fn publish_first_group(
        &mut self,
        gid: usize,
        mut table: GroupRibOut,
    ) -> Option<GroupRibOut> {
        if self.group_ribs.contains_key(&gid) {
            return Some(table);
        }
        table.evpn_table_stamp = self.next_evpn_table_stamp().unwrap_or(0);
        self.group_ribs.insert(gid, table);
        None
    }

    /// Build the group's staged table when it does not exist yet — the
    /// join-time build pass (one shared staging walk, deltas discarded:
    /// correct only while the group is memberless). `peer` is the
    /// exemplar whose group-uniform staging inputs seed the profile.
    #[expect(
        clippy::too_many_lines,
        reason = "the ordered family staging and its readiness checkpoints share one group build"
    )]
    pub(in crate::manager) fn ensure_group_table(&mut self, gid: usize, peer: PeerId) {
        if !self.group_ribs.contains_key(&gid) {
            #[cfg(test)]
            if let Some(observer) = &self.replacement_readiness_test_hook {
                observer(if self.group_ribs.is_empty() {
                    "destination_build_without_installed_tables"
                } else {
                    "destination_build_with_installed_tables"
                });
            }
            self.replacement_checkpoint(true);
            let mut group = GroupRibOut::new(
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
            self.replacement_checkpoint(true);
            group.owns_evpn = self.planned_group_owns_evpn(gid);
            if self.paced_policy_destination == Some(gid) {
                group.prepare_optional_retirement();
            }
            group.evpn_table_stamp = self.next_evpn_table_stamp().unwrap_or(0);
            self.group_ribs.insert(gid, group);
            self.replacement_checkpoint(true);
            let mut prefixes = HashSet::with_capacity(self.loc_rib.len());
            self.replacement_checkpoint(true);
            prefixes.extend(
                self.loc_rib
                    .iter()
                    .inspect(|_| crate::manager::group_build_row_checkpoint(self))
                    .map(|r| r.prefix),
            );
            let mut memo = crate::manager::distribution::ExportMemo::default();
            // Deltas of the build passes are discarded: there are no
            // members yet, and the joining member replays the whole
            // table anyway.
            #[cfg(test)]
            let last = self
                .cold_build_last_prefix
                .and_then(|prefix| prefixes.take(&prefix));
            let mut staged = self.stage_group_prefixes(gid, &prefixes, &mut memo);
            staged.retire_with(&mut |force| self.replacement_checkpoint(force));
            drop(staged);
            #[cfg(test)]
            if let Some(last) = last {
                let mut final_row =
                    self.stage_group_prefixes(gid, &HashSet::from([last]), &mut memo);
                final_row.retire_with(&mut |force| self.replacement_checkpoint(force));
            }
            self.replacement_checkpoint(true);
            if self
                .group_ribs
                .get(&gid)
                .is_some_and(GroupRibOut::stages_vpn)
            {
                self.replacement_checkpoint(true);
                let mut keys = HashSet::with_capacity(self.loc_rib.vpn_len());
                self.replacement_checkpoint(true);
                keys.extend(
                    self.loc_rib
                        .iter_vpn()
                        .inspect(|_| self.replacement_checkpoint(false))
                        .map(|r| r.nlri.key()),
                );
                if !keys.is_empty() {
                    let mut staged = self.stage_group_vpn_keys(gid, &keys);
                    staged.retire_with(&mut |force| self.replacement_checkpoint(force));
                }
                self.replacement_checkpoint(true);
                crate::manager::retire_hash_set(&mut keys, &mut || {
                    self.replacement_checkpoint(false)
                });
                self.replacement_checkpoint(true);
            }
            if self
                .group_ribs
                .get(&gid)
                .is_some_and(GroupRibOut::owns_evpn_routes)
            {
                let mut keys = self
                    .loc_rib
                    .iter_evpn()
                    .inspect(|_| self.replacement_checkpoint(false))
                    .map(crate::route::EvpnRibRoute::key)
                    .collect();
                let mut staged = self.stage_group_evpn_keys(gid, &keys);
                staged.retire_with(&mut |force| self.replacement_checkpoint(force));
                crate::manager::retire_hash_set(&mut keys, &mut || {
                    self.replacement_checkpoint(false)
                });
            }
            self.replacement_checkpoint(true);
            #[cfg(feature = "bench-internals")]
            memo.record_replacement_capacities(self);
            memo.retire_with(&mut || self.replacement_checkpoint(false));
            self.replacement_checkpoint(true);
            crate::manager::retire_hash_set(&mut prefixes, &mut || {
                self.replacement_checkpoint(false)
            });
            self.replacement_checkpoint(true);
            drop(memo);
            drop(prefixes);
            self.replacement_checkpoint(true);
        }
    }

    /// Install one peer into an already-created group and make the peer's
    /// operator-visible policy handle share the group's actual counter
    /// instance. Every grouped membership path uses this seam: ordinary
    /// recompute/fallback, rollback to a prior group, and the optimized clean
    /// transition commit. Ungrouped peers never pass through it and retain
    /// their independently installed chain.
    pub(super) fn install_group_member(&mut self, gid: usize, peer: PeerId) {
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
        self.export_chains.insert(peer, export_chain);

        // The joining member's advertised-count seed (RTC groups only):
        // the O(table) walk rides the join replay's existing cost.
        let filter = self.member_rt_filter(peer);
        let rs_control = self.rs_control_context(peer);
        #[cfg(feature = "bench-internals")]
        if let Some(group) = self.group_ribs.get(&gid) {
            let (len, slots, capacity) = group.table.bench_unicast_storage_shape();
            self.replacement_storage_shape("group_before_shrink", len, capacity, slots);
        }
        if self.prepared_destination == Some(gid)
            && self
                .group_ribs
                .get(&gid)
                .is_some_and(|group| group.members.is_empty())
        {
            self.adopt_prepared_destination(gid);
        }
        if self.paced_policy_destination == Some(gid) {
            self.paced_policy_destination = None;
        }
        let readiness = &self.replacement_readiness;
        let keys = self.peer_unexportable.get(&peer);
        let install = |group: &mut GroupRibOut, live| {
            let checkpoint = |force| {
                crate::manager::checkpoint_with_summary_reader(readiness, None, force, live)
            };
            if group.members.is_empty() {
                checkpoint(true);
                group.table.shrink_unicast_to_fit();
                checkpoint(true);
            }
            group.members.insert(peer);
            group.recompute_vpn_member_counts(peer, filter.as_ref(), &mut || {
                checkpoint(false);
            });
            if let Some(rs_control) = rs_control {
                group.add_rs_member(peer, rs_control, &mut || {
                    checkpoint(false);
                });
            }
            if let Some(keys) = keys {
                let mut counts = [0; 4];
                for key in keys {
                    checkpoint(false);
                    if let Some(slot) =
                        group.visible_rejected_slot(peer, key, rs_control, filter.as_ref())
                    {
                        counts[slot] += 1;
                    }
                }
                group.visible_rejections.insert(peer, counts);
            }
        };
        if self.can_detach_summary_group(gid) {
            let mut group = self
                .group_ribs
                .remove(&gid)
                .expect("group registered above");
            install(&mut group, Some(self));
            self.group_ribs.insert(gid, group);
        } else {
            install(
                self.group_ribs
                    .get_mut(&gid)
                    .expect("group registered above"),
                None,
            );
        }
    }
}
