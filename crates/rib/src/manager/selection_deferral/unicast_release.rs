//! One startup release producer per unicast AFI. A bounded key batch owns
//! its group deltas through member admission; other batches reread live rows.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::ops::Bound::{Excluded, Unbounded};
use std::task::Poll;

use rustbgpd_wire::{Afi, Prefix, Safi};

use super::rejections::{ReleaseRejections, RetireReleaseRejections};
use super::{
    RibManager, SelectionDeferralReleaseReason, SelectionDeferralTransition,
    UnicastReleaseInventory,
};
use crate::PeerId;
use crate::manager::distribution::{ReleaseDistribution, ReleaseSelection};
use crate::manager::outbound_owing::OwedFamily;
use crate::outbound_credit::CHUNK_ROWS;

const INVENTORY_STEPS: usize = 256;
const SELECTION_STEPS: usize = 1024;
const PEERS_PER_STEP: usize = 32;

#[derive(Default)]
pub(in crate::manager) struct UnicastReleases {
    jobs: VecDeque<Release>,
    // Only startup deferral needs ordered traversal of the registered sessions.
    peers: Option<BTreeSet<PeerId>>,
    retiring_peers: bool,
    // Sessions that omitted a partially published family from their initial dump.
    late_joins: [BTreeSet<LateJoin>; 2],
    pub(in crate::manager) rejections: ReleaseRejections,
    // After the family gate opens, each unvisited peer still owns its marker.
    markers: HashMap<Afi, Option<PeerId>>,
}

// Ready entries sort first so an AFI with only evicted receivers needs no scan.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum LateJoin {
    Ready(PeerId),
    // The cap's whole-table owner checks the writer and any EVPN hold.
    Evicted(PeerId),
}

struct Release {
    afi: Afi,
    terminal: Option<SelectionDeferralReleaseReason>,
    reason: &'static str,
    phase: Phase,
}

enum Phase {
    Enroll(Option<PeerId>),
    Walk(Box<Walk>),
    Markers,
}

struct Walk {
    inventory: UnicastReleaseInventory,
    exhausted: bool,
    keys: VecDeque<Prefix>,
    retry: Option<Prefix>,
    selection: Option<ReleaseSelection>,
    distribution: Option<ReleaseDistribution>,
    rejection_retirement: Option<RetireReleaseRejections>,
    covered: HashSet<Prefix>,
}

impl RibManager {
    pub(in crate::manager) fn initialize_release_peers(&mut self) {
        let needed = self.selection_deferral.as_ref().is_some_and(|gate| {
            [Afi::Ipv4, Afi::Ipv6]
                .into_iter()
                .any(|afi| gate.may_hold_family((afi, Safi::Unicast)))
        });
        self.unicast_release
            .rejections
            .initialize(self.selection_deferral.as_ref(), &self.peer_unexportable);
        if needed {
            self.unicast_release.retiring_peers = false;
            self.unicast_release.peers = Some(self.outbound_session_ids.keys().copied().collect());
        }
    }

    pub(in crate::manager) fn track_release_peer(&mut self, peer: PeerId) {
        self.forget_late_release_join(peer);
        if !self.unicast_release.retiring_peers
            && let Some(peers) = self.unicast_release.peers.as_mut()
        {
            peers.insert(peer);
        }
    }

    /// Until the walk has staged every key, neither a frozen group row nor
    /// the Loc-RIB inventory is an authoritative initial table for this AFI.
    pub(in crate::manager) fn initial_selection_deferred(&self, family: (Afi, Safi)) -> bool {
        self.selection_deferred(family) || self.owed_release_open(family)
    }

    pub(in crate::manager) fn late_release_join_pending(
        &self,
        peer: PeerId,
        family: (Afi, Safi),
    ) -> bool {
        matches!(family, (Afi::Ipv4 | Afi::Ipv6, Safi::Unicast)) && {
            let joins = &self.unicast_release.late_joins[usize::from(family.0 == Afi::Ipv6)];
            joins.contains(&LateJoin::Ready(peer)) || joins.contains(&LateJoin::Evicted(peer))
        }
    }

    pub(in crate::manager) fn next_late_release_join(&self) -> Option<(usize, PeerId)> {
        [Afi::Ipv4, Afi::Ipv6]
            .into_iter()
            .enumerate()
            .find_map(|(index, afi)| {
                let &LateJoin::Ready(peer) = self.unicast_release.late_joins[index].first()? else {
                    return None;
                };
                (!self.initial_selection_deferred((afi, Safi::Unicast))).then_some((index, peer))
            })
    }

    /// Another operation took over or dropped the eviction. Recheck any
    /// initial-table duty that its whole-table resync had yet to admit.
    pub(in crate::manager) fn wake_evicted_late_join(&mut self, peer: PeerId) {
        for joins in &mut self.unicast_release.late_joins {
            if joins.remove(&LateJoin::Evicted(peer)) {
                joins.insert(LateJoin::Ready(peer));
            }
        }
    }

    pub(in crate::manager) fn take_late_joins_for_resync(&mut self, peer: PeerId) {
        for (index, afi) in [Afi::Ipv4, Afi::Ipv6].into_iter().enumerate() {
            let family = (afi, Safi::Unicast);
            if !self.initial_selection_deferred(family) {
                let joins = &mut self.unicast_release.late_joins[index];
                if joins.remove(&LateJoin::Evicted(peer)) || joins.remove(&LateJoin::Ready(peer)) {
                    self.handoff_late_refresh(peer, family);
                }
            }
        }
    }

    fn handoff_late_refresh(&mut self, peer: PeerId, family: (Afi, Safi)) {
        if !self.selection_peer_convergence_held(peer, family)
            && crate::manager::route_refresh::remove_family_drop_empty(
                &mut self.selection_deferred_refresh,
                peer,
                family,
            )
        {
            self.defer_refresh_answer(peer, family, self.eor.owes(peer, family));
        }
    }

    pub(in crate::manager) fn recover_late_release_join(&mut self) {
        use crate::manager::route_refresh::{FamilyReplayKind, FamilyReplayOutcome};

        let Some((index, peer)) = self.next_late_release_join() else {
            return;
        };
        self.unicast_release.late_joins[index].remove(&LateJoin::Ready(peer));
        if self.outbound_channel_gone(peer) {
            return;
        }
        if self.owed_row_evicted.contains(&peer) {
            // A waiting group member continues to receive ordinary deltas.
            // Only the evicted receiver's own admissible unit can promote it.
            self.unicast_release.late_joins[index].insert(LateJoin::Evicted(peer));
            if self.dirty_peers.contains(&peer) {
                self.set_selection_partial_caught_up(peer, false);
            }
            return;
        }
        let family = ([Afi::Ipv4, Afi::Ipv6][index], Safi::Unicast);
        self.handoff_late_refresh(peer, family);
        if self.dirty_peers.contains(&peer) || self.force_outbound_peers.contains(&peer) {
            self.wake_unicast_release_resync(peer, family);
        } else if self.grouped_member_of(peer).is_some()
            && self.send_route_refresh_response_inner(
                peer,
                family.0,
                family.1,
                FamilyReplayKind::SelectionRelease,
            ) == FamilyReplayOutcome::Committed
        {
            self.settle_eor_of(
                peer,
                &[family],
                crate::manager::eor_hold::EorTrigger::Release,
            );
        } else {
            self.mark_outbound_dirty(peer);
        }
    }

    /// An ordinary update from a source registered after inventory capture can
    /// already be in the group table, yet never occur in the rest of the walk.
    /// Reconcile from this session's actual admission once staging is complete.
    pub(in crate::manager) fn track_late_release_join(&mut self, peer: PeerId) -> bool {
        let mut pending = false;
        for (index, afi) in [Afi::Ipv4, Afi::Ipv6].into_iter().enumerate() {
            let family = (afi, Safi::Unicast);
            if self.late_release_join_pending(peer, family) {
                // An existing session can repeat its initial dump on a Paths-Limit
                // change. Its earlier obligation survives a refusal of this one.
                pending = true;
            } else if self.owed_release_open(family)
                && self
                    .peer_sendable_families
                    .get(&peer)
                    .is_some_and(|set| set.contains(&family))
                && !self
                    .peer_orf_pending
                    .get(&peer)
                    .is_some_and(|held| held.contains(&family))
            {
                self.unicast_release.late_joins[index].insert(LateJoin::Ready(peer));
                pending = true;
            }
        }
        pending
    }

    fn forget_late_release_join(&mut self, peer: PeerId) {
        for joins in &mut self.unicast_release.late_joins {
            joins.remove(&LateJoin::Ready(peer));
            joins.remove(&LateJoin::Evicted(peer));
        }
    }

    pub(in crate::manager) fn untrack_release_peer(&mut self, peer: PeerId) {
        self.forget_late_release_join(peer);
        if let Some(peers) = self.unicast_release.peers.as_mut() {
            peers.remove(&peer);
        }
    }

    pub(in crate::manager) fn release_peer_batch(
        &self,
        after: Option<PeerId>,
        limit: usize,
    ) -> Vec<PeerId> {
        self.unicast_release
            .peers
            .as_ref()
            .into_iter()
            .flat_map(|peers| peers.range((after.map_or(Unbounded, Excluded), Unbounded)))
            .take(limit)
            .copied()
            .collect()
    }

    pub(in crate::manager) fn unicast_release_in_progress(&self, afi: Afi) -> bool {
        self.owed_release_open((afi, Safi::Unicast))
    }

    pub(in crate::manager) fn unicast_release_partial(&self) -> bool {
        self.release_readiness_count.is_some()
    }

    pub(in crate::manager) fn release_markers_active(&self) -> bool {
        !self.unicast_release.markers.is_empty()
    }

    pub(in crate::manager) fn retire_release_peers_if_idle(&mut self) {
        self.unicast_release
            .rejections
            .update_tracking(self.selection_deferral.as_ref());
        if self.unicast_release.peers.is_some()
            && !self.release_markers_active()
            && !self.selection_deferral.as_ref().is_some_and(|state| {
                [Afi::Ipv4, Afi::Ipv6]
                    .into_iter()
                    .any(|afi| state.may_hold_family((afi, Safi::Unicast)))
            })
        {
            self.unicast_release.retiring_peers = true;
        }
    }

    pub(in crate::manager) fn release_marker_pending(
        &self,
        peer: PeerId,
        (afi, safi): (Afi, Safi),
    ) -> bool {
        safi == Safi::Unicast
            && self
                .unicast_release
                .markers
                .get(&afi)
                .is_some_and(|after| after.is_none_or(|after| peer > after))
    }

    pub(in crate::manager) fn release_resync_waits(&self, peer: PeerId) -> bool {
        self.unicast_release_partial()
            && self
                .peer_sendable_families
                .get(&peer)
                .is_some_and(|families| {
                    families.iter().any(|&family| {
                        self.owed_release_open(family) && !self.selection_deferred(family)
                    })
                })
    }

    pub(in crate::manager) fn unicast_release_runnable(&self) -> bool {
        !self.unicast_release.jobs.is_empty()
            || self.unicast_release.retiring_peers
            || self.unicast_release.rejections.retirement_pending()
            || self.release_helper_retirement_pending()
    }

    pub(in crate::manager) fn release_delivery_pending(&self) -> bool {
        self.unicast_release.jobs.front().is_some_and(
            |job| matches!(&job.phase, Phase::Walk(walk) if walk.distribution.is_some()),
        )
    }

    // A transition can be dispatched from inside registration or teardown.
    // Only finish inline when the entire walk and its member fanout fit here;
    // a parked group delta may never survive the rest of that caller's work.
    pub(super) fn finish_small_unicast_release(&mut self) {
        if self.small_unicast_release() {
            while !self.unicast_release.jobs.is_empty() {
                self.advance_unicast_release();
            }
        }
    }

    fn small_unicast_release(&self) -> bool {
        const LIMIT: usize = 16;
        let small = self.unicast_release.jobs.len() == 1
            && self.unicast_release.rejections.len() <= LIMIT
            && self.outbound_peers.len() <= LIMIT
            && self.update_groups.group_key(LIMIT).is_none()
            && (0..LIMIT)
                .filter_map(|gid| self.group_ribs.get(&gid))
                .all(|group| group.table.len() <= LIMIT)
            && self.unicast_prefix_peers.next_epoch <= 32
            && self.deferred_selection_keys.unicast.len() <= LIMIT
            && self.loc_rib.len() <= LIMIT
            && self.ribs.capacity() <= 2 * LIMIT
            && self
                .ribs
                .values()
                .map(crate::adj_rib_in::AdjRibIn::len)
                .sum::<usize>()
                <= LIMIT;
        if !small {
            return false;
        }
        // Held withdrawals can leave much more history than there are current candidates.
        let afi = self.unicast_release.jobs[0].afi;
        let (keys, exhausted) = self
            .next_unicast_release_batch(&mut self.unicast_release_inventory(afi), INVENTORY_STEPS);
        if !exhausted || keys.len() > LIMIT {
            return false;
        }
        let groups = (0..LIMIT).filter_map(|gid| self.group_ribs.get(&gid));
        for group in groups {
            if keys
                .iter()
                .any(|key| !group.small_release_history(key, LIMIT))
            {
                return false;
            }
        }
        for peer in self.release_peer_batch(None, LIMIT) {
            if let Some(routes) = self.policy_filtered_routes.get(&peer) {
                for key in &keys {
                    if let Some(crate::manager::PolicyFilteredBucket::Many(paths)) = routes.get(key)
                        && paths.len() > LIMIT
                    {
                        return false;
                    }
                }
            }
        }
        true
    }

    pub(super) fn invalidate_release_selection(&mut self, affected: &HashSet<Prefix>) {
        for job in &mut self.unicast_release.jobs {
            if let Phase::Walk(walk) = &mut job.phase
                && walk.selection.is_some()
                && walk.keys.front().is_some_and(|key| affected.contains(key))
            {
                // Revisit a changing prefix after other queued and newly discovered work.
                walk.selection = None;
                walk.retry = walk.keys.pop_front();
            }
        }
    }

    pub(super) fn cancel_rearmed_release(&mut self, family: (Afi, Safi)) {
        if family.1 == Safi::Unicast {
            self.deferred_selection_keys.cancel_unicast_release(family);
            // Coverage published before a Stage was interrupted remains visible.
            // Keep the read fence and the private cursor open for the next walk.
            self.unicast_release
                .jobs
                .retain(|job| job.afi != family.0 || job.terminal.is_some());
        }
    }

    pub(super) fn start_unicast_release(
        &mut self,
        transition: SelectionDeferralTransition,
        reason: &'static str,
    ) -> bool {
        let (family, terminal, already_staged) = match transition {
            SelectionDeferralTransition::Stage { family } => (family, None, false),
            SelectionDeferralTransition::Release {
                family,
                release_reason,
                already_staged,
            } => (family, Some(release_reason), already_staged),
        };
        if !matches!(family, (Afi::Ipv4 | Afi::Ipv6, Safi::Unicast))
            || !self.selection_convergence_held(family)
        {
            return false;
        }
        let afi = family.0;
        let Some(gate) = self
            .selection_deferral
            .as_mut()
            .and_then(|s| s.active.get_mut(&family))
        else {
            return false;
        };
        if gate.finishing {
            return true;
        }
        if terminal.is_none() {
            tracing::info!(
                ?afi,
                safi = ?family.1,
                reason,
                "RFC 4724 route selection staged while collision-failback convergence remains held"
            );
        }
        gate.finishing = terminal.is_some();
        gate.selection_staged = true;
        if let Some(pos) = self
            .unicast_release
            .jobs
            .iter()
            .position(|job| job.afi == afi)
        {
            if already_staged {
                self.unicast_release.jobs[pos].terminal = terminal;
                self.unicast_release.jobs[pos].reason = reason;
                return true;
            }
            // Timer fallback after a collision Stage walks again from the start.
            self.unicast_release.jobs.remove(pos);
        }
        let phase = if already_staged && !self.owed_release_open(family) {
            self.begin_release_markers(
                afi,
                terminal.expect("only a release consumes a completed Stage"),
                reason,
            );
            Phase::Markers
        } else {
            if !self.unicast_release_partial() {
                self.release_readiness_count = Some(self.loc_rib.len());
            }
            self.set_owed_release_open(family, true);
            self.advance_all_route_pages();
            self.selection_readiness_checkpoint();
            self.release_conditional_advertisement_family(family);
            Phase::Enroll(None)
        };
        self.unicast_release.jobs.push_back(Release {
            afi,
            terminal,
            reason,
            phase,
        });
        true
    }

    fn begin_release_markers(
        &mut self,
        afi: Afi,
        release_reason: SelectionDeferralReleaseReason,
        reason: &'static str,
    ) {
        self.unicast_release.markers.insert(afi, None);
        if let Some(selection) = self.selection_deferral.as_mut() {
            selection.release((afi, Safi::Unicast), release_reason, &self.metrics);
        }
        self.update_selection_inventory_index();
        self.unicast_release
            .rejections
            .update_tracking(self.selection_deferral.as_ref());
        tracing::info!(?afi, safi = ?Safi::Unicast, reason, "RFC 4724 route-selection deferral released");
    }

    fn enroll_release_peer(&mut self, peer: PeerId, family: (Afi, Safi)) {
        if !self
            .peer_sendable_families
            .get(&peer)
            .is_some_and(|families| families.contains(&family))
        {
            return;
        }
        if self.dirty_peers.contains(&peer) || self.force_outbound_peers.contains(&peer) {
            self.wake_unicast_release_resync(peer, family);
            return;
        }
        let owed = OwedFamily::of(family).expect("unicast family is oweable");
        if self.owing_peer_in_scope(peer)
            && self.owing_family_in_scope(peer, owed)
            && !self
                .peer_orf_pending
                .get(&peer)
                .is_some_and(|held| held.contains(&family))
        {
            self.owe_whole_family(peer, owed);
        }
    }

    pub(in crate::manager) fn advance_unicast_release(&mut self) {
        self.unicast_release.rejections.retire_index(PEERS_PER_STEP);
        let Some(mut job) = self.unicast_release.jobs.pop_front() else {
            if self.release_helper_retirement_pending() {
                self.advance_release_helper_retirement();
            }
            if let Some(peers) = self
                .unicast_release
                .peers
                .as_mut()
                .filter(|_| self.unicast_release.retiring_peers)
            {
                for _ in 0..PEERS_PER_STEP {
                    if peers.pop_first().is_none() {
                        self.unicast_release.peers = None;
                        self.unicast_release.retiring_peers = false;
                        break;
                    }
                }
            }
            return;
        };
        let family = (job.afi, Safi::Unicast);
        if let Phase::Enroll(after) = &mut job.phase {
            let peers = self.release_peer_batch(*after, PEERS_PER_STEP);
            for &peer in &peers {
                self.enroll_release_peer(peer, family);
            }
            if peers.len() == PEERS_PER_STEP {
                *after = peers.last().copied();
                self.unicast_release.jobs.push_back(job);
                return;
            }
            job.phase = Phase::Walk(Box::new(Walk {
                inventory: self.unicast_release_inventory(job.afi),
                exhausted: false,
                keys: VecDeque::new(),
                retry: None,
                selection: None,
                distribution: None,
                rejection_retirement: None,
                covered: HashSet::new(),
            }));
        }
        if let Phase::Walk(walk) = &mut job.phase {
            if !self.poll_unicast_walk(job.afi, walk) {
                if walk.distribution.is_some() {
                    self.unicast_release.jobs.push_front(job);
                } else {
                    self.unicast_release.jobs.push_back(job);
                }
                return;
            }
            self.deferred_selection_keys.complete_family_release(family);
            if let Some(reason) = job.terminal {
                self.begin_release_markers(job.afi, reason, job.reason);
                job.phase = Phase::Markers;
            }
            self.set_owed_release_open(family, false);
            if ![Afi::Ipv4, Afi::Ipv6]
                .into_iter()
                .any(|afi| self.unicast_release_in_progress(afi))
            {
                self.release_readiness_count = None;
            }
            self.selection_readiness_checkpoint();
            self.publish_unicast_selection_counts();
            self.advance_all_route_pages();
            if job.terminal.is_none() {
                return;
            }
        }
        let after = self.unicast_release.markers[&job.afi];
        let peers = self.release_peer_batch(after, PEERS_PER_STEP);
        for &peer in &peers {
            self.unicast_release.markers.insert(job.afi, Some(peer));
            self.finish_unicast_release_peer(peer, family);
        }
        if peers.len() == PEERS_PER_STEP {
            self.unicast_release.jobs.push_back(job);
        } else {
            self.unicast_release.markers.remove(&job.afi);
            self.retire_release_peers_if_idle();
            self.schedule_release_helper_retirement();
        }
    }

    fn poll_unicast_walk(&mut self, afi: Afi, walk: &mut Walk) -> bool {
        if walk.distribution.is_none() {
            let slots = CHUNK_ROWS - walk.keys.len() - usize::from(walk.retry.is_some());
            if slots > 0 && !walk.exhausted {
                let (keys, exhausted) = self
                    .next_unicast_release_batch(&mut walk.inventory, slots.min(INVENTORY_STEPS));
                walk.exhausted = exhausted;
                walk.keys.extend(keys);
            }
            walk.keys.extend(walk.retry.take());
            let mut committed = false;
            let mut removed_best = false;
            let mut budget = SELECTION_STEPS;
            while budget > 0
                && walk.covered.len() < CHUNK_ROWS
                && let Some(&key) = walk.keys.front()
            {
                let selection = walk
                    .selection
                    .get_or_insert_with(|| ReleaseSelection::new(key));
                let Poll::Ready(withdrawn) = self.poll_release_selection(selection, &mut budget)
                else {
                    break;
                };
                removed_best |= withdrawn;
                committed = true;
                walk.keys.pop_front();
                walk.selection = None;
                walk.covered.insert(key);
            }
            if committed {
                self.advance_all_route_pages();
            }
            // Inventory and selection have independent work budgets. Fill an ordinary
            // outbound envelope across polls; only prefix identities survive these seams.
            // An overflowed family can owe a withdrawal that only its frozen
            // Loc-RIB row identified. Hand it to the fenced batch before a
            // waiter re-arm or timer can restart this walk.
            let flush_withdrawals = removed_best
                && self
                    .deferred_selection_keys
                    .overflowed_families
                    .contains(&(afi, Safi::Unicast));
            if flush_withdrawals
                || walk.covered.len() == CHUNK_ROWS
                || (!walk.covered.is_empty()
                    && walk.exhausted
                    && (walk.keys.is_empty() || walk.selection.is_some()))
            {
                walk.distribution = Some(ReleaseDistribution::new(
                    afi,
                    std::mem::take(&mut walk.covered),
                ));
            }
        }
        if let Some(pass) = &mut walk.distribution {
            if walk.rejection_retirement.is_none() {
                self.selection_release_staging = true;
                let done = self.poll_unicast_release_distribution(pass);
                self.selection_release_staging = false;
                if !done {
                    return false;
                }
                walk.rejection_retirement = self.release_rejections_for_batch(&pass.prefixes);
            }
            if let Some(retirement) = &mut walk.rejection_retirement
                && !self.retire_release_rejections(retirement, SELECTION_STEPS)
            {
                // Keep the delivery fence through rejection cleanup. A new source
                // must never race the liveness proof for this withdrawal.
                return false;
            }
            walk.rejection_retirement = None;
            walk.covered = std::mem::take(&mut pass.prefixes);
            walk.distribution = None;
            for key in walk.covered.drain() {
                self.retire_unicast_release_key(key);
            }
        }
        walk.exhausted && walk.keys.is_empty()
    }
}
