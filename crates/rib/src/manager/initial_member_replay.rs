//! Replay a published single-best group through the registration lane. A full
//! writer parks with its exact admitted-key proof and its scan position intact.

mod changes;

#[cfg(feature = "bench-internals")]
mod observation;
#[cfg(feature = "bench-internals")]
pub use observation::BenchReplayEvent;

use std::collections::{HashMap, HashSet, VecDeque};

use changes::ReplayChanges;
use tokio::sync::mpsc;

use super::distribution::OutboundCommitBatch;
use super::update_groups::admitted_recovery::{Key, OnReservationRefusal, ReplayRoom};
use super::{PeerId, RibManager};
use crate::fast_hash::FastSet;
use crate::loc_rib::{REGISTRATION_PAGE_SIZE, RegistrationScanStatus};
use crate::update::{ExactExportKey, OutboundRouteUpdate, RouteQueryKey, route_query_key};
use rustbgpd_wire::{Afi, Prefix, Safi};

pub(super) use rustbgpd_telemetry::reason_labels::{PacedFallbackCause, PacedJob};

enum Phase {
    PrepareProof(Option<RouteQueryKey>),
    Send,
}

/// An initial replay sends a cold member its table. A reconcile repairs a
/// member whose replay lost track of its changes: it rescans the Loc-RIB
/// with every key reconciled against admission (R1), then sweeps the
/// admitted proof for keys the Loc-RIB no longer holds (R2). Both owe the
/// End-of-RIB the replay owed when it started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Initial,
    Reconcile,
}

/// Re-arms after which a reconcile's scan stops overflowing.
// ponytail: past this, the member's repair log grows with every distinct
// changed key (at most the Loc-RIB) and sustained churn can still hold its
// End-of-RIB back. The shared lag bound replaces both (S5).
const REARMS_BEFORE_UNBOUNDED_REPAIRS: u16 = 4;

struct Replay {
    gid: usize,
    table_stamp: u64,
    session: u64,
    sender: mpsc::Sender<OutboundRouteUpdate>,
    phase: Phase,
    changes: ReplayChanges,
    // Page keys left when a poll spent its unit budget. An RS-control
    // member's slot may search the prefix's fallback rows.
    carry: VecDeque<Prefix>,
    mode: Mode,
    // A reconcile restarts its scan at its next turn. Until then the scan is
    // stopped: the rescan revisits every key, so nothing needs recording.
    rewind: bool,
    rearms: u16,
    // R2's position: the last proof key it visited, and whether it is done.
    swept: Option<Key>,
    sweep_done: bool,
}

/// What a paceable registration waits for before its replay can start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SlotWait {
    /// Every one of the `MAX_JOIN_COHORT` replay slots is taken.
    Cap,
    /// The live replays' proofs leave no room for this table, or an older
    /// registration waits for that room.
    Budget,
}

impl SlotWait {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Cap => "replay_cap",
            Self::Budget => "proof_budget",
        }
    }
}

#[derive(Default)]
pub(super) struct InitialMemberReplays {
    members: HashMap<PeerId, Replay>,
    ready: VecDeque<PeerId>,
    blocked: VecDeque<PeerId>,
    registration_due: bool,
    // The registration queue length when its every entry last waited for a
    // replay slot. A replay's end, or a queue change, makes it runnable.
    slot_wait: Option<usize>,
    // Registrations waiting for a replay slot, each with its cause, logged
    // once per wait.
    waiters: HashMap<PeerId, SlotWait>,
    // Groups published for a founder that then waited for a slot. One no
    // queued registration claims is retired.
    founder_groups: Vec<usize>,
    #[cfg(feature = "bench-internals")]
    observer: Option<observation::ReplayObserver>,
    #[cfg(test)]
    pub(super) min_routes: Option<usize>,
}

impl InitialMemberReplays {
    pub(super) fn note_founder_group(&mut self, gid: usize) {
        if !self.founder_groups.contains(&gid) {
            self.founder_groups.push(gid);
        }
    }

    pub(super) fn take_founder_groups(&mut self) -> Vec<usize> {
        std::mem::take(&mut self.founder_groups)
    }

    pub(super) fn runnable(&self) -> bool {
        !self.ready.is_empty()
    }

    pub(super) fn parked(&self) -> bool {
        !self.blocked.is_empty()
    }
}

impl RibManager {
    pub(super) fn is_initial_member_replay(&self, peer: PeerId) -> bool {
        self.initial_member_replays.members.contains_key(&peer)
    }

    /// A queued change is already in the group table but not yet accepted by
    /// the member's writer, so its admission proof no longer describes the
    /// advertised attributes of that key.
    pub(super) fn initial_member_replay_changes_pending(&self, peer: PeerId) -> bool {
        self.initial_member_replays
            .members
            .get(&peer)
            .is_some_and(|replay| replay.mode == Mode::Reconcile || replay.changes.unsent())
    }

    /// What `peer`'s paceable registration waits for, if anything: a slot
    /// while live replays hold every one, or proof budget while their
    /// proofs leave no room for its table (and always when `behind_budget`,
    /// an older registration waiting for that room, keeps the queue FIFO).
    /// It does not wait when no replay is live, when its table would not
    /// fit even once they end, or when its replay would be refused anyway.
    pub(super) fn replay_slot_wait(&self, peer: PeerId, behind_budget: bool) -> Option<SlotWait> {
        let replays = &self.initial_member_replays.members;
        if replays.is_empty() || replays.contains_key(&peer) {
            return None;
        }
        let room = self.paced_replay_room(peer)?;
        if replays.len() >= super::peer_lifecycle::MAX_JOIN_COHORT {
            return Some(SlotWait::Cap);
        }
        (behind_budget || room == ReplayRoom::AfterReplays).then_some(SlotWait::Budget)
    }

    /// The proof room for `peer`'s paced replay, or `None` when its
    /// registration cannot take one whatever ends: it is not eligible, peer
    /// state refuses it, or its table fits under neither limit. Such a
    /// registration sends its table in one turn.
    pub(super) fn paced_replay_room(&self, peer: PeerId) -> Option<ReplayRoom> {
        if !self.eligible_initial_member_replay(peer) || self.replay_peer_refusal(peer).is_some() {
            return None;
        }
        let room = self
            .pending_group_admitted
            .initial_replay_room(self.pending_replay_rows(peer));
        (room != ReplayRoom::Never).then_some(room)
    }

    /// [`Self::replay_slot_wait`] for a registration completed outside the
    /// queue walk: it also waits behind any queued registration that waits
    /// for proof budget.
    pub(super) fn registration_waits_for_replay_slot(&mut self, peer: PeerId) -> bool {
        let behind_budget = self
            .pending_initial_registrations
            .iter()
            .take_while(|queued| **queued != peer)
            .any(|queued| {
                self.initial_member_replays.waiters.get(queued) == Some(&SlotWait::Budget)
            });
        let wait = self.replay_slot_wait(peer, behind_budget);
        self.note_replay_slot_wait(peer, wait);
        wait.is_some()
    }

    /// Record the registration's wait, logging the first of each.
    pub(super) fn note_replay_slot_wait(&mut self, peer: PeerId, wait: Option<SlotWait>) {
        let Some(wait) = wait else {
            self.initial_member_replays.waiters.remove(&peer);
            return;
        };
        if self
            .initial_member_replays
            .waiters
            .insert(peer, wait)
            .is_none()
        {
            tracing::debug!(
                %peer,
                cause = wait.as_str(),
                replays = self.initial_member_replays.members.len(),
                "paced initial table waits for a replay slot"
            );
        }
    }

    /// Peer state that refuses a paced replay whatever the free slots, so
    /// waiting for one would not help.
    fn replay_peer_refusal(&self, peer: PeerId) -> Option<PacedFallbackCause> {
        if self.dirty_peers.contains(&peer) {
            Some(PacedFallbackCause::AlreadyDirty)
        } else if self.outbound_prefix_limits.contains_key(&peer)
            || self.configured_outbound_limit(peer)
        {
            // A waiting registration installs its configured limits only
            // when it registers.
            Some(PacedFallbackCause::PrefixLimit)
        } else if self.retain_initial_group_admitted(peer) {
            Some(PacedFallbackCause::RetainedProof)
        } else if self.peer_orf_pending.contains_key(&peer) {
            Some(PacedFallbackCause::OrfPending)
        } else {
            None
        }
    }

    /// Whether a queued registration can make progress. One whose every
    /// entry waits for a replay slot is not, until a replay ends, the queue
    /// changes, or a message other than a unicast receipt arrives (a session
    /// or profile change can end a wait).
    pub(super) fn registration_runnable(&self) -> bool {
        !self.pending_initial_registrations.is_empty()
            && self.initial_member_replays.slot_wait
                != Some(self.pending_initial_registrations.len())
    }

    pub(super) fn set_registration_slot_wait(&mut self, waiting: bool) {
        self.initial_member_replays.slot_wait =
            waiting.then_some(self.pending_initial_registrations.len());
    }

    pub(super) fn start_initial_member_replay(&mut self, peer: PeerId) -> bool {
        let Some(gid) = self.grouped_member_of(peer) else {
            return self.refuse_initial_member_replay(peer, PacedFallbackCause::Ungrouped);
        };
        let group = &self.group_ribs[&gid];
        let refusal = if self.initial_member_replays.members.len()
            >= super::peer_lifecycle::MAX_JOIN_COHORT
        {
            Some(PacedFallbackCause::ReplayCap)
        } else if group.evpn_table_stamp == 0 {
            Some(PacedFallbackCause::UnpublishedTable)
        } else {
            self.replay_peer_refusal(peer)
        };
        if let Some(cause) = refusal {
            return self.refuse_initial_member_replay(peer, cause);
        }
        let table_stamp = group.evpn_table_stamp;
        let changes = if group.per_client_best || self.rs_control_context(peer).is_some() {
            ReplayChanges::coalescing()
        } else {
            ReplayChanges::default()
        };
        let enrollment = self
            .pending_group_admitted
            .begin_initial_replay(peer, group.table.len());
        match enrollment {
            Ok(true) => {}
            Ok(false) => {
                return self.refuse_initial_member_replay(peer, PacedFallbackCause::ProofState);
            }
            Err(error) => {
                // The registration sends its table in its own turn.
                let cause = super::update_groups::RecoveryFallbackCause::from(error.cause);
                self.note_paced_fallback(PacedJob::InitialReplay, cause.into(), peer);
                #[cfg(feature = "bench-internals")]
                self.observe_initial_replay(
                    peer,
                    BenchReplayEvent::EnrollmentRefused(error.cause.as_str()),
                );
                return false;
            }
        }
        self.refresh_group_recovery_gauges();
        self.loc_rib.start_member_replay_scan(peer);
        self.initial_member_replays.members.insert(
            peer,
            Replay {
                gid,
                table_stamp,
                session: self.outbound_session_ids[&peer],
                sender: self.outbound_peers[&peer].clone(),
                phase: Phase::PrepareProof(None),
                changes,
                carry: VecDeque::new(),
                mode: Mode::Initial,
                rewind: false,
                rearms: 0,
                swept: None,
                sweep_done: false,
            },
        );
        self.initial_member_replays.ready.push_back(peer);
        self.set_initial_group_admitted_counts(peer, [0; 6]);
        self.start_initial_replay_policy(peer, gid);
        #[cfg(feature = "bench-internals")]
        self.observe_initial_replay(peer, BenchReplayEvent::Enrolled);
        let families = self.peer_sendable_families[&peer]
            .iter()
            .copied()
            .chain(
                self.registered_withheld_families(peer)
                    .iter()
                    .map(|(family, _)| *family),
            )
            .collect::<Vec<_>>();
        for family in families {
            self.owe_eor(peer, family);
        }
        true
    }

    /// The registration sends its table in its own turn instead.
    fn refuse_initial_member_replay(&self, peer: PeerId, cause: PacedFallbackCause) -> bool {
        self.note_paced_fallback(PacedJob::InitialReplay, cause, peer);
        #[cfg(feature = "bench-internals")]
        self.observe_initial_replay(peer, BenchReplayEvent::Refused(cause.as_str()));
        false
    }

    /// Why a large initial table goes out in one turn when its pending
    /// registration cannot take a paced replay at all, read before the
    /// registration installs. A replay that starts and is refused counts its
    /// own cause, and so does a first-group build that fell back. Below the
    /// pacing threshold, one turn is the intended path, not a fallback.
    pub(super) fn unpaced_initial_table_cause(
        &self,
        peer: PeerId,
        eligible: bool,
    ) -> Option<PacedFallbackCause> {
        if self.loc_rib.len() < self.initial_member_replay_min_routes()
            || self
                .live_sessions
                .get(&peer)
                .and_then(|sessions| sessions.last())
                .is_some_and(|record| record.registration_policy_fallback)
        {
            return None;
        }
        Some(if eligible {
            self.replay_peer_refusal(peer)
                .unwrap_or(PacedFallbackCause::ProofBudget)
        } else {
            PacedFallbackCause::IneligibleShape
        })
    }

    /// Count an installed registration's unpaced initial table, read by
    /// [`Self::unpaced_initial_table_cause`], when that table carries
    /// unicast routes: a sendable unicast family that neither selection
    /// deferral nor the ORF gate holds, as the initial table filters them.
    /// An EVPN-only, VPN-only or selection-held registration sends no
    /// table-sized unicast dump.
    pub(super) fn note_unpaced_initial_table(
        &self,
        peer: PeerId,
        cause: Option<PacedFallbackCause>,
    ) {
        let Some(cause) = cause else {
            return;
        };
        let orf_gated = self.peer_orf_pending.get(&peer);
        let unicast = self
            .peer_sendable_families
            .get(&peer)
            .is_some_and(|families| {
                families.iter().any(|&family| {
                    matches!(family, (Afi::Ipv4 | Afi::Ipv6, Safi::Unicast))
                        && !self.initial_selection_deferred(family)
                        && orf_gated.is_none_or(|gated| !gated.contains(&family))
                })
            });
        if unicast {
            self.note_paced_fallback(PacedJob::InitialReplay, cause, peer);
        }
    }

    /// Count one paced job's fallback to a one-turn path.
    pub(super) fn note_paced_fallback(
        &self,
        job: PacedJob,
        cause: PacedFallbackCause,
        peer: PeerId,
    ) {
        self.metrics.record_rib_paced_fallback(job, cause);
        tracing::debug!(
            %peer,
            job = job.as_str(),
            cause = cause.as_str(),
            "paced job fell back to a one-turn path"
        );
    }

    pub(super) fn abort_initial_member_replay(&mut self, peer: PeerId) -> bool {
        if self.initial_member_replays.members.remove(&peer).is_none() {
            return false;
        }
        // A released slot or proof budget may admit a waiting registration.
        self.initial_member_replays.slot_wait = None;
        self.initial_member_replays.ready.retain(|p| *p != peer);
        self.initial_member_replays.blocked.retain(|p| *p != peer);
        self.loc_rib.stop_member_replay_scan(peer);
        self.refresh_eor_retry(peer);
        true
    }

    pub(super) fn wake_initial_member_replay(&mut self) -> bool {
        // The release notification is shared and coalesces releases that land
        // while the actor is busy. Check each parked member once and resume
        // every released writer, so none waits for a later resync tick.
        let mut woke = false;
        for _ in 0..self.initial_member_replays.blocked.len() {
            let peer = self
                .initial_member_replays
                .blocked
                .pop_front()
                .expect("parked replay");
            if self.outbound_channel_gone(peer)
                || (!self.outbound_channel_full(peer) && !self.outbound_operation_live(peer))
            {
                self.initial_member_replays.ready.push_back(peer);
                woke = true;
                continue;
            }
            self.initial_member_replays.blocked.push_back(peer);
        }
        woke
    }

    pub(super) fn service_initial_member_replay(&mut self) -> bool {
        if self.initial_member_replays.registration_due
            && (self.first_group_build.is_some() || self.registration_runnable())
        {
            self.initial_member_replays.registration_due = false;
            return false;
        }
        let Some(peer) = self.initial_member_replays.ready.pop_front() else {
            return false;
        };
        self.initial_member_replays.registration_due = true;
        self.advance_initial_member_replay(peer);
        true
    }

    /// Rewind a replay that lost track of its member's table into a paced
    /// reconcile, or hand it to the dirty resync when it cannot reconcile:
    /// its proof is gone, another owner already marked it dirty, or the
    /// cause needs more than its unicast table (a regroup moves its
    /// withdrawal duties; an ORF change filters at the commit). `true` while
    /// the replay stays live.
    pub(super) fn recover_initial_member_replay(
        &mut self,
        peer: PeerId,
        cause: PacedFallbackCause,
    ) -> bool {
        use PacedFallbackCause as Cause;
        let reconcilable = match cause {
            Cause::ScanRepairLimit
            | Cause::ChangeOutsideScan
            | Cause::ReleaseFanout
            | Cause::SelectionRelease => true,
            Cause::ForcedResync => !self.peer_orf_filters.contains_key(&peer),
            _ => false,
        };
        if reconcilable
            && !self.dirty_peers.contains(&peer)
            && self
                .pending_group_admitted
                .initial_replay_sparse_len(peer)
                .is_some()
            && let Some(replay) = self.initial_member_replays.members.get_mut(&peer)
        {
            replay.mode = Mode::Reconcile;
            replay.rewind = true;
            replay.rearms = replay.rearms.saturating_add(1);
            replay.changes = ReplayChanges::coalescing();
            replay.carry.clear();
            replay.swept = None;
            replay.sweep_done = false;
            let rearms = replay.rearms;
            self.loc_rib.stop_member_replay_scan(peer);
            let replays = &mut self.initial_member_replays;
            if !replays.ready.contains(&peer) && !replays.blocked.contains(&peer) {
                replays.ready.push_back(peer);
            }
            if cause == Cause::ForcedResync {
                // Every reconcile row is a forced replay.
                self.force_outbound_peers.remove(&peer);
                self.refresh_eor_retry(peer);
            }
            tracing::debug!(
                %peer,
                cause = cause.as_str(),
                rearms,
                "paced initial replay rewinds into a reconcile"
            );
            #[cfg(feature = "bench-internals")]
            self.observe_initial_replay(peer, BenchReplayEvent::Reconciled(cause.as_str()));
            #[cfg(test)]
            super::slice_timing::record_work("initial_replay_reconciles", 1);
            return true;
        }
        self.note_paced_fallback(PacedJob::InitialReplay, cause, peer);
        self.abort_initial_member_replay(peer);
        let marked = self.mark_outbound_dirty(peer);
        #[cfg(feature = "bench-internals")]
        if marked {
            self.observe_initial_replay(peer, BenchReplayEvent::Dirty(cause.as_str()));
        }
        #[cfg(not(feature = "bench-internals"))]
        let _ = marked;
        false
    }

    /// Restart a reconcile's scan from its first bucket. The proof stays.
    fn rewind_initial_member_replay(&mut self, peer: PeerId) {
        let replay = self
            .initial_member_replays
            .members
            .get_mut(&peer)
            .expect("live replay");
        replay.rewind = false;
        let unbounded = replay.rearms > REARMS_BEFORE_UNBOUNDED_REPAIRS;
        self.loc_rib.start_member_replay_scan(peer);
        if unbounded {
            self.loc_rib.lift_member_replay_repair_limit(peer);
        }
    }

    fn advance_initial_member_replay(&mut self, peer: PeerId) {
        // The ingest owner publishes accumulated Loc-RIB changes to the group at
        // its window boundary. Never consume their repairs against the old table.
        if !self.pending_distribute_changed.is_empty()
            || !self.pending_distribute_affected.is_empty()
        {
            self.initial_member_replays.ready.push_back(peer);
            return;
        }
        let Some(job) = self.initial_member_replays.members.get(&peer) else {
            return;
        };
        if job.sender.is_closed()
            || self.outbound_session_ids.get(&peer) != Some(&job.session)
            || !self
                .outbound_peers
                .get(&peer)
                .is_some_and(|tx| tx.same_channel(&job.sender))
        {
            self.abort_initial_member_replay(peer);
            return;
        }
        let gid = job.gid;
        let rewind = job.rewind;
        let invalidation = if self.grouped_member_of(peer) != Some(gid)
            || self
                .group_ribs
                .get(&gid)
                .is_none_or(|g| g.evpn_table_stamp != job.table_stamp)
        {
            Some(PacedFallbackCause::GroupChanged)
        } else if self.dirty_peers.contains(&peer) {
            Some(
                self.group_recovery_fallback(peer)
                    .map_or(PacedFallbackCause::AlreadyDirty, Into::into),
            )
        } else if self
            .pending_group_admitted
            .initial_replay_sparse_len(peer)
            .is_none()
        {
            Some(PacedFallbackCause::MissingProof)
        } else {
            if rewind {
                self.rewind_initial_member_replay(peer);
            }
            (self.loc_rib.member_replay_scan_status(peer) == RegistrationScanStatus::Overflow)
                .then_some(PacedFallbackCause::ScanRepairLimit)
        };
        if let Some(cause) = invalidation {
            // A reconcile is scheduled again and rewinds at its next turn.
            self.recover_initial_member_replay(peer, cause);
            return;
        }
        if self.outbound_channel_full(peer) || self.outbound_operation_live(peer) {
            self.initial_member_replays.blocked.push_back(peer);
            return;
        }
        if let Phase::PrepareProof(after) = self.initial_member_replays.members[&peer].phase {
            self.prepare_initial_member_proof_page(peer, gid, after);
            return;
        }
        if self.complete_initial_member_replay(peer) {
            return;
        }
        let replay = &self.initial_member_replays.members[&peer];
        if replay.mode == Mode::Reconcile
            && replay.carry.is_empty()
            && self.loc_rib.member_replay_scan_status(peer) == RegistrationScanStatus::Ready
        {
            self.sweep_initial_member_page(peer, gid);
        } else {
            self.send_initial_member_page(peer, gid);
        }
    }

    /// Complete once nothing is left to send. A page that drains the last
    /// repair completes in its own turn when the writer has room for the
    /// marker behind it: input that lands before the next turn would
    /// otherwise queue a repair again, so steady churn slower than the
    /// drain could hold back End-of-RIB indefinitely.
    fn complete_initial_member_replay(&mut self, peer: PeerId) -> bool {
        let job = &self.initial_member_replays.members[&peer];
        if job.changes.has_pending()
            || !job.carry.is_empty()
            || job.rewind
            || (job.mode == Mode::Reconcile && !job.sweep_done)
            || self.loc_rib.member_replay_scan_status(peer) != RegistrationScanStatus::Ready
            || self.dirty_peers.contains(&peer)
        {
            return false;
        }
        debug_assert!(!job.changes.unsent(), "a coalesced key outlived its repair");
        // End-of-RIB waits for the rest of an UPDATE whose first chunks applied.
        if !self.pending_route_batches.is_empty() {
            self.initial_member_replays.ready.push_back(peer);
            return true;
        }
        self.abort_initial_member_replay(peer);
        #[cfg(feature = "bench-internals")]
        self.observe_initial_replay(peer, BenchReplayEvent::Completed);
        self.complete_initial_selection_replay(peer);
        self.retire_completed_initial_group_admitted(peer);
        self.settle_free_eor(peer);
        true
    }

    fn prepare_initial_member_proof_page(
        &mut self,
        peer: PeerId,
        gid: usize,
        after: Option<RouteQueryKey>,
    ) {
        let table = &self.group_ribs[&gid].table;
        let mut last = None;
        // The ordered iterator revisits the one single-best row at its inclusive seek.
        let mut visits = usize::from(after.is_some());
        let remaining = REGISTRATION_PAGE_SIZE - visits;
        let keys = table.iter_ordered_from(after).take(remaining).map(|row| {
            last = Some(route_query_key(row));
            visits += 1;
            Key::Unicast(row.prefix, row.path_id)
        });
        if !self
            .pending_group_admitted
            .extend_initial_replay_universe(peer, keys)
        {
            self.recover_initial_member_replay(peer, PacedFallbackCause::MissingProof);
            return;
        }
        #[cfg(test)]
        super::slice_timing::record_work("initial_member_replay_visits", visits);
        self.initial_member_replays
            .members
            .get_mut(&peer)
            .expect("live replay")
            .phase = if visits == REGISTRATION_PAGE_SIZE {
            Phase::PrepareProof(last)
        } else {
            Phase::Send
        };
        self.initial_member_replays.ready.push_back(peer);
    }

    fn send_initial_member_page(&mut self, peer: PeerId, gid: usize) {
        let Ok(mut operation) = self.begin_outbound_operation(peer, 1) else {
            self.initial_member_replays.blocked.push_back(peer);
            return;
        };
        if self.initial_member_replays.members[&peer]
            .changes
            .has_pending()
        {
            self.send_initial_replay_change(peer, operation);
            return;
        }
        let rs_control = self.rs_control_context(peer);
        let replay = self
            .initial_member_replays
            .members
            .get_mut(&peer)
            .expect("live replay");
        let reconcile = replay.mode == Mode::Reconcile;
        if replay.carry.is_empty() {
            let page = self.loc_rib.take_member_replay_page(peer);
            #[cfg(test)]
            super::slice_timing::record_work(
                "initial_member_replay_visits",
                page.bucket_visits + page.repairs,
            );
            replay.carry = page.keys.into();
        }
        let Some(admitted) = self.pending_group_admitted.get(&peer) else {
            self.recover_initial_member_replay(peer, PacedFallbackCause::MissingProof);
            return;
        };
        let group = &self.group_ribs[&gid];
        let mut routes = Vec::new();
        let mut actions = Vec::new();
        let mut withdraw = Vec::new();
        let mut prior = FastSet::default();
        let mut reconciled = Vec::new();
        let mut keys = HashSet::new();
        let mut units = 0;
        while units < REGISTRATION_PAGE_SIZE
            && let Some(prefix) = replay.carry.pop_front()
        {
            // One unit per key, plus each fallback row its slot searched.
            units += 1;
            keys.insert(prefix);
            // Grouped single-best outbound identities use path ID zero,
            // including when the received winner has its own Add-Path ID.
            let key = ExactExportKey::Unicast(prefix, 0);
            let sent = admitted.contains(&key);
            // A coalesced key reconciles its current row against admission,
            // and so does every key a reconcile visits.
            if reconcile || replay.changes.coalesced(&prefix) {
                reconciled.push(prefix);
            } else if sent || replay.changes.owns_absent(&prefix) {
                continue;
            }
            let slot = group.replay_slot(peer, &prefix, rs_control);
            if rs_control.is_some() {
                units += group.rs_fallback_searched(&prefix, slot.as_ref());
            }
            if let Some(entry) = slot {
                // RFC 7947: prepend from the source tags, scrub the post-policy route.
                let (_, source_large) =
                    group.source_control_for_route(entry.route, entry.source_attrs);
                let mut route = entry.route.clone();
                super::distribution::rs_control::rs_control_route_rewrite(
                    &mut route,
                    source_large,
                    rs_control,
                );
                routes.push(route);
                actions.push(entry.nh.cloned());
            } else if sent {
                withdraw.push((prefix, 0));
            } else {
                continue;
            }
            if sent {
                prior.insert(key);
            }
        }
        #[cfg(test)]
        super::slice_timing::record_work("initial_member_replay_units", units);
        if !routes.is_empty() || !withdraw.is_empty() {
            let batch = OutboundCommitBatch {
                slot: operation.slot(),
                force_unicast_replay: true,
                unicast_otc_prechecked: true,
                withdraw,
                ..OutboundCommitBatch::with_unicast(routes.into(), actions.into())
            };
            if !self.commit_initial_member_batch(peer, batch, prior) {
                return;
            }
        }
        self.initial_member_replays
            .members
            .get_mut(&peer)
            .expect("live replay")
            .changes
            .settle_coalesced(&reconciled);
        self.apply_initial_replay_page_policy(peer, gid, &keys);
        if self.outbound_channel_full(peer) || !self.complete_initial_member_replay(peer) {
            self.initial_member_replays.ready.push_back(peer);
        }
    }

    /// R2: withdraw admitted keys whose current slot is gone, one page of
    /// proof positions at a time in key order. R1 visited every key the
    /// Loc-RIB holds; a key it dropped while the replay had lost track of
    /// its changes has no scan repair and is found only here.
    fn sweep_initial_member_page(&mut self, peer: PeerId, gid: usize) {
        let Ok(mut operation) = self.begin_outbound_operation(peer, 1) else {
            self.initial_member_replays.blocked.push_back(peer);
            return;
        };
        let rs_control = self.rs_control_context(peer);
        let Some(admitted) = self.pending_group_admitted.get(&peer) else {
            self.recover_initial_member_replay(peer, PacedFallbackCause::MissingProof);
            return;
        };
        let replay = &self.initial_member_replays.members[&peer];
        let (keys, next, visited) = admitted.sweep_unicast(replay.swept, REGISTRATION_PAGE_SIZE);
        let group = &self.group_ribs[&gid];
        let mut units = 0;
        let mut withdraw = Vec::new();
        let mut prior = FastSet::default();
        for prefix in keys {
            units += 1;
            let slot = group.replay_slot(peer, &prefix, rs_control);
            if rs_control.is_some() {
                units += group.rs_fallback_searched(&prefix, slot.as_ref());
            }
            if slot.is_none() {
                withdraw.push((prefix, 0));
                prior.insert(ExactExportKey::Unicast(prefix, 0));
            }
        }
        #[cfg(test)]
        {
            super::slice_timing::record_work("initial_member_replay_visits", visited);
            super::slice_timing::record_work("initial_member_replay_units", units);
            super::slice_timing::record_work("initial_member_replay_swept", withdraw.len());
        }
        #[cfg(not(test))]
        let _ = (units, visited);
        if !withdraw.is_empty() {
            let batch = OutboundCommitBatch {
                slot: operation.slot(),
                force_unicast_replay: true,
                unicast_otc_prechecked: true,
                withdraw,
                ..OutboundCommitBatch::default()
            };
            if !self.commit_initial_member_batch(peer, batch, prior) {
                return;
            }
        }
        let replay = self
            .initial_member_replays
            .members
            .get_mut(&peer)
            .expect("live replay");
        replay.sweep_done = next.is_none();
        replay.swept = next;
        if self.outbound_channel_full(peer) || !self.complete_initial_member_replay(peer) {
            self.initial_member_replays.ready.push_back(peer);
        }
    }

    fn commit_initial_member_batch(
        &mut self,
        peer: PeerId,
        mut batch: OutboundCommitBatch,
        prior: FastSet<ExactExportKey>,
    ) -> bool {
        batch.on_proof_refusal = OnReservationRefusal::StopBeforeSend;
        let commit =
            self.try_send_and_commit_outbound_update_with_group_prior(peer, batch, prior, None);
        if let Err(failure) = commit {
            self.recover_initial_member_replay(peer, failure.paced_fallback_cause());
            return false;
        }
        if let Some(failure) = self.group_recovery_fallback(peer) {
            self.recover_initial_member_replay(peer, failure.into());
            return false;
        }
        self.advance_advertised_pages();
        true
    }
}
