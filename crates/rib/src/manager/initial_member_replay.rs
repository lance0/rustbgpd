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
use super::update_groups::admitted_recovery::{Key, OnReservationRefusal};
use super::{PeerId, RibManager};
use crate::fast_hash::FastSet;
use crate::loc_rib::{REGISTRATION_PAGE_SIZE, RegistrationScanStatus};
use crate::update::{ExactExportKey, OutboundRouteUpdate, RouteQueryKey, route_query_key};
use rustbgpd_wire::Prefix;

// The non-benchmark failure path carries only success/failure, and never
// evaluates the diagnostic (including any extra lookups it needs).
#[derive(Clone, Copy)]
pub(super) struct ReplayCause {
    #[cfg(feature = "bench-internals")]
    label: &'static str,
}

impl ReplayCause {
    pub(super) fn from_label(label: impl FnOnce() -> &'static str) -> Self {
        #[cfg(not(feature = "bench-internals"))]
        let _ = label;
        Self {
            #[cfg(feature = "bench-internals")]
            label: label(),
        }
    }
}

enum Phase {
    PrepareProof(Option<RouteQueryKey>),
    Send,
}

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
}

#[derive(Default)]
pub(super) struct InitialMemberReplays {
    members: HashMap<PeerId, Replay>,
    ready: VecDeque<PeerId>,
    blocked: VecDeque<PeerId>,
    registration_due: bool,
    #[cfg(feature = "bench-internals")]
    observer: Option<observation::ReplayObserver>,
    #[cfg(test)]
    pub(super) min_routes: Option<usize>,
}

impl InitialMemberReplays {
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
            .is_some_and(|replay| replay.changes.unsent())
    }

    pub(super) fn start_initial_member_replay(&mut self, peer: PeerId) -> bool {
        let Some(gid) = self.grouped_member_of(peer) else {
            return false;
        };
        let group = &self.group_ribs[&gid];
        if self.initial_member_replays.members.len() >= super::peer_lifecycle::MAX_JOIN_COHORT
            || group.evpn_table_stamp == 0
            || self.dirty_peers.contains(&peer)
            || self.outbound_prefix_limits.contains_key(&peer)
            || self.retain_initial_group_admitted(peer)
            || self.peer_orf_pending.contains_key(&peer)
        {
            return false;
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
        if !matches!(enrollment, Ok(true)) {
            #[cfg(feature = "bench-internals")]
            if let Err(error) = enrollment {
                self.observe_initial_replay(
                    peer,
                    BenchReplayEvent::EnrollmentRefused(error.cause.as_str()),
                );
            }
            return false;
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

    pub(super) fn abort_initial_member_replay(&mut self, peer: PeerId) -> bool {
        if self.initial_member_replays.members.remove(&peer).is_none() {
            return false;
        }
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
            && (self.first_group_build.is_some() || !self.pending_initial_registrations.is_empty())
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

    pub(super) fn recover_initial_member_replay(&mut self, peer: PeerId, cause: ReplayCause) {
        self.abort_initial_member_replay(peer);
        let marked = self.mark_outbound_dirty(peer);
        #[cfg(feature = "bench-internals")]
        if marked {
            self.observe_initial_replay(peer, BenchReplayEvent::Dirty(cause.label));
        }
        #[cfg(not(feature = "bench-internals"))]
        let _ = (cause, marked);
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
        let invalidation = if self.grouped_member_of(peer) != Some(gid)
            || self
                .group_ribs
                .get(&gid)
                .is_none_or(|g| g.evpn_table_stamp != job.table_stamp)
        {
            Some(ReplayCause::from_label(|| "group_changed"))
        } else if self.dirty_peers.contains(&peer) {
            Some(ReplayCause::from_label(|| {
                self.group_recovery_fallback(peer)
                    .map_or("already_dirty", |cause| cause.as_str())
            }))
        } else if self.loc_rib.member_replay_scan_status(peer) == RegistrationScanStatus::Overflow {
            Some(ReplayCause::from_label(|| "scan_repair_limit"))
        } else {
            match self.pending_group_admitted.initial_replay_sparse_len(peer) {
                None => Some(ReplayCause::from_label(|| "missing_proof")),
                Some(rows) if rows > REGISTRATION_PAGE_SIZE => {
                    Some(ReplayCause::from_label(|| "sparse_key_limit"))
                }
                Some(_) => None,
            }
        };
        if let Some(cause) = invalidation {
            self.recover_initial_member_replay(peer, cause);
            return;
        }
        if self.outbound_channel_full(peer) || self.outbound_operation_live(peer) {
            self.initial_member_replays.blocked.push_back(peer);
            return;
        }
        if let Phase::PrepareProof(after) = job.phase {
            self.prepare_initial_member_proof_page(peer, gid, after);
            return;
        }
        if !self.complete_initial_member_replay(peer) {
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
            self.recover_initial_member_replay(peer, ReplayCause::from_label(|| "missing_proof"));
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
            self.recover_initial_member_replay(peer, ReplayCause::from_label(|| "missing_proof"));
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
            // A coalesced key reconciles its current row against admission.
            if replay.changes.coalesced(&prefix) {
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
            self.recover_initial_member_replay(peer, ReplayCause::from_label(|| failure.as_str()));
            return false;
        }
        if let Some(failure) = self.group_recovery_fallback(peer) {
            self.recover_initial_member_replay(peer, ReplayCause::from_label(|| failure.as_str()));
            return false;
        }
        self.advance_advertised_pages();
        true
    }
}
