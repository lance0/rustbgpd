//! Preserve actual staged changes in publication order once replay begins
//! sending. Discovery owns the untouched rows. A change that does not fit the
//! bounded log is coalesced into its key's scan repair, which sends the
//! current row after the log drains instead of falling back to a resync.

use std::collections::{BTreeSet, VecDeque};

use rustbgpd_policy::NextHopAction;
use rustbgpd_wire::Prefix;

use super::{PacedFallbackCause, Phase, REGISTRATION_PAGE_SIZE, RibManager};
use crate::PeerId;
use crate::manager::distribution::OutboundCommitBatch;
use crate::manager::selection_deferral::retained_route_bytes;
use crate::manager::update_groups::{GroupDelta, GroupStageOutput};
use crate::outbound_credit::OutboundOperation;
use crate::route::Route;
use crate::update::ExactExportKey;

const MAX_BODY_BYTES: usize = 256 * 1024;

enum PreviousRoute {
    Different,
    Same(Option<NextHopAction>),
}

struct Announcement {
    route: Route,
    action: Option<NextHopAction>,
    previous: PreviousRoute,
    local_source: Option<crate::adj_rib_out::LocalExportSource>,
    charge: usize,
}

impl Announcement {
    fn into_batch(
        self,
        manager: &RibManager,
        peer: PeerId,
        admitted: bool,
    ) -> Option<OutboundCommitBatch<'static>> {
        let mut exact_export_snapshot = None;
        // The stage proved route equality. The receiver supplies the actual
        // prior and a single immutable profile for comparison and admission.
        if let PreviousRoute::Same(old) = self.previous
            && admitted
            && (self.route.peer != PeerId::LOCAL
                || manager
                    .adj_ribs_out
                    .get(&peer)
                    .and_then(|rib| rib.local_export_source(&self.route.prefix, 0))
                    == self.local_source)
            && let Some(encoder) = manager.peer_export_encoders.get(&peer)
        {
            let snapshot = encoder.snapshot();
            if snapshot.owner_id() == encoder.owner_id() {
                if snapshot.unicast_next_hop_actions_equal(
                    &self.route,
                    old.as_ref(),
                    self.action.as_ref(),
                ) {
                    return None;
                }
                exact_export_snapshot = Some(snapshot);
            }
        }
        let prefix = self.route.prefix;
        let mut batch =
            OutboundCommitBatch::with_unicast(vec![self.route].into(), vec![self.action].into());
        batch.exact_export_snapshot = exact_export_snapshot;
        if let Some(source) = self.local_source {
            batch.local_sources.insert((prefix, 0), source);
        }
        Some(batch)
    }
}

enum Change {
    Announce(Box<Announcement>),
    Withdraw(Prefix),
}

#[derive(Default)]
pub(super) struct ReplayChanges {
    pending: VecDeque<Change>,
    // Keys drained from the journal that are absent after a withdrawal or
    // exact-export rejection must not be rediscovered.
    absent: BTreeSet<Prefix>,
    // Changed keys the ordered log could not hold. Each still has its queued
    // scan repair, which sends the current group row once the log drains.
    coalesced: BTreeSet<Prefix>,
    // Set by the first coalesced change for the rest of the replay.
    overflowed: bool,
    body_bytes: usize,
}

impl ReplayChanges {
    /// A per-client-best slot also follows the runner-up, and an RS-control
    /// receiver's slot follows its own RFC 7947 view. The ordered log holds
    /// the shared row, so every change for such a member reconciles its
    /// current slot against admission instead.
    pub(super) fn coalescing() -> Self {
        Self {
            overflowed: true,
            ..Self::default()
        }
    }

    pub(super) fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Whether the group view holds a change this member has not accepted.
    pub(super) fn unsent(&self) -> bool {
        !self.pending.is_empty() || !self.coalesced.is_empty()
    }

    pub(super) fn owns_absent(&self, prefix: &Prefix) -> bool {
        self.absent.contains(prefix)
    }

    pub(super) fn coalesced(&self, prefix: &Prefix) -> bool {
        self.coalesced.contains(prefix)
    }

    /// Whether any of `prefixes` has a change this member has not settled:
    /// a coalesced repair, or a withdrawal it owns.
    pub(super) fn touches(&self, prefixes: &[Prefix]) -> bool {
        (!self.coalesced.is_empty() || !self.absent.is_empty())
            && prefixes
                .iter()
                .any(|prefix| self.coalesced.contains(prefix) || self.absent.contains(prefix))
    }

    pub(super) fn settle_coalesced(&mut self, prefixes: &[Prefix]) {
        for prefix in prefixes {
            self.coalesced.remove(prefix);
        }
    }

    /// Leave a change that does not fit to the key's repair. Repair pages run
    /// only after the log drains, so the repair follows every logged change
    /// for the key.
    fn coalesce(&mut self, prefix: Prefix) {
        self.absent.remove(&prefix);
        self.coalesced.insert(prefix);
        self.overflowed = true;
    }

    /// Log one change, or return `false` without side effects when it does not fit.
    fn push(&mut self, peer: PeerId, delta: &GroupDelta, stage: &GroupStageOutput) -> bool {
        let row = delta.new.as_ref().filter(|(row, _)| row.peer != peer);
        if row.is_none() && delta.old_source.is_none_or(|source| source == peer) {
            return true;
        }
        if self.pending.len() >= REGISTRATION_PAGE_SIZE {
            return false;
        }
        let change = if let Some((route, action)) = row {
            let Some(charge) = retained_route_bytes(route, size_of::<Announcement>())
                .filter(|charge| *charge <= MAX_BODY_BYTES - self.body_bytes)
            else {
                return false;
            };
            self.body_bytes += charge;
            Change::Announce(Box::new(Announcement {
                route: route.clone(),
                action: action.clone(),
                previous: stage
                    .prior_equal_actions
                    .get(&(delta.prefix, delta.path_id))
                    .map_or(PreviousRoute::Different, |old| {
                        PreviousRoute::Same(old.clone())
                    }),
                local_source: delta.local_source,
                charge,
            }))
        } else {
            Change::Withdraw(delta.prefix)
        };
        self.pending.push_back(change);
        true
    }
}

impl RibManager {
    pub(in crate::manager) fn record_initial_replay_changes(
        &mut self,
        peer: PeerId,
        stage: &GroupStageOutput,
    ) -> Result<(), PacedFallbackCause> {
        let rs_control = self.rs_control_context(peer).is_some();
        let replay = &self.initial_member_replays.members[&peer];
        // A pending rewind revisits every key.
        if matches!(replay.phase, Phase::PrepareProof) || replay.rewind {
            return Ok(());
        }
        let gid = replay.gid;
        let reconcile = replay.mode == super::Mode::Reconcile;
        // A reconcile reconciles every key it visits, so each change is a
        // repair whatever the group's shape.
        if self.group_ribs[&gid].per_client_best || rs_control || reconcile {
            // The member's slot reads the winner, its runner-up and, toward
            // an RS-control receiver, the source tags and fallback rows. The
            // last three change without a Loc-RIB write, so record the keys
            // the live per-member emit reads as scan repairs. A single-best
            // group has no runner-up or fallback rows.
            let keys = stage
                .deltas
                .iter()
                .map(|delta| delta.prefix)
                .chain(
                    stage
                        .lane_deltas
                        .iter()
                        .filter(|delta| delta.emit_target == Some(peer))
                        .map(|delta| delta.prefix),
                )
                .chain(
                    stage
                        .rs_transitions
                        .iter()
                        .map(|transition| transition.prefix)
                        .chain(stage.rs_priors.iter().map(|(prefix, _)| *prefix))
                        .filter(|_| rs_control),
                );
            let keys: Vec<Prefix> = keys.collect();
            for prefix in keys {
                if !self.record_replay_scan_change(peer, prefix) {
                    return Err(PacedFallbackCause::ScanRepairLimit);
                }
                self.initial_member_replays
                    .members
                    .get_mut(&peer)
                    .expect("active replay")
                    .changes
                    .coalesce(prefix);
            }
            return Ok(());
        }
        // A stage larger than one page goes to the repairs whole, so the
        // log never holds part of one publication.
        let oversized = stage.deltas.len() > REGISTRATION_PAGE_SIZE;
        for delta in &stage.deltas {
            // A write outside the scan's repair scope must go to the normal
            // resync before the receiver can settle its initial table.
            if !self.replay_scan_change_recorded(peer, delta.prefix) {
                return Err(if self.replay_scan_overflowed(peer) {
                    PacedFallbackCause::ScanRepairLimit
                } else {
                    PacedFallbackCause::ChangeOutsideScan
                });
            }
            let replay = self
                .initial_member_replays
                .members
                .get_mut(&peer)
                .expect("active replay");
            // After the first overflow, every later change joins the repairs
            // too. The log then only drains, so churn faster than one change
            // per writer operation cannot hold pages back past that drain.
            if oversized || replay.changes.overflowed || !replay.changes.push(peer, delta, stage) {
                replay.changes.coalesce(delta.prefix);
            }
        }
        Ok(())
    }

    pub(super) fn send_initial_replay_change(
        &mut self,
        peer: PeerId,
        mut operation: OutboundOperation,
    ) {
        let changes = &mut self
            .initial_member_replays
            .members
            .get_mut(&peer)
            .expect("active replay")
            .changes;
        let change = changes.pending.pop_front().expect("pending replay change");
        let prefix = match &change {
            Change::Announce(row) => row.route.prefix,
            Change::Withdraw(prefix) => *prefix,
        };
        let key = ExactExportKey::Unicast(prefix, 0);
        let prior = self
            .pending_group_admitted
            .get(&peer)
            .filter(|view| view.contains(&key))
            .map(|_| key.clone());
        #[cfg(test)]
        super::super::slice_timing::record_work("initial_member_replay_visits", 1);
        let batch = match change {
            Change::Announce(row) => {
                changes.body_bytes -= row.charge;
                let Some(batch) = row.into_batch(self, peer, prior.is_some()) else {
                    self.initial_member_replays.ready.push_back(peer);
                    return;
                };
                batch
            }
            Change::Withdraw(prefix) => OutboundCommitBatch {
                withdraw: vec![(prefix, 0)],
                ..OutboundCommitBatch::default()
            },
        };
        if prior.is_some() || batch.withdraw.is_empty() {
            let batch = OutboundCommitBatch {
                slot: operation.slot(),
                force_unicast_replay: true,
                unicast_otc_prechecked: true,
                ..batch
            };
            if !self.commit_initial_member_batch(peer, batch, prior.into_iter().collect(), None) {
                return;
            }
        }
        let changes = &mut self
            .initial_member_replays
            .members
            .get_mut(&peer)
            .expect("active replay")
            .changes;
        if self
            .pending_group_admitted
            .get(&peer)
            .is_some_and(|view| view.contains(&key))
        {
            changes.absent.remove(&prefix);
        } else if changes.absent.len() < REGISTRATION_PAGE_SIZE {
            // Past the cap, a later page that reaches this key probes it
            // again and admits only what the current group row allows.
            changes.absent.insert(prefix);
        }
        self.initial_member_replays.ready.push_back(peer);
    }
}
