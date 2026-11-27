//! Replay a published single-best group through the registration lane. A full
//! writer parks with its exact admitted-key proof and its scan position intact.
//!
//! Members that join one group table under the same view ride one scan of
//! the Loc-RIB. The cohort keeps the pages it took in a log, and each member
//! works through that log at its own writer's pace. A member that falls a
//! whole log behind leaves the scan and reconciles on its own.

mod changes;

#[cfg(feature = "bench-internals")]
mod observation;
#[cfg(feature = "bench-internals")]
pub use observation::BenchReplayEvent;

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use changes::ReplayChanges;
use tokio::sync::mpsc;

use super::distribution::{
    LazyCleanGroupPrior, OutboundCommitBatch, SharedUnicastPrecommit, SharedUnicastProbeCache,
};
use super::update_groups::admitted_recovery::{
    Failure, Key, OnReservationRefusal, ReplayRoom, SnapshotHandle,
};
use super::{PeerId, RibManager};
use crate::fast_hash::FastSet;
use crate::loc_rib::{REGISTRATION_PAGE_SIZE, RegistrationScanStatus, ScanBoundary};
use crate::route::Route;
use crate::update::{ExactExportKey, OutboundRouteUpdate, RouteQueryKey, route_query_key};
use rustbgpd_wire::{Afi, Prefix, Safi};

pub(super) use rustbgpd_telemetry::reason_labels::{PacedFallbackCause, PacedJob};

enum Phase {
    /// The member's cohort has not walked its whole group table yet.
    PrepareProof,
    Send,
}

/// Members replaying one group table under the same view share one key
/// universe: the table's keys, walked once. Each member's proof is its own
/// mask over that universe plus its own sparse overlay, so one member's
/// admissions and withdrawals never show in another's. The ledger counts the
/// members; the last reference retires the universe.
///
/// They also share one scan of the Loc-RIB. The pages the cohort took from
/// it stay in a log until every rider has worked through them, so the scan
/// visits each bucket once per pass however many members ride it.
struct Cohort {
    handle: SnapshotHandle,
    key: CohortKey,
    // The shared walk of the group table: its next seek, and whether it has
    // reached the end.
    after: Option<RouteQueryKey>,
    walked: bool,
    // The largest overlay a member completed with: keys the table gained
    // after the walk passed them.
    overlay: usize,
    // Every peer that enrolled with this universe, including one that has
    // since left the scan: only these can hold a proof that references it.
    enrolled: Vec<PeerId>,
    // The cohort's Loc-RIB scan, live while a member rides it.
    scan: Option<u32>,
    riders: usize,
    // Pages taken from the scan that some rider has not worked through,
    // oldest first, and the sequence number of the first.
    log: VecDeque<LogPage>,
    base: u64,
}

/// A rider may fall this many pages behind the newest before it leaves the
/// scan for its own reconcile. A parked writer holds its member back while
/// the others advance; the log holds at most this many pages for it.
const COHORT_LOG_PAGES: usize = 64;

/// One page of the cohort's scan: discovered buckets or changed keys.
struct LogPage {
    keys: Vec<Prefix>,
    // Set by the first rider to take the page.
    shared: Option<SharedPage>,
}

/// What a page's keys resolve to once for every rider.
struct SharedPage {
    // Each page key's position in the cohort's universe. The universe is
    // complete before any rider sends, so these outlive the rows.
    positions: Vec<u32>,
    prefixes: Arc<HashSet<Prefix>>,
    // Resolved for the first rider that holds none of the page's keys, and
    // dropped when the group table is written at one of them.
    rows: Option<SharedRows>,
}

/// What every rider's slot shares at a page's keys: the staged winner of
/// each key that RFC 7947 control leaves alone for the cohort's view. A
/// member takes these rows as they are, less the ones it sourced. `private`
/// keys carry a control community for the view's RS ASN, so each member
/// resolves its own slot there.
struct SharedRows {
    routes: Arc<Vec<Route>>,
    actions: Arc<Vec<Option<rustbgpd_policy::NextHopAction>>>,
    private: Vec<Prefix>,
    encode: Arc<crate::update::SharedGroupEncode>,
    probes: SharedUnicastProbeCache,
}

/// A rider's place on its cohort's scan: the boundary at which the scan has
/// passed every bucket since the member joined, and the next log page the
/// member works through.
#[derive(Clone, Copy)]
struct Lap {
    end: ScanBoundary,
    seq: u64,
}

/// The group, its table stamp at enrollment and the view class: the
/// route-server ASN under RFC 7947 control, or none.
type CohortKey = (usize, u64, Option<u32>);

/// A late joiner starts a new universe once a member's overlay passed one
/// key in this many of the universe: past that, the keys the old universe
/// lacks cost each member more than its mask.
const COHORT_OVERLAY_DIVISOR: usize = 16;

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

/// Rewinds a replay may take before it takes the dirty resync with cause
/// `lag`.
// Interim liveness bound: churn that overflows every rescan, or a member
// marked dirty again faster than its rescan finishes, would otherwise re-arm
// forever and hold the replay back. After this many rewinds the replay takes
// one counted dirty resync, trading a rare whole-table turn for a capped
// repair log and certain completion. A rewind still pending is not counted
// again. The shared lag bound replaces this with a forced bounded unit and a
// paced restart.
const MAX_REARMS: u16 = 8;

#[expect(
    clippy::struct_excessive_bools,
    reason = "rewind, forced resync, sweep completion, the sweep's turn and denial completion are independent replay states"
)]
struct Replay {
    gid: usize,
    table_stamp: u64,
    session: u64,
    sender: mpsc::Sender<OutboundRouteUpdate>,
    // The cohort universe the member's proof references. An adopted proof
    // keeps its own form and has none.
    universe: Option<SnapshotHandle>,
    // The member rides its cohort's scan. Without one it reconciles on a
    // scan of its own.
    lap: Option<Lap>,
    phase: Phase,
    changes: ReplayChanges,
    // Page keys left when a poll spent its unit budget. An RS-control
    // member's slot may search the prefix's fallback rows.
    carry: VecDeque<Prefix>,
    mode: Mode,
    // A reconcile restarts its scan at its next turn. Until then the scan is
    // stopped: the rescan revisits every key, so nothing needs recording.
    rewind: bool,
    // Rewinds this replay took after its scan had started.
    rearms: u16,
    // The reconcile consumed a forced resync, which holds until R1 has
    // resent every row. A fallback before then must force its resync.
    forced: bool,
    // R2's position: the last proof key it visited, and whether it is done.
    swept: Option<Key>,
    sweep_done: bool,
    // Once R1 has visited every key, repair and sweep turns alternate, so a
    // change before every turn cannot hold R2 back.
    sweep_due: bool,
    // R3's position in the member's denial history: the last prefix it
    // visited, and whether it is done. A denied prefix that left the
    // Loc-RIB while the replay had lost track of its changes is in that
    // history alone, so neither R1 nor R2 reaches it.
    denied: Option<Prefix>,
    denials_done: bool,
    // A reconcile the resync tick enrolled for a member that fell behind. It
    // owes no End-of-RIB of its own, and its fallback counts for the
    // grouped resync.
    resync: bool,
    // The start of the dirty episode this replay took over, at enrollment
    // or from a later dirty mark. The member counts as pending a resync
    // until the replay completes.
    dirty_since: Option<tokio::time::Instant>,
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
    // Live universes, oldest first. One whose last reference is gone is
    // dropped at the next enrollment.
    cohorts: Vec<Cohort>,
    next_scan: u32,
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
    // Members whose replay fell back to the dirty resync, by session, with
    // the start of the dirty episode the replay had taken over: that resync runs in one
    // turn, the fallback the replay counted. Enrolling it again could repeat
    // the refusal or the lag that ended the replay.
    one_turn: HashMap<PeerId, (u64, Option<tokio::time::Instant>)>,
    #[cfg(feature = "bench-internals")]
    observer: Option<observation::ReplayObserver>,
    #[cfg(test)]
    pub(super) min_routes: Option<usize>,
    // The synchronous reference arm of the resync oracles.
    #[cfg(test)]
    pub(super) resync_in_one_turn: bool,
    // A cohort log depth below [`COHORT_LOG_PAGES`], for tables of a few pages.
    #[cfg(test)]
    pub(super) cohort_log_pages: Option<usize>,
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

    /// Whether `peer` owes a one-turn resync its replay's fallback counted.
    #[cfg(test)]
    pub(super) fn one_turn_resync_owed(&self, peer: PeerId) -> bool {
        self.initial_member_replays.one_turn.contains_key(&peer)
    }

    /// Whether `peer`'s reconcile has passed every key (R1) and swept part
    /// of its proof (R2).
    #[cfg(test)]
    pub(super) fn initial_member_replay_sweeping(&self, peer: PeerId) -> bool {
        self.initial_member_replays
            .members
            .get(&peer)
            .is_some_and(|replay| replay.mode == Mode::Reconcile && replay.swept.is_some())
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
        let (rows, gid) = self.pending_replay_rows(peer);
        let shared = gid.and_then(|gid| self.replay_cohort(self.replay_cohort_key(peer, gid)?));
        let room = self
            .pending_group_admitted
            .initial_replay_room(rows, shared);
        (room != ReplayRoom::Never).then_some(room)
    }

    /// The cohort `peer` would join in published group `gid`. A registration
    /// still waiting reads the RS-control setting its session will install.
    fn replay_cohort_key(&self, peer: PeerId, gid: usize) -> Option<CohortKey> {
        let stamp = self.group_ribs.get(&gid)?.evpn_table_stamp;
        // The pending setting is consumed when the session installs: while it
        // is there, the installed one belongs to an older session.
        let pending = self
            .live_sessions
            .get(&peer)
            .and_then(|sessions| sessions.last())
            .and_then(|record| self.pending_peer_rs_control.get(&(peer, record.session_id)));
        let view = match pending {
            Some(view) => *view,
            None => self.peer_rs_control.get(&peer).copied(),
        };
        Some((gid, stamp, view))
    }

    /// The largest overlay a member completed with, per universe.
    #[cfg(test)]
    pub(super) fn replay_cohort_overlays(&self) -> Vec<usize> {
        let cohorts = &self.initial_member_replays.cohorts;
        cohorts.iter().map(|cohort| cohort.overlay).collect()
    }

    /// The newest live universe of cohort `key` a joiner may share.
    fn replay_cohort(&self, key: CohortKey) -> Option<SnapshotHandle> {
        let cohort = self
            .initial_member_replays
            .cohorts
            .iter()
            .rev()
            .find(|cohort| cohort.key == key)?;
        let rows = self
            .pending_group_admitted
            .replay_universe_capacity(cohort.handle)?;
        (cohort.overlay.saturating_mul(COHORT_OVERLAY_DIVISOR) <= rows).then_some(cohort.handle)
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
        let universe = match self.enroll_replay_proof(peer, gid) {
            Ok(Some(universe)) => universe,
            Ok(None) => {
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
        };
        self.refresh_group_recovery_gauges();
        let lap = self.join_cohort_scan(universe);
        let previous = self.initial_member_replays.members.insert(
            peer,
            Replay {
                gid,
                table_stamp,
                session: self.outbound_session_ids[&peer],
                sender: self.outbound_peers[&peer].clone(),
                universe: Some(universe),
                lap: Some(lap),
                // A late joiner whose cohort has walked the table sends at
                // its first turn.
                phase: Phase::PrepareProof,
                changes,
                carry: VecDeque::new(),
                mode: Mode::Initial,
                rewind: false,
                rearms: 0,
                forced: false,
                swept: None,
                sweep_done: false,
                sweep_due: false,
                denied: None,
                denials_done: true,
                resync: false,
                dirty_since: None,
            },
        );
        debug_assert!(previous.is_none(), "a live replay was overwritten");
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

    /// Start `peer`'s replay proof in group `gid`: a reference to its
    /// cohort's live universe, or a new universe the cohort's walk fills.
    /// `None` when the member's proof is not complete and empty.
    fn enroll_replay_proof(
        &mut self,
        peer: PeerId,
        gid: usize,
    ) -> Result<Option<SnapshotHandle>, Failure> {
        let rows = self.group_ribs[&gid].table.len();
        let key = self.replay_cohort_key(peer, gid).expect("published group");
        let shared = self.replay_cohort(key);
        let Some(universe) = self
            .pending_group_admitted
            .begin_initial_replay(peer, rows, shared)?
        else {
            return Ok(None);
        };
        let ledger = &self.pending_group_admitted;
        let cohorts = &mut self.initial_member_replays.cohorts;
        // A rider whose proof was dropped still leaves its scan at its turn.
        cohorts.retain(|cohort| {
            cohort.riders != 0 || ledger.replay_universe_capacity(cohort.handle).is_some()
        });
        let index = cohorts
            .iter()
            .position(|cohort| cohort.handle == universe)
            .unwrap_or_else(|| {
                cohorts.push(Cohort {
                    handle: universe,
                    key,
                    after: None,
                    walked: false,
                    overlay: 0,
                    enrolled: Vec::new(),
                    scan: None,
                    riders: 0,
                    log: VecDeque::new(),
                    base: 0,
                });
                cohorts.len() - 1
            });
        if !cohorts[index].enrolled.contains(&peer) {
            cohorts[index].enrolled.push(peer);
        }
        Ok(Some(universe))
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
        // Teardown and replacement end any owed one-turn resync with the
        // session; a fallback records its own entry after this.
        self.initial_member_replays.one_turn.remove(&peer);
        let Some(replay) = self.initial_member_replays.members.remove(&peer) else {
            return false;
        };
        // A forced resync the reconcile had not finished passes to the
        // owner that takes over this session's table.
        if replay.forced && self.outbound_session_ids.get(&peer) == Some(&replay.session) {
            self.force_outbound_peers.insert(peer);
        }
        // A released slot or proof budget may admit a waiting registration.
        self.initial_member_replays.slot_wait = None;
        self.initial_member_replays.ready.retain(|p| *p != peer);
        self.initial_member_replays.blocked.retain(|p| *p != peer);
        self.stop_replay_scan(peer, replay.lap.is_some(), replay.universe);
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
        // Another owner may have marked the member dirty. When the member
        // could reconcile a resync in pages, the reconcile is that resync.
        let dirty = self.dirty_peers.contains(&peer);
        let reconcilable = match cause {
            Cause::ScanRepairLimit
            | Cause::CohortLag
            | Cause::ChangeOutsideScan
            | Cause::ReleaseFanout
            | Cause::SelectionRelease
            | Cause::AlreadyDirty => true,
            Cause::ForcedResync => !self.peer_orf_filters.contains_key(&peer),
            _ => false,
        } && (!dirty || self.resync_reconcile_refusal(peer, true).is_ok());
        let mut cause = cause;
        if reconcilable
            && self
                .pending_group_admitted
                .initial_replay_sparse_len(peer)
                .is_some()
            && self.initial_member_replays.members.contains_key(&peer)
        {
            // The dirty mark's force bit holds as a forced resync's does.
            let marked_force =
                dirty && self.dirty_peers.remove(&peer) && self.force_outbound_peers.remove(&peer);
            let episode = dirty.then(|| {
                self.dirty_since
                    .get(&peer)
                    .copied()
                    .unwrap_or_else(tokio::time::Instant::now)
            });
            if dirty {
                self.refresh_eor_retry(peer);
            }
            let replay = self
                .initial_member_replays
                .members
                .get_mut(&peer)
                .expect("live replay");
            replay.forced |= marked_force;
            // The replay now owes the member the resync that mark asked for.
            if let Some(since) = episode {
                replay.dirty_since.get_or_insert(since);
            }
            // A pending rewind already covers every later cause, such as the
            // next batch of a paged release.
            let pending = replay.rewind;
            if !pending {
                replay.rearms += 1;
            }
            if pending {
                replay.forced |= cause == Cause::ForcedResync;
                if cause == Cause::ForcedResync {
                    self.force_outbound_peers.remove(&peer);
                    self.refresh_eor_retry(peer);
                }
                return true;
            }
            if replay.rearms > MAX_REARMS {
                cause = Cause::Lag;
            } else {
                replay.mode = Mode::Reconcile;
                replay.rewind = true;
                replay.changes = ReplayChanges::coalescing();
                replay.carry.clear();
                replay.swept = None;
                replay.sweep_done = false;
                replay.denied = None;
                replay.denials_done = false;
                // Every reconcile row is a forced replay.
                replay.forced |= cause == Cause::ForcedResync;
                let rearms = replay.rearms;
                // A rider leaves its cohort's scan: the rescan is its own.
                let (rode, universe) = (replay.lap.take().is_some(), replay.universe);
                self.stop_replay_scan(peer, rode, universe);
                let replays = &mut self.initial_member_replays;
                if !replays.ready.contains(&peer) && !replays.blocked.contains(&peer) {
                    replays.ready.push_back(peer);
                }
                if cause == Cause::ForcedResync {
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
                Self::count_reconcile(cause);
                return true;
            }
        }
        if !self.fall_back_initial_member_replay(peer, cause) {
            self.note_paced_fallback(PacedJob::InitialReplay, cause, peer);
        }
        let marked = self.mark_outbound_dirty(peer);
        if marked {
            self.restore_resync_episode(peer);
        }
        #[cfg(feature = "bench-internals")]
        if marked {
            self.observe_initial_replay(peer, BenchReplayEvent::Dirty(cause.as_str()));
        }
        false
    }

    /// Count a reconcile, in total and under its cause's label.
    #[cfg(test)]
    fn count_reconcile(cause: PacedFallbackCause) {
        super::slice_timing::record_work("initial_replay_reconciles", 1);
        super::slice_timing::record_work(cause.as_str(), 1);
    }

    /// End `peer`'s replay for a fallback to its dirty resync, counting the
    /// fallback for its job. That resync then runs in one turn: enrolling
    /// it again could repeat the refusal or the lag that ended the replay.
    /// `false` without a replay.
    pub(super) fn fall_back_initial_member_replay(
        &mut self,
        peer: PeerId,
        cause: PacedFallbackCause,
    ) -> bool {
        let Some(replay) = self.initial_member_replays.members.get(&peer) else {
            return false;
        };
        let (session, since) = (replay.session, replay.dirty_since);
        let job = if replay.resync {
            PacedJob::GroupedResync
        } else {
            PacedJob::InitialReplay
        };
        self.note_paced_fallback(job, cause, peer);
        self.abort_initial_member_replay(peer);
        self.initial_member_replays
            .one_turn
            .insert(peer, (session, since));
        true
    }

    /// A resync reconcile that fell back keeps its dirty episode's start
    /// once the member is marked dirty again.
    pub(super) fn restore_resync_episode(&mut self, peer: PeerId) {
        if let Some(&(_, Some(since))) = self.initial_member_replays.one_turn.get(&peer) {
            self.dirty_since.insert(peer, since);
        }
    }

    /// Why dirty `peer`'s resync cannot reconcile in pages, or its group
    /// when it can. `Err(None)` keeps the one-turn resync without counting
    /// a fallback: an ungrouped receiver (the owed row cursor paces it), a
    /// table below the pacing threshold, a selection hold, an owed-row cap
    /// eviction (counted as `owed_row_cap`), a selection-held rebuild, or a
    /// replay that already counted the fallback that made the member dirty.
    /// `live`: the member's replay already runs, so it takes no new slot.
    pub(super) fn resync_reconcile_refusal(
        &self,
        peer: PeerId,
        live: bool,
    ) -> Result<usize, Option<PacedFallbackCause>> {
        use PacedFallbackCause as Cause;
        let Some(gid) = self.grouped_member_of(peer) else {
            return Err(None);
        };
        let session = self.outbound_session_ids.get(&peer).copied();
        let Some(record) = session.and_then(|session| {
            self.live_sessions
                .get(&peer)?
                .iter()
                .rev()
                .find(|record| record.session_id == session)
        }) else {
            return Err(None);
        };
        #[cfg(test)]
        let reference = self.initial_member_replays.resync_in_one_turn;
        #[cfg(not(test))]
        let reference = false;
        if reference
            || self.loc_rib.len() < self.initial_member_replay_min_routes()
            || self.owed_row_evicted.contains(&peer)
            || self.held_rebuilds.iter().any(|peers| peers.contains(&peer))
            || record.selection_initial_pending
            || record.selection_partial_pending.contains(&true)
            || self.selection_resync_held(peer)
            || self.selection_release_resync_pending(peer)
            || (!live
                && session.is_some_and(|session| {
                    self.initial_member_replays
                        .one_turn
                        .get(&peer)
                        .is_some_and(|(owner, _)| *owner == session)
                }))
        {
            return Err(None);
        }
        let cause = if !self.paced_session_shape(record)
            || self
                .peer_otc_blocked
                .get(&peer)
                .is_some_and(|blocked| !blocked.is_empty())
        {
            Cause::IneligibleShape
        } else if self.pending_regroup_baseline.contains_key(&peer) {
            // The member still owes the withdrawals of the group it left.
            Cause::GroupChanged
        } else if self
            .group_ribs
            .get(&gid)
            .is_none_or(|group| group.evpn_table_stamp == 0)
        {
            Cause::UnpublishedTable
        } else if self.outbound_prefix_limits.contains_key(&peer)
            || self.configured_outbound_limit(peer)
        {
            Cause::PrefixLimit
        } else if self.peer_orf_pending.contains_key(&peer) {
            Cause::OrfPending
        } else if let Some(fallback) = self.group_recovery_fallback(peer) {
            fallback.into()
        } else if !self.pending_group_admitted.contains_key(&peer) {
            Cause::MissingProof
        } else if !live
            && self.initial_member_replays.members.len() >= super::peer_lifecycle::MAX_JOIN_COHORT
        {
            Cause::ReplayCap
        } else {
            return Ok(gid);
        };
        Err(Some(cause))
    }

    /// The resync tick's unit for dirty `peer`. An eligible grouped member
    /// enrolls a paced reconcile of its table instead of building it whole
    /// in this turn: R1 rescans the Loc-RIB against the member's captured
    /// proof, which is what it was sent, and R2 sweeps that proof for keys
    /// that are gone. The reconcile owes no End-of-RIB of its own; a marker
    /// the member already owes stays held until it completes. `Err` leaves
    /// the one-turn resync to run, with the cause
    /// [`Self::grouped_resync_ran`] counts once it is built.
    ///
    /// A member whose replay is already live (parked on a full writer, or
    /// its rewind held behind a source departure) keeps it: the replay takes
    /// the mark as it would at its next turn, rewinding with its proof and
    /// force bit, or falling back and counting why.
    pub(super) fn reconcile_grouped_resync(
        &mut self,
        peer: PeerId,
    ) -> Result<(), Option<PacedFallbackCause>> {
        if self.is_initial_member_replay(peer) {
            let cause = self
                .group_recovery_fallback(peer)
                .map_or(PacedFallbackCause::AlreadyDirty, Into::into);
            if self.recover_initial_member_replay(peer, cause) {
                return Ok(());
            }
        }
        let gid = self.resync_reconcile_refusal(peer, false)?;
        let adopted = self.pending_group_admitted.begin_reconcile(peer);
        debug_assert!(adopted, "a complete proof was checked");
        let forced = self.force_outbound_peers.remove(&peer);
        self.dirty_peers.remove(&peer);
        self.initial_member_replays.one_turn.remove(&peer);
        let since = self
            .dirty_since
            .get(&peer)
            .copied()
            .unwrap_or_else(tokio::time::Instant::now);
        let previous = self.initial_member_replays.members.insert(
            peer,
            Replay {
                gid,
                table_stamp: self.group_ribs[&gid].evpn_table_stamp,
                session: self.outbound_session_ids[&peer],
                sender: self.outbound_peers[&peer].clone(),
                // The captured proof is the member's admission: nothing to prepare.
                universe: None,
                lap: None,
                phase: Phase::Send,
                changes: ReplayChanges::coalescing(),
                carry: VecDeque::new(),
                mode: Mode::Reconcile,
                // R1 starts at the member's first turn, after any source departure.
                rewind: true,
                rearms: 0,
                forced,
                swept: None,
                sweep_done: false,
                sweep_due: false,
                // R1 revisits every Loc-RIB key's denials; R3 pages through
                // the history for denied routes that left while the member
                // was dirty.
                denied: None,
                denials_done: false,
                resync: true,
                dirty_since: Some(since),
            },
        );
        debug_assert!(previous.is_none(), "a live replay was overwritten");
        self.initial_member_replays.ready.push_back(peer);
        // The export counters a one-turn resync replays, synthesized from
        // the group as a join's are.
        self.start_initial_replay_policy(peer, gid);
        self.refresh_group_recovery_gauges();
        self.refresh_eor_retry(peer);
        tracing::debug!(%peer, forced, "grouped resync enrolls a paced reconcile");
        #[cfg(feature = "bench-internals")]
        self.observe_initial_replay(peer, BenchReplayEvent::ResyncReconcile);
        #[cfg(test)]
        super::slice_timing::record_work("grouped_resync_reconciles", 1);
        Ok(())
    }

    /// The resync tick's one-turn unit for `peer` ran. When it built the
    /// table, count `fallback`, the cause [`Self::reconcile_grouped_resync`]
    /// refused with; a unit refused before the build retries uncounted. A
    /// later resync of the member may reconcile again.
    pub(super) fn grouped_resync_ran(
        &mut self,
        peer: PeerId,
        built: bool,
        fallback: Option<PacedFallbackCause>,
    ) {
        if built && let Some(cause) = fallback {
            self.note_paced_fallback(PacedJob::GroupedResync, cause, peer);
        }
        #[cfg(feature = "bench-internals")]
        if built && self.grouped_member_of(peer).is_some() {
            self.observe_initial_replay(
                peer,
                BenchReplayEvent::ResyncOneTurn(fallback.map(PacedFallbackCause::as_str)),
            );
        }
        self.initial_member_replays.one_turn.remove(&peer);
    }

    /// Each member whose replay took over a dirty episode, with its start:
    /// a resync reconcile, or a join that consumed a later dirty mark.
    pub(super) fn resync_reconciles(
        &self,
    ) -> impl Iterator<Item = (PeerId, tokio::time::Instant)> + '_ {
        self.initial_member_replays
            .members
            .iter()
            .filter_map(|(peer, replay)| Some((*peer, replay.dirty_since?)))
    }

    /// The start of the dirty episode `peer`'s replay took over, if any.
    pub(super) fn resync_reconcile_since(&self, peer: PeerId) -> Option<tokio::time::Instant> {
        self.initial_member_replays
            .members
            .get(&peer)
            .and_then(|replay| replay.dirty_since)
    }

    /// Restart a reconcile's scan from its first bucket. The proof stays.
    fn rewind_initial_member_replay(&mut self, peer: PeerId) {
        let replay = self
            .initial_member_replays
            .members
            .get_mut(&peer)
            .expect("live replay");
        replay.rewind = false;
        self.loc_rib.start_member_replay_scan(peer);
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
        // The rescan covers a running departure's changes: rewinding before
        // it ends would only overflow again.
        if rewind && self.source_departure.is_some() {
            self.initial_member_replays.ready.push_back(peer);
            return;
        }
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
            (self.replay_scan_status(peer) == RegistrationScanStatus::Overflow)
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
        if matches!(
            self.initial_member_replays.members[&peer].phase,
            Phase::PrepareProof
        ) && !self.prepare_initial_member_proof_page(peer, gid)
        {
            return;
        }
        if self.complete_initial_member_replay(peer) {
            return;
        }
        let ready = self.replay_scan_status(peer) == RegistrationScanStatus::Ready;
        let discovered = self.loc_rib.member_replay_discovery_finished(peer);
        let replay = self
            .initial_member_replays
            .members
            .get_mut(&peer)
            .expect("live replay");
        if replay.mode == Mode::Reconcile
            && replay.carry.is_empty()
            && (ready
                || (discovered && replay.sweep_due && !(replay.sweep_done && replay.denials_done)))
        {
            // R1 has resent every row. Repairs queued since then reconcile
            // their keys against the current slot and admission, including
            // keys this sweep has already passed.
            replay.forced = false;
            replay.sweep_due = false;
            if replay.sweep_done && !replay.denials_done {
                self.sweep_initial_member_denials(peer, gid);
            } else {
                self.sweep_initial_member_page(peer, gid);
            }
        } else {
            replay.sweep_due = true;
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
            || (job.mode == Mode::Reconcile && !(job.sweep_done && job.denials_done))
            || self.replay_scan_status(peer) != RegistrationScanStatus::Ready
            || self.dirty_peers.contains(&peer)
        {
            return false;
        }
        debug_assert!(!job.changes.unsent(), "a coalesced key outlived its repair");
        let job_gid = job.gid;
        let universe = job.universe;
        // End-of-RIB waits for the rest of an UPDATE whose first chunks applied.
        if !self.pending_route_batches.is_empty() {
            self.initial_member_replays.ready.push_back(peer);
            return true;
        }
        // What the member admitted outside its universe measures how far the
        // table has moved from it, for the next joiner.
        if let Some(overlay) = self.pending_group_admitted.initial_replay_sparse_len(peer)
            && let Some(cohort) = self
                .initial_member_replays
                .cohorts
                .iter_mut()
                .find(|cohort| Some(cohort.handle) == universe)
        {
            cohort.overlay = cohort.overlay.max(overlay);
        }
        self.abort_initial_member_replay(peer);
        #[cfg(feature = "bench-internals")]
        self.observe_initial_replay(peer, BenchReplayEvent::Completed);
        self.complete_initial_selection_replay(peer);
        // A reconcile that took over a dirty member's resync also retires
        // the residue the group kept for it, as a completed resync does.
        if self
            .group_ribs
            .get(&job_gid)
            .is_some_and(|group| group.dirty_members.contains(&peer))
        {
            self.clear_grouped_member_synced(peer);
        }
        self.retire_completed_initial_group_admitted(peer);
        self.settle_free_eor(peer);
        true
    }

    /// One page of the cohort's walk of its group table, taken by whichever
    /// member's turn comes: the walk runs once however many members share
    /// the universe. `true` once the walk has ended and `peer` may send in
    /// this turn.
    fn prepare_initial_member_proof_page(&mut self, peer: PeerId, gid: usize) -> bool {
        let replays = &mut self.initial_member_replays;
        let universe = replays.members[&peer].universe;
        let Some(cohort) = replays
            .cohorts
            .iter_mut()
            .find(|cohort| Some(cohort.handle) == universe)
        else {
            self.recover_initial_member_replay(peer, PacedFallbackCause::MissingProof);
            return false;
        };
        if cohort.walked {
            replays.members.get_mut(&peer).expect("live replay").phase = Phase::Send;
            return true;
        }
        let table = &self.group_ribs[&gid].table;
        let mut last = None;
        // The ordered iterator revisits the one single-best row at its inclusive seek.
        let mut visits = usize::from(cohort.after.is_some());
        let remaining = REGISTRATION_PAGE_SIZE - visits;
        let keys = table
            .iter_ordered_from(cohort.after)
            .take(remaining)
            .map(|row| {
                last = Some(route_query_key(row));
                visits += 1;
                Key::Unicast(row.prefix, row.path_id)
            });
        if !self.pending_group_admitted.extend_initial_replay_universe(
            cohort.handle,
            keys,
            &cohort.enrolled,
        ) {
            self.recover_initial_member_replay(peer, PacedFallbackCause::MissingProof);
            return false;
        }
        #[cfg(test)]
        {
            super::slice_timing::record_work("initial_member_replay_visits", visits);
            super::slice_timing::record_work("initial_member_proof_walk_rows", visits);
        }
        if visits == REGISTRATION_PAGE_SIZE {
            cohort.after = last;
        } else {
            cohort.walked = true;
            replays.members.get_mut(&peer).expect("live replay").phase = Phase::Send;
        }
        replays.ready.push_back(peer);
        false
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
        if replay.carry.is_empty() && !self.fill_replay_carry(peer, gid, &mut operation) {
            return;
        }
        let replay = self
            .initial_member_replays
            .members
            .get_mut(&peer)
            .expect("live replay");
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
            if !self.commit_initial_member_batch(peer, batch, prior, None) {
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
        let (keys, mut next, visited) =
            admitted.sweep_unicast(replay.swept, REGISTRATION_PAGE_SIZE);
        let mut checked = None;
        let group = &self.group_ribs[&gid];
        let mut units = 0;
        let mut withdraw = Vec::new();
        let mut prior = FastSet::default();
        for key in keys {
            // An RS-control slot may search the prefix's fallback rows: the
            // next page resumes after the last key this one checked.
            if units >= REGISTRATION_PAGE_SIZE {
                next = checked;
                break;
            }
            checked = Some(key);
            let Key::Unicast(prefix, _) = key else {
                continue;
            };
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
            if !self.commit_initial_member_batch(peer, batch, prior, None) {
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

    /// R3: reconcile one page of the member's denial history, in prefix
    /// order, for prefixes the Loc-RIB no longer holds. R1 reconciled the
    /// denials of every key the Loc-RIB holds, and the live passes keep
    /// them current; a prefix that left while the replay had lost track of
    /// its changes is found only here.
    fn sweep_initial_member_denials(&mut self, peer: PeerId, gid: usize) {
        use std::ops::Bound::{Excluded, Unbounded};

        let after = self.initial_member_replays.members[&peer].denied;
        let mut visits = 0;
        let mut last = None;
        let departed: HashSet<Prefix> = self
            .policy_filtered_routes
            .get(&peer)
            .into_iter()
            .flat_map(|history| history.range((after.map_or(Unbounded, Excluded), Unbounded)))
            .take(REGISTRATION_PAGE_SIZE)
            .map(|(prefix, _)| {
                visits += 1;
                last = Some(*prefix);
                *prefix
            })
            .filter(|prefix| self.loc_rib.get(prefix).is_none())
            .collect();
        #[cfg(test)]
        super::slice_timing::record_work("initial_member_replay_denial_visits", visits);
        if !departed.is_empty() {
            self.apply_initial_replay_page_policy(peer, gid, &departed);
        }
        let replay = self
            .initial_member_replays
            .members
            .get_mut(&peer)
            .expect("live replay");
        replay.denials_done = visits < REGISTRATION_PAGE_SIZE;
        replay.denied = last;
        if self.outbound_channel_full(peer) || !self.complete_initial_member_replay(peer) {
            self.initial_member_replays.ready.push_back(peer);
        }
    }

    fn commit_initial_member_batch(
        &mut self,
        peer: PeerId,
        mut batch: OutboundCommitBatch,
        prior: FastSet<ExactExportKey>,
        shared: Option<SharedUnicastPrecommit<'_>>,
    ) -> bool {
        batch.on_proof_refusal = OnReservationRefusal::StopBeforeSend;
        let commit =
            self.try_send_and_commit_outbound_update_with_group_prior(peer, batch, prior, shared);
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

    /// Stop the scan `peer` read: its place on the scan of `universe`'s
    /// cohort when it `rode` one, else its own scan.
    fn stop_replay_scan(&mut self, peer: PeerId, rode: bool, universe: Option<SnapshotHandle>) {
        if rode {
            self.leave_cohort_scan(universe);
        } else {
            self.loc_rib.stop_member_replay_scan(peer);
        }
    }

    /// Take the next page of keys for `peer` to resolve one by one: from its
    /// own scan, or what its cohort's page leaves to it. `false` when the
    /// cohort's page was sent as shared rows, or the replay recovered.
    fn fill_replay_carry(
        &mut self,
        peer: PeerId,
        gid: usize,
        operation: &mut crate::outbound_credit::OutboundOperation,
    ) -> bool {
        let keys = if self.initial_member_replays.members[&peer].lap.is_some() {
            let Some(keys) = self.take_cohort_page(peer, gid, operation) else {
                return false;
            };
            keys
        } else {
            let page = self.loc_rib.take_member_replay_page(peer);
            #[cfg(test)]
            super::slice_timing::record_work(
                "initial_member_replay_visits",
                page.bucket_visits + page.repairs,
            );
            page.keys
        };
        let replay = self
            .initial_member_replays
            .members
            .get_mut(&peer)
            .expect("live replay");
        replay.carry = keys.into();
        true
    }

    /// Put a member on the scan of the cohort that owns `universe`, starting
    /// the scan with its first rider. The member completes one pass later.
    fn join_cohort_scan(&mut self, universe: SnapshotHandle) -> Lap {
        let replays = &mut self.initial_member_replays;
        let cohort = replays
            .cohorts
            .iter_mut()
            .find(|cohort| cohort.handle == universe)
            .expect("enrolled cohort");
        let scan = if let Some(scan) = cohort.scan {
            scan
        } else {
            let scan = replays.next_scan;
            replays.next_scan = replays.next_scan.wrapping_add(1);
            self.loc_rib.start_cohort_replay_scan(scan);
            cohort.scan = Some(scan);
            scan
        };
        cohort.riders += 1;
        Lap {
            end: self.loc_rib.cohort_replay_lap_end(scan),
            seq: cohort.base + cohort.log.len() as u64,
        }
    }

    /// A rider of `universe`'s cohort left its scan. The last one stops the
    /// scan and drops its log; otherwise the log gives up the pages only
    /// that rider still needed.
    ///
    /// Either way the pages are dropped in this turn, up to
    /// [`COHORT_LOG_PAGES`] of them with their resolved rows. That drop is
    /// not paced. If it shows in a poll, the replacement is to move the
    /// pages to a list that each replay turn drops one page from.
    fn leave_cohort_scan(&mut self, universe: Option<SnapshotHandle>) {
        let cohorts = &mut self.initial_member_replays.cohorts;
        let Some(index) = cohorts
            .iter()
            .position(|cohort| Some(cohort.handle) == universe)
        else {
            return;
        };
        let cohort = &mut cohorts[index];
        cohort.riders = cohort.riders.saturating_sub(1);
        if cohort.riders == 0 {
            if let Some(scan) = cohort.scan.take() {
                self.loc_rib.stop_cohort_replay_scan(scan);
            }
            cohort.log.clear();
            cohort.base = 0;
            // No page of this table is left to keep current.
            let gid = cohort.key.0;
            if !cohorts
                .iter()
                .any(|cohort| cohort.key.0 == gid && cohort.scan.is_some())
                && let Some(group) = self.group_ribs.get_mut(&gid)
            {
                group.cohort_writes = None;
            }
        } else {
            self.trim_cohort_log(index);
        }
    }

    /// The riders of cohort `index` with the log page each works through next.
    fn cohort_riders(&self, index: usize) -> impl Iterator<Item = (PeerId, u64)> + '_ {
        let replays = &self.initial_member_replays;
        let cohort = &replays.cohorts[index];
        cohort.enrolled.iter().filter_map(|peer| {
            let replay = replays.members.get(peer)?;
            (replay.universe == Some(cohort.handle)).then_some((*peer, replay.lap?.seq))
        })
    }

    /// Drop the log pages every rider has worked through, in this turn (see
    /// [`Self::leave_cohort_scan`] for the limit).
    fn trim_cohort_log(&mut self, index: usize) {
        let oldest = self.cohort_riders(index).map(|(_, seq)| seq).min();
        let cohort = &mut self.initial_member_replays.cohorts[index];
        while oldest.is_none_or(|oldest| cohort.base < oldest) && cohort.log.pop_front().is_some() {
            cohort.base += 1;
        }
    }

    /// A rider's cohort, its scan and its place on it.
    fn ride(&self, peer: PeerId) -> Option<(usize, u32, Lap)> {
        let replays = &self.initial_member_replays;
        let replay = replays.members.get(&peer)?;
        let lap = replay.lap?;
        let index = replays
            .cohorts
            .iter()
            .position(|cohort| Some(cohort.handle) == replay.universe)?;
        Some((index, replays.cohorts[index].scan?, lap))
    }

    /// The state of the scan `peer` reads: its own, or its cohort's as the
    /// member sees it. A rider is ready once the scan has passed every
    /// bucket since it joined, it has worked through the whole log, and no
    /// changed key waits for a page.
    fn replay_scan_status(&self, peer: PeerId) -> RegistrationScanStatus {
        let replays = &self.initial_member_replays;
        if replays.members[&peer].lap.is_none() {
            return self.loc_rib.member_replay_scan_status(peer);
        }
        let Some((index, scan, lap)) = self.ride(peer) else {
            // The cohort is gone: the member reconciles on its own.
            return RegistrationScanStatus::Overflow;
        };
        let cohort = &replays.cohorts[index];
        if self.loc_rib.cohort_replay_overflowed(scan) {
            RegistrationScanStatus::Overflow
        } else if lap.seq == cohort.base + cohort.log.len() as u64
            && !self.loc_rib.cohort_replay_repairs_pending(scan)
            && self.loc_rib.cohort_replay_lap_reached(scan, lap.end)
        {
            RegistrationScanStatus::Ready
        } else {
            RegistrationScanStatus::Scanning
        }
    }

    /// Queue a repair at `prefix` on the scan `peer` reads. `false` once
    /// that scan's repair log has overflowed.
    pub(super) fn record_replay_scan_change(&mut self, peer: PeerId, prefix: Prefix) -> bool {
        if self.initial_member_replays.members[&peer].lap.is_none() {
            return self.loc_rib.record_member_replay_change(peer, prefix);
        }
        self.ride(peer)
            .is_some_and(|(_, scan, _)| self.loc_rib.record_cohort_replay_change(scan, prefix))
    }

    /// Whether the scan `peer` reads holds a queued repair at `prefix`.
    pub(super) fn replay_scan_change_recorded(&self, peer: PeerId, prefix: Prefix) -> bool {
        if self.initial_member_replays.members[&peer].lap.is_none() {
            return self.loc_rib.member_replay_change_recorded(peer, prefix);
        }
        self.ride(peer)
            .is_some_and(|(_, scan, _)| self.loc_rib.cohort_replay_change_recorded(scan, prefix))
    }

    pub(super) fn replay_scan_overflowed(&self, peer: PeerId) -> bool {
        self.replay_scan_status(peer) == RegistrationScanStatus::Overflow
    }

    /// The cohort scans `targets` ride.
    pub(in crate::manager) fn cohort_scans_of(&self, targets: &HashSet<PeerId>) -> Vec<u32> {
        let mut scans: Vec<u32> = targets
            .iter()
            .filter_map(|peer| Some(self.ride(*peer)?.1))
            .collect();
        scans.sort_unstable();
        scans.dedup();
        scans
    }

    /// The riders of each live cohort scan and the pages its log holds.
    #[cfg(test)]
    pub(super) fn cohort_scan_riders(&self) -> Vec<(usize, usize)> {
        let cohorts = &self.initial_member_replays.cohorts;
        cohorts
            .iter()
            .filter(|cohort| cohort.scan.is_some())
            .map(|cohort| (cohort.riders, cohort.log.len()))
            .collect()
    }

    /// Whether `peer` rides its cohort's scan.
    #[cfg(test)]
    pub(super) fn rides_cohort_scan(&self, peer: PeerId) -> bool {
        self.ride(peer).is_some()
    }

    /// Advance rider `peer` to its next log page, taking one from the
    /// cohort's scan when it has worked through the log. Returns the
    /// cohort, its scan and the page's sequence number, or `None` when the
    /// scan had no keys for it this turn.
    fn next_cohort_page(&mut self, peer: PeerId) -> Option<(usize, u32, u64)> {
        let (index, scan, lap) = self.ride(peer).expect("rider");
        let cohort = &self.initial_member_replays.cohorts[index];
        if lap.seq == cohort.base + cohort.log.len() as u64 {
            #[cfg(test)]
            let depth = self
                .initial_member_replays
                .cohort_log_pages
                .unwrap_or(COHORT_LOG_PAGES);
            #[cfg(not(test))]
            let depth = COHORT_LOG_PAGES;
            if cohort.log.len() >= depth {
                self.evict_cohort_laggards(index);
            }
            // A member that has seen every bucket takes only repairs: the
            // rest of the pass belongs to riders that joined later.
            let discover = !self.loc_rib.cohort_replay_lap_reached(scan, lap.end);
            let page = self.loc_rib.take_cohort_replay_page(scan, discover);
            #[cfg(test)]
            {
                let visits = page.bucket_visits + page.repairs;
                super::slice_timing::record_work("initial_member_replay_visits", visits);
                super::slice_timing::record_work("cohort_scan_pages", 1);
            }
            if page.keys.is_empty() {
                return None;
            }
            self.initial_member_replays.cohorts[index]
                .log
                .push_back(LogPage {
                    keys: page.keys,
                    shared: None,
                });
        }
        let replay = self
            .initial_member_replays
            .members
            .get_mut(&peer)
            .expect("live replay");
        replay.lap.as_mut().expect("rider").seq += 1;
        Some((index, scan, lap.seq))
    }

    /// Rider `peer`'s next page of its cohort's log. A page whose keys the
    /// member holds none of goes out as the rows the cohort resolved once,
    /// and `None` is returned: the page is sent, or the replay recovered.
    /// Otherwise the keys the member must resolve one by one are returned:
    /// all of them when it holds some, none when it holds every one.
    fn take_cohort_page(
        &mut self,
        peer: PeerId,
        gid: usize,
        operation: &mut crate::outbound_credit::OutboundOperation,
    ) -> Option<Vec<Prefix>> {
        let Some((index, _, seq)) = self.next_cohort_page(peer) else {
            return Some(Vec::new());
        };
        let replays = &mut self.initial_member_replays;
        let cohort = &mut replays.cohorts[index];
        let at = usize::try_from(seq - cohort.base).expect("log index");
        // A key with a change the member has not settled reconciles against
        // its own admission.
        if replays.members[&peer].changes.touches(&cohort.log[at].keys) {
            let keys = cohort.log[at].keys.clone();
            self.trim_cohort_log(index);
            return Some(keys);
        }
        let page = &mut cohort.log[at];
        if page.shared.is_none() {
            page.shared = Some(SharedPage {
                positions: self
                    .pending_group_admitted
                    .replay_universe_positions(cohort.handle, page.keys.iter().copied()),
                prefixes: Arc::new(page.keys.iter().copied().collect()),
                rows: None,
            });
        }
        let page = &self.initial_member_replays.cohorts[index].log[at];
        let shared = page.shared.as_ref().expect("resolved above");
        let held = self.pending_group_admitted.get(&peer).map(|admitted| {
            admitted.admitted_unicast(
                shared
                    .positions
                    .iter()
                    .copied()
                    .zip(page.keys.iter().copied()),
            )
        });
        if held == Some(page.keys.len()) {
            // A second pass over keys the member already holds, with no
            // change of its own to settle: nothing to send.
            #[cfg(test)]
            super::slice_timing::record_work("cohort_held_pages", 1);
            self.trim_cohort_log(index);
            return Some(Vec::new());
        }
        if held != Some(0) {
            // The member holds some of these keys, from a repair or an
            // earlier pass: each key reconciles against its admission.
            let keys = page.keys.clone();
            self.trim_cohort_log(index);
            return Some(keys);
        }
        self.send_shared_page(peer, gid, (index, at, seq), operation);
        None
    }

    /// Send rider `peer` the rows its cohort resolved for the log page at
    /// `at` (sequence `seq`) of cohort `index`, none of whose keys it holds,
    /// and leave it the keys only it can resolve.
    fn send_shared_page(
        &mut self,
        peer: PeerId,
        gid: usize,
        (index, at, seq): (usize, usize, u64),
        operation: &mut crate::outbound_credit::OutboundOperation,
    ) {
        self.settle_cohort_writes(gid);
        if self.initial_member_replays.cohorts[index].log[at]
            .shared
            .as_ref()
            .is_some_and(|shared| shared.rows.is_none())
        {
            let rows = self.resolve_cohort_rows(gid, index, at);
            let page = &mut self.initial_member_replays.cohorts[index].log[at];
            page.shared.as_mut().expect("resolved page").rows = Some(rows);
        }
        let page = &mut self.initial_member_replays.cohorts[index].log[at];
        let shared = page.shared.as_mut().expect("resolved page");
        let prefixes = Arc::clone(&shared.prefixes);
        let rows = shared.rows.as_mut().expect("resolved rows");
        let routes = Arc::clone(&rows.routes);
        let actions = Arc::clone(&rows.actions);
        let encode = Arc::clone(&rows.encode);
        let mut probes = std::mem::take(&mut rows.probes);
        let mut carry = rows.private.clone();
        // Where the member sourced the winner, a per-client-best group
        // serves it the runner-up, which only the member's own slot names.
        if self.group_ribs[&gid].per_client_best {
            carry.extend(
                routes
                    .iter()
                    .filter(|route| route.peer == peer)
                    .map(|route| route.prefix),
            );
        }
        #[cfg(test)]
        {
            super::slice_timing::record_work("initial_member_replay_units", routes.len());
            super::slice_timing::record_work("cohort_shared_rows", routes.len());
        }
        // A page whose every row the member sourced would be an envelope
        // that carries nothing once transport drops them.
        if routes.iter().any(|route| route.peer != peer) {
            let batch = OutboundCommitBatch {
                slot: operation.slot(),
                force_unicast_replay: true,
                unicast_otc_prechecked: true,
                // Transport drops the rows this member sourced.
                announce_source_exclusion: Some(peer),
                shared_group_encode: Some(Arc::clone(&encode)),
                ..OutboundCommitBatch::with_unicast(routes, actions)
            };
            let precommit = SharedUnicastPrecommit {
                group_id: gid,
                probe_cache: &mut probes,
                // The member holds none of these keys.
                lazy_group_prior: Some(LazyCleanGroupPrior { peer, deltas: &[] }),
            };
            let sent =
                self.commit_initial_member_batch(peer, batch, FastSet::default(), Some(precommit));
            // The page keeps the first member's probes for the others.
            if let Some((index, ..)) = self.ride(peer)
                && let cohort = &mut self.initial_member_replays.cohorts[index]
                && let Some(page) = seq
                    .checked_sub(cohort.base)
                    .and_then(|at| cohort.log.get_mut(usize::try_from(at).ok()?))
                && let Some(shared) = &mut page.shared
                && let Some(rows) = &mut shared.rows
                && Arc::ptr_eq(&rows.encode, &encode)
            {
                rows.probes = probes;
            }
            if !sent {
                return;
            }
        }
        self.trim_cohort_log(index);
        self.apply_initial_replay_page_policy(peer, gid, &prefixes);
        let replay = self
            .initial_member_replays
            .members
            .get_mut(&peer)
            .expect("live replay");
        replay.carry = carry.into();
        if self.outbound_channel_full(peer) || !self.complete_initial_member_replay(peer) {
            self.initial_member_replays.ready.push_back(peer);
        }
    }

    /// Drop the resolved rows of every log page that holds a key written
    /// to group `gid`'s table since the last look, and keep listening. Only
    /// those pages are resolved again; a burst of more keys than the
    /// table's write list holds drops the rows of every page.
    fn settle_cohort_writes(&mut self, gid: usize) {
        let Some(group) = self.group_ribs.get_mut(&gid) else {
            return;
        };
        let writes = group.cohort_writes.get_or_insert_default();
        if writes.keys.is_empty() {
            return;
        }
        let every = std::mem::take(&mut writes.overflow);
        let keys = std::mem::take(&mut writes.keys);
        let cohorts = &mut self.initial_member_replays.cohorts;
        for cohort in cohorts.iter_mut().filter(|cohort| cohort.key.0 == gid) {
            for shared in cohort
                .log
                .iter_mut()
                .filter_map(|page| page.shared.as_mut())
            {
                if shared.rows.is_some()
                    && (every || keys.iter().any(|key| shared.prefixes.contains(key)))
                {
                    shared.rows = None;
                }
            }
        }
    }

    /// Resolve the rows every rider shares at log page `at` of cohort
    /// `index`: one winner per key, whatever the riders.
    fn resolve_cohort_rows(&self, gid: usize, index: usize, at: usize) -> SharedRows {
        use super::distribution::rs_control::rs_control_route_tagged;

        let cohort = &self.initial_member_replays.cohorts[index];
        let keys = &cohort.log[at].keys;
        let view = cohort.key.2;
        let group = &self.group_ribs[&gid];
        let mut routes = Vec::with_capacity(keys.len());
        let mut actions = Vec::with_capacity(keys.len());
        let mut private = Vec::new();
        for prefix in keys {
            let Some(entry) = group.replay_winner(prefix) else {
                continue;
            };
            // RFC 7947 decides on the source's control communities and
            // scrubs the post-policy route's. A winner that carries neither
            // for the view's RS ASN is the same row toward every member.
            let tagged = view.is_some_and(|rs_asn| {
                let (communities, large) =
                    group.source_control_for_route(entry.route, entry.source_attrs);
                rs_control_route_tagged(communities, large, rs_asn)
                    || rs_control_route_tagged(
                        entry.route.communities(),
                        entry.route.large_communities(),
                        rs_asn,
                    )
            });
            if tagged {
                private.push(*prefix);
            } else {
                routes.push(entry.route.clone());
                actions.push(entry.nh.cloned());
            }
        }
        #[cfg(test)]
        super::slice_timing::record_work("cohort_page_resolves", keys.len());
        SharedRows {
            routes: routes.into(),
            actions: actions.into(),
            private,
            encode: Arc::default(),
            probes: SharedUnicastProbeCache::default(),
        }
    }

    /// The log of cohort `index` is full: the riders still at its oldest
    /// page leave the scan, each into a reconcile of its own, so the scan
    /// can take its next page. No rider waits for another's writer longer
    /// than the log is deep.
    fn evict_cohort_laggards(&mut self, index: usize) {
        let base = self.initial_member_replays.cohorts[index].base;
        let laggards: Vec<PeerId> = self
            .cohort_riders(index)
            .filter(|(_, seq)| *seq == base)
            .map(|(peer, _)| peer)
            .collect();
        for peer in laggards {
            #[cfg(test)]
            super::slice_timing::record_work("cohort_scan_evictions", 1);
            self.recover_initial_member_replay(peer, PacedFallbackCause::CohortLag);
        }
    }
}
