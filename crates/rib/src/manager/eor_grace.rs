//! Opt-in End-of-RIB grace window after a marker-backed planned restart.
//!
//! RFC 4724 §4.1 has the restarting speaker send End-of-RIB once its initial
//! update is complete; a Graceful Restart helper then removes every stale
//! route it still retains from the previous session (§4.2). Routes that an
//! injection controller re-adds only after it notices the restart arrive
//! after that marker, so the helper drops them in between. The grace window
//! keeps each configured peer's End-of-RIB queued until one absolute
//! deadline fixed at process start. Route announcements and withdrawals keep
//! flowing; only the marker waits. A timer does not prove that controller
//! replay finished, so on its own the window closes the observed gap only
//! when replay completes before the deadline.
//!
//! The listed replay controllers (`gr_eor_replay_owners`) close that gap
//! explicitly: each signals `MarkReplayComplete` for the current daemon
//! incarnation after its replay, and the held End-of-RIB is released as soon
//! as every listed controller has signalled. The signal travels through the
//! RIB queue behind the controller's injections, so their routes are
//! distributed first. The deadline still wins when a controller stays
//! silent.

use crate::PeerId;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use rustbgpd_telemetry::reason_labels::GrEorGraceReleaseReason;
use rustbgpd_wire::{Afi, Safi};
use tracing::{info, warn};

use super::RibManager;
use crate::injection_lease::LeaseConflict;
use crate::update::RibCommandError;

/// A configured neighbor whose grace window starts before its session exists.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum EorGraceTarget {
    /// An addressed neighbor whose handle is allocated at startup.
    Peer(PeerId),
    /// An interface-only neighbor, before its learned endpoint has a handle.
    Interface(Arc<str>),
}

impl EorGraceTarget {
    fn label(&self) -> String {
        match self {
            Self::Peer(peer) => peer.label(),
            Self::Interface(interface) => rustbgpd_telemetry::interface_peer_label(interface),
        }
    }
}

impl From<PeerId> for EorGraceTarget {
    fn from(peer: PeerId) -> Self {
        Self::Peer(peer)
    }
}

impl fmt::Display for EorGraceTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Peer(peer) => fmt::Display::fmt(peer, f),
            Self::Interface(interface) => write!(f, "interface:{interface}"),
        }
    }
}

/// One configured peer's grace window, resolved at daemon start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EorGracePeerConfig {
    /// Configured neighbor identity, independent of its first binding.
    pub peer: EorGraceTarget,
    /// Absolute release deadline: daemon start plus the configured window,
    /// clamped to the restarting-speaker (marker) window. Counting from
    /// daemon start keeps startup work from stretching the window.
    pub deadline: tokio::time::Instant,
    /// Families covered by the restart (the Graceful Restart families this
    /// daemon advertises to the peer).
    pub families: Vec<(Afi, Safi)>,
}

/// Process-start End-of-RIB grace configuration. Only a valid planned
/// (marker-backed) restart has peers; a cold boot passes none.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EorGraceConfig {
    /// Peers with a non-zero window.
    pub peers: Vec<EorGracePeerConfig>,
    /// Controllers whose replay-complete signals together release every
    /// window early (`gr_eor_replay_owners`). Empty keeps the windows
    /// timer-only.
    pub replay_owners: Vec<String>,
}

/// Result of an accepted replay-complete signal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayComplete {
    /// The owner was the last one awaited; the held End-of-RIB was released.
    Released,
    /// Recorded; these listed owners have not signalled yet (sorted).
    Recorded {
        /// Owners still awaited.
        awaiting: Vec<String>,
    },
    /// The owner is not listed. Nothing changed.
    NotExpected,
    /// No End-of-RIB is held (cold boot, no window, or the window ended).
    /// Nothing changed.
    NotHolding,
}

/// The listed replay controllers and when each first signalled.
#[derive(Debug, Default)]
pub(super) struct ReplayWait {
    expected: BTreeSet<String>,
    signalled: BTreeMap<String, tokio::time::Instant>,
}

impl ReplayWait {
    pub(super) fn awaiting(&self) -> Vec<String> {
        self.awaiting_at(None)
    }

    /// Listed owners that had not signalled before `deadline` (or at all):
    /// a window is over at its deadline.
    fn awaiting_at(&self, deadline: Option<tokio::time::Instant>) -> Vec<String> {
        self.expected
            .iter()
            .filter(|owner| {
                self.signalled
                    .get(*owner)
                    .is_none_or(|at| deadline.is_some_and(|deadline| *at >= deadline))
            })
            .cloned()
            .collect()
    }
}

/// One configured peer's held families. Its deadline lives in
/// `RibManager::eor_grace_deadlines`, whose cached minimum keeps the
/// per-turn timer probe O(1).
#[derive(Debug)]
pub(super) struct EorGracePeer {
    peer: Option<PeerId>,
    families: HashSet<(Afi, Safi)>,
    /// The current session negotiated helper retention: the peer advertised
    /// a Graceful Restart capability (a helper-only capability lists no
    /// family) and did not itself set Restart State. Set per session at
    /// registration, so a reconnect re-evaluates it but keeps the deadline.
    helper_session: bool,
}

impl RibManager {
    /// Install the startup grace windows before the actor starts.
    #[must_use]
    pub fn with_eor_grace(mut self, config: EorGraceConfig) -> Self {
        let now = tokio::time::Instant::now();
        let mut peers: HashMap<EorGraceTarget, EorGracePeer> = HashMap::new();
        let mut deadlines = super::graceful_restart::DeadlineMap::default();
        for entry in config.peers {
            if entry.families.is_empty() {
                continue;
            }
            // Duplicate startup entries must not extend an existing window.
            if deadlines
                .get(&entry.peer)
                .is_some_and(|existing| *existing <= entry.deadline)
            {
                continue;
            }
            deadlines.insert(entry.peer.clone(), entry.deadline);
            let peer = match &entry.peer {
                EorGraceTarget::Peer(peer) => Some(*peer),
                EorGraceTarget::Interface(_) => None,
            };
            peers.insert(
                entry.peer,
                EorGracePeer {
                    peer,
                    families: entry.families.into_iter().collect(),
                    helper_session: false,
                },
            );
        }
        for (peer, deadline) in &deadlines {
            info!(
                %peer,
                remaining_ms = u64::try_from(deadline.saturating_duration_since(now).as_millis())
                    .unwrap_or(u64::MAX),
                "planned restart: holding End-of-RIB toward this Graceful Restart helper until the grace window ends"
            );
        }
        self.eor_grace = peers;
        self.eor_grace_deadlines = deadlines;
        self.eor_replay = ReplayWait {
            expected: config.replay_owners.into_iter().collect(),
            signalled: BTreeMap::new(),
        };
        if !self.eor_grace.is_empty() && !self.eor_replay.expected.is_empty() {
            info!(
                awaiting = %self.eor_replay.awaiting().join(","),
                "planned restart: a replay-complete signal from every listed controller releases the held End-of-RIB before the deadline"
            );
        }
        self
    }

    /// Apply a controller's replay-complete signal. A stale incarnation is
    /// refused without changing anything: the controller replayed into an
    /// earlier process and must read the incarnation and replay again.
    pub(super) fn mark_replay_complete(
        &mut self,
        owner: &str,
        incarnation: u64,
    ) -> Result<ReplayComplete, RibCommandError> {
        let current = self.injection_leases.incarnation();
        if incarnation != current {
            warn!(
                owner = %owner,
                incarnation,
                current,
                "replay-complete signal refused: it names another daemon incarnation"
            );
            return Err(RibCommandError::FailedPrecondition(
                LeaseConflict::IncarnationMismatch,
                format!(
                    "incarnation {incarnation} is not this daemon's ({current}): the daemon \
                     restarted, so read the incarnation and replay again"
                ),
            ));
        }
        if !self.eor_replay.expected.contains(owner) {
            warn!(
                owner = %owner,
                "replay-complete signal from a controller not listed in gr_eor_replay_owners; ignored"
            );
            return Ok(ReplayComplete::NotExpected);
        }
        // Replay completion is a fact about this incarnation, so it is
        // recorded even when nothing is held. Windows exist per configured
        // peer from daemon start, whether or not a session is up, so a
        // release below covers peers that establish later too: their initial
        // dump then ends in End-of-RIB at once.
        let now = tokio::time::Instant::now();
        self.eor_replay
            .signalled
            .entry(owner.to_string())
            .or_insert(now);
        // A window whose deadline has passed is over even before its expiry
        // turn runs: the run loop drains the backlog captured at the
        // deadline first, and a signal in that backlog must not claim the
        // release. The expiry turn counts it as `deadline` and names the
        // controllers that had not signalled by that window's deadline.
        let holding: Vec<EorGraceTarget> = self
            .eor_grace_deadlines
            .iter()
            .filter(|&(_, &deadline)| deadline > now)
            .map(|(peer, _)| peer.clone())
            .collect();
        if holding.is_empty() {
            info!(owner = %owner, "replay-complete signal: no End-of-RIB is held");
            return Ok(ReplayComplete::NotHolding);
        }
        let awaiting = self.eor_replay.awaiting();
        if !awaiting.is_empty() {
            info!(
                owner = %owner,
                awaiting = %awaiting.join(","),
                "replay-complete signal recorded; still awaiting other controllers"
            );
            return Ok(ReplayComplete::Recorded { awaiting });
        }
        for peer in holding {
            let (helper_session, held) =
                self.release_eor_grace_peer(&peer, GrEorGraceReleaseReason::ReplayComplete);
            info!(
                %peer,
                owner = %owner,
                helper_session,
                held_families = %held,
                "every listed controller signalled replay complete; releasing held End-of-RIB"
            );
        }
        // One retirement for the whole batch: a carry kept for these windows
        // retires once nothing else can hold its peer's End-of-RIB. Each
        // released window already counted as a hold source ending.
        self.retire_helper_stale_exempt();
        Ok(ReplayComplete::Released)
    }

    /// End `peer`'s window: count the release and emit its held markers.
    /// A dirty peer keeps them pending for its resync, after the routes it
    /// replays. Returns the session's helper flag and the held families.
    fn release_eor_grace_peer(
        &mut self,
        target: &EorGraceTarget,
        reason: GrEorGraceReleaseReason,
    ) -> (bool, String) {
        self.eor_grace_deadlines.remove(target);
        let Some(grace) = self.eor_grace.remove(target) else {
            return (false, String::new());
        };
        self.helper_stale_hold_ends = self.helper_stale_hold_ends.saturating_add(1);
        let mut held: Vec<&str> = grace
            .peer
            .and_then(|peer| self.pending_eor.get(&peer))
            .into_iter()
            .flatten()
            .filter(|family| grace.helper_session && grace.families.contains(family))
            .map(|&(afi, safi)| super::helpers::afi_safi_label(afi, safi))
            .collect();
        held.sort_unstable();
        let held = held.join(",");
        self.metrics
            .record_gr_eor_grace_released(&target.label(), reason);
        if let Some(peer) = grace.peer
            && !self.dirty_peers.contains(&peer)
        {
            self.flush_pending_eor(peer);
        }
        (grace.helper_session, held)
    }

    fn eor_grace_target(&self, peer: PeerId) -> EorGraceTarget {
        let addressed = EorGraceTarget::Peer(peer);
        if self.eor_grace.contains_key(&addressed) {
            return addressed;
        }
        peer.interface()
            .map(EorGraceTarget::Interface)
            .filter(|target| self.eor_grace.contains_key(target))
            .unwrap_or(addressed)
    }

    /// Whether a grace window is still open for `peer`, covering `family`
    /// when one is given: our End-of-RIB toward it may be held by grace.
    pub(super) fn eor_grace_covers(&self, peer: PeerId, family: Option<(Afi, Safi)>) -> bool {
        if self.eor_grace.is_empty() {
            return false;
        }
        self.eor_grace
            .get(&self.eor_grace_target(peer))
            .is_some_and(|grace| family.is_none_or(|family| grace.families.contains(&family)))
    }

    /// Whether any grace window is still open.
    pub(super) fn eor_grace_open(&self) -> bool {
        !self.eor_grace.is_empty()
    }

    /// Whether the grace window holds `family`'s End-of-RIB toward `peer`.
    pub(super) fn eor_grace_held(&self, peer: PeerId, family: (Afi, Safi)) -> bool {
        self.eor_grace
            .get(&self.eor_grace_target(peer))
            .is_some_and(|grace| grace.helper_session && grace.families.contains(&family))
    }

    /// Classify a newly registered session. The deadline never moves.
    pub(super) fn eor_grace_classify_session(
        &mut self,
        peer: PeerId,
        peer_gr_helper: bool,
        peer_restart_state: bool,
    ) {
        let target = self.eor_grace_target(peer);
        if let Some(grace) = self.eor_grace.get_mut(&target) {
            grace.peer = Some(peer);
            grace.helper_session = peer_gr_helper && !peer_restart_state;
        }
    }

    /// Binding retirement keeps the interface's startup window; final
    /// neighbor deletion ends it.
    pub(super) fn eor_grace_peer_deleted(&mut self, peer: PeerId, keep_series: bool) {
        let target = self.eor_grace_target(peer);
        if keep_series && matches!(target, EorGraceTarget::Interface(_)) {
            if let Some(grace) = self.eor_grace.get_mut(&target) {
                grace.peer = None;
                grace.helper_session = false;
            }
            return;
        }
        self.eor_grace_deadlines.remove(&target);
        if self.eor_grace.remove(&target).is_some() {
            self.request_helper_stale_retire();
        }
    }

    pub(super) fn retire_eor_grace_interface(&mut self, interface: Arc<str>) {
        let target = EorGraceTarget::Interface(interface);
        self.eor_grace_deadlines.remove(&target);
        if self.eor_grace.remove(&target).is_some() {
            self.request_helper_stale_retire();
        }
    }

    pub(super) fn next_eor_grace_deadline(&mut self) -> Option<tokio::time::Instant> {
        self.eor_grace_deadlines.min()
    }

    /// Release the windows whose deadline is at or before `due`, the
    /// deadline the shared hold timer fired for. The run loop drained only
    /// the work queued when that deadline fell due, so a later window must
    /// not ride along even if it has passed by now: a replay queued between
    /// the two deadlines would land behind its End-of-RIB. The release is
    /// timer-driven only: it does not know whether controller replay
    /// finished, and the log says so.
    pub(super) fn expire_eor_grace(&mut self, due: tokio::time::Instant) {
        let expired: Vec<EorGraceTarget> = self
            .eor_grace_deadlines
            .iter()
            .filter(|&(_, &deadline)| deadline <= due)
            .map(|(peer, _)| peer.clone())
            .collect();
        let now = tokio::time::Instant::now();
        for peer in expired {
            let Some(&deadline) = self.eor_grace_deadlines.get(&peer) else {
                continue;
            };
            let late_ms = u64::try_from(now.saturating_duration_since(deadline).as_millis())
                .unwrap_or(u64::MAX);
            // A controller that signalled only after this window's deadline,
            // while a longer window was still open, missed this one.
            let awaiting = self.eor_replay.awaiting_at(Some(deadline));
            let (helper_session, held) =
                self.release_eor_grace_peer(&peer, GrEorGraceReleaseReason::Deadline);
            if awaiting.is_empty() {
                info!(
                    %peer,
                    late_ms,
                    helper_session,
                    held_families = %held,
                    "End-of-RIB grace window ended at its deadline; releasing held End-of-RIB. \
                     Controller replay completion is not verified: a route not re-injected by now \
                     is removed by the helper at this End-of-RIB"
                );
            } else {
                warn!(
                    %peer,
                    late_ms,
                    helper_session,
                    held_families = %held,
                    awaiting = %awaiting.join(","),
                    "End-of-RIB grace window ended at its deadline before every listed controller \
                     signalled replay complete; releasing held End-of-RIB. A route the awaited \
                     controllers have not re-injected is removed by the helper at this End-of-RIB"
                );
            }
        }
        // One retirement for every window this deadline released; each
        // counted as a hold source ending, so a shared-timer deadline that
        // released none (an RTC or ORF hold) costs nothing here.
        self.retire_helper_stale_exempt();
    }
}
