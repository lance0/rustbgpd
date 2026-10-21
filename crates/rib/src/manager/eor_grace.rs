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

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::IpAddr;

use rustbgpd_telemetry::reason_labels::GrEorGraceReleaseReason;
use rustbgpd_wire::{Afi, Safi};
use tracing::{info, warn};

use super::RibManager;
use crate::injection_lease::LeaseConflict;
use crate::update::RibCommandError;

/// One configured peer's grace window, resolved at daemon start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EorGracePeerConfig {
    /// Static peer address.
    pub peer: IpAddr,
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

/// The listed replay controllers and the ones that have signalled.
#[derive(Debug, Default)]
pub(super) struct ReplayWait {
    expected: BTreeSet<String>,
    signalled: BTreeSet<String>,
}

impl ReplayWait {
    fn awaiting(&self) -> Vec<String> {
        self.expected.difference(&self.signalled).cloned().collect()
    }
}

/// One configured peer's held families. Its deadline lives in
/// `RibManager::eor_grace_deadlines`, whose cached minimum keeps the
/// per-turn timer probe O(1).
#[derive(Debug)]
pub(super) struct EorGracePeer {
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
        let mut peers: HashMap<IpAddr, EorGracePeer> = HashMap::new();
        let mut deadlines = super::graceful_restart::DeadlineMap::default();
        for entry in config.peers {
            if entry.families.is_empty() {
                continue;
            }
            // Address-only RIB identity cannot tell scoped duplicates apart;
            // the earlier deadline is the conservative choice.
            if deadlines
                .get(&entry.peer)
                .is_some_and(|existing| *existing <= entry.deadline)
            {
                continue;
            }
            deadlines.insert(entry.peer, entry.deadline);
            peers.insert(
                entry.peer,
                EorGracePeer {
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
            signalled: BTreeSet::new(),
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
        // A window whose deadline has passed is over even before its expiry
        // turn runs: the run loop drains the backlog captured at the
        // deadline first, and a signal in that backlog must not claim the
        // release. The expiry turn counts it as `deadline` and names the
        // controllers that had not signalled by then.
        let now = tokio::time::Instant::now();
        let holding: Vec<IpAddr> = self
            .eor_grace_deadlines
            .iter()
            .filter(|&(_, &deadline)| deadline > now)
            .map(|(&peer, _)| peer)
            .collect();
        if holding.is_empty() {
            info!(owner = %owner, "replay-complete signal: no End-of-RIB is held");
            return Ok(ReplayComplete::NotHolding);
        }
        self.eor_replay.signalled.insert(owner.to_string());
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
                self.release_eor_grace_peer(peer, GrEorGraceReleaseReason::ReplayComplete);
            info!(
                %peer,
                owner = %owner,
                helper_session,
                held_families = %held,
                "every listed controller signalled replay complete; releasing held End-of-RIB"
            );
        }
        Ok(ReplayComplete::Released)
    }

    /// End `peer`'s window: count the release and emit its held markers.
    /// A dirty peer keeps them pending for its resync, after the routes it
    /// replays. Returns the session's helper flag and the held families.
    fn release_eor_grace_peer(
        &mut self,
        peer: IpAddr,
        reason: GrEorGraceReleaseReason,
    ) -> (bool, String) {
        self.eor_grace_deadlines.remove(&peer);
        let Some(grace) = self.eor_grace.remove(&peer) else {
            return (false, String::new());
        };
        let mut held: Vec<&str> = self
            .pending_eor
            .get(&peer)
            .into_iter()
            .flatten()
            .filter(|family| grace.helper_session && grace.families.contains(family))
            .map(|&(afi, safi)| super::helpers::afi_safi_label(afi, safi))
            .collect();
        held.sort_unstable();
        let held = held.join(",");
        self.metrics
            .record_gr_eor_grace_released(&peer.to_string(), reason);
        if !self.dirty_peers.contains(&peer) {
            self.flush_pending_eor(peer);
        }
        (grace.helper_session, held)
    }

    /// Whether the grace window holds `family`'s End-of-RIB toward `peer`.
    pub(super) fn eor_grace_held(&self, peer: IpAddr, family: (Afi, Safi)) -> bool {
        self.eor_grace
            .get(&peer)
            .is_some_and(|grace| grace.helper_session && grace.families.contains(&family))
    }

    /// Classify a newly registered session. The deadline never moves.
    pub(super) fn eor_grace_classify_session(
        &mut self,
        peer: IpAddr,
        peer_gr_helper: bool,
        peer_restart_state: bool,
    ) {
        if let Some(grace) = self.eor_grace.get_mut(&peer) {
            grace.helper_session = peer_gr_helper && !peer_restart_state;
        }
    }

    /// A deleted peer has no future session to hold for.
    pub(super) fn eor_grace_peer_deleted(&mut self, peer: IpAddr) {
        self.eor_grace.remove(&peer);
        self.eor_grace_deadlines.remove(&peer);
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
        let expired: Vec<IpAddr> = self
            .eor_grace_deadlines
            .iter()
            .filter(|&(_, &deadline)| deadline <= due)
            .map(|(&peer, _)| peer)
            .collect();
        let now = tokio::time::Instant::now();
        let awaiting = self.eor_replay.awaiting();
        for peer in expired {
            let Some(late_ms) = self.eor_grace_deadlines.get(&peer).map(|deadline| {
                u64::try_from(now.saturating_duration_since(*deadline).as_millis())
                    .unwrap_or(u64::MAX)
            }) else {
                continue;
            };
            let (helper_session, held) =
                self.release_eor_grace_peer(peer, GrEorGraceReleaseReason::Deadline);
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
    }
}
