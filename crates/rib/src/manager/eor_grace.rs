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
//! replay finished, so the window closes the observed gap only when replay
//! completes before the deadline.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::Duration;

use rustbgpd_wire::{Afi, Safi};
use tracing::info;

use super::RibManager;

/// One configured peer's grace window, resolved at daemon start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EorGracePeerConfig {
    /// Static peer address.
    pub peer: IpAddr,
    /// Time from process start until held End-of-RIB is released. Already
    /// clamped to the remaining restarting-speaker (marker) window.
    pub window: Duration,
    /// Families covered by the restart (the Graceful Restart families this
    /// daemon advertises to the peer).
    pub families: Vec<(Afi, Safi)>,
}

/// Process-start End-of-RIB grace configuration. Only a valid planned
/// (marker-backed) restart builds one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EorGraceConfig {
    /// Peers with a non-zero window.
    pub peers: Vec<EorGracePeerConfig>,
}

/// One configured peer's held families. Its deadline lives in
/// `RibManager::eor_grace_deadlines`, whose cached minimum keeps the
/// per-turn timer probe O(1).
#[derive(Debug)]
pub(super) struct EorGracePeer {
    window: Duration,
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
            if entry.window.is_zero() || entry.families.is_empty() {
                continue;
            }
            let candidate = EorGracePeer {
                window: entry.window,
                families: entry.families.into_iter().collect(),
                helper_session: false,
            };
            // Address-only RIB identity cannot tell scoped duplicates apart;
            // the shorter window is the conservative choice.
            match peers.get(&entry.peer) {
                Some(existing) if existing.window <= candidate.window => {}
                _ => {
                    deadlines.insert(entry.peer, now + entry.window);
                    peers.insert(entry.peer, candidate);
                }
            }
        }
        for (peer, grace) in &peers {
            info!(
                %peer,
                window_secs = grace.window.as_secs(),
                "planned restart: holding End-of-RIB toward this Graceful Restart helper until the grace window ends"
            );
        }
        self.eor_grace = peers;
        self.eor_grace_deadlines = deadlines;
        self
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

    /// Release every window whose deadline passed. The release is
    /// timer-driven only: it does not know whether controller replay
    /// finished, and the log says so.
    pub(super) fn expire_eor_grace(&mut self) {
        let now = tokio::time::Instant::now();
        let expired: Vec<IpAddr> = self
            .eor_grace_deadlines
            .iter()
            .filter(|&(_, &deadline)| deadline <= now)
            .map(|(&peer, _)| peer)
            .collect();
        for peer in expired {
            self.eor_grace_deadlines.remove(&peer);
            let Some(grace) = self.eor_grace.remove(&peer) else {
                continue;
            };
            let mut held: Vec<String> = self
                .pending_eor
                .get(&peer)
                .into_iter()
                .flatten()
                .filter(|family| grace.helper_session && grace.families.contains(family))
                .map(|&(afi, safi)| super::helpers::afi_safi_label(afi, safi).to_string())
                .collect();
            held.sort_unstable();
            self.metrics.record_gr_eor_grace_expired(&peer.to_string());
            info!(
                %peer,
                window_secs = grace.window.as_secs(),
                helper_session = grace.helper_session,
                held_families = %held.join(","),
                "End-of-RIB grace window ended at its deadline; releasing held End-of-RIB. \
                 Controller replay completion is not verified: a route not re-injected by now \
                 is removed by the helper at this End-of-RIB"
            );
            if !self.dirty_peers.contains(&peer) {
                self.flush_pending_eor(peer);
            }
        }
    }
}
