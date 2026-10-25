//! Per-message actor turn timing (`bgp_rib_actor_turn_duration_seconds`) and
//! the rate-limited slow-turn warning.
//!
//! A turn is one call of [`RibManager::handle_update`]: the synchronous
//! handling of one inbound message. It cannot yield, so it is always inside
//! one actor poll; readiness queries answered at checkpoints within it are
//! part of its wall-clock time. Work the message only queues (route chunks,
//! distribution windows, policy-transition polls, timers) runs in later loop
//! iterations and is timed by `bgp_rib_actor_work_duration_seconds` instead.

use std::time::{Duration, Instant};

use rustbgpd_telemetry::metrics::RibActorTurnKind;
use tracing::warn;

use super::RibManager;
use crate::PeerId;
use crate::adj_rib_in::AdjRibIn;
use crate::update::RibUpdate;

/// A turn at or above this logs a slow-turn WARN. It equals the 200 ms core
/// readiness deadline (`CORE_READINESS_DEADLINE` in `rustbgpd-api`, which
/// depends on this crate) and the `le="0.2"` edge of the actor histograms:
/// a message from any peer queued behind such a turn can wait a whole
/// readiness deadline. `FLUSH_POLL_BUDGET` (25 ms) is a pacing target that
/// single bulk messages legitimately exceed, so it would warn constantly.
pub(super) const SLOW_ACTOR_TURN: Duration = Duration::from_millis(200);

/// Minimum spacing between slow-turn WARN lines. The histogram counts every
/// slow turn; the log names one example and how many were suppressed.
pub(super) const SLOW_ACTOR_TURN_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// The kind and cheap size fields of one turn, captured before the message
/// is consumed.
#[derive(Clone, Copy)]
pub(super) struct ActorTurn {
    kind: RibActorTurnKind,
    peer: Option<PeerId>,
    routes: Option<usize>,
    members: Option<usize>,
}

impl ActorTurn {
    pub(super) fn new(
        update: &RibUpdate,
        ribs: &std::collections::HashMap<PeerId, AdjRibIn>,
    ) -> Self {
        let (routes, members) = match update {
            RibUpdate::WireRoutesReceived(batch) => (
                Some(
                    batch.announced.len()
                        + batch.withdrawn.len()
                        + batch.flowspec_announced.len()
                        + batch.flowspec_withdrawn.len()
                        + batch.evpn_announced.len()
                        + batch.evpn_withdrawn.len(),
                ),
                None,
            ),
            RibUpdate::RoutesReceived {
                announced,
                withdrawn,
                flowspec_announced,
                flowspec_withdrawn,
                evpn_announced,
                evpn_withdrawn,
                ..
            } => (
                Some(
                    announced.len()
                        + withdrawn.len()
                        + flowspec_announced.len()
                        + flowspec_withdrawn.len()
                        + evpn_announced.len()
                        + evpn_withdrawn.len(),
                ),
                None,
            ),
            RibUpdate::BgpLsRoutesReceived {
                announced,
                withdrawn,
                ..
            } => (Some(announced.len() + withdrawn.len()), None),
            RibUpdate::VpnRoutesReceived {
                announced,
                withdrawn,
                ..
            } => (Some(announced.len() + withdrawn.len()), None),
            RibUpdate::LabeledRoutesReceived {
                announced,
                withdrawn,
                ..
            } => (Some(announced.len() + withdrawn.len()), None),
            RibUpdate::RtcRoutesReceived {
                announced,
                withdrawn,
                ..
            } => (Some(announced.len() + withdrawn.len()), None),
            // Unicast routes the departing session still holds: the
            // teardown work scales with them.
            RibUpdate::PeerDown { peer, .. } | RibUpdate::PeerDeleted { peer, .. } => {
                (ribs.get(peer).map(AdjRibIn::len), None)
            }
            RibUpdate::ReplacePeerExportPolicies { replacements, .. }
            | RibUpdate::ReplacePeerExportPoliciesAuthoritatively { replacements, .. }
            | RibUpdate::RestorePeerExportPoliciesAuthoritatively { replacements, .. } => {
                (None, Some(replacements.len()))
            }
            RibUpdate::ReevaluatePeerExportPolicies { peers, .. } => (None, Some(peers.len())),
            _ => (None, None),
        };
        let peer = match update {
            RibUpdate::PeerDeleted { peer, .. }
            | RibUpdate::ReplacePeerExportPolicy { peer, .. }
            | RibUpdate::ReplayPeerOutbound { peer, .. } => Some(*peer),
            _ => update.session_peer(),
        };
        Self {
            kind: update.actor_turn_kind(),
            peer,
            routes,
            members,
        }
    }
}

/// At most one slow-turn line per [`SLOW_ACTOR_TURN_LOG_INTERVAL`].
#[derive(Default)]
pub(super) struct SlowActorTurnLog {
    pub(super) last: Option<Instant>,
    pub(super) suppressed: u64,
}

impl SlowActorTurnLog {
    /// Whether a slow turn ending at `now` may log. Returns the number of
    /// slow turns suppressed since the previous line.
    fn admit(&mut self, now: Instant) -> Option<u64> {
        if self
            .last
            .is_some_and(|last| now.saturating_duration_since(last) < SLOW_ACTOR_TURN_LOG_INTERVAL)
        {
            self.suppressed += 1;
            return None;
        }
        self.last = Some(now);
        Some(std::mem::take(&mut self.suppressed))
    }
}

impl RibManager {
    /// Record one finished turn and warn, rate-limited, when it was slow.
    pub(super) fn finish_actor_turn(&mut self, turn: ActorTurn, elapsed: Duration) {
        self.metrics.observe_rib_actor_turn(turn.kind, elapsed);
        if elapsed < SLOW_ACTOR_TURN {
            return;
        }
        let Some(suppressed) = self.slow_actor_turn_log.admit(Instant::now()) else {
            return;
        };
        warn!(
            kind = turn.kind.as_str(),
            elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            threshold_ms = u64::try_from(SLOW_ACTOR_TURN.as_millis()).unwrap_or(u64::MAX),
            peer = turn.peer.map(tracing::field::display),
            routes = turn.routes,
            members = turn.members,
            suppressed,
            "slow RIB actor turn"
        );
    }
}
