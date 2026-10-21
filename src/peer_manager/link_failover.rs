//! Fast external failover: poke eligible sessions when the kernel link state
//! changes.
//!
//! Delivery is level-triggered. The link monitor publishes its current
//! snapshot on a `watch` channel; every published change wakes the manager,
//! which asks each eligible session (operator knob on, administratively
//! enabled, not known to be iBGP) to `CheckLinks`. The session re-reads the
//! *current* snapshot through its transport config and judges its own
//! connections, so nothing per event is queued here: a session whose mailbox
//! is full keeps a single pending flag until the retry delivers, and any
//! number of link changes in between collapse into that one check.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use rustbgpd_transport::{LinkSnapshot, LinkStateFeed, PeerCommand};
use tokio::sync::{mpsc, watch};
use tracing::debug;

use super::{ManagedPeerState, PeerManager};

const LINK_CHECK_RETRY: Duration = Duration::from_millis(100);

/// The monitor's snapshot feed and the sessions whose check did not fit their
/// mailbox: one entry per session id, so at most one per live session.
#[derive(Default)]
pub(super) struct LinkCheckDelivery {
    pub(super) state: Option<watch::Receiver<Arc<LinkSnapshot>>>,
    pub(super) pending: BTreeMap<u64, mpsc::Sender<PeerCommand>>,
    pub(super) retry_at: Option<tokio::time::Instant>,
}

impl PeerManager {
    /// Attach the fast-external-failover link state. Without it (non-Linux, or
    /// the monitor could not open its netlink socket) sessions keep relying on
    /// the hold timer and BFD.
    #[must_use]
    pub fn with_link_failover(mut self, state: watch::Receiver<Arc<LinkSnapshot>>) -> Self {
        self.link_check.state = Some(state);
        self
    }

    /// The read handle a session's transport config carries, with the
    /// neighbor's resolved `fast_external_failover` setting.
    pub(super) fn link_state_feed(&self, enabled: bool) -> LinkStateFeed {
        let feed = self
            .link_check
            .state
            .clone()
            .map(|state| LinkStateFeed::new(state, enabled))
            .unwrap_or_default();
        feed.set_enabled(enabled);
        feed
    }

    /// A receiver for the run loop's "links changed" arm.
    pub(super) fn link_state_changes(&self) -> Option<watch::Receiver<Arc<LinkSnapshot>>> {
        self.link_check.state.clone()
    }

    /// The link state changed: ask every eligible session to check. A session
    /// already waiting for mailbox space keeps its single pending flag.
    pub(super) fn handle_links_changed(&mut self) {
        let targets = self.link_check_targets();
        debug!(
            candidate_sessions = targets.len(),
            "fast external failover: link state changed; asking sessions to check"
        );
        for (session_id, commands) in targets {
            if self.link_check.pending.contains_key(&session_id) {
                continue;
            }
            if let Err(mpsc::error::TrySendError::Full(_)) =
                commands.try_send(PeerCommand::CheckLinks)
            {
                self.link_check.pending.insert(session_id, commands);
            }
        }
        // Keep an armed deadline: changes arriving faster than the retry
        // interval must not postpone delivery indefinitely.
        if self.link_check.retry_at.is_none() {
            self.schedule_link_check_retry();
        }
    }

    /// Retry checks that found a full mailbox. Eligibility is re-read now: a
    /// session that exited, was replaced, or is no longer eligible (opted
    /// out, disabled) is dropped; a still-full one waits for the next retry.
    pub(super) fn retry_link_checks(&mut self) {
        let eligible: std::collections::HashSet<u64> = self
            .link_check_targets()
            .into_iter()
            .map(|(session_id, _)| session_id)
            .collect();
        self.link_check.pending.retain(|session_id, commands| {
            eligible.contains(session_id)
                && matches!(
                    commands.try_send(PeerCommand::CheckLinks),
                    Err(mpsc::error::TrySendError::Full(_))
                )
        });
        self.schedule_link_check_retry();
    }

    /// Every eligible session, collision candidates included.
    fn link_check_targets(&self) -> Vec<(u64, mpsc::Sender<PeerCommand>)> {
        self.peers
            .values()
            .filter(|managed| fast_external_failover_eligible(managed))
            .flat_map(|managed| {
                let pending = managed
                    .pending_inbound
                    .as_ref()
                    .map(|pending| (pending.session_id, pending.handle.commands_sender()));
                std::iter::once((managed.session_id(), managed.handle().commands_sender()))
                    .chain(pending)
            })
            .collect()
    }

    fn schedule_link_check_retry(&mut self) {
        self.link_check.retry_at = (!self.link_check.pending.is_empty())
            .then(|| tokio::time::Instant::now() + LINK_CHECK_RETRY);
    }
}

/// Knob on, administratively enabled, and not known to be iBGP. A remote ASN
/// of 0 is an accept-any dynamic child whose ASN the manager has not learned
/// yet; classification is deferred to the session, which checks the
/// negotiated ASN before stopping anything.
fn fast_external_failover_eligible(managed: &ManagedPeerState) -> bool {
    managed.enabled
        && managed.transport_config.fast_external_failover
        && managed.remote_asn != managed.transport_config.peer.local_asn
}
