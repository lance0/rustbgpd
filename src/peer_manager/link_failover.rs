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

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rustbgpd_transport::{LinkSnapshot, LinkStateFeed, PeerCommand};
use tokio::sync::{mpsc, watch};
use tracing::debug;

use super::{ManagedPeerState, PeerManager};

const LINK_CHECK_RETRY: Duration = Duration::from_millis(100);
/// How often an unacknowledged link-local BFD scope move is re-attempted.
pub(super) const BFD_SCOPE_RETRY: Duration = Duration::from_secs(1);

/// The monitor's snapshot feed and the sessions whose check did not fit their
/// mailbox: one entry per session id, so at most one per live session.
///
/// Link checks never wait on BFD. A link change dispatches checks and arms
/// their retry at once; moving link-local BFD sessions to a recreated
/// interface's index is a separate run-loop step (`bfd_refresh_due`), and
/// the long waits inside it keep servicing link changes and check retries.
#[derive(Default)]
pub(super) struct LinkCheckDelivery {
    pub(super) state: Option<watch::Receiver<Arc<LinkSnapshot>>>,
    /// The run loop's (and long waits') "links changed" receiver.
    pub(super) changes: Option<watch::Receiver<Arc<LinkSnapshot>>>,
    pub(super) pending: BTreeMap<u64, mpsc::Sender<PeerCommand>>,
    pub(super) retry_at: Option<tokio::time::Instant>,
    /// Re-resolve link-local BFD scopes at the top of the next run-loop turn.
    pub(super) bfd_refresh_due: bool,
    /// BFD peers whose scope move the actor has not acknowledged yet.
    pub(super) bfd_unsettled: BTreeSet<IpAddr>,
    /// When to re-attempt an unacknowledged move.
    pub(super) bfd_retry_at: Option<tokio::time::Instant>,
}

impl PeerManager {
    /// Attach the fast-external-failover link state. Without it (non-Linux, or
    /// the monitor could not open its netlink socket) sessions keep relying on
    /// the hold timer and BFD.
    #[must_use]
    pub fn with_link_failover(mut self, state: watch::Receiver<Arc<LinkSnapshot>>) -> Self {
        self.link_check.changes = Some(state.clone());
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

    /// Wait for the next published link-state change. `false` when the
    /// monitor has exited (the receiver is then dropped).
    pub(super) async fn receive_link_change(
        changes: &mut Option<watch::Receiver<Arc<LinkSnapshot>>>,
    ) -> bool {
        let alive = match changes.as_mut() {
            Some(rx) => rx.changed().await.is_ok(),
            None => std::future::pending().await,
        };
        if !alive {
            *changes = None;
        }
        alive
    }

    /// Run the BFD scope refresh a link change or retry asked for.
    pub(super) async fn run_due_bfd_scope_refresh(&mut self) {
        if std::mem::take(&mut self.link_check.bfd_refresh_due) {
            self.refresh_bfd_link_local_scopes().await;
        }
    }

    /// The unacknowledged BFD scope move is due for another attempt.
    pub(super) fn bfd_scope_retry_due(&mut self) {
        self.link_check.bfd_retry_at = None;
        self.link_check.bfd_refresh_due = true;
    }

    /// The link state changed: ask every eligible session to check, without
    /// waiting on anything. A session already waiting for mailbox space keeps
    /// its single pending flag. Link-local BFD scopes are reconciled
    /// afterwards, as their own run-loop step.
    pub(super) fn handle_links_changed(&mut self) {
        self.feed_unnumbered_links();
        self.link_check.bfd_refresh_due = true;
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
