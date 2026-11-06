use rustbgpd_rib::PeerId;
use std::collections::BTreeSet;

use rustbgpd_api::peer_types::{
    ConfigEvent, DynamicPeerBounceOutcome, DynamicRangeTarget, OutboundRefreshError, PeerKey,
    PeerLifecycleError, PeerManagerNeighborConfig, PresenceAwareNeighborCreate,
    SessionLifecycleEventType, SetGshutError,
};
use rustbgpd_rib::{RibCommandError, RibUpdate};
use rustbgpd_transport::{PeerCommand, PeerCommandError};
use rustbgpd_transport::{PeerHandle, SessionIdentity, TcpAoKeyring};
use rustbgpd_wire::{Afi, Safi};
use tokio::sync::oneshot;
use tracing::{debug, error, info, warn};

use crate::policy_admin::apply_config_event;

use super::ManagedPeerState;
use super::{
    ManagedPeer, OperatorReadAdmission, PEER_LIFECYCLE_COMMAND_TIMEOUT, PEER_POLICY_UPDATE_TIMEOUT,
    PeerManager, PeerShutdownOutcome,
};

pub(super) enum RuntimeCreatePeerFailureEffect {
    NoEffect,
    FullyCompensated,
    /// The BFD actor did not acknowledge the socket family the neighbor
    /// needed; BFD is fenced and its final state is unknown.
    CompensationAmbiguous,
}

pub(super) enum ReconfigurePeerFailureEffect {
    NoEffect,
    FullyCompensated,
    CompensationAmbiguous,
}

pub(super) enum PeerReshapeSnapshotOutcome {
    Success(Vec<PeerManagerNeighborConfig>),
    RejectedNoEffect(PeerLifecycleError),
    FullyCompensated(PeerLifecycleError),
    CompensationAmbiguous(PeerLifecycleError),
}

async fn send_max_prefix_start_before(
    commands: tokio::sync::mpsc::Sender<PeerCommand>,
    deadline: tokio::time::Instant,
) -> Result<(), PeerCommandError> {
    tokio::select! {
        biased;
        () = tokio::time::sleep_until(deadline) => Err(PeerCommandError::TimedOut {
            operation: "start",
            deadline: PEER_LIFECYCLE_COMMAND_TIMEOUT,
        }),
        result = commands.send(PeerCommand::Start) => {
            result.map_err(|_| PeerCommandError::SessionExited)
        }
    }
}

/// Send one session command within [`PEER_LIFECYCLE_COMMAND_TIMEOUT`] through
/// an owned sender, so a sweep can address many sessions at once.
async fn send_session_command(
    commands: tokio::sync::mpsc::Sender<PeerCommand>,
    command: PeerCommand,
    operation: &'static str,
) -> Result<(), PeerCommandError> {
    match tokio::time::timeout(PEER_LIFECYCLE_COMMAND_TIMEOUT, commands.send(command)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(PeerCommandError::SessionExited),
        Err(_elapsed) => Err(PeerCommandError::TimedOut {
            operation,
            deadline: PEER_LIFECYCLE_COMMAND_TIMEOUT,
        }),
    }
}

/// Peers waiting for a forced outbound refresh, each at most once.
#[derive(Default)]
struct OutboundRefreshQueue {
    pending: std::collections::VecDeque<PeerId>,
    waiting: std::collections::HashSet<PeerId>,
}

impl OutboundRefreshQueue {
    fn extend(&mut self, peers: Vec<PeerId>) {
        for peer in peers {
            if self.waiting.insert(peer) {
                self.pending.push_back(peer);
            }
        }
    }

    /// The next peer to refresh. From here on a toggle for it asks for a
    /// replay of its own: the one about to run may read the older state.
    fn pop(&mut self) -> Option<PeerId> {
        let peer = self.pending.pop_front()?;
        self.waiting.remove(&peer);
        Some(peer)
    }
}

fn lock_refresh_queue(
    queue: &std::sync::Mutex<OutboundRefreshQueue>,
) -> std::sync::MutexGuard<'_, OutboundRefreshQueue> {
    queue
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The peer manager's handle on the outbound refresher. Requests merge
/// straight into the refresher's queue, so however many toggles arrive while
/// a refresh waits on the RIB, it holds each waiting peer once. Dropping the
/// handle stops the refresher.
pub(super) struct OutboundRefresher {
    queue: std::sync::Arc<std::sync::Mutex<OutboundRefreshQueue>>,
    wake: std::sync::Arc<tokio::sync::Notify>,
    task: tokio::task::JoinHandle<()>,
}

impl OutboundRefresher {
    fn start(rib_tx: tokio::sync::mpsc::Sender<RibUpdate>) -> Self {
        let queue = std::sync::Arc::default();
        let wake = std::sync::Arc::new(tokio::sync::Notify::new());
        let task = tokio::spawn(run_outbound_refresher(
            rib_tx,
            std::sync::Arc::clone(&queue),
            std::sync::Arc::clone(&wake),
        ));
        Self { queue, wake, task }
    }

    fn request(&self, peers: Vec<PeerId>) {
        lock_refresh_queue(&self.queue).extend(peers);
        self.wake.notify_one();
    }

    /// Peers waiting for a refresh, not counting one in flight.
    #[cfg(test)]
    pub(super) fn waiting(&self) -> usize {
        lock_refresh_queue(&self.queue).pending.len()
    }
}

impl Drop for OutboundRefresher {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Drain forced outbound refreshes one peer at a time: each
/// `RefreshPeerOutbound` is sent only after the RIB answered the one before,
/// so the RIB's FIFO lane carries at most one replay ahead of the sessions'
/// route updates. Requests for a peer already waiting are merged; the replay
/// reads the peer's state when the RIB runs it, so one is enough. A peer the
/// RIB no longer has registered for outbound updates (deleted, or not yet
/// Established) is skipped: its next `PeerUp` emits fresh. Each time the
/// queue empties, one log line counts what it refreshed and what failed.
async fn run_outbound_refresher(
    rib_tx: tokio::sync::mpsc::Sender<RibUpdate>,
    queue: std::sync::Arc<std::sync::Mutex<OutboundRefreshQueue>>,
    wake: std::sync::Arc<tokio::sync::Notify>,
) {
    let (mut refreshed, mut skipped, mut failed) = (0_usize, 0_usize, 0_usize);
    loop {
        let next = lock_refresh_queue(&queue).pop();
        let Some(peer) = next else {
            if refreshed + skipped + failed > 0 {
                info!(
                    refreshed,
                    skipped, failed, "graceful-shutdown outbound refreshes complete"
                );
                (refreshed, skipped, failed) = (0, 0, 0);
            }
            wake.notified().await;
            continue;
        };
        let (reply, response) = oneshot::channel();
        if rib_tx
            .send(RibUpdate::RefreshPeerOutbound { peer, reply })
            .await
            .is_err()
        {
            return;
        }
        match response.await {
            Ok(Ok(())) => refreshed += 1,
            Ok(Err(RibCommandError::NotFound(_))) => skipped += 1,
            Ok(Err(error)) => {
                failed += 1;
                warn!(%peer, %error, "graceful-shutdown outbound refresh failed");
            }
            Err(_) => {
                // The RIB dropped the reply. If it has exited, the next send
                // fails and ends the refresher.
                failed += 1;
                warn!(%peer, "graceful-shutdown outbound refresh reply dropped");
            }
        }
    }
}

/// A peer taken out of the table whose sessions have yet to stop
/// ([`PeerManager::detach_peer_for_delete`]).
pub(super) struct DetachedPeer {
    primary: PeerHandle,
    primary_session_id: u64,
    pending: Option<super::PendingInbound>,
    stop_reason: Option<bytes::Bytes>,
    settlement: DeleteSettlement,
}

/// A validated delete ([`PeerManager::prepare_delete`]); the peer and its
/// sessions are untouched.
pub(super) struct PreparedDelete {
    peer: PeerKey,
    next_config: Option<crate::config::Config>,
    /// The discard list changes, so the sessions' routes must be purged
    /// first ([`PeerManager::purge_reset_for_delete`]).
    pub(super) purge_reset: bool,
}

impl PreparedDelete {
    pub(super) fn peer(&self) -> &PeerKey {
        &self.peer
    }
}

/// The admission result of each purge, and the pending generations of the
/// peers whose primary purge failed, to retire with
/// [`PeerManager::retire_purged_candidates`].
#[must_use]
pub(super) struct PurgeOutcome {
    pub(super) results: Vec<Result<(), PeerLifecycleError>>,
    pub(super) retiring: Vec<PurgedCandidate>,
}

/// A peer whose primary purge was not admitted: its primary stays installed,
/// fenced as retiring until its pending generation has been retired.
pub(super) struct PurgedCandidate {
    peer: PeerKey,
    primary_session_id: u64,
    pending: Option<super::PendingInbound>,
}

/// What a delete still does once the peer's sessions have stopped.
struct DeleteSettlement {
    peer: PeerKey,
    next_config: Option<crate::config::Config>,
    removed_config: PeerManagerNeighborConfig,
    reap_metric_series: bool,
}

impl PeerManager {
    pub(super) fn publish_peer_admin_enabled_metric(&self, peer: &PeerKey, enabled: bool) {
        self.metrics.set_peer_admin_enabled(
            &self.peer_metric_label(peer),
            peer.interface.as_deref().unwrap_or(""),
            enabled,
        );
    }

    /// Publish `bgp_max_prefix_latched` for an installed peer. A latch change
    /// while the peer is absent (a retiring session during delete or
    /// reconfigure) publishes nothing: the delete-path reap owns that
    /// identity, and a re-added peer is seeded from the latch map.
    pub(super) fn publish_max_prefix_latched_metric(&self, peer: &PeerKey, latched: bool) {
        if self.peers.contains_key(peer) {
            self.metrics.set_max_prefix_latched(
                &self.peer_metric_label(peer),
                peer.interface.as_deref().unwrap_or(""),
                latched,
            );
        }
    }

    /// Publish the `bgp_peer_info` identity join series from the installed
    /// [`ManagedPeer`]. A peer that has gone away is skipped; its series are
    /// dropped by the identity and bare-address reaps on removal.
    pub(super) fn publish_peer_info_metric(&self, peer: &PeerKey) {
        let Some(managed) = self.peers.get(peer) else {
            return;
        };
        self.metrics.set_peer_info(
            &self.peer_metric_label(peer),
            peer.interface.as_deref().unwrap_or(""),
            managed.remote_asn,
            &managed.description,
            managed.peer_group.as_deref().unwrap_or(""),
        );
    }

    pub(super) fn seed_peer_truth_metrics(&self, peer: &PeerKey, enabled: bool) {
        let peer_label = self.peer_metric_label(peer);
        let interface = peer.interface.as_deref().unwrap_or("");
        self.metrics
            .set_peer_admin_enabled(&peer_label, interface, enabled);
        self.metrics.set_max_prefix_latched(
            &peer_label,
            interface,
            self.max_prefix_latches.contains_key(peer),
        );
        self.metrics
            .set_peer_session_established(&peer_label, interface, false);
        self.metrics
            .set_peer_session_state(&peer_label, interface, "idle");
    }

    pub(super) async fn provision_new_peer_session(
        &mut self,
        peer: &PeerKey,
        enabled: bool,
        should_start: bool,
        handle: PeerHandle,
        context: &'static str,
    ) -> Result<PeerHandle, PeerCommandError> {
        self.seed_peer_truth_metrics(peer, enabled);
        #[cfg(test)]
        let forced_failure = std::mem::take(&mut self.fail_next_peer_start);
        #[cfg(not(test))]
        let forced_failure = false;
        let started = if !should_start {
            Ok(())
        } else if forced_failure {
            Err(PeerCommandError::SessionExited)
        } else {
            handle.start_timeout(PEER_LIFECYCLE_COMMAND_TIMEOUT).await
        };
        if let Err(error) = started {
            warn!(peer = %peer, %error, %context, "failed to start new peer session");
            let _ = self
                .shutdown_handle_bounded(peer.address, context, handle)
                .await;
            // An interface-only neighbor's identity series belong to the
            // neighbor, not to this endpoint: a failed start keeps them, its
            // down history included, for the retry.
            if !self.interface_only_owns(peer.interface.as_deref()) {
                self.metrics.reap_peer_identity_series(
                    &self.peer_metric_label(peer),
                    peer.interface.as_deref().unwrap_or(""),
                );
            }
            return Err(error);
        }
        Ok(handle)
    }

    pub(super) async fn sync_owned_session_metrics(&self, peer: &PeerKey) {
        let Some(managed) = self.peers.get(peer) else {
            return;
        };
        if let Err(error) = managed
            .handle()
            .activate_max_prefix_metrics_timeout(0, PEER_LIFECYCLE_COMMAND_TIMEOUT)
            .await
        {
            warn!(
                peer = %peer,
                %error,
                "failed to synchronize newly owned session metrics"
            );
        }
    }

    pub(super) fn allocate_max_prefix_latch_generation(&mut self) -> u64 {
        let generation = self.next_max_prefix_latch_generation;
        self.next_max_prefix_latch_generation =
            self.next_max_prefix_latch_generation.wrapping_add(1);
        generation
    }

    pub(super) fn recompute_next_max_prefix_restart_deadline(&mut self) {
        self.next_max_prefix_restart_deadline = self
            .max_prefix_latches
            .values()
            .filter_map(|latch| latch.deadline)
            .min();
    }

    pub(super) fn install_max_prefix_latch(
        &mut self,
        peer: PeerKey,
        source_session_id: u64,
        error: String,
        restart_seconds: Option<u32>,
    ) -> bool {
        // The first terminal incident owns the hold-down. Duplicate terminal
        // notices from collision/retirement paths must not extend it.
        if self.max_prefix_latches.contains_key(&peer) {
            return false;
        }
        let generation = self.allocate_max_prefix_latch_generation();
        let deadline = restart_seconds.map(|seconds| {
            tokio::time::Instant::now() + std::time::Duration::from_secs(seconds.into())
        });
        self.publish_max_prefix_latched_metric(&peer, true);
        self.max_prefix_latches.insert(
            peer,
            super::MaxPrefixLatch {
                error,
                generation,
                source_session_id,
                deadline,
            },
        );
        if deadline.is_some_and(|candidate| {
            self.next_max_prefix_restart_deadline
                .is_none_or(|current| candidate < current)
        }) {
            self.next_max_prefix_restart_deadline = deadline;
        }
        true
    }

    pub(super) fn invalidate_max_prefix_restart(&mut self, peer: &PeerKey) {
        if self.invalidate_max_prefix_restart_without_recompute(peer) {
            self.recompute_next_max_prefix_restart_deadline();
        }
    }

    fn invalidate_max_prefix_restart_without_recompute(&mut self, peer: &PeerKey) -> bool {
        let generation = self.allocate_max_prefix_latch_generation();
        self.max_prefix_latches.get_mut(peer).is_some_and(|latch| {
            if latch.deadline.take().is_some() {
                latch.generation = generation;
                true
            } else {
                false
            }
        })
    }

    /// Reconcile a peer's hold-down with an edited restart duration.
    ///
    /// An armed countdown is rescheduled to `now + new` under a fresh latch
    /// generation, so the superseded deadline can never fire. Removing the
    /// duration cancels the countdown and leaves the peer latched until an
    /// explicit enable. A latch without a countdown — an indefinite shutdown,
    /// or one whose single automatic attempt was already consumed — never
    /// gains a countdown from a config edit.
    pub(super) fn rearm_max_prefix_restart(
        &mut self,
        peer: &PeerKey,
        restart_seconds: Option<u32>,
    ) {
        let generation = self.allocate_max_prefix_latch_generation();
        let rearmed = self
            .max_prefix_latches
            .get_mut(peer)
            .is_some_and(|latch| latch.reschedule(generation, restart_seconds));
        if rearmed {
            // The rescheduled deadline may be later than the cached minimum it
            // replaces, so a full recompute is required (the cheap min-update
            // in `install_max_prefix_latch` would keep a stale earlier wake).
            self.recompute_next_max_prefix_restart_deadline();
        }
    }

    pub(super) fn remove_max_prefix_latch(&mut self, peer: &PeerKey) {
        if self.max_prefix_latches.remove(peer).is_some() {
            self.publish_max_prefix_latched_metric(peer, false);
            self.recompute_next_max_prefix_restart_deadline();
        }
    }

    pub(super) fn dynamic_restart_policy_still_current(&self, managed: &ManagedPeerState) -> bool {
        if !managed.is_dynamic {
            return true;
        }
        let Some(accepted) = managed.accepted_dynamic_range.as_ref() else {
            return false;
        };
        self.current_config
            .peer_groups
            .get(&accepted.peer_group)
            .and_then(|group| group.max_prefix_restart_seconds)
            .map(std::num::NonZeroU32::get)
            == managed.max_prefix_restart_seconds
    }

    pub(super) fn sync_dynamic_max_prefix_restart_for_group(&mut self, name: &str) {
        let restart_seconds = self
            .current_config
            .peer_groups
            .get(name)
            .and_then(|group| group.max_prefix_restart_seconds)
            .map(std::num::NonZeroU32::get);
        let dynamic_members: Vec<PeerKey> = self
            .peers
            .iter()
            .filter(|(_, managed)| {
                managed.is_dynamic
                    && managed
                        .accepted_dynamic_range
                        .as_ref()
                        .is_some_and(|accepted| accepted.peer_group == name)
                    && managed.max_prefix_restart_seconds != restart_seconds
            })
            .map(|(peer, _)| peer.clone())
            .collect();
        for peer in dynamic_members {
            self.rearm_max_prefix_restart(&peer, restart_seconds);
            if let Some(managed) = self.peers.get_mut(&peer) {
                managed.max_prefix_restart_seconds = restart_seconds;
            }
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the restart fan-out keeps hold-down expiry, BFD withholding, and per-peer outcome bookkeeping together"
    )]
    pub(super) async fn handle_due_max_prefix_restarts(&mut self) {
        let now = tokio::time::Instant::now();
        let mut due: Vec<(PeerKey, u64)> = self
            .max_prefix_latches
            .iter()
            .filter_map(|(peer, latch)| {
                latch
                    .deadline
                    .is_some_and(|deadline| deadline <= now)
                    .then_some((peer.clone(), latch.generation))
            })
            .collect();
        due.sort_by(|left, right| left.0.cmp(&right.0));

        let attempt_deadline = now + PEER_LIFECYCLE_COMMAND_TIMEOUT;
        let mut starts = Vec::with_capacity(due.len());
        for (peer, generation) in due {
            let latch_matches = self.max_prefix_latches.get(&peer).is_some_and(|latch| {
                latch.generation == generation
                    && latch.deadline.is_some_and(|deadline| deadline <= now)
            });
            let peer_matches = self.peers.get(&peer).is_some_and(|managed| {
                !managed.enabled
                    && managed.pending_inbound.is_none()
                    && managed.max_prefix_restart_seconds.is_some()
                    && (!managed.is_dynamic
                        || self.dynamic_peer_still_allowed_by_current_ranges(managed))
                    && self.dynamic_restart_policy_still_current(managed)
            });
            if !latch_matches || !peer_matches {
                let _ = self.invalidate_max_prefix_restart_without_recompute(&peer);
                continue;
            }

            // Consume the single automatic attempt before awaiting the bounded
            // command. Failure therefore remains an indefinite fail-closed
            // latch and can never become a retry loop.
            let _ = self.invalidate_max_prefix_restart_without_recompute(&peer);
            let address = peer.address;
            if self.bfd_should_withhold(&address) {
                if let Some(managed) = self.peers.get_mut(&peer) {
                    managed.enabled = true;
                }
                self.publish_peer_admin_enabled_metric(&peer, true);
                let _ = self.max_prefix_latches.remove(&peer);
                self.publish_max_prefix_latched_metric(&peer, false);
                self.set_bfd_peer_disabled(address, false);
                self.mark_bfd_withheld(address);
                self.publish_peer_lifecycle_event(
                    &peer,
                    SessionLifecycleEventType::PeerEnabled,
                    format!("peer {address} max-prefix hold-down expired; waiting for BFD"),
                );
                info!(peer = %address, "max-prefix hold-down expired; strict BFD still withholds BGP until BFD Up");
                continue;
            }
            let commands = self
                .peers
                .get(&peer)
                .expect("validated above")
                .handle()
                .commands_sender();
            starts.push((peer, commands));
        }
        self.recompute_next_max_prefix_restart_deadline();

        let attempts = starts
            .iter()
            .map(|(_, commands)| send_max_prefix_start_before(commands.clone(), attempt_deadline));
        let results = self
            .await_with_readiness(
                futures::future::join_all(attempts),
                OperatorReadAdmission::Fenced {
                    reason: "bounded max-prefix restart fan-out outside any policy transaction",
                },
            )
            .await;

        for ((peer, _commands), result) in starts.into_iter().zip(results) {
            let address = peer.address;
            match result {
                Ok(()) => {
                    if let Some(managed) = self.peers.get_mut(&peer) {
                        managed.enabled = true;
                    }
                    self.publish_peer_admin_enabled_metric(&peer, true);
                    let _ = self.max_prefix_latches.remove(&peer);
                    self.publish_max_prefix_latched_metric(&peer, false);
                    self.set_bfd_peer_disabled(address, false);
                    self.publish_peer_lifecycle_event(
                        &peer,
                        SessionLifecycleEventType::PeerEnabled,
                        format!(
                            "peer {address} automatically restarted after max-prefix hold-down"
                        ),
                    );
                    info!(peer = %address, "peer automatically restarted after max-prefix hold-down");
                }
                Err(error) => {
                    if let Some(latch) = self.max_prefix_latches.get_mut(&peer) {
                        latch.error = format!(
                            "automatic max-prefix restart failed: {error}; peer remains disabled; run 'rbgp neighbor {} enable' to retry",
                            peer.label()
                        );
                    }
                    warn!(peer = %address, %error, "automatic max-prefix restart attempt failed; peer remains latched disabled");
                }
            }
        }
        self.recompute_next_max_prefix_restart_deadline();
    }

    /// Keep a removed generation terminally owned until its actor cannot emit
    /// again, then consume every lossless notice it published before retiring
    /// the session id. This is the common ownership-transfer fence.
    pub(super) async fn quiesce_retiring_session(
        &mut self,
        peer: &PeerKey,
        session_id: u64,
        handle: PeerHandle,
        context: &'static str,
        collision_dump: bool,
    ) -> PeerShutdownOutcome {
        self.retiring_sessions.insert(session_id, peer.clone());
        if collision_dump {
            let _ = handle
                .collision_dump_timeout(PEER_LIFECYCLE_COMMAND_TIMEOUT)
                .await;
        }
        let outcome = self
            .shutdown_handle_bounded(peer.address, context, handle)
            .await;
        Box::pin(self.drain_ready_session_notifications(Some(peer))).await;
        self.retiring_sessions.remove(&session_id);
        self.unregister_session(session_id);
        outcome
    }

    /// Stop `handle` within the bounded shutdown. The session sends its final
    /// `PeerDown` while it stops, so the wait drives deferred RIB admission:
    /// a granted reservation is sent rather than holding the slot that
    /// `PeerDown` needs, and the deferred update keeps its place in line.
    pub(super) async fn shutdown_handle_bounded(
        &mut self,
        address: std::net::IpAddr,
        context: &'static str,
        handle: PeerHandle,
    ) -> PeerShutdownOutcome {
        self.deferred_rib
            .drive_while(Self::shutdown_handle_bounded_owned(
                address, context, handle,
            ))
            .await
    }

    pub(super) async fn shutdown_handle_bounded_owned(
        address: std::net::IpAddr,
        context: &'static str,
        handle: PeerHandle,
    ) -> PeerShutdownOutcome {
        match handle
            .shutdown_timeout(PEER_LIFECYCLE_COMMAND_TIMEOUT)
            .await
        {
            Ok(Ok(())) => PeerShutdownOutcome::Joined,
            Ok(Err(e)) => {
                warn!(peer = %address, %context, error = %e, "peer shutdown returned transport error");
                PeerShutdownOutcome::Joined
            }
            Err(rustbgpd_transport::PeerShutdownError::Join(e)) => {
                error!(peer = %address, %context, error = %e, "peer task join error during shutdown");
                PeerShutdownOutcome::Joined
            }
            Err(rustbgpd_transport::PeerShutdownError::TimedOut { .. }) => {
                warn!(
                    peer = %address,
                    %context,
                    timeout_ms = %PEER_LIFECYCLE_COMMAND_TIMEOUT.as_millis(),
                    "peer shutdown timed out; aborted session task and continuing without parking PeerManager"
                );
                PeerShutdownOutcome::TimedOut
            }
        }
    }

    pub(super) fn removed_peer_config(
        peer: &PeerKey,
        managed: &ManagedPeerState,
    ) -> PeerManagerNeighborConfig {
        let tc = &managed.transport_config;
        PeerManagerNeighborConfig {
            address: peer.address,
            interface: peer.interface.clone(),
            scope_id: tc.peer_scope_id,
            remote_asn: managed.remote_asn,
            remote_asn_external: managed.transport_config.peer.remote_asn_external,
            description: managed.description.clone(),
            peer_group: managed.peer_group.clone(),
            admin_down: managed.admin_down.clone(),
            restore_admin_enabled: Some(managed.enabled),
            hold_time: managed.hold_time,
            min_hold_time: tc.peer.min_hold_time,
            send_hold_time: Some(tc.peer.send_hold_time),
            max_prefixes: managed.max_prefixes,
            max_prefixes_ipv4: tc.max_prefixes_ipv4,
            max_prefixes_ipv6: tc.max_prefixes_ipv6,
            max_prefixes_received_ipv4: tc.max_prefixes_received_ipv4,
            max_prefixes_received_ipv6: tc.max_prefixes_received_ipv6,
            max_prefixes_family: tc.max_prefixes_family,
            max_prefix_action: tc.max_prefix_action,
            max_prefix_warning_percent: tc.max_prefix_warning_percent,
            max_prefix_restart_seconds: managed.max_prefix_restart_seconds,
            md5_password: tc.md5_password.clone(),
            tcp_ao: tc.tcp_ao.clone(),
            tcp_mss: tc.tcp_mss,
            ttl_security_hops: tc.ttl_security_hops,
            families: tc.peer.families.clone(),
            required_families: tc.peer.required_families.clone(),
            graceful_restart: tc.peer.graceful_restart,
            gr_restart_time: tc.peer.gr_restart_time,
            gr_peer_restart_time_max: tc.gr_peer_restart_time_max,
            gr_stale_routes_time: tc.gr_stale_routes_time,
            llgr_stale_time: tc.llgr_stale_time,
            // Runtime delete rollback re-adds through the still-original
            // config snapshot, so startup-only GR eligibility is re-resolved
            // there rather than reconstructed from the removed live peer.
            gr_restart_eligible: false,
            local_ipv6_nexthop: tc.local_ipv6_nexthop,
            route_reflector_client: tc.route_reflector_client,
            orr_vantage: tc.orr_vantage,
            route_server_client: tc.route_server_client,
            send_non_transitive_extended_communities: tc.send_non_transitive_extended_communities,
            per_client_best: tc.per_client_best,
            next_hop_ownership_strict_peer: tc.next_hop_ownership_strict_peer,
            slow_peer_threshold_pct: tc.slow_peer_threshold_pct,
            slow_peer_duration: tc.slow_peer_duration,
            slow_peer_isolation: tc.slow_peer_isolation,
            fast_external_failover: tc.fast_external_failover,
            interpret_rfc1997: tc.interpret_rfc1997,
            rs_control_communities: tc.rs_control_communities,
            remove_private_as: tc.remove_private_as,
            discard_path_attributes: tc.discard_path_attributes.clone(),
            add_path_receive: tc.peer.add_path_receive,
            add_path_send: tc.peer.add_path_send,
            add_path_send_max: tc.peer.add_path_send_max,
            paths_limit_receive_max: tc.peer.paths_limit_receive_max,
            local_role: tc.peer.local_role,
            strict_role: tc.peer.strict_role,
            prefix_orf_receive: tc.peer.prefix_orf_receive,
            disable_ipv4_unicast: tc.peer.disable_ipv4_unicast,
            link_local_next_hop: tc.peer.link_local_next_hop,
            import_policy: managed.import_policy.clone(),
            export_policy: managed.export_policy.clone(),
        }
    }

    /// Startup registration as one operation: one import-roster publication
    /// however many peers it adds (ADR-0136), plus one final BFD resync.
    /// Genuine BFD admin-state changes still publish immediately.
    pub(super) async fn add_configured_peers(
        &mut self,
        configs: Vec<PeerManagerNeighborConfig>,
    ) -> Result<(), (usize, PeerLifecycleError)> {
        let batch = self.peers.begin_batch();
        if let Some(coupling) = self.bfd_coupling.as_mut() {
            coupling.registering = true;
        }
        let mut result = Ok(());
        for (index, config) in configs.into_iter().enumerate() {
            if let Err(error) = self.add_peer(config, false).await {
                result = Err((index, error));
                break;
            }
        }
        self.peers.end_batch(batch);
        if let Some(coupling) = self.bfd_coupling.as_mut() {
            coupling.registering = false;
        }
        // The command owns this await through success or partial failure.
        // Resync after registration: an initial BFD ack may have arrived
        // before the strict peers existed and could not release their holds.
        self.republish_bfd_desired();
        result
    }

    pub(super) async fn add_peer(
        &mut self,
        config: PeerManagerNeighborConfig,
        sync_config_snapshot: bool,
    ) -> Result<(), PeerLifecycleError> {
        // A new peer's admin state is the config's: `admin_down` adds it
        // disabled, so it never connects or accepts until enabled. A replayed
        // rollback prior restores its captured state instead.
        let enabled = config
            .restore_admin_enabled
            .unwrap_or(config.admin_down.is_none());
        self.add_peer_impl(config, sync_config_snapshot, enabled, true)
            .await
    }

    pub(super) async fn runtime_create_peer(
        &mut self,
        spec: Box<PresenceAwareNeighborCreate>,
    ) -> Result<(), PeerLifecycleError> {
        self.runtime_create_peer_classified(spec, None).await
    }

    /// The settlement outcome of an owned runtime create.
    pub(super) async fn owned_runtime_create_peer(
        &mut self,
        spec: Box<PresenceAwareNeighborCreate>,
    ) -> rustbgpd_api::peer_types::OwnedNeighborMutationOutcome {
        use rustbgpd_api::peer_types::{OwnedNeighborMutationError, OwnedNeighborMutationOutcome};
        let mut effect = RuntimeCreatePeerFailureEffect::NoEffect;
        let Err(error) = self
            .runtime_create_peer_classified(spec, Some(&mut effect))
            .await
        else {
            return OwnedNeighborMutationOutcome::Success;
        };
        let error = OwnedNeighborMutationError::Peer(error);
        match effect {
            RuntimeCreatePeerFailureEffect::NoEffect => {
                OwnedNeighborMutationOutcome::RejectedNoEffect(error)
            }
            RuntimeCreatePeerFailureEffect::FullyCompensated => {
                OwnedNeighborMutationOutcome::FullyCompensated(error)
            }
            RuntimeCreatePeerFailureEffect::CompensationAmbiguous => {
                OwnedNeighborMutationOutcome::CompensationAmbiguous(error)
            }
        }
    }

    pub(super) async fn runtime_create_peer_classified(
        &mut self,
        spec: Box<PresenceAwareNeighborCreate>,
        mut failure_effect: Option<&mut RuntimeCreatePeerFailureEffect>,
    ) -> Result<(), PeerLifecycleError> {
        let Some(address) = spec.address else {
            return self.add_interface_only_neighbor(spec);
        };
        let peer = PeerKey::new(address, spec.interface.clone());
        if self.peers.contains_key(&peer) {
            return Err(PeerLifecycleError::AlreadyExists(peer));
        }

        let mut next_config = self.current_config.clone();
        apply_config_event(
            &mut next_config,
            &ConfigEvent::PresenceAwareNeighborAdded { spec, ack: None },
        )
        .map_err(|error| PeerLifecycleError::Invalid(error.to_string()))?;
        let neighbor = next_config
            .neighbors
            .iter()
            .find(|neighbor| {
                neighbor.address == peer.address.to_string() && neighbor.interface == peer.interface
            })
            .ok_or_else(|| {
                PeerLifecycleError::Internal(format!(
                    "presence-aware neighbor {peer} missing after snapshot update"
                ))
            })?;
        let resolved = next_config
            .resolve_neighbor(neighbor)
            .map_err(|error| PeerLifecycleError::Invalid(error.to_string()))?;
        let config = Self::peer_manager_config_from_resolved(resolved, false);
        // Inbound MD5/GTSM/MSS enforcement lives on the BGP listener. Coordinated
        // SIGHUP can update MD5/GTSM; MSS is startup-only. A runtime-created
        // neighbor resolving to any of them would have an inconsistent inbound half.
        if config.md5_password.is_some()
            || config.ttl_security_hops.is_some()
            || config.tcp_mss.is_some()
        {
            return Err(PeerLifecycleError::RestartRequired(format!(
                "peer {peer} resolves md5_password, ttl_security, or tcp_mss; runtime peer CRUD \
                 cannot change inbound listener enforcement — use the config file and SIGHUP \
                 for md5_password/ttl_security, or restart for tcp_mss"
            )));
        }
        // ADR-0142: a static link-local add is refused before any effect
        // when a learned endpoint holds its address, bound or reserved. This
        // RPC is the admission, so a BMP identity refusal is counted here;
        // the read-only plan and reload preflights never count one.
        self.unnumbered_preflight(&next_config).map_err(|error| {
            if error.starts_with("bmp_identity_conflict:") {
                self.metrics.record_bmp_identity_conflict(false);
            }
            PeerLifecycleError::Precondition(error)
        })?;

        let (previous_config, bfd) = self.install_current_config(next_config);
        let failure = match bfd {
            // Without its member a strict neighbor would start ungated:
            // refuse a BFD session that cannot be derived, such as one whose
            // interface scope vanished after `resolve_neighbor`.
            Err(error) => Some((
                PeerLifecycleError::Precondition(format!("BFD session for {peer}: {error}")),
                RuntimeCreatePeerFailureEffect::FullyCompensated,
            )),
            // The neighbor's BFD session can be the first in its socket family.
            Ok(()) => match self.open_bfd_member_family(address).await {
                super::DynamicBfdSocketOutcome::Ready => None,
                super::DynamicBfdSocketOutcome::Rejected(error) => Some((
                    PeerLifecycleError::Precondition(error),
                    RuntimeCreatePeerFailureEffect::FullyCompensated,
                )),
                super::DynamicBfdSocketOutcome::Ambiguous(error) => Some((
                    PeerLifecycleError::Internal(format!("BFD socket family for {peer}: {error}")),
                    RuntimeCreatePeerFailureEffect::CompensationAmbiguous,
                )),
            },
        };
        if let Some((error, effect)) = failure {
            // Restoring the snapshot removes any member it added, except
            // under a fenced coupling: that outcome stays ambiguous.
            self.replace_current_config(previous_config);
            if let Some(slot) = &mut failure_effect {
                **slot = effect;
            }
            return Err(error);
        }
        match self.add_peer(config, false).await {
            Ok(()) => Ok(()),
            Err(error) => {
                self.replace_current_config(previous_config);
                if let Some(effect) = &mut failure_effect {
                    **effect = RuntimeCreatePeerFailureEffect::FullyCompensated;
                }
                Err(error)
            }
        }
    }

    pub(super) async fn add_peer_with_admin_state(
        &mut self,
        config: PeerManagerNeighborConfig,
        sync_config_snapshot: bool,
        enabled: bool,
    ) -> Result<(), PeerLifecycleError> {
        self.add_peer_impl(config, sync_config_snapshot, enabled, false)
            .await
    }

    #[expect(
        clippy::too_many_lines,
        reason = "peer add wires transport, policy, BFD desired state, persistence, and events"
    )]
    pub(super) async fn add_peer_impl(
        &mut self,
        config: PeerManagerNeighborConfig,
        sync_config_snapshot: bool,
        enabled: bool,
        emit_presence: bool,
    ) -> Result<(), PeerLifecycleError> {
        let peer_key = PeerKey::new(config.address, config.interface.clone());
        let enabled = enabled && !self.max_prefix_latches.contains_key(&peer_key);
        let is_link_local = matches!(config.address, std::net::IpAddr::V6(v6) if v6.segments()[0] & 0xffc0 == 0xfe80);
        match (is_link_local, config.interface.as_ref()) {
            (true, None) => {
                return Err(PeerLifecycleError::Invalid(format!(
                    "peer {peer_key} is IPv6 link-local and requires an interface"
                )));
            }
            (false, Some(_)) => {
                return Err(PeerLifecycleError::Invalid(format!(
                    "peer {peer_key} has an interface but is not IPv6 link-local"
                )));
            }
            _ => {}
        }
        if self.peers.contains_key(&peer_key) {
            return Err(PeerLifecycleError::AlreadyExists(peer_key));
        }
        // ADR-0142 admission: a BMP collector cannot tell two sessions at
        // one address apart. While collectors are configured, a neighbor at
        // an address another monitored neighbor holds is refused, or, when
        // every collector sets `on_identity_conflict = "exclude"`, admitted
        // with its session left out of BMP. The neighbor admitted first
        // keeps its session and its monitoring.
        // Only a link-local address can be shared, so a numbered add never
        // searches the table.
        let sharing = self.peers_sharing_address(&peer_key);
        let bmp_policy = if sharing.is_empty() {
            None
        } else {
            self.bmp_identity_conflict()
        };
        let bmp_excluded = match (
            bmp_policy,
            bmp_policy.and_then(|_| self.bmp_identity_holder_of(&sharing)),
        ) {
            (Some(crate::config::BmpIdentityConflict::Refuse), Some(holder)) => {
                self.metrics.record_bmp_identity_conflict(false);
                return Err(PeerLifecycleError::Invalid(format!(
                    "bmp_identity_conflict: peer {peer_key} uses {}, which {holder} \
                     holds, and BMP collectors cannot tell the two sessions apart",
                    config.address
                )));
            }
            (Some(crate::config::BmpIdentityConflict::Exclude), Some(holder)) => {
                warn!(
                    peer = %peer_key, %holder, reason = "bmp_identity_conflict",
                    "admitting a neighbor at an address another BMP-monitored neighbor holds; its session reports nothing to BMP"
                );
                true
            }
            _ => false,
        };
        if let Some(interface) = &config.interface
            && config.scope_id.is_none()
            && let Err(error) = nix::net::if_::if_nametoindex(interface.as_str())
        {
            return Err(PeerLifecycleError::Invalid(format!(
                "peer {peer_key} interface {interface:?} cannot be resolved: {error}"
            )));
        }

        let (mut transport, label, peer_group, import_policy, export_policy, next_config) =
            if sync_config_snapshot {
                let mut next_config = self.current_config.clone();
                apply_config_event(
                    &mut next_config,
                    &ConfigEvent::NeighborAdded {
                        config: config.clone(),
                        ack: None,
                    },
                )
                .map_err(|e| PeerLifecycleError::Invalid(e.to_string()))?;
                let neighbor = next_config
                    .neighbors
                    .iter()
                    .find(|neighbor| {
                        neighbor.address == config.address.to_string()
                            && neighbor.interface == config.interface
                    })
                    .ok_or_else(|| {
                        PeerLifecycleError::Internal(format!(
                            "neighbor {peer_key} missing after config snapshot update"
                        ))
                    })?;
                let resolved = next_config
                    .resolve_neighbor(neighbor)
                    .map_err(|e| PeerLifecycleError::Invalid(e.to_string()))?;
                (
                    resolved.transport_config,
                    resolved.label,
                    resolved.peer_group,
                    resolved.import_policy,
                    resolved.export_policy,
                    Some(next_config),
                )
            } else {
                (
                    self.build_transport_config(&config),
                    config.description.clone(),
                    config.peer_group.clone(),
                    config.import_policy.clone(),
                    config.export_policy.clone(),
                    None,
                )
            };

        // Whatever BMP does, state keyed by the bare address (BFD, the TCP
        // MD5/TCP-AO listener keys, and beside a static neighbor the GTSM
        // listener policy and a per-neighbor log level) cannot serve two
        // neighbors at one address: refuse a learned or runtime neighbor
        // that would put such a feature on a shared address.
        if let Some(reason) = self.shared_address_feature_conflict(
            &peer_key,
            next_config.as_ref().unwrap_or(&self.current_config),
        ) {
            return Err(PeerLifecycleError::Invalid(reason));
        }

        // A static neighbor at a retained dynamic neighbor's address is a new
        // neighbor: none of the retained identity carries over, and the
        // retained neighbor goes once the new session has started.
        let replaces_retained = self.retained_dynamic.contains_key(&peer_key);
        transport.neighbor_counters = if replaces_retained {
            rustbgpd_transport::NeighborCounters::default()
        } else {
            self.neighbor_counters_for(&peer_key)
        };
        transport.interface_only = self.interface_only_owns(peer_key.interface.as_deref());
        transport.dampening_admission = self
            .configured_owner_admission_for_static(peer_key.clone(), config.remote_asn)
            .map_err(|error| PeerLifecycleError::Internal(error.to_string()))?;
        let enabled = enabled
            && !transport
                .dampening_admission
                .as_ref()
                .is_some_and(rustbgpd_rib::dampening::DampeningAdmission::is_blocked);
        transport.local_forwarding_state = Some(rustbgpd_transport::ForwardingStateSource::Live(
            self.local_forwarding_state.clone(),
        ));
        let address = config.address;
        let admin_down = config.admin_down.clone();
        let remote_asn = config.remote_asn;
        let description = label;
        let hold_time = Some(transport.peer.hold_time);
        let max_prefixes = transport.max_prefixes;

        let (rib_peer, new_rib_peer) =
            self.static_rib_peer_slot(&peer_key, transport.interface_only, replaces_retained);
        transport.rib_peer = rib_peer;

        if replaces_retained {
            // The new session emits under the member's label from its spawn:
            // the member's series go first. The member itself goes only once
            // the session has started; a failed start keeps it, with its RIB
            // series, which the RIB's teardown of the member settles once it
            // is retired.
            let label = self.peer_metric_label(&peer_key);
            self.metrics
                .reap_peer_identity_series(&label, peer_key.interface.as_deref().unwrap_or(""));
            self.metrics.reap_non_rib_peer_series(&label);
        }
        self.admit_deferred_rib_updates_for(&peer_key).await;
        let session_id = self.allocate_session_id();
        #[cfg(test)]
        if let Some(observations) = &mut self.dataset_generations_at_peer_construction {
            for handle in self.current_config.policy.dataset_bindings.handles() {
                observations.push((
                    peer_key.clone(),
                    handle.name().to_string(),
                    handle.pin().generation,
                ));
            }
        }
        let handle = PeerHandle::spawn_at_tcp_ao_generation(
            transport.clone(),
            self.metrics.clone(),
            self.rib_tx.clone(),
            import_policy.clone(),
            export_policy.clone(),
            Some(self.session_notify_tx.clone()),
            Some(self.session_notification_event_tx.clone()),
            Some(self.session_lifecycle_tx.clone()),
            if bmp_excluded {
                None
            } else {
                self.bmp_tx.clone()
            },
            self.validation_rx.clone(),
            false,
            SessionIdentity::primary(session_id),
            self.tcp_ao_generation,
        );

        // ADR-0067 step 4b — strict BFD: create/store the peer but withhold BGP
        // establishment until BFD is Up. Non-strict (the default) starts now
        // only when the peer is administratively enabled.
        // The handle is spawned Idle either way; `start()` is what begins the
        // FSM, so withholding is simply not sending it yet. Strict BFD is
        // level-triggered: always pre-hold on add/enable, then release when the
        // BFD actor confirms the current permitted state through a resync ack
        // or a fresh transition.
        let withhold = enabled && self.bfd_should_withhold(&address);
        let handle = match self
            .provision_new_peer_session(
                &peer_key,
                enabled,
                enabled && !withhold,
                handle,
                "static peer start failure",
            )
            .await
        {
            Ok(handle) => handle,
            Err(error) => {
                if new_rib_peer && let Some(peer) = transport.rib_peer.get() {
                    self.release_unused_rib_peer(peer);
                }
                if replaces_retained {
                    // The member stays; only its reaped retention gauge comes back.
                    self.publish_retained_dynamic(&peer_key);
                }
                return Err(PeerLifecycleError::Internal(format!(
                    "failed to start peer: {error}"
                )));
            }
        };

        if replaces_retained {
            // The member's deletion is admitted before this add completes.
            // The new session sends the RIB nothing until it is Established,
            // a BGP handshake later, so the deletion reaches the RIB first
            // unless older queued cleanup holds its admission that long.
            self.retire_replaced_retained_dynamic(&peer_key);
            self.admit_deferred_rib_updates_for(&peer_key).await;
        }
        info!(peer = %address, %remote_asn, "peer added dynamically");
        if bmp_excluded {
            self.metrics.record_bmp_identity_conflict(true);
            self.bmp_excluded.insert(peer_key.clone());
        } else {
            self.bmp_excluded.remove(&peer_key);
        }
        self.publish_bmp_excluded_metric();
        let tcp_ao_protected = transport.tcp_ao.is_some();
        self.peers.insert(
            peer_key.clone(),
            ManagedPeer::new(
                handle,
                session_id,
                ManagedPeerState {
                    policy_known_down: false,
                    remote_asn,
                    description,
                    peer_group,
                    enabled,
                    admin_down,
                    hold_time,
                    max_prefixes,
                    max_prefix_restart_seconds: config.max_prefix_restart_seconds,
                    transport_config: transport,
                    import_policy,
                    export_policy,
                    pending_inbound: None,
                    is_dynamic: false,
                    // ADR-0112: static neighbors only — this path never accepts a
                    // dynamic range's child, so the configured `remote_asn` is
                    // still the authoritative classification input.
                    rfc8212_external: self.current_config.rfc8212_external_asn(remote_asn),
                    tcp_ao_protected,
                    tcp_ao_rotation: rustbgpd_transport::TcpAoRotationStatus {
                        desired: self.tcp_ao_generation,
                        applied: self.tcp_ao_generation,
                        phase: rustbgpd_transport::TcpAoRotationPhase::Idle,
                        last_error: None,
                    },
                    accepted_dynamic_range: None,
                    pending_refresh: false,
                    pending_export_apply: false,
                    advertise_graceful_shutdown: false,
                },
            ),
        );
        self.retain_neighbor_counters(&peer_key);
        self.register_session(session_id, &peer_key);
        self.sync_owned_session_metrics(&peer_key).await;
        self.publish_peer_info_metric(&peer_key);

        if let Some(next_config) = next_config {
            self.replace_current_config(next_config);
        }
        // ADR-0112: the peer is registered with its resolved chains, so the
        // directional gauges have something to read.
        self.refresh_rfc8212_policy_metrics(&peer_key);

        if enabled {
            // ADR-0067 step 4: (re-)arm this peer's BFD session. Critically
            // covers the delete→add reconfigure cycle — a re-added BFD peer
            // must clear its disabled mark so the actor restarts the session.
            // During reload, publication waits for the generation's BFD commit.
            self.set_bfd_peer_disabled(address, false);
            // For a strict peer, mark it pre-held so the first BFD Up releases
            // the withhold via the normal up→start path.
            if withhold {
                self.mark_bfd_withheld(address);
                info!(peer = %address, "strict BFD — withholding BGP establishment until BFD is Up");
            }
        } else {
            // A disabled re-add is a live config object only; keep BGP stopped
            // and keep the BFD desired session disabled until EnablePeer.
            self.set_bfd_peer_disabled(address, true);
        }
        if emit_presence {
            self.publish_peer_added_event(&peer_key);
        }
        let current_enabled = self
            .peers
            .get(&peer_key)
            .expect("newly installed peer must remain registered")
            .enabled;
        let (event_type, admin_state) = if current_enabled {
            (SessionLifecycleEventType::PeerEnabled, "enabled")
        } else {
            (SessionLifecycleEventType::PeerDisabled, "disabled")
        };
        self.publish_peer_lifecycle_event(
            &peer_key,
            event_type,
            format!("peer {peer_key} added administratively {admin_state}"),
        );
        Ok(())
    }

    /// Runtime (RPC / config-transaction) entry to [`Self::delete_peer`].
    /// The peer's inbound MD5 key and GTSM selector live on the BGP listener,
    /// which only startup and SIGHUP reload can update — a runtime delete
    /// would leave the stale host key installed (fail-closed, but a
    /// delete-then-re-add wedges the re-added peer's inbound half until
    /// SIGHUP). SIGHUP reconcile removals use [`Self::delete_peer`] directly:
    /// the reload coordinator replaces the listener inventory in the same
    /// coordinated apply.
    pub(super) async fn delete_peer_runtime(
        &mut self,
        peer: PeerKey,
        sync_config_snapshot: bool,
    ) -> Result<PeerManagerNeighborConfig, PeerLifecycleError> {
        // ADR-0142: discovery owns an interface-only neighbor's peer; deleting
        // it here would only leave discovery bound to a session that is gone.
        if let Some(interface) = self.unnumbered_owner_of(&peer) {
            return Err(PeerLifecycleError::Precondition(format!(
                "peer {peer} belongs to the interface-only neighbor on {interface}; delete that \
                 neighbor by its interface (empty address, interface \"{interface}\")"
            )));
        }
        if self.peers.get(&peer).is_some_and(|managed| {
            managed.transport_config.md5_password.is_some()
                || managed.transport_config.ttl_security_hops.is_some()
                || managed.transport_config.tcp_mss.is_some()
        }) {
            return Err(PeerLifecycleError::RestartRequired(format!(
                "peer {peer} resolves md5_password, ttl_security, or tcp_mss; runtime peer CRUD \
                 cannot change inbound listener enforcement — use the config file and SIGHUP \
                 for md5_password/ttl_security, or restart for tcp_mss"
            )));
        }
        self.delete_peer(peer, sync_config_snapshot).await
    }

    pub(super) async fn delete_peer(
        &mut self,
        peer: PeerKey,
        sync_config_snapshot: bool,
    ) -> Result<PeerManagerNeighborConfig, PeerLifecycleError> {
        self.delete_peer_checked(peer, sync_config_snapshot, None, true, None, None)
            .await
    }

    /// Runtime (config-transaction) entry to [`Self::reconfigure_peer`].
    /// Unlike SIGHUP reload — which replaces the listener MD5/GTSM inventory
    /// in the same coordinated apply — runtime paths cannot update the BGP
    /// listener, so a change to those fields or startup-owned MSS must fail
    /// loudly instead of leaving the listener enforcing the old inventory.
    pub(super) async fn reconfigure_peer_runtime(
        &mut self,
        config: PeerManagerNeighborConfig,
    ) -> Result<PeerManagerNeighborConfig, PeerLifecycleError> {
        let peer = PeerKey::new(config.address, config.interface.clone());
        if let Some(managed) = self.peers.get(&peer)
            && (managed.transport_config.md5_password != config.md5_password
                || managed.transport_config.ttl_security_hops != config.ttl_security_hops
                || managed.transport_config.tcp_mss != config.tcp_mss)
        {
            return Err(PeerLifecycleError::RestartRequired(format!(
                "peer {peer} changes md5_password, ttl_security, or tcp_mss; runtime peer \
                 reconfigure cannot change inbound listener enforcement — use the config file \
                 and SIGHUP for md5_password/ttl_security, or restart for tcp_mss"
            )));
        }
        self.reconfigure_peer(config).await
    }

    pub(super) async fn reconfigure_peer(
        &mut self,
        config: PeerManagerNeighborConfig,
    ) -> Result<PeerManagerNeighborConfig, PeerLifecycleError> {
        let mut effect = ReconfigurePeerFailureEffect::NoEffect;
        self.reconfigure_peer_classified(config, &mut effect, None, &mut None)
            .await
    }

    async fn reconfigure_peer_classified(
        &mut self,
        config: PeerManagerNeighborConfig,
        effect: &mut ReconfigurePeerFailureEffect,
        rollback_config: Option<&crate::config::Config>,
        dataset_prior: &mut Option<crate::config::DatasetRollback>,
    ) -> Result<PeerManagerNeighborConfig, PeerLifecycleError> {
        let peer = PeerKey::new(config.address, config.interface.clone());
        #[cfg(any(test, debug_assertions))]
        if (cfg!(test) || rollback_config.is_some())
            && let Some(remaining) = self.inject_reconfigure_failures.get_mut(&peer)
        {
            if *remaining == 0 {
                // Unit tests retain their existing counter semantics. The
                // debug daemon consumes its selected failure exactly once.
                #[cfg(not(test))]
                self.inject_reconfigure_failures.remove(&peer);
                return Err(PeerLifecycleError::Internal(format!(
                    "injected reconfigure failure for {peer}"
                )));
            }
            *remaining -= 1;
        }
        self.invalidate_max_prefix_restart(&peer);
        let (was_enabled, graceful_shutdown, enabled) = self
            .peers
            .get(&peer)
            .map(|managed| {
                (
                    managed.enabled,
                    managed.advertise_graceful_shutdown,
                    config_admin_enable(managed, &config).unwrap_or(managed.enabled),
                )
            })
            .ok_or_else(|| PeerLifecycleError::NotFound(peer.clone()))?;

        let previous = self
            .delete_peer_checked(
                peer.clone(),
                false,
                config.tcp_ao.as_ref(),
                false,
                Some(&config.discard_path_attributes),
                replacement_stop_reason(was_enabled, enabled, &config),
            )
            .await?;
        if let Err(add_error) = self.add_peer_with_admin_state(config, false, enabled).await {
            if let Some(prior) = dataset_prior.take() {
                prior.restore();
            }
            return match self
                .restore_reconfigured_peer(
                    peer.clone(),
                    previous.clone(),
                    was_enabled,
                    graceful_shutdown,
                    rollback_config,
                )
                .await
            {
                Ok(()) => {
                    *effect = ReconfigurePeerFailureEffect::FullyCompensated;
                    Err(PeerLifecycleError::Internal(format!(
                        "failed to add reconfigured peer {peer}: {add_error}; previous peer restored"
                    )))
                }
                Err(restore_error) => {
                    *effect = ReconfigurePeerFailureEffect::CompensationAmbiguous;
                    Err(PeerLifecycleError::Internal(format!(
                        "failed to add reconfigured peer {peer}: {add_error}; restore previous peer failed: {restore_error}"
                    )))
                }
            };
        }

        if let Err(state_error) = self
            .apply_reconfigured_peer_state(peer.clone(), graceful_shutdown)
            .await
        {
            if let Some(prior) = dataset_prior.take() {
                prior.restore();
            }
            return match self
                .restore_reconfigured_peer(
                    peer.clone(),
                    previous.clone(),
                    was_enabled,
                    graceful_shutdown,
                    rollback_config,
                )
                .await
            {
                Ok(()) => {
                    *effect = ReconfigurePeerFailureEffect::FullyCompensated;
                    Err(PeerLifecycleError::Internal(format!(
                        "failed to restore runtime state for reconfigured peer {peer}: {state_error}; previous peer restored"
                    )))
                }
                Err(restore_error) => {
                    *effect = ReconfigurePeerFailureEffect::CompensationAmbiguous;
                    Err(PeerLifecycleError::Internal(format!(
                        "failed to restore runtime state for reconfigured peer {peer}: {state_error}; restore previous peer failed: {restore_error}"
                    )))
                }
            };
        }

        Ok(previous)
    }

    /// LAN-341: apply a hot-applicable-only config change to a live static
    /// peer in place — the counterpart to [`Self::reconfigure_peer`] for
    /// edits whose every changed field is reload-matrix `live`
    /// (hot-applied). The session task, its TCP connection, and the FSM
    /// are untouched: per-session runtime knobs swap through
    /// `PeerCommand::UpdateRuntimeConfig`, and policy chains go through
    /// the same live-policy seam as gRPC chain edits (Route Refresh +
    /// Adj-RIB-Out re-emit included).
    ///
    /// The caller (reload's changed-neighbor partition) guarantees only
    /// hot fields differ; this function doesn't re-verify, it just never
    /// touches anything session-bound (identity, OPEN-negotiated, or
    /// socket-scoped fields are copied from `config` into the stored
    /// transport config by the next rebuild path, which resolves from the
    /// config snapshot anyway).
    #[cfg(test)]
    pub(super) async fn hot_update_peer(
        &mut self,
        config: PeerManagerNeighborConfig,
    ) -> Result<(), PeerLifecycleError> {
        let peer = PeerKey::new(config.address, config.interface.clone());
        if self
            .peers
            .get(&peer)
            .ok_or_else(|| PeerLifecycleError::NotFound(peer.clone()))?
            .is_dynamic
        {
            return Err(PeerLifecycleError::Invalid(format!(
                "hot update target {peer} is a dynamic peer; reload reconciles static neighbors only"
            )));
        }
        self.hot_update_peer_in_place(config).await
    }

    pub(super) async fn hot_update_peer_owned(
        &mut self,
        config: PeerManagerNeighborConfig,
    ) -> rustbgpd_api::peer_types::OwnedHotUpdatePeerOutcome {
        use rustbgpd_api::peer_types::OwnedHotUpdatePeerOutcome;

        let peer = PeerKey::new(config.address, config.interface.clone());
        let Some(managed) = self.peers.get(&peer) else {
            return OwnedHotUpdatePeerOutcome::RejectedNoEffect(PeerLifecycleError::NotFound(peer));
        };
        if managed.is_dynamic {
            return OwnedHotUpdatePeerOutcome::RejectedNoEffect(PeerLifecycleError::Invalid(
                format!(
                    "hot update target {peer} is a dynamic peer; reload reconciles static neighbors only"
                ),
            ));
        }
        self.hot_update_peer_in_place_owned(config).await
    }

    /// Classified in-place application for preflighted static or dynamic peers.
    /// External `HotUpdatePeer` commands retain the static-only guard above.
    pub(super) async fn hot_update_peer_in_place_owned(
        &mut self,
        config: PeerManagerNeighborConfig,
    ) -> rustbgpd_api::peer_types::OwnedHotUpdatePeerOutcome {
        use rustbgpd_api::peer_types::OwnedHotUpdatePeerOutcome;

        let peer = PeerKey::new(config.address, config.interface.clone());
        if !self.peers.contains_key(&peer) {
            return OwnedHotUpdatePeerOutcome::RejectedNoEffect(PeerLifecycleError::NotFound(peer));
        }
        match self.hot_update_peer_in_place(config).await {
            Ok(()) => OwnedHotUpdatePeerOutcome::Success,
            Err(error) => OwnedHotUpdatePeerOutcome::KnownDivergence(error),
        }
    }

    /// The applier half of `Self::hot_update_peer`, without the
    /// static-only guard.
    ///
    /// Everything it touches is per-session runtime state that an accepted
    /// dynamic peer holds exactly like a static one, so the peer-group hot
    /// path reaches dynamic inheritors through here. The guard above stays
    /// on the reload entry point, where a dynamic target means the static
    /// neighbor reconcile and the managed-peer set disagree.
    #[expect(
        clippy::too_many_lines,
        reason = "one linear pass: change detection, policy seam, knob apply, export refresh, bookkeeping"
    )]
    pub(super) async fn hot_update_peer_in_place(
        &mut self,
        config: PeerManagerNeighborConfig,
    ) -> Result<(), PeerLifecycleError> {
        let peer = PeerKey::new(config.address, config.interface.clone());
        #[cfg(test)]
        if let Some(remaining) = self.inject_hot_update_failures.get_mut(&peer) {
            if *remaining == 0 {
                return Err(PeerLifecycleError::Internal(format!(
                    "injected hot update failure for {peer}"
                )));
            }
            *remaining -= 1;
        }
        let (
            knobs_changed,
            export_knobs_changed,
            remove_private_as_changed,
            policies_changed,
            restart_policy_changed,
            admin_enable,
        ) = {
            let managed = self
                .peers
                .get(&peer)
                .ok_or_else(|| PeerLifecycleError::NotFound(peer.clone()))?;
            let admin_enable = config_admin_enable(managed, &config);
            let tc = &managed.transport_config;
            // The export-affecting subset: `local_ipv6_nexthop` decides the
            // exact-export preflight's `MissingIpv6NextHop` suppression and
            // `remove_private_as` changes the wire AS_PATH of routes already
            // in Adj-RIB-Out, so a change to either must force an outbound
            // re-probe below.
            let export_knobs_changed = tc.local_ipv6_nexthop != config.local_ipv6_nexthop
                || tc.remove_private_as != config.remove_private_as;
            (
                tc.max_prefixes != config.max_prefixes
                    || tc.max_prefixes_ipv4 != config.max_prefixes_ipv4
                    || tc.max_prefixes_ipv6 != config.max_prefixes_ipv6
                    || tc.max_prefixes_received_ipv4 != config.max_prefixes_received_ipv4
                    || tc.max_prefixes_received_ipv6 != config.max_prefixes_received_ipv6
                    || tc.max_prefixes_family != config.max_prefixes_family
                    || tc.max_prefix_action != config.max_prefix_action
                    || tc.max_prefix_warning_percent != config.max_prefix_warning_percent
                    || tc.gr_stale_routes_time != config.gr_stale_routes_time
                    || tc.gr_peer_restart_time_max != config.gr_peer_restart_time_max
                    || export_knobs_changed,
                export_knobs_changed,
                tc.remove_private_as != config.remove_private_as,
                managed.import_policy != config.import_policy
                    || managed.export_policy != config.export_policy,
                managed.max_prefix_restart_seconds != config.max_prefix_restart_seconds,
                admin_enable,
            )
        };

        // Policy first: the live-policy seam compensates its own failures.
        // A later knob or refresh failure can leave session effects applied
        // before bookkeeping. Owned callers must classify that as divergence.
        if policies_changed {
            self.update_runtime_policies_fatal(
                peer.clone(),
                config.import_policy.clone(),
                config.export_policy.clone(),
            )
            .await
            .map_err(PeerLifecycleError::Internal)?;
        }

        let mut ipv6_unlock_only = false;
        if knobs_changed {
            let managed = self
                .peers
                .get(&peer)
                .ok_or_else(|| PeerLifecycleError::NotFound(peer.clone()))?;
            ipv6_unlock_only = managed
                .handle()
                .update_runtime_config_timeout(
                    config.max_prefixes,
                    config.max_prefixes_ipv4,
                    config.max_prefixes_ipv6,
                    config.max_prefixes_received_ipv4,
                    config.max_prefixes_received_ipv6,
                    config.max_prefixes_family,
                    config.max_prefix_action,
                    config.max_prefix_warning_percent,
                    config.gr_stale_routes_time,
                    config.gr_peer_restart_time_max,
                    config.local_ipv6_nexthop,
                    config.remove_private_as,
                    PEER_POLICY_UPDATE_TIMEOUT,
                )
                .await
                .map_err(|error| {
                    PeerLifecycleError::Internal(format!(
                        "failed to hot-apply runtime knobs to {peer}: {error}"
                    ))
                })?;
        }

        // Force re-emission after an export-affecting knob swap unless the
        // session already queued the IPv6 family unlock's full-table resync.
        // A simultaneous remove_private_as change still needs the refresh
        // for other already-sendable families. This is the same
        // reason the gshut toggle and live-policy apply refresh: routes the
        // exact-export preflight suppressed under the OLD knobs (e.g.
        // `MissingIpv6NextHop`) are only re-probed, and already-advertised
        // AS_PATHs only re-encoded, on an outbound event. Without this the
        // remediation stays off the wire until unrelated churn or a session
        // bounce. Runs BEFORE bookkeeping: a hard refresh failure returns
        // Err with live knobs changed but stored transport config still old.
        // Applying the stored prior through normal change detection cannot
        // prove restoration; owned callers must fence this uncertainty.
        if export_knobs_changed {
            let addr = peer.address;
            let confirm_unlock = ipv6_unlock_only && !remove_private_as_changed;
            match self
                .refresh_peer_outbound_in_rib(
                    &peer,
                    OperatorReadAdmission::Fenced {
                        reason: "session knobs changed but manager metadata awaits refresh acknowledgement",
                    },
                    confirm_unlock,
                )
                .await
            {
                Err(error) => {
                    return Err(PeerLifecycleError::Internal(format!(
                        "failed to refresh outbound routes after hot-applying export knobs to {peer}: {error}"
                    )));
                }
                Ok(Err(error)) => {
                    if confirm_unlock && !matches!(error, RibCommandError::NotFound(_)) {
                        return Err(PeerLifecycleError::Internal(format!(
                            "RIB did not confirm IPv6 unlock for {peer}: {error}"
                        )));
                    }
                    // "not registered for outbound updates" is expected for a
                    // peer not yet Established — the next PeerUp emits from
                    // the updated config.
                    debug!(
                        peer = %addr, error = %error,
                        "RIB declined export-knob refresh (peer likely not yet Established)"
                    );
                }
                Ok(Ok(())) => {}
            }
        }

        // The actor runs this method serially, so a deadline cannot fire while
        // the awaited updates above are in flight. Reconcile the incident's
        // countdown only after every fallible apply step succeeds: an accepted
        // duration change reschedules an armed countdown to now + new (the
        // superseded deadline is generation-fenced and can never fire),
        // removing the duration cancels it, and a rejected change or an
        // unrelated hot edit keeps the prior recovery timing intact.
        if restart_policy_changed {
            self.rearm_max_prefix_restart(&peer, config.max_prefix_restart_seconds);
        }

        // A changed config `admin_down` reuses the operator disable/enable
        // paths: setting it sends Cease/Administrative Shutdown with the
        // configured RFC 9003 reason, clearing it starts the session.
        // A config transition stays pending until its Stop is enqueued: a
        // failed `disable_peer` leaves `enabled` false but `admin_down`
        // unrecorded, so the next reload retries it whatever `enabled` says.
        let (enabled, pending_edge) = self.peers.get(&peer).map_or((false, false), |managed| {
            (
                managed.enabled,
                config.restore_admin_enabled.is_none()
                    && managed.admin_down.is_some() != config.admin_down.is_some(),
            )
        });
        match admin_enable {
            Some(false) if enabled || pending_edge => {
                self.disable_peer(peer.clone(), admin_down_shutdown_communication(&config))
                    .await?;
            }
            Some(true) if !enabled => self.enable_peer(peer.clone()).await?,
            _ => {}
        }

        // Manager-side bookkeeping so `rbgp neighbor list` and any later
        // session rebuild see the new values.
        let managed = self
            .peers
            .get_mut(&peer)
            .ok_or_else(|| PeerLifecycleError::NotFound(peer.clone()))?;
        managed.description.clone_from(&config.description);
        managed.admin_down.clone_from(&config.admin_down);
        managed.max_prefixes = config.max_prefixes;
        managed.max_prefix_restart_seconds = config.max_prefix_restart_seconds;
        managed.transport_config.max_prefixes = config.max_prefixes;
        managed.transport_config.max_prefixes_ipv4 = config.max_prefixes_ipv4;
        managed.transport_config.max_prefixes_ipv6 = config.max_prefixes_ipv6;
        managed.transport_config.max_prefixes_received_ipv4 = config.max_prefixes_received_ipv4;
        managed.transport_config.max_prefixes_received_ipv6 = config.max_prefixes_received_ipv6;
        managed.transport_config.max_prefixes_family = config.max_prefixes_family;
        managed.transport_config.max_prefix_action = config.max_prefix_action;
        managed.transport_config.max_prefix_warning_percent = config.max_prefix_warning_percent;
        managed.transport_config.gr_stale_routes_time = config.gr_stale_routes_time;
        managed.transport_config.gr_peer_restart_time_max = config.gr_peer_restart_time_max;
        managed.transport_config.local_ipv6_nexthop = config.local_ipv6_nexthop;
        managed.transport_config.remove_private_as = config.remove_private_as;
        managed.transport_config.fast_external_failover = config.fast_external_failover;
        managed
            .transport_config
            .link_state
            .set_enabled(config.fast_external_failover);
        self.publish_peer_info_metric(&peer);
        info!(%peer, "hot-applied neighbor config change in place (no session rebuild)");
        Ok(())
    }

    pub(super) async fn apply_peer_reshape_snapshot(
        &mut self,
        targets: Vec<PeerManagerNeighborConfig>,
    ) -> Result<Vec<PeerManagerNeighborConfig>, PeerLifecycleError> {
        match self
            .apply_peer_reshape_snapshot_classified(targets, None, &mut None)
            .await
        {
            PeerReshapeSnapshotOutcome::Success(priors) => Ok(priors),
            PeerReshapeSnapshotOutcome::RejectedNoEffect(error)
            | PeerReshapeSnapshotOutcome::FullyCompensated(error)
            | PeerReshapeSnapshotOutcome::CompensationAmbiguous(error) => Err(error),
        }
    }

    /// Reshape every target peer as one operation: one import-roster
    /// publication for the whole cohort and its compensation.
    pub(super) async fn apply_peer_reshape_snapshot_classified(
        &mut self,
        targets: Vec<PeerManagerNeighborConfig>,
        rollback_config: Option<&crate::config::Config>,
        dataset_prior: &mut Option<crate::config::DatasetRollback>,
    ) -> PeerReshapeSnapshotOutcome {
        let batch = self.peers.begin_batch();
        let result = Box::pin(self.apply_peer_reshape_snapshot_unbatched(
            targets,
            rollback_config,
            dataset_prior,
        ))
        .await;
        self.peers.end_batch(batch);
        result
    }

    async fn apply_peer_reshape_snapshot_unbatched(
        &mut self,
        targets: Vec<PeerManagerNeighborConfig>,
        rollback_config: Option<&crate::config::Config>,
        dataset_prior: &mut Option<crate::config::DatasetRollback>,
    ) -> PeerReshapeSnapshotOutcome {
        let mut seen = BTreeSet::new();
        for target in &targets {
            let peer = PeerKey::new(target.address, target.interface.clone());
            if !seen.insert(peer.clone()) {
                return PeerReshapeSnapshotOutcome::RejectedNoEffect(PeerLifecycleError::Invalid(
                    format!("peer reshape target {peer} appears more than once"),
                ));
            }
            let Some(managed) = self.peers.get(&peer) else {
                return PeerReshapeSnapshotOutcome::RejectedNoEffect(PeerLifecycleError::NotFound(
                    peer,
                ));
            };
            if managed.transport_config.tcp_ao != target.tcp_ao {
                return PeerReshapeSnapshotOutcome::RejectedNoEffect(
                    PeerLifecycleError::RestartRequired(format!(
                        "peer reshape target {peer} changes tcp_ao; TCP-AO changes require a daemon restart"
                    )),
                );
            }
            // Inbound MD5 keys and GTSM selectors live on the BGP listener and
            // require coordinated SIGHUP; MSS is startup-only. A runtime reshape
            // that changed them would leave the
            // listener enforcing the old inventory (stale password accepted
            // inbound, new password rejected).
            if managed.transport_config.md5_password != target.md5_password
                || managed.transport_config.ttl_security_hops != target.ttl_security_hops
                || managed.transport_config.tcp_mss != target.tcp_mss
            {
                return PeerReshapeSnapshotOutcome::RejectedNoEffect(
                    PeerLifecycleError::RestartRequired(format!(
                        "peer reshape target {peer} changes md5_password, ttl_security, or \
                         tcp_mss; runtime reshape cannot change inbound listener enforcement — \
                         use the config file and SIGHUP for md5_password/ttl_security, or restart \
                         for tcp_mss"
                    )),
                );
            }
            // Defense in depth: the transaction executor already gates dynamic
            // ranges out of reshape targets, but reconfigure's delete/re-add
            // semantics are wrong for an ephemeral dynamic peer (it would change
            // `is_dynamic` lifecycle/persistence), so refuse one here too.
            if managed.is_dynamic {
                return PeerReshapeSnapshotOutcome::RejectedNoEffect(PeerLifecycleError::Invalid(
                    format!(
                        "peer reshape target {peer} is a dynamic peer; reshape transactions reconfigure static neighbors only"
                    ),
                ));
            }
        }

        let mut priors = Vec::with_capacity(targets.len());
        for target in targets {
            let peer = PeerKey::new(target.address, target.interface.clone());
            let mut effect = ReconfigurePeerFailureEffect::NoEffect;
            match self
                .reconfigure_peer_classified(target, &mut effect, rollback_config, dataset_prior)
                .await
            {
                Ok(previous) => priors.push(previous),
                Err(error) => {
                    let had_prior_effects = !priors.is_empty();
                    // Prior session construction must observe prior dataset
                    // contents, including recovery owned by this inner batch.
                    if let Some(prior) = dataset_prior.take() {
                        prior.restore();
                    }
                    let restore = self
                        .restore_peer_reshape_priors(priors, rollback_config)
                        .await;
                    let restore_failed = restore.is_err();
                    let composed = match restore {
                        Ok(()) => PeerLifecycleError::Internal(format!(
                            "failed to reconfigure peer {peer}: {error}; prior peers restored"
                        )),
                        Err(restore_error) => PeerLifecycleError::Internal(format!(
                            "failed to reconfigure peer {peer}: {error}; {restore_error}"
                        )),
                    };
                    return if restore_failed
                        || matches!(effect, ReconfigurePeerFailureEffect::CompensationAmbiguous)
                    {
                        PeerReshapeSnapshotOutcome::CompensationAmbiguous(composed)
                    } else if had_prior_effects
                        || matches!(effect, ReconfigurePeerFailureEffect::FullyCompensated)
                    {
                        PeerReshapeSnapshotOutcome::FullyCompensated(composed)
                    } else {
                        PeerReshapeSnapshotOutcome::RejectedNoEffect(composed)
                    };
                }
            }
        }
        PeerReshapeSnapshotOutcome::Success(priors)
    }

    /// Restore reshape priors as one operation: one import-roster
    /// publication for the whole sweep.
    pub(super) async fn restore_peer_reshape_priors(
        &mut self,
        priors: Vec<PeerManagerNeighborConfig>,
        rollback_config: Option<&crate::config::Config>,
    ) -> Result<(), PeerLifecycleError> {
        let batch = self.peers.begin_batch();
        let result =
            Box::pin(self.restore_peer_reshape_priors_unbatched(priors, rollback_config)).await;
        self.peers.end_batch(batch);
        result
    }

    async fn restore_peer_reshape_priors_unbatched(
        &mut self,
        priors: Vec<PeerManagerNeighborConfig>,
        rollback_config: Option<&crate::config::Config>,
    ) -> Result<(), PeerLifecycleError> {
        // Internal cohort compensation must build from the accepted generation,
        // even while the enclosing reload still owns the candidate snapshot.
        let prior_bfd_lookup = self.set_bfd_rollback_lookup(true);
        let candidate =
            rollback_config.map(|prior| Box::new(self.replace_current_config(prior.clone())));
        // Replays the captured prior configs in reverse of the apply order.
        // `reconfigure_peer` re-reads the live enabled / graceful-shutdown state
        // and re-applies it, so rollback preserves the peer's current admin and
        // GShut state rather than resurrecting a stale transient toggle. A
        // prior also carries the admin state captured before the reshape,
        // which `config_admin_enable` restores exactly.
        //
        // Best-effort: a failed restore does not stop the sweep — every prior
        // is still attempted, so one stuck member cannot strand the others in
        // the reshaped state. Per ADR-0081 the aggregated error names exactly
        // which members were left reshaped; members it does not name were
        // restored to their prior config.
        let total = priors.len();
        let mut failures = Vec::new();
        for prior in priors.into_iter().rev() {
            let peer = PeerKey::new(prior.address, prior.interface.clone());
            if let Err(error) = self.reconfigure_peer(prior).await {
                failures.push(format!("{peer}: {error}"));
            }
        }
        if let Some(candidate) = candidate {
            self.replace_current_config(*candidate);
        }
        self.set_bfd_rollback_lookup(prior_bfd_lookup);
        if failures.is_empty() {
            return Ok(());
        }
        Err(PeerLifecycleError::Internal(format!(
            "peer reshape rollback failed for {} of {total} prior peers \
             (unnamed priors were restored; each named member's state is \
             described by its error): {}",
            failures.len(),
            failures.join("; ")
        )))
    }

    /// Gracefully reset the live dynamic sessions accepted by `ranges` so
    /// they re-accept under the current (already staged) runtime config.
    ///
    /// The dynamic counterpart of [`Self::apply_peer_reshape_snapshot`]: an
    /// accepted dynamic peer cannot be delete/re-added — it exists only
    /// because the remote dialed in, and `delete_peer_checked` rejects
    /// dynamic targets so the `dynamic_neighbor_limit` slot accounting stays
    /// owned by the `BackToIdle` reap path. Instead, each matched peer is
    /// sent a graceful stop (Cease NOTIFICATION carrying an RFC 9003
    /// shutdown communication) with its admin state untouched; the session's
    /// `BackToIdle` notification then drives the normal dynamic auto-removal
    /// (slot decrement, dead-letter carry-over, metric reaping), and the
    /// remote's reconnect is re-accepted by `handle_inbound`, which resolves
    /// the session config from `current_config` — the staged candidate.
    ///
    /// Best-effort by contract: this runs only after the owning transaction
    /// persisted, so per-peer signaling failures are reported in the outcome
    /// rather than failing the committed transaction. A peer that could not
    /// be signaled keeps its running session config until it reconnects (the
    /// same documented semantics that SIGHUP and targeted peer-group RPCs
    /// keep for session-shaping dynamic peer-group edits). Admin-disabled
    /// dynamic peers are skipped: they have no running session, and `BackToIdle`
    /// deliberately keeps them un-reaped.
    #[expect(
        clippy::too_many_lines,
        reason = "one sweep: member selection, per-member purge-or-stop ordering, and outcome reporting"
    )]
    pub(super) async fn bounce_dynamic_peers_for_ranges(
        &mut self,
        ranges: &[DynamicRangeTarget],
        purge_ranges: &[DynamicRangeTarget],
    ) -> DynamicPeerBounceOutcome {
        let mut outcome = DynamicPeerBounceOutcome::default();
        if ranges.is_empty() {
            return outcome;
        }

        let peer_groups: BTreeSet<_> = ranges
            .iter()
            .map(|range| range.peer_group.as_str())
            .collect();
        let purge_ranges: BTreeSet<_> = purge_ranges
            .iter()
            .map(|range| (range.addr, range.prefix_len, range.peer_group.as_str()))
            .collect();
        for peer_group in peer_groups {
            self.sync_dynamic_max_prefix_restart_for_group(peer_group);
        }

        let mut matched: Vec<PeerKey> = self
            .peers
            .iter()
            .filter(|(_, managed)| {
                managed.is_dynamic
                    && managed.enabled
                    && managed
                        .accepted_dynamic_range
                        .as_ref()
                        .is_some_and(|accepted| {
                            ranges.iter().any(|range| {
                                range.addr == accepted.addr
                                    && range.prefix_len == accepted.prefix_len
                                    && range.peer_group == accepted.peer_group
                            })
                        })
            })
            .map(|(key, _)| key.clone())
            .collect();
        matched.sort();

        let reason = rustbgpd_wire::notification::encode_shutdown_communication(
            "peer-group configuration change",
        );
        let mut signals = Vec::with_capacity(matched.len());
        for peer_key in &matched {
            let managed = &self.peers[peer_key];
            let purge_routes = managed
                .accepted_dynamic_range
                .as_ref()
                .is_some_and(|accepted| {
                    purge_ranges.contains(&(
                        accepted.addr,
                        accepted.prefix_len,
                        accepted.peer_group.as_str(),
                    ))
                });
            let primary = managed.handle().commands_sender();
            let pending = managed
                .pending_inbound
                .as_ref()
                .filter(|_| purge_routes)
                .map(|pending| pending.handle.commands_sender());
            let reason = reason.clone();
            // Bounded sends, all members at once: a session task that has
            // stopped draining commands costs one window for the whole
            // post-persist sweep, not one per member. The sweep is
            // best-effort by contract: a peer that can't be signaled keeps
            // its running config until it reconnects, same as a send error.
            signals.push(async move {
                if !purge_routes {
                    return send_session_command(
                        primary,
                        PeerCommand::Stop {
                            reason: Some(reason),
                        },
                        "stop",
                    )
                    .await
                    .map_err(|error| error.to_string());
                }
                // Collision generations can both have announced routes. Queue
                // the purge on the pending candidate first and only then the
                // primary. The peer-manager actor cannot process either
                // BackToIdle while this sweep awaits command admission, so
                // successful admission to both channels is the ownership
                // fence; later ordinary Shutdown remains FIFO behind each
                // PurgeReset. If pending admission fails, leave the primary
                // untouched so it cannot retire and ordinary-shutdown the
                // unpurged candidate.
                if let Some(pending) = pending {
                    send_session_command(pending, PeerCommand::PurgeReset, "purge reset")
                        .await
                        .map_err(|error| format!("pending session: {error}"))?;
                }
                send_session_command(primary, PeerCommand::PurgeReset, "purge reset")
                    .await
                    .map_err(|error| format!("primary session: {error}"))
            });
        }
        let signaled = self
            .await_session_sweep(futures::future::join_all(signals))
            .await;

        for (peer_key, signaled) in matched.into_iter().zip(signaled) {
            match signaled {
                Ok(()) => {
                    info!(
                        peer = %peer_key,
                        "peer-group reshape: signaled dynamic session to reset; it \
                         re-accepts under the committed config on reconnect"
                    );
                    outcome.signaled += 1;
                }
                Err(error) => {
                    warn!(
                        peer = %peer_key,
                        %error,
                        "peer-group reshape: failed to signal dynamic session reset; \
                         the session keeps its running config until it reconnects"
                    );
                    outcome.failures.push(format!("{peer_key}: {error}"));
                }
            }
        }
        outcome
    }

    pub(super) async fn restore_reconfigured_peer(
        &mut self,
        peer: PeerKey,
        previous: PeerManagerNeighborConfig,
        was_enabled: bool,
        graceful_shutdown: bool,
        rollback_config: Option<&crate::config::Config>,
    ) -> Result<(), PeerLifecycleError> {
        let prior_bfd_lookup = self.set_bfd_rollback_lookup(true);
        let candidate =
            rollback_config.map(|prior| Box::new(self.replace_current_config(prior.clone())));
        let restored = async {
            if let Some(current_enabled) = self.peers.get(&peer).map(|managed| managed.enabled) {
                self.delete_peer_checked(
                    peer.clone(),
                    false,
                    previous.tcp_ao.as_ref(),
                    false,
                    Some(&previous.discard_path_attributes),
                    replacement_stop_reason(current_enabled, was_enabled, &previous),
                )
                .await?;
            }
            self.add_peer_with_admin_state(previous, false, was_enabled)
                .await?;
            self.apply_reconfigured_peer_state(peer, graceful_shutdown)
                .await
        }
        .await;
        if let Some(candidate) = candidate {
            self.replace_current_config(*candidate);
        }
        self.set_bfd_rollback_lookup(prior_bfd_lookup);
        restored
    }

    async fn apply_reconfigured_peer_state(
        &mut self,
        peer: PeerKey,
        graceful_shutdown: bool,
    ) -> Result<(), PeerLifecycleError> {
        // Graceful-shutdown replay is best-effort like normal GSHUT fan-out.
        // The enabled/disabled state itself is applied during add, before a
        // disabled peer can transiently start.
        if graceful_shutdown
            && let Err(error) = self.set_graceful_shutdown(Some(peer.clone()), true).await
        {
            warn!(
                peer = %peer,
                error = %error,
                "failed to replay graceful-shutdown intent after peer reconfigure"
            );
        }
        Ok(())
    }

    /// `reap_metric_series` distinguishes a real peer *deletion* (reap
    /// the peer's per-peer metric series — the peer ceases to exist)
    /// from reconfigure's delete-then-re-add (the peer continues to
    /// exist and keeps its series and counter history).
    pub(super) async fn delete_peer_checked(
        &mut self,
        peer: PeerKey,
        sync_config_snapshot: bool,
        next_tcp_ao: Option<&TcpAoKeyring>,
        reap_metric_series: bool,
        next_discard_path_attributes: Option<&[u8]>,
        stop_reason: Option<bytes::Bytes>,
    ) -> Result<PeerManagerNeighborConfig, PeerLifecycleError> {
        let detached = self
            .detach_peer_for_delete(
                peer,
                sync_config_snapshot,
                next_tcp_ao,
                reap_metric_series,
                next_discard_path_attributes,
                stop_reason,
            )
            .await?;
        Ok(self
            .delete_detached_peers(vec![detached])
            .await
            .pop()
            .expect("one detached peer settles one delete"))
    }

    /// A delete's first half: validate, settle any purge reset, and take the
    /// peer out of the table, its sessions still running. Finish it with
    /// [`Self::delete_detached_peers`], which stops the sessions of many
    /// detached peers at once. To purge-reset many peers at once, use
    /// [`Self::prepare_delete`], [`Self::purge_reset_for_delete`] and
    /// [`Self::detach_prepared`] instead.
    pub(super) async fn detach_peer_for_delete(
        &mut self,
        peer: PeerKey,
        sync_config_snapshot: bool,
        next_tcp_ao: Option<&TcpAoKeyring>,
        reap_metric_series: bool,
        next_discard_path_attributes: Option<&[u8]>,
        stop_reason: Option<bytes::Bytes>,
    ) -> Result<DetachedPeer, PeerLifecycleError> {
        let prepared = self
            .prepare_delete(
                peer,
                sync_config_snapshot,
                next_tcp_ao,
                next_discard_path_attributes,
            )
            .await?;
        if prepared.purge_reset {
            let PurgeOutcome {
                mut results,
                retiring,
            } = self
                .purge_reset_for_delete(std::slice::from_ref(&prepared.peer))
                .await;
            // No other peer was purged, so nothing else is mid-reconfiguration.
            self.retire_purged_candidates(retiring).await;
            results.pop().expect("one purge per prepared peer")?;
        }
        self.detach_prepared(prepared, reap_metric_series, stop_reason)
    }

    /// Validate a delete and build its next snapshot, with no effect on the
    /// peer or its sessions.
    pub(super) async fn prepare_delete(
        &mut self,
        peer: PeerKey,
        sync_config_snapshot: bool,
        next_tcp_ao: Option<&TcpAoKeyring>,
        next_discard_path_attributes: Option<&[u8]>,
    ) -> Result<PreparedDelete, PeerLifecycleError> {
        let address = peer.address;
        // Dynamic-range peers are not deletable through the static-neighbor
        // surface: they auto-remove when their session ends (a range delete
        // only stops future accepts). Deleting one here would permanently
        // leak its dynamic_neighbor_limit slot (the BackToIdle decrement
        // never runs for it), and the persist-failure rollback would
        // resurrect it as a persisted static neighbor. Mirrors the reshape
        // executor's dynamic guard.
        if self
            .peers
            .get(&peer)
            .is_some_and(|managed| managed.is_dynamic)
        {
            return Err(PeerLifecycleError::Invalid(format!(
                "peer {address} is a dynamic-range peer; dynamic peers are removed \
                 automatically when their session ends — delete the dynamic-neighbor \
                 range to stop future accepts"
            )));
        }
        let current_tcp_ao = self
            .peers
            .get(&peer)
            .and_then(|managed| managed.transport_config.tcp_ao.as_ref())
            .cloned();
        if current_tcp_ao
            .as_ref()
            .is_some_and(|current| next_tcp_ao != Some(current))
        {
            return Err(PeerLifecycleError::RestartRequired(format!(
                "peer {address} uses TCP-AO; protected-owner removal requires restart (live MKT deletion cannot remove the owner)"
            )));
        }

        // Build and validate the next actor-owned snapshot before the first
        // teardown effect. A discard-list change then has its own explicit
        // settlement boundary below: purge commands may be observable before
        // a later delivery failure, so those failures are reported rather
        // than mislabeled as no-effect.
        let next_config = if sync_config_snapshot {
            let mut next_config = self.current_config.clone();
            apply_config_event(
                &mut next_config,
                &ConfigEvent::NeighborDeleted {
                    peer: peer.clone(),
                    ack: None,
                },
            )
            .map_err(|error| PeerLifecycleError::Invalid(error.to_string()))?;
            Some(next_config)
        } else {
            None
        };

        // Linearize any terminal signal emitted before this operation.
        self.drain_ready_session_notifications(Some(&peer)).await;
        if !self.peers.contains_key(&peer) {
            return Err(PeerLifecycleError::NotFound(peer));
        }
        let purge_reset = next_discard_path_attributes.is_some_and(|next| {
            self.peers.get(&peer).is_some_and(|managed| {
                managed.transport_config.discard_path_attributes.as_ref() != next
            })
        });
        Ok(PreparedDelete {
            peer,
            next_config,
            purge_reset,
        })
    }

    /// Purge-reset every peer in `peers` before its delete, all at once.
    /// Per peer the pending candidate is purged before the primary.
    ///
    /// Both collision generations are fenced as retiring before a purge is
    /// enqueued, so a fast `BackToIdle` is not handled as a live restart
    /// while reconfiguration still owns the generation. A peer whose pending
    /// purge is not admitted is left untouched; one whose primary purge is
    /// not admitted keeps its old primary and config for an explicit retry,
    /// and its pending generation, which may already have purged, is taken
    /// out for [`Self::retire_purged_candidates`]. Retire those only once
    /// every peer whose purge was admitted has been detached: retiring
    /// handles every ready notification, and an installed peer's
    /// purge-driven `BackToIdle` would be handled as a live failure.
    /// Results come back in input order.
    pub(super) async fn purge_reset_for_delete(&mut self, peers: &[PeerKey]) -> PurgeOutcome {
        let mut purges = Vec::with_capacity(peers.len());
        let mut fences = Vec::with_capacity(peers.len());
        for peer in peers {
            let Some(managed) = self.peers.get(peer) else {
                fences.push(None);
                purges.push(futures::future::Either::Left(std::future::ready(Ok(()))));
                continue;
            };
            let primary_session_id = managed.session_id();
            let pending_session_id = managed
                .pending_inbound
                .as_ref()
                .map(|pending| pending.session_id);
            let primary = managed.handle().commands_sender();
            let pending = managed
                .pending_inbound
                .as_ref()
                .map(|pending| pending.handle.commands_sender());
            self.retiring_sessions
                .insert(primary_session_id, peer.clone());
            if let Some(session_id) = pending_session_id {
                self.retiring_sessions.insert(session_id, peer.clone());
            }
            fences.push(Some((primary_session_id, pending_session_id)));
            // Admission to both channels is the ownership fence: the actor
            // handles no BackToIdle while the sweep waits, and a later
            // Shutdown queues behind each PurgeReset.
            purges.push(futures::future::Either::Right(async move {
                if let Some(pending) = pending {
                    send_session_command(pending, PeerCommand::PurgeReset, "purge reset")
                        .await
                        .map_err(|error| (true, error))?;
                }
                send_session_command(primary, PeerCommand::PurgeReset, "purge reset")
                    .await
                    .map_err(|error| (false, error))
            }));
        }
        let admitted = self
            .await_session_sweep(futures::future::join_all(purges))
            .await;

        let mut results = Vec::with_capacity(peers.len());
        let mut retiring = Vec::new();
        for ((peer, fence), admission) in peers.iter().zip(fences).zip(admitted) {
            let Some((primary_session_id, pending_session_id)) = fence else {
                results.push(Err(PeerLifecycleError::NotFound(peer.clone())));
                continue;
            };
            results.push(match admission {
                Ok(()) => Ok(()),
                Err((true, error)) => {
                    self.retiring_sessions.remove(&primary_session_id);
                    if let Some(session_id) = pending_session_id {
                        self.retiring_sessions.remove(&session_id);
                    }
                    Err(PeerLifecycleError::Internal(format!(
                        "failed to purge-reset pending session for {peer}: {error}"
                    )))
                }
                Err((false, error)) => {
                    // The pending purge may already have executed. Its
                    // generation is retired deliberately, later, while the
                    // old primary and config stay owned for an explicit
                    // retry. Both stay fenced as retiring until then.
                    let pending = self
                        .peers
                        .get_mut(peer)
                        .and_then(|managed| managed.pending_inbound.take());
                    retiring.push(PurgedCandidate {
                        peer: peer.clone(),
                        primary_session_id,
                        pending,
                    });
                    Err(PeerLifecycleError::Internal(format!(
                        "failed to purge-reset primary session for {peer}: {error}"
                    )))
                }
            });
        }
        PurgeOutcome { results, retiring }
    }

    /// Stop the pending generations of peers whose primary purge was not
    /// admitted, all at once while serving readiness, then handle what they
    /// reported and lift their fences. Call it once every peer whose purge
    /// was admitted has left the table.
    pub(super) async fn retire_purged_candidates(&mut self, mut retiring: Vec<PurgedCandidate>) {
        if retiring.is_empty() {
            return;
        }
        let shutdowns: Vec<_> = retiring
            .iter_mut()
            .filter_map(|candidate| {
                let address = candidate.peer.address;
                candidate.pending.take().map(|pending| async move {
                    let _ = Self::shutdown_handle_bounded_owned(
                        address,
                        "purge pending after primary delivery failure",
                        pending.handle,
                    )
                    .await;
                    pending.session_id
                })
            })
            .collect();
        let stopped = self
            .await_session_sweep(super::bounded_fan_out(shutdowns))
            .await;
        for candidate in &retiring {
            Box::pin(self.drain_ready_session_notifications(Some(&candidate.peer))).await;
            self.retiring_sessions.remove(&candidate.primary_session_id);
        }
        for session_id in stopped {
            self.retiring_sessions.remove(&session_id);
            self.unregister_session(session_id);
        }
    }

    /// Take a prepared peer out of the table, its sessions still running.
    pub(super) fn detach_prepared(
        &mut self,
        PreparedDelete {
            peer, next_config, ..
        }: PreparedDelete,
        reap_metric_series: bool,
        stop_reason: Option<bytes::Bytes>,
    ) -> Result<DetachedPeer, PeerLifecycleError> {
        let (primary, primary_session_id, mut managed) = self
            .peers
            .remove(&peer)
            .ok_or_else(|| PeerLifecycleError::NotFound(peer.clone()))?
            .into_parts();
        if self.bmp_excluded.remove(&peer) {
            self.publish_bmp_excluded_metric();
        }
        let removed_config = Self::removed_peer_config(&peer, &managed);
        self.retiring_sessions
            .insert(primary_session_id, peer.clone());
        let pending = managed.pending_inbound.take();
        if let Some(pending) = &pending {
            self.retiring_sessions
                .insert(pending.session_id, peer.clone());
        }
        Ok(DetachedPeer {
            primary,
            primary_session_id,
            pending,
            stop_reason,
            settlement: DeleteSettlement {
                peer,
                next_config,
                removed_config,
                reap_metric_series,
            },
        })
    }

    /// A delete's second half for every peer in `detached`: stop all their
    /// sessions at once, then settle each delete in input order. Per peer the
    /// order is unchanged: the pending inbound candidate stops before the
    /// primary, and the primary is sent its Cease first when there is a stop
    /// reason. Up to `PEER_SHUTDOWN_CONCURRENCY` peers' chains run at once
    /// ([`super::bounded_fan_out`]), so sessions that stopped draining
    /// commands cost one delete window per 64 of them, not one per peer.
    pub(super) async fn delete_detached_peers(
        &mut self,
        detached: Vec<DetachedPeer>,
    ) -> Vec<PeerManagerNeighborConfig> {
        let mut settlements = Vec::with_capacity(detached.len());
        let mut shutdowns = Vec::with_capacity(detached.len());
        for DetachedPeer {
            primary,
            primary_session_id,
            pending,
            stop_reason,
            settlement,
        } in detached
        {
            let address = settlement.peer.address;
            let pending_session_id = pending.as_ref().map(|pending| pending.session_id);
            shutdowns.push(async move {
                if let Some(pending) = pending {
                    let _ = Self::shutdown_handle_bounded_owned(
                        address,
                        "delete pending inbound",
                        pending.handle,
                    )
                    .await;
                }
                if stop_reason.is_some() {
                    // Best effort: an Established session sends
                    // Cease/Administrative Shutdown with the reason; the
                    // shutdown below closes it anyway.
                    let _ = primary
                        .stop_timeout(stop_reason, PEER_LIFECYCLE_COMMAND_TIMEOUT)
                        .await;
                }
                Self::shutdown_handle_bounded_owned(address, "delete primary", primary).await
            });
            settlements.push((settlement, pending_session_id, primary_session_id));
        }
        let shutdowns = self
            .await_session_sweep(super::bounded_fan_out(shutdowns))
            .await;

        let mut removed = Vec::with_capacity(settlements.len());
        for ((settlement, pending_session_id, primary_session_id), shutdown) in
            settlements.into_iter().zip(shutdowns)
        {
            // As in `quiesce_retiring_session`: what the stopped sessions
            // reported is handled while they are still known as retiring.
            Box::pin(self.drain_ready_session_notifications(Some(&settlement.peer))).await;
            for session_id in pending_session_id.into_iter().chain([primary_session_id]) {
                self.retiring_sessions.remove(&session_id);
                self.unregister_session(session_id);
            }
            removed.push(self.settle_peer_delete(settlement, shutdown));
        }
        removed
    }

    fn settle_peer_delete(
        &mut self,
        DeleteSettlement {
            peer,
            next_config,
            removed_config,
            reap_metric_series,
        }: DeleteSettlement,
        shutdown: PeerShutdownOutcome,
    ) -> PeerManagerNeighborConfig {
        let address = peer.address;
        if reap_metric_series {
            // A real operator deletion is authoritative even if the actor
            // crossed max-prefix while it was being joined. Reconfigure keeps
            // the latch for the replacement generation.
            self.remove_max_prefix_latch(&peer);
        }
        if shutdown.joined() {
            info!(peer = %address, "peer deleted");
        }
        // ADR-0137: a gate kept for this peer past its neighbor's removal is
        // pruned once the session is gone.
        if self
            .conditional_advertisements
            .attachments
            .contains_key(&peer.rib_endpoint())
        {
            self.conditional_reconcile_pending = true;
        }

        let peer_for_reap = peer.clone();
        if let Some(next_config) = next_config {
            self.replace_current_config(next_config);
        }

        // ADR-0067 step 4: drain the deleted peer's BFD session.
        self.set_bfd_peer_disabled(address, true);

        // Operator rule: reap per-peer runtime/state metrics for
        // *deleted* peers only — never on a session flap (the session
        // task records its final transitions before bounded shutdown
        // joins or aborts-and-awaits it, so this runs after the last
        // transport-side emission).
        if reap_metric_series {
            self.reap_deleted_peer_metric_series_for_key(&peer_for_reap);
        }
        self.recheck_refused_bindings();
        removed_config
    }

    /// The lifetime counter block for `peer`: its retained block, or a new
    /// one that [`Self::retain_neighbor_counters`] keeps once the neighbor
    /// is installed, so a refused accept leaves nothing behind.
    pub(super) fn neighbor_counters_for(
        &self,
        peer: &PeerKey,
    ) -> rustbgpd_transport::NeighborCounters {
        self.neighbor_counters
            .get(peer)
            .cloned()
            .unwrap_or_default()
    }

    /// Keep the installed neighbor's counter block and RIB identity slot
    /// until it is deleted.
    pub(super) fn retain_neighbor_counters(&mut self, peer: &PeerKey) {
        if let Some(managed) = self.peers.get(peer) {
            self.neighbor_counters.insert(
                peer.clone(),
                managed.transport_config.neighbor_counters.clone(),
            );
            self.rib_peers
                .insert(peer.clone(), managed.transport_config.rib_peer.clone());
        }
    }

    /// Seed the RIB identities the daemon allocated for its startup
    /// neighbors, so the RIB's startup waiters and the sessions agree.
    #[must_use]
    pub(crate) fn with_rib_peers(
        mut self,
        peers: impl IntoIterator<Item = (PeerKey, rustbgpd_transport::RibPeerSlot)>,
    ) -> Self {
        self.rib_peers.extend(peers);
        self
    }

    /// The RIB identity slot for a static neighbor: its retained (or seeded)
    /// slot, or a newly allocated handle, flagged as new so a refused add can
    /// release it.
    /// An interface-only neighbor's handle labels by its interface.
    fn static_rib_peer_slot(
        &self,
        peer: &PeerKey,
        interface_only: bool,
        replaces_retained: bool,
    ) -> (rustbgpd_transport::RibPeerSlot, bool) {
        if let Some(slot) = self.rib_peers.get(peer).filter(|_| !replaces_retained) {
            return (slot.clone(), false);
        }
        let endpoint = rustbgpd_rib::PeerEndpoint::new(peer.address, peer.interface.as_deref());
        let handle = if interface_only {
            PeerId::allocate_interface_only(endpoint)
        } else {
            PeerId::allocate(endpoint)
        };
        (rustbgpd_transport::RibPeerSlot::assigned(handle), true)
    }

    /// Whether `interface` belongs to a configured interface-only neighbor
    /// (ADR-0142), which owns it: no static neighbor may share it, so a peer
    /// scoped to it is that neighbor's learned endpoint.
    pub(super) fn interface_only_owns(&self, interface: Option<&str>) -> bool {
        interface.is_some_and(|interface| {
            self.current_config
                .neighbors
                .interface_only_on(interface)
                .is_some()
        })
    }

    /// The `peer` metric label of `peer`, the value its session emits:
    /// `interface:<name>` for an interface-only neighbor's learned endpoint,
    /// else the key's own label.
    pub(super) fn peer_metric_label(&self, peer: &PeerKey) -> String {
        match peer.interface.as_deref() {
            Some(interface) if self.interface_only_owns(Some(interface)) => {
                rustbgpd_telemetry::interface_peer_label(interface)
            }
            _ => peer.label(),
        }
    }

    /// The handle the neighbor's sessions use in the RIB: its allocated one,
    /// or [`PeerId::UNASSIGNED`] while a dynamic neighbor has none yet (its
    /// OPEN has not validated) or for an unknown neighbor, which names no
    /// RIB state.
    pub(super) fn rib_peer_of(&self, peer: &PeerKey) -> PeerId {
        self.rib_peers
            .get(peer)
            .or_else(|| {
                self.peers
                    .get(peer)
                    .map(|managed| &managed.transport_config.rib_peer)
            })
            .map_or(PeerId::UNASSIGNED, |slot| slot.current(peer.address))
    }

    /// Release a handle the RIB never learned of (a refused add). Queued
    /// behind anything a session might have sent, like a deletion's release,
    /// without waiting for mailbox room.
    pub(super) fn release_unused_rib_peer(&mut self, peer: PeerId) {
        if self
            .defer_rib_update(None, RibUpdate::ReleasePeer { peer })
            .is_err()
        {
            // The RIB is gone, so nothing can still name the handle.
            let _ = peer.release();
        }
    }

    /// Remove a deleted peer's per-peer metric series.
    ///
    /// Every emission site — transport session, RIB manager, BFD
    /// runtime — labels `peer` with the neighbor's one value (the bare
    /// address, or `addr%if` for a link-local neighbor), so one reap
    /// covers them all. Call only after the peer has been removed from
    /// `self.peers` and its session task joined or was aborted and
    /// awaited by bounded shutdown.
    ///
    /// Never waits for the RIB: a full mailbox defers the deletion's
    /// `PeerDeleted` and `ReleasePeer`, in order, behind every update queued
    /// before them. Every later update this actor sends through the ordered
    /// path goes behind them, and no session starts at the label they reap
    /// before they are admitted. The direct round trips (policy,
    /// conditional-advertisement, owner publication, outbound refresh,
    /// dampening barrier, BMP and retention queries) may be admitted first:
    /// they name live or retained handles or RIB-wide state. Two come close
    /// to a deleted handle. The spawned retention query can ask about a
    /// retained neighbor deleted after it was sent, and
    /// `finish_retention_pass` drops that answer. An interface-only
    /// neighbor's handle, kept across endpoints (`keep_series`), is reused
    /// by a `RebindPeer` sent directly, and only once no cleanup under its
    /// interface's label is queued, so its deletion has been admitted.
    pub(super) fn reap_deleted_peer_metric_series_for_key(&mut self, peer: &PeerKey) {
        // A deleted neighbor's counters end with it; a re-add starts at 0.
        self.neighbor_counters.remove(peer);
        // A peer installed without a retained slot (a test harness peer)
        // ran on its standalone slot, which is its address's pinned handle.
        let rib_peer = self.rib_peers.remove(peer).map_or_else(
            || PeerId::from_addr(peer.address),
            |slot| slot.current(peer.address),
        );
        // An interface-only neighbor's endpoint is labelled by its interface.
        // Leaving it for the next endpoint keeps the neighbor's series; only
        // removing its stanza ends them.
        let owner = self.unnumbered_owner_of(peer).map(str::to_owned);
        let keep_series = owner.as_deref().is_some_and(|interface| {
            self.current_config
                .neighbors
                .interface_only_on(interface)
                .is_some()
        });
        let peer_label = owner
            .as_deref()
            .map_or_else(|| peer.label(), rustbgpd_telemetry::interface_peer_label);
        let removed = match self.unnumbered_presence_reason(peer) {
            Some(reason) => format!("peer {peer} removed: {reason}"),
            None => format!("peer {peer} removed"),
        };
        self.publish_peer_lifecycle_event(peer, SessionLifecycleEventType::PeerRemoved, removed);
        if !keep_series {
            self.metrics
                .reap_peer_identity_series(&peer_label, peer.interface.as_deref().unwrap_or(""));
            self.metrics.reap_peer_series(&peer_label);
        }
        // A neighbor that never reached the RIB (a dynamic one whose OPEN
        // never validated) has no handle and no RIB state.
        if rib_peer != PeerId::UNASSIGNED {
            // The RIB manager emits bare-address series from its own
            // task; this marker is queued behind the session's final
            // `PeerDown`, so the RIB manager reaps its own families again
            // *after* its teardown emissions instead of racing them. It
            // leaves the families reaped above, which a neighbor re-added
            // at the address may emit before the RIB gets here. Send
            // failure means the RIB manager is gone (daemon shutdown).
            let _ = self.defer_rib_update(
                Some(peer_label.clone()),
                RibUpdate::PeerDeleted {
                    peer: rib_peer,
                    label: Some(peer_label.as_str().into()),
                    keep_series,
                },
            );
            // An interface-only neighbor keeps its handle across endpoints;
            // any other deletion returns it, after the cleanup above, so a
            // re-added neighbor gets a new one and late messages are dropped.
            if !self.unnumbered_holds(rib_peer) {
                let _ = self
                    .defer_rib_update(Some(peer_label), RibUpdate::ReleasePeer { peer: rib_peer });
            }
        }
    }

    pub(super) async fn enable_peer(&mut self, peer: PeerKey) -> Result<(), PeerLifecycleError> {
        if self.peers.get(&peer).is_some_and(|managed| {
            managed
                .transport_config
                .dampening_admission
                .as_ref()
                .is_some_and(rustbgpd_rib::dampening::DampeningAdmission::is_blocked)
        }) {
            return Err(PeerLifecycleError::Invalid(
                "dampening capacity recovery requires an owned explicit enable".into(),
            ));
        }
        // ADR-0086: a dynamic peer exists only while a range admits it. Its
        // release normally follows the range's removal; until then, enable
        // must not restart a peer no configured range covers.
        if self.peers.get(&peer).is_some_and(|managed| {
            managed.is_dynamic && !self.dynamic_peer_still_allowed_by_current_ranges(managed)
        }) {
            return Err(PeerLifecycleError::Precondition(format!(
                "peer {peer} is a dynamic-range peer and no configured dynamic-neighbor range \
                 admits it any more"
            )));
        }
        let address = peer.address;
        // ADR-0067 step 4b: re-enabling a strict peer must re-apply the withhold
        // — start BGP only if BFD is already Up, else withhold until it is.
        // (A freshly-restarted BFD session begins Down with no transition, so an
        // unconditional start here would establish BGP with BFD down.)
        let withhold = self.bfd_should_withhold(&address);
        let stopped = self.unnumbered_stopped(&peer);
        let Some((handle, managed)) = self.peers.get_mut_with_handle(&peer) else {
            return Err(PeerLifecycleError::NotFound(peer));
        };
        if !withhold {
            match handle.start_timeout(PEER_LIFECYCLE_COMMAND_TIMEOUT).await {
                Ok(()) => {}
                // An interface-only neighbor's stopped peer has no task to
                // start: the session that replaces it, at a new binding or
                // from an inbound connection, takes the enabled state.
                Err(rustbgpd_transport::PeerCommandError::SessionExited) if stopped => {}
                Err(e) => {
                    return Err(PeerLifecycleError::Internal(format!(
                        "failed to start peer: {e}"
                    )));
                }
            }
        }
        // Enable is the sole recovery operation for a max-prefix shutdown.
        // Clear the manager-owned error only after the session accepted Start,
        // so a failed command cannot accidentally reopen passive acceptance.
        managed.enabled = true;
        self.publish_peer_admin_enabled_metric(&peer, true);
        self.remove_max_prefix_latch(&peer);
        self.publish_peer_lifecycle_event(
            &peer,
            SessionLifecycleEventType::PeerEnabled,
            format!("peer {address} enabled"),
        );
        // Re-arm this peer's BFD session in the desired set.
        self.set_bfd_peer_disabled(address, false);
        if withhold {
            self.mark_bfd_withheld(address);
            info!(peer = %address, "strict BFD — withholding BGP until BFD Up (re-enable)");
        }
        info!(peer = %address, "peer enabled");
        Ok(())
    }

    pub(super) async fn disable_peer(
        &mut self,
        peer: PeerKey,
        reason: Option<bytes::Bytes>,
    ) -> Result<(), PeerLifecycleError> {
        let address = peer.address;
        // Invalidate before any await: an already-due automatic restart must
        // never overtake an explicit operator disable.
        self.invalidate_max_prefix_restart(&peer);
        let pending = {
            let managed = self
                .peers
                .get_mut(&peer)
                .ok_or_else(|| PeerLifecycleError::NotFound(peer.clone()))?;
            managed.enabled = false;
            managed.pending_inbound.take()
        };
        self.publish_peer_admin_enabled_metric(&peer, false);
        if let Some(pending) = pending {
            let _ = self
                .quiesce_retiring_session(
                    &peer,
                    pending.session_id,
                    pending.handle,
                    "disable pending inbound",
                    false,
                )
                .await;
        }
        let stopped = self.unnumbered_stopped(&peer);
        let managed = self
            .peers
            .get(&peer)
            .ok_or_else(|| PeerLifecycleError::NotFound(peer.clone()))?;
        match managed
            .handle()
            .stop_timeout(reason, PEER_LIFECYCLE_COMMAND_TIMEOUT)
            .await
        {
            Ok(()) => {}
            // An interface-only neighbor's stopped peer is already stopped.
            Err(rustbgpd_transport::PeerCommandError::SessionExited) if stopped => {}
            Err(e) => {
                return Err(PeerLifecycleError::Internal(format!(
                    "failed to stop peer: {e}"
                )));
            }
        }
        self.publish_peer_lifecycle_event(
            &peer,
            SessionLifecycleEventType::PeerDisabled,
            format!("peer {address} disabled"),
        );
        // ADR-0067 step 4: drain this peer's BFD session (published disabled).
        self.set_bfd_peer_disabled(address, true);
        self.mark_unadmitted_disabled_dynamic(&peer);
        info!(peer = %address, "peer disabled");
        Ok(())
    }

    /// Operator session reset: Cease/Administrative Reset with the optional
    /// shutdown communication. A static active-open peer reconnects on its
    /// normal schedule; an accepted dynamic peer follows the ordinary
    /// `BackToIdle` removal path and must be re-established by the remote.
    /// The peer's enable/disable state is untouched, so a disabled peer is
    /// rejected instead of silently bounced.
    pub(super) async fn reset_peer(
        &mut self,
        peer: PeerKey,
        reason: Option<bytes::Bytes>,
    ) -> Result<(), PeerLifecycleError> {
        let address = peer.address;
        let pending = {
            let managed = self
                .peers
                .get_mut(&peer)
                .ok_or_else(|| PeerLifecycleError::NotFound(peer.clone()))?;
            if !managed.enabled {
                return Err(PeerLifecycleError::RestartRequired(format!(
                    "peer {peer} is administratively disabled; enable it before resetting"
                )));
            }
            managed.pending_inbound.take()
        };
        if let Some(pending) = pending {
            let _ = self
                .quiesce_retiring_session(
                    &peer,
                    pending.session_id,
                    pending.handle,
                    "administrative reset pending inbound",
                    false,
                )
                .await;
        }
        let managed = self
            .peers
            .get(&peer)
            .ok_or_else(|| PeerLifecycleError::NotFound(peer.clone()))?;
        managed
            .handle()
            .administrative_reset_timeout(reason, PEER_LIFECYCLE_COMMAND_TIMEOUT)
            .await
            .map_err(|e| PeerLifecycleError::Internal(format!("failed to reset peer: {e}")))?;
        info!(peer = %address, "peer reset");
        Ok(())
    }

    /// RFC 8326 graceful-shutdown initiator: toggle `GRACEFUL_SHUTDOWN`
    /// community attachment for one peer (`Some(addr)`) or every peer
    /// (`None`), including the intent held for neighbors between sessions.
    ///
    /// Three steps, each taken for every target before the next, so the
    /// toggle is observable on the wire AND survives session restart:
    ///
    /// 1. **Update desired state on `ManagedPeer`** — survives session
    ///    restart so a flap mid-maintenance doesn't silently drop the
    ///    toggle.
    /// 2. **Send the live-session command** — flips the per-session
    ///    bool; the next outbound advertise carries (or stops carrying)
    ///    the community. Every session is told at once, so sessions that
    ///    stopped draining commands share one deadline.
    /// 3. **Queue `RibUpdate::RefreshPeerOutbound`** for every peer whose
    ///    session acknowledged — forces re-emission of routes already in
    ///    `AdjRibOut` so the wire form updates without waiting for an
    ///    unrelated RIB event. The outbound refresher sends them one at a
    ///    time, each after the RIB answered the previous one, so a session's
    ///    route updates queue between the replays rather than behind all of
    ///    them. The reply does not wait for them: refresh failures are
    ///    logged, not returned.
    ///
    /// `Some(peer)` for a missing peer surfaces as `SetGshutError::PeerNotFound`
    /// so callers can distinguish that from a session failure.
    /// Per-peer session failures aggregate into `Internal`. The
    /// authoritative state is updated even when the live-session
    /// command fails — the toggle takes effect on the next
    /// session spawn regardless.
    pub(super) async fn set_graceful_shutdown(
        &mut self,
        peer: Option<PeerKey>,
        enabled: bool,
    ) -> Result<(), SetGshutError> {
        if peer.is_none() {
            // A neighbor between sessions holds its intent for its next
            // peer: a dynamic neighbor's dead-letter entry and an unbound
            // interface-only neighbor's port, bound before or not. An
            // all-peers toggle reaches them too. Otherwise a clear lets the
            // neighbor reconnect advertising GRACEFUL_SHUTDOWN with no peer
            // left to clear it by name, and a set lets it connect undrained
            // during the maintenance window. A dynamic neighbor with no
            // dead-letter entry has nothing held; its next accept starts
            // without the intent.
            for held in self.dead_lettered_pending.values_mut() {
                held.graceful_shutdown = enabled;
            }
            if let Some(unnumbered) = self.unnumbered.as_mut() {
                unnumbered.set_held_graceful_shutdown(enabled);
            }
        }
        let targets: Vec<PeerKey> = match peer {
            Some(peer) => {
                if !self.peers.contains_key(&peer) {
                    return Err(SetGshutError::PeerNotFound(peer));
                }
                vec![peer]
            }
            None => self.peers.keys().cloned().collect(),
        };

        // (1) Update authoritative state on ManagedPeer so it survives
        // session restart.
        let mut toggles = Vec::with_capacity(targets.len());
        for peer in &targets {
            // Targets were read from the table with no await since.
            let commands = self.peers[peer].handle().commands_sender();
            if let Some(managed) = self.peers.get_mut(peer) {
                managed.advertise_graceful_shutdown = enabled;
            }
            toggles.push(PeerHandle::update_graceful_shutdown_with(
                commands,
                enabled,
                PEER_POLICY_UPDATE_TIMEOUT,
            ));
        }

        // (2) Tell every live session at once, best-effort. If a session
        // task is wedged or already restarting, the new session will pick
        // up the toggle from ManagedPeer at spawn time.
        let acks = self
            .await_session_sweep(futures::future::join_all(toggles))
            .await;
        let mut failures: Vec<String> = Vec::new();
        let mut acknowledged = Vec::with_capacity(targets.len());
        for (peer, ack) in targets.iter().zip(acks) {
            match ack {
                Ok(()) => acknowledged.push(peer.clone()),
                Err(e) => {
                    warn!(
                        peer = %peer.address,
                        enabled,
                        error = %e,
                        "failed to toggle graceful-shutdown on live peer session — \
                         desired state stored, will apply on next session"
                    );
                    failures.push(format!("{}: session: {e}", peer.address));
                }
            }
        }

        // (3) Force re-emission of already-advertised routes so the toggle
        // is visible on the wire without waiting for an unrelated RIB event,
        // for every peer whose session acknowledged, each after its own
        // toggle. The refresher replays one peer's table per RIB turn, off
        // this actor, so the operator's reply does not wait for it.
        if !acknowledged.is_empty() {
            let peers = acknowledged
                .iter()
                .map(|peer| self.rib_peer_of(peer))
                .collect();
            self.request_outbound_refresh(peers);
        }

        if failures.is_empty() {
            info!(
                count = targets.len(),
                enabled, "RFC 8326 graceful-shutdown toggled on peer set"
            );
            Ok(())
        } else {
            Err(SetGshutError::Internal(format!(
                "graceful-shutdown toggle had failures on {} of {} {} (desired \
                 state stored regardless): {}",
                failures.len(),
                targets.len(),
                if targets.len() == 1 { "peer" } else { "peers" },
                failures.join("; ")
            )))
        }
    }

    pub(super) async fn soft_reset_in(
        &self,
        peer: PeerKey,
        families: Vec<(Afi, Safi)>,
    ) -> Result<(), PeerLifecycleError> {
        self.soft_reset_in_reporting_delivery(peer, families)
            .await
            .map_err(|failure| failure.error)
    }

    /// Refresh admission and acknowledgement share one absolute deadline.
    /// Finish an already-admitted read before returning, even if that deadline
    /// expires meanwhile. Keep transport failures separate from the RIB's
    /// result: callers retain their existing partial-effect semantics.
    async fn refresh_peer_outbound_in_rib(
        &mut self,
        peer: &PeerKey,
        admission: OperatorReadAdmission,
        confirm_unlock: bool,
    ) -> Result<Result<(), RibCommandError>, String> {
        let deadline = tokio::time::Instant::now() + super::RIB_REPLY_TIMEOUT;
        let rib_peer = self.rib_peer_of(peer);
        let session_id = self.peers.get(peer).map_or(0, ManagedPeer::session_id);
        let timed_out = || {
            format!(
                "outbound refresh for peer {peer} timed out after {:?}",
                super::RIB_REPLY_TIMEOUT
            )
        };
        let rib_tx = self.rib_tx.clone();
        let round_trip = async {
            let permit = rib_tx.reserve().await.map_err(|_| {
                format!("RIB channel closed before outbound refresh for peer {peer}")
            })?;
            // Never admit after the absolute deadline when capacity returns
            // during read servicing.
            if tokio::time::Instant::now() >= deadline {
                return Err(timed_out());
            }
            let (reply, response) = oneshot::channel();
            permit.send(if confirm_unlock {
                RibUpdate::ConfirmPeerOutbound {
                    peer: rib_peer,
                    session_id,
                    reply,
                }
            } else {
                RibUpdate::RefreshPeerOutbound {
                    peer: rib_peer,
                    reply,
                }
            });
            response
                .await
                .map_err(|_| format!("RIB dropped reply for outbound refresh of peer {peer}"))
        };
        let bounded = async {
            tokio::select! {
                biased;
                () = tokio::time::sleep_until(deadline) => Err(timed_out()),
                result = round_trip => result,
            }
        };
        self.await_with_readiness(bounded, admission).await
    }

    /// Queue a forced outbound refresh for `peers` on the outbound refresher,
    /// started on first use.
    fn request_outbound_refresh(&mut self, peers: Vec<PeerId>) {
        let rib_tx = self.rib_tx.clone();
        self.outbound_refresher
            .get_or_insert_with(|| OutboundRefresher::start(rib_tx))
            .request(peers);
    }

    /// Re-emit the current exportable outbound inventory for one managed peer.
    ///
    /// The RIB owns the authoritative outbound registration. A managed peer
    /// that is down or has not completed `PeerUp` is therefore reported
    /// separately from an unknown peer.
    pub(super) async fn refresh_outbound(
        &mut self,
        peer: PeerKey,
    ) -> Result<(), OutboundRefreshError> {
        if !self.peers.contains_key(&peer) {
            return Err(OutboundRefreshError::PeerNotFound(peer));
        }

        match self
            .refresh_peer_outbound_in_rib(&peer, OperatorReadAdmission::Served, false)
            .await
            .map_err(OutboundRefreshError::Internal)?
        {
            Ok(()) => Ok(()),
            Err(RibCommandError::NotFound(_)) => Err(OutboundRefreshError::PeerUnavailable(peer)),
            Err(
                RibCommandError::Internal(message)
                | RibCommandError::FailedPrecondition(_, message)
                | RibCommandError::ResourceExhausted(message),
            ) => Err(OutboundRefreshError::Internal(message)),
        }
    }

    /// Schedule replay on the exact managed session, including scoped identity.
    pub(super) async fn replay_outbound(
        &mut self,
        peer: PeerKey,
        mut reply: oneshot::Sender<Result<(), OutboundRefreshError>>,
    ) {
        if reply.is_closed() {
            return;
        }
        let Some(managed) = self.peers.get(&peer) else {
            let _ = reply.send(Err(OutboundRefreshError::PeerNotFound(peer)));
            return;
        };
        // BMP's peer cache is keyed by IP address. Refuse ambiguity before
        // dispatch, so enrollment cannot reset another scoped peer's view.
        if self
            .peers
            .keys()
            .any(|other| other.address == peer.address && other != &peer)
        {
            let _ = reply.send(Err(OutboundRefreshError::ReplayUnavailable(
                "outbound replay requires a unique peer IP address among managed peers".into(),
            )));
            return;
        }
        let commands = managed.handle().commands_sender();
        let deadline = tokio::time::Instant::now() + super::RIB_REPLY_TIMEOUT;
        // Cancellation and expiry belong to the step, not the read-admitting
        // helper: a consumed read retains its own reply and deadline. When it
        // finishes, cancellation/expiry wins over newly writable capacity.
        let scheduling = async {
            tokio::select! {
                biased;
                () = reply.closed() => None,
                () = tokio::time::sleep_until(deadline) => Some(Err(PeerCommandError::TimedOut {
                    operation: "replay_outbound",
                    deadline: super::RIB_REPLY_TIMEOUT,
                })),
                result = PeerHandle::replay_outbound_via(commands) => Some(result),
            }
        };
        if let Some(result) = self
            .await_with_readiness(scheduling, OperatorReadAdmission::Served)
            .await
        {
            let result = result.map_err(|error| match error {
                PeerCommandError::NotEstablished | PeerCommandError::SessionExited => {
                    OutboundRefreshError::PeerUnavailable(peer)
                }
                PeerCommandError::ReplayUnavailable(message) => {
                    OutboundRefreshError::ReplayUnavailable(message)
                }
                error => OutboundRefreshError::Internal(format!(
                    "failed to schedule outbound replay for peer {peer}: {error}"
                )),
            });
            let _ = reply.send(result);
        }
    }

    /// [`Self::soft_reset_in`], additionally reporting whether the peer's
    /// `AdjRibIn` may already have started moving when the refresh failed.
    ///
    /// Only the policy transaction needs this: families are requested
    /// sequentially, so a failure is not proof that nothing was asked for, and
    /// its rollback has to know the difference.
    pub(super) async fn soft_reset_in_reporting_delivery(
        &self,
        peer: PeerKey,
        families: Vec<(Afi, Safi)>,
    ) -> Result<(), SoftResetFailure> {
        self.soft_reset_target(&peer)?.send(families).await
    }

    /// What an inbound soft reset of `peer` needs, owned, so many peers'
    /// requests can run at once.
    pub(super) fn soft_reset_target(
        &self,
        peer: &PeerKey,
    ) -> Result<SoftResetTarget, SoftResetFailure> {
        let managed = self.peers.get(peer).ok_or_else(|| SoftResetFailure {
            error: PeerLifecycleError::NotFound(peer.clone()),
            delivery_began: false,
            acknowledgement_lost: false,
        })?;
        Ok(SoftResetTarget {
            address: peer.address,
            commands: managed.handle().commands_sender(),
            configured_families: managed.transport_config.peer.families.clone(),
        })
    }
}

/// One peer's inbound soft reset, detached from the manager
/// ([`PeerManager::soft_reset_target`]).
pub(super) struct SoftResetTarget {
    address: std::net::IpAddr,
    commands: tokio::sync::mpsc::Sender<PeerCommand>,
    configured_families: Vec<(Afi, Safi)>,
}

impl SoftResetTarget {
    /// Ask the peer to resend `families`; empty asks for every family it
    /// can be asked for.
    pub(super) async fn send(self, families: Vec<(Afi, Safi)>) -> Result<(), SoftResetFailure> {
        let address = self.address;
        // An empty request means "everything this peer can be asked for".
        let refresh_all = families.is_empty();
        let target_families = if refresh_all {
            self.configured_families
        } else {
            families
        };

        let mut refreshed = Vec::with_capacity(target_families.len());
        for (afi, safi) in &target_families {
            match PeerHandle::send_route_refresh_with(
                self.commands.clone(),
                *afi,
                *safi,
                PEER_LIFECYCLE_COMMAND_TIMEOUT,
            )
            .await
            {
                Ok(()) => refreshed.push((*afi, *safi)),
                // ADR-0112: "everything" is bounded by the *negotiated* set,
                // not the configured one. A configured family the peer did not
                // negotiate has no `AdjRibIn` to re-evaluate, so refusing to
                // ask for it is right — but failing the whole refresh over it
                // is not, and it made every whole-peer refresh (policy edits,
                // RPKI/ASPA cache updates, dataset swaps) fail on any session
                // that negotiated down. An explicitly requested family still
                // errors: the caller named it, so it deserves the answer.
                Err(PeerCommandError::FamilyNotNegotiated { .. }) if refresh_all => {}
                Err(e) => {
                    warn!(peer = %address, error = %e, "failed to send route refresh");
                    // Conservative by construction: an already-accepted family
                    // is delivery, and so is a reply we never got. Only a
                    // definite session-side rejection on the very first family
                    // (no capability, not Established, the writer refused to
                    // queue) proves nothing was asked for.
                    let acknowledgement_lost = matches!(
                        e,
                        PeerCommandError::TimedOut { .. } | PeerCommandError::ReplyDropped
                    );
                    let delivery_began = !refreshed.is_empty() || acknowledgement_lost;
                    return Err(SoftResetFailure {
                        error: PeerLifecycleError::Internal(format!(
                            "send failed: route refresh to {address}: {e}"
                        )),
                        delivery_began,
                        acknowledgement_lost,
                    });
                }
            }
        }

        info!(peer = %address, families = ?refreshed, "soft reset in requested");
        Ok(())
    }
}

/// A failed whole-peer Route Refresh, plus whether any family may already have
/// been asked for before it failed.
pub(super) struct SoftResetFailure {
    pub(super) error: PeerLifecycleError,
    /// True when at least one family's request was accepted, or when the
    /// failing reply was ambiguous (timeout, dropped reply) and therefore
    /// cannot prove the request did not reach the peer.
    pub(super) delivery_began: bool,
    /// A command may have been accepted without an authoritative reply. Keep
    /// this distinct from a definite rejection after earlier family delivery.
    pub(super) acknowledgement_lost: bool,
}

/// The admin state a reload or reshape must apply to `managed` for `next`,
/// or `None` to keep the runtime state.
///
/// The config's `admin_down` is the boot truth, but on a live peer only a
/// change to it acts: setting it disables the peer and clearing it enables
/// the peer. While it is unchanged, the transient runtime
/// `enable`/`disable` toggle (ADR-0043) carries over, so an operator enable
/// of a config-down peer lasts until restart or a reload that changes the
/// key.
///
/// A replayed rollback prior ([`PeerManager::removed_peer_config`]) carries
/// the admin state captured before the forward step and restores exactly that
/// state, so compensation leaves an earlier runtime toggle intact.
pub(super) fn config_admin_enable(
    managed: &ManagedPeerState,
    next: &PeerManagerNeighborConfig,
) -> Option<bool> {
    if let Some(enabled) = next.restore_admin_enabled {
        return Some(enabled);
    }
    let next_down = next.admin_down.is_some();
    (managed.admin_down.is_some() != next_down).then_some(!next_down)
}

/// The shutdown communication for a replacement's teardown: the configured
/// reason when the replacement takes an enabled peer down, as disable sends.
pub(super) fn replacement_stop_reason(
    enabled: bool,
    next_enabled: bool,
    next: &PeerManagerNeighborConfig,
) -> Option<bytes::Bytes> {
    (enabled && !next_enabled)
        .then(|| admin_down_shutdown_communication(next))
        .flatten()
}

/// The RFC 9003 shutdown communication a config-driven disable sends.
fn admin_down_shutdown_communication(config: &PeerManagerNeighborConfig) -> Option<bytes::Bytes> {
    config
        .admin_down
        .as_deref()
        .filter(|reason| !reason.is_empty())
        .map(rustbgpd_wire::notification::encode_shutdown_communication)
}
