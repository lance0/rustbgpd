use rustbgpd_api::peer_types::PeerKey;
use rustbgpd_transport::{
    PeerHandle, SessionIdentity, SessionLifecycleNotification, SessionNotification,
};
use tracing::{debug, info, warn};

use super::{ManagedPeer, ManagedPeerState, PeerManager};
use futures::{FutureExt as _, StreamExt as _};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use tokio::time::Instant;

/// Crashes of one peer's session task within [`SESSION_CRASH_WINDOW`] that
/// latch the peer disabled. One crash is a restart; a third crash within the
/// window means the failure recurs, for example on every UPDATE the peer
/// resends after each restart, and restarting again would only repeat it.
pub(super) const SESSION_CRASH_LATCH: usize = 3;
/// How long a session-task crash counts toward [`SESSION_CRASH_LATCH`]. Ten
/// minutes covers several reconnects at the default 120-second `ConnectRetry`
/// interval, so a crash that recurs once per established session is latched
/// even when each reconnect waits out `ConnectRetry`.
pub(super) const SESSION_CRASH_WINDOW: std::time::Duration = std::time::Duration::from_secs(600);

/// Session tasks of one peer that ended without a shutdown request. The
/// manager keeps it by [`PeerKey`], like a max-prefix latch, so it survives
/// the sessions it restarts, a reconfigure that replaces the peer, and a
/// dynamic peer's removal and reconnect. Explicit enable or deleting the
/// neighbor clears it; an unlatched record lapses with its window.
#[derive(Clone, Debug, Default)]
pub(super) struct SessionCrashes {
    /// When each crash within the window was handled, oldest first.
    recent: VecDeque<Instant>,
    /// The neighbor's `last_error` for the latest crash.
    last_error: String,
    /// The [`SESSION_CRASH_LATCH`]th crash within the window latched the
    /// peer disabled. Only an explicit enable or deletion clears it.
    latched: bool,
}

impl SessionCrashes {
    /// Whether these crashes latched the neighbor disabled.
    pub(super) fn latched(&self) -> bool {
        self.latched
    }

    /// Latched, or the latest crash is still within the window.
    fn current(&self, now: Instant) -> bool {
        self.latched
            || self
                .recent
                .back()
                .is_some_and(|at| now.duration_since(*at) < SESSION_CRASH_WINDOW)
    }

    /// The latest crash's error and whether it latched the neighbor, while
    /// the record is current.
    pub(super) fn error(&self) -> Option<(&str, bool)> {
        self.current(Instant::now())
            .then_some((self.last_error.as_str(), self.latched))
    }
}

struct NotificationRetirement {
    peer: PeerKey,
    sessions: Vec<(u64, PeerHandle, &'static str)>,
    stop_primary: Option<(
        u64,
        tokio::sync::mpsc::Sender<rustbgpd_transport::PeerCommand>,
    )>,
    dynamic: Option<Box<DynamicRetirement>>,
}

struct DynamicRetirement {
    managed: ManagedPeerState,
    end_retention: rustbgpd_transport::SessionEndRetention,
    primary_id: u64,
}

struct SettledNotificationRetirement {
    peer: PeerKey,
    /// Each joined session and the RIB registration it owned when its task
    /// ended: itself once its `PeerUp` was admitted, else its predecessor.
    sessions: Vec<(u64, Option<u64>)>,
    failed_stop: Option<(u64, rustbgpd_transport::PeerCommandError)>,
    dynamic: Option<Box<DynamicRetirement>>,
}

enum NotificationCompletion {
    Sessions(SettledNotificationRetirement),
    Barrier(SettledNotificationRetirement, bool),
    Replaced {
        peer: PeerKey,
        old_id: u64,
        managed: Box<ManagedPeerState>,
        rib_owner: Option<u64>,
    },
}

/// Start one of a round's owned waits: poll it once now, so its command is
/// sent and its window is open before the actor does anything else inline.
pub(super) fn start_round_wait<T>(
    wait: impl std::future::Future<Output = T> + Send + 'static,
    pending: &mut futures::stream::FuturesUnordered<futures::future::BoxFuture<'static, T>>,
    ready: &mut VecDeque<T>,
) {
    let mut wait = wait.boxed();
    // Every target gets its first poll before any completion can await.
    if let Some(completed) = wait.as_mut().now_or_never() {
        ready.push_back(completed);
    } else {
        pending.push(wait);
    }
}

impl NotificationRetirement {
    /// Stop the primary and join every session at once, each within
    /// `deadline_at`, so a primary that cannot take its Stop leaves a pending
    /// candidate its whole window for an orderly Shutdown.
    async fn wait(self, deadline_at: Instant) -> SettledNotificationRetirement {
        let Self {
            peer,
            sessions,
            stop_primary,
            dynamic,
        } = self;
        let stop = async move {
            let (id, commands) = stop_primary?;
            let remaining = deadline_at.saturating_duration_since(Instant::now());
            let timed_out = || rustbgpd_transport::PeerCommandError::TimedOut {
                operation: "stop",
                deadline: remaining,
            };
            let result = if remaining.is_zero() {
                Err(timed_out())
            } else {
                match tokio::time::timeout_at(
                    deadline_at,
                    commands.send(rustbgpd_transport::PeerCommand::Stop { reason: None }),
                )
                .await
                {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(_)) => Err(rustbgpd_transport::PeerCommandError::SessionExited),
                    Err(_) => Err(timed_out()),
                }
            };
            result.err().map(|error| (id, error))
        };
        let address = peer.address;
        let joins = futures::future::join_all(sessions.into_iter().map(
            |(id, handle, context)| async move {
                let registration = handle.rib_registration_state();
                PeerManager::shutdown_handle_until_owned(address, context, handle, deadline_at)
                    .await;
                // Final only now: the task can register until it ends.
                (id, registration.owner(id))
            },
        ));
        let (failed_stop, sessions) = futures::join!(stop, joins);
        SettledNotificationRetirement {
            peer,
            sessions,
            failed_stop,
            dynamic,
        }
    }
}

impl PeerManager {
    /// A failed Stop enqueue cannot leave a candidate's sibling primary live:
    /// abort it, fence its old RIB ownership, and install a fresh disabled Idle
    /// actor so the max-prefix latch remains fail-closed but explicit Enable is
    /// still a usable recovery operation. A primary whose task already ended
    /// is replaced the same way. Returns the replaced task's panic message,
    /// if it panicked.
    pub(super) async fn replace_unstoppable_primary(
        &mut self,
        peer_key: &rustbgpd_api::peer_types::PeerKey,
    ) -> Option<String> {
        let (
            old_session_id,
            superseded,
            mut transport,
            import_policy,
            export_policy,
            gshut,
            tcp_ao_generation,
        ) = self.peers.get(peer_key).map(|managed| {
            (
                managed.session_id(),
                managed
                    .handle()
                    .rib_registration_owner(managed.session_id()),
                managed.transport_config.clone(),
                managed.import_policy.clone(),
                managed.export_policy.clone(),
                managed.advertise_graceful_shutdown,
                managed.tcp_ao_rotation.applied,
            )
        })?;

        self.admit_deferred_rib_updates_for(peer_key).await;
        transport.supersedes_session = superseded;
        let new_session_id = self.allocate_session_id();
        let replacement = PeerHandle::spawn_at_tcp_ao_generation(
            transport,
            self.metrics.clone(),
            self.rib_tx.clone(),
            import_policy,
            export_policy,
            Some(self.session_notify_tx.clone()),
            Some(self.session_notification_event_tx.clone()),
            Some(self.session_lifecycle_tx.clone()),
            self.session_bmp_tx(peer_key),
            self.validation_rx.clone(),
            gshut,
            SessionIdentity::primary(new_session_id),
            tcp_ao_generation,
        );
        let (aborted, _) = self
            .peers
            .replace_handle(peer_key, replacement, new_session_id)?;
        // Join cancellation before publishing PeerDown, so the old actor
        // emits nothing new behind the fence. What it already held follows
        // from its own hand-off, ending with its PeerDown when it was
        // Established; the RIB drops route messages from a session it no
        // longer registers.
        let panic = aborted.join_exited().await;

        // The aborted session retires itself in the RIB, but this send stays:
        // it is on this actor's ordered lane, ahead of the barrier or Enable
        // that follows, where the session's hand-off has no fixed place while
        // the mailbox is full, and it also clears a primary that was not
        // Established and so had no epoch of its own to close. When the
        // primary was Established the RIB therefore sees two PeerDowns for
        // it: this authoritative one and the one its hand-off delivers
        // marked late. Whichever arrives second finds an empty peer. The
        // late one can no longer end retention another session created,
        // however long the mailbox delays it.
        // Reads stay queued while the peer's session identity is mid-swap.
        if self
            .send_rib_update(
                rustbgpd_rib::RibUpdate::PeerDown {
                    peer: self.rib_peer_of(peer_key),
                    session_id: old_session_id,
                },
                super::OperatorReadAdmission::Fenced {
                    reason: "the replaced primary's session is not yet unregistered",
                },
            )
            .await
            .is_err()
        {
            warn!(peer = %peer_key, old_session_id, "RIB unavailable while fencing replaced primary");
        }
        self.unregister_session(old_session_id);
        self.register_session(new_session_id, peer_key);
        panic
    }

    /// Whether a repeating session-task crash latched `peer` disabled until
    /// an explicit enable.
    pub(super) fn session_crash_latched(&self, peer: &PeerKey) -> bool {
        self.session_crashes
            .get(peer)
            .is_some_and(|crashes| crashes.latched)
    }

    /// The neighbor's `last_error` for its latest session-task crash, and
    /// whether the crashes latched it, while the peer is latched or that
    /// crash is within the window.
    pub(super) fn session_crash_error(&self, peer: &PeerKey) -> Option<(&str, bool)> {
        self.session_crashes
            .get(peer)
            .and_then(SessionCrashes::error)
    }

    /// Take `peer`'s crash record, to carry an interface-only neighbor's to
    /// its next endpoint, under a new key.
    pub(super) fn take_session_crashes(&mut self, peer: &PeerKey) -> Option<SessionCrashes> {
        self.session_crashes.remove(peer)
    }

    /// Install a carried crash record under the neighbor's new key.
    pub(super) fn restore_session_crashes(&mut self, peer: &PeerKey, crashes: SessionCrashes) {
        self.session_crashes.insert(peer.clone(), crashes);
    }

    /// Forget `peer`'s session-task crashes: an explicit enable, or the
    /// neighbor is gone.
    pub(super) fn clear_session_crashes(&mut self, peer: &PeerKey) {
        self.session_crashes.remove(peer);
    }

    /// Record one crash of `peer_key`'s session task and set its
    /// `last_error`. Returns the crashes within the window, whether this one
    /// latches the peer, and the error. `cause` is already scrubbed.
    fn record_session_crash(&mut self, peer_key: &PeerKey, cause: &str) -> (usize, bool, String) {
        let now = Instant::now();
        // Records outlive their peers (a dynamic peer reconnects under the
        // same key), so lapsed ones are dropped here, where records are made.
        self.session_crashes
            .retain(|key, crashes| key == peer_key || crashes.current(now));
        let unix_seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        // The recovery names the neighbor as `rbgp neighbor` selects it: an
        // interface-only neighbor by its interface, which outlives the
        // learned endpoint the record may move away from.
        let selector = match peer_key.interface.as_deref() {
            Some(interface) if self.interface_only_owns(Some(interface)) => interface.to_owned(),
            _ => peer_key.label(),
        };
        let crashes = self.session_crashes.entry(peer_key.clone()).or_default();
        while crashes
            .recent
            .front()
            .is_some_and(|at| now.duration_since(*at) >= SESSION_CRASH_WINDOW)
        {
            crashes.recent.pop_front();
        }
        crashes.recent.push_back(now);
        let count = crashes.recent.len();
        let latch = count >= SESSION_CRASH_LATCH;
        crashes.latched |= latch;
        let window_minutes = SESSION_CRASH_WINDOW.as_secs() / 60;
        let error = if latch {
            format!(
                "session task crashed at unix time {unix_seconds} ({cause}), {count} times in \
                 {window_minutes} minutes; peer latched disabled; run 'rbgp neighbor {selector} \
                 enable' to restart it"
            )
        } else {
            format!(
                "session task crashed at unix time {unix_seconds} ({cause}); restarted, \
                 {count} of {SESSION_CRASH_LATCH} crashes in {window_minutes} minutes before \
                 the peer is latched disabled"
            )
        };
        crashes.last_error.clone_from(&error);
        (count, latch, error)
    }

    /// Latch `peer_key` disabled after its [`SESSION_CRASH_LATCH`]th crash,
    /// as a max-prefix shutdown does: an armed max-prefix restart can no
    /// longer re-enable it, a pending inbound candidate is retired rather
    /// than promoted, and with `stop_primary` the live primary is stopped. A
    /// dynamic peer already being retired is kept, disabled, by its
    /// retirement.
    fn latch_crashed_peer(
        &mut self,
        peer_key: &PeerKey,
        error: String,
        stop_primary: bool,
        retirements: &mut Vec<NotificationRetirement>,
    ) {
        self.invalidate_max_prefix_restart(peer_key);
        self.publish_peer_lifecycle_event(
            peer_key,
            rustbgpd_api::peer_types::SessionLifecycleEventType::PeerDisabled,
            error,
        );
        let stop_primary = self
            .peers
            .get(peer_key)
            .filter(|_| stop_primary)
            .map(|managed| (managed.session_id(), managed.handle().commands_sender()));
        let Some(managed) = self.peers.get_mut(peer_key) else {
            return;
        };
        managed.enabled = false;
        let pending = managed.pending_inbound.take();
        self.publish_peer_admin_enabled_metric(peer_key, false);
        self.set_bfd_peer_disabled(peer_key.address, true);
        let sessions: Vec<_> = pending
            .into_iter()
            .map(|pending| {
                self.retiring_sessions
                    .insert(pending.session_id, peer_key.clone());
                (
                    pending.session_id,
                    pending.handle,
                    "session-crash latch pending inbound",
                )
            })
            .collect();
        if stop_primary.is_some() || !sessions.is_empty() {
            retirements.push(NotificationRetirement {
                peer: peer_key.clone(),
                sessions,
                stop_primary,
                dynamic: None,
            });
        }
    }

    /// A session task ended without a shutdown request. Every crash counts
    /// toward the peer's latch: its [`SESSION_CRASH_LATCH`]th within
    /// [`SESSION_CRASH_WINDOW`] latches the peer disabled until an explicit
    /// enable.
    ///
    /// A pending inbound candidate, or an enabled dynamic peer, is handled as
    /// if the session fell back to Idle. Any other primary is replaced by a
    /// fresh session, which is started again when the peer is a static one,
    /// enabled and not latched. A disabled or dampening-blocked dynamic peer
    /// thus keeps a live session for a later enable.
    ///
    /// The replacement publishes the dead session's `PeerDown` on this
    /// actor's ordered RIB lane before the new session gets its `Start`, so
    /// the dead epoch is closed in the RIB before the new one's `PeerUp`.
    #[expect(
        clippy::too_many_lines,
        reason = "one ordered decision: which exit retires, which is replaced, and whether the replacement starts"
    )]
    async fn handle_session_task_exit(
        &mut self,
        session_id: u64,
        role: rustbgpd_transport::SessionRole,
        peer_addr: std::net::IpAddr,
        cause: String,
        retirements: &mut Vec<NotificationRetirement>,
    ) {
        // An error or panic message is arbitrary text: log and keep one
        // bounded line of it.
        let scrub = rustbgpd_telemetry::metrics::scrub_info_label;
        let cause = scrub(&cause);
        let Some(peer_key) = self.peer_key_for_session(session_id) else {
            debug!(peer = %peer_addr, session_id, ?role, "ignoring task exit of unknown session");
            return;
        };
        let Some(managed) = self.peers.get(&peer_key) else {
            return;
        };
        let primary = managed.session_id() == session_id;
        let pending = managed
            .pending_inbound
            .as_ref()
            .is_some_and(|pending| pending.session_id == session_id);
        if !primary && !pending {
            // A retiring session: its owner joins it.
            debug!(peer = %peer_addr, session_id, ?role, %cause, "ignoring task exit of a retiring session");
            return;
        }
        let dynamic = managed.is_dynamic;
        let enabled = managed.enabled;
        let blocked = managed
            .transport_config
            .dampening_admission
            .as_ref()
            .is_some_and(rustbgpd_rib::dampening::DampeningAdmission::is_blocked);
        // A dynamic primary's exit retires the peer. A policy walk that owns
        // the actor holds the whole notice, before the crash is counted.
        if !pending
            && dynamic
            && enabled
            && !blocked
            && self
                .hold_for_owned_walk(SessionNotification::TaskExited {
                    session_id,
                    role,
                    peer_addr,
                    cause: cause.clone(),
                })
                .is_none()
        {
            return;
        }
        self.metrics.record_session_task_crash(
            &self.peer_metric_label(&peer_key),
            peer_key.interface.as_deref().unwrap_or(""),
        );
        if pending || (dynamic && enabled && !blocked) {
            // Recorded first: a latched dynamic peer's retirement keeps it.
            let (count, latch, error) = self.record_session_crash(&peer_key, &cause);
            warn!(peer = %peer_addr, session_id, ?role, %cause, count, "session task ended without a shutdown request; retiring it");
            // The same event: the re-entry counts it again.
            self.uncount_owned_walk_event();
            Box::pin(self.handle_one_session_notification(
                SessionNotification::BackToIdle {
                    session_id,
                    role,
                    peer_addr,
                },
                retirements,
            ))
            .await;
            if latch {
                // A crashed candidate's primary can be live.
                self.latch_crashed_peer(&peer_key, error, pending, retirements);
                warn!(peer = %peer_addr, session_id, %cause, count, "session task crashed repeatedly; peer latched disabled until an explicit enable");
            }
            return;
        }

        self.note_unnumbered_session_idle(&peer_key);
        let panic = self.replace_unstoppable_primary(&peer_key).await;
        let cause = panic.map_or(cause, |message| scrub(&format!("panicked: {message}")));
        let (count, latch, error) = self.record_session_crash(&peer_key, &cause);

        if latch {
            self.latch_crashed_peer(&peer_key, error, false, retirements);
            warn!(peer = %peer_addr, session_id, %cause, count, "session task crashed repeatedly; peer latched disabled until an explicit enable");
            return;
        }
        if dynamic {
            self.mark_unadmitted_disabled_dynamic(&peer_key);
            warn!(peer = %peer_addr, session_id, %cause, "session task of a disabled or dampening-blocked dynamic peer crashed; replaced, not started");
            return;
        }
        if !enabled {
            warn!(peer = %peer_addr, session_id, %cause, "session task of a disabled peer crashed; replaced, not started");
            return;
        }
        if self.bfd_should_withhold(&peer_addr) {
            // A BFD session that stays Up sends no new edge: republishing the
            // desired state asks the BFD actor for the acknowledgement that
            // releases the hold, as enable does.
            self.set_bfd_peer_disabled(peer_addr, false);
            self.mark_bfd_withheld(peer_addr);
            warn!(peer = %peer_addr, session_id, %cause, "session task crashed; replaced, strict BFD withholds the restart until BFD Up");
            return;
        }
        if self.bfd_withholding(&peer_addr) {
            // A BFD Down holds this peer: the Up that releases the hold
            // sends the replacement its `Start`. An Up handled before this
            // exit met the ended session and left the hold in place, so the
            // desired state is republished for the BFD actor to re-confirm
            // the level, as on the strict path. Inside a generation
            // publication is suspended, and its commit or abort settles it.
            self.set_bfd_peer_disabled(peer_addr, false);
            self.keep_bfd_hold_across_replacement(peer_addr);
            warn!(peer = %peer_addr, session_id, %cause, "session task crashed; replaced, the BFD hold withholds the restart until BFD Up");
            return;
        }
        // The replacement's command channel is new and empty.
        let started = self.peers.get(&peer_key).is_some_and(|managed| {
            managed
                .handle()
                .commands_sender()
                .try_send(rustbgpd_transport::PeerCommand::Start)
                .is_ok()
        });
        if started {
            warn!(peer = %peer_addr, session_id, %cause, count, "session task crashed; restarted the session");
        } else {
            warn!(peer = %peer_addr, session_id, %cause, "session task crashed; the replacement did not accept Start");
        }
    }

    /// The Idle primary's state, queried only when a candidate is pending.
    async fn idle_primary_state_for_pending(
        &mut self,
        peer_key: &PeerKey,
    ) -> Option<rustbgpd_transport::StateQueryOutcome> {
        let managed = self.peers.get(peer_key)?;
        managed.pending_inbound.as_ref()?;
        let commands = managed.handle().commands_sender();
        Some(
            self.await_session_sweep(PeerHandle::query_state_outcome_with(
                commands,
                super::PEER_QUERY_TIMEOUT,
            ))
            .await,
        )
    }

    /// Drain lossless session ownership/latch signals that were already queued
    /// before an inbound-accept command. This closes the cross-channel race in
    /// which a passive reconnect could replace the breached session generation
    /// before its max-prefix latch was applied.
    ///
    /// Outside a notification handler this handles every ready notification.
    /// Inside one (a promotion or retirement fence for `peer`) it handles
    /// `peer`'s notifications in order and defers the rest to the outermost
    /// handler, so nesting is bounded by one peer's notices instead of growing
    /// with every queued collision until the worker stack overflows. A
    /// notification is `peer`'s when its session resolves to `peer`; one that
    /// does not resolve, or a fence with no `peer`, handles nothing.
    pub(super) async fn drain_ready_session_notifications(&mut self, peer: Option<&PeerKey>) {
        if self.session_notification_depth == 0 {
            // Until the channel is empty: a notice queued while an earlier
            // one was handled is applied before the caller goes on.
            while let Ok(notification) = self.session_notify_rx.try_recv() {
                self.drain_ready_session_lifecycle_notifications();
                super::boxed(|| self.handle_session_notification(notification)).await;
            }
            return;
        }
        let ready = self.session_notify_rx.ready_count()
            + peer
                .and_then(|peer| self.deferred_session_notification_counts.get(peer))
                .copied()
                .unwrap_or(0);
        for _ in 0..ready {
            // `peer`'s deferred notices are older than anything still queued.
            let deferred = peer
                .filter(|peer| {
                    self.deferred_session_notification_counts
                        .contains_key(*peer)
                })
                .and_then(|peer| self.take_deferred_session_notification(peer));
            let notification = if deferred.is_some() {
                self.drain_ready_session_lifecycle_notifications();
                deferred
            } else if let Ok(notification) = self.session_notify_rx.try_recv() {
                self.drain_ready_session_lifecycle_notifications();
                let owner = self.peer_key_for_session(session_notification_id(&notification));
                if owner.is_some() && owner.as_ref() == peer {
                    Some(notification)
                } else {
                    self.defer_session_notification(owner, notification);
                    None
                }
            } else {
                return;
            };
            if let Some(notification) = notification {
                super::boxed(|| self.handle_session_notification(notification)).await;
            }
        }
    }

    /// Defer another peer's notification to the outermost handler. Dequeueing
    /// a max-prefix warning frees its scope's slot in the session channel, so
    /// a long nested drain can take that scope's next warning too; it is added
    /// to the deferred one, keeping one deferred warning per session scope.
    fn defer_session_notification(
        &mut self,
        owner: Option<PeerKey>,
        notification: SessionNotification,
    ) {
        if let SessionNotification::MaxPrefixWarning {
            session_id,
            family,
            stage,
            crossings,
            ..
        } = &notification
        {
            match self
                .deferred_warning_crossings
                .entry((*session_id, *family, *stage))
            {
                std::collections::hash_map::Entry::Occupied(mut queued) => {
                    let queued = queued.get_mut();
                    *queued = queued.saturating_add(*crossings);
                    return;
                }
                std::collections::hash_map::Entry::Vacant(scope) => {
                    scope.insert(*crossings);
                }
            }
        }
        if let Some(owner) = &owner {
            *self
                .deferred_session_notification_counts
                .entry(owner.clone())
                .or_default() += 1;
        }
        self.deferred_session_notifications
            .push_back((owner, notification));
    }

    /// Remove `peer`'s oldest deferred notification. The scan is O(deferred)
    /// and runs only while `peer` has one, so a fence costs O(deferred) per
    /// own notice rather than per drained notification.
    fn take_deferred_session_notification(
        &mut self,
        peer: &PeerKey,
    ) -> Option<SessionNotification> {
        let index = self
            .deferred_session_notifications
            .iter()
            .position(|(owner, _)| owner.as_ref() == Some(peer))?;
        self.release_deferred_session_notification(index)
    }

    fn release_deferred_session_notification(
        &mut self,
        index: usize,
    ) -> Option<SessionNotification> {
        let (owner, mut notification) = self.deferred_session_notifications.remove(index)?;
        if let SessionNotification::MaxPrefixWarning {
            session_id,
            family,
            stage,
            crossings,
            ..
        } = &mut notification
            && let Some(total) =
                self.deferred_warning_crossings
                    .remove(&(*session_id, *family, *stage))
        {
            *crossings = total;
        }
        if let Some(owner) = owner
            && let Some(count) = self.deferred_session_notification_counts.get_mut(&owner)
        {
            *count -= 1;
            if *count == 0 {
                self.deferred_session_notification_counts.remove(&owner);
            }
        }
        Some(notification)
    }

    /// Capture one finite outer round. Nested drains keep one peer's notices
    /// ordered; unrelated notices they discover belong to the following round.
    pub(super) async fn handle_session_notification(&mut self, notification: SessionNotification) {
        self.handle_session_notification_round(notification, usize::MAX)
            .await;
    }

    /// [`Self::handle_session_notification`], capturing at most `more`
    /// further queued notifications into the outer round: a policy walk's
    /// seam bounds what one round takes from the channel.
    pub(super) async fn handle_session_notification_round(
        &mut self,
        notification: SessionNotification,
        more: usize,
    ) {
        self.session_notification_depth += 1;
        if self.session_notification_depth > 1 {
            let mut retirements = Vec::new();
            super::boxed(|| self.handle_one_session_notification(notification, &mut retirements))
                .await;
            self.finish_notification_round(retirements).await;
            self.session_notification_depth -= 1;
            return;
        }
        let owner = self.peer_key_for_session(session_notification_id(&notification));
        self.defer_session_notification(owner, notification);
        for _ in 0..self.session_notify_rx.ready_count().min(more) {
            if let Ok(notification) = self.session_notify_rx.try_recv() {
                let owner = self.peer_key_for_session(session_notification_id(&notification));
                self.defer_session_notification(owner, notification);
            }
        }
        loop {
            let mut retirements = Vec::new();
            let mut ordered_after_collision = BTreeSet::new();
            let ready = self.deferred_session_notifications.len();
            let mut index = 0;
            for _ in 0..ready {
                let Some((peer, notification)) = self.deferred_session_notifications.get(index)
                else {
                    break;
                };
                let collision = self.is_collision_notification(notification);
                if collision
                    || peer
                        .as_ref()
                        .is_some_and(|peer| ordered_after_collision.contains(peer))
                {
                    if let Some(peer) = peer {
                        ordered_after_collision.insert(peer.clone());
                    }
                    index += 1;
                    continue;
                }
                let notification = self
                    .release_deferred_session_notification(index)
                    .expect("the captured notification remains queued");
                self.drain_ready_session_lifecycle_notifications();
                super::boxed(|| {
                    self.handle_one_session_notification(notification, &mut retirements)
                })
                .await;
            }
            self.finish_notification_round(retirements).await;
            // A newly deferred ordinary retirement belongs to the next
            // finite cohort; only collision selection runs on its own.
            if self.deferred_session_notifications.is_empty() {
                break;
            }
            if self
                .deferred_session_notifications
                .front()
                .is_some_and(|(_, notification)| self.is_collision_notification(notification))
            {
                let notification = self
                    .release_deferred_session_notification(0)
                    .expect("the deferred collision remains queued");
                let mut retirements = Vec::new();
                super::boxed(|| {
                    self.handle_one_session_notification(notification, &mut retirements)
                })
                .await;
                self.finish_notification_round(retirements).await;
            }
            // Unrelated notices found by a nested drain form the next finite batch.
        }
        self.session_notification_depth -= 1;
    }

    fn is_collision_notification(&self, notification: &SessionNotification) -> bool {
        if matches!(notification, SessionNotification::OpenReceived { .. }) {
            return true;
        }
        let SessionNotification::BackToIdle { session_id, .. } = notification else {
            return false;
        };
        self.peer_key_for_session(*session_id)
            .and_then(|peer| self.peers.get(&peer))
            .is_some_and(|managed| {
                managed.session_id() == *session_id
                    && !managed.is_dynamic
                    && managed.pending_inbound.is_some()
                    && managed.enabled
                    && !self.bfd_withholding(&managed.transport_config.remote_addr.ip())
            })
    }

    fn queue_notification_retirement(
        &mut self,
        peer: &PeerKey,
        session_id: u64,
        handle: PeerHandle,
        context: &'static str,
        retirements: &mut Vec<NotificationRetirement>,
    ) {
        self.retiring_sessions.insert(session_id, peer.clone());
        retirements.push(NotificationRetirement {
            peer: peer.clone(),
            sessions: vec![(session_id, handle, context)],
            stop_primary: None,
            dynamic: None,
        });
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one completion pump keeps same-peer ordering and ownership settlement visible together"
    )]
    async fn finish_notification_round(&mut self, retirements: Vec<NotificationRetirement>) {
        if retirements.is_empty() {
            return;
        }
        #[cfg(test)]
        if retirements
            .iter()
            .any(|retirement| retirement.dynamic.is_some())
        {
            self.hold_retirement_for_test().await;
        }
        // The round's clock starts with its concurrent session waits: what a
        // handler awaited inline before them is not charged to any session.
        let deadline_at = Instant::now() + super::PEER_LIFECYCLE_COMMAND_TIMEOUT;
        let mut by_peer: BTreeMap<PeerKey, VecDeque<NotificationRetirement>> = BTreeMap::new();
        for retirement in retirements {
            by_peer
                .entry(retirement.peer.clone())
                .or_default()
                .push_back(retirement);
        }
        let mut pending = futures::stream::FuturesUnordered::new();
        let mut ready = VecDeque::new();
        for queue in by_peer.values_mut() {
            if let Some(retirement) = queue.pop_front() {
                start_round_wait(
                    async move { NotificationCompletion::Sessions(retirement.wait(deadline_at).await) },
                    &mut pending,
                    &mut ready,
                );
            }
        }
        loop {
            let completion = if let Some(completion) = ready.pop_front() {
                completion
            } else if let Some(completion) = self.await_session_sweep(pending.next()).await {
                completion
            } else {
                break;
            };
            let (settled, barrier_failed) = match completion {
                NotificationCompletion::Replaced {
                    peer,
                    old_id,
                    managed,
                    rib_owner,
                } => {
                    let mut additional = Vec::new();
                    Box::pin(self.collect_notification_owner(&peer, &mut additional)).await;
                    by_peer.entry(peer.clone()).or_default().extend(additional);
                    self.finish_notification_replacement(&peer, old_id, *managed, rib_owner);
                    if let Some(retirement) = by_peer.get_mut(&peer).and_then(VecDeque::pop_front) {
                        start_round_wait(
                            async move {
                                NotificationCompletion::Sessions(retirement.wait(deadline_at).await)
                            },
                            &mut pending,
                            &mut ready,
                        );
                    }
                    continue;
                }
                NotificationCompletion::Barrier(settled, failed) => (settled, failed),
                NotificationCompletion::Sessions(mut settled) => {
                    let peer = &settled.peer;
                    if let Some((session_id, error)) = settled.failed_stop.take()
                        && self
                            .peers
                            .get(peer)
                            .is_some_and(|managed| managed.session_id() == session_id)
                    {
                        warn!(peer = %peer, session_id, %error, "failed to stop primary after max-prefix breach");
                        if let Some(managed) = self.peers.remove(peer) {
                            let (aborted, old_id, managed) = managed.into_parts();
                            let peer = peer.clone();
                            self.retiring_sessions.insert(old_id, peer.clone());
                            start_round_wait(
                                async move {
                                    let rib_owner =
                                        aborted.abort_and_rib_registration_owner(old_id).await;
                                    NotificationCompletion::Replaced {
                                        peer,
                                        old_id,
                                        managed: Box::new(managed),
                                        rib_owner,
                                    }
                                },
                                &mut pending,
                                &mut ready,
                            );
                        }
                    }
                    if settled.dynamic.as_ref().is_some_and(|dynamic| {
                        dynamic
                            .managed
                            .transport_config
                            .dampening_admission
                            .as_ref()
                            .is_some_and(|admission| admission.owner.records_wire_history())
                    }) {
                        let sessions = settled.sessions.iter().copied();
                        if let Some(acknowledged) =
                            self.dampening_retirement_barrier(peer, sessions)
                        {
                            // Admission and acknowledgement share the bound
                            // of every other primary-lane control round trip.
                            let barrier_deadline = Instant::now() + super::RIB_REPLY_TIMEOUT;
                            start_round_wait(
                                async move {
                                    let failed = !matches!(
                                        tokio::time::timeout_at(barrier_deadline, acknowledged)
                                            .await,
                                        Ok(Ok(_))
                                    );
                                    NotificationCompletion::Barrier(settled, failed)
                                },
                                &mut pending,
                                &mut ready,
                            );
                            continue;
                        }
                        (settled, true)
                    } else {
                        (settled, false)
                    }
                }
            };
            let peer = settled.peer.clone();
            let mut additional = Vec::new();
            Box::pin(self.collect_notification_owner(&peer, &mut additional)).await;
            by_peer.entry(peer.clone()).or_default().extend(additional);
            for (id, _) in &settled.sessions {
                self.retiring_sessions.remove(id);
                self.unregister_session(*id);
            }
            if let Some(dynamic) = settled.dynamic {
                // The primary's registration as read after its task ended.
                let superseded = settled
                    .sessions
                    .iter()
                    .find(|(id, _)| *id == dynamic.primary_id)
                    .and_then(|(_, owner)| *owner);
                self.finish_dynamic_notification_retirement(
                    &peer,
                    *dynamic,
                    superseded,
                    barrier_failed,
                );
            }
            if let Some(retirement) = by_peer.get_mut(&peer).and_then(VecDeque::pop_front) {
                start_round_wait(
                    async move { NotificationCompletion::Sessions(retirement.wait(deadline_at).await) },
                    &mut pending,
                    &mut ready,
                );
            }
        }
    }

    /// Joined producers' same-peer notices apply before their IDs disappear.
    /// Any retirement they request joins the outer pump rather than holding
    /// another peer's ready bookkeeping behind a nested wait.
    async fn collect_notification_owner(
        &mut self,
        peer: &PeerKey,
        retirements: &mut Vec<NotificationRetirement>,
    ) {
        let ready = self.session_notify_rx.ready_count()
            + self
                .deferred_session_notification_counts
                .get(peer)
                .copied()
                .unwrap_or(0);
        for _ in 0..ready {
            // The count is checked first: the scan is O(deferred), and other
            // peers' notices deferred below must not be rescanned each turn.
            let deferred = self
                .deferred_session_notification_counts
                .contains_key(peer)
                .then(|| self.take_deferred_session_notification(peer))
                .flatten();
            let notification = if let Some(notification) = deferred {
                notification
            } else if let Ok(notification) = self.session_notify_rx.try_recv() {
                let owner = self.peer_key_for_session(session_notification_id(&notification));
                if owner.as_ref() != Some(peer) {
                    self.defer_session_notification(owner, notification);
                    continue;
                }
                notification
            } else {
                break;
            };
            self.drain_ready_session_lifecycle_notifications();
            self.handle_one_session_notification(notification, retirements)
                .await;
        }
    }

    pub(super) fn finish_notification_replacement(
        &mut self,
        peer: &PeerKey,
        old_id: u64,
        mut managed: ManagedPeerState,
        rib_owner: Option<u64>,
    ) {
        self.fence_retired_session(peer, old_id, rib_owner);
        let session_id = self.allocate_session_id();
        let mut transport = managed.transport_config.clone();
        transport.supersedes_session = rib_owner;
        let handle = PeerHandle::spawn_at_tcp_ao_generation(
            transport,
            self.metrics.clone(),
            self.rib_tx.clone(),
            managed.import_policy.clone(),
            managed.export_policy.clone(),
            Some(self.session_notify_tx.clone()),
            Some(self.session_notification_event_tx.clone()),
            Some(self.session_lifecycle_tx.clone()),
            self.session_bmp_tx(peer),
            self.validation_rx.clone(),
            managed.advertise_graceful_shutdown,
            SessionIdentity::primary(session_id),
            managed.tcp_ao_rotation.applied,
        );
        managed.enabled = false;
        self.peers
            .insert(peer.clone(), ManagedPeer::new(handle, session_id, managed));
        self.retiring_sessions.remove(&old_id);
        self.unregister_session(old_id);
        self.register_session(session_id, peer);
    }

    /// Queue the dynamic source-retirement fence without waiting for the
    /// RIB: the end of every joined session (each `(id, registration owner)`
    /// through [`Self::fence_retired_session`]), then an acknowledgement,
    /// in that order on this actor's primary lane. The RIB therefore answers
    /// only after it has handled every route batch those sessions queued and
    /// has stopped accepting what they still hand off, so a capacity block
    /// their routes cause is published before the caller reads it. A full
    /// mailbox, or updates already deferred, keep the fence in the deferred
    /// FIFO, which the caller's readiness wait sends as room appears. `None`
    /// once the RIB has exited.
    pub(super) fn dampening_retirement_barrier(
        &mut self,
        peer: &PeerKey,
        retired_sessions: impl IntoIterator<Item = (u64, Option<u64>)>,
    ) -> Option<tokio::sync::oneshot::Receiver<usize>> {
        for (session_id, owner) in retired_sessions {
            self.fence_retired_session(peer, session_id, owner);
        }
        let (reply, acknowledged) = tokio::sync::oneshot::channel();
        self.defer_rib_update(None, rustbgpd_rib::RibUpdate::QueryLocRibCount { reply })
            .ok()
            .map(|()| acknowledged)
    }

    /// End a joined session in the RIB: the registration it owned when its
    /// task ended (`owner`: itself, or the predecessor it inherited), and,
    /// when that is a predecessor, also what the session staged under its
    /// own id before a `PeerUp` it never delivered. That second end is
    /// always marked late: with no session registered a plain `PeerDown`
    /// would run the peer's teardown and could purge retention the
    /// predecessor's restart end created, where a late one only drops the
    /// staged context. Neither waits for mailbox room.
    fn fence_retired_session(&mut self, peer: &PeerKey, session_id: u64, owner: Option<u64>) {
        if owner.is_some_and(|owner| owner != session_id) {
            let staged = rustbgpd_rib::RibUpdate::PeerDown {
                peer: self.rib_peer_of(peer),
                session_id,
            };
            if self
                .defer_rib_update(
                    None,
                    rustbgpd_rib::RibUpdate::LateSessionEnd(Box::new(staged)),
                )
                .is_err()
            {
                warn!(peer = %peer, session_id, "RIB unavailable while dropping a retired session's staged context");
            }
        }
        self.defer_retired_session_down(peer, owner.unwrap_or(session_id));
    }

    /// A queued cleanup can outlive more than one replacement. Mark it late
    /// so it cannot purge retention belonging to any later RIB generation.
    fn defer_retired_session_down(&mut self, peer: &PeerKey, session_id: u64) {
        let update = rustbgpd_rib::RibUpdate::PeerDown {
            peer: self.rib_peer_of(peer),
            session_id,
        };
        let update = if self.deferred_rib.queue.is_empty() {
            match self.rib_tx.try_send(update) {
                Ok(()) => return,
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    warn!(peer = %peer, session_id, "RIB unavailable while fencing retired session");
                    return;
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(update)) => update,
            }
        } else {
            update
        };
        let _ = self.defer_rib_update(
            None,
            rustbgpd_rib::RibUpdate::LateSessionEnd(Box::new(update)),
        );
    }

    #[expect(
        clippy::too_many_lines,
        reason = "notification handling keeps collision, dynamic-peer removal, and lifecycle ordering together"
    )]
    async fn handle_one_session_notification(
        &mut self,
        notification: SessionNotification,
        retirements: &mut Vec<NotificationRetirement>,
    ) {
        self.count_owned_walk_event();
        match notification {
            SessionNotification::OpenReceived {
                session_id,
                role,
                peer_addr,
                remote_router_id,
                peer_asn,
            } => {
                let Some(peer_key) = self.peer_key_for_session(session_id) else {
                    debug!(peer = %peer_addr, session_id, ?role, "ignoring notification for unknown peer session");
                    return;
                };
                let matches_current = self.peers.get(&peer_key).is_some_and(|m| {
                    m.session_id() == session_id
                        || m.pending_inbound
                            .as_ref()
                            .is_some_and(|p| p.session_id == session_id)
                });
                if !matches_current {
                    debug!(peer = %peer_addr, session_id, ?role, "ignoring stale OpenReceived notification");
                    return;
                }
                // A retained member's collision verdict can move it to the
                // candidate's RIB identity, which a policy walk that owns the
                // actor may already have named in its rollback. The walk
                // holds the notice until it ends.
                if self.retained_dynamic_candidate_pending(&peer_key)
                    && self
                        .hold_for_owned_walk(SessionNotification::OpenReceived {
                            session_id,
                            role,
                            peer_addr,
                            remote_router_id,
                            peer_asn,
                        })
                        .is_none()
                {
                    return;
                }
                self.learn_dynamic_remote_asn(&peer_key, peer_asn);
                if self
                    .peers
                    .get(&peer_key)
                    .is_some_and(|m| m.pending_inbound.is_some())
                {
                    super::boxed(|| {
                        self.resolve_collision(peer_key.clone(), remote_router_id, peer_asn)
                    })
                    .await;
                }
                // The session whose OPEN this is, if it is the primary now: a
                // collision winner promoted just above takes the retention
                // handoff too; a loser never does.
                if self
                    .peers
                    .get(&peer_key)
                    .is_some_and(|m| m.session_id() == session_id)
                {
                    self.retained_dynamic_open_from(&peer_key, peer_asn);
                }
            }
            SessionNotification::BackToIdle {
                session_id,
                role,
                peer_addr,
            } => {
                let Some(peer_key) = self.peer_key_for_session(session_id) else {
                    debug!(peer = %peer_addr, session_id, ?role, "ignoring BackToIdle for unknown peer session");
                    return;
                };
                let pending = self.peers.get_mut(&peer_key).and_then(|m| {
                    if m.pending_inbound
                        .as_ref()
                        .is_some_and(|p| p.session_id == session_id)
                    {
                        m.pending_inbound.take()
                    } else {
                        None
                    }
                });
                if let Some(pending) = pending {
                    debug!(peer = %peer_addr, session_id, ?role, "inbound collision candidate went idle, dropping");
                    self.queue_notification_retirement(
                        &peer_key,
                        pending.session_id,
                        pending.handle,
                        "BackToIdle pending inbound candidate",
                        retirements,
                    );
                    return;
                }

                let current_primary = self
                    .peers
                    .get(&peer_key)
                    .is_some_and(|m| m.session_id() == session_id);
                if !current_primary {
                    debug!(peer = %peer_addr, session_id, ?role, "ignoring stale BackToIdle notification");
                    return;
                }
                self.note_unnumbered_session_idle(&peer_key);
                // Auto-remove dynamic peers when they go idle (no reconnect).
                if self.peers.get(&peer_key).is_some_and(|m| {
                    m.is_dynamic
                        && (!m.enabled
                            || m.transport_config.dampening_admission.as_ref().is_some_and(
                                rustbgpd_rib::dampening::DampeningAdmission::is_blocked,
                            ))
                }) {
                    // Operator explicitly disabled — don't remove, just let it stay idle.
                    self.mark_unadmitted_disabled_dynamic(&peer_key);
                } else if self.peers.get(&peer_key).is_some_and(|m| m.is_dynamic) {
                    // Retiring removes the peer from the table. A policy
                    // walk that owns the actor captured it, so the walk
                    // holds the notice until it ends.
                    if self
                        .hold_for_owned_walk(SessionNotification::BackToIdle {
                            session_id,
                            role,
                            peer_addr,
                        })
                        .is_some()
                        && let Some(retirement) =
                            self.prepare_dynamic_notification_retirement(&peer_key)
                    {
                        retirements.push(retirement);
                    }
                    // Skip pending inbound logic for removed dynamic peers
                } else {
                    let enabled = self.peers.get(&peer_key).is_some_and(|m| m.enabled);
                    // RFC 5882 coupling: a BFD hold must also gate candidate
                    // promotion. The primary often goes BackToIdle BECAUSE
                    // BFD tore it down — promoting a candidate spawned before
                    // the hold would re-establish BGP over the BFD-down path.
                    let withheld = self.bfd_withholding(&peer_addr);
                    if enabled && !withheld {
                        // Existing primary failed — promote the already-running
                        // inbound candidate if one exists, unless the primary
                        // is waiting out an escalated NOTIFICATION backoff.
                        let promoted = match self.idle_primary_state_for_pending(&peer_key).await {
                            None => false,
                            // An exited primary has no reconnect wait to honour.
                            Some(rustbgpd_transport::StateQueryOutcome::SessionGone) => {
                                super::boxed(|| {
                                    self.promote_pending_inbound_unless_backoff(&peer_key, None)
                                })
                                .await
                            }
                            Some(rustbgpd_transport::StateQueryOutcome::State(state)) => {
                                super::boxed(|| {
                                    self.promote_pending_inbound_unless_backoff(
                                        &peer_key,
                                        Some(&state),
                                    )
                                })
                                .await
                            }
                            // A live primary whose backoff streak is unknown:
                            // promoting could bypass its wait and reset the
                            // streak. Drop the candidate, as a timed-out query
                            // does on accept and at OPEN resolution; the
                            // neighbor retries.
                            Some(rustbgpd_transport::StateQueryOutcome::TimedOut) => {
                                if let Some(pending) = self
                                    .peers
                                    .get_mut(&peer_key)
                                    .and_then(|m| m.pending_inbound.take())
                                {
                                    info!(peer = %peer_addr, "primary state query timed out after BackToIdle; dropping inbound collision candidate");
                                    self.queue_notification_retirement(
                                        &peer_key,
                                        pending.session_id,
                                        pending.handle,
                                        "BackToIdle unknown-primary pending inbound",
                                        retirements,
                                    );
                                }
                                false
                            }
                        };
                        if promoted {
                            info!(peer = %peer_addr, "existing session went idle, promoting inbound collision candidate");
                        }
                    } else if let Some(pending) = self
                        .peers
                        .get_mut(&peer_key)
                        .and_then(|m| m.pending_inbound.take())
                    {
                        self.queue_notification_retirement(
                            &peer_key,
                            pending.session_id,
                            pending.handle,
                            "BackToIdle dropped pending inbound",
                            retirements,
                        );
                        if withheld {
                            info!(peer = %peer_addr, "BFD withholding — dropped inbound collision candidate instead of promoting");
                        }
                    }
                }
            }
            SessionNotification::MaxPrefixWarning {
                session_id,
                role,
                peer_addr,
                family,
                stage,
                usage,
                bound,
                percent,
                crossings,
            } => {
                // Informational: nothing is latched. One durable session event
                // per received warning so operators can alert on it without a
                // log tail. A warning that stands for crossings made while it
                // was queued says how many; the metric counts each one.
                let Some(peer_key) = self.peer_key_for_session(session_id) else {
                    debug!(peer = %peer_addr, session_id, ?role, "ignoring max-prefix warning from unknown session");
                    return;
                };
                let currently_owned = self.peers.get(&peer_key).is_some_and(|managed| {
                    managed.session_id() == session_id
                        || managed
                            .pending_inbound
                            .as_ref()
                            .is_some_and(|pending| pending.session_id == session_id)
                });
                if !currently_owned {
                    debug!(peer = %peer_addr, session_id, ?role, "ignoring stale max-prefix warning notification");
                    return;
                }
                let rendered_peer = peer_key.label();
                let since = if crossings > 1 {
                    format!("; {crossings} threshold crossings since the last report")
                } else {
                    String::new()
                };
                let reason = format!(
                    "max-prefix warning for peer {rendered_peer}: family {family} stage {stage} usage {usage} of bound {bound} (threshold {percent}%){since}"
                );
                self.publish_lifecycle_event(rustbgpd_api::peer_types::SessionLifecycleEvent {
                    event_type:
                        rustbgpd_api::peer_types::SessionLifecycleEventType::MaxPrefixWarning,
                    peer: peer_addr,
                    peer_label: Some(rendered_peer.clone()),
                    timestamp_unix_ms: Self::session_event_timestamp(),
                    old_state: None,
                    new_state: None,
                    session_role: Some(Self::session_role_label(role).to_string()),
                    reason,
                });
            }
            SessionNotification::TaskExited {
                session_id,
                role,
                peer_addr,
                cause,
            } => {
                self.handle_session_task_exit(session_id, role, peer_addr, cause, retirements)
                    .await;
            }
            SessionNotification::MaxPrefixExceeded {
                session_id,
                role,
                peer_addr,
                count,
                bound,
                family,
                received,
                path_limit,
            } => {
                let Some(peer_key) = self.peer_key_for_session(session_id) else {
                    debug!(peer = %peer_addr, session_id, ?role, "ignoring max-prefix latch from unknown session");
                    return;
                };
                // SessionRole describes how the task was spawned and remains
                // InboundCandidate after promotion. Current ownership is
                // therefore fenced exclusively by the manager's session IDs.
                let currently_owned = self.peers.get(&peer_key).is_some_and(|managed| {
                    managed.session_id() == session_id
                        || managed
                            .pending_inbound
                            .as_ref()
                            .is_some_and(|pending| pending.session_id == session_id)
                });
                let retiring_owned = self
                    .retiring_sessions
                    .get(&session_id)
                    .is_some_and(|owner| owner == &peer_key);
                if !currently_owned && !retiring_owned {
                    debug!(peer = %peer_addr, session_id, ?role, "ignoring stale max-prefix latch notification");
                    return;
                }

                let error = if path_limit {
                    let (afi, safi) = family.expect("Add-Path receive cap has a family");
                    format!(
                        "Add-Path receive limit exceeded for {afi:?}/{safi:?}: {count} paths for one prefix, bound {bound}"
                    )
                } else {
                    let counted = if received { "received" } else { "accepted" };
                    family.map_or_else(
                        || format!("max-prefix limit exceeded: {count} accepted, bound {bound}"),
                        |(afi, safi)| {
                            format!(
                                "max-prefix limit exceeded for {afi:?}/{safi:?}: {count} {counted}, bound {bound}"
                            )
                        },
                    )
                };
                let (pending, restart_seconds) =
                    self.peers
                        .get_mut(&peer_key)
                        .map_or((None, None), |managed| {
                            managed.enabled = false;
                            (
                                managed.pending_inbound.take(),
                                managed.max_prefix_restart_seconds,
                            )
                        });
                if self.peers.contains_key(&peer_key) {
                    self.publish_peer_admin_enabled_metric(&peer_key, false);
                }
                let installed = self.install_max_prefix_latch(
                    peer_key.clone(),
                    session_id,
                    error.clone(),
                    restart_seconds,
                );
                self.set_bfd_peer_disabled(peer_addr, true);

                let stop_primary = self
                    .peers
                    .get(&peer_key)
                    .map(|managed| (managed.session_id(), managed.handle().commands_sender()));
                let sessions: Vec<_> = pending
                    .into_iter()
                    .map(|pending| {
                        self.retiring_sessions
                            .insert(pending.session_id, peer_key.clone());
                        (
                            pending.session_id,
                            pending.handle,
                            "max-prefix latch pending inbound",
                        )
                    })
                    .collect();
                if stop_primary.is_some() || !sessions.is_empty() {
                    retirements.push(NotificationRetirement {
                        peer: peer_key.clone(),
                        sessions,
                        stop_primary,
                        dynamic: None,
                    });
                }
                if installed {
                    if let Some(seconds) = restart_seconds {
                        info!(peer = %peer_addr, %error, seconds, "peer latched disabled after max-prefix breach; one automatic restart scheduled");
                    } else {
                        info!(peer = %peer_addr, %error, "peer latched disabled after max-prefix breach; explicit enable required");
                    }
                } else {
                    let original_session_id = self
                        .max_prefix_latches
                        .get(&peer_key)
                        .map(|latch| latch.source_session_id);
                    debug!(peer = %peer_addr, session_id, original_session_id, "duplicate max-prefix terminal notice kept the original latch deadline");
                }
            }
        }
    }

    fn prepare_dynamic_notification_retirement(
        &mut self,
        peer: &PeerKey,
    ) -> Option<NotificationRetirement> {
        self.dead_letter_pending_for(peer.address);
        let managed = self.peers.remove(peer)?;
        let (primary, primary_id, mut managed) = managed.into_parts();
        let end_retention = primary.session_end_retention();
        let mut sessions = Vec::new();
        if let Some(pending) = managed.pending_inbound.take() {
            sessions.push((
                pending.session_id,
                pending.handle,
                "BackToIdle dynamic pending inbound",
            ));
        }
        sessions.push((primary_id, primary, "BackToIdle dynamic primary"));
        for (id, _, _) in &sessions {
            self.retiring_sessions.insert(*id, peer.clone());
        }
        info!(peer = %peer, "dynamic peer session went idle, retiring producers");
        Some(NotificationRetirement {
            peer: peer.clone(),
            sessions,
            stop_primary: None,
            dynamic: Some(Box::new(DynamicRetirement {
                managed,
                end_retention,
                primary_id,
            })),
        })
    }

    fn finish_dynamic_notification_retirement(
        &mut self,
        peer_key: &PeerKey,
        retirement: DynamicRetirement,
        superseded: Option<u64>,
        barrier_failed: bool,
    ) {
        let DynamicRetirement {
            mut managed,
            end_retention,
            primary_id: _,
        } = retirement;
        let peer_addr = peer_key.address;
        if barrier_failed {
            tracing::error!(peer = %peer_addr, "dynamic dampening retirement barrier unanswered; retaining disabled peer");
            self.dampening_control_failed = true;
        }

        if barrier_failed
            || self.max_prefix_latches.contains_key(peer_key)
            || self.session_crash_latched(peer_key)
            || managed
                .transport_config
                .dampening_admission
                .as_ref()
                .is_some_and(rustbgpd_rib::dampening::DampeningAdmission::is_blocked)
        {
            // A late terminal block or an unacknowledged RIB
            // fence must retain the explicit recovery target.
            let session_id = self.allocate_session_id();
            let mut transport = managed.transport_config.clone();
            transport.supersedes_session = superseded;
            let handle = PeerHandle::spawn_at_tcp_ao_generation(
                transport,
                self.metrics.clone(),
                self.rib_tx.clone(),
                managed.import_policy.clone(),
                managed.export_policy.clone(),
                Some(self.session_notify_tx.clone()),
                Some(self.session_notification_event_tx.clone()),
                Some(self.session_lifecycle_tx.clone()),
                self.session_bmp_tx(peer_key),
                self.validation_rx.clone(),
                managed.advertise_graceful_shutdown,
                SessionIdentity::primary(session_id),
                managed.tcp_ao_rotation.applied,
            );
            managed.enabled = false;
            self.peers.insert(
                peer_key.clone(),
                ManagedPeer::new(handle, session_id, managed),
            );
            self.register_session(session_id, peer_key);
            self.seed_peer_truth_metrics(peer_key, false);
            self.publish_peer_info_metric(peer_key);
            info!(peer = %peer_addr, "retained dynamic peer disabled after terminal block or failed RIB retirement fence");
        } else if self.resume_retained_dynamic(peer_key, end_retention) {
            // A reconnect that never reached Established: the
            // retention it waited on stands, unchanged.
        } else if self.retain_dynamic_identity(peer_key, &managed, superseded, end_retention) {
            // Graceful restart may still hold routes on either
            // side: the RIB's for the peer, or the peer's of
            // ours. Its identity stays until both lapse, so a
            // reconnect resumes as the same RIB peer.
        } else {
            // Producer joins and the required RIB fence found
            // no terminal block, so auto-removal is authoritative.
            self.dynamic_peer_count = self.dynamic_peer_count.saturating_sub(1);
            self.refresh_dynamic_neighbor_capacity_metrics();
            self.reap_deleted_peer_metric_series_for_key(peer_key);
        }
        // The session is gone: so is its BFD session, unless its
        // peer stays, disabled, for a recovery target.
        self.release_dynamic_bfd(peer_addr);
    }

    pub(super) fn handle_session_lifecycle_notification(
        &mut self,
        notification: &SessionLifecycleNotification,
    ) {
        let SessionLifecycleNotification::StateChanged {
            session_id,
            role,
            peer_addr,
            peer_asn,
            old,
            new,
            teardown_cause,
        } = notification;
        let (session_id, role) = (*session_id, *role);
        let Some(peer_key) = self.peer_key_for_session(session_id) else {
            debug!(peer = %peer_addr, session_id, ?role, "ignoring lifecycle notification for unknown peer session");
            return;
        };
        let matches_current = self.peers.get(&peer_key).is_some_and(|m| {
            m.session_id() == session_id
                || m.pending_inbound
                    .as_ref()
                    .is_some_and(|p| p.session_id == session_id)
        });
        if !matches_current {
            debug!(peer = %peer_addr, session_id, ?role, "ignoring stale StateChanged lifecycle notification");
            return;
        }
        if let Some(peer_asn) = *peer_asn {
            self.learn_dynamic_remote_asn(&peer_key, peer_asn);
        }
        self.note_unnumbered_session_state(&peer_key, *old, *new);
        self.publish_state_lifecycle_event(&peer_key, role, *old, *new, teardown_cause.as_deref());
    }

    pub(super) fn drain_ready_session_lifecycle_notifications(&mut self) {
        while let Ok(notification) = self.session_lifecycle_rx.try_recv() {
            self.count_owned_walk_event();
            self.handle_session_lifecycle_notification(&notification);
        }
    }

    fn learn_dynamic_remote_asn(&mut self, peer_key: &PeerKey, peer_asn: u32) {
        let Some(managed) = self.peers.get_mut(peer_key).filter(|_| peer_asn != 0) else {
            return;
        };
        if managed.is_dynamic && managed.remote_asn == 0 {
            managed.remote_asn = peer_asn;
            managed.transport_config.peer.remote_asn = peer_asn;
        } else if managed.transport_config.peer.remote_asn_external
            && managed.remote_asn != peer_asn
        {
            // `remote_asn = "external"`: the session keeps matching any ASN
            // but the local one (the transport config is untouched); the
            // identity series shows the ASN this peer's OPEN carried.
            managed.remote_asn = peer_asn;
        } else {
            return;
        }
        self.publish_peer_info_metric(peer_key);
    }
}

fn session_notification_id(notification: &SessionNotification) -> u64 {
    match notification {
        SessionNotification::OpenReceived { session_id, .. }
        | SessionNotification::BackToIdle { session_id, .. }
        | SessionNotification::MaxPrefixExceeded { session_id, .. }
        | SessionNotification::MaxPrefixWarning { session_id, .. }
        | SessionNotification::TaskExited { session_id, .. } => *session_id,
    }
}
