use std::net::IpAddr;

use rustbgpd_fsm::SessionState;
use rustbgpd_transport::{
    PeerHandle, SessionIdentity, SessionLifecycleNotification, SessionNotification,
};
use tracing::{debug, info, warn};

use super::PeerManager;

impl PeerManager {
    /// A failed Stop enqueue cannot leave a candidate's sibling primary live:
    /// abort it, fence its old RIB ownership, and install a fresh disabled Idle
    /// actor so the max-prefix latch remains fail-closed but explicit Enable is
    /// still a usable recovery operation.
    async fn replace_unstoppable_primary(&mut self, peer_key: &rustbgpd_api::peer_types::PeerKey) {
        let Some((
            old_session_id,
            transport,
            import_policy,
            export_policy,
            gshut,
            tcp_ao_generation,
        )) = self.peers.get(peer_key).map(|managed| {
            (
                managed.session_id,
                managed.transport_config.clone(),
                managed.import_policy.clone(),
                managed.export_policy.clone(),
                managed.advertise_graceful_shutdown,
                managed.tcp_ao_rotation.applied,
            )
        })
        else {
            return;
        };

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
            self.bmp_tx.clone(),
            self.validation_rx.clone(),
            gshut,
            SessionIdentity::primary(new_session_id),
            self.transport_event_sink.clone(),
            tcp_ao_generation,
        );
        let Some(managed) = self.peers.get_mut(peer_key) else {
            return;
        };
        let aborted = std::mem::replace(&mut managed.handle, replacement);
        managed.session_id = new_session_id;
        // Join cancellation before publishing PeerDown. Without this strict
        // ordering the old actor could complete an in-flight RIB send after the
        // fence and repopulate routes under its now-unregistered generation.
        aborted.abort_for_transport_safety_and_wait().await;

        // The aborted actor cannot execute SessionDown. Fence its exact RIB
        // generation before a later Enable can emit PeerUp from the replacement.
        if self
            .rib_tx
            .send(rustbgpd_rib::RibUpdate::PeerDown {
                peer: peer_key.address,
                session_id: old_session_id,
            })
            .await
            .is_err()
        {
            warn!(peer = %peer_key, old_session_id, "RIB unavailable while fencing aborted max-prefix primary");
        }
        self.unregister_session(old_session_id);
        self.register_session(new_session_id, peer_key);
    }

    /// Drain lossless session ownership/latch signals that were already queued
    /// before an inbound-accept command. This closes the cross-channel race in
    /// which a passive reconnect could replace the breached session generation
    /// before its max-prefix latch was applied.
    pub(super) async fn drain_ready_session_notifications(&mut self) {
        while let Ok(notification) = self.session_notify_rx.try_recv() {
            self.drain_ready_session_lifecycle_notifications();
            self.handle_session_notification(notification).await;
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "notification handling keeps collision, dynamic-peer removal, and lifecycle ordering together"
    )]
    pub(super) async fn handle_session_notification(&mut self, notification: SessionNotification) {
        match notification {
            SessionNotification::StateChanged {
                session_id,
                role,
                peer_addr,
                old,
                new,
            } => {
                self.handle_state_changed_notification(session_id, role, peer_addr, None, old, new);
            }
            SessionNotification::OpenReceived {
                session_id,
                role,
                peer_addr,
                remote_router_id,
                peer_asn,
            } => {
                let Some(peer_key) = self.peer_key_for_session(session_id) else {
                    debug!(%peer_addr, session_id, ?role, "ignoring notification for unknown peer session");
                    return;
                };
                let matches_current = self.peers.get(&peer_key).is_some_and(|m| {
                    m.session_id == session_id
                        || m.pending_inbound
                            .as_ref()
                            .is_some_and(|p| p.session_id == session_id)
                });
                if !matches_current {
                    debug!(%peer_addr, session_id, ?role, "ignoring stale OpenReceived notification");
                    return;
                }
                if self
                    .peers
                    .get(&peer_key)
                    .is_some_and(|m| m.pending_inbound.is_some())
                {
                    self.resolve_collision(peer_key, remote_router_id, peer_asn)
                        .await;
                }
            }
            SessionNotification::BackToIdle {
                session_id,
                role,
                peer_addr,
            } => {
                let Some(peer_key) = self.peer_key_for_session(session_id) else {
                    debug!(%peer_addr, session_id, ?role, "ignoring BackToIdle for unknown peer session");
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
                    debug!(%peer_addr, session_id, ?role, "inbound collision candidate went idle, dropping");
                    let _ = self
                        .quiesce_retiring_session(
                            &peer_key,
                            pending.session_id,
                            pending.handle,
                            "BackToIdle pending inbound candidate",
                            false,
                        )
                        .await;
                    return;
                }

                let current_primary = self
                    .peers
                    .get(&peer_key)
                    .is_some_and(|m| m.session_id == session_id);
                if !current_primary {
                    debug!(%peer_addr, session_id, ?role, "ignoring stale BackToIdle notification");
                    return;
                }
                // Auto-remove dynamic peers when they go idle (no reconnect).
                if self
                    .peers
                    .get(&peer_key)
                    .is_some_and(|m| m.is_dynamic && !m.enabled)
                {
                    // Operator explicitly disabled — don't remove, just let it stay idle.
                } else if self.peers.get(&peer_key).is_some_and(|m| m.is_dynamic) {
                    // Snapshot any unfired hot-apply / Route Refresh
                    // intent before we drop the ManagedPeer. A
                    // re-establishing dynamic peer at the same address
                    // (typical for a transient TCP drop on a
                    // [[dynamic_neighbors]] range) inherits the retry
                    // when handle_inbound recreates the ManagedPeer.
                    self.dead_letter_pending_for(peer_addr);
                    info!(%peer_addr, "dynamic peer session went idle, removing");
                    if let Some(mut managed) = self.peers.remove(&peer_key) {
                        let primary_session_id = managed.session_id;
                        self.retiring_sessions
                            .insert(primary_session_id, peer_key.clone());
                        if let Some(pending) = managed.pending_inbound.take() {
                            let _ = self
                                .quiesce_retiring_session(
                                    &peer_key,
                                    pending.session_id,
                                    pending.handle,
                                    "BackToIdle dynamic pending inbound",
                                    false,
                                )
                                .await;
                        }
                        let shutdown = self
                            .quiesce_retiring_session(
                                &peer_key,
                                primary_session_id,
                                managed.handle,
                                "BackToIdle dynamic primary",
                                false,
                            )
                            .await;

                        if self.max_prefix_latches.contains_key(&peer_key) {
                            // The retiring actor crossed max-prefix after its
                            // earlier BackToIdle was queued. Keep a disabled
                            // recovery target instead of auto-removing the peer
                            // and making explicit Enable impossible.
                            let session_id = self.allocate_session_id();
                            managed.handle = PeerHandle::spawn_at_tcp_ao_generation(
                                managed.transport_config.clone(),
                                self.metrics.clone(),
                                self.rib_tx.clone(),
                                managed.import_policy.clone(),
                                managed.export_policy.clone(),
                                Some(self.session_notify_tx.clone()),
                                Some(self.session_notification_event_tx.clone()),
                                Some(self.session_lifecycle_tx.clone()),
                                self.bmp_tx.clone(),
                                self.validation_rx.clone(),
                                managed.advertise_graceful_shutdown,
                                SessionIdentity::primary(session_id),
                                self.transport_event_sink.clone(),
                                managed.tcp_ao_rotation.applied,
                            );
                            managed.session_id = session_id;
                            managed.enabled = false;
                            self.peers.insert(peer_key.clone(), managed);
                            self.register_session(session_id, &peer_key);
                            info!(%peer_addr, "retained dynamic peer disabled after terminal max-prefix signal during retirement");
                        } else {
                            // Auto-removal is authoritative when no terminal
                            // breach was discovered during the join barrier.
                            self.dynamic_peer_count = self.dynamic_peer_count.saturating_sub(1);
                            if shutdown.joined() {
                                self.reap_deleted_peer_metric_series(peer_addr).await;
                            } else {
                                info!(
                                    %peer_addr,
                                    "skipping dynamic-peer metric reap because session shutdown did not join before the deadline"
                                );
                            }
                        }
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
                        // inbound candidate if one exists.
                        if self.promote_pending_inbound(&peer_key).await {
                            info!(%peer_addr, "existing session went idle, promoting inbound collision candidate");
                        }
                    } else if let Some(pending) = self
                        .peers
                        .get_mut(&peer_key)
                        .and_then(|m| m.pending_inbound.take())
                    {
                        let _ = self
                            .quiesce_retiring_session(
                                &peer_key,
                                pending.session_id,
                                pending.handle,
                                "BackToIdle dropped pending inbound",
                                false,
                            )
                            .await;
                        if withheld {
                            info!(%peer_addr, "BFD withholding — dropped inbound collision candidate instead of promoting");
                        }
                    }
                }
            }
            SessionNotification::MaxPrefixExceeded {
                session_id,
                role,
                peer_addr,
                count,
                bound,
                family,
            } => {
                let Some(peer_key) = self.peer_key_for_session(session_id) else {
                    debug!(%peer_addr, session_id, ?role, "ignoring max-prefix latch from unknown session");
                    return;
                };
                // SessionRole describes how the task was spawned and remains
                // InboundCandidate after promotion. Current ownership is
                // therefore fenced exclusively by the manager's session IDs.
                let currently_owned = self.peers.get(&peer_key).is_some_and(|managed| {
                    managed.session_id == session_id
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
                    debug!(%peer_addr, session_id, ?role, "ignoring stale max-prefix latch notification");
                    return;
                }

                let error = family.map_or_else(
                    || format!("max-prefix limit exceeded: {count} accepted, bound {bound}"),
                    |(afi, safi)| {
                        format!(
                            "max-prefix limit exceeded for {afi:?}/{safi:?}: {count} accepted, bound {bound}"
                        )
                    },
                );
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
                let installed = self.install_max_prefix_latch(
                    peer_key.clone(),
                    session_id,
                    error.clone(),
                    restart_seconds,
                );
                self.set_bfd_peer_disabled(peer_addr, true);

                // Stop the currently owned primary for every breach. The
                // breaching actor normally stopped itself first, but a queued
                // Enable/Start can clear that session-local flag before this
                // manager latch wins the cross-channel race.
                if let Some(managed) = self.peers.get(&peer_key)
                    && let Err(stop_error) = managed
                        .handle
                        .stop_timeout(None, super::PEER_LIFECYCLE_COMMAND_TIMEOUT)
                        .await
                {
                    warn!(
                        %peer_addr,
                        session_id,
                        error = %stop_error,
                        "failed to stop primary after max-prefix breach"
                    );
                    self.replace_unstoppable_primary(&peer_key).await;
                }
                if let Some(pending) = pending {
                    self.unregister_session(pending.session_id);
                    let _ = self
                        .shutdown_handle_bounded(
                            peer_addr,
                            "max-prefix latch pending inbound",
                            pending.handle,
                        )
                        .await;
                }
                if installed {
                    if let Some(seconds) = restart_seconds {
                        info!(%peer_addr, %error, seconds, "peer latched disabled after max-prefix breach; one automatic restart scheduled");
                    } else {
                        info!(%peer_addr, %error, "peer latched disabled after max-prefix breach; explicit enable required");
                    }
                } else {
                    let original_session_id = self
                        .max_prefix_latches
                        .get(&peer_key)
                        .map(|latch| latch.source_session_id);
                    debug!(%peer_addr, session_id, original_session_id, "duplicate max-prefix terminal notice kept the original latch deadline");
                }
            }
        }
    }

    pub(super) fn handle_session_lifecycle_notification(
        &mut self,
        notification: &SessionLifecycleNotification,
    ) {
        match notification {
            SessionLifecycleNotification::StateChanged {
                session_id,
                role,
                peer_addr,
                peer_asn,
                old,
                new,
            } => self.handle_state_changed_notification(
                *session_id,
                *role,
                *peer_addr,
                *peer_asn,
                *old,
                *new,
            ),
        }
    }

    pub(super) fn drain_ready_session_lifecycle_notifications(&mut self) {
        while let Ok(notification) = self.session_lifecycle_rx.try_recv() {
            self.handle_session_lifecycle_notification(&notification);
        }
    }

    pub(super) fn handle_state_changed_notification(
        &mut self,
        session_id: u64,
        role: rustbgpd_transport::SessionRole,
        peer_addr: IpAddr,
        peer_asn: Option<u32>,
        old: SessionState,
        new: SessionState,
    ) {
        let Some(peer_key) = self.peer_key_for_session(session_id) else {
            debug!(%peer_addr, session_id, ?role, "ignoring lifecycle notification for unknown peer session");
            return;
        };
        let matches_current = self.peers.get(&peer_key).is_some_and(|m| {
            m.session_id == session_id
                || m.pending_inbound
                    .as_ref()
                    .is_some_and(|p| p.session_id == session_id)
        });
        if !matches_current {
            debug!(%peer_addr, session_id, ?role, "ignoring stale StateChanged lifecycle notification");
            return;
        }
        if let Some(peer_asn) = peer_asn.filter(|asn| *asn != 0)
            && let Some(managed) = self.peers.get_mut(&peer_key)
            && managed.is_dynamic
            && managed.remote_asn == 0
        {
            managed.remote_asn = peer_asn;
            managed.transport_config.peer.remote_asn = peer_asn;
        }
        self.publish_state_lifecycle_event(&peer_key, role, old, new);
    }
}
