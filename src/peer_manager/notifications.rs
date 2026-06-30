use std::net::IpAddr;

use rustbgpd_fsm::SessionState;
use rustbgpd_transport::{SessionLifecycleNotification, SessionNotification};
use tracing::{debug, info};

use super::PeerManager;

impl PeerManager {
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
                    self.resolve_collision(peer_key, remote_router_id).await;
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
                    self.unregister_session(pending.session_id);
                    let _ = self
                        .shutdown_handle_bounded(
                            peer_addr,
                            "BackToIdle pending inbound candidate",
                            pending.handle,
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
                        self.unregister_session(managed.session_id);
                        if let Some(pending) = managed.pending_inbound.take() {
                            self.unregister_session(pending.session_id);
                            let _ = self
                                .shutdown_handle_bounded(
                                    peer_addr,
                                    "BackToIdle dynamic pending inbound",
                                    pending.handle,
                                )
                                .await;
                        }
                        // Auto-removal is a full peer deletion (the
                        // ManagedPeer is gone; a re-accepted peer at
                        // this address starts a fresh lifecycle), so
                        // reap its per-peer metric series too — but
                        // join the session task first so the reap runs
                        // after its last transport-side emission, the
                        // same ordering the static delete path uses.
                        let shutdown = self
                            .shutdown_handle_bounded(
                                peer_addr,
                                "BackToIdle dynamic primary",
                                managed.handle,
                            )
                            .await;
                        if shutdown.joined() {
                            self.reap_deleted_peer_metric_series(
                                peer_addr,
                                &managed.transport_config,
                            )
                            .await;
                        } else {
                            info!(
                                %peer_addr,
                                "skipping dynamic-peer metric reap because session shutdown did not join before the deadline"
                            );
                        }
                    }
                    self.dynamic_peer_count = self.dynamic_peer_count.saturating_sub(1);
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
                        self.unregister_session(pending.session_id);
                        let _ = self
                            .shutdown_handle_bounded(
                                peer_addr,
                                "BackToIdle dropped pending inbound",
                                pending.handle,
                            )
                            .await;
                        if withheld {
                            info!(%peer_addr, "BFD withholding — dropped inbound collision candidate instead of promoting");
                        }
                    }
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
