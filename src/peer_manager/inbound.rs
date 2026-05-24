use std::net::{IpAddr, Ipv4Addr};

use rustbgpd_fsm::SessionState;
use rustbgpd_transport::{PeerHandle, SessionIdentity};
use tokio::net::TcpStream;
use tracing::{info, warn};

use super::{ManagedPeer, PEER_QUERY_TIMEOUT, PeerManager, PendingInbound};

impl PeerManager {
    pub(super) async fn spawn_pending_inbound(
        &mut self,
        peer_addr: IpAddr,
        stream: TcpStream,
    ) -> bool {
        if self
            .peers
            .get(&peer_addr)
            .is_some_and(|m| m.pending_inbound.is_some())
        {
            info!(%peer_addr, "dropping extra inbound connection while collision candidate is pending");
            return false;
        }

        let Some(managed) = self.peers.get(&peer_addr) else {
            return false;
        };
        let transport_config = managed.transport_config.clone();
        let import_policy = managed.import_policy.clone();
        let export_policy = managed.export_policy.clone();
        let advertise_graceful_shutdown = managed.advertise_graceful_shutdown;
        let session_id = self.allocate_session_id();
        let handle = PeerHandle::spawn_inbound_with_identity_and_lifecycle(
            transport_config,
            self.metrics.clone(),
            self.rib_tx.clone(),
            import_policy,
            export_policy,
            stream,
            Some(self.session_notify_tx.clone()),
            Some(self.session_notification_event_tx.clone()),
            Some(self.session_lifecycle_tx.clone()),
            self.bmp_tx.clone(),
            self.validation_rx.clone(),
            advertise_graceful_shutdown,
            SessionIdentity::inbound_candidate(session_id),
        );

        if let Err(e) = handle.start().await {
            warn!(%peer_addr, error = %e, "failed to start inbound collision candidate");
            let _ = handle.shutdown().await;
            return false;
        }

        let Some(managed) = self.peers.get_mut(&peer_addr) else {
            let _ = handle.shutdown().await;
            return false;
        };
        debug_assert!(
            managed.pending_inbound.is_none(),
            "PeerManager is a single-task actor; starting a candidate must not reenter handlers"
        );
        if managed.pending_inbound.is_some() {
            info!(%peer_addr, "collision candidate appeared while starting another, dropping newer inbound");
            let _ = handle.shutdown().await;
            return false;
        }
        managed.pending_inbound = Some(PendingInbound { handle, session_id });
        true
    }

    #[expect(clippy::too_many_lines)]
    pub(super) async fn handle_inbound(&mut self, stream: TcpStream, peer_addr: IpAddr) {
        // If peer is not statically configured, try dynamic range matching.
        if !self.peers.contains_key(&peer_addr) {
            if let Some(range) = self.match_dynamic_range(peer_addr) {
                // Check dynamic peer limit
                if self.dynamic_peer_count >= self.dynamic_neighbor_limit as usize {
                    warn!(
                        %peer_addr,
                        limit = self.dynamic_neighbor_limit,
                        "dynamic neighbor limit reached, dropping inbound connection"
                    );
                    return;
                }

                // Look up the peer group to build the config
                let Some(group) = self.current_config.peer_groups.get(&range.peer_group) else {
                    warn!(
                        %peer_addr,
                        peer_group = %range.peer_group,
                        "dynamic neighbor peer_group not found, dropping"
                    );
                    return;
                };

                let remote_asn = range.remote_asn;
                let description = range
                    .description
                    .clone()
                    .unwrap_or_else(|| format!("dynamic:{}", range.peer_group));
                let peer_group_name = range.peer_group.clone();

                // Resolve the dynamic neighbor config from the peer group
                let resolved = match self.current_config.resolve_dynamic_neighbor(
                    peer_addr,
                    remote_asn,
                    &description,
                    group,
                    &peer_group_name,
                ) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(
                            %peer_addr,
                            error = %e,
                            "failed to resolve dynamic neighbor config, dropping"
                        );
                        return;
                    }
                };

                let cfg = Self::peer_manager_config_from_resolved(resolved, false);
                let transport = self.build_transport_config(&cfg);
                let import_policy = cfg.import_policy.clone();
                let export_policy = cfg.export_policy.clone();
                let advertise_graceful_shutdown = self
                    .dead_lettered_pending
                    .get(&peer_addr)
                    .is_some_and(|pending| pending.graceful_shutdown);

                let session_id = self.allocate_session_id();
                let handle = PeerHandle::spawn_inbound_with_identity_and_lifecycle(
                    transport.clone(),
                    self.metrics.clone(),
                    self.rib_tx.clone(),
                    import_policy.clone(),
                    export_policy.clone(),
                    stream,
                    Some(self.session_notify_tx.clone()),
                    Some(self.session_notification_event_tx.clone()),
                    Some(self.session_lifecycle_tx.clone()),
                    self.bmp_tx.clone(),
                    self.validation_rx.clone(),
                    advertise_graceful_shutdown,
                    SessionIdentity::primary(session_id),
                );

                if let Err(e) = handle.start().await {
                    warn!(%peer_addr, error = %e, "failed to start dynamic peer session");
                    return;
                }

                let managed = ManagedPeer {
                    handle,
                    session_id,
                    remote_asn,
                    description,
                    peer_group: Some(peer_group_name),
                    enabled: true,
                    hold_time: cfg.hold_time,
                    max_prefixes: cfg.max_prefixes,
                    transport_config: transport,
                    import_policy,
                    export_policy,
                    pending_inbound: None,
                    is_dynamic: true,
                    pending_refresh: false,
                    pending_export_apply: false,
                    advertise_graceful_shutdown,
                };
                self.peers.insert(peer_addr, managed);
                self.dynamic_peer_count += 1;

                // Restore any dead-lettered hot-apply / Route Refresh
                // intent left behind by a prior dynamic-peer auto-
                // removal at this address. Carries the retry across
                // the brief drop-and-recreate window so a transient
                // TCP flap doesn't silently lose a SetPolicy edit.
                self.restore_dead_lettered_pending(peer_addr);

                info!(
                    %peer_addr,
                    "accepted dynamic neighbor from configured range"
                );
                return;
            }

            // No dynamic range match either — drop with hint
            warn!(
                %peer_addr,
                hint = %format_args!(
                    "to accept: rustbgpctl neighbor {peer_addr} add --asn <REMOTE_ASN>"
                ),
                "inbound connection from unknown peer, dropping"
            );
            return;
        }

        // ADR-0067 step 4b — strict BFD withholding must cover the passive path
        // too. The active-open lifecycle (`add_peer` / `enable_peer`) withholds
        // `start()` while BFD does not permit BGP, but every inbound sub-case
        // below (`replace_with_inbound`, collision candidates) starts a session
        // directly. Without this gate a strict peer that is currently withheld
        // could accept an inbound connection and establish BGP anyway —
        // defeating strict mode. Gate on the *current* held state (not the
        // add-time decision) so an already-established strict peer still accepts
        // inbound normally; a withheld peer's eventual release starts the
        // session through the normal up→start path.
        if self.bfd_withholding(&peer_addr) {
            info!(%peer_addr, "strict BFD — dropping inbound connection while BGP is withheld");
            return;
        }

        let Some(managed) = self.peers.get_mut(&peer_addr) else {
            return;
        };

        if !managed.enabled {
            info!(%peer_addr, "inbound connection for disabled peer, dropping");
            return;
        }

        // Bounded so an inbound TCP arriving during a TCP-back-pressure
        // wedge on the existing session can't park the peer-manager actor
        // mid-collision-resolution. A timeout falls back to `Idle` here,
        // which sends us through the "accept immediately" arm — equivalent
        // to the existing "no session yet" path, with the same
        // `replace_with_inbound` outcome.
        let current_state = managed.handle.query_state_timeout(PEER_QUERY_TIMEOUT).await;
        let fsm_state = current_state
            .as_ref()
            .map_or(SessionState::Idle, |s| s.fsm_state);

        match fsm_state {
            SessionState::Idle => {
                // Accept immediately — no collision possible
                self.replace_with_inbound(peer_addr, stream).await;
            }
            SessionState::Established => {
                // Already established — drop inbound (no collision)
                info!(%peer_addr, "inbound connection for established peer, dropping");
            }
            SessionState::Connect | SessionState::Active | SessionState::OpenSent => {
                // Start a live inbound candidate. Parking the raw socket here
                // deadlocks simultaneous active-open: both outbound sessions
                // wait for OPEN while both accepted inbound sockets sit inert.
                info!(%peer_addr, state = fsm_state.as_str(), "starting inbound collision candidate");
                self.spawn_pending_inbound(peer_addr, stream).await;
            }
            SessionState::OpenConfirm => {
                // We already have router-id from negotiation; start a live
                // inbound candidate and resolve immediately.
                let remote_router_id = current_state.and_then(|s| s.remote_router_id);
                let started = self.spawn_pending_inbound(peer_addr, stream).await;
                if let Some(rid) = remote_router_id {
                    if started {
                        self.resolve_collision(peer_addr, rid).await;
                    }
                } else {
                    // Shouldn't happen; the live candidate can still notify
                    // us once it receives the peer OPEN.
                    warn!(%peer_addr, "OpenConfirm but no remote_router_id, waiting for inbound candidate notification");
                }
            }
        }
    }

    pub(super) async fn resolve_collision(
        &mut self,
        peer_addr: IpAddr,
        remote_router_id: Ipv4Addr,
    ) {
        let local_id = u32::from(self.router_id);
        let remote_id = u32::from(remote_router_id);

        match local_id.cmp(&remote_id) {
            std::cmp::Ordering::Greater => {
                // We win — keep existing session, drop inbound
                info!(
                    %peer_addr,
                    local_id = %self.router_id,
                    remote_id = %remote_router_id,
                    "collision: local wins, dropping inbound"
                );
                if let Some(pending) = self
                    .peers
                    .get_mut(&peer_addr)
                    .and_then(|m| m.pending_inbound.take())
                {
                    let _ = pending.handle.collision_dump().await;
                }
            }
            std::cmp::Ordering::Less => {
                // Remote wins — dump existing, accept inbound
                info!(
                    %peer_addr,
                    local_id = %self.router_id,
                    remote_id = %remote_router_id,
                    "collision: remote wins, replacing with inbound"
                );
                if let Some(old_handle) = self.promote_pending_inbound_handle(peer_addr) {
                    let _ = old_handle.collision_dump().await;
                }
            }
            std::cmp::Ordering::Equal => {
                // Equal router-ids — should not happen; drop inbound
                warn!(
                    %peer_addr,
                    router_id = %self.router_id,
                    "collision: equal router-ids, dropping inbound"
                );
                if let Some(pending) = self
                    .peers
                    .get_mut(&peer_addr)
                    .and_then(|m| m.pending_inbound.take())
                {
                    let _ = pending.handle.collision_dump().await;
                }
            }
        }
    }

    pub(super) fn promote_pending_inbound_handle(
        &mut self,
        peer_addr: IpAddr,
    ) -> Option<PeerHandle> {
        let managed = self.peers.get_mut(&peer_addr)?;
        let pending = managed.pending_inbound.take()?;
        let old_handle = std::mem::replace(&mut managed.handle, pending.handle);
        managed.session_id = pending.session_id;
        Some(old_handle)
    }

    pub(super) async fn promote_pending_inbound(&mut self, peer_addr: IpAddr) -> bool {
        let Some(old_handle) = self.promote_pending_inbound_handle(peer_addr) else {
            return false;
        };
        let _ = old_handle.shutdown().await;
        true
    }

    pub(super) async fn replace_with_inbound(&mut self, peer_addr: IpAddr, stream: TcpStream) {
        let session_id = self.allocate_session_id();
        let Some(managed) = self.peers.get_mut(&peer_addr) else {
            return;
        };

        // Replay the operator-driven RFC 8326 toggle on the new
        // session so a flap or collision-replace doesn't silently
        // drop the GShut state mid-maintenance.
        let advertise_graceful_shutdown = managed.advertise_graceful_shutdown;
        let old_handle = std::mem::replace(
            &mut managed.handle,
            PeerHandle::spawn_inbound_with_identity_and_lifecycle(
                managed.transport_config.clone(),
                self.metrics.clone(),
                self.rib_tx.clone(),
                managed.import_policy.clone(),
                managed.export_policy.clone(),
                stream,
                Some(self.session_notify_tx.clone()),
                Some(self.session_notification_event_tx.clone()),
                Some(self.session_lifecycle_tx.clone()),
                self.bmp_tx.clone(),
                self.validation_rx.clone(),
                advertise_graceful_shutdown,
                SessionIdentity::primary(session_id),
            ),
        );
        managed.session_id = session_id;

        // Shut down the old session
        let _ = old_handle.shutdown().await;

        // Start the new inbound session — trigger TcpConnectionConfirmed
        if let Err(e) = managed.handle.start().await {
            warn!(%peer_addr, error = %e, "failed to start inbound session");
        } else {
            info!(%peer_addr, "inbound session started");
        }
    }
}
