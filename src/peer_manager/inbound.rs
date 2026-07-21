use std::net::{Ipv4Addr, SocketAddr};

use rustbgpd_api::peer_types::PeerKey;
use rustbgpd_fsm::SessionState;
use rustbgpd_transport::{
    PeerHandle, SessionIdentity, StateQueryOutcome, TcpAoInfoSnapshot, TcpAoRotationGeneration,
};
use tokio::net::TcpStream;
use tracing::{info, warn};

use super::{
    ManagedPeer, PEER_LIFECYCLE_COMMAND_TIMEOUT, PEER_QUERY_TIMEOUT, PeerManager, PendingInbound,
};

fn accepted_selected_owner(
    managed: &ManagedPeer,
) -> rustbgpd_transport::listener::TcpAoSelectedOwner {
    if let Some(range) = managed.accepted_dynamic_range.as_ref() {
        rustbgpd_transport::listener::TcpAoSelectedOwner {
            owner: rustbgpd_transport::TcpAoListenerOwnerKind::Dynamic,
            peer: range.addr,
            prefix_len: range.prefix_len,
        }
    } else {
        rustbgpd_transport::listener::TcpAoSelectedOwner {
            owner: rustbgpd_transport::TcpAoListenerOwnerKind::Static,
            peer: managed.transport_config.remote_addr.ip(),
            prefix_len: if managed.transport_config.remote_addr.is_ipv4() {
                32
            } else {
                128
            },
        }
    }
}

fn reconcile_selected_owner_metadata(
    keyring: &mut rustbgpd_transport::TcpAoKeyring,
    selected_owner: rustbgpd_transport::listener::TcpAoSelectedOwner,
    accepted: &TcpAoInfoSnapshot,
) -> Result<(), &'static str> {
    let metadata = keyring
        .0
        .iter()
        .map(|key| {
            let mut matches = accepted.keys.iter().filter(|state| {
                state.peer == selected_owner.peer
                    && state.prefix_len == selected_owner.prefix_len
                    && state.send_id == key.send_id
                    && state.recv_id == key.recv_id
                    && state.algorithm == key.algorithm
            });
            let Some(state) = matches.next() else {
                return Err("accepted socket is missing a selected-owner key");
            };
            if matches.next().is_some() {
                return Err("accepted socket has duplicate selected-owner keys");
            }
            Ok((state.preferred, state.deprecated))
        })
        .collect::<Result<Vec<_>, _>>()?;

    for (key, (preferred, deprecated)) in keyring.0.iter_mut().zip(metadata) {
        key.preferred = preferred;
        key.deprecated = deprecated;
    }
    Ok(())
}

fn tcp_ao_accept_generation_valid(
    protected: bool,
    accepted: Option<TcpAoRotationGeneration>,
    rotation: &rustbgpd_transport::TcpAoRotationStatus,
) -> bool {
    match (protected, accepted) {
        (false, None) => true,
        (true, Some(generation)) => match rotation.phase {
            rustbgpd_transport::TcpAoRotationPhase::AddOnly
            | rustbgpd_transport::TcpAoRotationPhase::Selecting
            | rustbgpd_transport::TcpAoRotationPhase::AwaitingPeer => {
                (rotation.desired == rotation.applied && generation == rotation.applied)
                    || (rotation
                        .applied
                        .next()
                        .is_some_and(|desired| desired == rotation.desired)
                        && (generation == rotation.applied || generation == rotation.desired))
            }
            rustbgpd_transport::TcpAoRotationPhase::Idle
            | rustbgpd_transport::TcpAoRotationPhase::AddOnlyFailed
            | rustbgpd_transport::TcpAoRotationPhase::SelectionFailed => {
                generation == rotation.applied
            }
        },
        _ => false,
    }
}

impl PeerManager {
    pub(super) async fn accept_inbound(
        &mut self,
        stream: TcpStream,
        peer_addr: SocketAddr,
        tcp_ao_info: Option<TcpAoInfoSnapshot>,
        tcp_ao_generation: Option<TcpAoRotationGeneration>,
    ) {
        self.drain_ready_session_notifications().await;
        self.handle_inbound(stream, peer_addr, tcp_ao_info, tcp_ao_generation)
            .await;
    }

    pub(super) async fn spawn_pending_inbound(
        &mut self,
        peer_key: PeerKey,
        stream: TcpStream,
        tcp_ao_info: Option<TcpAoInfoSnapshot>,
        tcp_ao_generation: TcpAoRotationGeneration,
    ) -> bool {
        let peer_addr = peer_key.address;
        if self
            .peers
            .get(&peer_key)
            .is_some_and(|m| m.pending_inbound.is_some())
        {
            info!(%peer_addr, "dropping extra inbound connection while collision candidate is pending");
            return false;
        }

        let Some(managed) = self.peers.get(&peer_key) else {
            return false;
        };
        let transport_config = managed.transport_config.clone();
        let import_policy = managed.import_policy.clone();
        let export_policy = managed.export_policy.clone();
        let advertise_graceful_shutdown = managed.advertise_graceful_shutdown;
        let tcp_ao_selected_owner = tcp_ao_info
            .as_ref()
            .map(|_| accepted_selected_owner(managed));
        let session_id = self.allocate_session_id();
        let handle = PeerHandle::spawn_inbound_at_tcp_ao_generation(
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
            self.transport_event_sink.clone(),
            tcp_ao_info,
            tcp_ao_selected_owner,
            tcp_ao_generation,
        );

        if let Err(e) = handle.start_timeout(PEER_LIFECYCLE_COMMAND_TIMEOUT).await {
            warn!(%peer_addr, error = %e, "failed to start inbound collision candidate");
            let _ = self
                .shutdown_handle_bounded(peer_addr, "inbound candidate start failure", handle)
                .await;
            return false;
        }

        let Some(managed) = self.peers.get_mut(&peer_key) else {
            let _ = self
                .shutdown_handle_bounded(peer_addr, "inbound candidate missing peer", handle)
                .await;
            return false;
        };
        debug_assert!(
            managed.pending_inbound.is_none(),
            "PeerManager is a single-task actor; starting a candidate must not reenter handlers"
        );
        if managed.pending_inbound.is_some() {
            info!(%peer_addr, "collision candidate appeared while starting another, dropping newer inbound");
            let _ = self
                .shutdown_handle_bounded(peer_addr, "inbound candidate duplicate", handle)
                .await;
            return false;
        }
        managed.pending_inbound = Some(PendingInbound { handle, session_id });
        self.register_session(session_id, &peer_key);
        true
    }

    fn inbound_peer_key(&self, peer_addr: SocketAddr) -> Option<PeerKey> {
        let ip = peer_addr.ip();
        if let SocketAddr::V6(v6) = peer_addr
            && v6.ip().segments()[0] & 0xffc0 == 0xfe80
        {
            return self
                .peers
                .keys()
                .find(|key| {
                    key.address == ip
                        && self
                            .peers
                            .get(*key)
                            .and_then(|managed| managed.transport_config.peer_scope_id)
                            == Some(v6.scope_id())
                })
                .cloned();
        }
        let key = PeerKey::new(ip, None);
        self.peers.contains_key(&key).then_some(key)
    }

    #[expect(clippy::too_many_lines)]
    pub(super) async fn handle_inbound(
        &mut self,
        stream: TcpStream,
        peer_addr: SocketAddr,
        tcp_ao_info: Option<TcpAoInfoSnapshot>,
        tcp_ao_generation: Option<TcpAoRotationGeneration>,
    ) {
        let peer_ip = peer_addr.ip();
        if !tcp_ao_accept_generation_valid(
            tcp_ao_info.is_some(),
            tcp_ao_generation,
            &self.tcp_ao_rotation,
        ) {
            if tcp_ao_info.is_some() {
                warn!(
                    %peer_ip,
                    accepted_generation = tcp_ao_generation.map(TcpAoRotationGeneration::as_u64),
                    desired_generation = self.tcp_ao_rotation.desired.as_u64(),
                    applied_generation = self.tcp_ao_rotation.applied.as_u64(),
                    phase = ?self.tcp_ao_rotation.phase,
                    "rejecting protected inbound connection outside the valid TCP-AO generation fence"
                );
            } else {
                warn!(%peer_ip, "rejecting inbound connection with inconsistent TCP-AO generation metadata");
            }
            return;
        }
        let accepted_generation = tcp_ao_generation.unwrap_or(self.tcp_ao_generation);
        let peer_key = self.inbound_peer_key(peer_addr);
        // If peer is not statically configured, try dynamic range matching.
        if peer_key.is_none() {
            if self.config_snapshot_staged {
                warn!(
                    %peer_ip,
                    "dropping dynamic inbound connection while a config transaction snapshot is staged"
                );
                return;
            }
            // A link-local inbound that did not match a configured scoped peer
            // must not fall through to dynamic acceptance: dynamic peers are
            // keyed by bare address (`PeerKey::new(ip, None)`), so accepting a
            // `fe80::` source here would create an unscoped link-local peer and
            // re-introduce the RFC 4007 ambiguity that scoped static peers exist
            // to remove. v1 requires link-local peers to be statically
            // configured with an interface (ADR-0069).
            if let SocketAddr::V6(v6) = peer_addr
                && v6.ip().segments()[0] & 0xffc0 == 0xfe80
            {
                warn!(
                    %peer_addr,
                    "inbound IPv6 link-local connection did not match a configured scoped neighbor; dynamic acceptance of link-local peers is not supported, dropping"
                );
                return;
            }
            if let Some(range) = self.match_dynamic_range(peer_ip) {
                // Check dynamic peer limit
                if self.dynamic_peer_count >= self.dynamic_neighbor_limit as usize {
                    warn!(
                        %peer_ip,
                        limit = self.dynamic_neighbor_limit,
                        "dynamic neighbor limit reached, dropping inbound connection"
                    );
                    return;
                }

                // Look up the peer group to build the config
                let Some(group) = self.current_config.peer_groups.get(&range.peer_group) else {
                    warn!(
                        %peer_ip,
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
                let accepted_dynamic_range = range.accepted_attribution();
                let mut accepted_tcp_ao_keyring = range.tcp_ao.clone();

                // Resolve the dynamic neighbor config from the peer group
                let resolved = match self.current_config.resolve_dynamic_neighbor(
                    peer_ip,
                    remote_asn,
                    &description,
                    group,
                    &peer_group_name,
                ) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(
                            %peer_ip,
                            error = %e,
                            "failed to resolve dynamic neighbor config, dropping"
                        );
                        return;
                    }
                };

                let cfg = Self::peer_manager_config_from_resolved(resolved, false);
                let mut transport = self.build_transport_config(&cfg);
                let import_policy = cfg.import_policy.clone();
                let export_policy = cfg.export_policy.clone();
                let advertise_graceful_shutdown = self
                    .dead_lettered_pending
                    .get(&peer_ip)
                    .is_some_and(|pending| pending.graceful_shutdown);
                let tcp_ao_protected = tcp_ao_info.is_some();
                if tcp_ao_protected != accepted_tcp_ao_keyring.is_some() {
                    warn!(
                        %peer_ip,
                        "dynamic inbound TCP-AO socket protection differs from its explicit selected-owner keyring, dropping"
                    );
                    return;
                }
                let tcp_ao_selected_owner =
                    tcp_ao_protected.then_some(rustbgpd_transport::listener::TcpAoSelectedOwner {
                        owner: rustbgpd_transport::TcpAoListenerOwnerKind::Dynamic,
                        peer: accepted_dynamic_range.addr,
                        prefix_len: accepted_dynamic_range.prefix_len,
                    });
                if tcp_ao_protected {
                    let (Some(keyring), Some(selected_owner), Some(accepted)) = (
                        accepted_tcp_ao_keyring.as_mut(),
                        tcp_ao_selected_owner,
                        tcp_ao_info.as_ref(),
                    ) else {
                        warn!(
                            %peer_ip,
                            "protected dynamic TCP-AO accept lacks selected-owner metadata, dropping"
                        );
                        return;
                    };
                    if let Err(error) =
                        reconcile_selected_owner_metadata(keyring, selected_owner, accepted)
                    {
                        warn!(
                            %peer_ip,
                            error,
                            "failed to reconcile protected dynamic TCP-AO accept, dropping"
                        );
                        return;
                    }
                }
                // `resolve_dynamic_neighbor` intentionally derives session
                // policy from the peer group and has no per-host TCP-AO field.
                // Seed the exact most-specific direct owner's keyring before
                // cloning this transport into PeerSession and retaining it on
                // ManagedPeer. This makes fresh-start selection authoritative
                // without falling back to the accepted socket's owner union.
                transport.tcp_ao = accepted_tcp_ao_keyring;

                let session_id = self.allocate_session_id();
                let handle = PeerHandle::spawn_inbound_at_tcp_ao_generation(
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
                    self.transport_event_sink.clone(),
                    tcp_ao_info,
                    tcp_ao_selected_owner,
                    accepted_generation,
                );

                if let Err(e) = handle.start_timeout(PEER_LIFECYCLE_COMMAND_TIMEOUT).await {
                    warn!(%peer_addr, error = %e, "failed to start dynamic peer session");
                    // The session task was already spawned; the handle is never
                    // stored, so shut it down (abort-on-timeout) rather than
                    // dropping it and orphaning a wedged task.
                    let _ = self
                        .shutdown_handle_bounded(
                            peer_addr.ip(),
                            "dynamic peer start failure",
                            handle,
                        )
                        .await;
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
                    max_prefix_restart_seconds: cfg.max_prefix_restart_seconds,
                    transport_config: transport,
                    import_policy,
                    export_policy,
                    pending_inbound: None,
                    is_dynamic: true,
                    tcp_ao_protected,
                    tcp_ao_rotation: if tcp_ao_protected {
                        self.tcp_ao_rotation.clone()
                    } else {
                        rustbgpd_transport::TcpAoRotationStatus {
                            desired: accepted_generation,
                            applied: accepted_generation,
                            phase: rustbgpd_transport::TcpAoRotationPhase::Idle,
                            last_error: None,
                        }
                    },
                    accepted_dynamic_range: Some(accepted_dynamic_range),
                    pending_refresh: false,
                    pending_export_apply: false,
                    advertise_graceful_shutdown,
                };
                let peer_key = PeerKey::new(peer_ip, None);
                self.peers.insert(peer_key.clone(), managed);
                self.register_session(session_id, &peer_key);
                self.dynamic_peer_count += 1;

                // Restore any dead-lettered hot-apply / Route Refresh
                // intent left behind by a prior dynamic-peer auto-
                // removal at this address. Carries the retry across
                // the brief drop-and-recreate window so a transient
                // TCP flap doesn't silently lose a SetPolicy edit.
                self.restore_dead_lettered_pending(peer_ip);

                // Report which range accepted the peer by borrowing the stored
                // attribution (no clone). This read also keeps the field live;
                // the transaction executor is its other consumer.
                if let Some(accepted) = self
                    .peers
                    .get(&peer_key)
                    .and_then(|managed| managed.accepted_dynamic_range.as_ref())
                {
                    info!(
                        %peer_ip,
                        accepted_prefix = %format_args!("{}/{}", accepted.addr, accepted.prefix_len),
                        accepted_peer_group = %accepted.peer_group,
                        "accepted dynamic neighbor from configured range"
                    );
                }
                return;
            }

            // No dynamic range match either — drop with hint
            warn!(
                %peer_ip,
                hint = %format_args!(
                    "to accept: rbgp neighbor {peer_ip} add --asn <REMOTE_ASN>"
                ),
                "inbound connection from unknown peer, dropping"
            );
            return;
        }

        // ADR-0067 step 4 — BFD withholding must cover the passive path too. The
        // active-open lifecycle (`add_peer` / `enable_peer`) withholds `start()`
        // while BFD does not permit BGP, but every inbound sub-case below
        // (`replace_with_inbound`, collision candidates) starts a session
        // directly. Without this gate a peer whose BGP is currently held by BFD
        // could accept an inbound connection and establish BGP anyway. This
        // covers both holds: a strict peer withheld pending BFD-up, and a
        // (strict or non-strict) peer torn down by a BFD-down — in both cases
        // BFD does not currently permit BGP, so we must not re-establish it over
        // a presumed-dead path. Gate on the *current* held state (not the
        // add-time decision) so an established, BFD-up peer still accepts inbound
        // normally; the hold's eventual release starts the session via the
        // normal up→start path.
        let Some(peer_key) = peer_key else {
            warn!(%peer_ip, "inbound peer lookup missing before BFD gate, dropping");
            return;
        };
        let peer_addr = peer_key.address;
        if self.bfd_withholding(&peer_addr) {
            info!(%peer_addr, "BFD — dropping inbound connection while BGP is held");
            return;
        }

        let Some(managed) = self.peers.get_mut(&peer_key) else {
            return;
        };

        if !managed.enabled {
            info!(%peer_addr, "inbound connection for disabled peer, dropping");
            return;
        }
        let queried_session_id = managed.session_id;

        // Bounded so an inbound TCP arriving during a TCP-back-pressure
        // wedge on the existing session can't park the peer-manager actor
        // mid-collision-resolution. The outcome keeps a dead session task
        // separate from a query that merely missed the deadline:
        //
        // - SessionGone: the session task has exited, so there is nothing
        //   to collide with. Treat it as `Idle` and take the "accept
        //   immediately" arm — equivalent to the no-session-yet path.
        // - TimedOut: the task may still be alive. The documented cause of
        //   a missed deadline is precisely a TCP-back-pressure wedge, and a
        //   wedged session may be Established — RFC 4271 §6.8 requires the
        //   NEW connection to lose a collision against an Established
        //   session, so treating a timeout as `Idle` would convert a
        //   transient stall into a session reset. Drop the inbound instead:
        //   if the existing session is genuinely wedged-dead, hold-timer
        //   expiry tears it down and the remote's retry then lands in the
        //   genuine `Idle` arm. Losing one inbound attempt is cheap;
        //   tearing down an Established session on a transient stall is
        //   not.
        let current_state = match managed.handle.query_state_outcome(PEER_QUERY_TIMEOUT).await {
            StateQueryOutcome::State(state) => Some(state),
            StateQueryOutcome::SessionGone => None,
            StateQueryOutcome::TimedOut => {
                info!(
                    %peer_addr,
                    "session state query timed out during inbound handling; keeping the existing session and dropping the inbound connection (remote will retry)"
                );
                return;
            }
        };
        let fsm_state = current_state
            .as_ref()
            .map_or(SessionState::Idle, |s| s.fsm_state);

        match fsm_state {
            SessionState::Idle => {
                // MaxPrefixExceeded is sent before the session drives itself
                // to Idle, but it crosses a different manager channel than
                // AcceptInbound. Drain that lossless lane after the bounded
                // state query, then re-check both ownership and admin state:
                // otherwise an inbound reconnect can replace the breached
                // generation in the narrow query/notification race.
                self.drain_ready_session_notifications().await;
                if !self.peers.get(&peer_key).is_some_and(|managed| {
                    managed.enabled && managed.session_id == queried_session_id
                }) {
                    info!(
                        %peer_addr,
                        "peer ownership or admin state changed during inbound Idle query; dropping connection"
                    );
                    return;
                }
                // Accept immediately — no collision possible
                self.replace_with_inbound(
                    peer_key.clone(),
                    stream,
                    tcp_ao_info,
                    accepted_generation,
                )
                .await;
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
                self.spawn_pending_inbound(
                    peer_key.clone(),
                    stream,
                    tcp_ao_info,
                    accepted_generation,
                )
                .await;
            }
            SessionState::OpenConfirm => {
                // We already have router-id from negotiation; start a live
                // inbound candidate and resolve immediately.
                let remote_router_id = current_state.and_then(|s| s.remote_router_id);
                let started = self
                    .spawn_pending_inbound(
                        peer_key.clone(),
                        stream,
                        tcp_ao_info,
                        accepted_generation,
                    )
                    .await;
                if let Some(rid) = remote_router_id {
                    if started {
                        self.resolve_collision(peer_key, rid).await;
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
        peer_key: PeerKey,
        remote_router_id: Ipv4Addr,
    ) {
        let peer_addr = peer_key.address;
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
                    .get_mut(&peer_key)
                    .and_then(|m| m.pending_inbound.take())
                {
                    self.quiesce_retiring_session(
                        &peer_key,
                        pending.session_id,
                        pending.handle,
                        "local-wins collision loser",
                        true,
                    )
                    .await;
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
                let promoted = {
                    let managed = self.peers.get_mut(&peer_key);
                    managed.and_then(|managed| {
                        let pending = managed.pending_inbound.take()?;
                        let old_handle = std::mem::replace(&mut managed.handle, pending.handle);
                        let old_session_id = managed.session_id;
                        managed.session_id = pending.session_id;
                        Some((old_handle, old_session_id, pending.session_id))
                    })
                };
                if let Some((old_handle, old_session_id, new_session_id)) = promoted {
                    self.register_session(new_session_id, &peer_key);
                    self.finish_inbound_promotion(
                        &peer_key,
                        old_session_id,
                        old_handle,
                        new_session_id,
                        "remote-wins collision loser",
                        true,
                    )
                    .await;
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
                    .get_mut(&peer_key)
                    .and_then(|m| m.pending_inbound.take())
                {
                    self.quiesce_retiring_session(
                        &peer_key,
                        pending.session_id,
                        pending.handle,
                        "equal-router-id collision loser",
                        true,
                    )
                    .await;
                }
            }
        }
    }

    pub(super) fn promote_pending_inbound_handle(
        &mut self,
        peer_key: &PeerKey,
    ) -> Option<(PeerHandle, u64, u64)> {
        let (old_handle, old_session_id, new_session_id) = {
            let managed = self.peers.get_mut(peer_key)?;
            let pending = managed.pending_inbound.take()?;
            let old_handle = std::mem::replace(&mut managed.handle, pending.handle);
            let old_session_id = managed.session_id;
            managed.session_id = pending.session_id;
            (old_handle, old_session_id, pending.session_id)
        };
        self.register_session(new_session_id, peer_key);
        Some((old_handle, old_session_id, new_session_id))
    }

    pub(super) async fn promote_pending_inbound(&mut self, peer_key: &PeerKey) -> bool {
        let Some((old_handle, old_session_id, new_session_id)) =
            self.promote_pending_inbound_handle(peer_key)
        else {
            return false;
        };
        self.finish_inbound_promotion(
            peer_key,
            old_session_id,
            old_handle,
            new_session_id,
            "promote pending inbound old primary",
            false,
        )
        .await;
        true
    }

    async fn finish_inbound_promotion(
        &mut self,
        peer_key: &PeerKey,
        old_session_id: u64,
        old_handle: PeerHandle,
        new_session_id: u64,
        context: &'static str,
        collision_dump: bool,
    ) {
        let _ = self
            .quiesce_retiring_session(
                peer_key,
                old_session_id,
                old_handle,
                context,
                collision_dump,
            )
            .await;
        self.activate_promoted_max_prefix_metrics(peer_key, new_session_id)
            .await;
    }

    async fn activate_promoted_max_prefix_metrics(
        &self,
        peer_key: &PeerKey,
        expected_session_id: u64,
    ) {
        let Some(managed) = self.peers.get(peer_key) else {
            return;
        };
        if managed.session_id != expected_session_id {
            warn!(
                peer = %peer_key.address,
                expected_session_id,
                current_session_id = managed.session_id,
                "skipping stale max-prefix metric ownership transfer"
            );
            return;
        }
        if let Err(error) = managed
            .handle
            .activate_max_prefix_metrics_timeout(PEER_LIFECYCLE_COMMAND_TIMEOUT)
            .await
        {
            // Missing gauges are safer than allowing a collision loser to
            // publish or reap the winner's shared peer label.
            warn!(
                peer = %peer_key.address,
                session_id = expected_session_id,
                %error,
                "failed to activate promoted session max-prefix metrics"
            );
        }
    }

    pub(super) async fn replace_with_inbound(
        &mut self,
        peer_key: PeerKey,
        stream: TcpStream,
        tcp_ao_info: Option<TcpAoInfoSnapshot>,
        tcp_ao_generation: TcpAoRotationGeneration,
    ) {
        let peer_addr = peer_key.address;
        let session_id = self.allocate_session_id();
        let Some((old_handle, old_session_id)) = ({
            let Some(managed) = self.peers.get_mut(&peer_key) else {
                return;
            };

            // Replay the operator-driven RFC 8326 toggle on the new
            // session so a flap or collision-replace doesn't silently
            // drop the GShut state mid-maintenance.
            let advertise_graceful_shutdown = managed.advertise_graceful_shutdown;
            let tcp_ao_selected_owner = tcp_ao_info
                .as_ref()
                .map(|_| accepted_selected_owner(managed));
            let old_session_id = managed.session_id;
            let old_handle = std::mem::replace(
                &mut managed.handle,
                PeerHandle::spawn_inbound_at_tcp_ao_generation(
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
                    self.transport_event_sink.clone(),
                    tcp_ao_info,
                    tcp_ao_selected_owner,
                    tcp_ao_generation,
                ),
            );
            managed.session_id = session_id;
            Some((old_handle, old_session_id))
        }) else {
            return;
        };
        self.register_session(session_id, &peer_key);

        // Shut down the old session
        let _ = self
            .quiesce_retiring_session(
                &peer_key,
                old_session_id,
                old_handle,
                "replace with inbound old primary",
                false,
            )
            .await;

        // Start the new inbound session — trigger TcpConnectionConfirmed
        let Some(managed) = self.peers.get(&peer_key) else {
            return;
        };
        if !managed.enabled {
            info!(%peer_addr, "inbound replacement remains stopped by terminal peer latch");
            return;
        }
        if let Err(e) = managed
            .handle
            .start_timeout(PEER_LIFECYCLE_COMMAND_TIMEOUT)
            .await
        {
            warn!(%peer_addr, error = %e, "failed to start inbound session");
        } else {
            info!(%peer_addr, "inbound session started");
        }
    }
}

#[cfg(test)]
mod generation_tests {
    use super::*;

    #[test]
    fn protected_accept_requires_exact_applied_generation() {
        let one = TcpAoRotationGeneration::STARTUP;
        let two = TcpAoRotationGeneration::new(2).unwrap();
        let idle = rustbgpd_transport::TcpAoRotationStatus {
            desired: two,
            applied: two,
            phase: rustbgpd_transport::TcpAoRotationPhase::Idle,
            last_error: None,
        };
        assert!(tcp_ao_accept_generation_valid(true, Some(two), &idle));
        assert!(!tcp_ao_accept_generation_valid(true, Some(one), &idle));
        assert!(!tcp_ao_accept_generation_valid(true, None, &idle));
        assert!(tcp_ao_accept_generation_valid(false, None, &idle));
        assert!(!tcp_ao_accept_generation_valid(false, Some(two), &idle));

        let applying = rustbgpd_transport::TcpAoRotationStatus {
            phase: rustbgpd_transport::TcpAoRotationPhase::AddOnly,
            ..idle.clone()
        };
        assert!(tcp_ao_accept_generation_valid(true, Some(two), &applying));
        assert!(!tcp_ao_accept_generation_valid(true, Some(one), &applying));

        let applying = rustbgpd_transport::TcpAoRotationStatus {
            desired: two,
            applied: one,
            phase: rustbgpd_transport::TcpAoRotationPhase::AddOnly,
            last_error: None,
        };
        assert!(tcp_ao_accept_generation_valid(true, Some(one), &applying));
        assert!(tcp_ao_accept_generation_valid(true, Some(two), &applying));
        assert!(!tcp_ao_accept_generation_valid(
            true,
            TcpAoRotationGeneration::new(3),
            &applying
        ));

        let failed = rustbgpd_transport::TcpAoRotationStatus {
            desired: two,
            applied: one,
            phase: rustbgpd_transport::TcpAoRotationPhase::AddOnlyFailed,
            last_error: Some("listener apply failed".to_string()),
        };
        assert!(tcp_ao_accept_generation_valid(true, Some(one), &failed));
        assert!(!tcp_ao_accept_generation_valid(true, Some(two), &failed));

        for phase in [
            rustbgpd_transport::TcpAoRotationPhase::Selecting,
            rustbgpd_transport::TcpAoRotationPhase::AwaitingPeer,
        ] {
            let recovered = rustbgpd_transport::TcpAoRotationStatus {
                phase,
                ..idle.clone()
            };
            assert!(tcp_ao_accept_generation_valid(true, Some(two), &recovered));
            assert!(!tcp_ao_accept_generation_valid(true, Some(one), &recovered));
            let selecting = rustbgpd_transport::TcpAoRotationStatus {
                desired: two,
                applied: one,
                phase,
                last_error: None,
            };
            assert!(tcp_ao_accept_generation_valid(true, Some(one), &selecting));
            assert!(tcp_ao_accept_generation_valid(true, Some(two), &selecting));
        }
        let selection_failed = rustbgpd_transport::TcpAoRotationStatus {
            desired: two,
            applied: one,
            phase: rustbgpd_transport::TcpAoRotationPhase::SelectionFailed,
            last_error: Some("observation failed".to_string()),
        };
        assert!(tcp_ao_accept_generation_valid(
            true,
            Some(one),
            &selection_failed
        ));
        assert!(!tcp_ao_accept_generation_valid(
            true,
            Some(two),
            &selection_failed
        ));
    }
}
