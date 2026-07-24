use std::collections::BTreeSet;

use rustbgpd_api::peer_types::{
    ConfigEvent, DynamicPeerBounceOutcome, DynamicRangeTarget, PeerKey, PeerLifecycleError,
    PeerManagerNeighborConfig, SessionLifecycleEventType, SetGshutError,
};
use rustbgpd_rib::RibUpdate;
use rustbgpd_transport::{PeerCommand, PeerCommandError};
use rustbgpd_transport::{PeerHandle, SessionIdentity, TcpAoKeyring, TransportConfig};
use rustbgpd_wire::{Afi, Safi};
use tokio::sync::oneshot;
use tracing::{debug, error, info, warn};

use crate::policy_admin::apply_config_event;

use super::{
    ManagedPeer, PEER_LIFECYCLE_COMMAND_TIMEOUT, PEER_POLICY_UPDATE_TIMEOUT, PeerManager,
    PeerShutdownOutcome,
};

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

impl PeerManager {
    fn allocate_max_prefix_latch_generation(&mut self) -> u64 {
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
        let Some(seconds) = restart_seconds else {
            self.invalidate_max_prefix_restart(peer);
            return;
        };
        let generation = self.allocate_max_prefix_latch_generation();
        let rearmed = self.max_prefix_latches.get_mut(peer).is_some_and(|latch| {
            if latch.deadline.is_some() {
                latch.generation = generation;
                latch.deadline = Some(
                    tokio::time::Instant::now() + std::time::Duration::from_secs(seconds.into()),
                );
                true
            } else {
                false
            }
        });
        if rearmed {
            // The rescheduled deadline may be later than the cached minimum it
            // replaces, so a full recompute is required (the cheap min-update
            // in `install_max_prefix_latch` would keep a stale earlier wake).
            self.recompute_next_max_prefix_restart_deadline();
        }
    }

    pub(super) fn remove_max_prefix_latch(&mut self, peer: &PeerKey) {
        if self.max_prefix_latches.remove(peer).is_some() {
            self.recompute_next_max_prefix_restart_deadline();
        }
    }

    pub(super) fn dynamic_restart_policy_still_current(&self, managed: &ManagedPeer) -> bool {
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
                let _ = self.max_prefix_latches.remove(&peer);
                self.set_bfd_peer_disabled(address, false);
                self.mark_bfd_withheld(address);
                self.publish_peer_lifecycle_event(
                    &peer,
                    SessionLifecycleEventType::PeerEnabled,
                    format!("peer {address} max-prefix hold-down expired; waiting for BFD"),
                );
                info!(%address, "max-prefix hold-down expired; strict BFD still withholds BGP until BFD Up");
                continue;
            }
            let commands = self
                .peers
                .get(&peer)
                .expect("validated above")
                .handle
                .commands_sender();
            starts.push((peer, commands));
        }
        self.recompute_next_max_prefix_restart_deadline();

        let attempts = starts
            .iter()
            .map(|(_, commands)| send_max_prefix_start_before(commands.clone(), attempt_deadline));
        let results = self
            .await_with_readiness(futures::future::join_all(attempts))
            .await;

        for ((peer, _commands), result) in starts.into_iter().zip(results) {
            let address = peer.address;
            match result {
                Ok(()) => {
                    if let Some(managed) = self.peers.get_mut(&peer) {
                        managed.enabled = true;
                    }
                    let _ = self.max_prefix_latches.remove(&peer);
                    self.set_bfd_peer_disabled(address, false);
                    self.publish_peer_lifecycle_event(
                        &peer,
                        SessionLifecycleEventType::PeerEnabled,
                        format!(
                            "peer {address} automatically restarted after max-prefix hold-down"
                        ),
                    );
                    info!(%address, "peer automatically restarted after max-prefix hold-down");
                }
                Err(error) => {
                    if let Some(latch) = self.max_prefix_latches.get_mut(&peer) {
                        latch.error = format!(
                            "automatic max-prefix restart failed: {error}; peer remains disabled; run 'rbgp neighbor {} enable' to retry",
                            peer.label()
                        );
                    }
                    warn!(%address, %error, "automatic max-prefix restart attempt failed; peer remains latched disabled");
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
        Box::pin(self.drain_ready_session_notifications()).await;
        self.retiring_sessions.remove(&session_id);
        self.unregister_session(session_id);
        outcome
    }

    pub(super) async fn shutdown_handle_bounded(
        &self,
        address: std::net::IpAddr,
        context: &'static str,
        handle: PeerHandle,
    ) -> PeerShutdownOutcome {
        Self::shutdown_handle_bounded_owned(address, context, handle).await
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
                warn!(%address, %context, error = %e, "peer shutdown returned transport error");
                PeerShutdownOutcome::Joined
            }
            Err(rustbgpd_transport::PeerShutdownError::Join(e)) => {
                error!(%address, %context, error = %e, "peer task join error during shutdown");
                PeerShutdownOutcome::Joined
            }
            Err(rustbgpd_transport::PeerShutdownError::TimedOut { .. }) => {
                warn!(
                    %address,
                    %context,
                    timeout_ms = %PEER_LIFECYCLE_COMMAND_TIMEOUT.as_millis(),
                    "peer shutdown timed out; aborted session task and continuing without parking PeerManager"
                );
                PeerShutdownOutcome::TimedOut
            }
        }
    }

    fn removed_peer_config(peer: &PeerKey, managed: &ManagedPeer) -> PeerManagerNeighborConfig {
        let tc = &managed.transport_config;
        PeerManagerNeighborConfig {
            address: peer.address,
            interface: peer.interface.clone(),
            scope_id: tc.peer_scope_id,
            remote_asn: managed.remote_asn,
            description: managed.description.clone(),
            peer_group: managed.peer_group.clone(),
            hold_time: managed.hold_time,
            min_hold_time: tc.peer.min_hold_time,
            send_hold_time: Some(tc.peer.send_hold_time),
            max_prefixes: managed.max_prefixes,
            max_prefixes_ipv4: tc.max_prefixes_ipv4,
            max_prefixes_ipv6: tc.max_prefixes_ipv6,
            max_prefix_restart_seconds: managed.max_prefix_restart_seconds,
            md5_password: tc.md5_password.clone(),
            tcp_ao: tc.tcp_ao.clone(),
            ttl_security: tc.ttl_security,
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
            per_client_best: tc.per_client_best,
            next_hop_ownership_strict_peer: tc.next_hop_ownership_strict_peer,
            slow_peer_threshold_pct: tc.slow_peer_threshold_pct,
            slow_peer_duration: tc.slow_peer_duration,
            slow_peer_isolation: tc.slow_peer_isolation,
            interpret_rfc1997: tc.interpret_rfc1997,
            rs_control_communities: tc.rs_control_communities,
            remove_private_as: tc.remove_private_as,
            add_path_receive: tc.peer.add_path_receive,
            add_path_send: tc.peer.add_path_send,
            add_path_send_max: tc.peer.add_path_send_max,
            paths_limit_receive_max: tc.peer.paths_limit_receive_max,
            local_role: tc.peer.local_role,
            strict_role: tc.peer.strict_role,
            prefix_orf_receive: tc.peer.prefix_orf_receive,
            disable_ipv4_unicast: tc.peer.disable_ipv4_unicast,
            import_policy: managed.import_policy.clone(),
            export_policy: managed.export_policy.clone(),
        }
    }

    pub(super) async fn add_peer(
        &mut self,
        config: PeerManagerNeighborConfig,
        sync_config_snapshot: bool,
    ) -> Result<(), PeerLifecycleError> {
        self.add_peer_with_admin_state(config, sync_config_snapshot, true)
            .await
    }

    #[expect(
        clippy::too_many_lines,
        reason = "peer add wires transport, policy, BFD desired state, persistence, and events"
    )]
    pub(super) async fn add_peer_with_admin_state(
        &mut self,
        config: PeerManagerNeighborConfig,
        sync_config_snapshot: bool,
        enabled: bool,
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
        if let Some(interface) = &config.interface
            && config.scope_id.is_none()
            && let Err(error) = nix::net::if_::if_nametoindex(interface.as_str())
        {
            return Err(PeerLifecycleError::Invalid(format!(
                "peer {peer_key} interface {interface:?} cannot be resolved: {error}"
            )));
        }

        let (transport, label, peer_group, import_policy, export_policy, next_config) =
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

        let address = config.address;
        let remote_asn = config.remote_asn;
        let description = label;
        let hold_time = Some(transport.peer.hold_time);
        let max_prefixes = transport.max_prefixes;

        let session_id = self.allocate_session_id();
        let handle = PeerHandle::spawn_at_tcp_ao_generation(
            transport.clone(),
            self.metrics.clone(),
            self.rib_tx.clone(),
            import_policy.clone(),
            export_policy.clone(),
            Some(self.session_notify_tx.clone()),
            Some(self.session_notification_event_tx.clone()),
            Some(self.session_lifecycle_tx.clone()),
            self.bmp_tx.clone(),
            self.validation_rx.clone(),
            false,
            SessionIdentity::primary(session_id),
            self.transport_event_sink.clone(),
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
        if enabled
            && !withhold
            && let Err(e) = handle.start_timeout(PEER_LIFECYCLE_COMMAND_TIMEOUT).await
        {
            warn!(%address, error = %e, "failed to start peer session");
            return Err(PeerLifecycleError::Internal(format!(
                "failed to start peer: {e}"
            )));
        }

        info!(%address, %remote_asn, "peer added dynamically");
        let tcp_ao_protected = transport.tcp_ao.is_some();
        self.peers.insert(
            peer_key.clone(),
            ManagedPeer {
                handle,
                session_id,
                remote_asn,
                description,
                peer_group,
                enabled,
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
        );
        self.register_session(session_id, &peer_key);

        if let Some(next_config) = next_config {
            self.current_config = next_config;
        }

        if enabled {
            // ADR-0067 step 4: (re-)arm this peer's BFD session. Critically
            // covers the delete→add reconfigure cycle — a re-added BFD peer
            // must clear its disabled mark so the actor restarts the session.
            // A brand-new peer not in the startup-pinned BFD set is unaffected
            // (BFD is restart-required).
            self.set_bfd_peer_disabled(address, false);
            // For a strict peer, mark it pre-held so the first BFD Up releases
            // the withhold via the normal up→start path.
            if withhold {
                self.mark_bfd_withheld(address);
                info!(%address, "strict BFD — withholding BGP establishment until BFD is Up");
            }
        } else {
            // A disabled re-add is a live config object only; keep BGP stopped
            // and keep the BFD desired session disabled until EnablePeer.
            self.set_bfd_peer_disabled(address, true);
        }
        Ok(())
    }

    pub(super) async fn delete_peer(
        &mut self,
        peer: PeerKey,
        sync_config_snapshot: bool,
    ) -> Result<PeerManagerNeighborConfig, PeerLifecycleError> {
        self.delete_peer_checked(peer, sync_config_snapshot, None, true)
            .await
    }

    /// Reconfigure's delete half: the peer is immediately re-added, so
    /// it continues to exist and keeps its metric series
    /// (`reap_metric_series = false`).
    pub(super) async fn delete_peer_for_reconfigure(
        &mut self,
        peer: PeerKey,
        next_tcp_ao: Option<&TcpAoKeyring>,
    ) -> Result<(), PeerLifecycleError> {
        self.delete_peer_checked(peer, false, next_tcp_ao, false)
            .await
            .map(|_| ())
    }

    pub(super) async fn reconfigure_peer(
        &mut self,
        config: PeerManagerNeighborConfig,
    ) -> Result<PeerManagerNeighborConfig, PeerLifecycleError> {
        let peer = PeerKey::new(config.address, config.interface.clone());
        self.invalidate_max_prefix_restart(&peer);
        #[cfg(test)]
        if let Some(remaining) = self.inject_reconfigure_failures.get_mut(&peer) {
            if *remaining == 0 {
                return Err(PeerLifecycleError::Internal(format!(
                    "injected reconfigure failure for {peer}"
                )));
            }
            *remaining -= 1;
        }
        let (was_enabled, graceful_shutdown) = self
            .peers
            .get(&peer)
            .map(|managed| (managed.enabled, managed.advertise_graceful_shutdown))
            .ok_or_else(|| PeerLifecycleError::NotFound(peer.clone()))?;

        let previous = self
            .delete_peer_checked(peer.clone(), false, config.tcp_ao.as_ref(), false)
            .await?;
        if let Err(add_error) = self
            .add_peer_with_admin_state(config, false, was_enabled)
            .await
        {
            return match self
                .restore_reconfigured_peer(
                    peer.clone(),
                    previous.clone(),
                    was_enabled,
                    graceful_shutdown,
                )
                .await
            {
                Ok(()) => Err(PeerLifecycleError::Internal(format!(
                    "failed to add reconfigured peer {peer}: {add_error}; previous peer restored"
                ))),
                Err(restore_error) => Err(PeerLifecycleError::Internal(format!(
                    "failed to add reconfigured peer {peer}: {add_error}; restore previous peer failed: {restore_error}"
                ))),
            };
        }

        if let Err(state_error) = self
            .apply_reconfigured_peer_state(peer.clone(), graceful_shutdown)
            .await
        {
            return match self
                .restore_reconfigured_peer(
                    peer.clone(),
                    previous.clone(),
                    was_enabled,
                    graceful_shutdown,
                )
                .await
            {
                Ok(()) => Err(PeerLifecycleError::Internal(format!(
                    "failed to restore runtime state for reconfigured peer {peer}: {state_error}; previous peer restored"
                ))),
                Err(restore_error) => Err(PeerLifecycleError::Internal(format!(
                    "failed to restore runtime state for reconfigured peer {peer}: {state_error}; restore previous peer failed: {restore_error}"
                ))),
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
    #[expect(
        clippy::too_many_lines,
        reason = "one linear pass: change detection, policy seam, knob apply, export refresh, bookkeeping"
    )]
    pub(super) async fn hot_update_peer(
        &mut self,
        config: PeerManagerNeighborConfig,
    ) -> Result<(), PeerLifecycleError> {
        let peer = PeerKey::new(config.address, config.interface.clone());
        let (knobs_changed, export_knobs_changed, policies_changed, restart_policy_changed) = {
            let managed = self
                .peers
                .get(&peer)
                .ok_or_else(|| PeerLifecycleError::NotFound(peer.clone()))?;
            if managed.is_dynamic {
                return Err(PeerLifecycleError::Invalid(format!(
                    "hot update target {peer} is a dynamic peer; reload reconciles static neighbors only"
                )));
            }
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
                    || tc.gr_stale_routes_time != config.gr_stale_routes_time
                    || tc.gr_peer_restart_time_max != config.gr_peer_restart_time_max
                    || export_knobs_changed,
                export_knobs_changed,
                managed.import_policy != config.import_policy
                    || managed.export_policy != config.export_policy,
                managed.max_prefix_restart_seconds != config.max_prefix_restart_seconds,
            )
        };

        // Policy first: the live-policy seam has its own rollback, so a
        // failure here leaves the peer fully on its prior config. A
        // later knob failure leaves policies advanced — safe, because
        // reload halts, keeps the OLD neighbor in its snapshot, and the
        // next SIGHUP re-detects and re-applies both (idempotent).
        if policies_changed {
            self.update_runtime_policies_fatal(
                peer.clone(),
                config.import_policy.clone(),
                config.export_policy.clone(),
            )
            .await
            .map_err(PeerLifecycleError::Internal)?;
        }

        if knobs_changed {
            let managed = self
                .peers
                .get(&peer)
                .ok_or_else(|| PeerLifecycleError::NotFound(peer.clone()))?;
            managed
                .handle
                .update_runtime_config_timeout(
                    config.max_prefixes,
                    config.max_prefixes_ipv4,
                    config.max_prefixes_ipv6,
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

        // Force re-emission after an export-affecting knob swap — the same
        // reason the gshut toggle and live-policy apply refresh: routes the
        // exact-export preflight suppressed under the OLD knobs (e.g.
        // `MissingIpv6NextHop`) are only re-probed, and already-advertised
        // AS_PATHs only re-encoded, on an outbound event. Without this the
        // remediation stays off the wire until unrelated churn or a session
        // bounce. Runs BEFORE the bookkeeping below: a hard refresh failure
        // returns Err while the stored transport config still holds the old
        // values, so the next SIGHUP re-detects the diff and retries
        // (idempotent — the session-side knob re-apply is a no-op).
        if export_knobs_changed {
            let addr = peer.address;
            let (reply_tx, reply_rx) = oneshot::channel();
            self.rib_tx
                .send(RibUpdate::RefreshPeerOutbound {
                    peer: addr,
                    reply: reply_tx,
                })
                .await
                .map_err(|error| {
                    PeerLifecycleError::Internal(format!(
                        "failed to send RIB refresh after hot-applying export knobs to {peer}: {error}"
                    ))
                })?;
            match tokio::time::timeout(super::RIB_REPLY_TIMEOUT, reply_rx).await {
                Err(_) => {
                    return Err(PeerLifecycleError::Internal(format!(
                        "RIB did not reply to export-knob refresh for {peer} within {:?}",
                        super::RIB_REPLY_TIMEOUT
                    )));
                }
                Ok(Err(_)) => {
                    return Err(PeerLifecycleError::Internal(format!(
                        "RIB dropped reply for export-knob refresh for {peer}"
                    )));
                }
                Ok(Ok(Err(error))) => {
                    // "not registered for outbound updates" is expected for a
                    // peer not yet Established — the next PeerUp emits from
                    // the updated config.
                    debug!(
                        %addr, error = %error,
                        "RIB declined export-knob refresh (peer likely not yet Established)"
                    );
                }
                Ok(Ok(Ok(()))) => {}
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

        // Manager-side bookkeeping so `rbgp neighbor list` and any later
        // session rebuild see the new values.
        let managed = self
            .peers
            .get_mut(&peer)
            .ok_or_else(|| PeerLifecycleError::NotFound(peer.clone()))?;
        managed.description.clone_from(&config.description);
        managed.max_prefixes = config.max_prefixes;
        managed.max_prefix_restart_seconds = config.max_prefix_restart_seconds;
        managed.transport_config.max_prefixes = config.max_prefixes;
        managed.transport_config.max_prefixes_ipv4 = config.max_prefixes_ipv4;
        managed.transport_config.max_prefixes_ipv6 = config.max_prefixes_ipv6;
        managed.transport_config.gr_stale_routes_time = config.gr_stale_routes_time;
        managed.transport_config.gr_peer_restart_time_max = config.gr_peer_restart_time_max;
        managed.transport_config.local_ipv6_nexthop = config.local_ipv6_nexthop;
        managed.transport_config.remove_private_as = config.remove_private_as;
        info!(%peer, "hot-applied neighbor config change in place (no session rebuild)");
        Ok(())
    }

    pub(super) async fn apply_peer_reshape_snapshot(
        &mut self,
        targets: Vec<PeerManagerNeighborConfig>,
    ) -> Result<Vec<PeerManagerNeighborConfig>, PeerLifecycleError> {
        let mut seen = BTreeSet::new();
        for target in &targets {
            let peer = PeerKey::new(target.address, target.interface.clone());
            if !seen.insert(peer.clone()) {
                return Err(PeerLifecycleError::Invalid(format!(
                    "peer reshape target {peer} appears more than once"
                )));
            }
            let managed = self
                .peers
                .get(&peer)
                .ok_or_else(|| PeerLifecycleError::NotFound(peer.clone()))?;
            if managed.transport_config.tcp_ao != target.tcp_ao {
                return Err(PeerLifecycleError::RestartRequired(format!(
                    "peer reshape target {peer} changes tcp_ao; TCP-AO changes require a daemon restart"
                )));
            }
            // Defense in depth: the transaction executor already gates dynamic
            // ranges out of reshape targets, but reconfigure's delete/re-add
            // semantics are wrong for an ephemeral dynamic peer (it would change
            // `is_dynamic` lifecycle/persistence), so refuse one here too.
            if managed.is_dynamic {
                return Err(PeerLifecycleError::Invalid(format!(
                    "peer reshape target {peer} is a dynamic peer; reshape transactions reconfigure static neighbors only"
                )));
            }
        }

        let mut priors = Vec::with_capacity(targets.len());
        for target in targets {
            let peer = PeerKey::new(target.address, target.interface.clone());
            match self.reconfigure_peer(target).await {
                Ok(previous) => priors.push(previous),
                Err(error) => {
                    return match self.restore_peer_reshape_priors(priors).await {
                        Ok(()) => Err(PeerLifecycleError::Internal(format!(
                            "failed to reconfigure peer {peer}: {error}; prior peers restored"
                        ))),
                        // The rollback error already names exactly which prior
                        // members were left reshaped (and notes the rest were
                        // restored), so compose it verbatim.
                        Err(restore_error) => Err(PeerLifecycleError::Internal(format!(
                            "failed to reconfigure peer {peer}: {error}; {restore_error}"
                        ))),
                    };
                }
            }
        }
        Ok(priors)
    }

    async fn restore_peer_reshape_priors(
        &mut self,
        priors: Vec<PeerManagerNeighborConfig>,
    ) -> Result<(), PeerLifecycleError> {
        // Replays the captured prior configs in reverse of the apply order.
        // `reconfigure_peer` re-reads the live enabled / graceful-shutdown state
        // and re-applies it, so rollback preserves the peer's current admin and
        // GShut state rather than resurrecting a stale transient toggle.
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
    /// sent a graceful stop (Cease NOTIFICATION carrying an RFC 8203
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
    pub(super) async fn bounce_dynamic_peers_for_ranges(
        &mut self,
        ranges: &[DynamicRangeTarget],
    ) -> DynamicPeerBounceOutcome {
        let mut outcome = DynamicPeerBounceOutcome::default();
        if ranges.is_empty() {
            return outcome;
        }

        let peer_groups: BTreeSet<_> = ranges
            .iter()
            .map(|range| range.peer_group.as_str())
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

        for peer_key in matched {
            let Some(managed) = self.peers.get(&peer_key) else {
                continue;
            };
            let reason = bytes::Bytes::from_static(b"peer-group configuration change");
            // Bounded send: the session command channel is small, so a
            // session task that has stopped draining commands would park
            // this whole post-persist sweep (and the peer-manager actor
            // behind it) on one wedged peer. The sweep is best-effort by
            // contract — a peer that can't be signaled keeps its running
            // config until it reconnects, same as a send error.
            let signaled = managed
                .handle
                .stop_timeout(Some(reason), PEER_LIFECYCLE_COMMAND_TIMEOUT)
                .await
                .map_err(|e| e.to_string());
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

    async fn restore_reconfigured_peer(
        &mut self,
        peer: PeerKey,
        previous: PeerManagerNeighborConfig,
        was_enabled: bool,
        graceful_shutdown: bool,
    ) -> Result<(), PeerLifecycleError> {
        if self.peers.contains_key(&peer) {
            self.delete_peer_checked(peer.clone(), false, previous.tcp_ao.as_ref(), false)
                .await?;
        }
        self.add_peer_with_admin_state(previous, false, was_enabled)
            .await?;
        self.apply_reconfigured_peer_state(peer, graceful_shutdown)
            .await
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
    ) -> Result<PeerManagerNeighborConfig, PeerLifecycleError> {
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

        // Linearize any terminal signal already emitted by this generation
        // before moving it out of the live ownership table.
        self.drain_ready_session_notifications().await;
        let mut managed = self
            .peers
            .remove(&peer)
            .ok_or_else(|| PeerLifecycleError::NotFound(peer.clone()))?;
        let removed_config = Self::removed_peer_config(&peer, &managed);
        let primary_session_id = managed.session_id;
        self.retiring_sessions
            .insert(primary_session_id, peer.clone());
        if let Some(pending) = managed.pending_inbound.take() {
            let _ = self
                .quiesce_retiring_session(
                    &peer,
                    pending.session_id,
                    pending.handle,
                    "delete pending inbound",
                    false,
                )
                .await;
        }

        let shutdown = self
            .quiesce_retiring_session(
                &peer,
                primary_session_id,
                managed.handle,
                "delete primary",
                false,
            )
            .await;
        if reap_metric_series {
            // A real operator deletion is authoritative even if the actor
            // crossed max-prefix while it was being joined. Reconfigure keeps
            // the latch for the replacement generation.
            self.remove_max_prefix_latch(&peer);
        }
        if shutdown.joined() {
            info!(%address, "peer deleted");
        }

        if sync_config_snapshot {
            apply_config_event(
                &mut self.current_config,
                &ConfigEvent::NeighborDeleted { peer, ack: None },
            )
            .map_err(|e| PeerLifecycleError::Invalid(e.to_string()))?;
        }

        // ADR-0067 step 4: drain the deleted peer's BFD session.
        self.set_bfd_peer_disabled(address, true);

        // Operator rule: reap per-peer runtime/state metrics for
        // *deleted* peers only — never on a session flap (the session
        // task records its final transitions before the shutdown join
        // above, so this runs after the last transport-side emission).
        if reap_metric_series && shutdown.joined() {
            self.reap_deleted_peer_metric_series(address, &managed.transport_config)
                .await;
        } else if reap_metric_series {
            warn!(
                %address,
                "skipping deleted-peer metric reap because session shutdown did not join before the deadline"
            );
        }
        Ok(removed_config)
    }

    /// Remove a deleted peer's per-peer metric series.
    ///
    /// Transport sessions label `peer` with the remote `SocketAddr`
    /// (`"10.0.0.2:179"`, `"[fe80::2%3]:179"`), while the RIB manager
    /// and BFD runtime label it with the bare address — reap both
    /// exact forms. Call only after the peer has been removed from
    /// `self.peers` and its session task joined.
    pub(super) async fn reap_deleted_peer_metric_series(
        &self,
        address: std::net::IpAddr,
        transport_config: &TransportConfig,
    ) {
        // The SocketAddr form is unique to this peer (same-address
        // link-local peers differ in scope id), so it is always safe.
        self.metrics
            .reap_peer_series(&transport_config.remote_addr.to_string());
        // The bare-address form can be shared with a surviving peer
        // (the same link-local address on another interface) — leave
        // it alone unless this peer was the last user of the address.
        if self.peer_keys_for_address(address).is_empty() {
            self.metrics.reap_peer_series(&address.to_string());
            // The RIB manager emits bare-address series from its own
            // task; this marker is queued behind the session's final
            // `PeerDown`, so the RIB manager reaps again *after* its
            // own teardown emissions instead of racing them. Send
            // failure means the RIB manager is gone (daemon shutdown).
            let _ = self
                .rib_tx
                .send(RibUpdate::PeerDeleted { peer: address })
                .await;
        }
    }

    pub(super) async fn enable_peer(&mut self, peer: PeerKey) -> Result<(), PeerLifecycleError> {
        let address = peer.address;
        // ADR-0067 step 4b: re-enabling a strict peer must re-apply the withhold
        // — start BGP only if BFD is already Up, else withhold until it is.
        // (A freshly-restarted BFD session begins Down with no transition, so an
        // unconditional start here would establish BGP with BFD down.)
        let withhold = self.bfd_should_withhold(&address);
        let Some(managed) = self.peers.get_mut(&peer) else {
            return Err(PeerLifecycleError::NotFound(peer));
        };
        if !withhold {
            managed
                .handle
                .start()
                .await
                .map_err(|e| PeerLifecycleError::Internal(format!("failed to start peer: {e}")))?;
        }
        // Enable is the sole recovery operation for a max-prefix shutdown.
        // Clear the manager-owned error only after the session accepted Start,
        // so a failed command cannot accidentally reopen passive acceptance.
        managed.enabled = true;
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
            info!(%address, "strict BFD — withholding BGP until BFD Up (re-enable)");
        }
        info!(%address, "peer enabled");
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
        let managed = self
            .peers
            .get_mut(&peer)
            .ok_or_else(|| PeerLifecycleError::NotFound(peer.clone()))?;
        managed
            .handle
            .stop_timeout(reason, PEER_LIFECYCLE_COMMAND_TIMEOUT)
            .await
            .map_err(|e| PeerLifecycleError::Internal(format!("failed to stop peer: {e}")))?;
        self.publish_peer_lifecycle_event(
            &peer,
            SessionLifecycleEventType::PeerDisabled,
            format!("peer {address} disabled"),
        );
        // ADR-0067 step 4: drain this peer's BFD session (published disabled).
        self.set_bfd_peer_disabled(address, true);
        info!(%address, "peer disabled");
        Ok(())
    }

    /// RFC 8326 graceful-shutdown initiator: toggle `GRACEFUL_SHUTDOWN`
    /// community attachment for one peer (`Some(addr)`) or every
    /// currently-managed peer (`None`).
    ///
    /// Three-step per-peer sequence so the toggle is observable on the
    /// wire AND survives session restart:
    ///
    /// 1. **Update desired state on `ManagedPeer`** — survives session
    ///    restart so a flap mid-maintenance doesn't silently drop the
    ///    toggle.
    /// 2. **Send the live-session command** — flips the per-session
    ///    bool; the next outbound advertise carries (or stops carrying)
    ///    the community.
    /// 3. **Issue `RibUpdate::RefreshPeerOutbound`** — forces re-emission
    ///    of routes already in `AdjRibOut` so the wire form updates
    ///    immediately. Without this, an operator running
    ///    `rbgp gshut` against an Established session with active
    ///    routes would see no change until something else triggered a
    ///    re-advertise.
    ///
    /// `Some(peer)` for a missing peer surfaces as `SetGshutError::PeerNotFound`
    /// so callers can distinguish that from a session/RIB failure.
    /// Per-peer dispatch failures aggregate into `Internal`. The
    /// authoritative state is updated even when the live-session
    /// command or refresh fails — the toggle takes effect on the next
    /// session spawn regardless.
    pub(super) async fn set_graceful_shutdown(
        &mut self,
        peer: Option<PeerKey>,
        enabled: bool,
    ) -> Result<(), SetGshutError> {
        let targets: Vec<PeerKey> = match peer {
            Some(peer) => {
                if !self.peers.contains_key(&peer) {
                    return Err(SetGshutError::PeerNotFound(peer));
                }
                vec![peer]
            }
            None => self.peers.keys().cloned().collect(),
        };

        let mut failures: Vec<String> = Vec::new();
        for peer in &targets {
            let addr = peer.address;
            // (1) Update authoritative state on ManagedPeer so it
            // survives session restart.
            if let Some(managed) = self.peers.get_mut(peer) {
                managed.advertise_graceful_shutdown = enabled;
            } else {
                // Peer disappeared between snapshot and dispatch; rare
                // (would require concurrent removal in this same
                // task). Skip silently.
                continue;
            }

            // (2) Tell the live session — best-effort. If the session
            // task is wedged or already restarting, the new session
            // will pick up the toggle from ManagedPeer at spawn time.
            if let Some(managed) = self.peers.get(peer)
                && let Err(e) = managed
                    .handle
                    .update_graceful_shutdown_timeout(enabled, PEER_POLICY_UPDATE_TIMEOUT)
                    .await
            {
                warn!(
                    %addr,
                    enabled,
                    error = %e,
                    "failed to toggle graceful-shutdown on live peer session — \
                     desired state stored, will apply on next session"
                );
                failures.push(format!("{addr}: session: {e}"));
                continue;
            }

            // (3) Force re-emission of already-advertised routes so
            // the toggle is visible on the wire without waiting for
            // an unrelated RIB event. RIB ignores peers not yet
            // registered for outbound (newly added, not Established
            // yet) — that's fine, the next PeerUp will emit fresh.
            let (reply_tx, reply_rx) = oneshot::channel();
            if let Err(e) = self
                .rib_tx
                .send(RibUpdate::RefreshPeerOutbound {
                    peer: addr,
                    reply: reply_tx,
                })
                .await
            {
                warn!(%addr, error = %e, "failed to send RIB refresh after gshut toggle");
                failures.push(format!("{addr}: rib send: {e}"));
                continue;
            }
            // Bounded: a wedged RIB task must not park the peer-manager
            // actor (and the SIGHUP reload driving this toggle) forever.
            match tokio::time::timeout(super::RIB_REPLY_TIMEOUT, reply_rx).await {
                Err(_) => {
                    warn!(%addr, "RIB did not reply to gshut refresh within deadline");
                    failures.push(format!(
                        "{addr}: rib reply timed out after {:?}",
                        super::RIB_REPLY_TIMEOUT
                    ));
                }
                Ok(Err(_)) => {
                    warn!(%addr, "RIB dropped reply for gshut refresh");
                    failures.push(format!("{addr}: rib reply dropped"));
                }
                Ok(Ok(Err(e))) => {
                    // "peer X not registered for outbound updates" is
                    // expected for peers not yet Established — log at
                    // debug, not as a failure.
                    debug!(
                        %addr, error = %e,
                        "RIB declined refresh (peer likely not yet Established) — \
                         desired state stored, will apply on next PeerUp"
                    );
                }
                Ok(Ok(Ok(()))) => {}
            }
        }

        if failures.is_empty() {
            info!(
                count = targets.len(),
                enabled, "RFC 8326 graceful-shutdown toggled on peer set"
            );
            Ok(())
        } else {
            Err(SetGshutError::Internal(format!(
                "graceful-shutdown toggle had failures on {} of {} peers (desired \
                 state stored regardless): {}",
                failures.len(),
                targets.len(),
                failures.join("; ")
            )))
        }
    }

    pub(super) async fn soft_reset_in(
        &self,
        peer: PeerKey,
        families: Vec<(Afi, Safi)>,
    ) -> Result<(), PeerLifecycleError> {
        let address = peer.address;
        let managed = self
            .peers
            .get(&peer)
            .ok_or_else(|| PeerLifecycleError::NotFound(peer.clone()))?;

        // Determine which families to request refresh for
        let target_families = if families.is_empty() {
            // All configured families for this peer
            managed.transport_config.peer.families.clone()
        } else {
            families
        };

        for (afi, safi) in &target_families {
            if let Err(e) = managed
                .handle
                .send_route_refresh_timeout(*afi, *safi, PEER_LIFECYCLE_COMMAND_TIMEOUT)
                .await
            {
                warn!(%address, error = %e, "failed to send route refresh");
                return Err(PeerLifecycleError::Internal(format!(
                    "send failed: route refresh to {address}: {e}"
                )));
            }
        }

        info!(%address, families = ?target_families, "soft reset in requested");
        Ok(())
    }
}
