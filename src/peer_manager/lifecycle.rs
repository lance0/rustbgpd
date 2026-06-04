use rustbgpd_api::peer_types::{
    ConfigEvent, PeerKey, PeerManagerNeighborConfig, SessionLifecycleEventType, SetGshutError,
};
use rustbgpd_rib::RibUpdate;
use rustbgpd_transport::{PeerHandle, SessionIdentity, TcpAoConfig};
use rustbgpd_wire::{Afi, Safi};
use tokio::sync::oneshot;
use tracing::{debug, error, info, warn};

use crate::policy_admin::apply_config_event;

use super::{ManagedPeer, PEER_POLICY_UPDATE_TIMEOUT, PeerManager};

impl PeerManager {
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
            max_prefixes: managed.max_prefixes,
            md5_password: tc.md5_password.clone(),
            tcp_ao: tc.tcp_ao.clone(),
            ttl_security: tc.ttl_security,
            families: tc.peer.families.clone(),
            graceful_restart: tc.peer.graceful_restart,
            gr_restart_time: tc.peer.gr_restart_time,
            gr_stale_routes_time: tc.gr_stale_routes_time,
            llgr_stale_time: tc.llgr_stale_time,
            // Runtime delete rollback re-adds through the still-original
            // config snapshot, so startup-only GR eligibility is re-resolved
            // there rather than reconstructed from the removed live peer.
            gr_restart_eligible: false,
            local_ipv6_nexthop: tc.local_ipv6_nexthop,
            route_reflector_client: tc.route_reflector_client,
            route_server_client: tc.route_server_client,
            remove_private_as: tc.remove_private_as,
            add_path_receive: tc.peer.add_path_receive,
            add_path_send: tc.peer.add_path_send,
            add_path_send_max: tc.peer.add_path_send_max,
            local_role: tc.peer.local_role,
            strict_role: tc.peer.strict_role,
            prefix_orf_receive: tc.peer.prefix_orf_receive,
            import_policy: managed.import_policy.clone(),
            export_policy: managed.export_policy.clone(),
        }
    }

    pub(super) async fn add_peer(
        &mut self,
        config: PeerManagerNeighborConfig,
        sync_config_snapshot: bool,
    ) -> Result<(), String> {
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
    ) -> Result<(), String> {
        let peer_key = PeerKey::new(config.address, config.interface.clone());
        let is_link_local = matches!(config.address, std::net::IpAddr::V6(v6) if v6.segments()[0] & 0xffc0 == 0xfe80);
        match (is_link_local, config.interface.as_ref()) {
            (true, None) => {
                return Err(format!(
                    "peer {peer_key} is IPv6 link-local and requires an interface"
                ));
            }
            (false, Some(_)) => {
                return Err(format!(
                    "peer {peer_key} has an interface but is not IPv6 link-local"
                ));
            }
            _ => {}
        }
        if self.peers.contains_key(&peer_key) {
            return Err(format!("peer {peer_key} already exists"));
        }
        if let Some(interface) = &config.interface
            && config.scope_id.is_none()
            && let Err(error) = nix::net::if_::if_nametoindex(interface.as_str())
        {
            return Err(format!(
                "peer {peer_key} interface {interface:?} cannot be resolved: {error}"
            ));
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
                .map_err(|e| e.to_string())?;
                let neighbor = next_config
                    .neighbors
                    .iter()
                    .find(|neighbor| {
                        neighbor.address == config.address.to_string()
                            && neighbor.interface == config.interface
                    })
                    .ok_or_else(|| {
                        format!("neighbor {peer_key} missing after config snapshot update")
                    })?;
                let resolved = next_config
                    .resolve_neighbor(neighbor)
                    .map_err(|e| e.to_string())?;
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
        let handle = PeerHandle::spawn_with_event_sink_and_identity_and_lifecycle(
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
        );

        // ADR-0067 step 4b — strict BFD: create/store the peer but withhold BGP
        // establishment until BFD is Up. Non-strict (the default) starts now
        // only when the peer is administratively enabled.
        // The handle is spawned Idle either way; `start()` is what begins the
        // FSM, so withholding is simply not sending it yet. Level-triggered: if
        // BFD already reached Up before this add (the actor starts sessions at
        // spawn), we do NOT withhold — start now, since no future transition
        // would release the hold.
        let withhold = enabled && self.bfd_should_withhold(&address);
        if enabled
            && !withhold
            && let Err(e) = handle.start().await
        {
            warn!(%address, error = %e, "failed to start peer session");
            return Err(format!("failed to start peer: {e}"));
        }

        info!(%address, %remote_asn, "peer added dynamically");
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
                transport_config: transport,
                import_policy,
                export_policy,
                pending_inbound: None,
                is_dynamic: false,
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
    ) -> Result<PeerManagerNeighborConfig, String> {
        self.delete_peer_checked(peer, sync_config_snapshot, None)
            .await
    }

    pub(super) async fn delete_peer_for_reconfigure(
        &mut self,
        peer: PeerKey,
        next_tcp_ao: Option<&TcpAoConfig>,
    ) -> Result<(), String> {
        self.delete_peer_checked(peer, false, next_tcp_ao)
            .await
            .map(|_| ())
    }

    pub(super) async fn reconfigure_peer(
        &mut self,
        config: PeerManagerNeighborConfig,
    ) -> Result<PeerManagerNeighborConfig, String> {
        let peer = PeerKey::new(config.address, config.interface.clone());
        let (was_enabled, graceful_shutdown) = self
            .peers
            .get(&peer)
            .map(|managed| (managed.enabled, managed.advertise_graceful_shutdown))
            .ok_or_else(|| format!("peer {peer} not found"))?;

        let previous = self
            .delete_peer_checked(peer.clone(), false, config.tcp_ao.as_ref())
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
                Ok(()) => Err(format!(
                    "failed to add reconfigured peer {peer}: {add_error}; previous peer restored"
                )),
                Err(restore_error) => Err(format!(
                    "failed to add reconfigured peer {peer}: {add_error}; restore previous peer failed: {restore_error}"
                )),
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
                Ok(()) => Err(format!(
                    "failed to restore runtime state for reconfigured peer {peer}: {state_error}; previous peer restored"
                )),
                Err(restore_error) => Err(format!(
                    "failed to restore runtime state for reconfigured peer {peer}: {state_error}; restore previous peer failed: {restore_error}"
                )),
            };
        }

        Ok(previous)
    }

    async fn restore_reconfigured_peer(
        &mut self,
        peer: PeerKey,
        previous: PeerManagerNeighborConfig,
        was_enabled: bool,
        graceful_shutdown: bool,
    ) -> Result<(), String> {
        if self.peers.contains_key(&peer) {
            self.delete_peer_checked(peer.clone(), false, previous.tcp_ao.as_ref())
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
    ) -> Result<(), String> {
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

    pub(super) async fn delete_peer_checked(
        &mut self,
        peer: PeerKey,
        sync_config_snapshot: bool,
        next_tcp_ao: Option<&TcpAoConfig>,
    ) -> Result<PeerManagerNeighborConfig, String> {
        let address = peer.address;
        let current_tcp_ao = self
            .peers
            .get(&peer)
            .and_then(|managed| managed.transport_config.tcp_ao.as_ref())
            .cloned();
        if current_tcp_ao
            .as_ref()
            .is_some_and(|current| next_tcp_ao != Some(current))
        {
            return Err(format!(
                "peer {address} uses TCP-AO; removing protected peers requires restart until listener MKT deletion is implemented"
            ));
        }

        let mut managed = self
            .peers
            .remove(&peer)
            .ok_or_else(|| format!("peer {peer} not found"))?;
        let removed_config = Self::removed_peer_config(&peer, &managed);
        self.unregister_session(managed.session_id);
        if let Some(pending) = managed.pending_inbound.take() {
            self.unregister_session(pending.session_id);
            let _ = pending.handle.shutdown().await;
        }

        match managed.handle.shutdown().await {
            Ok(Ok(())) => info!(%address, "peer deleted"),
            Ok(Err(e)) => warn!(%address, error = %e, "peer shutdown error during delete"),
            Err(e) => error!(%address, error = %e, "peer task join error during delete"),
        }

        if sync_config_snapshot {
            apply_config_event(
                &mut self.current_config,
                &ConfigEvent::NeighborDeleted { peer, ack: None },
            )
            .map_err(|e| e.to_string())?;
        }

        // ADR-0067 step 4: drain the deleted peer's BFD session.
        self.set_bfd_peer_disabled(address, true);
        Ok(removed_config)
    }

    pub(super) async fn enable_peer(&mut self, peer: PeerKey) -> Result<(), String> {
        let address = peer.address;
        if !self.peers.contains_key(&peer) {
            return Err(format!("peer {peer} not found"));
        }
        self.peers.get_mut(&peer).expect("peer present").enabled = true;
        // ADR-0067 step 4b: re-enabling a strict peer must re-apply the withhold
        // — start BGP only if BFD is already Up, else withhold until it is.
        // (A freshly-restarted BFD session begins Down with no transition, so an
        // unconditional start here would establish BGP with BFD down.)
        let withhold = self.bfd_should_withhold(&address);
        if !withhold {
            self.peers
                .get(&peer)
                .expect("peer present")
                .handle
                .start()
                .await
                .map_err(|e| format!("failed to start peer: {e}"))?;
        }
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
    ) -> Result<(), String> {
        let address = peer.address;
        let pending = {
            let managed = self
                .peers
                .get_mut(&peer)
                .ok_or_else(|| format!("peer {peer} not found"))?;
            managed.enabled = false;
            managed.pending_inbound.take()
        };
        if let Some(pending) = pending {
            self.unregister_session(pending.session_id);
            let _ = pending.handle.shutdown().await;
        }
        let managed = self
            .peers
            .get_mut(&peer)
            .ok_or_else(|| format!("peer {peer} not found"))?;
        managed
            .handle
            .stop(reason)
            .await
            .map_err(|e| format!("failed to stop peer: {e}"))?;
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
    ///    `rustbgpctl gshut` against an Established session with active
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
            match reply_rx.await {
                Err(_) => {
                    warn!(%addr, "RIB dropped reply for gshut refresh");
                    failures.push(format!("{addr}: rib reply dropped"));
                }
                Ok(Err(e)) => {
                    // "peer X not registered for outbound updates" is
                    // expected for peers not yet Established — log at
                    // debug, not as a failure.
                    debug!(
                        %addr, error = %e,
                        "RIB declined refresh (peer likely not yet Established) — \
                         desired state stored, will apply on next PeerUp"
                    );
                }
                Ok(Ok(())) => {}
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
    ) -> Result<(), String> {
        let address = peer.address;
        let managed = self
            .peers
            .get(&peer)
            .ok_or_else(|| format!("not found: peer {peer}"))?;

        // Determine which families to request refresh for
        let target_families = if families.is_empty() {
            // All configured families for this peer
            managed.transport_config.peer.families.clone()
        } else {
            families
        };

        for (afi, safi) in &target_families {
            if let Err(e) = managed.handle.send_route_refresh(*afi, *safi).await {
                warn!(%address, error = %e, "failed to send route refresh");
                return Err(format!("send failed: route refresh to {address}: {e}"));
            }
        }

        info!(%address, families = ?target_families, "soft reset in requested");
        Ok(())
    }
}
