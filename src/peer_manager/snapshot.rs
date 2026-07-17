use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use rustbgpd_api::peer_types::{PeerInfo, PeerKey, WarmCheckpointCapture, WarmCheckpointSession};
use rustbgpd_bmp::{BmpEvent, BmpPeerInfo, BmpPeerType};
use rustbgpd_fsm::SessionState;
use rustbgpd_transport::{PeerHandle, PeerSessionState};
use tracing::warn;

use super::{ManagedPeer, PEER_QUERY_TIMEOUT, PeerManager};

/// Build a `PeerInfo` snapshot from config + an optional fresh
/// `PeerSessionState`. `session_state = None` means the bounded
/// `query_state` either timed out (peer parked on TCP write) or its task
/// has already exited; in both cases we surface `state = Idle, stale =
/// true` so consumers know the field isn't authoritative.
pub(super) fn build_peer_info(
    peer: &PeerKey,
    managed: &ManagedPeer,
    session_state: Option<&PeerSessionState>,
) -> PeerInfo {
    let stale = session_state.is_none();
    let remote_asn = effective_remote_asn(managed, session_state);
    PeerInfo {
        address: peer.address,
        interface: peer.interface.clone(),
        remote_asn,
        description: managed.description.clone(),
        peer_group: managed.peer_group.clone(),
        state: session_state.map_or(SessionState::Idle, |s| s.fsm_state),
        enabled: managed.enabled,
        prefix_count: session_state.map_or(0, |s| s.prefix_count),
        hold_time: managed.hold_time,
        send_hold_time: managed.transport_config.peer.send_hold_time,
        max_prefixes: managed.max_prefixes,
        families: managed.transport_config.peer.families.clone(),
        remove_private_as: managed.transport_config.remove_private_as,
        route_server_client: managed.transport_config.route_server_client,
        per_client_best: managed.transport_config.per_client_best,
        local_role: managed.transport_config.peer.local_role,
        strict_role: managed.transport_config.peer.strict_role,
        remote_role: session_state.and_then(|s| s.remote_role),
        role_negotiated: session_state.is_some_and(|s| s.role_negotiated),
        add_path_receive: managed.transport_config.peer.add_path_receive,
        add_path_send: managed.transport_config.peer.add_path_send,
        add_path_send_max: managed.transport_config.peer.add_path_send_max,
        paths_limit_receive_max: managed.transport_config.peer.paths_limit_receive_max,
        peer_paths_limits: session_state
            .map(|state| state.peer_paths_limits.clone())
            .unwrap_or_default(),
        effective_add_path_send_limits: session_state
            .map(|state| state.effective_add_path_send_limits.clone())
            .unwrap_or_default(),
        updates_received: session_state.map_or(0, |s| s.updates_received),
        updates_sent: session_state.map_or(0, |s| s.updates_sent),
        notifications_received: session_state.map_or(0, |s| s.notifications_received),
        notifications_sent: session_state.map_or(0, |s| s.notifications_sent),
        messages_received: session_state.map_or(0, |s| s.messages_received),
        messages_sent: session_state.map_or(0, |s| s.messages_sent),
        route_reflector_client: managed.transport_config.route_reflector_client,
        otc_routes_blocked: session_state.map_or(0, |s| s.otc_routes_blocked),
        import_policy_routes_permitted: session_state
            .map_or(0, |s| s.import_policy_routes_permitted),
        import_policy_routes_denied: session_state.map_or(0, |s| s.import_policy_routes_denied),
        export_policy_routes_permitted: 0,
        export_policy_routes_denied: 0,
        flap_count: session_state.map_or(0, |s| s.flap_count),
        uptime_secs: session_state.map_or(0, |s| s.uptime_secs),
        last_error: session_state.map_or_else(String::new, |s| s.last_error.clone()),
        authentication: if session_state
            .map_or(managed.tcp_ao_protected, |state| state.tcp_ao_protected)
        {
            "tcp_ao"
        } else if managed.transport_config.md5_password.is_some() {
            "md5"
        } else {
            "plaintext"
        }
        .to_string(),
        tcp_ao_info: session_state.and_then(|s| s.tcp_ao_info.as_deref().cloned()),
        tcp_ao_rotation: managed.tcp_ao_rotation.clone(),
        is_dynamic: managed.is_dynamic,
        stale,
        slow_peer: session_state.is_some_and(|s| s.slow_peer),
    }
}

fn effective_remote_asn(managed: &ManagedPeer, session_state: Option<&PeerSessionState>) -> u32 {
    session_state
        .and_then(|s| s.peer_asn)
        .filter(|asn| *asn != 0)
        .unwrap_or(managed.remote_asn)
}

/// Run a bounded `query_state` against every peer concurrently.
///
/// Each query is bounded by [`PEER_QUERY_TIMEOUT`]; a peer whose session
/// task is parked on TCP write (or whose command channel is full) lands
/// in the result map as `Some(addr) -> None`. A peer whose task spawn
/// failed entirely is absent from the map. Both cases are treated as
/// `stale = true` by [`build_peer_info`].
async fn collect_session_states(
    peers: &HashMap<PeerKey, ManagedPeer>,
) -> HashMap<PeerKey, Option<PeerSessionState>> {
    let mut tasks: Vec<tokio::task::JoinHandle<(PeerKey, Option<PeerSessionState>)>> =
        Vec::with_capacity(peers.len());
    for (peer, managed) in peers {
        let peer = peer.clone();
        let commands = managed.handle.commands_sender();
        tasks.push(tokio::spawn(async move {
            let state = PeerHandle::query_state_with(commands, PEER_QUERY_TIMEOUT).await;
            (peer, state)
        }));
    }

    let mut out = HashMap::with_capacity(tasks.len());
    for task in tasks {
        match task.await {
            Ok((addr, state)) => {
                out.insert(addr, state);
            }
            Err(e) => {
                warn!(error = %e, "query_state task join failed");
            }
        }
    }
    out
}

impl PeerManager {
    /// Capture negotiated truth for every V1 checkpoint candidate.
    ///
    /// Static, enabled, numbered, unambiguous peers are queried concurrently.
    /// A timeout or collision candidate rejects the complete checkpoint rather
    /// than publishing a partial identity inventory. Sessions that are not
    /// currently Established with negotiated GR are simply ineligible: their
    /// routes are excluded by the following RIB-actor query.
    #[expect(
        clippy::too_many_lines,
        reason = "one blocked peer-manager turn binds live config, policy, and every bounded session query"
    )]
    pub(super) async fn query_warm_checkpoint_capture(
        &self,
    ) -> Result<WarmCheckpointCapture, String> {
        // Capture config identity before awaiting session actors. The peer
        // manager remains inside this one command while those queries run, so
        // no reload/config transaction can advance `current_config` or the
        // resolved policies paired with the returned session generations.
        let desired_local_asn = self.current_config.global.asn;
        let desired_local_router_id = self
            .current_config
            .global
            .router_id
            .parse::<Ipv4Addr>()
            .map_err(|error| format!("invalid live router ID during warm checkpoint: {error}"))?;
        // ASN/router-ID changes are restart-required: `current_config` can
        // legitimately contain the accepted desired values while the running
        // listener and every live session still use these immutable fields.
        // A checkpoint digest must never claim the desired identity describes
        // the captured live routes. Fail closed until the restart applies it.
        if desired_local_asn != self.local_asn || desired_local_router_id != self.router_id {
            return Err(format!(
                "restart-required local identity differs from the live daemon during warm checkpoint (desired ASN/router-ID {desired_local_asn}/{desired_local_router_id}, live {}/{})",
                self.local_asn, self.router_id
            ));
        }
        let effective_config_toml = self.current_config.effective_redacted_toml()?;
        let local_asn = self.local_asn;
        let local_router_id = self.router_id;
        let restart_time_secs = self
            .current_config
            .resolved_neighbors()
            .map_err(|error| {
                format!("failed to resolve current neighbors for warm checkpoint: {error}")
            })?
            .iter()
            .filter(|neighbor| neighbor.transport_config.peer.graceful_restart)
            .map(|neighbor| u64::from(neighbor.transport_config.peer.gr_restart_time))
            .filter(|seconds| *seconds > 0)
            .max();
        let mut address_counts = HashMap::<IpAddr, usize>::new();
        for (peer, managed) in &self.peers {
            if !managed.is_dynamic {
                *address_counts.entry(peer.address).or_default() += 1;
            }
        }

        let mut tasks = Vec::new();
        for (peer, managed) in &self.peers {
            if managed.is_dynamic
                || !managed.enabled
                || peer.interface.is_some()
                || address_counts.get(&peer.address).copied() != Some(1)
                || !managed.transport_config.peer.graceful_restart
            {
                continue;
            }
            if managed.pending_inbound.is_some() {
                return Err(format!(
                    "peer {peer} has an unresolved collision candidate during checkpoint"
                ));
            }
            let canonical_import_policy = match managed.import_policy.as_ref() {
                Some(policy) => match policy.warm_checkpoint_identity_v1() {
                    Ok(identity) => identity,
                    Err(reason) => {
                        warn!(peer = %peer, reason, "excluding peer from V1 warm checkpoint");
                        continue;
                    }
                },
                None => b"rustbgpd/policy-chain/warm-checkpoint/v1/implicit-permit\n".to_vec(),
            };
            let peer = peer.clone();
            let session_id = managed.session_id;
            let commands = managed.handle.commands_sender();
            tasks.push(tokio::spawn(async move {
                let state =
                    PeerHandle::query_warm_checkpoint_state_with(commands, PEER_QUERY_TIMEOUT)
                        .await;
                (peer, session_id, canonical_import_policy, state)
            }));
        }

        let mut sessions = Vec::with_capacity(tasks.len());
        for task in tasks {
            let (peer, session_id, canonical_import_policy, state) = task
                .await
                .map_err(|error| format!("warm checkpoint session query task failed: {error}"))?;
            let state = state.ok_or_else(|| {
                format!("peer {peer} did not answer the bounded checkpoint query")
            })?;
            if state.fsm_state != SessionState::Established
                || !state.peer_gr_capable
                || state.peer_gr_restart_time == 0
                || state.peer_gr_families.is_empty()
            {
                continue;
            }
            let peer_asn = state
                .peer_asn
                .filter(|asn| *asn != 0)
                .ok_or_else(|| format!("Established peer {peer} has no negotiated remote ASN"))?;
            let peer_router_id = state
                .peer_router_id
                .filter(|router_id| !router_id.is_unspecified())
                .ok_or_else(|| {
                    format!("Established peer {peer} has no negotiated BGP identifier")
                })?;
            sessions.push(WarmCheckpointSession {
                peer,
                session_id,
                peer_asn,
                peer_router_id,
                negotiated_families: state.negotiated_families,
                peer_gr_families: state.peer_gr_families,
                add_path_receive_families: state.add_path_receive_families,
                canonical_import_policy,
            });
        }
        sessions.sort_by(|left, right| left.peer.cmp(&right.peer));
        Ok(WarmCheckpointCapture {
            local_asn,
            local_router_id,
            effective_config_toml,
            restart_time_secs,
            sessions,
        })
    }

    pub(super) async fn get_peer_info(&self, peer: &PeerKey) -> Option<PeerInfo> {
        let managed = self.peers.get(peer)?;
        let session_state = managed.handle.query_state_timeout(PEER_QUERY_TIMEOUT).await;
        Some(build_peer_info(peer, managed, session_state.as_ref()))
    }

    pub(super) async fn list_peers(&self) -> Vec<PeerInfo> {
        // Concurrent fan-out: one bounded `query_state` per peer in parallel.
        // Sequential `.await` per peer was the GetHealth wedge — a session
        // task parked on TCP write back-pressure couldn't service its
        // QueryState command, and the loop hung on the first such peer.
        // Spawning per-peer tasks needs `'static` futures, so we drive the
        // query through `PeerHandle::query_state_with` over a cloned command
        // sender (the sender is `Clone`; the handle proper is not).
        let states = collect_session_states(&self.peers).await;

        let mut infos = Vec::with_capacity(self.peers.len());
        for (peer, managed) in &self.peers {
            let session_state = states.get(peer).and_then(Option::as_ref);
            infos.push(build_peer_info(peer, managed, session_state));
        }
        infos
    }

    fn bmp_peer_info(
        peer_addr: IpAddr,
        remote_asn: u32,
        remote_router_id: Option<Ipv4Addr>,
        four_octet_as: Option<bool>,
    ) -> BmpPeerInfo {
        BmpPeerInfo {
            peer_addr,
            peer_asn: remote_asn,
            peer_bgp_id: remote_router_id.unwrap_or(Ipv4Addr::UNSPECIFIED),
            peer_type: BmpPeerType::Global,
            is_ipv6: peer_addr.is_ipv6(),
            is_post_policy: false,
            is_rib_out: false,
            is_as4: four_octet_as.unwrap_or(true),
            timestamp: std::time::SystemTime::now(),
        }
    }

    /// One bounded RIB query for every peer's post-policy Adj-RIB-Out
    /// counts per AFI/SAFI (RFC 8671 BMP stat types 15/17). `None` when
    /// the RIB manager is unavailable or slow — the stats report then
    /// omits types 15/17 rather than reporting a false zero.
    async fn query_adj_rib_out_counts(&self) -> Option<rustbgpd_rib::AdjRibOutCounts> {
        let (reply, rx) = tokio::sync::oneshot::channel();
        self.rib_tx
            .send(rustbgpd_rib::RibUpdate::QueryAdjRibOutCounts { reply })
            .await
            .ok()?;
        tokio::time::timeout(PEER_QUERY_TIMEOUT, rx)
            .await
            .ok()?
            .ok()
    }

    /// RFC 9069 Loc-RIB stats (types 8 + 10) for the emulated Loc-RIB
    /// instance peer, emitted on the same periodic tick as the per-peer
    /// stats. Skipped entirely unless some collector monitors `loc_rib`.
    async fn emit_loc_rib_bmp_stats(&self, bmp_tx: &tokio::sync::mpsc::Sender<BmpEvent>) {
        let monitored = self.current_config.bmp.as_ref().is_some_and(|bmp| {
            bmp.collectors.iter().any(|collector| {
                collector
                    .monitor
                    .contains(&crate::config::BmpMonitorView::LocRib)
            })
        });
        if !monitored {
            return;
        }
        let (reply, rx) = tokio::sync::oneshot::channel();
        if self
            .rib_tx
            .send(rustbgpd_rib::RibUpdate::QueryBmpLocRibStats { reply })
            .await
            .is_err()
        {
            return;
        }
        let Ok(Ok(per_family)) = tokio::time::timeout(PEER_QUERY_TIMEOUT, rx).await else {
            // Unavailable this tick — omit rather than report a false zero.
            return;
        };
        if let Err(e) = bmp_tx.try_send(BmpEvent::LocRibStats { per_family }) {
            warn!(
                error = %e,
                "BMP event channel full or closed, dropping periodic Loc-RIB stats report"
            );
        }
    }

    pub(super) async fn emit_periodic_bmp_stats(&self) {
        let Some(ref bmp_tx) = self.bmp_tx else {
            return;
        };

        // Same fan-out pattern as `list_peers` — sequential awaits would let
        // any one TCP-back-pressured peer block the per-minute BMP tick and,
        // through it, every other admin command queued behind the BMP arm.
        let states = collect_session_states(&self.peers).await;
        let rib_out_counts = self.query_adj_rib_out_counts().await;
        self.emit_loc_rib_bmp_stats(bmp_tx).await;
        for (peer, managed) in &self.peers {
            let peer_addr = peer.address;
            let Some(Some(state)) = states.get(peer) else {
                continue;
            };
            if state.fsm_state != SessionState::Established {
                continue;
            }

            let prefix_count = u64::try_from(state.prefix_count).unwrap_or(u64::MAX);
            let remote_asn = effective_remote_asn(managed, Some(state));
            // RFC 8671 types 15/17: a peer absent from the RIB's
            // Adj-RIB-Out map simply has nothing advertised — report
            // an honest empty set (type 15 = 0) rather than omitting.
            let adj_rib_out_post = rib_out_counts.as_ref().map(|counts| {
                counts
                    .get(&peer_addr)
                    .map(|families| {
                        families
                            .iter()
                            .map(|&((afi, safi), count)| (afi as u16, safi as u8, count))
                            .collect()
                    })
                    .unwrap_or_default()
            });
            let event = BmpEvent::StatsReport {
                peer_info: Self::bmp_peer_info(
                    peer_addr,
                    remote_asn,
                    state.remote_router_id,
                    state.four_octet_as,
                ),
                adj_rib_in_routes: prefix_count,
                adj_rib_out_post,
            };

            if let Err(e) = bmp_tx.try_send(event) {
                warn!(
                    peer = %peer_addr,
                    error = %e,
                    "BMP event channel full or closed, dropping periodic stats report"
                );
            }
        }
    }
}
