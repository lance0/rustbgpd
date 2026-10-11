use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use rustbgpd_api::peer_types::{
    DynamicRangeTarget, PeerInfo, PeerKey, Rfc8212PolicyStatus, WarmCheckpointCapture,
    WarmCheckpointSession,
};
use rustbgpd_bmp::{BmpEvent, BmpPeerInfo, BmpPeerType};
use rustbgpd_fsm::SessionState;
use rustbgpd_policy::PolicyChain;
use rustbgpd_transport::{PeerCommand, PeerHandle, PeerSessionState, StateQueryOutcome};
use rustbgpd_wire::{Afi, Safi};
use tokio::sync::{mpsc, oneshot};
use tokio_util::task::AbortOnDropHandle;
use tracing::warn;

use crate::config::{RFC8212_MISSING_EXPORT_POLICY, RFC8212_MISSING_IMPORT_POLICY};

use super::ManagedPeerState;
use super::{PEER_QUERY_TIMEOUT, PeerManager, PeerTable};

fn accepted_dynamic_range_snapshot(managed: &ManagedPeerState) -> Option<DynamicRangeTarget> {
    managed
        .accepted_dynamic_range
        .as_ref()
        .map(|range| DynamicRangeTarget {
            addr: range.addr,
            prefix_len: range.prefix_len,
            peer_group: range.peer_group.clone(),
        })
}

fn authentication_label(tcp_ao_protected: bool, md5_configured: bool) -> &'static str {
    if tcp_ao_protected {
        "tcp_ao"
    } else if md5_configured {
        "md5"
    } else {
        "plaintext"
    }
}

pub(super) fn rfc9972_adj_rib_in_counts(state: &PeerSessionState) -> Option<Vec<(u16, u8, u64)>> {
    let session = state.negotiated_session.as_ref()?;
    if session
        .add_path_receive_families
        .iter()
        .any(|family| matches!(family, (Afi::Ipv4 | Afi::Ipv6, Safi::Unicast)))
    {
        return None;
    }
    let mut counts = Vec::new();
    if session.families.contains(&(Afi::Ipv4, Safi::Unicast)) {
        counts.push((
            Afi::Ipv4 as u16,
            Safi::Unicast as u8,
            u64::try_from(state.max_prefix.prefix_count_ipv4).unwrap_or(u64::MAX),
        ));
    }
    if session.families.contains(&(Afi::Ipv6, Safi::Unicast)) {
        counts.push((
            Afi::Ipv6 as u16,
            Safi::Unicast as u8,
            u64::try_from(state.max_prefix.prefix_count_ipv6).unwrap_or(u64::MAX),
        ));
    }
    (!counts.is_empty()).then_some(counts)
}

pub(super) fn rfc9972_policy_reject_counts(
    state: &PeerSessionState,
) -> Option<Vec<(u16, u8, u64)>> {
    let session = state.negotiated_session.as_ref()?;
    let policy_rejects = state.policy_reject_counts?;
    let mut counts = Vec::new();
    if session.families.contains(&(Afi::Ipv4, Safi::Unicast)) {
        counts.push((
            Afi::Ipv4 as u16,
            Safi::Unicast as u8,
            policy_rejects.ipv4_unicast,
        ));
    }
    if session.families.contains(&(Afi::Ipv6, Safi::Unicast)) {
        counts.push((
            Afi::Ipv6 as u16,
            Safi::Unicast as u8,
            policy_rejects.ipv6_unicast,
        ));
    }
    (!counts.is_empty()).then_some(counts)
}

pub(super) fn rfc9972_rpki_validation_counts(
    peer: IpAddr,
    state: &PeerSessionState,
    counts: Option<&rustbgpd_rib::AdjRibInRpkiCounts>,
) -> Option<Vec<(u16, u8, rustbgpd_bmp::BmpRpkiValidationCounts)>> {
    let session = state.negotiated_session.as_ref()?;
    let counts = counts?;
    let peer_counts = counts.get(&peer);
    let mut projected = Vec::with_capacity(2);
    for (afi, safi) in [(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)] {
        if !session.families.contains(&(afi, safi)) {
            continue;
        }
        let exact = peer_counts
            .and_then(|families| {
                families.iter().find_map(|&((row_afi, row_safi), counts)| {
                    (row_afi == afi && row_safi == safi).then_some(counts)
                })
            })
            .unwrap_or_default();
        projected.push((
            afi as u16,
            safi as u8,
            rustbgpd_bmp::BmpRpkiValidationCounts {
                invalid: exact.invalid,
                valid: exact.valid,
                not_found: exact.not_found,
            },
        ));
    }
    (!projected.is_empty()).then_some(projected)
}

/// Build a `PeerInfo` snapshot from config + an optional fresh
/// `PeerSessionState`. `session_state = None` means the bounded
/// `query_state` either timed out (peer parked on TCP write) or its task
/// has already exited; in both cases we surface `state = Idle, stale =
/// true` so consumers know the field isn't authoritative.
/// One `inbound_prefix_limits[]` row per finite bound (ADR-0108 amendment).
fn inbound_prefix_limit_rows(
    state: &PeerSessionState,
) -> Vec<rustbgpd_api::peer_types::InboundPrefixLimitState> {
    state
        .max_prefix
        .scopes
        .iter()
        .map(|row| rustbgpd_api::peer_types::InboundPrefixLimitState {
            scope: row.scope.to_string(),
            usage: u64::try_from(row.usage).unwrap_or(u64::MAX),
            limit: row.limit,
            headroom: row.headroom,
            blocking: row.blocking,
        })
        .collect()
}

pub(super) fn build_peer_info(
    peer: &PeerKey,
    managed: &ManagedPeerState,
    session_state: Option<&PeerSessionState>,
    ebgp_requires_policy: bool,
) -> PeerInfo {
    let mut info = manager_peer_info(peer, managed, ebgp_requires_policy);
    if let Some(state) = session_state {
        apply_session_state(
            &mut info,
            managed.transport_config.md5_password.is_some(),
            state,
        );
    }
    info
}

/// The manager half of one neighbor row: every field the manager owns, with
/// the stale placeholders a missing session observation reports.
fn manager_peer_info(
    peer: &PeerKey,
    managed: &ManagedPeerState,
    ebgp_requires_policy: bool,
) -> PeerInfo {
    let (rfc8212_import_policy, rfc8212_export_policy) =
        rfc8212_statuses(managed, ebgp_requires_policy);
    PeerInfo {
        address: peer.address,
        interface: peer.interface.clone(),
        remote_asn: managed.remote_asn,
        description: managed.description.clone(),
        peer_group: managed.peer_group.clone(),
        state: SessionState::Idle,
        enabled: managed.enabled,
        graceful_shutdown_advertise_intent: managed.advertise_graceful_shutdown,
        prefix_count: 0,
        rejected_routes_retained: None,
        prefix_count_ipv4: 0,
        prefix_count_ipv6: 0,
        max_prefixes_effective: managed.max_prefixes,
        max_prefixes_ipv4_effective: managed.transport_config.max_prefixes_ipv4,
        max_prefixes_ipv6_effective: managed.transport_config.max_prefixes_ipv6,
        max_prefix_headroom: None,
        max_prefix_headroom_ipv4: None,
        max_prefix_headroom_ipv6: None,
        inbound_prefix_limits: Vec::new(),
        hold_time: managed.hold_time,
        min_hold_time: managed.transport_config.peer.min_hold_time,
        send_hold_time: managed.transport_config.peer.send_hold_time,
        max_prefixes: managed.max_prefixes,
        max_prefix_action: match managed.transport_config.max_prefix_action {
            rustbgpd_transport::MaxPrefixAction::Shutdown
                if managed.max_prefix_restart_seconds.is_some() =>
            {
                "restart"
            }
            action => action.as_str(),
        }
        .to_string(),
        max_prefix_restart_seconds: managed.max_prefix_restart_seconds,
        max_prefix_restart_remaining_millis: None,
        families: managed.transport_config.peer.families.clone(),
        required_families: managed.transport_config.peer.required_families.clone(),
        negotiated_session: None,
        remove_private_as: managed.transport_config.remove_private_as,
        discard_path_attributes: managed.transport_config.discard_path_attributes.clone(),
        route_server_client: managed.transport_config.route_server_client,
        per_client_best: managed.transport_config.per_client_best,
        next_hop_ownership_strict_peer: managed.transport_config.next_hop_ownership_strict_peer,
        interpret_rfc1997: managed.transport_config.interpret_rfc1997,
        rs_control_communities: managed.transport_config.rs_control_communities,
        orr_vantage: managed.transport_config.orr_vantage,
        local_role: managed.transport_config.peer.local_role,
        strict_role: managed.transport_config.peer.strict_role,
        remote_role: None,
        role_negotiated: false,
        add_path_receive: managed.transport_config.peer.add_path_receive,
        add_path_send: managed.transport_config.peer.add_path_send,
        add_path_send_max: managed.transport_config.peer.add_path_send_max,
        paths_limit_receive_max: managed.transport_config.peer.paths_limit_receive_max,
        peer_paths_limits: Vec::new(),
        effective_add_path_send_limits: Vec::new(),
        updates_received: 0,
        updates_sent: 0,
        notifications_received: 0,
        notifications_sent: 0,
        messages_received: 0,
        messages_sent: 0,
        route_reflector_client: managed.transport_config.route_reflector_client,
        otc_routes_blocked: 0,
        import_policy_routes_permitted: 0,
        import_policy_routes_denied: 0,
        export_policy_routes_permitted: 0,
        export_policy_routes_denied: 0,
        flap_count: 0,
        uptime_secs: 0,
        reconnect_in_secs: 0,
        last_error: String::new(),
        authentication: authentication_label(
            managed.tcp_ao_protected,
            managed.transport_config.md5_password.is_some(),
        )
        .to_string(),
        tcp_ao_info: None,
        tcp_ao_rotation: managed.tcp_ao_rotation.clone(),
        is_dynamic: managed.is_dynamic,
        accepted_dynamic_range: accepted_dynamic_range_snapshot(managed),
        stale: true,
        slow_peer: false,
        rfc8212_import_policy,
        rfc8212_export_policy,
    }
}

/// Overlay one live session observation on its manager half. `md5_configured`
/// is the manager's authentication fallback when the session is not TCP-AO.
fn apply_session_state(info: &mut PeerInfo, md5_configured: bool, state: &PeerSessionState) {
    if let Some(asn) = state.peer_asn.filter(|asn| *asn != 0) {
        info.remote_asn = asn;
    }
    info.state = state.fsm_state;
    info.prefix_count = state.prefix_count;
    info.rejected_routes_retained = Some(state.rejected_routes_retained);
    info.prefix_count_ipv4 = state.max_prefix.prefix_count_ipv4;
    info.prefix_count_ipv6 = state.max_prefix.prefix_count_ipv6;
    info.max_prefixes_effective = state.max_prefix.max_prefixes;
    info.max_prefixes_ipv4_effective = state.max_prefix.max_prefixes_ipv4;
    info.max_prefixes_ipv6_effective = state.max_prefix.max_prefixes_ipv6;
    info.max_prefix_headroom = state.max_prefix.headroom;
    info.max_prefix_headroom_ipv4 = state.max_prefix.headroom_ipv4;
    info.max_prefix_headroom_ipv6 = state.max_prefix.headroom_ipv6;
    info.inbound_prefix_limits = inbound_prefix_limit_rows(state);
    info.negotiated_session
        .clone_from(&state.negotiated_session);
    info.remote_role = state.remote_role;
    info.role_negotiated = state.role_negotiated;
    info.peer_paths_limits.clone_from(&state.peer_paths_limits);
    info.effective_add_path_send_limits
        .clone_from(&state.effective_add_path_send_limits);
    info.updates_received = state.updates_received;
    info.updates_sent = state.updates_sent;
    info.notifications_received = state.notifications_received;
    info.notifications_sent = state.notifications_sent;
    info.messages_received = state.messages_received;
    info.messages_sent = state.messages_sent;
    info.otc_routes_blocked = state.otc_routes_blocked;
    info.import_policy_routes_permitted = state.import_policy_routes_permitted;
    info.import_policy_routes_denied = state.import_policy_routes_denied;
    info.flap_count = state.flap_count;
    info.uptime_secs = state.uptime_secs;
    info.reconnect_in_secs = state.reconnect_in_secs;
    info.last_error.clone_from(&state.last_error);
    info.authentication = authentication_label(state.tcp_ao_protected, md5_configured).to_string();
    info.tcp_ao_info = state.tcp_ao_info.as_deref().cloned();
    info.stale = false;
    info.slow_peer = state.slow_peer;
}

/// A manager-owned max-prefix latch overrides the session's error and action.
/// The remaining hold-down is computed when the row is completed.
fn apply_max_prefix_latch(
    info: &mut PeerInfo,
    error: &str,
    deadline: Option<tokio::time::Instant>,
) {
    error.clone_into(&mut info.last_error);
    info.max_prefix_action = if deadline.is_some() {
        "restart"
    } else {
        "shutdown"
    }
    .to_string();
    info.max_prefix_restart_remaining_millis = deadline.map(|deadline| {
        deadline
            .saturating_duration_since(tokio::time::Instant::now())
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    });
}

/// One neighbor row captured when a transaction wait admits `ListPeers`,
/// and the reply of the session query enqueued at that instant.
struct DetachedPeerRow {
    info: PeerInfo,
    md5_configured: bool,
    latch: Option<(String, Option<tokio::time::Instant>)>,
    /// `None` when the session's command channel had already closed.
    state: Option<oneshot::Receiver<PeerSessionState>>,
}

/// Join one detached neighbor snapshot (ADR-0132, 2026-10-10 amendment).
/// Every query was enqueued at admission, so waiting for each reply in turn
/// under one absolute deadline waits for them concurrently. Caller
/// cancellation drops the receivers, which marks the queued reads canceled.
async fn complete_detached_list_peers(
    rows: Vec<DetachedPeerRow>,
    mut reply: oneshot::Sender<Vec<PeerInfo>>,
    deadline: tokio::time::Instant,
) {
    let collect = async move {
        let mut infos = Vec::with_capacity(rows.len());
        for row in rows {
            let DetachedPeerRow {
                mut info,
                md5_configured,
                latch,
                state,
            } = row;
            if let Some(state) = state
                && let Ok(Ok(state)) = tokio::time::timeout_at(deadline, state).await
            {
                apply_session_state(&mut info, md5_configured, &state);
            }
            if let Some((error, deadline)) = &latch {
                apply_max_prefix_latch(&mut info, error, *deadline);
            }
            infos.push(info);
        }
        infos
    };
    let infos = tokio::select! {
        biased;
        () = reply.closed() => return,
        infos = collect => infos,
    };
    let _ = reply.send(infos);
}

/// ADR-0112 directional status for both of one peer's directions.
///
/// The single funnel for every consumer — neighbor detail, JSON, and the
/// per-peer gauges all go through here, so none of them can report a verdict
/// the others do not.
pub(super) fn rfc8212_statuses(
    managed: &ManagedPeerState,
    ebgp_requires_policy: bool,
) -> (Rfc8212PolicyStatus, Rfc8212PolicyStatus) {
    let enforced = ebgp_requires_policy && managed.rfc8212_external;
    (
        rfc8212_status(
            enforced,
            managed.import_policy.as_ref(),
            RFC8212_MISSING_IMPORT_POLICY,
        ),
        rfc8212_status(
            enforced,
            managed.export_policy.as_ref(),
            RFC8212_MISSING_EXPORT_POLICY,
        ),
    )
}

/// ADR-0112 directional status for one direction of one peer.
///
/// `chain` must be the chain this peer currently has *installed* —
/// `ManagedPeer::import_policy` / `::export_policy`, which only advance after
/// the session task acknowledges the swap and stay at the prior value through
/// every bail and rollback. Everything the surface reports is read from there,
/// so it agrees with what the session is evaluating by construction rather
/// than by a second bookkeeping path staying in step.
///
/// The reserved-deny test runs first and unconditionally. If the two inputs
/// ever disagreed — a deny installed on a peer no longer believed enforced —
/// the honest answer is the one the routes obey.
pub(super) fn rfc8212_status(
    enforced: bool,
    chain: Option<&PolicyChain>,
    reserved_name: &str,
) -> Rfc8212PolicyStatus {
    if crate::config::is_reserved_rfc8212_deny(chain, reserved_name) {
        Rfc8212PolicyStatus::Missing
    } else if !enforced {
        Rfc8212PolicyStatus::NotRequired
    } else if chain.is_some() {
        Rfc8212PolicyStatus::Present
    } else {
        // A governed direction resolves to either an explicit operator chain
        // or the reserved deny, so a governed direction with no chain at all
        // is an unreachable state. Report it as unknown rather than calling
        // `evaluate_chain(None, ..)` permit-all "present": a false green here
        // would say the requirement is met on a direction with no policy at
        // all, which is the failure this feature exists to prevent.
        Rfc8212PolicyStatus::Unknown
    }
}

fn effective_remote_asn(
    managed: &ManagedPeerState,
    session_state: Option<&PeerSessionState>,
) -> u32 {
    session_state
        .and_then(|s| s.peer_asn)
        .filter(|asn| *asn != 0)
        .unwrap_or(managed.remote_asn)
}

/// Run a bounded state query against every peer concurrently.
///
/// Each query is bounded by [`PEER_QUERY_TIMEOUT`]; a peer whose session
/// task is parked on TCP write (or whose command channel is full) lands as
/// [`StateQueryOutcome::TimedOut`], while a closed session task lands as
/// [`StateQueryOutcome::SessionGone`]. A peer whose query task fails to join
/// is absent from the map. Every non-state outcome is treated as `stale =
/// true` by [`build_peer_info`].
async fn collect_session_states(peers: &PeerTable) -> HashMap<PeerKey, StateQueryOutcome> {
    let mut tasks = Vec::with_capacity(peers.len());
    for (peer, managed) in peers {
        let peer = peer.clone();
        let commands = managed.handle().commands_sender();
        tasks.push(AbortOnDropHandle::new(tokio::spawn(async move {
            let outcome = PeerHandle::query_state_outcome_with(commands, PEER_QUERY_TIMEOUT).await;
            (peer, outcome)
        })));
    }

    let mut out = HashMap::with_capacity(tasks.len());
    for task in tasks {
        match task.await {
            Ok((addr, outcome)) => {
                out.insert(addr, outcome);
            }
            Err(e) => {
                warn!(error = %e, "query_state task join failed");
            }
        }
    }
    out
}

impl PeerManager {
    /// Refresh both ADR-0112 gauges for one peer from the chains it currently
    /// has installed.
    ///
    /// Call this wherever a peer's import/export chain is installed or
    /// replaced: peer creation, dynamic accept, and the end of a runtime
    /// policy update. It shares [`rfc8212_statuses`] with the neighbor-detail
    /// surface, so the gauge and the reported verdict cannot disagree — both
    /// are one read of `ManagedPeer`'s installed chains.
    ///
    /// A peer that has gone away is skipped; its series are dropped by
    /// `reap_peer_series` on removal.
    pub(super) fn refresh_rfc8212_policy_metrics(&self, peer: &PeerKey) {
        let Some(managed) = self.peers.get(peer) else {
            return;
        };
        let (import, export) = rfc8212_statuses(
            managed,
            self.current_config.rfc8212_posture().policy_effective,
        );
        self.metrics.set_rfc8212_missing_policy(
            &peer.address.to_string(),
            import == Rfc8212PolicyStatus::Missing,
            export == Rfc8212PolicyStatus::Missing,
        );
    }

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
        &mut self,
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
            .resolved_neighbors_for_comparison()
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
            let session_id = managed.session_id();
            let commands = managed.handle().commands_sender();
            tasks.push(AbortOnDropHandle::new(tokio::spawn(async move {
                let state =
                    PeerHandle::query_warm_checkpoint_state_with(commands, PEER_QUERY_TIMEOUT)
                        .await;
                (peer, session_id, canonical_import_policy, state)
            })));
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
        let session_state = managed
            .handle()
            .query_state_timeout(PEER_QUERY_TIMEOUT)
            .await;
        let mut info = build_peer_info(
            peer,
            managed,
            session_state.as_ref(),
            self.current_config.rfc8212_posture().policy_effective,
        );
        if let Some(latch) = self.max_prefix_latches.get(peer) {
            apply_max_prefix_latch(&mut info, &latch.error, latch.deadline);
        }
        Some(info)
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
            let session_state = states.get(peer).and_then(|outcome| match outcome {
                StateQueryOutcome::State(state) => Some(state),
                StateQueryOutcome::TimedOut | StateQueryOutcome::SessionGone => None,
            });
            let mut info = build_peer_info(
                peer,
                managed,
                session_state,
                self.current_config.rfc8212_posture().policy_effective,
            );
            if let Some(latch) = self.max_prefix_latches.get(peer) {
                apply_max_prefix_latch(&mut info, &latch.error, latch.deadline);
            }
            infos.push(info);
        }
        infos
    }

    /// Serve a `ListPeers` admitted at a transaction wait without holding the
    /// owner (ADR-0132, 2026-10-10 amendment). Capture the manager half of
    /// every row and enqueue one `QueryState` per session before returning;
    /// a task in [`PeerManager::detached_list_peers`] joins the replies.
    /// Session command channels are FIFO, so each session answers before it
    /// executes any command the owner sends after this point.
    ///
    /// Returns the reply for in-place service when the detached-read limit
    /// (the operator lane's capacity) is reached or any session channel is
    /// full. A closed channel reports that session as unavailable, as the
    /// in-place fan-out does.
    pub(super) fn detach_list_peers(
        &mut self,
        reply: oneshot::Sender<Vec<PeerInfo>>,
    ) -> Result<(), oneshot::Sender<Vec<PeerInfo>>> {
        // One absolute deadline from admission, as the in-place fan-out has.
        let deadline = tokio::time::Instant::now() + PEER_QUERY_TIMEOUT;
        while let Some(joined) = self.detached_list_peers.try_join_next() {
            if let Err(error) = joined
                && !error.is_cancelled()
            {
                warn!(error = %error, "detached neighbor snapshot task failed");
            }
        }
        let limit = self
            .operator_rx
            .as_ref()
            .map_or(0, mpsc::Receiver::max_capacity);
        if self.detached_list_peers.len() >= limit {
            return Err(reply);
        }
        if reply.is_closed() {
            return Ok(());
        }
        let mut reserved = Vec::with_capacity(self.peers.len());
        for (peer, managed) in &self.peers {
            let permit = match managed.handle().commands_sender().try_reserve_owned() {
                Ok(permit) => Some(permit),
                Err(mpsc::error::TrySendError::Closed(_)) => None,
                Err(mpsc::error::TrySendError::Full(_)) => return Err(reply),
            };
            reserved.push((peer, managed, permit));
        }
        let ebgp_requires_policy = self.current_config.rfc8212_posture().policy_effective;
        let rows = reserved
            .into_iter()
            .map(|(peer, managed, permit)| DetachedPeerRow {
                info: manager_peer_info(peer, managed, ebgp_requires_policy),
                md5_configured: managed.transport_config.md5_password.is_some(),
                latch: self
                    .max_prefix_latches
                    .get(peer)
                    .map(|latch| (latch.error.clone(), latch.deadline)),
                state: permit.map(|permit| {
                    let (state_tx, state_rx) = oneshot::channel();
                    permit.send(PeerCommand::QueryState { reply: state_tx });
                    state_rx
                }),
            })
            .collect();
        self.detached_list_peers
            .spawn(complete_detached_list_peers(rows, reply, deadline));
        Ok(())
    }

    /// Answer an operator/readiness peer snapshot only when its caller still
    /// owns the response. Dropping the response mid-fan-out drops
    /// `list_peers`; its abort-on-drop query drivers then release any bounded
    /// session-command slots they were waiting to acquire. A query already
    /// admitted to a session may still be observed, but no orphaned driver
    /// remains behind the canceled aggregate read.
    pub(super) async fn answer_list_peers(
        &self,
        mut reply: tokio::sync::oneshot::Sender<Vec<PeerInfo>>,
    ) {
        if reply.is_closed() {
            return;
        }
        let infos = tokio::select! {
            biased;
            () = reply.closed() => return,
            infos = self.list_peers() => infos,
        };
        let _ = reply.send(infos);
    }

    /// Complete-only warm-checkpoint reply fence. Cancellation drops the
    /// capture future and therefore every abort-on-drop per-session driver;
    /// successful callers still receive one all-or-nothing, sorted capture.
    pub(super) async fn answer_warm_checkpoint_capture(
        &mut self,
        mut reply: tokio::sync::oneshot::Sender<Result<WarmCheckpointCapture, String>>,
    ) {
        if reply.is_closed() {
            return;
        }
        let capture = tokio::select! {
            biased;
            () = reply.closed() => return,
            capture = self.query_warm_checkpoint_capture() => capture,
        };
        let _ = reply.send(capture);
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

    /// One bounded RIB query for all actor-owned per-peer BMP counts. Channel
    /// admission and the reply share one absolute deadline so a full actor
    /// mailbox cannot double the per-tick latency budget.
    pub(super) async fn query_bmp_peer_stats(&self) -> Option<rustbgpd_rib::BmpPeerStats> {
        let (reply, rx) = tokio::sync::oneshot::channel();
        let deadline = tokio::time::Instant::now() + PEER_QUERY_TIMEOUT;
        tokio::time::timeout_at(
            deadline,
            self.rib_tx
                .send(rustbgpd_rib::RibUpdate::QueryBmpPeerStats { reply }),
        )
        .await
        .ok()?
        .ok()?;
        tokio::time::timeout_at(deadline, rx).await.ok()?.ok()
    }

    /// RFC 9069 Loc-RIB counts, omitted unless a collector monitors `loc_rib`.
    /// As with peer counts, admission and reply share one sampling deadline.
    pub(super) async fn query_bmp_loc_rib_stats(&self) -> Option<Vec<(u16, u8, u64)>> {
        let monitored = self.current_config.bmp.as_ref().is_some_and(|bmp| {
            bmp.collectors.iter().any(|collector| {
                collector
                    .monitor
                    .contains(&crate::config::BmpMonitorView::LocRib)
            })
        });
        if !monitored {
            return None;
        }
        let (reply, rx) = tokio::sync::oneshot::channel();
        let deadline = tokio::time::Instant::now() + PEER_QUERY_TIMEOUT;
        tokio::time::timeout_at(
            deadline,
            self.rib_tx
                .send(rustbgpd_rib::RibUpdate::QueryBmpLocRibStats { reply }),
        )
        .await
        .ok()?
        .ok()?;
        // Unavailable this tick: omit rather than report a false zero.
        tokio::time::timeout_at(deadline, rx).await.ok()?.ok()
    }

    fn emit_loc_rib_bmp_stats(
        &self,
        bmp_tx: &tokio::sync::mpsc::Sender<BmpEvent>,
        per_family: Vec<(u16, u8, u64)>,
    ) {
        if let Err(e) = bmp_tx.try_send(BmpEvent::LocRibStats { per_family }) {
            let reason = match e {
                tokio::sync::mpsc::error::TrySendError::Full(_) => "channel_full",
                tokio::sync::mpsc::error::TrySendError::Closed(_) => "channel_closed",
            };
            self.metrics.record_bmp_loc_rib_source_drop("stats", reason);
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
        // These independent reads observe the same managed peer set, but do
        // not form one atomic cross-actor snapshot. Overlap their bounded waits
        // instead of stacking three 100 ms budgets on the actor's timer arm.
        let (states, bmp_peer_stats, loc_rib_stats) = tokio::join!(
            collect_session_states(&self.peers),
            self.query_bmp_peer_stats(),
            self.query_bmp_loc_rib_stats(),
        );
        if let Some(per_family) = loc_rib_stats {
            self.emit_loc_rib_bmp_stats(bmp_tx, per_family);
        }
        for (peer, managed) in &self.peers {
            let peer_addr = peer.address;
            let state = match states.get(peer) {
                Some(StateQueryOutcome::State(state)) => state,
                Some(StateQueryOutcome::TimedOut) => {
                    let peer_label = rustbgpd_telemetry::peer_label(peer_addr);
                    self.metrics
                        .record_bmp_source_drop(&peer_label, "state_query_timeout");
                    warn!(
                        peer = %peer_addr,
                        "peer state query timed out, omitting periodic BMP stats report"
                    );
                    continue;
                }
                Some(StateQueryOutcome::SessionGone) | None => continue,
            };
            if state.fsm_state != SessionState::Established {
                continue;
            }

            let prefix_count = u64::try_from(state.prefix_count).unwrap_or(u64::MAX);
            let rfc9972_adj_rib_in_post = rfc9972_adj_rib_in_counts(state);
            let rfc9972_policy_rejects = rfc9972_policy_reject_counts(state);
            let rfc9972_rpki_adj_rib_in_post = rfc9972_rpki_validation_counts(
                peer_addr,
                state,
                bmp_peer_stats
                    .as_ref()
                    .and_then(|stats| stats.rpki_adj_rib_in_post.as_ref()),
            );
            let remote_asn = effective_remote_asn(managed, Some(state));
            // RFC 8671 types 15/17: a peer absent from the RIB's
            // Adj-RIB-Out map simply has nothing advertised — report
            // an honest empty set (type 15 = 0) rather than omitting.
            let adj_rib_out_post = bmp_peer_stats.as_ref().map(|stats| {
                stats
                    .adj_rib_out_post
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
                rfc9972_adj_rib_in_post,
                rfc9972_policy_rejects,
                rfc9972_rpki_adj_rib_in_post,
                adj_rib_out_post,
            };

            if let Err(e) = bmp_tx.try_send(event) {
                let reason = match &e {
                    tokio::sync::mpsc::error::TrySendError::Full(_) => "channel_full",
                    tokio::sync::mpsc::error::TrySendError::Closed(_) => "channel_closed",
                };
                self.metrics
                    .record_bmp_source_drop(&rustbgpd_telemetry::peer_label(peer_addr), reason);
                warn!(
                    peer = %peer_addr,
                    error = %e,
                    "BMP event channel full or closed, dropping periodic stats report"
                );
            }
        }
    }
}
