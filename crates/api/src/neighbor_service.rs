//! gRPC neighbor service — add, remove, enable, disable, and list BGP peers.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rustbgpd_transport::RemovePrivateAs;
use rustbgpd_wire::{Afi, BgpRole, Safi};
use tokio::sync::{Mutex, mpsc, oneshot};
use tonic::{Request, Response, Status};

use crate::peer_types::{
    ConfigEvent, DynamicRangeError, PeerInfo, PeerKey, PeerLifecycleError, PeerManagerCommand,
    PeerManagerNeighborConfig, RemovedDynamicRange,
};
use crate::proto;
use crate::server::{
    AccessMode, ConfigMutationGateFn, check_config_mutation_gate, persist_runtime_config_event,
    read_only_rejection,
};
use rustbgpd_rib::{EffectiveDistributionMode, PeerOutboundState, RibUpdate};

const CONFIG_PERSIST_RESERVE_TIMEOUT: Duration = Duration::from_secs(2);

fn is_ipv6_link_local(address: IpAddr) -> bool {
    match address {
        IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80,
        IpAddr::V4(_) => false,
    }
}

/// Parse a list of family strings from the gRPC proto into `(Afi, Safi)` pairs.
#[allow(
    clippy::result_large_err,
    reason = "tonic::Status is the standard gRPC error type"
)]
pub(crate) fn parse_families_proto(families: &[String]) -> Result<Vec<(Afi, Safi)>, Status> {
    if families.is_empty() {
        return Ok(vec![(Afi::Ipv4, Safi::Unicast)]);
    }
    let mut result = Vec::with_capacity(families.len());
    for f in families {
        let family = match f.as_str() {
            "ipv4_unicast" => (Afi::Ipv4, Safi::Unicast),
            "ipv6_unicast" => (Afi::Ipv6, Safi::Unicast),
            other => {
                return Err(Status::invalid_argument(format!(
                    "unknown address family {other:?}, expected \"ipv4_unicast\" or \"ipv6_unicast\""
                )));
            }
        };
        if !result.contains(&family) {
            result.push(family);
        }
    }
    Ok(result)
}

/// gRPC service for adding, removing, enabling, and disabling BGP neighbors.
#[allow(
    clippy::struct_field_names,
    reason = "service fields intentionally keep neighbor/control-plane nouns explicit"
)]
pub struct NeighborService {
    local_asn: u32,
    access_mode: AccessMode,
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    rib_tx: mpsc::Sender<RibUpdate>,
    config_tx: Option<mpsc::Sender<ConfigEvent>>,
    runtime_config_lock: Arc<Mutex<()>>,
    config_mutation_gate: Option<ConfigMutationGateFn>,
}

impl NeighborService {
    /// Create a new neighbor service with the given channels.
    #[cfg(test)]
    pub fn new(
        local_asn: u32,
        access_mode: AccessMode,
        peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
        rib_tx: mpsc::Sender<RibUpdate>,
        config_tx: Option<mpsc::Sender<ConfigEvent>>,
    ) -> Self {
        Self::with_runtime_config_lock(
            local_asn,
            access_mode,
            peer_mgr_tx,
            rib_tx,
            config_tx,
            Arc::new(Mutex::new(())),
            None,
        )
    }

    /// Create a new neighbor service using the shared runtime config lock.
    ///
    /// The daemon wires the same lock into SIGHUP reload and FIB-table CRUD so
    /// persisted runtime mutations cannot interleave with a TOML reload.
    pub fn with_runtime_config_lock(
        local_asn: u32,
        access_mode: AccessMode,
        peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
        rib_tx: mpsc::Sender<RibUpdate>,
        config_tx: Option<mpsc::Sender<ConfigEvent>>,
        runtime_config_lock: Arc<Mutex<()>>,
        config_mutation_gate: Option<ConfigMutationGateFn>,
    ) -> Self {
        Self {
            local_asn,
            access_mode,
            peer_mgr_tx,
            rib_tx,
            config_tx,
            runtime_config_lock,
            config_mutation_gate,
        }
    }
}

async fn reserve_config_event_slot(
    config_tx: Option<mpsc::Sender<ConfigEvent>>,
) -> Result<Option<mpsc::OwnedPermit<ConfigEvent>>, Status> {
    let Some(tx) = config_tx else {
        return Ok(None);
    };

    let permit = tokio::time::timeout(CONFIG_PERSIST_RESERVE_TIMEOUT, tx.reserve_owned())
        .await
        .map_err(|_| {
            Status::unavailable("config persistence queue busy — refusing mutation to avoid drift")
        })?
        .map_err(|_| Status::unavailable("config persistence unavailable"))?;

    Ok(Some(permit))
}

async fn query_advertised_count(
    rib_tx: &mpsc::Sender<RibUpdate>,
    peer: std::net::IpAddr,
) -> Result<u64, Status> {
    let (reply_tx, reply_rx) = oneshot::channel();
    rib_tx
        .send(RibUpdate::QueryAdvertisedCount {
            peer,
            reply: reply_tx,
        })
        .await
        .map_err(|_| Status::internal("RIB manager unavailable"))?;
    let count = reply_rx
        .await
        .map_err(|_| Status::internal("RIB manager dropped reply"))?;
    Ok(u64::try_from(count).unwrap_or(u64::MAX))
}

async fn query_export_policy_stats(
    rib_tx: &mpsc::Sender<RibUpdate>,
    peer: std::net::IpAddr,
) -> Result<rustbgpd_rib::NeighborPolicyStats, Status> {
    let (reply_tx, reply_rx) = oneshot::channel();
    rib_tx
        .send(RibUpdate::QueryNeighborPolicyStats {
            peer,
            reply: reply_tx,
        })
        .await
        .map_err(|_| Status::internal("RIB manager unavailable"))?;
    reply_rx
        .await
        .map_err(|_| Status::internal("RIB manager dropped reply"))
}

async fn query_peer_outbound_state(
    rib_tx: &mpsc::Sender<RibUpdate>,
    peer: std::net::IpAddr,
) -> Result<PeerOutboundState, Status> {
    let (reply_tx, reply_rx) = oneshot::channel();
    rib_tx
        .send(RibUpdate::QueryPeerOutboundState {
            peer,
            reply: reply_tx,
        })
        .await
        .map_err(|_| Status::internal("RIB manager unavailable"))?;
    reply_rx
        .await
        .map_err(|_| Status::internal("RIB manager dropped reply"))
}

fn dynamic_range_error_status(error: DynamicRangeError) -> Status {
    match error {
        DynamicRangeError::AlreadyExists(message) => Status::already_exists(message),
        DynamicRangeError::NotFound(message) => Status::not_found(message),
        DynamicRangeError::Invalid(message) => Status::invalid_argument(message),
    }
}

pub(crate) fn peer_lifecycle_error_status(error: PeerLifecycleError) -> Status {
    match error {
        PeerLifecycleError::AlreadyExists(peer) => {
            Status::already_exists(format!("peer {peer} already exists"))
        }
        PeerLifecycleError::NotFound(peer) => Status::not_found(format!("peer {peer} not found")),
        PeerLifecycleError::Invalid(message) => Status::invalid_argument(message),
        PeerLifecycleError::RestartRequired(message) => Status::failed_precondition(message),
        PeerLifecycleError::Internal(message) => Status::internal(message),
    }
}

async fn add_dynamic_range(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    prefix: String,
    peer_group: String,
    remote_asn: u32,
    description: Option<String>,
) -> Result<(), Status> {
    let (reply_tx, reply_rx) = oneshot::channel();
    peer_mgr_tx
        .send(PeerManagerCommand::AddDynamicRange {
            prefix,
            peer_group,
            remote_asn,
            description,
            reply: reply_tx,
        })
        .await
        .map_err(|_| Status::internal("peer manager unavailable"))?;

    reply_rx
        .await
        .map_err(|_| Status::internal("peer manager dropped reply"))?
        .map_err(dynamic_range_error_status)
}

async fn add_static_peer(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    config: PeerManagerNeighborConfig,
) -> Result<(), Status> {
    let (reply_tx, reply_rx) = oneshot::channel();
    peer_mgr_tx
        .send(PeerManagerCommand::AddPeer {
            config,
            sync_config_snapshot: true,
            reply: reply_tx,
        })
        .await
        .map_err(|_| Status::internal("peer manager unavailable"))?;

    reply_rx
        .await
        .map_err(|_| Status::internal("peer manager dropped reply"))?
        .map_err(peer_lifecycle_error_status)
}

async fn delete_static_peer(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    peer: PeerKey,
    sync_config_snapshot: bool,
) -> Result<PeerManagerNeighborConfig, Status> {
    let (reply_tx, reply_rx) = oneshot::channel();
    peer_mgr_tx
        .send(PeerManagerCommand::DeletePeer {
            peer,
            sync_config_snapshot,
            reply: reply_tx,
        })
        .await
        .map_err(|_| Status::internal("peer manager unavailable"))?;

    reply_rx
        .await
        .map_err(|_| Status::internal("peer manager dropped reply"))?
        .map_err(peer_lifecycle_error_status)
}

async fn apply_peer_manager_config_event(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    event: ConfigEvent,
) -> Result<(), Status> {
    let (reply_tx, reply_rx) = oneshot::channel();
    peer_mgr_tx
        .send(PeerManagerCommand::ApplyConfigEvent {
            event,
            reply: reply_tx,
        })
        .await
        .map_err(|_| Status::internal("peer manager unavailable"))?;

    reply_rx
        .await
        .map_err(|_| Status::internal("peer manager dropped reply"))?
        .map_err(Status::internal)
}

async fn delete_dynamic_range(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    prefix: String,
) -> Result<RemovedDynamicRange, Status> {
    let (reply_tx, reply_rx) = oneshot::channel();
    peer_mgr_tx
        .send(PeerManagerCommand::DeleteDynamicRange {
            prefix,
            reply: reply_tx,
        })
        .await
        .map_err(|_| Status::internal("peer manager unavailable"))?;

    reply_rx
        .await
        .map_err(|_| Status::internal("peer manager dropped reply"))?
        .map_err(dynamic_range_error_status)
}

pub(crate) fn family_to_string(afi: Afi, safi: Safi) -> String {
    match (afi, safi) {
        (Afi::Ipv4, Safi::Unicast) => "ipv4_unicast".to_string(),
        (Afi::Ipv6, Safi::Unicast) => "ipv6_unicast".to_string(),
        _ => format!("{afi:?}_{safi:?}"),
    }
}

#[allow(
    clippy::result_large_err,
    reason = "tonic::Status is the standard gRPC error type"
)]
pub(crate) fn parse_remove_private_as_proto(mode: &str) -> Result<RemovePrivateAs, Status> {
    match mode {
        "" => Ok(RemovePrivateAs::Disabled),
        "remove" => Ok(RemovePrivateAs::Remove),
        "all" => Ok(RemovePrivateAs::All),
        "replace" => Ok(RemovePrivateAs::Replace),
        other => Err(Status::invalid_argument(format!(
            "unknown remove_private_as mode {other:?}, expected \"remove\", \"all\", \"replace\", or empty string"
        ))),
    }
}

fn remove_private_as_to_string(mode: RemovePrivateAs) -> String {
    match mode {
        RemovePrivateAs::Disabled => String::new(),
        RemovePrivateAs::Remove => "remove".to_string(),
        RemovePrivateAs::All => "all".to_string(),
        RemovePrivateAs::Replace => "replace".to_string(),
    }
}

fn bgp_role_to_string(role: Option<BgpRole>) -> String {
    match role {
        Some(BgpRole::Provider) => "provider".to_string(),
        Some(BgpRole::RouteServer) => "rs".to_string(),
        Some(BgpRole::RouteServerClient) => "rs-client".to_string(),
        Some(BgpRole::Customer) => "customer".to_string(),
        Some(BgpRole::Peer) => "peer".to_string(),
        None => String::new(),
    }
}

fn parse_bgp_role_proto(role: &str) -> Result<Option<BgpRole>, Status> {
    let role = role.trim();
    if role.is_empty() {
        return Ok(None);
    }
    match role {
        "provider" => Ok(Some(BgpRole::Provider)),
        "rs" | "route_server" => Ok(Some(BgpRole::RouteServer)),
        "rs-client" | "route_server_client" => Ok(Some(BgpRole::RouteServerClient)),
        "customer" => Ok(Some(BgpRole::Customer)),
        "peer" => Ok(Some(BgpRole::Peer)),
        other => Err(Status::invalid_argument(format!(
            "unknown BGP role {other:?}, expected provider, rs, rs-client, customer, or peer"
        ))),
    }
}

#[expect(
    clippy::too_many_lines,
    clippy::items_after_statements,
    reason = "neighbor conversion keeps config, session state, and family-local capability visibility in one audit-friendly mapping"
)]
fn peer_info_to_proto(info: &PeerInfo) -> proto::NeighborState {
    let families = info
        .families
        .iter()
        .map(|(afi, safi)| family_to_string(*afi, *safi))
        .collect();

    let config = proto::NeighborConfig {
        address: info.address.to_string(),
        interface: info.interface.clone().unwrap_or_default(),
        remote_asn: info.remote_asn,
        description: info.description.clone(),
        hold_time: info.hold_time.map_or(0, u32::from),
        // Effective value (configured or the RFC 9687 §6 derived
        // default); 0 = disabled.
        send_hold_time: Some(info.send_hold_time),
        max_prefixes: info.max_prefixes.unwrap_or(0),
        families,
        remove_private_as: remove_private_as_to_string(info.remove_private_as),
        peer_group: info.peer_group.clone().unwrap_or_default(),
        route_server_client: info.route_server_client,
        per_client_best: info.per_client_best,
        role: bgp_role_to_string(info.local_role),
        strict_role: info.strict_role,
        add_path_receive: info.add_path_receive,
        add_path_send: info.add_path_send,
        add_path_send_max: info.add_path_send_max,
        paths_limit_receive_max: u32::from(info.paths_limit_receive_max),
    };

    let paths_limits = paths_limit_state_to_proto(info);

    fn paths_limit_state_to_proto(info: &PeerInfo) -> Vec<proto::PathsLimitState> {
        let mut paths_limit_families = info.families.clone();
        for family in info
            .peer_paths_limits
            .iter()
            .map(|(family, _)| family)
            .chain(
                info.effective_add_path_send_limits
                    .iter()
                    .map(|(family, _)| family),
            )
        {
            if !paths_limit_families.contains(family) {
                paths_limit_families.push(*family);
            }
        }
        paths_limit_families.sort_by_key(|(afi, safi)| (*afi as u16, *safi as u8));
        paths_limit_families
            .iter()
            .filter_map(|family| {
                let locally_configured = info.families.contains(family);
                let received = info
                    .peer_paths_limits
                    .iter()
                    .find_map(|(candidate, value)| {
                        (candidate == family).then_some(u32::from(*value))
                    })
                    .unwrap_or(0);
                let effective = info
                    .effective_add_path_send_limits
                    .iter()
                    .find_map(|(candidate, value)| (candidate == family).then_some(*value));
                let effective_send_limit =
                    effective.map(|value| if value == u32::MAX { 0 } else { value });
                let effective_send_max = effective.unwrap_or(0);
                let configured_receive_max = if locally_configured {
                    u32::from(info.paths_limit_receive_max)
                } else {
                    0
                };
                let advertised = if locally_configured
                    && info.add_path_receive
                    && matches!(
                        family.1,
                        Safi::Unicast | Safi::MplsVpn | Safi::LabeledUnicast
                    ) {
                    u32::from(info.paths_limit_receive_max)
                } else {
                    0
                };
                (advertised != 0 || received != 0 || effective.is_some()).then(|| {
                    proto::PathsLimitState {
                        family: family_to_string(family.0, family.1),
                        configured_receive_max,
                        advertised_receive_max: advertised,
                        received_receive_max: received,
                        effective_send_max,
                        effective_send_limit,
                    }
                })
            })
            .collect()
    }

    let state = match info.state {
        rustbgpd_fsm::SessionState::Idle => proto::SessionState::Idle,
        rustbgpd_fsm::SessionState::Connect => proto::SessionState::Connect,
        rustbgpd_fsm::SessionState::Active => proto::SessionState::Active,
        rustbgpd_fsm::SessionState::OpenSent => proto::SessionState::OpenSent,
        rustbgpd_fsm::SessionState::OpenConfirm => proto::SessionState::OpenConfirm,
        rustbgpd_fsm::SessionState::Established => proto::SessionState::Established,
    };

    let tcp_ao_health = if info.authentication != "tcp_ao" {
        proto::TcpAoHealth::NotApplicable
    } else if let Some(ao) = info.tcp_ao_info.as_ref() {
        if !ao.has_current_key
            || !ao.has_rnext_key
            || ao.pkt_bad > 0
            || ao.pkt_key_not_found > 0
            || ao.pkt_ao_required > 0
            || ao.pkt_dropped_icmp > 0
            || ao.keys.is_empty()
            || ao
                .keys
                .iter()
                .any(|key| key.pkt_bad > 0 || key.deprecated && (key.is_current || key.is_rnext))
            || !ao
                .keys
                .iter()
                .any(|key| key.is_current && key.send_id == ao.current_key)
            || !ao
                .keys
                .iter()
                .any(|key| key.is_rnext && key.recv_id == ao.rnext_key)
        {
            proto::TcpAoHealth::Degraded
        } else {
            proto::TcpAoHealth::Healthy
        }
    } else {
        proto::TcpAoHealth::Unavailable
    };

    proto::NeighborState {
        config: Some(config),
        state: state.into(),
        uptime_seconds: info.uptime_secs,
        prefixes_received: info.prefix_count as u64,
        prefixes_sent: 0,
        updates_received: info.updates_received,
        updates_sent: info.updates_sent,
        notifications_received: info.notifications_received,
        notifications_sent: info.notifications_sent,
        messages_received: info.messages_received,
        messages_sent: info.messages_sent,
        route_reflector_client: info.route_reflector_client,
        paths_limits,
        flap_count: info.flap_count,
        last_error: info.last_error.clone(),
        is_dynamic: info.is_dynamic,
        stale: info.stale,
        local_role: bgp_role_to_string(info.local_role),
        remote_role: bgp_role_to_string(info.remote_role),
        role_negotiated: info.role_negotiated,
        otc_routes_blocked: info.otc_routes_blocked,
        import_policy_routes_permitted: info.import_policy_routes_permitted,
        import_policy_routes_denied: info.import_policy_routes_denied,
        export_policy_routes_permitted: info.export_policy_routes_permitted,
        export_policy_routes_denied: info.export_policy_routes_denied,
        update_group: String::new(),
        authentication: match info.authentication.as_str() {
            "tcp_ao" => proto::AuthenticationMode::TcpAo.into(),
            "md5" => proto::AuthenticationMode::Md5.into(),
            "plaintext" => proto::AuthenticationMode::Plaintext.into(),
            _ => proto::AuthenticationMode::Unspecified.into(),
        },
        tcp_ao: info.tcp_ao_info.as_ref().map(|ao| proto::TcpAoState {
            current_key_id: ao.has_current_key.then_some(u32::from(ao.current_key)),
            rnext_key_id: ao.has_rnext_key.then_some(u32::from(ao.rnext_key)),
            ao_required: ao.ao_required,
            accept_icmps: ao.accept_icmps,
            packets_good: ao.pkt_good,
            packets_bad: ao.pkt_bad,
            packets_key_not_found: ao.pkt_key_not_found,
            packets_ao_required: ao.pkt_ao_required,
            packets_dropped_icmp: ao.pkt_dropped_icmp,
            keys: ao
                .keys
                .iter()
                .map(|key| proto::TcpAoKeyState {
                    peer_address: key.peer.to_string(),
                    prefix_length: u32::from(key.prefix_len),
                    send_id: u32::from(key.send_id),
                    recv_id: u32::from(key.recv_id),
                    algorithm: key.algorithm.linux_name().to_string(),
                    is_current: key.is_current,
                    is_rnext: key.is_rnext,
                    preferred: key.preferred,
                    deprecated: key.deprecated,
                    packets_good: key.pkt_good,
                    packets_bad: key.pkt_bad,
                    vrf_ifindex: key.vrf_ifindex,
                })
                .collect(),
        }),
        tcp_ao_health: tcp_ao_health.into(),
        effective_distribution_mode: proto::EffectiveDistributionMode::Unknown.into(),
        selection_deferral: Vec::new(),
    }
}

fn effective_distribution_mode_to_proto(
    mode: EffectiveDistributionMode,
) -> proto::EffectiveDistributionMode {
    match mode {
        EffectiveDistributionMode::Unknown => proto::EffectiveDistributionMode::Unknown,
        EffectiveDistributionMode::SingleBest => proto::EffectiveDistributionMode::SingleBest,
        EffectiveDistributionMode::AddPath => proto::EffectiveDistributionMode::AddPath,
        EffectiveDistributionMode::Orr => proto::EffectiveDistributionMode::Orr,
        EffectiveDistributionMode::PerClientBest => proto::EffectiveDistributionMode::PerClientBest,
    }
}

fn selection_deferral_to_proto(
    rows: Vec<rustbgpd_rib::SelectionDeferralPeerFamilyState>,
) -> Vec<proto::SelectionDeferralFamilyState> {
    rows.into_iter()
        .map(|row| proto::SelectionDeferralFamilyState {
            afi: row.afi as u32,
            safi: row.safi as u32,
            active: row.active,
            waiter_state: row.waiter_state,
            waiter_session_id: row.waiter_session_id,
            blocking_waiters: row.blocking_waiters,
            remaining_millis: row.remaining_millis,
            release_reason: row.release_reason,
        })
        .collect()
}

fn peer_key(address: &str, interface: &str) -> Result<PeerKey, Status> {
    let address: IpAddr = address
        .parse()
        .map_err(|e| Status::invalid_argument(format!("invalid address: {e}")))?;
    let interface = (!interface.trim().is_empty()).then(|| interface.to_string());
    match (is_ipv6_link_local(address), interface.as_ref()) {
        (true, None) => {
            return Err(Status::invalid_argument(
                "interface is required for IPv6 link-local neighbors",
            ));
        }
        (false, Some(_)) => {
            return Err(Status::invalid_argument(
                "interface is only valid for IPv6 link-local neighbors",
            ));
        }
        _ => {}
    }
    Ok(PeerKey::new(address, interface))
}

#[tonic::async_trait]
impl proto::neighbor_service_server::NeighborService for NeighborService {
    #[expect(
        clippy::too_many_lines,
        reason = "gRPC add maps the public proto surface into the peer-manager command"
    )]
    async fn add_neighbor(
        &self,
        request: Request<proto::AddNeighborRequest>,
    ) -> Result<Response<proto::AddNeighborResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let req = request.into_inner();
        let config = req
            .config
            .ok_or_else(|| Status::invalid_argument("config is required"))?;

        let address: IpAddr = config
            .address
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid address: {e}")))?;

        if config.remote_asn == 0 {
            return Err(Status::invalid_argument("remote_asn must be > 0"));
        }

        if config.hold_time > 0 && config.hold_time < 3 {
            return Err(Status::invalid_argument("hold_time must be 0 or >= 3"));
        }
        // RFC 9687 §4.4 parity with the config path: a non-zero send
        // hold time must exceed the effective hold time (0 = disabled,
        // unset = derived default). hold_time 0 here means "use the
        // default" (see the Some/None mapping below), so validate
        // against what the peer manager will actually apply.
        if let Some(value) = config.send_hold_time
            && value != 0
        {
            // Unset hold_time falls back to the daemon default the peer
            // manager applies (single source of truth in the fsm crate).
            let effective_hold_time = if config.hold_time > 0 {
                config.hold_time
            } else {
                u32::from(rustbgpd_fsm::DEFAULT_HOLD_TIME)
            };
            if value <= effective_hold_time {
                return Err(Status::invalid_argument(format!(
                    "invalid send_hold_time {value}: must be 0 (disabled) or greater than \
                     hold_time {effective_hold_time} (RFC 9687 §4.4)"
                )));
            }
        }
        let interface = (!config.interface.trim().is_empty()).then(|| config.interface.clone());
        match (is_ipv6_link_local(address), interface.as_ref()) {
            (true, None) => {
                return Err(Status::invalid_argument(
                    "interface is required for IPv6 link-local neighbors",
                ));
            }
            (false, Some(_)) => {
                return Err(Status::invalid_argument(
                    "interface is only valid for IPv6 link-local neighbors",
                ));
            }
            _ => {}
        }

        let families = parse_families_proto(&config.families)?;
        let remove_private_as = parse_remove_private_as_proto(&config.remove_private_as)?;
        let local_role = parse_bgp_role_proto(&config.role)?;
        let paths_limit_receive_max = u16::try_from(config.paths_limit_receive_max)
            .map_err(|_| Status::invalid_argument("paths_limit_receive_max must be <= 65535"))?;
        if remove_private_as != RemovePrivateAs::Disabled && config.remote_asn == self.local_asn {
            return Err(Status::invalid_argument(format!(
                "remove_private_as requires eBGP (remote_asn {} == local asn {})",
                config.remote_asn, self.local_asn
            )));
        }
        if config.route_server_client && config.remote_asn == self.local_asn {
            return Err(Status::invalid_argument(format!(
                "route_server_client requires eBGP (remote_asn {} == local asn {})",
                config.remote_asn, self.local_asn
            )));
        }
        if config.per_client_best && !config.route_server_client {
            return Err(Status::invalid_argument(
                "per_client_best requires route_server_client",
            ));
        }
        if local_role.is_some() && config.remote_asn == self.local_asn {
            return Err(Status::invalid_argument(format!(
                "role requires eBGP (remote_asn {} == local asn {})",
                config.remote_asn, self.local_asn
            )));
        }
        if config.strict_role && local_role.is_none() {
            return Err(Status::invalid_argument("strict_role requires role"));
        }

        let peer_config = PeerManagerNeighborConfig {
            address,
            interface,
            scope_id: None,
            remote_asn: config.remote_asn,
            description: config.description,
            peer_group: if config.peer_group.trim().is_empty() {
                None
            } else {
                Some(config.peer_group)
            },
            hold_time: if config.hold_time > 0 {
                Some(
                    u16::try_from(config.hold_time)
                        .map_err(|_| Status::invalid_argument("hold_time exceeds u16 range"))?,
                )
            } else {
                None
            },
            send_hold_time: config.send_hold_time,
            max_prefixes: if config.max_prefixes > 0 {
                Some(config.max_prefixes)
            } else {
                None
            },
            md5_password: None,
            tcp_ao: None,
            ttl_security: false,
            families,
            graceful_restart: true,
            gr_restart_time: 120,
            gr_stale_routes_time: 360,
            llgr_stale_time: 0,
            gr_restart_eligible: false,
            local_ipv6_nexthop: None,
            route_reflector_client: false,
            // Like route_reflector_client, the ORR vantage is not exposed
            // on the runtime neighbor-add gRPC surface; configure it via
            // the static TOML `orr_vantage` knob.
            orr_vantage: None,
            route_server_client: config.route_server_client,
            per_client_best: config.per_client_best,
            remove_private_as,
            add_path_receive: config.add_path_receive,
            add_path_send: config.add_path_send,
            add_path_send_max: config.add_path_send_max,
            paths_limit_receive_max,
            local_role,
            strict_role: config.strict_role,
            // ORF and IPv6-only peering are not exposed on the runtime
            // neighbor-add gRPC surface; enable them via the static TOML
            // `prefix_orf_receive` / `disable_ipv4_unicast` knobs instead.
            prefix_orf_receive: false,
            disable_ipv4_unicast: false,
            import_policy: None,
            export_policy: None,
        };

        // Reserve config persistence capacity before mutating runtime state.
        // This makes AddNeighbor fail-fast when persistence is unavailable.
        let persist_permit = reserve_config_event_slot(self.config_tx.clone()).await?;
        let peer_key = PeerKey::new(peer_config.address, peer_config.interface.clone());
        let peer_mgr_tx = self.peer_mgr_tx.clone();
        let runtime_config_lock = self.runtime_config_lock.clone();
        let config_mutation_gate = self.config_mutation_gate.clone();
        let join = tokio::spawn(async move {
            let _guard = runtime_config_lock.lock().await;
            check_config_mutation_gate(&config_mutation_gate, "NeighborService.AddNeighbor")
                .await?;
            add_static_peer(&peer_mgr_tx, peer_config.clone()).await?;

            // Keep the shared runtime-config lock held until the TOML write is
            // acknowledged; otherwise a concurrent SIGHUP could reload stale
            // disk and drop the accepted runtime neighbor from the snapshot.
            if let Some(permit) = persist_permit
                && let Err(error) =
                    persist_runtime_config_event(permit, |ack| ConfigEvent::NeighborAdded {
                        config: peer_config.clone(),
                        ack: Some(ack),
                    })
                    .await
            {
                let rollback = delete_static_peer(&peer_mgr_tx, peer_key, true).await;
                if let Err(rollback_error) = rollback {
                    return Err(Status::internal(format!(
                        "{error}; rollback of neighbor add failed: {rollback_error}"
                    )));
                }
                return Err(error);
            }
            Ok::<(), Status>(())
        });
        join.await
            .map_err(|_| Status::internal("neighbor add task did not complete"))??;

        Ok(Response::new(proto::AddNeighborResponse {}))
    }

    async fn delete_neighbor(
        &self,
        request: Request<proto::DeleteNeighborRequest>,
    ) -> Result<Response<proto::DeleteNeighborResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let req = request.into_inner();
        let peer = peer_key(&req.address, &req.interface)?;

        // Reserve config persistence capacity before mutating runtime state.
        // This makes DeleteNeighbor fail-fast when persistence is unavailable.
        let persist_permit = reserve_config_event_slot(self.config_tx.clone()).await?;

        let peer_mgr_tx = self.peer_mgr_tx.clone();
        let runtime_config_lock = self.runtime_config_lock.clone();
        let config_mutation_gate = self.config_mutation_gate.clone();
        let join = tokio::spawn(async move {
            let _guard = runtime_config_lock.lock().await;
            check_config_mutation_gate(&config_mutation_gate, "NeighborService.DeleteNeighbor")
                .await?;
            let removed = delete_static_peer(&peer_mgr_tx, peer.clone(), false).await?;

            // Hold the shared runtime-config lock until persistence completes
            // so SIGHUP cannot rebuild from stale TOML in the middle.
            if let Some(permit) = persist_permit
                && let Err(error) =
                    persist_runtime_config_event(permit, |ack| ConfigEvent::NeighborDeleted {
                        peer: peer.clone(),
                        ack: Some(ack),
                    })
                    .await
            {
                let rollback = add_static_peer(&peer_mgr_tx, removed).await;
                if let Err(rollback_error) = rollback {
                    return Err(Status::internal(format!(
                        "{error}; rollback of neighbor delete failed: {rollback_error}"
                    )));
                }
                return Err(error);
            }
            // Delete differs from add on purpose: the live peer is removed
            // before persistence, but the peer-manager config snapshot is only
            // updated after the TOML write succeeds. That keeps the original
            // config row available for rollback instead of reconstructing it
            // from a lossy runtime snapshot.
            if let Err(error) = apply_peer_manager_config_event(
                &peer_mgr_tx,
                ConfigEvent::NeighborDeleted {
                    peer: peer.clone(),
                    ack: None,
                },
            )
            .await
            {
                tracing::warn!(
                    %peer,
                    error = %error,
                    "neighbor delete persisted but peer-manager snapshot update failed"
                );
            }
            Ok::<(), Status>(())
        });
        join.await
            .map_err(|_| Status::internal("neighbor delete task did not complete"))??;

        Ok(Response::new(proto::DeleteNeighborResponse {}))
    }

    async fn list_neighbors(
        &self,
        _request: Request<proto::ListNeighborsRequest>,
    ) -> Result<Response<proto::ListNeighborsResponse>, Status> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::ListPeers { reply: reply_tx })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;

        let infos = reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?;

        let mut neighbors = Vec::with_capacity(infos.len());
        for info in &infos {
            let mut state = peer_info_to_proto(info);
            state.prefixes_sent = query_advertised_count(&self.rib_tx, info.address).await?;
            let policy_stats = query_export_policy_stats(&self.rib_tx, info.address).await?;
            state.export_policy_routes_permitted = policy_stats.export_policy_routes_permitted;
            state.export_policy_routes_denied = policy_stats.export_policy_routes_denied;
            let outbound = query_peer_outbound_state(&self.rib_tx, info.address).await?;
            state.update_group = outbound.update_group;
            state.effective_distribution_mode =
                effective_distribution_mode_to_proto(outbound.effective_distribution_mode).into();
            state.selection_deferral = selection_deferral_to_proto(outbound.selection_deferral);
            neighbors.push(state);
        }

        Ok(Response::new(proto::ListNeighborsResponse { neighbors }))
    }

    async fn get_neighbor_state(
        &self,
        request: Request<proto::GetNeighborStateRequest>,
    ) -> Result<Response<proto::NeighborState>, Status> {
        let req = request.into_inner();
        let peer = peer_key(&req.address, &req.interface)?;

        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::GetPeerState {
                peer: peer.clone(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;

        let info = reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?
            .ok_or_else(|| Status::not_found(format!("peer {peer} not found")))?;

        let mut state = peer_info_to_proto(&info);
        state.prefixes_sent = query_advertised_count(&self.rib_tx, info.address).await?;
        let policy_stats = query_export_policy_stats(&self.rib_tx, info.address).await?;
        state.export_policy_routes_permitted = policy_stats.export_policy_routes_permitted;
        state.export_policy_routes_denied = policy_stats.export_policy_routes_denied;
        let outbound = query_peer_outbound_state(&self.rib_tx, info.address).await?;
        state.update_group = outbound.update_group;
        state.effective_distribution_mode =
            effective_distribution_mode_to_proto(outbound.effective_distribution_mode).into();
        state.selection_deferral = selection_deferral_to_proto(outbound.selection_deferral);
        Ok(Response::new(state))
    }

    async fn enable_neighbor(
        &self,
        request: Request<proto::EnableNeighborRequest>,
    ) -> Result<Response<proto::EnableNeighborResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let req = request.into_inner();
        let peer = peer_key(&req.address, &req.interface)?;

        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::EnablePeer {
                peer,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;

        reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?
            .map_err(peer_lifecycle_error_status)?;

        Ok(Response::new(proto::EnableNeighborResponse {}))
    }

    async fn soft_reset_in(
        &self,
        request: Request<proto::SoftResetInRequest>,
    ) -> Result<Response<proto::SoftResetInResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let req = request.into_inner();
        let peer = peer_key(&req.address, &req.interface)?;

        // Empty means "all configured families" — pass empty vec through.
        // Transport filters to negotiated families before sending.
        let families = if req.families.is_empty() {
            vec![]
        } else {
            parse_families_proto(&req.families)?
        };

        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::SoftResetIn {
                peer,
                families,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;

        reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?
            .map_err(peer_lifecycle_error_status)?;

        Ok(Response::new(proto::SoftResetInResponse {}))
    }

    async fn disable_neighbor(
        &self,
        request: Request<proto::DisableNeighborRequest>,
    ) -> Result<Response<proto::DisableNeighborResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let req = request.into_inner();
        let peer = peer_key(&req.address, &req.interface)?;

        let reason = if req.reason.is_empty() {
            None
        } else {
            Some(rustbgpd_wire::notification::encode_shutdown_communication(
                &req.reason,
            ))
        };

        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::DisablePeer {
                peer,
                reason,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;

        reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?
            .map_err(peer_lifecycle_error_status)?;

        Ok(Response::new(proto::DisableNeighborResponse {}))
    }

    async fn list_dynamic_neighbors(
        &self,
        _request: Request<proto::ListDynamicNeighborsRequest>,
    ) -> Result<Response<proto::ListDynamicNeighborsResponse>, Status> {
        // Query the current dynamic neighbor ranges from PeerManager.
        // For now, return the ranges configured in the running config.
        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::ListDynamicRanges { reply: reply_tx })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;

        let ranges = reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?;

        let proto_ranges = ranges
            .into_iter()
            .map(|r| proto::DynamicNeighborRange {
                prefix: r.prefix,
                peer_group: r.peer_group,
                remote_asn: r.remote_asn,
                description: r.description,
            })
            .collect();

        Ok(Response::new(proto::ListDynamicNeighborsResponse {
            ranges: proto_ranges,
        }))
    }

    async fn add_dynamic_neighbor(
        &self,
        request: Request<proto::AddDynamicNeighborRequest>,
    ) -> Result<Response<proto::AddDynamicNeighborResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let range = request
            .into_inner()
            .range
            .ok_or_else(|| Status::invalid_argument("range is required"))?;
        if range.prefix.trim().is_empty() {
            return Err(Status::invalid_argument("range.prefix is required"));
        }
        if range.peer_group.trim().is_empty() {
            return Err(Status::invalid_argument("range.peer_group is required"));
        }
        let description = if range.description.is_empty() {
            None
        } else {
            Some(range.description.clone())
        };

        // Reserve config persistence capacity before mutating runtime state
        // (fail-fast when persistence is unavailable), mirroring AddNeighbor.
        let persist_permit = reserve_config_event_slot(self.config_tx.clone()).await?;

        let peer_mgr_tx = self.peer_mgr_tx.clone();
        let runtime_config_lock = self.runtime_config_lock.clone();
        let config_mutation_gate = self.config_mutation_gate.clone();
        let join = tokio::spawn(async move {
            let _guard = runtime_config_lock.lock().await;
            check_config_mutation_gate(&config_mutation_gate, "NeighborService.AddDynamicNeighbor")
                .await?;
            add_dynamic_range(
                &peer_mgr_tx,
                range.prefix.clone(),
                range.peer_group.clone(),
                range.remote_asn,
                description.clone(),
            )
            .await?;

            // Persist only after successful runtime mutation. This runs inside
            // the spawned task so a canceled gRPC request cannot split runtime
            // add from the queued config event. When persistence is configured,
            // keep the shared runtime-config lock held until the TOML write is
            // acknowledged; otherwise a concurrent SIGHUP could reload stale
            // disk and drop the accepted runtime add from the rebuilt matcher.
            if let Some(permit) = persist_permit
                && let Err(error) =
                    persist_runtime_config_event(permit, |ack| ConfigEvent::DynamicNeighborAdded {
                        prefix: range.prefix.clone(),
                        peer_group: range.peer_group.clone(),
                        remote_asn: range.remote_asn,
                        description: description.clone(),
                        ack: Some(ack),
                    })
                    .await
            {
                let rollback = delete_dynamic_range(&peer_mgr_tx, range.prefix.clone()).await;
                if let Err(rollback_error) = rollback {
                    return Err(Status::internal(format!(
                        "{error}; rollback of dynamic-neighbor add failed: {rollback_error}"
                    )));
                }
                return Err(error);
            }
            Ok::<(), Status>(())
        });
        join.await
            .map_err(|_| Status::internal("dynamic-neighbor add task did not complete"))??;

        Ok(Response::new(proto::AddDynamicNeighborResponse {}))
    }

    async fn delete_dynamic_neighbor(
        &self,
        request: Request<proto::DeleteDynamicNeighborRequest>,
    ) -> Result<Response<proto::DeleteDynamicNeighborResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let prefix = request.into_inner().prefix;
        if prefix.trim().is_empty() {
            return Err(Status::invalid_argument("prefix is required"));
        }

        let persist_permit = reserve_config_event_slot(self.config_tx.clone()).await?;

        let peer_mgr_tx = self.peer_mgr_tx.clone();
        let runtime_config_lock = self.runtime_config_lock.clone();
        let config_mutation_gate = self.config_mutation_gate.clone();
        let join = tokio::spawn(async move {
            let _guard = runtime_config_lock.lock().await;
            check_config_mutation_gate(
                &config_mutation_gate,
                "NeighborService.DeleteDynamicNeighbor",
            )
            .await?;
            let removed = delete_dynamic_range(&peer_mgr_tx, prefix.clone()).await?;

            // Queue persistence inside the spawned task so cancellation after
            // runtime delete cannot leave disk with the removed range. Hold the
            // shared runtime-config lock until the write is acknowledged so
            // SIGHUP cannot rebuild from stale TOML in the middle.
            if let Some(permit) = persist_permit
                && let Err(error) = persist_runtime_config_event(permit, |ack| {
                    ConfigEvent::DynamicNeighborDeleted {
                        prefix: prefix.clone(),
                        ack: Some(ack),
                    }
                })
                .await
            {
                let rollback = add_dynamic_range(
                    &peer_mgr_tx,
                    removed.prefix,
                    removed.peer_group,
                    removed.remote_asn,
                    removed.description,
                )
                .await;
                if let Err(rollback_error) = rollback {
                    return Err(Status::internal(format!(
                        "{error}; rollback of dynamic-neighbor delete failed: {rollback_error}"
                    )));
                }
                return Err(error);
            }
            Ok::<(), Status>(())
        });
        join.await
            .map_err(|_| Status::internal("dynamic-neighbor delete task did not complete"))??;

        Ok(Response::new(proto::DeleteDynamicNeighborResponse {}))
    }

    async fn set_graceful_shutdown(
        &self,
        request: Request<proto::SetGracefulShutdownRequest>,
    ) -> Result<Response<proto::SetGracefulShutdownResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let req = request.into_inner();
        // Empty address means broadcast to every currently-managed peer
        // (operator running planned maintenance on the whole router).
        let peer = if req.address.is_empty() {
            None
        } else {
            Some(peer_key(&req.address, &req.interface)?)
        };

        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::SetGracefulShutdown {
                peer,
                enabled: req.enabled,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;

        reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?
            .map_err(|e| match e {
                // PeerNotFound is the operator-typo case — distinguish
                // from session/RIB dispatch failures so clients can
                // react appropriately.
                crate::peer_types::SetGshutError::PeerNotFound(peer) => {
                    Status::not_found(format!("peer {peer} not found"))
                }
                crate::peer_types::SetGshutError::Internal(msg) => Status::internal(msg),
            })?;

        Ok(Response::new(proto::SetGracefulShutdownResponse {}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::peer_info;
    use proto::neighbor_service_server::NeighborService as _;
    use tokio::sync::mpsc::error::TryRecvError;

    fn make_service() -> NeighborService {
        let (tx, _rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        NeighborService::new(65001, AccessMode::ReadWrite, tx, rib_tx, None)
    }

    #[test]
    fn neighbor_observability_proto_fields_are_append_only() {
        let source = include_str!("../../../proto/rustbgpd.proto");
        assert!(source.contains("AuthenticationMode authentication = 27;"));
        assert!(source.contains("TcpAoState tcp_ao = 28;"));
        assert!(source.contains("TcpAoHealth tcp_ao_health = 29;"));
        assert!(source.contains("repeated TcpAoKeyState keys = 10;"));
        assert!(source.contains("message TcpAoKeyState {"));
        assert!(source.contains("EffectiveDistributionMode effective_distribution_mode = 30;"));
        assert!(source.contains("repeated SelectionDeferralFamilyState selection_deferral = 31;"));
        assert!(source.contains("message SelectionDeferralFamilyState {"));
        assert!(source.contains("optional uint32 effective_send_limit = 6;"));
    }

    fn test_static_peer_config() -> PeerManagerNeighborConfig {
        PeerManagerNeighborConfig {
            address: "10.0.0.2".parse().unwrap(),
            interface: None,
            scope_id: None,
            remote_asn: 65002,
            description: "static peer".to_string(),
            peer_group: None,
            hold_time: Some(90),
            send_hold_time: None,
            max_prefixes: None,
            md5_password: None,
            tcp_ao: None,
            ttl_security: false,
            families: vec![(Afi::Ipv4, Safi::Unicast)],
            graceful_restart: true,
            gr_restart_time: 120,
            gr_stale_routes_time: 360,
            llgr_stale_time: 0,
            gr_restart_eligible: false,
            local_ipv6_nexthop: None,
            route_reflector_client: false,
            orr_vantage: None,
            route_server_client: false,
            per_client_best: false,
            remove_private_as: RemovePrivateAs::Disabled,
            add_path_receive: false,
            add_path_send: false,
            add_path_send_max: 0,
            paths_limit_receive_max: 0,
            local_role: None,
            strict_role: false,
            prefix_orf_receive: false,
            disable_ipv4_unicast: false,
            import_policy: None,
            export_policy: None,
        }
    }

    #[test]
    fn peer_lifecycle_errors_map_by_variant() {
        let peer = PeerKey::new("10.0.0.2".parse().unwrap(), None);
        let cases = [
            (
                PeerLifecycleError::AlreadyExists(peer.clone()),
                tonic::Code::AlreadyExists,
            ),
            (PeerLifecycleError::NotFound(peer), tonic::Code::NotFound),
            (
                PeerLifecycleError::Invalid("bad input".to_string()),
                tonic::Code::InvalidArgument,
            ),
            (
                PeerLifecycleError::RestartRequired("restart required".to_string()),
                tonic::Code::FailedPrecondition,
            ),
            (
                PeerLifecycleError::Internal("session failed".to_string()),
                tonic::Code::Internal,
            ),
        ];

        for (error, code) in cases {
            assert_eq!(peer_lifecycle_error_status(error).code(), code);
        }
    }

    #[test]
    fn peer_key_rejects_link_local_without_interface() {
        let err = peer_key("fe80::1", "").unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("interface"));
    }

    #[test]
    fn peer_key_accepts_scoped_link_local() {
        let key = peer_key("fe80::1", "eth0").unwrap();
        assert_eq!(key.address, "fe80::1".parse::<IpAddr>().unwrap());
        assert_eq!(key.interface.as_deref(), Some("eth0"));
    }

    #[test]
    fn peer_key_rejects_numbered_with_interface() {
        let err = peer_key("192.0.2.1", "eth0").unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("only valid"));
    }

    #[tokio::test]
    async fn add_neighbor_rejects_asn_zero() {
        let svc = make_service();
        let req = Request::new(proto::AddNeighborRequest {
            config: Some(proto::NeighborConfig {
                address: "10.0.0.2".into(),
                interface: String::new(),
                remote_asn: 0,
                description: String::new(),
                hold_time: 90,
                max_prefixes: 0,
                families: Vec::new(),
                peer_group: String::new(),
                remove_private_as: String::new(),
                ..Default::default()
            }),
        });
        let err = svc.add_neighbor(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("remote_asn"));
    }

    #[tokio::test]
    async fn add_neighbor_rejects_hold_time_two() {
        let svc = make_service();
        let req = Request::new(proto::AddNeighborRequest {
            config: Some(proto::NeighborConfig {
                address: "10.0.0.2".into(),
                interface: String::new(),
                remote_asn: 65002,
                description: String::new(),
                hold_time: 2,
                max_prefixes: 0,
                families: Vec::new(),
                peer_group: String::new(),
                remove_private_as: String::new(),
                ..Default::default()
            }),
        });
        let err = svc.add_neighbor(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("hold_time"));
    }

    /// RFC 9687 §4.4 parity with the config path: a non-zero
    /// `send_hold_time` must exceed the effective hold time — both when
    /// `hold_time` is explicit and when it is the daemon default (90).
    #[tokio::test]
    async fn add_neighbor_rejects_send_hold_time_not_above_hold_time() {
        let svc = make_service();
        for (hold_time, send_hold_time) in [(90, 90), (0, 90), (120, 100)] {
            let req = Request::new(proto::AddNeighborRequest {
                config: Some(proto::NeighborConfig {
                    address: "10.0.0.2".into(),
                    remote_asn: 65002,
                    hold_time,
                    send_hold_time: Some(send_hold_time),
                    ..Default::default()
                }),
            });
            let err = svc.add_neighbor(req).await.unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
            assert!(
                err.message().contains("send_hold_time"),
                "hold {hold_time} / send-hold {send_hold_time}: {}",
                err.message()
            );
        }
    }

    #[tokio::test]
    async fn add_neighbor_forwards_send_hold_time() {
        let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let svc = NeighborService::new(65001, AccessMode::ReadWrite, peer_mgr_tx, rib_tx, None);

        let call = tokio::spawn(async move {
            svc.add_neighbor(Request::new(proto::AddNeighborRequest {
                config: Some(proto::NeighborConfig {
                    address: "10.0.0.2".into(),
                    remote_asn: 65002,
                    hold_time: 90,
                    // 0 = disabled is also valid (config-path parity).
                    send_hold_time: Some(0),
                    ..Default::default()
                }),
            }))
            .await
        });
        match peer_mgr_rx.recv().await.unwrap() {
            PeerManagerCommand::AddPeer { config, reply, .. } => {
                assert_eq!(config.send_hold_time, Some(0));
                reply.send(Ok(())).unwrap();
            }
            _ => panic!("expected AddPeer"),
        }
        call.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn add_neighbor_rejects_link_local_without_interface() {
        let svc = make_service();
        let req = Request::new(proto::AddNeighborRequest {
            config: Some(proto::NeighborConfig {
                address: "fe80::1".into(),
                interface: String::new(),
                remote_asn: 65002,
                description: String::new(),
                hold_time: 90,
                max_prefixes: 0,
                families: Vec::new(),
                peer_group: String::new(),
                remove_private_as: String::new(),
                ..Default::default()
            }),
        });
        let err = svc.add_neighbor(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("interface"));
    }

    #[tokio::test]
    async fn add_neighbor_rejects_numbered_peer_with_interface() {
        let svc = make_service();
        let req = Request::new(proto::AddNeighborRequest {
            config: Some(proto::NeighborConfig {
                address: "2001:db8::1".into(),
                interface: "eth0".into(),
                remote_asn: 65002,
                description: String::new(),
                hold_time: 90,
                max_prefixes: 0,
                families: Vec::new(),
                peer_group: String::new(),
                remove_private_as: String::new(),
                ..Default::default()
            }),
        });
        let err = svc.add_neighbor(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("link-local"));
    }

    #[tokio::test]
    async fn add_neighbor_rejected_on_read_only_listener() {
        let (tx, mut rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let svc = NeighborService::new(65001, AccessMode::ReadOnly, tx, rib_tx, None);
        let req = Request::new(proto::AddNeighborRequest {
            config: Some(proto::NeighborConfig {
                address: "10.0.0.2".into(),
                interface: String::new(),
                remote_asn: 65002,
                description: String::new(),
                hold_time: 90,
                max_prefixes: 0,
                families: Vec::new(),
                peer_group: String::new(),
                remove_private_as: String::new(),
                ..Default::default()
            }),
        });
        let err = svc.add_neighbor(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[tokio::test]
    async fn dynamic_neighbor_placeholders_rejected_on_read_only_listener() {
        let (tx, mut rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let svc = NeighborService::new(65001, AccessMode::ReadOnly, tx, rib_tx, None);

        let err = svc
            .add_dynamic_neighbor(Request::new(proto::AddDynamicNeighborRequest {
                range: None,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let err = svc
            .delete_dynamic_neighbor(Request::new(proto::DeleteDynamicNeighborRequest {
                prefix: "192.0.2.0/24".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[tokio::test]
    async fn add_dynamic_neighbor_persists_after_runtime_success() {
        let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let (config_tx, mut config_rx) = mpsc::channel(16);
        let svc = NeighborService::new(
            65001,
            AccessMode::ReadWrite,
            peer_mgr_tx,
            rib_tx,
            Some(config_tx),
        );

        let mut call = tokio::spawn(async move {
            svc.add_dynamic_neighbor(Request::new(proto::AddDynamicNeighborRequest {
                range: Some(proto::DynamicNeighborRange {
                    prefix: "192.0.2.0/24".to_string(),
                    peer_group: "fabric".to_string(),
                    remote_asn: 65002,
                    description: "lab range".to_string(),
                }),
            }))
            .await
            .unwrap();
        });

        match peer_mgr_rx.recv().await.unwrap() {
            PeerManagerCommand::AddDynamicRange {
                prefix,
                peer_group,
                remote_asn,
                description,
                reply,
            } => {
                assert_eq!(prefix, "192.0.2.0/24");
                assert_eq!(peer_group, "fabric");
                assert_eq!(remote_asn, 65002);
                assert_eq!(description.as_deref(), Some("lab range"));
                reply.send(Ok(())).unwrap();
            }
            _ => panic!("expected AddDynamicRange"),
        }

        match config_rx.recv().await.unwrap() {
            ConfigEvent::DynamicNeighborAdded {
                prefix,
                peer_group,
                remote_asn,
                description,
                ack,
            } => {
                assert_eq!(prefix, "192.0.2.0/24");
                assert_eq!(peer_group, "fabric");
                assert_eq!(remote_asn, 65002);
                assert_eq!(description.as_deref(), Some("lab range"));
                let ack = ack.unwrap();
                assert!(
                    tokio::time::timeout(Duration::from_millis(20), &mut call)
                        .await
                        .is_err(),
                    "call must wait for config persistence acknowledgement"
                );
                ack.send(Ok(())).unwrap();
            }
            _ => panic!("expected DynamicNeighborAdded"),
        }
        call.await.unwrap();
    }

    #[tokio::test]
    async fn add_dynamic_neighbor_rolls_back_when_persist_fails() {
        let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let (config_tx, mut config_rx) = mpsc::channel(16);
        let svc = NeighborService::new(
            65001,
            AccessMode::ReadWrite,
            peer_mgr_tx,
            rib_tx,
            Some(config_tx),
        );

        let call = tokio::spawn(async move {
            svc.add_dynamic_neighbor(Request::new(proto::AddDynamicNeighborRequest {
                range: Some(proto::DynamicNeighborRange {
                    prefix: "192.0.2.0/24".to_string(),
                    peer_group: "fabric".to_string(),
                    remote_asn: 65002,
                    description: "lab range".to_string(),
                }),
            }))
            .await
        });

        match peer_mgr_rx.recv().await.unwrap() {
            PeerManagerCommand::AddDynamicRange { reply, .. } => {
                reply.send(Ok(())).unwrap();
            }
            _ => panic!("expected AddDynamicRange"),
        }
        match config_rx.recv().await.unwrap() {
            ConfigEvent::DynamicNeighborAdded { ack, .. } => {
                ack.unwrap()
                    .send(Err("disk full".to_string()))
                    .expect("send persist failure");
            }
            _ => panic!("expected DynamicNeighborAdded"),
        }
        match peer_mgr_rx.recv().await.unwrap() {
            PeerManagerCommand::DeleteDynamicRange { prefix, reply } => {
                assert_eq!(prefix, "192.0.2.0/24");
                reply
                    .send(Ok(RemovedDynamicRange {
                        prefix,
                        peer_group: "fabric".to_string(),
                        remote_asn: 65002,
                        description: Some("lab range".to_string()),
                    }))
                    .unwrap();
            }
            _ => panic!("expected DeleteDynamicRange rollback"),
        }

        let err = call.await.unwrap().unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("config persistence failed"));
    }

    #[tokio::test]
    async fn add_dynamic_neighbor_unknown_peer_group_maps_not_found() {
        let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let svc = NeighborService::new(65001, AccessMode::ReadWrite, peer_mgr_tx, rib_tx, None);

        let call = tokio::spawn(async move {
            svc.add_dynamic_neighbor(Request::new(proto::AddDynamicNeighborRequest {
                range: Some(proto::DynamicNeighborRange {
                    prefix: "192.0.2.0/24".to_string(),
                    peer_group: "missing".to_string(),
                    remote_asn: 65002,
                    description: String::new(),
                }),
            }))
            .await
        });

        match peer_mgr_rx.recv().await.unwrap() {
            PeerManagerCommand::AddDynamicRange { reply, .. } => {
                reply
                    .send(Err(DynamicRangeError::NotFound(
                        "peer_group \"missing\" not defined".to_string(),
                    )))
                    .unwrap();
            }
            _ => panic!("expected AddDynamicRange"),
        }

        let err = call.await.unwrap().unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn delete_dynamic_neighbor_persists_after_runtime_success() {
        let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let (config_tx, mut config_rx) = mpsc::channel(16);
        let svc = NeighborService::new(
            65001,
            AccessMode::ReadWrite,
            peer_mgr_tx,
            rib_tx,
            Some(config_tx),
        );

        let mut call = tokio::spawn(async move {
            svc.delete_dynamic_neighbor(Request::new(proto::DeleteDynamicNeighborRequest {
                prefix: "192.0.2.0/24".to_string(),
            }))
            .await
            .unwrap();
        });

        match peer_mgr_rx.recv().await.unwrap() {
            PeerManagerCommand::DeleteDynamicRange { prefix, reply } => {
                assert_eq!(prefix, "192.0.2.0/24");
                reply
                    .send(Ok(RemovedDynamicRange {
                        prefix,
                        peer_group: "fabric".to_string(),
                        remote_asn: 65002,
                        description: Some("lab range".to_string()),
                    }))
                    .unwrap();
            }
            _ => panic!("expected DeleteDynamicRange"),
        }

        match config_rx.recv().await.unwrap() {
            ConfigEvent::DynamicNeighborDeleted { prefix, ack } => {
                assert_eq!(prefix, "192.0.2.0/24");
                let ack = ack.unwrap();
                assert!(
                    tokio::time::timeout(Duration::from_millis(20), &mut call)
                        .await
                        .is_err(),
                    "call must wait for config persistence acknowledgement"
                );
                ack.send(Ok(())).unwrap();
            }
            _ => panic!("expected DynamicNeighborDeleted"),
        }
        call.await.unwrap();
    }

    #[tokio::test]
    async fn delete_dynamic_neighbor_rolls_back_when_persist_fails() {
        let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let (config_tx, mut config_rx) = mpsc::channel(16);
        let svc = NeighborService::new(
            65001,
            AccessMode::ReadWrite,
            peer_mgr_tx,
            rib_tx,
            Some(config_tx),
        );

        let call = tokio::spawn(async move {
            svc.delete_dynamic_neighbor(Request::new(proto::DeleteDynamicNeighborRequest {
                prefix: "192.0.2.0/24".to_string(),
            }))
            .await
        });

        let removed = RemovedDynamicRange {
            prefix: "192.0.2.0/24".to_string(),
            peer_group: "fabric".to_string(),
            remote_asn: 65002,
            description: Some("lab range".to_string()),
        };
        match peer_mgr_rx.recv().await.unwrap() {
            PeerManagerCommand::DeleteDynamicRange { prefix, reply } => {
                assert_eq!(prefix, "192.0.2.0/24");
                reply.send(Ok(removed.clone())).unwrap();
            }
            _ => panic!("expected DeleteDynamicRange"),
        }
        match config_rx.recv().await.unwrap() {
            ConfigEvent::DynamicNeighborDeleted { ack, .. } => {
                ack.unwrap()
                    .send(Err("disk full".to_string()))
                    .expect("send persist failure");
            }
            _ => panic!("expected DynamicNeighborDeleted"),
        }
        match peer_mgr_rx.recv().await.unwrap() {
            PeerManagerCommand::AddDynamicRange {
                prefix,
                peer_group,
                remote_asn,
                description,
                reply,
            } => {
                assert_eq!(prefix, removed.prefix);
                assert_eq!(peer_group, removed.peer_group);
                assert_eq!(remote_asn, removed.remote_asn);
                assert_eq!(description, removed.description);
                reply.send(Ok(())).unwrap();
            }
            _ => panic!("expected AddDynamicRange rollback"),
        }

        let err = call.await.unwrap().unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("config persistence failed"));
    }

    #[tokio::test]
    async fn lifecycle_mutations_rejected_on_read_only_listener() {
        let (tx, mut rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let svc = NeighborService::new(65001, AccessMode::ReadOnly, tx, rib_tx, None);

        let err = svc
            .delete_neighbor(Request::new(proto::DeleteNeighborRequest {
                address: "10.0.0.2".into(),
                interface: String::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let err = svc
            .enable_neighbor(Request::new(proto::EnableNeighborRequest {
                address: "10.0.0.2".into(),
                interface: String::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let err = svc
            .disable_neighbor(Request::new(proto::DisableNeighborRequest {
                address: "10.0.0.2".into(),
                interface: String::new(),
                reason: "maintenance".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let err = svc
            .soft_reset_in(Request::new(proto::SoftResetInRequest {
                address: "10.0.0.2".into(),
                interface: String::new(),
                families: Vec::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let err = svc
            .set_graceful_shutdown(Request::new(proto::SetGracefulShutdownRequest {
                address: "10.0.0.2".into(),
                interface: String::new(),
                enabled: true,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[test]
    fn parse_families_proto_deduplicates() {
        let families = vec![
            "ipv4_unicast".to_string(),
            "ipv4_unicast".to_string(),
            "ipv6_unicast".to_string(),
            "ipv6_unicast".to_string(),
        ];
        let parsed = parse_families_proto(&families).unwrap();
        assert_eq!(
            parsed,
            vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)]
        );
    }

    #[tokio::test]
    async fn soft_reset_in_deduplicates_requested_families() {
        let (peer_tx, mut peer_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let svc = NeighborService::new(65001, AccessMode::ReadWrite, peer_tx, rib_tx, None);

        tokio::spawn(async move {
            if let Some(PeerManagerCommand::SoftResetIn {
                families, reply, ..
            }) = peer_rx.recv().await
            {
                assert_eq!(
                    families,
                    vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)]
                );
                let _ = reply.send(Ok(()));
            }
        });

        let req = Request::new(proto::SoftResetInRequest {
            address: "10.0.0.2".into(),
            interface: String::new(),
            families: vec![
                "ipv4_unicast".into(),
                "ipv4_unicast".into(),
                "ipv6_unicast".into(),
                "ipv6_unicast".into(),
            ],
        });
        let resp = svc.soft_reset_in(req).await.unwrap();
        let _ = resp.into_inner();
    }

    #[tokio::test]
    async fn prefixes_sent_populated() {
        let (peer_tx, mut peer_rx) = mpsc::channel(16);
        let (rib_tx, mut rib_rx) = mpsc::channel(16);
        let svc = NeighborService::new(65001, AccessMode::ReadWrite, peer_tx, rib_tx, None);

        let addr: std::net::IpAddr = "10.0.0.1".parse().unwrap();

        // Spawn responders
        tokio::spawn(async move {
            if let Some(PeerManagerCommand::GetPeerState { reply, .. }) = peer_rx.recv().await {
                let mut info = peer_info(addr);
                info.remote_asn = 65001;
                info.prefix_count = 5;
                info.families = vec![(Afi::Ipv4, Safi::Unicast)];
                let _ = reply.send(Some(info));
            }
        });

        tokio::spawn(async move {
            while let Some(cmd) = rib_rx.recv().await {
                match cmd {
                    RibUpdate::QueryAdvertisedCount { reply, .. } => {
                        let _ = reply.send(7);
                    }
                    RibUpdate::QueryNeighborPolicyStats { reply, .. } => {
                        let _ = reply.send(rustbgpd_rib::NeighborPolicyStats {
                            export_policy_routes_permitted: 3,
                            export_policy_routes_denied: 4,
                            ..Default::default()
                        });
                    }
                    RibUpdate::QueryPeerOutboundState { reply, .. } => {
                        let _ = reply.send(PeerOutboundState {
                            update_group: "group:0".to_string(),
                            effective_distribution_mode: EffectiveDistributionMode::AddPath,
                            selection_deferral: vec![
                                rustbgpd_rib::SelectionDeferralPeerFamilyState {
                                    afi: Afi::Ipv4,
                                    safi: Safi::Unicast,
                                    active: true,
                                    waiter_state: "awaiting_eor".to_string(),
                                    waiter_session_id: Some(42),
                                    blocking_waiters: 2,
                                    remaining_millis: 1_500,
                                    release_reason: String::new(),
                                },
                            ],
                        });
                    }
                    _ => {}
                }
            }
        });

        let resp = svc
            .get_neighbor_state(Request::new(proto::GetNeighborStateRequest {
                address: "10.0.0.1".into(),
                interface: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(resp.prefixes_sent, 7);
        assert_eq!(resp.export_policy_routes_permitted, 3);
        assert_eq!(resp.export_policy_routes_denied, 4);
        assert_eq!(resp.update_group, "group:0");
        assert_eq!(
            resp.effective_distribution_mode,
            proto::EffectiveDistributionMode::AddPath as i32
        );
        assert_eq!(resp.selection_deferral.len(), 1);
        assert_eq!(resp.selection_deferral[0].afi, Afi::Ipv4 as u32);
        assert_eq!(resp.selection_deferral[0].safi, Safi::Unicast as u32);
        assert!(resp.selection_deferral[0].active);
        assert_eq!(resp.selection_deferral[0].waiter_state, "awaiting_eor");
        assert_eq!(resp.selection_deferral[0].waiter_session_id, Some(42));
        assert_eq!(resp.selection_deferral[0].blocking_waiters, 2);
        assert_eq!(resp.selection_deferral[0].remaining_millis, 1_500);
    }

    #[test]
    fn peer_info_to_proto_includes_families() {
        let mut info = peer_info("10.0.0.1".parse().unwrap());
        info.remote_asn = 65001;
        info.families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
        info.remove_private_as = RemovePrivateAs::All;
        info.local_role = Some(BgpRole::RouteServer);
        info.strict_role = true;
        info.remote_role = Some(BgpRole::RouteServerClient);
        info.role_negotiated = true;
        info.otc_routes_blocked = 3;
        info.import_policy_routes_permitted = 11;
        info.import_policy_routes_denied = 12;
        info.export_policy_routes_permitted = 13;
        info.export_policy_routes_denied = 14;
        let state = peer_info_to_proto(&info);
        let config = state.config.unwrap();
        assert_eq!(config.families, vec!["ipv4_unicast", "ipv6_unicast"]);
        assert_eq!(config.remove_private_as, "all");
        assert_eq!(config.role, "rs");
        assert!(config.strict_role);
        assert_eq!(state.local_role, "rs");
        assert_eq!(state.remote_role, "rs-client");
        assert!(state.role_negotiated);
        assert_eq!(state.otc_routes_blocked, 3);
        assert_eq!(state.import_policy_routes_permitted, 11);
        assert_eq!(state.import_policy_routes_denied, 12);
        assert_eq!(state.export_policy_routes_permitted, 13);
        assert_eq!(state.export_policy_routes_denied, 14);
    }

    /// LAN-322: total message counters and the RR-client flag cross the
    /// `PeerInfo` → proto boundary intact.
    #[test]
    fn peer_info_to_proto_carries_message_totals_and_rr_client() {
        let mut info = peer_info("10.0.0.1".parse().unwrap());
        info.messages_received = 4321;
        info.messages_sent = 1234;
        info.route_reflector_client = true;
        let state = peer_info_to_proto(&info);
        assert_eq!(state.messages_received, 4321);
        assert_eq!(state.messages_sent, 1234);
        assert!(state.route_reflector_client);
    }

    #[test]
    fn paths_limit_output_is_numeric_ordered_and_normalizes_active_unlimited() {
        let mut info = peer_info("10.0.0.1".parse().unwrap());
        info.families = vec![(Afi::Ipv6, Safi::Unicast), (Afi::Ipv4, Safi::Unicast)];
        info.paths_limit_receive_max = 3;
        info.peer_paths_limits = vec![
            ((Afi::L2Vpn, Safi::Evpn), 9),
            ((Afi::Ipv6, Safi::Unicast), 4),
        ];
        info.effective_add_path_send_limits = vec![
            ((Afi::Ipv6, Safi::Unicast), 2),
            ((Afi::Ipv4, Safi::Unicast), u32::MAX),
        ];

        let paths = peer_info_to_proto(&info).paths_limits;

        assert_eq!(
            paths
                .iter()
                .map(|row| row.family.as_str())
                .collect::<Vec<_>>(),
            vec!["ipv4_unicast", "ipv6_unicast", "L2Vpn_Evpn"]
        );
        assert_eq!(paths[0].effective_send_max, u32::MAX);
        assert_eq!(paths[0].effective_send_limit, Some(0));
        assert_eq!(paths[1].effective_send_max, 2);
        assert_eq!(paths[1].effective_send_limit, Some(2));
        assert_eq!(paths[2].effective_send_max, 0);
        assert_eq!(paths[2].effective_send_limit, None);
        assert_eq!(paths[2].configured_receive_max, 0);
        assert_eq!(paths[2].advertised_receive_max, 0);
    }

    #[test]
    fn peer_info_to_proto_carries_tcp_ao_health_without_inventing_key_ids() {
        let mut info = peer_info("10.0.0.1".parse().unwrap());
        info.authentication = "tcp_ao".to_string();
        info.tcp_ao_info = Some(rustbgpd_transport::TcpAoInfoSnapshot {
            has_current_key: true,
            has_rnext_key: false,
            ao_required: true,
            accept_icmps: false,
            current_key: 7,
            rnext_key: 0,
            pkt_good: 21,
            pkt_bad: 1,
            pkt_key_not_found: 2,
            pkt_ao_required: 3,
            pkt_dropped_icmp: 4,
            keys: vec![rustbgpd_transport::TcpAoKeyState {
                peer: "10.0.0.1".parse().unwrap(),
                prefix_len: 32,
                send_id: 7,
                recv_id: 9,
                algorithm: rustbgpd_transport::TcpAoAlgorithm::HmacSha256,
                is_current: true,
                is_rnext: false,
                preferred: true,
                deprecated: false,
                vrf_ifindex: None,
                pkt_good: 21,
                pkt_bad: 1,
            }],
        });
        let state = peer_info_to_proto(&info);
        assert_eq!(
            state.authentication,
            proto::AuthenticationMode::TcpAo as i32
        );
        let ao = state.tcp_ao.unwrap();
        assert_eq!(ao.current_key_id, Some(7));
        assert_eq!(ao.rnext_key_id, None);
        assert_eq!(ao.packets_good, 21);
        assert_eq!(ao.packets_bad, 1);
        assert_eq!(ao.packets_key_not_found, 2);
        assert_eq!(ao.packets_ao_required, 3);
        assert_eq!(ao.packets_dropped_icmp, 4);
        assert_eq!(ao.keys.len(), 1);
        assert_eq!(ao.keys[0].peer_address, "10.0.0.1");
        assert_eq!(ao.keys[0].algorithm, "hmac(sha256)");
        assert!(ao.keys[0].preferred);
        assert_eq!(ao.keys[0].vrf_ifindex, None);
        assert_eq!(state.tcp_ao_health, proto::TcpAoHealth::Degraded as i32);
    }

    #[test]
    fn peer_info_to_proto_reports_tcp_ao_unavailable_without_socket_snapshot() {
        let mut info = peer_info("10.0.0.1".parse().unwrap());
        info.authentication = "tcp_ao".to_string();
        info.tcp_ao_info = None;

        let state = peer_info_to_proto(&info);

        assert_eq!(
            state.authentication,
            proto::AuthenticationMode::TcpAo as i32
        );
        assert_eq!(state.tcp_ao_health, proto::TcpAoHealth::Unavailable as i32);
        assert!(state.tcp_ao.is_none());
    }

    #[test]
    fn tcp_ao_missing_current_key_degrades_clean_counters() {
        let mut info = peer_info("10.0.0.1".parse().unwrap());
        info.authentication = "tcp_ao".to_string();
        info.tcp_ao_info = Some(rustbgpd_transport::TcpAoInfoSnapshot {
            has_current_key: false,
            has_rnext_key: true,
            ao_required: false,
            accept_icmps: false,
            current_key: 0,
            rnext_key: 9,
            pkt_good: 20,
            pkt_bad: 0,
            pkt_key_not_found: 0,
            pkt_ao_required: 0,
            pkt_dropped_icmp: 0,
            keys: Vec::new(),
        });
        assert_eq!(
            peer_info_to_proto(&info).tcp_ao_health,
            proto::TcpAoHealth::Degraded as i32
        );
    }

    #[test]
    fn tcp_ao_missing_rnext_key_degrades_clean_counters() {
        let mut info = peer_info("10.0.0.1".parse().unwrap());
        info.authentication = "tcp_ao".to_string();
        info.tcp_ao_info = Some(rustbgpd_transport::TcpAoInfoSnapshot {
            has_current_key: true,
            has_rnext_key: false,
            ao_required: false,
            accept_icmps: false,
            current_key: 7,
            rnext_key: 0,
            pkt_good: 20,
            pkt_bad: 0,
            pkt_key_not_found: 0,
            pkt_ao_required: 0,
            pkt_dropped_icmp: 0,
            keys: Vec::new(),
        });
        assert_eq!(
            peer_info_to_proto(&info).tcp_ao_health,
            proto::TcpAoHealth::Degraded as i32
        );
    }

    #[test]
    fn peer_info_to_proto_reports_tcp_ao_health_not_applicable_for_plaintext() {
        let info = peer_info("10.0.0.1".parse().unwrap());

        let state = peer_info_to_proto(&info);

        assert_eq!(
            state.tcp_ao_health,
            proto::TcpAoHealth::NotApplicable as i32
        );
    }

    #[test]
    fn peer_info_to_proto_does_not_misreport_unknown_authentication_as_plaintext() {
        let mut info = peer_info("10.0.0.1".parse().unwrap());
        info.authentication = "future_auth_mode".to_string();

        let state = peer_info_to_proto(&info);

        assert_eq!(
            state.authentication,
            proto::AuthenticationMode::Unspecified as i32
        );
    }

    #[test]
    fn peer_info_to_proto_reports_clean_tcp_ao_snapshot_as_healthy() {
        let mut info = peer_info("10.0.0.1".parse().unwrap());
        info.authentication = "tcp_ao".to_string();
        info.tcp_ao_info = Some(rustbgpd_transport::TcpAoInfoSnapshot {
            has_current_key: true,
            has_rnext_key: true,
            ao_required: true,
            accept_icmps: false,
            current_key: 7,
            rnext_key: 9,
            pkt_good: 20,
            pkt_bad: 0,
            pkt_key_not_found: 0,
            pkt_ao_required: 0,
            pkt_dropped_icmp: 0,
            keys: vec![rustbgpd_transport::TcpAoKeyState {
                peer: "10.0.0.1".parse().unwrap(),
                prefix_len: 32,
                send_id: 7,
                recv_id: 9,
                algorithm: rustbgpd_transport::TcpAoAlgorithm::HmacSha256,
                is_current: true,
                is_rnext: true,
                preferred: true,
                deprecated: false,
                vrf_ifindex: None,
                pkt_good: 20,
                pkt_bad: 0,
            }],
        });

        let state = peer_info_to_proto(&info);

        assert_eq!(state.tcp_ao_health, proto::TcpAoHealth::Healthy as i32);
    }

    #[test]
    fn active_deprecated_tcp_ao_key_is_degraded() {
        let mut info = peer_info("10.0.0.1".parse().unwrap());
        info.authentication = "tcp_ao".to_string();
        let mut snapshot = rustbgpd_transport::TcpAoInfoSnapshot {
            has_current_key: true,
            has_rnext_key: true,
            ao_required: true,
            accept_icmps: false,
            current_key: 7,
            rnext_key: 9,
            pkt_good: 20,
            pkt_bad: 0,
            pkt_key_not_found: 0,
            pkt_ao_required: 0,
            pkt_dropped_icmp: 0,
            keys: vec![rustbgpd_transport::TcpAoKeyState {
                peer: "10.0.0.1".parse().unwrap(),
                prefix_len: 32,
                send_id: 7,
                recv_id: 9,
                algorithm: rustbgpd_transport::TcpAoAlgorithm::HmacSha256,
                is_current: true,
                is_rnext: true,
                preferred: false,
                deprecated: true,
                vrf_ifindex: None,
                pkt_good: 20,
                pkt_bad: 0,
            }],
        };
        info.tcp_ao_info = Some(snapshot.clone());
        assert_eq!(
            peer_info_to_proto(&info).tcp_ao_health,
            proto::TcpAoHealth::Degraded as i32
        );
        snapshot.keys[0].deprecated = false;
        snapshot.pkt_dropped_icmp = 1;
        info.tcp_ao_info = Some(snapshot);
        assert_eq!(
            peer_info_to_proto(&info).tcp_ao_health,
            proto::TcpAoHealth::Degraded as i32
        );
    }

    #[test]
    fn established_tcp_ao_peer_with_failed_inspection_is_unavailable() {
        let mut info = peer_info("10.0.0.1".parse().unwrap());
        info.authentication = "tcp_ao".to_string();
        info.tcp_ao_info = None;

        let state = peer_info_to_proto(&info);

        assert_eq!(state.state, proto::SessionState::Established as i32);
        assert_eq!(state.tcp_ao_health, proto::TcpAoHealth::Unavailable as i32);
        assert!(state.tcp_ao.is_none());
    }

    #[tokio::test]
    async fn add_neighbor_persists_after_runtime_success() {
        let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let (config_tx, mut config_rx) = mpsc::channel(16);
        let svc = NeighborService::new(
            65001,
            AccessMode::ReadWrite,
            peer_mgr_tx,
            rib_tx,
            Some(config_tx),
        );

        let mut call = tokio::spawn(async move {
            svc.add_neighbor(Request::new(proto::AddNeighborRequest {
                config: Some(proto::NeighborConfig {
                    address: "10.0.0.2".into(),
                    interface: String::new(),
                    remote_asn: 65002,
                    description: "static peer".into(),
                    hold_time: 90,
                    max_prefixes: 0,
                    families: vec!["ipv4_unicast".into()],
                    peer_group: String::new(),
                    remove_private_as: String::new(),
                    ..Default::default()
                }),
            }))
            .await
        });

        match peer_mgr_rx.recv().await.unwrap() {
            PeerManagerCommand::AddPeer {
                config,
                sync_config_snapshot,
                reply,
            } => {
                assert_eq!(config.address.to_string(), "10.0.0.2");
                assert!(sync_config_snapshot);
                reply.send(Ok(())).unwrap();
            }
            _ => panic!("expected AddPeer"),
        }

        match config_rx.recv().await.unwrap() {
            ConfigEvent::NeighborAdded { config, ack } => {
                assert_eq!(config.address.to_string(), "10.0.0.2");
                let ack = ack.unwrap();
                assert!(
                    tokio::time::timeout(Duration::from_millis(20), &mut call)
                        .await
                        .is_err(),
                    "call must wait for config persistence acknowledgement"
                );
                ack.send(Ok(())).unwrap();
            }
            _ => panic!("expected NeighborAdded"),
        }
        call.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn add_neighbor_rolls_back_when_persist_fails() {
        let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let (config_tx, mut config_rx) = mpsc::channel(16);
        let svc = NeighborService::new(
            65001,
            AccessMode::ReadWrite,
            peer_mgr_tx,
            rib_tx,
            Some(config_tx),
        );

        let call = tokio::spawn(async move {
            svc.add_neighbor(Request::new(proto::AddNeighborRequest {
                config: Some(proto::NeighborConfig {
                    address: "10.0.0.2".into(),
                    interface: String::new(),
                    remote_asn: 65002,
                    description: "static peer".into(),
                    hold_time: 90,
                    max_prefixes: 0,
                    families: vec!["ipv4_unicast".into()],
                    peer_group: String::new(),
                    remove_private_as: String::new(),
                    ..Default::default()
                }),
            }))
            .await
        });

        match peer_mgr_rx.recv().await.unwrap() {
            PeerManagerCommand::AddPeer { reply, .. } => {
                reply.send(Ok(())).unwrap();
            }
            _ => panic!("expected AddPeer"),
        }
        match config_rx.recv().await.unwrap() {
            ConfigEvent::NeighborAdded { ack, .. } => {
                ack.unwrap()
                    .send(Err("disk full".to_string()))
                    .expect("send persist failure");
            }
            _ => panic!("expected NeighborAdded"),
        }
        match peer_mgr_rx.recv().await.unwrap() {
            PeerManagerCommand::DeletePeer {
                peer,
                sync_config_snapshot,
                reply,
            } => {
                assert_eq!(peer.address.to_string(), "10.0.0.2");
                assert!(sync_config_snapshot);
                assert!(reply.send(Ok(test_static_peer_config())).is_ok());
            }
            _ => panic!("expected DeletePeer rollback"),
        }

        let err = call.await.unwrap().unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("config persistence failed"));
    }

    #[tokio::test]
    async fn delete_neighbor_persists_after_runtime_success() {
        let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let (config_tx, mut config_rx) = mpsc::channel(16);
        let svc = NeighborService::new(
            65001,
            AccessMode::ReadWrite,
            peer_mgr_tx,
            rib_tx,
            Some(config_tx),
        );

        let mut call = tokio::spawn(async move {
            svc.delete_neighbor(Request::new(proto::DeleteNeighborRequest {
                address: "10.0.0.2".into(),
                interface: String::new(),
            }))
            .await
        });

        match peer_mgr_rx.recv().await.unwrap() {
            PeerManagerCommand::DeletePeer {
                peer,
                sync_config_snapshot,
                reply,
            } => {
                assert_eq!(peer.address.to_string(), "10.0.0.2");
                assert!(!sync_config_snapshot);
                assert!(reply.send(Ok(test_static_peer_config())).is_ok());
            }
            _ => panic!("expected DeletePeer"),
        }

        match config_rx.recv().await.unwrap() {
            ConfigEvent::NeighborDeleted { peer, ack } => {
                assert_eq!(peer.address.to_string(), "10.0.0.2");
                let ack = ack.unwrap();
                assert!(
                    tokio::time::timeout(Duration::from_millis(20), &mut call)
                        .await
                        .is_err(),
                    "call must wait for config persistence acknowledgement"
                );
                ack.send(Ok(())).unwrap();
            }
            _ => panic!("expected NeighborDeleted"),
        }
        match peer_mgr_rx.recv().await.unwrap() {
            PeerManagerCommand::ApplyConfigEvent { event, reply } => {
                assert!(matches!(event, ConfigEvent::NeighborDeleted { .. }));
                reply.send(Ok(())).unwrap();
            }
            _ => panic!("expected ApplyConfigEvent"),
        }
        call.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn delete_neighbor_succeeds_when_snapshot_update_fails_after_persist() {
        let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let (config_tx, mut config_rx) = mpsc::channel(16);
        let svc = NeighborService::new(
            65001,
            AccessMode::ReadWrite,
            peer_mgr_tx,
            rib_tx,
            Some(config_tx),
        );

        let call = tokio::spawn(async move {
            svc.delete_neighbor(Request::new(proto::DeleteNeighborRequest {
                address: "10.0.0.2".into(),
                interface: String::new(),
            }))
            .await
        });

        match peer_mgr_rx.recv().await.unwrap() {
            PeerManagerCommand::DeletePeer {
                sync_config_snapshot,
                reply,
                ..
            } => {
                assert!(!sync_config_snapshot);
                assert!(reply.send(Ok(test_static_peer_config())).is_ok());
            }
            _ => panic!("expected DeletePeer"),
        }
        match config_rx.recv().await.unwrap() {
            ConfigEvent::NeighborDeleted { ack, .. } => {
                ack.unwrap()
                    .send(Ok(()))
                    .expect("send persist acknowledgement");
            }
            _ => panic!("expected NeighborDeleted"),
        }
        match peer_mgr_rx.recv().await.unwrap() {
            PeerManagerCommand::ApplyConfigEvent { reply, .. } => {
                reply
                    .send(Err("peer manager shutting down".to_string()))
                    .unwrap();
            }
            _ => panic!("expected ApplyConfigEvent"),
        }

        call.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn delete_neighbor_rolls_back_when_persist_fails() {
        let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let (config_tx, mut config_rx) = mpsc::channel(16);
        let svc = NeighborService::new(
            65001,
            AccessMode::ReadWrite,
            peer_mgr_tx,
            rib_tx,
            Some(config_tx),
        );

        let removed = test_static_peer_config();
        let call = tokio::spawn(async move {
            svc.delete_neighbor(Request::new(proto::DeleteNeighborRequest {
                address: "10.0.0.2".into(),
                interface: String::new(),
            }))
            .await
        });

        match peer_mgr_rx.recv().await.unwrap() {
            PeerManagerCommand::DeletePeer {
                sync_config_snapshot,
                reply,
                ..
            } => {
                assert!(!sync_config_snapshot);
                assert!(reply.send(Ok(removed.clone())).is_ok());
            }
            _ => panic!("expected DeletePeer"),
        }
        match config_rx.recv().await.unwrap() {
            ConfigEvent::NeighborDeleted { ack, .. } => {
                ack.unwrap()
                    .send(Err("disk full".to_string()))
                    .expect("send persist failure");
            }
            _ => panic!("expected NeighborDeleted"),
        }
        match peer_mgr_rx.recv().await.unwrap() {
            PeerManagerCommand::AddPeer {
                config,
                sync_config_snapshot,
                reply,
            } => {
                assert_eq!(config.address, removed.address);
                assert_eq!(config.remote_asn, removed.remote_asn);
                assert!(sync_config_snapshot);
                reply.send(Ok(())).unwrap();
            }
            _ => panic!("expected AddPeer rollback"),
        }

        let err = call.await.unwrap().unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("config persistence failed"));
    }

    #[tokio::test]
    async fn add_neighbor_fails_when_config_persistence_unavailable() {
        let (peer_tx, mut peer_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let (config_tx, config_rx) = mpsc::channel(1);
        drop(config_rx);
        let svc = NeighborService::new(
            65001,
            AccessMode::ReadWrite,
            peer_tx,
            rib_tx,
            Some(config_tx),
        );

        let req = Request::new(proto::AddNeighborRequest {
            config: Some(proto::NeighborConfig {
                address: "10.0.0.2".into(),
                interface: String::new(),
                remote_asn: 65002,
                description: String::new(),
                hold_time: 90,
                max_prefixes: 0,
                families: Vec::new(),
                peer_group: String::new(),
                remove_private_as: String::new(),
                ..Default::default()
            }),
        });
        let err = svc.add_neighbor(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unavailable);
        assert!(matches!(peer_rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[tokio::test]
    async fn delete_neighbor_fails_when_config_persistence_unavailable() {
        let (peer_tx, mut peer_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let (config_tx, config_rx) = mpsc::channel(1);
        drop(config_rx);
        let svc = NeighborService::new(
            65001,
            AccessMode::ReadWrite,
            peer_tx,
            rib_tx,
            Some(config_tx),
        );

        let req = Request::new(proto::DeleteNeighborRequest {
            address: "10.0.0.2".into(),
            interface: String::new(),
        });
        let err = svc.delete_neighbor(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unavailable);
        assert!(matches!(peer_rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[tokio::test]
    async fn add_neighbor_rejects_invalid_remove_private_as() {
        let svc = make_service();
        let req = Request::new(proto::AddNeighborRequest {
            config: Some(proto::NeighborConfig {
                address: "10.0.0.2".into(),
                interface: String::new(),
                remote_asn: 65002,
                description: String::new(),
                hold_time: 90,
                max_prefixes: 0,
                families: Vec::new(),
                peer_group: String::new(),
                remove_private_as: "bogus".into(),
                ..Default::default()
            }),
        });
        let err = svc.add_neighbor(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("remove_private_as"));
    }

    #[tokio::test]
    async fn add_neighbor_rejects_remove_private_as_on_ibgp() {
        let svc = make_service();
        let req = Request::new(proto::AddNeighborRequest {
            config: Some(proto::NeighborConfig {
                address: "10.0.0.2".into(),
                interface: String::new(),
                remote_asn: 65001,
                description: String::new(),
                hold_time: 90,
                max_prefixes: 0,
                families: Vec::new(),
                peer_group: String::new(),
                remove_private_as: "all".into(),
                ..Default::default()
            }),
        });
        let err = svc.add_neighbor(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("requires eBGP"));
    }

    #[tokio::test]
    async fn add_neighbor_rejects_route_server_client_on_ibgp() {
        let svc = make_service();
        let req = Request::new(proto::AddNeighborRequest {
            config: Some(proto::NeighborConfig {
                address: "10.0.0.2".into(),
                interface: String::new(),
                remote_asn: 65001,
                description: String::new(),
                hold_time: 90,
                max_prefixes: 0,
                families: Vec::new(),
                peer_group: String::new(),
                remove_private_as: String::new(),
                route_server_client: true,
                ..Default::default()
            }),
        });
        let err = svc.add_neighbor(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("route_server_client"));
    }

    #[tokio::test]
    async fn add_neighbor_rejects_role_on_ibgp() {
        let svc = make_service();
        let req = Request::new(proto::AddNeighborRequest {
            config: Some(proto::NeighborConfig {
                address: "10.0.0.2".into(),
                interface: String::new(),
                remote_asn: 65001,
                description: String::new(),
                hold_time: 90,
                max_prefixes: 0,
                families: Vec::new(),
                peer_group: String::new(),
                remove_private_as: String::new(),
                role: "peer".into(),
                ..Default::default()
            }),
        });
        let err = svc.add_neighbor(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("role"));
    }

    #[tokio::test]
    async fn add_neighbor_rejects_strict_role_without_role() {
        let svc = make_service();
        let req = Request::new(proto::AddNeighborRequest {
            config: Some(proto::NeighborConfig {
                address: "10.0.0.2".into(),
                interface: String::new(),
                remote_asn: 65002,
                description: String::new(),
                hold_time: 90,
                max_prefixes: 0,
                families: Vec::new(),
                peer_group: String::new(),
                remove_private_as: String::new(),
                strict_role: true,
                ..Default::default()
            }),
        });
        let err = svc.add_neighbor(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("strict_role"));
    }
}
