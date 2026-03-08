//! gRPC neighbor service — add, remove, enable, disable, and list BGP peers.

use std::net::IpAddr;
use std::time::Duration;

use rustbgpd_transport::RemovePrivateAs;
use rustbgpd_wire::{Afi, Safi};
use tokio::sync::{mpsc, oneshot};
use tonic::{Request, Response, Status};

use crate::peer_types::{ConfigEvent, PeerInfo, PeerManagerCommand, PeerManagerNeighborConfig};
use crate::proto;
use rustbgpd_rib::RibUpdate;

const CONFIG_PERSIST_RESERVE_TIMEOUT: Duration = Duration::from_secs(2);

/// Parse a list of family strings from the gRPC proto into `(Afi, Safi)` pairs.
#[allow(clippy::result_large_err)] // tonic::Status is the standard gRPC error type
fn parse_families_proto(families: &[String]) -> Result<Vec<(Afi, Safi)>, Status> {
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
#[allow(clippy::struct_field_names)]
pub struct NeighborService {
    local_asn: u32,
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    rib_tx: mpsc::Sender<RibUpdate>,
    config_tx: Option<mpsc::Sender<ConfigEvent>>,
}

impl NeighborService {
    /// Create a new neighbor service with the given channels.
    pub fn new(
        local_asn: u32,
        peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
        rib_tx: mpsc::Sender<RibUpdate>,
        config_tx: Option<mpsc::Sender<ConfigEvent>>,
    ) -> Self {
        Self {
            local_asn,
            peer_mgr_tx,
            rib_tx,
            config_tx,
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
            Status::internal("config persistence queue busy — refusing mutation to avoid drift")
        })?
        .map_err(|_| Status::internal("config persistence unavailable"))?;

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

fn family_to_string(afi: Afi, safi: Safi) -> String {
    match (afi, safi) {
        (Afi::Ipv4, Safi::Unicast) => "ipv4_unicast".to_string(),
        (Afi::Ipv6, Safi::Unicast) => "ipv6_unicast".to_string(),
        _ => format!("{afi:?}_{safi:?}"),
    }
}

#[allow(clippy::result_large_err)] // tonic::Status is the standard gRPC error type
fn parse_remove_private_as_proto(mode: &str) -> Result<RemovePrivateAs, Status> {
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

fn peer_info_to_proto(info: &PeerInfo) -> proto::NeighborState {
    let families = info
        .families
        .iter()
        .map(|(afi, safi)| family_to_string(*afi, *safi))
        .collect();

    let config = proto::NeighborConfig {
        address: info.address.to_string(),
        remote_asn: info.remote_asn,
        description: info.description.clone(),
        hold_time: info.hold_time.map_or(0, u32::from),
        max_prefixes: info.max_prefixes.unwrap_or(0),
        families,
        remove_private_as: remove_private_as_to_string(info.remove_private_as),
        peer_group: info.peer_group.clone().unwrap_or_default(),
        route_server_client: info.route_server_client,
        add_path_receive: info.add_path_receive,
        add_path_send: info.add_path_send,
        add_path_send_max: info.add_path_send_max,
    };

    let state = match info.state {
        rustbgpd_fsm::SessionState::Idle => proto::SessionState::Idle,
        rustbgpd_fsm::SessionState::Connect => proto::SessionState::Connect,
        rustbgpd_fsm::SessionState::Active => proto::SessionState::Active,
        rustbgpd_fsm::SessionState::OpenSent => proto::SessionState::OpenSent,
        rustbgpd_fsm::SessionState::OpenConfirm => proto::SessionState::OpenConfirm,
        rustbgpd_fsm::SessionState::Established => proto::SessionState::Established,
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
        flap_count: info.flap_count,
        last_error: info.last_error.clone(),
    }
}

#[tonic::async_trait]
impl proto::neighbor_service_server::NeighborService for NeighborService {
    async fn add_neighbor(
        &self,
        request: Request<proto::AddNeighborRequest>,
    ) -> Result<Response<proto::AddNeighborResponse>, Status> {
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

        let families = parse_families_proto(&config.families)?;
        let remove_private_as = parse_remove_private_as_proto(&config.remove_private_as)?;
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

        let peer_config = PeerManagerNeighborConfig {
            address,
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
            max_prefixes: if config.max_prefixes > 0 {
                Some(config.max_prefixes)
            } else {
                None
            },
            md5_password: None,
            ttl_security: false,
            families,
            graceful_restart: true,
            gr_restart_time: 120,
            gr_stale_routes_time: 360,
            llgr_stale_time: 0,
            gr_restart_eligible: false,
            local_ipv6_nexthop: None,
            route_reflector_client: false,
            route_server_client: config.route_server_client,
            remove_private_as,
            add_path_receive: config.add_path_receive,
            add_path_send: config.add_path_send,
            add_path_send_max: config.add_path_send_max,
            import_policy: None,
            export_policy: None,
        };

        // Reserve config persistence capacity before mutating runtime state.
        // This makes AddNeighbor fail-fast when persistence is unavailable.
        let persist_permit = reserve_config_event_slot(self.config_tx.clone()).await?;
        let persisted_config = persist_permit.as_ref().map(|_| peer_config.clone());

        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::AddPeer {
                config: peer_config,
                sync_config_snapshot: true,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;

        reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?
            .map_err(Status::already_exists)?;

        // Persist only after successful runtime mutation.
        if let (Some(permit), Some(cfg)) = (persist_permit, persisted_config) {
            permit.send(ConfigEvent::NeighborAdded(cfg));
        }

        Ok(Response::new(proto::AddNeighborResponse {}))
    }

    async fn delete_neighbor(
        &self,
        request: Request<proto::DeleteNeighborRequest>,
    ) -> Result<Response<proto::DeleteNeighborResponse>, Status> {
        let req = request.into_inner();
        let address: IpAddr = req
            .address
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid address: {e}")))?;

        // Reserve config persistence capacity before mutating runtime state.
        // This makes DeleteNeighbor fail-fast when persistence is unavailable.
        let persist_permit = reserve_config_event_slot(self.config_tx.clone()).await?;

        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::DeletePeer {
                address,
                sync_config_snapshot: true,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;

        reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?
            .map_err(Status::not_found)?;

        if let Some(permit) = persist_permit {
            permit.send(ConfigEvent::NeighborDeleted(address));
        }

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
            neighbors.push(state);
        }

        Ok(Response::new(proto::ListNeighborsResponse { neighbors }))
    }

    async fn get_neighbor_state(
        &self,
        request: Request<proto::GetNeighborStateRequest>,
    ) -> Result<Response<proto::NeighborState>, Status> {
        let req = request.into_inner();
        let address: IpAddr = req
            .address
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid address: {e}")))?;

        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::GetPeerState {
                address,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;

        let info = reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?
            .ok_or_else(|| Status::not_found(format!("peer {address} not found")))?;

        let mut state = peer_info_to_proto(&info);
        state.prefixes_sent = query_advertised_count(&self.rib_tx, info.address).await?;
        Ok(Response::new(state))
    }

    async fn enable_neighbor(
        &self,
        request: Request<proto::EnableNeighborRequest>,
    ) -> Result<Response<proto::EnableNeighborResponse>, Status> {
        let req = request.into_inner();
        let address: IpAddr = req
            .address
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid address: {e}")))?;

        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::EnablePeer {
                address,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;

        reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?
            .map_err(Status::not_found)?;

        Ok(Response::new(proto::EnableNeighborResponse {}))
    }

    async fn soft_reset_in(
        &self,
        request: Request<proto::SoftResetInRequest>,
    ) -> Result<Response<proto::SoftResetInResponse>, Status> {
        let req = request.into_inner();
        let address: IpAddr = req
            .address
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid address: {e}")))?;

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
                address,
                families,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;

        reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?
            .map_err(|e| {
                if e.starts_with("not found:") {
                    Status::not_found(e)
                } else {
                    Status::internal(e)
                }
            })?;

        Ok(Response::new(proto::SoftResetInResponse {}))
    }

    async fn disable_neighbor(
        &self,
        request: Request<proto::DisableNeighborRequest>,
    ) -> Result<Response<proto::DisableNeighborResponse>, Status> {
        let req = request.into_inner();
        let address: IpAddr = req
            .address
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid address: {e}")))?;

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
                address,
                reason,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;

        reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?
            .map_err(Status::not_found)?;

        Ok(Response::new(proto::DisableNeighborResponse {}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto::neighbor_service_server::NeighborService as _;
    use tokio::sync::mpsc::error::TryRecvError;

    fn make_service() -> NeighborService {
        let (tx, _rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        NeighborService::new(65001, tx, rib_tx, None)
    }

    #[tokio::test]
    async fn add_neighbor_rejects_asn_zero() {
        let svc = make_service();
        let req = Request::new(proto::AddNeighborRequest {
            config: Some(proto::NeighborConfig {
                address: "10.0.0.2".into(),
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
        let svc = NeighborService::new(65001, peer_tx, rib_tx, None);

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
        use crate::peer_types::PeerInfo;

        let (peer_tx, mut peer_rx) = mpsc::channel(16);
        let (rib_tx, mut rib_rx) = mpsc::channel(16);
        let svc = NeighborService::new(65001, peer_tx, rib_tx, None);

        let addr: std::net::IpAddr = "10.0.0.1".parse().unwrap();

        // Spawn responders
        tokio::spawn(async move {
            if let Some(PeerManagerCommand::GetPeerState { reply, .. }) = peer_rx.recv().await {
                let _ = reply.send(Some(PeerInfo {
                    address: addr,
                    remote_asn: 65001,
                    description: String::new(),
                    peer_group: None,
                    state: rustbgpd_fsm::SessionState::Established,
                    enabled: true,
                    prefix_count: 5,
                    hold_time: None,
                    max_prefixes: None,
                    families: vec![(Afi::Ipv4, Safi::Unicast)],
                    remove_private_as: RemovePrivateAs::Disabled,
                    route_server_client: false,
                    add_path_receive: false,
                    add_path_send: false,
                    add_path_send_max: 0,
                    updates_received: 0,
                    updates_sent: 0,
                    notifications_received: 0,
                    notifications_sent: 0,
                    flap_count: 0,
                    uptime_secs: 0,
                    last_error: String::new(),
                }));
            }
        });

        tokio::spawn(async move {
            if let Some(RibUpdate::QueryAdvertisedCount { reply, .. }) = rib_rx.recv().await {
                let _ = reply.send(7);
            }
        });

        let resp = svc
            .get_neighbor_state(Request::new(proto::GetNeighborStateRequest {
                address: "10.0.0.1".into(),
            }))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(resp.prefixes_sent, 7);
    }

    #[test]
    fn peer_info_to_proto_includes_families() {
        let info = PeerInfo {
            address: "10.0.0.1".parse().unwrap(),
            remote_asn: 65001,
            description: String::new(),
            peer_group: None,
            state: rustbgpd_fsm::SessionState::Established,
            enabled: true,
            prefix_count: 0,
            hold_time: None,
            max_prefixes: None,
            families: vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)],
            remove_private_as: RemovePrivateAs::All,
            route_server_client: false,
            add_path_receive: false,
            add_path_send: false,
            add_path_send_max: 0,
            updates_received: 0,
            updates_sent: 0,
            notifications_received: 0,
            notifications_sent: 0,
            flap_count: 0,
            uptime_secs: 0,
            last_error: String::new(),
        };
        let state = peer_info_to_proto(&info);
        let config = state.config.unwrap();
        assert_eq!(config.families, vec!["ipv4_unicast", "ipv6_unicast"]);
        assert_eq!(config.remove_private_as, "all");
    }

    #[tokio::test]
    async fn add_neighbor_fails_when_config_persistence_unavailable() {
        let (peer_tx, mut peer_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let (config_tx, config_rx) = mpsc::channel(1);
        drop(config_rx);
        let svc = NeighborService::new(65001, peer_tx, rib_tx, Some(config_tx));

        let req = Request::new(proto::AddNeighborRequest {
            config: Some(proto::NeighborConfig {
                address: "10.0.0.2".into(),
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
        assert_eq!(err.code(), tonic::Code::Internal);
        assert!(matches!(peer_rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[tokio::test]
    async fn delete_neighbor_fails_when_config_persistence_unavailable() {
        let (peer_tx, mut peer_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let (config_tx, config_rx) = mpsc::channel(1);
        drop(config_rx);
        let svc = NeighborService::new(65001, peer_tx, rib_tx, Some(config_tx));

        let req = Request::new(proto::DeleteNeighborRequest {
            address: "10.0.0.2".into(),
        });
        let err = svc.delete_neighbor(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Internal);
        assert!(matches!(peer_rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[tokio::test]
    async fn add_neighbor_rejects_invalid_remove_private_as() {
        let svc = make_service();
        let req = Request::new(proto::AddNeighborRequest {
            config: Some(proto::NeighborConfig {
                address: "10.0.0.2".into(),
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
}
