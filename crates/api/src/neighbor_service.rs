use std::net::IpAddr;

use rustbgpd_wire::{Afi, Safi};
use tokio::sync::{mpsc, oneshot};
use tonic::{Request, Response, Status};

use crate::peer_types::{PeerInfo, PeerManagerCommand, PeerManagerNeighborConfig};
use crate::proto;
use rustbgpd_rib::RibUpdate;

/// Parse a list of family strings from the gRPC proto into `(Afi, Safi)` pairs.
#[allow(clippy::result_large_err)] // tonic::Status is the standard gRPC error type
fn parse_families_proto(families: &[String]) -> Result<Vec<(Afi, Safi)>, Status> {
    if families.is_empty() {
        return Ok(vec![(Afi::Ipv4, Safi::Unicast)]);
    }
    let mut result = Vec::with_capacity(families.len());
    for f in families {
        match f.as_str() {
            "ipv4_unicast" => result.push((Afi::Ipv4, Safi::Unicast)),
            "ipv6_unicast" => result.push((Afi::Ipv6, Safi::Unicast)),
            other => {
                return Err(Status::invalid_argument(format!(
                    "unknown address family {other:?}, expected \"ipv4_unicast\" or \"ipv6_unicast\""
                )));
            }
        }
    }
    Ok(result)
}

pub struct NeighborService {
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    rib_tx: mpsc::Sender<RibUpdate>,
}

impl NeighborService {
    pub fn new(
        peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
        rib_tx: mpsc::Sender<RibUpdate>,
    ) -> Self {
        Self {
            peer_mgr_tx,
            rib_tx,
        }
    }
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

        let peer_config = PeerManagerNeighborConfig {
            address,
            remote_asn: config.remote_asn,
            description: config.description,
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
            families,
            graceful_restart: true,
            gr_restart_time: 120,
            gr_stale_routes_time: 360,
            local_ipv6_nexthop: None,
            route_reflector_client: false,
            add_path_receive: false,
            import_policy: None,
            export_policy: None,
        };

        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::AddPeer {
                config: peer_config,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;

        reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?
            .map_err(Status::already_exists)?;

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

        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::DeletePeer {
                address,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;

        reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?
            .map_err(Status::not_found)?;

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
            let mut result = Vec::with_capacity(req.families.len());
            for f in &req.families {
                match f.as_str() {
                    "ipv4_unicast" => result.push((Afi::Ipv4, Safi::Unicast)),
                    "ipv6_unicast" => result.push((Afi::Ipv6, Safi::Unicast)),
                    other => {
                        return Err(Status::invalid_argument(format!(
                            "unknown address family {other:?}"
                        )));
                    }
                }
            }
            result
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

        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::DisablePeer {
                address,
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

    fn make_service() -> NeighborService {
        let (tx, _rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        NeighborService::new(tx, rib_tx)
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
            }),
        });
        let err = svc.add_neighbor(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("hold_time"));
    }

    #[tokio::test]
    async fn prefixes_sent_populated() {
        use crate::peer_types::PeerInfo;

        let (peer_tx, mut peer_rx) = mpsc::channel(16);
        let (rib_tx, mut rib_rx) = mpsc::channel(16);
        let svc = NeighborService::new(peer_tx, rib_tx);

        let addr: std::net::IpAddr = "10.0.0.1".parse().unwrap();

        // Spawn responders
        tokio::spawn(async move {
            if let Some(PeerManagerCommand::GetPeerState { reply, .. }) = peer_rx.recv().await {
                let _ = reply.send(Some(PeerInfo {
                    address: addr,
                    remote_asn: 65001,
                    description: String::new(),
                    state: rustbgpd_fsm::SessionState::Established,
                    enabled: true,
                    prefix_count: 5,
                    hold_time: None,
                    max_prefixes: None,
                    families: vec![(Afi::Ipv4, Safi::Unicast)],
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
            state: rustbgpd_fsm::SessionState::Established,
            enabled: true,
            prefix_count: 0,
            hold_time: None,
            max_prefixes: None,
            families: vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)],
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
    }
}
