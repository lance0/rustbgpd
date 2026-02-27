use std::net::IpAddr;

use tokio::sync::{mpsc, oneshot};
use tonic::{Request, Response, Status};

use crate::peer_types::{PeerInfo, PeerManagerCommand, PeerManagerNeighborConfig};
use crate::proto;

pub struct NeighborService {
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
}

impl NeighborService {
    pub fn new(peer_mgr_tx: mpsc::Sender<PeerManagerCommand>) -> Self {
        Self { peer_mgr_tx }
    }
}

fn peer_info_to_proto(info: &PeerInfo) -> proto::NeighborState {
    let config = proto::NeighborConfig {
        address: info.address.to_string(),
        remote_asn: info.remote_asn,
        description: info.description.clone(),
        hold_time: 0,
        max_prefixes: 0,
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
        uptime_seconds: 0,
        prefixes_received: info.prefix_count as u64,
        prefixes_sent: 0,
        updates_received: 0,
        updates_sent: 0,
        notifications_received: 0,
        notifications_sent: 0,
        flap_count: 0,
        last_error: String::new(),
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

        let neighbors = infos.iter().map(peer_info_to_proto).collect();

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

        Ok(Response::new(peer_info_to_proto(&info)))
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
