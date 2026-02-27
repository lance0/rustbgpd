use std::net::SocketAddr;

use tokio::sync::mpsc;
use tonic::transport::Server;
use tracing::{error, info};

use crate::injection_service::InjectionService;
use crate::neighbor_service::NeighborService;
use crate::peer_types::PeerManagerCommand;
use crate::proto::injection_service_server::InjectionServiceServer;
use crate::proto::neighbor_service_server::NeighborServiceServer;
use crate::proto::rib_service_server::RibServiceServer;
use crate::rib_service::RibService;
use rustbgpd_rib::RibUpdate;

/// Start the gRPC server. Runs until the provided future resolves (shutdown signal).
pub async fn serve(
    addr: SocketAddr,
    rib_tx: mpsc::Sender<RibUpdate>,
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
) {
    let rib_svc = RibService::new(rib_tx.clone());
    let injection_svc = InjectionService::new(rib_tx);
    let neighbor_svc = NeighborService::new(peer_mgr_tx);

    info!(%addr, "starting gRPC server");

    if let Err(e) = Server::builder()
        .add_service(RibServiceServer::new(rib_svc))
        .add_service(InjectionServiceServer::new(injection_svc))
        .add_service(NeighborServiceServer::new(neighbor_svc))
        .serve(addr)
        .await
    {
        error!(error = %e, "gRPC server error");
    }
}
