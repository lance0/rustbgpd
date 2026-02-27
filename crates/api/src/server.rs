use std::net::SocketAddr;

use tokio::sync::mpsc;
use tonic::transport::Server;
use tracing::{error, info};

use crate::injection_service::InjectionService;
use crate::proto::injection_service_server::InjectionServiceServer;
use crate::proto::rib_service_server::RibServiceServer;
use crate::rib_service::RibService;
use rustbgpd_rib::RibUpdate;

/// Start the gRPC server. Runs until the provided future resolves (shutdown signal).
pub async fn serve(addr: SocketAddr, rib_tx: mpsc::Sender<RibUpdate>) {
    let rib_svc = RibService::new(rib_tx.clone());
    let injection_svc = InjectionService::new(rib_tx);

    info!(%addr, "starting gRPC server");

    if let Err(e) = Server::builder()
        .add_service(RibServiceServer::new(rib_svc))
        .add_service(InjectionServiceServer::new(injection_svc))
        .serve(addr)
        .await
    {
        error!(error = %e, "gRPC server error");
    }
}
