use std::net::SocketAddr;

use tokio::sync::{mpsc, oneshot};
use tonic::transport::Server;
use tracing::{error, info};

use crate::control_service::{ControlService, MrtTriggerTx};
use crate::global_service::GlobalService;
use crate::injection_service::InjectionService;
use crate::neighbor_service::NeighborService;
use crate::peer_types::{ConfigEvent, PeerManagerCommand};
use crate::proto::control_service_server::ControlServiceServer;
use crate::proto::global_service_server::GlobalServiceServer;
use crate::proto::injection_service_server::InjectionServiceServer;
use crate::proto::neighbor_service_server::NeighborServiceServer;
use crate::proto::rib_service_server::RibServiceServer;
use crate::rib_service::RibService;
use rustbgpd_rib::RibUpdate;
use rustbgpd_telemetry::BgpMetrics;

/// Configuration for the gRPC server beyond basic connectivity.
pub struct ServeConfig {
    pub asn: u32,
    pub router_id: String,
    pub listen_port: u32,
    pub metrics: BgpMetrics,
    pub start_time: tokio::time::Instant,
    pub mrt_trigger_tx: Option<MrtTriggerTx>,
}

/// Start the gRPC server. Runs until the shutdown signal fires.
///
/// `shutdown_tx` is given to the `ControlService` so the `Shutdown` RPC can
/// trigger server exit. `shutdown_rx` gates `serve_with_shutdown`.
pub async fn serve(
    addr: SocketAddr,
    rib_tx: mpsc::Sender<RibUpdate>,
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    config: ServeConfig,
    shutdown_rx: oneshot::Receiver<()>,
    shutdown_tx: oneshot::Sender<()>,
    config_tx: Option<mpsc::Sender<ConfigEvent>>,
) {
    let rib_svc = RibService::new(rib_tx.clone());
    let injection_svc = InjectionService::new(rib_tx.clone());
    let neighbor_svc =
        NeighborService::new(config.asn, peer_mgr_tx.clone(), rib_tx.clone(), config_tx);
    let global_svc = GlobalService::new(config.asn, config.router_id, config.listen_port);
    let control_svc = ControlService::new(
        config.start_time,
        config.metrics,
        peer_mgr_tx,
        rib_tx,
        shutdown_tx,
        config.mrt_trigger_tx,
    );

    info!(%addr, "starting gRPC server");

    if let Err(e) = Server::builder()
        .add_service(RibServiceServer::new(rib_svc))
        .add_service(InjectionServiceServer::new(injection_svc))
        .add_service(NeighborServiceServer::new(neighbor_svc))
        .add_service(GlobalServiceServer::new(global_svc))
        .add_service(ControlServiceServer::new(control_svc))
        .serve_with_shutdown(addr, async {
            let _ = shutdown_rx.await;
        })
        .await
    {
        error!(error = %e, "gRPC server error");
    }
}
