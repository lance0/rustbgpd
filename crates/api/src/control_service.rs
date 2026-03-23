use std::path::PathBuf;

use prometheus::{Encoder, TextEncoder};
use tokio::sync::{mpsc, oneshot, watch};
use tonic::{Request, Response, Status};
use tracing::info;

use crate::peer_types::PeerManagerCommand;
use crate::proto;
use crate::server::{AccessMode, read_only_rejection};
use rustbgpd_rib::RibUpdate;
use rustbgpd_telemetry::BgpMetrics;

/// MRT trigger channel type.
pub type MrtTriggerTx = mpsc::Sender<oneshot::Sender<Result<PathBuf, String>>>;

/// Daemon lifecycle and observability service.
///
/// `GetHealth` returns uptime, peer count, and route count.
/// `GetMetrics` returns Prometheus text exposition.
/// `Shutdown` triggers coordinated daemon shutdown via a watch channel.
pub struct ControlService {
    access_mode: AccessMode,
    start_time: tokio::time::Instant,
    metrics: BgpMetrics,
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    rib_tx: mpsc::Sender<RibUpdate>,
    shutdown_tx: watch::Sender<bool>,
    mrt_trigger_tx: Option<MrtTriggerTx>,
}

impl ControlService {
    /// Create a new `ControlService`.
    ///
    /// `shutdown_tx` is set to `true` by the first `Shutdown` RPC call to
    /// trigger coordinated daemon exit.
    pub fn new(
        access_mode: AccessMode,
        start_time: tokio::time::Instant,
        metrics: BgpMetrics,
        peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
        rib_tx: mpsc::Sender<RibUpdate>,
        shutdown_tx: watch::Sender<bool>,
        mrt_trigger_tx: Option<MrtTriggerTx>,
    ) -> Self {
        Self {
            access_mode,
            start_time,
            metrics,
            peer_mgr_tx,
            rib_tx,
            shutdown_tx,
            mrt_trigger_tx,
        }
    }
}

#[tonic::async_trait]
impl proto::control_service_server::ControlService for ControlService {
    async fn get_health(
        &self,
        _request: Request<proto::HealthRequest>,
    ) -> Result<Response<proto::HealthResponse>, Status> {
        let uptime = self.start_time.elapsed().as_secs();

        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::ListPeers { reply: reply_tx })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;

        let peers = reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?;

        let active_peers = peers
            .iter()
            .filter(|p| p.state == rustbgpd_fsm::SessionState::Established)
            .count();

        let (rib_reply_tx, rib_reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::QueryLocRibCount {
                reply: rib_reply_tx,
            })
            .await
            .map_err(|_| Status::internal("RIB manager unavailable"))?;

        let total_routes = rib_reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?;

        Ok(Response::new(proto::HealthResponse {
            healthy: true,
            uptime_seconds: uptime,
            active_peers: u32::try_from(active_peers).unwrap_or(u32::MAX),
            total_routes: u32::try_from(total_routes).unwrap_or(u32::MAX),
        }))
    }

    async fn get_metrics(
        &self,
        _request: Request<proto::MetricsRequest>,
    ) -> Result<Response<proto::MetricsResponse>, Status> {
        let encoder = TextEncoder::new();
        let families = self.metrics.registry().gather();
        let mut buf = Vec::new();
        encoder
            .encode(&families, &mut buf)
            .map_err(|e| Status::internal(format!("metrics encoding error: {e}")))?;
        let text =
            String::from_utf8(buf).map_err(|e| Status::internal(format!("UTF-8 error: {e}")))?;

        Ok(Response::new(proto::MetricsResponse {
            prometheus_text: text,
        }))
    }

    async fn shutdown(
        &self,
        request: Request<proto::ShutdownRequest>,
    ) -> Result<Response<proto::ShutdownResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let reason = request.into_inner().reason;
        info!(reason = %reason, "shutdown requested via gRPC");

        let peer_mgr_tx = self.peer_mgr_tx.clone();
        let shutdown_tx = self.shutdown_tx.clone();

        // Spawn the shutdown sequence so the RPC can return before we stop
        tokio::spawn(async move {
            let _ = peer_mgr_tx.send(PeerManagerCommand::Shutdown).await;
            let _ = shutdown_tx.send(true);
        });

        Ok(Response::new(proto::ShutdownResponse {}))
    }

    async fn trigger_mrt_dump(
        &self,
        _request: Request<proto::TriggerMrtDumpRequest>,
    ) -> Result<Response<proto::TriggerMrtDumpResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let trigger_tx = self
            .mrt_trigger_tx
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("MRT export is not configured"))?;

        let (reply_tx, reply_rx) = oneshot::channel();
        trigger_tx
            .send(reply_tx)
            .await
            .map_err(|_| Status::internal("MRT manager unavailable"))?;

        let result = reply_rx
            .await
            .map_err(|_| Status::internal("MRT manager dropped reply"))?;

        match result {
            Ok(path) => Ok(Response::new(proto::TriggerMrtDumpResponse {
                file_path: path.to_string_lossy().to_string(),
            })),
            Err(e) => Err(Status::internal(format!("MRT dump failed: {e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto::control_service_server::ControlService as _;

    fn make_service() -> ControlService {
        let (peer_tx, _peer_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);
        let metrics = BgpMetrics::new();
        ControlService::new(
            AccessMode::ReadWrite,
            tokio::time::Instant::now(),
            metrics,
            peer_tx,
            rib_tx,
            shutdown_tx,
            None,
        )
    }

    #[tokio::test]
    async fn get_metrics_succeeds() {
        let svc = make_service();
        let resp = svc
            .get_metrics(Request::new(proto::MetricsRequest {}))
            .await
            .unwrap()
            .into_inner();
        // Response is valid UTF-8 prometheus text (may be empty if no samples)
        assert!(resp.prometheus_text.is_ascii());
    }

    #[tokio::test]
    async fn shutdown_takes_sender() {
        let (peer_tx, _peer_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let metrics = BgpMetrics::new();
        let svc = ControlService::new(
            AccessMode::ReadWrite,
            tokio::time::Instant::now(),
            metrics,
            peer_tx,
            rib_tx,
            shutdown_tx,
            None,
        );

        let resp = svc
            .shutdown(Request::new(proto::ShutdownRequest {
                reason: "test".into(),
            }))
            .await;
        assert!(resp.is_ok());

        // Give the spawned task a moment to fire
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        shutdown_rx.changed().await.unwrap();
        assert!(*shutdown_rx.borrow());
    }

    #[tokio::test]
    async fn shutdown_rejected_on_read_only_listener() {
        let (peer_tx, _peer_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);
        let metrics = BgpMetrics::new();
        let svc = ControlService::new(
            AccessMode::ReadOnly,
            tokio::time::Instant::now(),
            metrics,
            peer_tx,
            rib_tx,
            shutdown_tx,
            None,
        );

        let err = svc
            .shutdown(Request::new(proto::ShutdownRequest {
                reason: "test".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn active_peers_counts_only_established() {
        use crate::peer_types::PeerInfo;

        let (peer_tx, mut peer_rx) = mpsc::channel(16);
        let (rib_tx, mut rib_rx) = mpsc::channel(16);
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);
        let metrics = BgpMetrics::new();
        let svc = ControlService::new(
            AccessMode::ReadWrite,
            tokio::time::Instant::now(),
            metrics,
            peer_tx,
            rib_tx,
            shutdown_tx,
            None,
        );

        // Spawn responders
        tokio::spawn(async move {
            if let Some(PeerManagerCommand::ListPeers { reply }) = peer_rx.recv().await {
                let peers = vec![
                    PeerInfo {
                        address: "10.0.0.1".parse().unwrap(),
                        remote_asn: 65001,
                        description: String::new(),
                        peer_group: None,
                        state: rustbgpd_fsm::SessionState::Established,
                        enabled: true,
                        prefix_count: 5,
                        hold_time: None,
                        max_prefixes: None,
                        families: vec![],
                        remove_private_as: rustbgpd_transport::RemovePrivateAs::Disabled,
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
                        is_dynamic: false,
                    },
                    PeerInfo {
                        address: "10.0.0.2".parse().unwrap(),
                        remote_asn: 65002,
                        description: String::new(),
                        peer_group: None,
                        state: rustbgpd_fsm::SessionState::Active,
                        enabled: true,
                        prefix_count: 0,
                        hold_time: None,
                        max_prefixes: None,
                        families: vec![],
                        remove_private_as: rustbgpd_transport::RemovePrivateAs::Disabled,
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
                        is_dynamic: false,
                    },
                ];
                let _ = reply.send(peers);
            }
        });

        tokio::spawn(async move {
            if let Some(RibUpdate::QueryLocRibCount { reply }) = rib_rx.recv().await {
                let _ = reply.send(42);
            }
        });

        let resp = svc
            .get_health(Request::new(proto::HealthRequest {}))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(resp.active_peers, 1, "only Established peers counted");
        assert_eq!(resp.total_routes, 42, "total_routes from Loc-RIB");
    }
}
