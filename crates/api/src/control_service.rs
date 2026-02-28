use std::sync::Mutex;

use prometheus::{Encoder, TextEncoder};
use tokio::sync::{mpsc, oneshot};
use tonic::{Request, Response, Status};
use tracing::info;

use crate::peer_types::PeerManagerCommand;
use crate::proto;
use rustbgpd_telemetry::BgpMetrics;

/// Daemon lifecycle and observability service.
///
/// `GetHealth` returns uptime, peer count, and route count.
/// `GetMetrics` returns Prometheus text exposition.
/// `Shutdown` triggers coordinated daemon shutdown via a oneshot channel.
pub struct ControlService {
    start_time: tokio::time::Instant,
    metrics: BgpMetrics,
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    shutdown_tx: Mutex<Option<oneshot::Sender<()>>>,
}

impl ControlService {
    /// Create a new `ControlService`.
    ///
    /// `shutdown_tx` is consumed by the first `Shutdown` RPC call to trigger
    /// coordinated daemon exit.
    pub fn new(
        start_time: tokio::time::Instant,
        metrics: BgpMetrics,
        peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
        shutdown_tx: oneshot::Sender<()>,
    ) -> Self {
        Self {
            start_time,
            metrics,
            peer_mgr_tx,
            shutdown_tx: Mutex::new(Some(shutdown_tx)),
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

        let active_peers = u32::try_from(peers.len()).unwrap_or(u32::MAX);
        let total_routes: u64 = peers.iter().map(|p| p.prefix_count as u64).sum();

        Ok(Response::new(proto::HealthResponse {
            healthy: true,
            uptime_seconds: uptime,
            active_peers,
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
        let reason = request.into_inner().reason;
        info!(reason = %reason, "shutdown requested via gRPC");

        let peer_mgr_tx = self.peer_mgr_tx.clone();
        let shutdown_tx = self
            .shutdown_tx
            .lock()
            .expect("shutdown_tx mutex poisoned")
            .take();

        // Spawn the shutdown sequence so the RPC can return before we stop
        tokio::spawn(async move {
            let _ = peer_mgr_tx.send(PeerManagerCommand::Shutdown).await;
            if let Some(tx) = shutdown_tx {
                let _ = tx.send(());
            }
        });

        Ok(Response::new(proto::ShutdownResponse {}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto::control_service_server::ControlService as _;

    fn make_service() -> ControlService {
        let (peer_tx, _peer_rx) = mpsc::channel(16);
        let (shutdown_tx, _shutdown_rx) = oneshot::channel();
        let metrics = BgpMetrics::new();
        ControlService::new(tokio::time::Instant::now(), metrics, peer_tx, shutdown_tx)
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
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let metrics = BgpMetrics::new();
        let svc = ControlService::new(tokio::time::Instant::now(), metrics, peer_tx, shutdown_tx);

        let resp = svc
            .shutdown(Request::new(proto::ShutdownRequest {
                reason: "test".into(),
            }))
            .await;
        assert!(resp.is_ok());

        // Give the spawned task a moment to fire
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        // shutdown_rx should have been signaled (or sender dropped)
        assert!(shutdown_rx.await.is_ok());
    }
}
