//! gRPC server startup and wiring.

use std::net::SocketAddr;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::net::UnixListener;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinSet;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::service::Interceptor;
use tonic::transport::Server;
use tonic::{Request, Status};
use tracing::{error, info, warn};

use crate::control_service::{ControlService, MrtTriggerTx};
use crate::global_service::GlobalService;
use crate::injection_service::InjectionService;
use crate::neighbor_service::NeighborService;
use crate::peer_types::{ConfigEvent, PeerManagerCommand};
use crate::policy_service::PolicyService;
use crate::proto::control_service_server::ControlServiceServer;
use crate::proto::global_service_server::GlobalServiceServer;
use crate::proto::injection_service_server::InjectionServiceServer;
use crate::proto::neighbor_service_server::NeighborServiceServer;
use crate::proto::policy_service_server::PolicyServiceServer;
use crate::proto::rib_service_server::RibServiceServer;
use crate::rib_service::RibService;
use rustbgpd_rib::RibUpdate;
use rustbgpd_telemetry::BgpMetrics;

/// Configuration for the gRPC server beyond basic connectivity.
#[derive(Clone)]
pub struct ServeConfig {
    /// Local autonomous system number.
    pub asn: u32,
    /// Local BGP router ID (dotted-quad string).
    pub router_id: String,
    /// BGP listen port (typically 179).
    pub listen_port: u32,
    /// Shared metrics registry for Prometheus exposition.
    pub metrics: BgpMetrics,
    /// Daemon start time for uptime calculation.
    pub start_time: tokio::time::Instant,
    /// Optional MRT dump trigger channel (None if MRT not configured).
    pub mrt_trigger_tx: Option<MrtTriggerTx>,
}

/// Resolved gRPC listener configuration.
#[derive(Clone, Debug)]
pub struct ListenerConfig {
    pub endpoint: ListenerEndpoint,
    pub auth_token: Option<String>,
}

/// Listener transport.
#[derive(Clone, Debug)]
pub enum ListenerEndpoint {
    Tcp(SocketAddr),
    Uds { path: PathBuf, mode: u32 },
}

#[derive(Clone, Debug)]
struct AuthInterceptor {
    expected_header: Option<Arc<String>>,
}

impl AuthInterceptor {
    fn new(token: Option<String>) -> Self {
        let expected_header = token.map(|token| Arc::new(format!("Bearer {token}")));
        Self { expected_header }
    }
}

impl Interceptor for AuthInterceptor {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        let Some(expected) = self.expected_header.as_ref() else {
            return Ok(request);
        };

        let value = request
            .metadata()
            .get("authorization")
            .ok_or_else(|| Status::unauthenticated("missing authorization metadata"))?;
        let actual = value
            .to_str()
            .map_err(|_| Status::unauthenticated("authorization metadata must be ASCII"))?;
        if constant_time_eq(actual.as_bytes(), expected.as_bytes()) {
            Ok(request)
        } else {
            Err(Status::unauthenticated("invalid bearer token"))
        }
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let max_len = a.len().max(b.len());
    let mut diff = a.len() ^ b.len();
    for idx in 0..max_len {
        let lhs = a.get(idx).copied().unwrap_or(0);
        let rhs = b.get(idx).copied().unwrap_or(0);
        diff |= usize::from(lhs ^ rhs);
    }
    diff == 0
}

/// Start all configured gRPC listeners. Runs until the shutdown signal fires
/// or a listener exits unexpectedly.
pub async fn serve(
    listeners: Vec<ListenerConfig>,
    rib_tx: mpsc::Sender<RibUpdate>,
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    config: ServeConfig,
    shutdown_rx: oneshot::Receiver<()>,
    rpc_shutdown_tx: watch::Sender<bool>,
    config_tx: Option<mpsc::Sender<ConfigEvent>>,
) {
    let (listener_shutdown_tx, listener_shutdown_rx) = watch::channel(false);
    let mut listener_tasks = JoinSet::new();

    for listener in listeners {
        let rib_tx = rib_tx.clone();
        let peer_mgr_tx = peer_mgr_tx.clone();
        let config = config.clone();
        let rpc_shutdown_tx = rpc_shutdown_tx.clone();
        let config_tx = config_tx.clone();
        let shutdown_rx = listener_shutdown_rx.clone();
        listener_tasks.spawn(async move {
            run_listener(
                listener,
                rib_tx,
                peer_mgr_tx,
                config,
                shutdown_rx,
                rpc_shutdown_tx,
                config_tx,
            )
            .await
        });
    }

    tokio::select! {
        () = async {
            let _ = shutdown_rx.await;
        } => {
            let _ = listener_shutdown_tx.send(true);
        }
        result = listener_tasks.join_next() => {
            match result {
                Some(Ok(Err(err))) => error!(error = %err, "gRPC listener exited unexpectedly"),
                Some(Err(err)) => error!(error = %err, "gRPC listener task panicked"),
                Some(Ok(Ok(()))) | None => error!("gRPC listener exited unexpectedly"),
            }
            let _ = listener_shutdown_tx.send(true);
        }
    }

    while let Some(result) = listener_tasks.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(err)) => error!(error = %err, "gRPC listener exit during shutdown"),
            Err(err) => error!(error = %err, "gRPC listener task panicked during shutdown"),
        }
    }
}

async fn run_listener(
    listener: ListenerConfig,
    rib_tx: mpsc::Sender<RibUpdate>,
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    config: ServeConfig,
    shutdown_rx: watch::Receiver<bool>,
    rpc_shutdown_tx: watch::Sender<bool>,
    config_tx: Option<mpsc::Sender<ConfigEvent>>,
) -> Result<(), String> {
    let asn = config.asn;
    let router_id = config.router_id;
    let listen_port = config.listen_port;
    let metrics = config.metrics;
    let start_time = config.start_time;
    let mrt_trigger_tx = config.mrt_trigger_tx;

    match listener.endpoint {
        ListenerEndpoint::Tcp(addr) => {
            run_tcp_listener(
                addr,
                listener.auth_token,
                rib_tx,
                peer_mgr_tx,
                asn,
                router_id,
                listen_port,
                metrics,
                start_time,
                mrt_trigger_tx,
                shutdown_rx,
                rpc_shutdown_tx,
                config_tx,
            )
            .await
        }
        ListenerEndpoint::Uds { path, mode } => {
            run_uds_listener(
                path,
                mode,
                listener.auth_token,
                rib_tx,
                peer_mgr_tx,
                asn,
                router_id,
                listen_port,
                metrics,
                start_time,
                mrt_trigger_tx,
                shutdown_rx,
                rpc_shutdown_tx,
                config_tx,
            )
            .await
        }
    }
}

#[expect(clippy::too_many_arguments, reason = "startup wiring for one listener")]
async fn run_tcp_listener(
    addr: SocketAddr,
    auth_token: Option<String>,
    rib_tx: mpsc::Sender<RibUpdate>,
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    asn: u32,
    router_id: String,
    listen_port: u32,
    metrics: BgpMetrics,
    start_time: tokio::time::Instant,
    mrt_trigger_tx: Option<MrtTriggerTx>,
    shutdown_rx: watch::Receiver<bool>,
    rpc_shutdown_tx: watch::Sender<bool>,
    config_tx: Option<mpsc::Sender<ConfigEvent>>,
) -> Result<(), String> {
    info!(
        %addr,
        auth_enabled = auth_token.is_some(),
        "starting gRPC TCP listener"
    );
    let interceptor = AuthInterceptor::new(auth_token);
    Server::builder()
        .add_service(RibServiceServer::with_interceptor(
            RibService::new(rib_tx.clone()),
            interceptor.clone(),
        ))
        .add_service(InjectionServiceServer::with_interceptor(
            InjectionService::new(rib_tx.clone()),
            interceptor.clone(),
        ))
        .add_service(NeighborServiceServer::with_interceptor(
            NeighborService::new(asn, peer_mgr_tx.clone(), rib_tx.clone(), config_tx.clone()),
            interceptor.clone(),
        ))
        .add_service(PolicyServiceServer::with_interceptor(
            PolicyService::new(peer_mgr_tx.clone(), config_tx.clone()),
            interceptor.clone(),
        ))
        .add_service(GlobalServiceServer::with_interceptor(
            GlobalService::new(asn, router_id, listen_port),
            interceptor.clone(),
        ))
        .add_service(ControlServiceServer::with_interceptor(
            ControlService::new(
                start_time,
                metrics,
                peer_mgr_tx,
                rib_tx,
                rpc_shutdown_tx,
                mrt_trigger_tx,
            ),
            interceptor,
        ))
        .serve_with_shutdown(addr, await_shutdown(shutdown_rx))
        .await
        .map_err(|e| format!("TCP listener {addr} failed: {e}"))
}

#[expect(clippy::too_many_arguments, reason = "startup wiring for one listener")]
async fn run_uds_listener(
    path: PathBuf,
    mode: u32,
    auth_token: Option<String>,
    rib_tx: mpsc::Sender<RibUpdate>,
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    asn: u32,
    router_id: String,
    listen_port: u32,
    metrics: BgpMetrics,
    start_time: tokio::time::Instant,
    mrt_trigger_tx: Option<MrtTriggerTx>,
    shutdown_rx: watch::Receiver<bool>,
    rpc_shutdown_tx: watch::Sender<bool>,
    config_tx: Option<mpsc::Sender<ConfigEvent>>,
) -> Result<(), String> {
    let auth_enabled = auth_token.is_some();
    let uds_listener = bind_uds_listener(&path, mode)?;
    info!(
        path = %path.display(),
        auth_enabled,
        "starting gRPC UDS listener"
    );
    let interceptor = AuthInterceptor::new(auth_token);
    let result = Server::builder()
        .add_service(RibServiceServer::with_interceptor(
            RibService::new(rib_tx.clone()),
            interceptor.clone(),
        ))
        .add_service(InjectionServiceServer::with_interceptor(
            InjectionService::new(rib_tx.clone()),
            interceptor.clone(),
        ))
        .add_service(NeighborServiceServer::with_interceptor(
            NeighborService::new(asn, peer_mgr_tx.clone(), rib_tx.clone(), config_tx.clone()),
            interceptor.clone(),
        ))
        .add_service(PolicyServiceServer::with_interceptor(
            PolicyService::new(peer_mgr_tx.clone(), config_tx.clone()),
            interceptor.clone(),
        ))
        .add_service(GlobalServiceServer::with_interceptor(
            GlobalService::new(asn, router_id, listen_port),
            interceptor.clone(),
        ))
        .add_service(ControlServiceServer::with_interceptor(
            ControlService::new(
                start_time,
                metrics,
                peer_mgr_tx,
                rib_tx,
                rpc_shutdown_tx,
                mrt_trigger_tx,
            ),
            interceptor,
        ))
        .serve_with_incoming_shutdown(
            UnixListenerStream::new(uds_listener),
            await_shutdown(shutdown_rx),
        )
        .await
        .map_err(|e| format!("UDS listener {} failed: {e}", path.display()));

    if let Err(err) = cleanup_uds_socket(&path) {
        warn!(path = %path.display(), error = %err, "failed to remove gRPC UDS socket");
    }

    result
}

fn bind_uds_listener(path: &Path, mode: u32) -> Result<UnixListener, String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create UDS parent {}: {e}", parent.display()))?;
    }

    if path.exists() {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|e| format!("failed to stat existing UDS path {}: {e}", path.display()))?;
        if metadata.file_type().is_socket() {
            std::fs::remove_file(path).map_err(|e| {
                format!("failed to remove stale UDS socket {}: {e}", path.display())
            })?;
        } else {
            return Err(format!(
                "refusing to replace non-socket file at {}",
                path.display()
            ));
        }
    }

    let listener = UnixListener::bind(path)
        .map_err(|e| format!("failed to bind UDS listener {}: {e}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|e| {
        format!(
            "failed to set permissions on UDS listener {}: {e}",
            path.display()
        )
    })?;
    Ok(listener)
}

fn cleanup_uds_socket(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!(
            "failed to remove UDS socket {}: {e}",
            path.display()
        )),
    }
}

async fn await_shutdown(mut shutdown_rx: watch::Receiver<bool>) {
    if *shutdown_rx.borrow() {
        return;
    }
    while shutdown_rx.changed().await.is_ok() {
        if *shutdown_rx.borrow() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_interceptor_allows_unprotected_requests() {
        let mut interceptor = AuthInterceptor::new(None);
        assert!(interceptor.call(Request::new(())).is_ok());
    }

    #[test]
    fn auth_interceptor_rejects_missing_token() {
        let mut interceptor = AuthInterceptor::new(Some("secret".to_string()));
        let err = interceptor.call(Request::new(())).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn auth_interceptor_accepts_matching_token() {
        let mut interceptor = AuthInterceptor::new(Some("secret".to_string()));
        let mut request = Request::new(());
        request
            .metadata_mut()
            .insert("authorization", "Bearer secret".parse().unwrap());
        assert!(interceptor.call(request).is_ok());
    }

    #[test]
    fn auth_interceptor_rejects_wrong_token() {
        let mut interceptor = AuthInterceptor::new(Some("secret".to_string()));
        let mut request = Request::new(());
        request
            .metadata_mut()
            .insert("authorization", "Bearer wrong".parse().unwrap());
        let err = interceptor.call(request).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }
}
