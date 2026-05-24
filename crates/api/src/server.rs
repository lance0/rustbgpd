//! gRPC server startup and wiring.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::net::{TcpListener, UnixListener};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinSet;
use tokio_stream::{
    StreamExt,
    wrappers::{TcpListenerStream, UnixListenerStream},
};
use tonic::service::Interceptor;
use tonic::transport::Server;
use tonic::{Request, Status};
use tracing::{error, info, warn};

use crate::authz::{AuthEnforcement, AuthTier, PrincipalRole};
use crate::authz_runtime::{BearerAuthSecret, GrpcAuthAuditContext, GrpcAuthnKind, GrpcAuthzLayer};
use crate::bfd_service::BfdService;
use crate::config_service::ConfigService;
use crate::connect_info::RustbgpdTcpStream;
use crate::control_service::{ControlService, MrtTriggerTx};
use crate::event_service::{DataplaneEventBroadcaster, EventService, dataplane_event_broadcaster};
use crate::evpn_service::{
    DuplicateMacClearFn, EvpnRuntimeApplyFn, EvpnRuntimeModelFn, EvpnService,
    OriginatedLocalMacCountFn,
};
use crate::global_service::GlobalService;
use crate::injection_service::InjectionService;
use crate::neighbor_service::NeighborService;
use crate::peer_group_service::PeerGroupService;
use crate::peer_types::{ConfigEvent, PeerManagerCommand};
use crate::policy_service::PolicyService;
use crate::proto::bfd_service_server::BfdServiceServer;
use crate::proto::config_service_server::ConfigServiceServer;
use crate::proto::control_service_server::ControlServiceServer;
use crate::proto::event_service_server::EventServiceServer;
use crate::proto::evpn_service_server::EvpnServiceServer;
use crate::proto::global_service_server::GlobalServiceServer;
use crate::proto::injection_service_server::InjectionServiceServer;
use crate::proto::neighbor_service_server::NeighborServiceServer;
use crate::proto::peer_group_service_server::PeerGroupServiceServer;
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
    /// Live count provider for locally-originated Type 2 MAC routes
    /// accepted by the RIB, keyed by VNI.
    pub evpn_originated_local_mac_count: OriginatedLocalMacCountFn,
    /// Live snapshot reader for the most recent
    /// `DataplaneReport.ip_vrf_status` rows. Returns an empty Vec
    /// when no IP-VRFs are configured or before the reconcile
    /// actor's first pass.
    pub evpn_ip_vrf_status_snapshot: crate::evpn_service::IpVrfStatusSnapshotFn,
    /// Live count provider for locally-originated Type 5 routes per
    /// IP-VRF (Gate 9 slice 6b). Returns 0 when the originator is
    /// not running (RR-only deployments without `[[evpn_ip_vrfs]]`).
    pub evpn_originated_ip_vrf_route_count: crate::evpn_service::OriginatedIpVrfRouteCountFn,
    /// Live count provider for installed remote Type 5 routes per
    /// IP-VRF (Gate 9 slice 6c). Returns 0 when no `[[evpn_ip_vrfs]]`
    /// are configured.
    pub evpn_installed_ip_vrf_route_count: crate::evpn_service::InstalledIpVrfRouteCountFn,
    /// Live snapshot reader for current remote Type 5 projection-drop
    /// counts by bounded `(vrf, reason)` labels.
    pub evpn_remote_ip_prefix_drop_counts: crate::evpn_service::RemoteIpPrefixDropCountSnapshotFn,
    /// Live snapshot reader for ADR-0059 FDB nexthop-group owned
    /// state. Returns an empty summary when the dataplane actor is
    /// not running.
    pub evpn_fdb_nexthop_snapshot: crate::evpn_service::FdbNexthopSnapshotFn,
    /// Live model reader for the committed ADR-0063 EVPN runtime
    /// generation. Generation 1 is the startup snapshot; later
    /// coordinator slices publish newer committed models here.
    pub evpn_runtime_model: EvpnRuntimeModelFn,
    /// Optional EVPN runtime apply hook. Present only on the daemon
    /// path that owns the ADR-0063 coordinator.
    pub evpn_runtime_apply: Option<EvpnRuntimeApplyFn>,
    /// Optional duplicate-MAC quarantine manual-clear hook. Present
    /// only when the EVPN originator actor is running.
    pub evpn_duplicate_mac_clear: Option<DuplicateMacClearFn>,
    /// Live snapshot reader for RFC 7999 BLACKHOLE kernel discard
    /// install state. Returns an empty list when the discard actor is
    /// disabled or has not observed any BLACKHOLE best routes.
    pub blackhole_discard_snapshot: crate::rib_service::BlackholeDiscardSnapshotFn,
    /// Live snapshot reader for ADR-0061 general unicast FIB route
    /// install state. Returns an empty list when no `[[fib_tables]]`
    /// are configured or before the actor's first reconcile pass.
    pub fib_route_snapshot: crate::rib_service::FibRouteSnapshotFn,
    /// Live ADR-0061 per-route FIB dataplane event source. This is
    /// separate from the aggregate dataplane poller so route events
    /// are not delayed by snapshot polling.
    pub dataplane_route_events: Option<tokio::sync::broadcast::Sender<crate::proto::BgpEvent>>,
    /// Live snapshot reader for ADR-0067 single-hop BFD session state.
    /// Returns an empty list when no BFD sessions are configured or off Linux.
    pub bfd_session_snapshot: crate::bfd_service::BfdSessionSnapshotFn,
    /// Live ADR-0067 BFD session-event source (state transitions) for the
    /// unified `WatchEvents` stream. `None` disables the BFD event stream.
    pub bfd_events: Option<tokio::sync::broadcast::Sender<crate::proto::BgpEvent>>,
}

/// Resolved gRPC listener configuration.
#[derive(Clone, Debug)]
pub struct ListenerConfig {
    pub endpoint: ListenerEndpoint,
    pub access_mode: AccessMode,
    /// Effective ADR-0064 listener method-tier ceiling.
    pub max_tier: AuthTier,
    /// ADR-0064 principal-role enforcement mode.
    pub enforcement: AuthEnforcement,
    /// Global principal-to-role map used when `enforcement = tier`.
    pub roles: Arc<BTreeMap<String, PrincipalRole>>,
    pub auth_token: Option<String>,
    /// Optional stable principal label for audit records. Bearer-token
    /// and UDS listeners may use it to avoid placeholder identities in
    /// `grpc_authz` logs; mTLS listeners derive their audit principal
    /// from the peer certificate instead.
    pub principal: Option<String>,
    /// Optional native mTLS for TCP listeners. The server presents
    /// `cert_pem` and accepts client connections that present a
    /// certificate signed by `client_ca_pem`. Ignored on UDS
    /// endpoints — file-system permissions are the auth surface there.
    pub tls: Option<TlsParams>,
}

/// PEM-encoded TLS material for a gRPC listener (server identity +
/// client-authentication CA root). Loaded from disk by the daemon
/// before the listener spawns; storing the bytes inline rather than
/// the paths means a config reload that changes the path doesn't
/// silently keep using stale material.
#[derive(Clone, Debug)]
pub struct TlsParams {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub client_ca_pem: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessMode {
    ReadOnly,
    ReadWrite,
}

impl AccessMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::ReadWrite => "read_write",
        }
    }
}

/// Listener transport.
#[derive(Clone, Debug)]
pub enum ListenerEndpoint {
    Tcp(SocketAddr),
    Uds { path: PathBuf, mode: u32 },
}

#[derive(Clone)]
struct RuntimeAuthzConfig {
    enforcement: AuthEnforcement,
    roles: Arc<BTreeMap<String, PrincipalRole>>,
}

fn tcp_audit_context(
    addr: SocketAddr,
    access_mode: AccessMode,
    max_tier: AuthTier,
    role_config: RuntimeAuthzConfig,
    auth_token: Option<&str>,
    tls_enabled: bool,
    configured_principal: Option<&str>,
) -> GrpcAuthAuditContext {
    let auth_enabled = auth_token.is_some();
    let (authn, principal) = if tls_enabled {
        (GrpcAuthnKind::Mtls, "mtls-unresolved".to_string())
    } else if auth_enabled {
        (
            GrpcAuthnKind::BearerToken,
            configured_principal.unwrap_or("bearer-token").to_string(),
        )
    } else {
        (GrpcAuthnKind::None, "unauthenticated".to_string())
    };
    let context = GrpcAuthAuditContext::new(
        format!("tcp://{addr}"),
        access_mode.as_str(),
        max_tier,
        authn,
        principal,
    )
    .with_role_enforcement(role_config.enforcement, role_config.roles)
    .with_bearer_token(auth_token);
    if tls_enabled {
        context.with_mtls_peer_principal()
    } else {
        context
    }
}

fn uds_audit_context(
    path: &Path,
    access_mode: AccessMode,
    max_tier: AuthTier,
    role_config: RuntimeAuthzConfig,
    auth_token: Option<&str>,
    configured_principal: Option<&str>,
) -> GrpcAuthAuditContext {
    let auth_enabled = auth_token.is_some();
    let (authn, principal) = if let Some(principal) = configured_principal {
        (
            if auth_enabled {
                GrpcAuthnKind::BearerToken
            } else {
                GrpcAuthnKind::Uds
            },
            principal.to_string(),
        )
    } else if auth_enabled {
        (GrpcAuthnKind::BearerToken, "bearer-token".to_string())
    } else {
        (GrpcAuthnKind::Uds, format!("uds:{}", path.display()))
    };
    GrpcAuthAuditContext::new(
        format!("unix://{}", path.display()),
        access_mode.as_str(),
        max_tier,
        authn,
        principal,
    )
    .with_role_enforcement(role_config.enforcement, role_config.roles)
    .with_bearer_token(auth_token)
}

#[derive(Clone, Debug)]
struct AuthInterceptor {
    bearer_auth: Option<BearerAuthSecret>,
}

impl AuthInterceptor {
    fn new(token: Option<&str>) -> Self {
        let bearer_auth = token.map(BearerAuthSecret::from_token);
        Self { bearer_auth }
    }
}

pub(crate) fn read_only_rejection(access_mode: AccessMode) -> Option<Status> {
    if access_mode == AccessMode::ReadOnly {
        Some(Status::permission_denied(
            "listener is read-only; mutating RPCs are not permitted",
        ))
    } else {
        None
    }
}

impl Interceptor for AuthInterceptor {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        let Some(bearer_auth) = self.bearer_auth.as_ref() else {
            return Ok(request);
        };
        bearer_auth.authenticate_metadata(request.metadata())?;
        Ok(request)
    }
}

/// Start all configured gRPC listeners. Runs until the shutdown signal fires
/// or a listener exits unexpectedly.
#[expect(clippy::too_many_arguments, reason = "startup wiring for gRPC server")]
pub async fn serve(
    listeners: Vec<ListenerConfig>,
    rib_tx: mpsc::Sender<RibUpdate>,
    rib_query_tx: mpsc::Sender<RibUpdate>,
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    config: ServeConfig,
    shutdown_rx: oneshot::Receiver<()>,
    rpc_shutdown_tx: watch::Sender<bool>,
    config_tx: Option<mpsc::Sender<ConfigEvent>>,
) {
    let (listener_shutdown_tx, listener_shutdown_rx) = watch::channel(false);
    let mut listener_tasks = JoinSet::new();
    let dataplane_events = dataplane_event_broadcaster();

    for listener in listeners {
        let rib_tx = rib_tx.clone();
        let rib_query_tx = rib_query_tx.clone();
        let peer_mgr_tx = peer_mgr_tx.clone();
        let config = config.clone();
        let dataplane_events = dataplane_events.clone();
        let rpc_shutdown_tx = rpc_shutdown_tx.clone();
        let config_tx = config_tx.clone();
        let shutdown_rx = listener_shutdown_rx.clone();
        listener_tasks.spawn(async move {
            run_listener(
                listener,
                rib_tx,
                rib_query_tx,
                peer_mgr_tx,
                config,
                dataplane_events,
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

#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "startup wiring for one listener"
)]
async fn run_listener(
    listener: ListenerConfig,
    rib_tx: mpsc::Sender<RibUpdate>,
    rib_query_tx: mpsc::Sender<RibUpdate>,
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    config: ServeConfig,
    dataplane_events: DataplaneEventBroadcaster,
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
    let evpn_originated_local_mac_count = config.evpn_originated_local_mac_count;
    let evpn_ip_vrf_status_snapshot = config.evpn_ip_vrf_status_snapshot;
    let evpn_originated_ip_vrf_route_count = config.evpn_originated_ip_vrf_route_count;
    let evpn_installed_ip_vrf_route_count = config.evpn_installed_ip_vrf_route_count;
    let evpn_remote_ip_prefix_drop_counts = config.evpn_remote_ip_prefix_drop_counts;
    let evpn_fdb_nexthop_snapshot = config.evpn_fdb_nexthop_snapshot;
    let evpn_runtime_model = config.evpn_runtime_model;
    let evpn_runtime_apply = config.evpn_runtime_apply;
    let evpn_duplicate_mac_clear = config.evpn_duplicate_mac_clear;
    let blackhole_discard_snapshot = config.blackhole_discard_snapshot;
    let fib_route_snapshot = config.fib_route_snapshot;
    let dataplane_route_events = config.dataplane_route_events;
    let bfd_session_snapshot = config.bfd_session_snapshot;
    let bfd_events = config.bfd_events;
    let ListenerConfig {
        endpoint,
        access_mode,
        max_tier,
        enforcement,
        roles,
        auth_token,
        principal,
        tls,
    } = listener;

    match endpoint {
        ListenerEndpoint::Tcp(addr) => {
            run_tcp_listener(
                addr,
                access_mode,
                max_tier,
                enforcement,
                roles,
                auth_token,
                principal,
                tls,
                rib_tx,
                rib_query_tx,
                peer_mgr_tx,
                asn,
                router_id,
                listen_port,
                metrics,
                start_time,
                mrt_trigger_tx,
                evpn_originated_local_mac_count,
                evpn_ip_vrf_status_snapshot,
                evpn_originated_ip_vrf_route_count,
                evpn_installed_ip_vrf_route_count,
                evpn_remote_ip_prefix_drop_counts,
                evpn_fdb_nexthop_snapshot,
                evpn_runtime_model,
                evpn_runtime_apply,
                evpn_duplicate_mac_clear,
                blackhole_discard_snapshot,
                fib_route_snapshot,
                dataplane_route_events,
                bfd_session_snapshot,
                bfd_events,
                dataplane_events,
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
                access_mode,
                max_tier,
                enforcement,
                roles,
                auth_token,
                principal,
                rib_tx,
                rib_query_tx,
                peer_mgr_tx,
                asn,
                router_id,
                listen_port,
                metrics,
                start_time,
                mrt_trigger_tx,
                evpn_originated_local_mac_count,
                evpn_ip_vrf_status_snapshot,
                evpn_originated_ip_vrf_route_count,
                evpn_installed_ip_vrf_route_count,
                evpn_remote_ip_prefix_drop_counts,
                evpn_fdb_nexthop_snapshot,
                evpn_runtime_model,
                evpn_runtime_apply,
                evpn_duplicate_mac_clear,
                blackhole_discard_snapshot,
                fib_route_snapshot,
                dataplane_route_events,
                bfd_session_snapshot,
                bfd_events,
                dataplane_events,
                shutdown_rx,
                rpc_shutdown_tx,
                config_tx,
            )
            .await
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "startup wiring for one listener"
)]
async fn run_tcp_listener(
    addr: SocketAddr,
    access_mode: AccessMode,
    max_tier: AuthTier,
    enforcement: AuthEnforcement,
    roles: Arc<BTreeMap<String, PrincipalRole>>,
    auth_token: Option<String>,
    principal: Option<String>,
    tls: Option<TlsParams>,
    rib_tx: mpsc::Sender<RibUpdate>,
    rib_query_tx: mpsc::Sender<RibUpdate>,
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    asn: u32,
    router_id: String,
    listen_port: u32,
    metrics: BgpMetrics,
    start_time: tokio::time::Instant,
    mrt_trigger_tx: Option<MrtTriggerTx>,
    evpn_originated_local_mac_count: OriginatedLocalMacCountFn,
    evpn_ip_vrf_status_snapshot: crate::evpn_service::IpVrfStatusSnapshotFn,
    evpn_originated_ip_vrf_route_count: crate::evpn_service::OriginatedIpVrfRouteCountFn,
    evpn_installed_ip_vrf_route_count: crate::evpn_service::InstalledIpVrfRouteCountFn,
    evpn_remote_ip_prefix_drop_counts: crate::evpn_service::RemoteIpPrefixDropCountSnapshotFn,
    evpn_fdb_nexthop_snapshot: crate::evpn_service::FdbNexthopSnapshotFn,
    evpn_runtime_model: EvpnRuntimeModelFn,
    evpn_runtime_apply: Option<EvpnRuntimeApplyFn>,
    evpn_duplicate_mac_clear: Option<DuplicateMacClearFn>,
    blackhole_discard_snapshot: crate::rib_service::BlackholeDiscardSnapshotFn,
    fib_route_snapshot: crate::rib_service::FibRouteSnapshotFn,
    dataplane_route_events: Option<tokio::sync::broadcast::Sender<crate::proto::BgpEvent>>,
    bfd_session_snapshot: crate::bfd_service::BfdSessionSnapshotFn,
    bfd_events: Option<tokio::sync::broadcast::Sender<crate::proto::BgpEvent>>,
    dataplane_events: DataplaneEventBroadcaster,
    shutdown_rx: watch::Receiver<bool>,
    rpc_shutdown_tx: watch::Sender<bool>,
    config_tx: Option<mpsc::Sender<ConfigEvent>>,
) -> Result<(), String> {
    let tcp_listener = TcpListener::bind(addr)
        .await
        .map_err(|e| format!("failed to bind gRPC TCP listener {addr}: {e}"))?;
    let bound_addr = tcp_listener.local_addr().unwrap_or(addr);
    info!(
        %bound_addr,
        requested_addr = %addr,
        access_mode = ?access_mode,
        auth_enabled = auth_token.is_some(),
        tls_enabled = tls.is_some(),
        "starting gRPC TCP listener"
    );
    let audit_context = tcp_audit_context(
        bound_addr,
        access_mode,
        max_tier,
        RuntimeAuthzConfig { enforcement, roles },
        auth_token.as_deref(),
        tls.is_some(),
        principal.as_deref(),
    );
    let interceptor = AuthInterceptor::new(auth_token.as_deref());
    let mut builder = Server::builder();
    if let Some(tls) = tls {
        let identity = tonic::transport::Identity::from_pem(&tls.cert_pem, &tls.key_pem);
        let client_ca = tonic::transport::Certificate::from_pem(&tls.client_ca_pem);
        let tls_cfg = tonic::transport::ServerTlsConfig::new()
            .identity(identity)
            .client_ca_root(client_ca);
        builder = builder
            .tls_config(tls_cfg)
            .map_err(|e| format!("TCP listener {addr} TLS config invalid: {e}"))?;
    }
    let mut builder = builder.layer(GrpcAuthzLayer::new(audit_context, metrics.clone()));
    let incoming =
        TcpListenerStream::new(tcp_listener).map(|accepted| accepted.map(RustbgpdTcpStream::new));
    builder
        .add_service(RibServiceServer::with_interceptor(
            RibService::with_status_snapshots_and_metrics(
                rib_query_tx.clone(),
                blackhole_discard_snapshot.clone(),
                fib_route_snapshot.clone(),
                metrics.clone(),
            ),
            interceptor.clone(),
        ))
        .add_service(EventServiceServer::with_interceptor(
            EventService::with_dataplane_snapshots_broadcaster_and_metrics(
                rib_tx.clone(),
                peer_mgr_tx.clone(),
                blackhole_discard_snapshot.clone(),
                fib_route_snapshot.clone(),
                dataplane_events,
                dataplane_route_events,
                bfd_events,
                metrics.clone(),
            ),
            interceptor.clone(),
        ))
        .add_service(BfdServiceServer::with_interceptor(
            BfdService::with_snapshot(bfd_session_snapshot),
            interceptor.clone(),
        ))
        .add_service(InjectionServiceServer::with_interceptor(
            InjectionService::new(rib_tx, access_mode),
            interceptor.clone(),
        ))
        .add_service(NeighborServiceServer::with_interceptor(
            NeighborService::new(
                asn,
                access_mode,
                peer_mgr_tx.clone(),
                rib_query_tx.clone(),
                config_tx.clone(),
            ),
            interceptor.clone(),
        ))
        .add_service(PeerGroupServiceServer::with_interceptor(
            PeerGroupService::new(access_mode, peer_mgr_tx.clone(), config_tx.clone()),
            interceptor.clone(),
        ))
        .add_service(PolicyServiceServer::with_interceptor(
            PolicyService::new(access_mode, peer_mgr_tx.clone(), config_tx.clone()),
            interceptor.clone(),
        ))
        .add_service(GlobalServiceServer::with_interceptor(
            GlobalService::new(access_mode, asn, router_id, listen_port),
            interceptor.clone(),
        ))
        .add_service(ConfigServiceServer::with_interceptor(
            ConfigService::new(peer_mgr_tx.clone()),
            interceptor.clone(),
        ))
        .add_service(EvpnServiceServer::with_interceptor(
            EvpnService::with_full_surface_runtime_and_duplicate_mac_control(
                evpn_originated_local_mac_count,
                evpn_ip_vrf_status_snapshot,
                evpn_originated_ip_vrf_route_count,
                evpn_installed_ip_vrf_route_count,
                evpn_fdb_nexthop_snapshot,
                evpn_runtime_model,
                evpn_runtime_apply,
                access_mode,
                evpn_duplicate_mac_clear,
            )
            .with_remote_ip_prefix_drop_counts(evpn_remote_ip_prefix_drop_counts),
            interceptor.clone(),
        ))
        .add_service(ControlServiceServer::with_interceptor(
            ControlService::new(
                access_mode,
                start_time,
                metrics,
                peer_mgr_tx,
                rib_query_tx,
                rpc_shutdown_tx,
                mrt_trigger_tx,
            ),
            interceptor,
        ))
        .serve_with_incoming_shutdown(incoming, await_shutdown(shutdown_rx))
        .await
        .map_err(|e| format!("TCP listener {bound_addr} failed: {e}"))
}

#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "startup wiring for one listener"
)]
async fn run_uds_listener(
    path: PathBuf,
    mode: u32,
    access_mode: AccessMode,
    max_tier: AuthTier,
    enforcement: AuthEnforcement,
    roles: Arc<BTreeMap<String, PrincipalRole>>,
    auth_token: Option<String>,
    principal: Option<String>,
    rib_tx: mpsc::Sender<RibUpdate>,
    rib_query_tx: mpsc::Sender<RibUpdate>,
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    asn: u32,
    router_id: String,
    listen_port: u32,
    metrics: BgpMetrics,
    start_time: tokio::time::Instant,
    mrt_trigger_tx: Option<MrtTriggerTx>,
    evpn_originated_local_mac_count: OriginatedLocalMacCountFn,
    evpn_ip_vrf_status_snapshot: crate::evpn_service::IpVrfStatusSnapshotFn,
    evpn_originated_ip_vrf_route_count: crate::evpn_service::OriginatedIpVrfRouteCountFn,
    evpn_installed_ip_vrf_route_count: crate::evpn_service::InstalledIpVrfRouteCountFn,
    evpn_remote_ip_prefix_drop_counts: crate::evpn_service::RemoteIpPrefixDropCountSnapshotFn,
    evpn_fdb_nexthop_snapshot: crate::evpn_service::FdbNexthopSnapshotFn,
    evpn_runtime_model: EvpnRuntimeModelFn,
    evpn_runtime_apply: Option<EvpnRuntimeApplyFn>,
    evpn_duplicate_mac_clear: Option<DuplicateMacClearFn>,
    blackhole_discard_snapshot: crate::rib_service::BlackholeDiscardSnapshotFn,
    fib_route_snapshot: crate::rib_service::FibRouteSnapshotFn,
    dataplane_route_events: Option<tokio::sync::broadcast::Sender<crate::proto::BgpEvent>>,
    bfd_session_snapshot: crate::bfd_service::BfdSessionSnapshotFn,
    bfd_events: Option<tokio::sync::broadcast::Sender<crate::proto::BgpEvent>>,
    dataplane_events: DataplaneEventBroadcaster,
    shutdown_rx: watch::Receiver<bool>,
    rpc_shutdown_tx: watch::Sender<bool>,
    config_tx: Option<mpsc::Sender<ConfigEvent>>,
) -> Result<(), String> {
    let uds_listener = bind_uds_listener(&path, mode)?;
    let auth_enabled = auth_token.is_some();
    let audit_context = uds_audit_context(
        &path,
        access_mode,
        max_tier,
        RuntimeAuthzConfig { enforcement, roles },
        auth_token.as_deref(),
        principal.as_deref(),
    );
    info!(
        path = %path.display(),
        access_mode = ?access_mode,
        auth_enabled,
        "starting gRPC UDS listener"
    );
    let interceptor = AuthInterceptor::new(auth_token.as_deref());
    let result = Server::builder()
        .layer(GrpcAuthzLayer::new(audit_context, metrics.clone()))
        .add_service(RibServiceServer::with_interceptor(
            RibService::with_status_snapshots_and_metrics(
                rib_query_tx.clone(),
                blackhole_discard_snapshot.clone(),
                fib_route_snapshot.clone(),
                metrics.clone(),
            ),
            interceptor.clone(),
        ))
        .add_service(EventServiceServer::with_interceptor(
            EventService::with_dataplane_snapshots_broadcaster_and_metrics(
                rib_tx.clone(),
                peer_mgr_tx.clone(),
                blackhole_discard_snapshot.clone(),
                fib_route_snapshot.clone(),
                dataplane_events,
                dataplane_route_events,
                bfd_events,
                metrics.clone(),
            ),
            interceptor.clone(),
        ))
        .add_service(BfdServiceServer::with_interceptor(
            BfdService::with_snapshot(bfd_session_snapshot),
            interceptor.clone(),
        ))
        .add_service(InjectionServiceServer::with_interceptor(
            InjectionService::new(rib_tx, access_mode),
            interceptor.clone(),
        ))
        .add_service(NeighborServiceServer::with_interceptor(
            NeighborService::new(
                asn,
                access_mode,
                peer_mgr_tx.clone(),
                rib_query_tx.clone(),
                config_tx.clone(),
            ),
            interceptor.clone(),
        ))
        .add_service(PeerGroupServiceServer::with_interceptor(
            PeerGroupService::new(access_mode, peer_mgr_tx.clone(), config_tx.clone()),
            interceptor.clone(),
        ))
        .add_service(PolicyServiceServer::with_interceptor(
            PolicyService::new(access_mode, peer_mgr_tx.clone(), config_tx.clone()),
            interceptor.clone(),
        ))
        .add_service(GlobalServiceServer::with_interceptor(
            GlobalService::new(access_mode, asn, router_id, listen_port),
            interceptor.clone(),
        ))
        .add_service(ConfigServiceServer::with_interceptor(
            ConfigService::new(peer_mgr_tx.clone()),
            interceptor.clone(),
        ))
        .add_service(EvpnServiceServer::with_interceptor(
            EvpnService::with_full_surface_runtime_and_duplicate_mac_control(
                evpn_originated_local_mac_count,
                evpn_ip_vrf_status_snapshot,
                evpn_originated_ip_vrf_route_count,
                evpn_installed_ip_vrf_route_count,
                evpn_fdb_nexthop_snapshot,
                evpn_runtime_model,
                evpn_runtime_apply,
                access_mode,
                evpn_duplicate_mac_clear,
            )
            .with_remote_ip_prefix_drop_counts(evpn_remote_ip_prefix_drop_counts),
            interceptor.clone(),
        ))
        .add_service(ControlServiceServer::with_interceptor(
            ControlService::new(
                access_mode,
                start_time,
                metrics,
                peer_mgr_tx,
                rib_query_tx,
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

    fn empty_roles() -> Arc<BTreeMap<String, PrincipalRole>> {
        Arc::new(BTreeMap::new())
    }

    fn legacy_authz() -> RuntimeAuthzConfig {
        RuntimeAuthzConfig {
            enforcement: AuthEnforcement::Legacy,
            roles: empty_roles(),
        }
    }

    #[test]
    fn auth_interceptor_allows_unprotected_requests() {
        let mut interceptor = AuthInterceptor::new(None);
        assert!(interceptor.call(Request::new(())).is_ok());
    }

    #[test]
    fn auth_interceptor_rejects_missing_token() {
        let mut interceptor = AuthInterceptor::new(Some("secret"));
        let err = interceptor.call(Request::new(())).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn auth_interceptor_accepts_matching_token() {
        let mut interceptor = AuthInterceptor::new(Some("secret"));
        let mut request = Request::new(());
        request
            .metadata_mut()
            .insert("authorization", "Bearer secret".parse().unwrap());
        assert!(interceptor.call(request).is_ok());
    }

    #[test]
    fn auth_interceptor_rejects_wrong_token() {
        let mut interceptor = AuthInterceptor::new(Some("secret"));
        let mut request = Request::new(());
        request
            .metadata_mut()
            .insert("authorization", "Bearer wrong".parse().unwrap());
        let err = interceptor.call(request).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn tcp_audit_context_uses_configured_bearer_principal() {
        let context = tcp_audit_context(
            "127.0.0.1:50051".parse().unwrap(),
            AccessMode::ReadWrite,
            AuthTier::OperatorOnly,
            legacy_authz(),
            Some("secret"),
            false,
            Some("automation.example"),
        );
        assert_eq!(context.authn(), GrpcAuthnKind::BearerToken);
        assert_eq!(context.principal(), "automation.example");
        assert_eq!(context.max_tier(), AuthTier::OperatorOnly);
    }

    #[test]
    fn tcp_audit_context_uses_mtls_fallback_until_request_cert_available() {
        let context = tcp_audit_context(
            "127.0.0.1:50051".parse().unwrap(),
            AccessMode::ReadWrite,
            AuthTier::Mutating,
            legacy_authz(),
            Some("secret"),
            true,
            Some("automation.example"),
        );
        assert_eq!(context.authn(), GrpcAuthnKind::Mtls);
        assert_eq!(context.principal(), "mtls-unresolved");
        assert_eq!(context.max_tier(), AuthTier::Mutating);
    }

    #[test]
    fn uds_audit_context_uses_configured_principal() {
        let context = uds_audit_context(
            Path::new("/run/rustbgpd/grpc.sock"),
            AccessMode::ReadWrite,
            AuthTier::SensitiveRead,
            legacy_authz(),
            None,
            Some("local-admin"),
        );
        assert_eq!(context.authn(), GrpcAuthnKind::Uds);
        assert_eq!(context.principal(), "local-admin");
        assert_eq!(context.max_tier(), AuthTier::SensitiveRead);
    }
}
