//! rustbgpd — API-first BGP daemon
//!
//! Binary entry point. Loads config, wires components, starts runtime.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

mod config;
mod config_persister;
mod metrics_server;
mod peer_manager;

use std::net::Ipv4Addr;
use std::path::Path;
use std::process;
use std::time::{Duration, Instant as StdInstant, SystemTime, UNIX_EPOCH};

use rustbgpd_rib::{RibManager, RibUpdate};
use rustbgpd_telemetry::{BgpMetrics, init_logging};
use rustbgpd_transport::BgpListener;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use rustbgpd_api::peer_types::{PeerManagerCommand, PeerManagerNeighborConfig};
use rustbgpd_api::server::ServeConfig;
use rustbgpd_policy::PolicyChain;

use crate::config::Config;
use crate::config_persister::{ConfigMutation, ConfigPersister};
use crate::peer_manager::PeerManager;

const GR_RESTART_MARKER_VERSION: u8 = 1;

#[derive(Debug, Serialize, Deserialize)]
struct GrRestartMarker {
    version: u8,
    expires_at_unix: u64,
}

struct BmpRuntime {
    control_tx: mpsc::Sender<rustbgpd_bmp::BmpControlEvent>,
    manager_handle: JoinHandle<()>,
    client_handles: Vec<JoinHandle<()>>,
}

fn max_gr_restart_time_secs(config: &Config) -> Option<u64> {
    config
        .neighbors
        .iter()
        .filter(|neighbor| neighbor.graceful_restart.unwrap_or(true))
        .map(|neighbor| u64::from(neighbor.gr_restart_time.unwrap_or(120)))
        .max()
}

fn marker_expires_at(marker: &GrRestartMarker) -> Result<SystemTime, String> {
    if marker.version != GR_RESTART_MARKER_VERSION {
        return Err(format!(
            "unsupported marker version {} (expected {})",
            marker.version, GR_RESTART_MARKER_VERSION
        ));
    }
    UNIX_EPOCH
        .checked_add(Duration::from_secs(marker.expires_at_unix))
        .ok_or_else(|| "marker expiry overflows system clock".to_string())
}

fn read_gr_restart_marker(path: &Path) -> Result<Option<SystemTime>, String> {
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let marker: GrRestartMarker = toml::from_str(&content).map_err(|e| e.to_string())?;
    marker_expires_at(&marker).map(Some)
}

fn write_gr_restart_marker(path: &Path, expires_at: SystemTime) -> std::io::Result<()> {
    let expires_at_unix = expires_at
        .duration_since(UNIX_EPOCH)
        .map_err(|e| std::io::Error::other(e.to_string()))?
        .as_secs();
    let marker = GrRestartMarker {
        version: GR_RESTART_MARKER_VERSION,
        expires_at_unix,
    };
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "restart marker path has no parent directory",
        )
    })?;
    std::fs::create_dir_all(parent)?;
    let encoded = toml::to_string(&marker).map_err(|e| std::io::Error::other(e.to_string()))?;
    std::fs::write(path, encoded)
}

fn remove_gr_restart_marker(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn main() {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/rustbgpd/config.toml".to_string());

    let config = match Config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: failed to load config from {config_path}: {e}");
            process::exit(1);
        }
    };

    if let Err(e) = init_logging() {
        eprintln!("error: failed to initialize logging: {e}");
        process::exit(1);
    }

    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(run(config));
}

#[expect(clippy::too_many_lines)]
async fn run(mut config: Config) {
    let start_time = tokio::time::Instant::now();
    let gr_restart_marker_path = config.gr_restart_marker_path();
    let local_gr_restart_until = match read_gr_restart_marker(&gr_restart_marker_path) {
        Ok(Some(expires_at)) => {
            if let Ok(remaining) = expires_at.duration_since(SystemTime::now()) {
                let deadline = StdInstant::now() + remaining;
                info!(
                    marker = %gr_restart_marker_path.display(),
                    restart_time_secs = remaining.as_secs(),
                    "detected GR restart marker — static peers will advertise R=1 until the restart window expires"
                );
                Some(deadline)
            } else {
                info!(
                    marker = %gr_restart_marker_path.display(),
                    "ignoring expired GR restart marker"
                );
                if let Err(e) = remove_gr_restart_marker(&gr_restart_marker_path) {
                    warn!(
                        marker = %gr_restart_marker_path.display(),
                        error = %e,
                        "failed to remove expired GR restart marker"
                    );
                }
                None
            }
        }
        Ok(None) => None,
        Err(e) => {
            warn!(
                marker = %gr_restart_marker_path.display(),
                error = %e,
                "ignoring invalid GR restart marker — starting without restarting-speaker mode"
            );
            if let Err(remove_err) = remove_gr_restart_marker(&gr_restart_marker_path) {
                warn!(
                    marker = %gr_restart_marker_path.display(),
                    error = %remove_err,
                    "failed to remove malformed GR restart marker"
                );
            }
            None
        }
    };

    if let Some(deadline) = local_gr_restart_until {
        let marker_path = gr_restart_marker_path.clone();
        let sleep_for = deadline.saturating_duration_since(StdInstant::now());
        tokio::spawn(async move {
            tokio::time::sleep(sleep_for).await;
            if let Err(e) = remove_gr_restart_marker(&marker_path) {
                warn!(
                    marker = %marker_path.display(),
                    error = %e,
                    "failed to remove expired GR restart marker"
                );
            }
        });
    }

    info!(
        version = env!("CARGO_PKG_VERSION"),
        asn = config.global.asn,
        router_id = %config.global.router_id,
        neighbors = config.neighbors.len(),
        "starting rustbgpd"
    );

    let metrics = BgpMetrics::new();
    let prometheus_addr = config.prometheus_addr();
    let grpc_addr = config.grpc_addr();
    let router_id: Ipv4Addr = config
        .global
        .router_id
        .parse()
        .expect("validated in Config::load");

    // Spawn metrics HTTP server
    let metrics_clone = metrics.clone();
    tokio::spawn(async move {
        metrics_server::serve_metrics(prometheus_addr, metrics_clone).await;
    });

    // Build global export policy chain for RIB manager fallback
    let export_policy = config.export_chain().unwrap_or_else(|e| {
        error!("invalid global export policy: {e}");
        process::exit(1);
    });

    // Spawn RIB manager
    let cluster_id = config.cluster_id();
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(4096);
    tokio::spawn(RibManager::new(rib_rx, export_policy, cluster_id, metrics.clone()).run());

    // Spawn RPKI subsystem (VRP manager + per-cache RTR clients)
    if let Some(ref rpki_config) = config.rpki
        && !rpki_config.cache_servers.is_empty()
    {
        let (vrp_update_tx, vrp_update_rx) = mpsc::channel(256);
        let (rpki_table_tx, mut rpki_table_rx) = mpsc::channel(16);

        // Spawn VRP manager
        let vrp_mgr = rustbgpd_rpki::VrpManager::new(vrp_update_rx, rpki_table_tx);
        tokio::spawn(vrp_mgr.run());

        // Forward VRP table updates to RIB manager
        let rpki_rib_tx = rib_tx.clone();
        tokio::spawn(async move {
            while let Some(update) = rpki_table_rx.recv().await {
                let _ = rpki_rib_tx
                    .send(RibUpdate::RpkiCacheUpdate {
                        table: update.table,
                    })
                    .await;
            }
        });

        // Spawn one RTR client per configured cache server
        for server in &rpki_config.cache_servers {
            let addr: std::net::SocketAddr = match server.address.parse() {
                Ok(a) => a,
                Err(e) => {
                    error!(
                        address = %server.address,
                        error = %e,
                        "invalid RPKI cache server address — skipping"
                    );
                    continue;
                }
            };
            let client_config = rustbgpd_rpki::RtrClientConfig {
                server_addr: addr,
                refresh_interval: server.refresh_interval,
                retry_interval: server.retry_interval,
                expire_interval: server.expire_interval,
            };
            let client = rustbgpd_rpki::RtrClient::new(client_config, vrp_update_tx.clone());
            info!(server = %addr, "spawning RTR client for RPKI cache");
            tokio::spawn(client.run());
        }
    }

    // Spawn BMP subsystem (manager + per-collector clients)
    let mut bmp_runtime: Option<BmpRuntime> = None;
    let bmp_tx = if let Some(ref bmp_config) = config.bmp
        && !bmp_config.collectors.is_empty()
    {
        let (bmp_event_tx, bmp_event_rx) = mpsc::channel(4096);
        let (bmp_control_tx, bmp_control_rx) = mpsc::channel(256);
        let sys_name = bmp_config.sys_name.clone();
        let sys_descr = if bmp_config.sys_descr.is_empty() {
            format!("rustbgpd {}", env!("CARGO_PKG_VERSION"))
        } else {
            bmp_config.sys_descr.clone()
        };

        let mut collector_txs = Vec::new();
        let mut client_handles = Vec::new();
        for collector in &bmp_config.collectors {
            let addr: std::net::SocketAddr = match collector.address.parse() {
                Ok(a) => a,
                Err(e) => {
                    error!(
                        address = %collector.address,
                        error = %e,
                        "invalid BMP collector address — skipping"
                    );
                    continue;
                }
            };
            let (msg_tx, msg_rx) = mpsc::channel(4096);
            let collector_id = collector_txs.len();
            collector_txs.push(msg_tx);
            let client = rustbgpd_bmp::BmpClient::new(
                rustbgpd_bmp::BmpClientConfig {
                    collector_id,
                    collector_addr: addr,
                    reconnect_interval: collector.reconnect_interval,
                },
                msg_rx,
                sys_name.clone(),
                sys_descr.clone(),
                Some(bmp_control_tx.clone()),
            );
            info!(collector = %addr, "spawning BMP client");
            client_handles.push(tokio::spawn(client.run()));
        }

        let mgr = rustbgpd_bmp::BmpManager::new(bmp_event_rx, bmp_control_rx, collector_txs);
        let manager_handle = tokio::spawn(mgr.run());
        bmp_runtime = Some(BmpRuntime {
            control_tx: bmp_control_tx,
            manager_handle,
            client_handles,
        });

        Some(bmp_event_tx)
    } else {
        None
    };

    // Spawn PeerManager (keep JoinHandle for coordinated shutdown)
    let (peer_mgr_tx, peer_mgr_rx) = mpsc::channel::<PeerManagerCommand>(64);
    let peer_mgr = PeerManager::new(
        peer_mgr_rx,
        config.global.asn,
        router_id,
        cluster_id,
        local_gr_restart_until,
        metrics.clone(),
        rib_tx.clone(),
        bmp_tx,
    );
    let peer_mgr_handle = tokio::spawn(peer_mgr.run());

    // Spawn config persister (converts gRPC config events → disk writes)
    let (config_event_tx, config_mutation_tx) = if let Some(ref path) = config.file_path {
        let (event_tx, mut event_rx) = mpsc::channel::<rustbgpd_api::peer_types::ConfigEvent>(64);
        let (mutation_tx, mutation_rx) = mpsc::channel::<ConfigMutation>(64);
        let persister = ConfigPersister::new(mutation_rx, path.clone(), config.clone());
        tokio::spawn(persister.run());
        let reload_mutation_tx = mutation_tx.clone();

        // Bridge: convert ConfigEvent → ConfigMutation
        tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                let mutation = match event {
                    rustbgpd_api::peer_types::ConfigEvent::NeighborAdded(cfg) => {
                        ConfigMutation::AddNeighbor(Box::new(config::Neighbor {
                            address: cfg.address.to_string(),
                            remote_asn: cfg.remote_asn,
                            description: Some(cfg.description),
                            hold_time: cfg.hold_time,
                            max_prefixes: cfg.max_prefixes,
                            md5_password: None,
                            ttl_security: false,
                            families: cfg
                                .families
                                .iter()
                                .map(|(afi, safi)| match (afi, safi) {
                                    (rustbgpd_wire::Afi::Ipv4, rustbgpd_wire::Safi::Unicast) => {
                                        "ipv4_unicast".to_string()
                                    }
                                    (rustbgpd_wire::Afi::Ipv6, rustbgpd_wire::Safi::Unicast) => {
                                        "ipv6_unicast".to_string()
                                    }
                                    (rustbgpd_wire::Afi::Ipv4, rustbgpd_wire::Safi::FlowSpec) => {
                                        "ipv4_flowspec".to_string()
                                    }
                                    (rustbgpd_wire::Afi::Ipv6, rustbgpd_wire::Safi::FlowSpec) => {
                                        "ipv6_flowspec".to_string()
                                    }
                                    _ => format!("{afi:?}_{safi:?}"),
                                })
                                .collect(),
                            graceful_restart: Some(cfg.graceful_restart),
                            gr_restart_time: Some(cfg.gr_restart_time),
                            gr_stale_routes_time: Some(cfg.gr_stale_routes_time),
                            llgr_stale_time: if cfg.llgr_stale_time > 0 {
                                Some(cfg.llgr_stale_time)
                            } else {
                                None
                            },
                            local_ipv6_nexthop: cfg.local_ipv6_nexthop.map(|a| a.to_string()),
                            route_reflector_client: cfg.route_reflector_client,
                            route_server_client: cfg.route_server_client,
                            add_path: if cfg.add_path_receive || cfg.add_path_send {
                                Some(config::AddPathConfig {
                                    receive: cfg.add_path_receive,
                                    send: cfg.add_path_send,
                                    send_max: if cfg.add_path_send_max > 0 {
                                        Some(cfg.add_path_send_max)
                                    } else {
                                        None
                                    },
                                })
                            } else {
                                None
                            },
                            import_policy: Vec::new(),
                            export_policy: Vec::new(),
                            import_policy_chain: Vec::new(),
                            export_policy_chain: Vec::new(),
                        }))
                    }
                    rustbgpd_api::peer_types::ConfigEvent::NeighborDeleted(addr) => {
                        ConfigMutation::DeleteNeighbor(addr)
                    }
                };
                if mutation_tx.send(mutation).await.is_err() {
                    break;
                }
            }
        });
        (Some(event_tx), Some(reload_mutation_tx))
    } else {
        (None, None)
    };

    // Shutdown channels:
    // - grpc_shutdown: signals the tonic server to stop
    // - rpc_shutdown: given to ControlService so Shutdown RPC can trigger exit
    let (grpc_shutdown_tx, grpc_shutdown_rx) = oneshot::channel::<()>();
    let (rpc_shutdown_tx, mut rpc_shutdown_rx) = oneshot::channel::<()>();

    // Warn if gRPC is bound to a non-loopback address
    if !grpc_addr.ip().is_loopback() {
        warn!(
            %grpc_addr,
            "gRPC server bound to non-loopback address — all RPCs are \
             unauthenticated. Use an auth proxy or mTLS for production \
             non-loopback deployments."
        );
    }

    // Spawn gRPC API server (keep JoinHandle for supervision)
    let grpc_rib_tx = rib_tx.clone();
    let grpc_peer_mgr_tx = peer_mgr_tx.clone();
    let serve_config = ServeConfig {
        asn: config.global.asn,
        router_id: config.global.router_id.clone(),
        listen_port: u32::from(config.global.listen_port),
        metrics: metrics.clone(),
        start_time,
    };
    let mut grpc_handle = tokio::spawn(async move {
        rustbgpd_api::server::serve(
            grpc_addr,
            grpc_rib_tx,
            grpc_peer_mgr_tx,
            serve_config,
            grpc_shutdown_rx,
            rpc_shutdown_tx,
            config_event_tx,
        )
        .await;
    });

    // Spawn BGP inbound TCP listener
    let listen_addr = config.listen_addr();
    let listener_peer_mgr_tx = peer_mgr_tx.clone();
    tokio::spawn(async move {
        let (accept_tx, mut accept_rx) =
            mpsc::channel::<rustbgpd_transport::AcceptedConnection>(64);
        match BgpListener::bind(listen_addr, accept_tx).await {
            Ok(listener) => {
                // Forward accepted connections to PeerManager in a separate task
                let tx = listener_peer_mgr_tx;
                tokio::spawn(async move {
                    while let Some(conn) = accept_rx.recv().await {
                        if let Err(e) = tx
                            .send(PeerManagerCommand::AcceptInbound {
                                stream: conn.stream,
                                peer_addr: conn.peer_addr,
                            })
                            .await
                        {
                            warn!(error = %e, "failed to forward inbound connection to peer manager");
                        }
                    }
                });
                listener.run().await;
            }
            Err(e) => {
                warn!(%listen_addr, error = %e, "failed to bind BGP listener");
            }
        }
    });

    // Add initial peers from config via PeerManager
    let peer_configs = config.to_peer_configs().unwrap_or_else(|e| {
        error!("invalid policy configuration: {e}");
        process::exit(1);
    });
    for (transport_config, label, import_policy, export_policy) in peer_configs {
        info!(
            peer = %transport_config.remote_addr,
            label = %label,
            remote_asn = transport_config.peer.remote_asn,
            "adding peer from config"
        );
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let _ = peer_mgr_tx
            .send(PeerManagerCommand::AddPeer {
                config: PeerManagerNeighborConfig {
                    address: transport_config.remote_addr.ip(),
                    remote_asn: transport_config.peer.remote_asn,
                    description: label.clone(),
                    hold_time: Some(transport_config.peer.hold_time),
                    max_prefixes: transport_config.max_prefixes,
                    families: transport_config.peer.families.clone(),
                    graceful_restart: transport_config.peer.graceful_restart,
                    gr_restart_time: transport_config.peer.gr_restart_time,
                    gr_stale_routes_time: transport_config.gr_stale_routes_time,
                    llgr_stale_time: transport_config.llgr_stale_time,
                    gr_restart_eligible: true,
                    local_ipv6_nexthop: transport_config.local_ipv6_nexthop,
                    route_reflector_client: transport_config.route_reflector_client,
                    route_server_client: transport_config.route_server_client,
                    add_path_receive: transport_config.peer.add_path_receive,
                    add_path_send: transport_config.peer.add_path_send,
                    add_path_send_max: transport_config.peer.add_path_send_max,
                    import_policy,
                    export_policy,
                },
                reply: reply_tx,
            })
            .await;
        match reply_rx.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => error!(label = %label, error = %e, "failed to add peer"),
            Err(e) => error!(label = %label, error = %e, "peer manager reply dropped"),
        }
    }

    // SIGHUP handler for config reload (unix-only, which is our target)
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .expect("failed to register SIGHUP handler");

    // Wait for shutdown signal: ctrl_c, Shutdown RPC, unexpected gRPC exit, or SIGHUP
    loop {
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                match result {
                    Ok(()) => info!("received shutdown signal"),
                    Err(e) => error!(error = %e, "failed to listen for shutdown signal"),
                }
                break;
            }
            _ = &mut rpc_shutdown_rx => {
                info!("shutdown initiated via gRPC");
                break;
            }
            result = &mut grpc_handle => {
                error!(?result, "gRPC server exited unexpectedly");
                info!("initiating shutdown due to gRPC server failure");
                break;
            }
            _ = sighup.recv() => {
                info!("SIGHUP received, reloading configuration");
                let path = config.file_path.as_ref().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
                if let Some(new_config) = reload_config(&path, &config, &peer_mgr_tx).await {
                    // Sync persister's snapshot so future gRPC mutations apply
                    // to the reloaded config, not the stale startup config.
                    if let Some(ref mtx) = config_mutation_tx
                        && let Err(e) = mtx
                            .send(ConfigMutation::ReplaceConfig(Box::new(new_config.clone())))
                            .await
                    {
                        error!(
                            error = %e,
                            "failed to sync config persister after reload — keeping previous in-memory config"
                        );
                        continue;
                    }
                    config = new_config;
                }
            }
        }
    }

    // Coordinated shutdown:
    // 1. Tell PeerManager to shut down (sends NOTIFICATIONs to all peers)
    info!("initiating coordinated shutdown");
    if let Some(restart_time_secs) = max_gr_restart_time_secs(&config) {
        let expires_at = SystemTime::now() + Duration::from_secs(restart_time_secs);
        if let Err(e) = write_gr_restart_marker(&gr_restart_marker_path, expires_at) {
            warn!(
                marker = %gr_restart_marker_path.display(),
                error = %e,
                "failed to write GR restart marker — restarting-speaker mode will be unavailable on the next start (check runtime_state_dir permissions)"
            );
        } else {
            info!(
                marker = %gr_restart_marker_path.display(),
                restart_time_secs,
                "wrote GR restart marker for coordinated shutdown"
            );
        }
    } else if let Err(e) = remove_gr_restart_marker(&gr_restart_marker_path) {
        warn!(
            marker = %gr_restart_marker_path.display(),
            error = %e,
            "failed to clear GR restart marker"
        );
    }
    let _ = peer_mgr_tx.send(PeerManagerCommand::Shutdown).await;

    // 2. Wait for PeerManager to finish draining all peers
    if let Err(e) = peer_mgr_handle.await {
        error!(error = %e, "peer manager task panicked");
    }

    // 3. Shut down BMP subsystem (send explicit shutdown and await bounded drain)
    if let Some(mut bmp_runtime) = bmp_runtime {
        if let Err(e) = bmp_runtime
            .control_tx
            .send(rustbgpd_bmp::BmpControlEvent::Shutdown)
            .await
        {
            warn!(error = %e, "failed to send BMP shutdown control event");
        }

        match tokio::time::timeout(Duration::from_secs(2), &mut bmp_runtime.manager_handle).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => warn!(error = %e, "BMP manager task panicked during shutdown"),
            Err(_) => {
                warn!("BMP manager did not exit within 2s; aborting task");
                bmp_runtime.manager_handle.abort();
            }
        }

        for mut handle in bmp_runtime.client_handles {
            match tokio::time::timeout(Duration::from_secs(2), &mut handle).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!(error = %e, "BMP client task panicked during shutdown"),
                Err(_) => {
                    warn!("BMP client did not exit within 2s; aborting task");
                    handle.abort();
                }
            }
        }
    }

    // 4. Stop the gRPC server
    let _ = grpc_shutdown_tx.send(());

    info!("rustbgpd exiting");
}

/// Build a `PeerManagerNeighborConfig` from transport config components.
fn build_peer_mgr_config(
    tc: &rustbgpd_transport::TransportConfig,
    label: &str,
    import: Option<&PolicyChain>,
    export: Option<&PolicyChain>,
) -> PeerManagerNeighborConfig {
    PeerManagerNeighborConfig {
        address: tc.remote_addr.ip(),
        remote_asn: tc.peer.remote_asn,
        description: label.to_string(),
        hold_time: Some(tc.peer.hold_time),
        max_prefixes: tc.max_prefixes,
        families: tc.peer.families.clone(),
        graceful_restart: tc.peer.graceful_restart,
        gr_restart_time: tc.peer.gr_restart_time,
        gr_stale_routes_time: tc.gr_stale_routes_time,
        llgr_stale_time: tc.llgr_stale_time,
        gr_restart_eligible: false,
        local_ipv6_nexthop: tc.local_ipv6_nexthop,
        route_reflector_client: tc.route_reflector_client,
        route_server_client: tc.route_server_client,
        add_path_receive: tc.peer.add_path_receive,
        add_path_send: tc.peer.add_path_send,
        add_path_send_max: tc.peer.add_path_send_max,
        import_policy: import.cloned(),
        export_policy: export.cloned(),
    }
}

/// Reload configuration from disk and reconcile peers.
///
/// Only neighbor changes take effect — global/RPKI/BMP/metrics changes
/// are logged as warnings and require a full restart.
async fn reload_config(
    config_path: &str,
    current: &Config,
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
) -> Option<Config> {
    let new_config = match Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "config reload failed — keeping current config");
            return None;
        }
    };

    // Warn about sections that require restart
    if new_config.global != current.global {
        warn!("[global] changed — requires full restart to take effect");
    }
    if new_config.rpki != current.rpki {
        warn!("[rpki] changed — requires full restart to take effect");
    }
    if new_config.bmp != current.bmp {
        warn!("[bmp] changed — requires full restart to take effect");
    }

    let diff = config::diff_neighbors(&current.neighbors, &new_config.neighbors);
    if diff.added.is_empty() && diff.removed.is_empty() && diff.changed.is_empty() {
        info!("config reloaded — no neighbor changes detected");
        return Some(new_config);
    }

    info!(
        added = diff.added.len(),
        removed = diff.removed.len(),
        changed = diff.changed.len(),
        "reconciling neighbors after config reload"
    );

    let peer_configs = match new_config.to_peer_configs() {
        Ok(p) => p,
        Err(e) => {
            error!(error = %e, "config reload failed — invalid policy in new config");
            return None;
        }
    };

    // Lookup by address
    let peer_map: std::collections::HashMap<String, _> = peer_configs
        .into_iter()
        .map(|(tc, label, imp, exp)| (tc.remote_addr.ip().to_string(), (tc, label, imp, exp)))
        .collect();

    let resolve = |neighbors: &[config::Neighbor]| -> Vec<PeerManagerNeighborConfig> {
        neighbors
            .iter()
            .filter_map(|n| {
                peer_map.get(&n.address).map(|(tc, label, imp, exp)| {
                    build_peer_mgr_config(tc, label, imp.as_ref(), exp.as_ref())
                })
            })
            .collect()
    };

    let (reply_tx, reply_rx) = oneshot::channel();
    if let Err(e) = peer_mgr_tx
        .send(PeerManagerCommand::ReconcilePeers {
            added: resolve(&diff.added),
            removed: diff.removed,
            changed: resolve(&diff.changed),
            reply: reply_tx,
        })
        .await
    {
        error!(error = %e, "failed to send reconcile command to peer manager");
        return None;
    }
    let reconcile = match reply_rx.await {
        Ok(result) => result,
        Err(e) => {
            error!(
                error = %e,
                "peer manager dropped reconcile reply — keeping current config"
            );
            return None;
        }
    };

    if !reconcile.is_success() {
        for failure in &reconcile.failures {
            warn!(
                kind = ?failure.kind,
                address = %failure.address,
                error = %failure.error,
                "config reload reconciliation operation failed"
            );
        }
        error!(
            failures = reconcile.failures.len(),
            "config reload reconciliation incomplete — keeping current config"
        );
        return None;
    }

    info!("config reload complete");
    Some(new_config)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn unique_temp_path(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("rustbgpd-{name}-{suffix}.toml"))
    }

    #[test]
    fn gr_restart_marker_round_trip() {
        let path = unique_temp_path("gr-restart-marker");
        let expires_at = SystemTime::now() + Duration::from_secs(120);
        write_gr_restart_marker(&path, expires_at).unwrap();
        let read_back = read_gr_restart_marker(&path).unwrap().unwrap();
        let diff = read_back
            .duration_since(expires_at)
            .unwrap_or_else(|e| e.duration());
        assert!(diff < Duration::from_secs(1));
        remove_gr_restart_marker(&path).unwrap();
    }

    #[test]
    fn gr_restart_marker_invalid_version_rejected() {
        let path = unique_temp_path("gr-restart-bad-version");
        std::fs::write(&path, "version = 2\nexpires_at_unix = 1\n").unwrap();
        let err = read_gr_restart_marker(&path).unwrap_err();
        assert!(err.contains("unsupported marker version"));
        remove_gr_restart_marker(&path).unwrap();
    }

    #[test]
    fn max_gr_restart_time_uses_largest_enabled_peer() {
        let config = crate::config::Config {
            global: crate::config::Global {
                asn: 65001,
                router_id: "10.0.0.1".to_string(),
                listen_port: 179,
                cluster_id: None,
                runtime_state_dir: "/tmp".to_string(),
                telemetry: crate::config::TelemetryConfig {
                    prometheus_addr: "127.0.0.1:9179".to_string(),
                    log_format: "json".to_string(),
                    grpc_addr: "127.0.0.1:50051".to_string(),
                },
            },
            neighbors: vec![
                crate::config::Neighbor {
                    address: "10.0.0.2".to_string(),
                    remote_asn: 65002,
                    description: None,
                    hold_time: None,
                    max_prefixes: None,
                    md5_password: None,
                    ttl_security: false,
                    families: Vec::new(),
                    graceful_restart: Some(true),
                    gr_restart_time: Some(90),
                    gr_stale_routes_time: None,
                    llgr_stale_time: None,
                    local_ipv6_nexthop: None,
                    route_reflector_client: false,
                    route_server_client: false,
                    add_path: None,
                    import_policy: Vec::new(),
                    export_policy: Vec::new(),
                    import_policy_chain: Vec::new(),
                    export_policy_chain: Vec::new(),
                },
                crate::config::Neighbor {
                    address: "10.0.0.3".to_string(),
                    remote_asn: 65003,
                    description: None,
                    hold_time: None,
                    max_prefixes: None,
                    md5_password: None,
                    ttl_security: false,
                    families: Vec::new(),
                    graceful_restart: Some(true),
                    gr_restart_time: Some(180),
                    gr_stale_routes_time: None,
                    llgr_stale_time: None,
                    local_ipv6_nexthop: None,
                    route_reflector_client: false,
                    route_server_client: false,
                    add_path: None,
                    import_policy: Vec::new(),
                    export_policy: Vec::new(),
                    import_policy_chain: Vec::new(),
                    export_policy_chain: Vec::new(),
                },
                crate::config::Neighbor {
                    address: "10.0.0.4".to_string(),
                    remote_asn: 65004,
                    description: None,
                    hold_time: None,
                    max_prefixes: None,
                    md5_password: None,
                    ttl_security: false,
                    families: Vec::new(),
                    graceful_restart: Some(false),
                    gr_restart_time: Some(300),
                    gr_stale_routes_time: None,
                    llgr_stale_time: None,
                    local_ipv6_nexthop: None,
                    route_reflector_client: false,
                    route_server_client: false,
                    add_path: None,
                    import_policy: Vec::new(),
                    export_policy: Vec::new(),
                    import_policy_chain: Vec::new(),
                    export_policy_chain: Vec::new(),
                },
            ],
            policy: crate::config::PolicyConfig::default(),
            rpki: None,
            bmp: None,
            file_path: None,
        };

        assert_eq!(max_gr_restart_time_secs(&config), Some(180));
    }
}
