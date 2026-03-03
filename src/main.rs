//! rustbgpd — API-first BGP daemon
//!
//! Binary entry point. Loads config, wires components, starts runtime.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

mod config;
mod metrics_server;
mod peer_manager;

use std::net::Ipv4Addr;
use std::process;

use rustbgpd_rib::{RibManager, RibUpdate};
use rustbgpd_telemetry::{BgpMetrics, init_logging};
use rustbgpd_transport::BgpListener;
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info, warn};

use rustbgpd_api::peer_types::{PeerManagerCommand, PeerManagerNeighborConfig};
use rustbgpd_api::server::ServeConfig;

use crate::config::Config;
use crate::peer_manager::PeerManager;

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
async fn run(config: Config) {
    let start_time = tokio::time::Instant::now();

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

    // Build global export policy for RIB manager fallback
    let export_policy = config.export_policy().unwrap_or_else(|e| {
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

    // Spawn PeerManager (keep JoinHandle for coordinated shutdown)
    let (peer_mgr_tx, peer_mgr_rx) = mpsc::channel::<PeerManagerCommand>(64);
    let peer_mgr = PeerManager::new(
        peer_mgr_rx,
        config.global.asn,
        router_id,
        cluster_id,
        metrics.clone(),
        rib_tx.clone(),
    );
    let peer_mgr_handle = tokio::spawn(peer_mgr.run());

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
                    local_ipv6_nexthop: transport_config.local_ipv6_nexthop,
                    route_reflector_client: transport_config.route_reflector_client,
                    add_path_receive: transport_config.peer.add_path_receive,
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

    // Wait for shutdown signal: ctrl_c, Shutdown RPC, or unexpected gRPC exit
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            match result {
                Ok(()) => info!("received shutdown signal"),
                Err(e) => error!(error = %e, "failed to listen for shutdown signal"),
            }
        }
        _ = &mut rpc_shutdown_rx => {
            info!("shutdown initiated via gRPC");
        }
        result = &mut grpc_handle => {
            error!(?result, "gRPC server exited unexpectedly");
            info!("initiating shutdown due to gRPC server failure");
        }
    }

    // Coordinated shutdown:
    // 1. Tell PeerManager to shut down (sends NOTIFICATIONs to all peers)
    info!("initiating coordinated shutdown");
    let _ = peer_mgr_tx.send(PeerManagerCommand::Shutdown).await;

    // 2. Wait for PeerManager to finish draining all peers
    if let Err(e) = peer_mgr_handle.await {
        error!(error = %e, "peer manager task panicked");
    }

    // 3. Stop the gRPC server
    let _ = grpc_shutdown_tx.send(());

    info!("rustbgpd exiting");
}
