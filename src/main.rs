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
use tokio::sync::mpsc;
use tracing::{error, info};

use rustbgpd_api::peer_types::{PeerManagerCommand, PeerManagerNeighborConfig};

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

async fn run(config: Config) {
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
    let export_policy = config.export_policy();

    // Spawn RIB manager
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(4096);
    tokio::spawn(RibManager::new(rib_rx, export_policy).run());

    // Spawn PeerManager
    let (peer_mgr_tx, peer_mgr_rx) = mpsc::channel::<PeerManagerCommand>(64);
    let peer_mgr = PeerManager::new(
        peer_mgr_rx,
        config.global.asn,
        router_id,
        metrics.clone(),
        rib_tx.clone(),
    );
    tokio::spawn(peer_mgr.run());

    // Spawn gRPC API server
    let grpc_rib_tx = rib_tx.clone();
    let grpc_peer_mgr_tx = peer_mgr_tx.clone();
    tokio::spawn(async move {
        rustbgpd_api::server::serve(grpc_addr, grpc_rib_tx, grpc_peer_mgr_tx).await;
    });

    // Add initial peers from config via PeerManager
    let peer_configs = config.to_peer_configs();
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

    // Wait for shutdown signal
    match tokio::signal::ctrl_c().await {
        Ok(()) => info!("received shutdown signal"),
        Err(e) => error!(error = %e, "failed to listen for shutdown signal"),
    }

    // Graceful shutdown via PeerManager
    let _ = peer_mgr_tx.send(PeerManagerCommand::Shutdown).await;

    info!("rustbgpd exiting");
}
