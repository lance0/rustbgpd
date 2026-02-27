//! rustbgpd — API-first BGP daemon
//!
//! Binary entry point. Loads config, wires components, starts runtime.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

mod config;
mod metrics_server;

use std::process;

use rustbgpd_rib::{RibManager, RibUpdate};
use rustbgpd_telemetry::{BgpMetrics, init_logging};
use rustbgpd_transport::PeerHandle;
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::config::Config;

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

    // Spawn metrics HTTP server
    let metrics_clone = metrics.clone();
    tokio::spawn(async move {
        metrics_server::serve_metrics(prometheus_addr, metrics_clone).await;
    });

    // Spawn RIB manager
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(4096);
    tokio::spawn(RibManager::new(rib_rx).run());

    // Spawn gRPC API server
    let grpc_rib_tx = rib_tx.clone();
    tokio::spawn(async move {
        rustbgpd_api::server::serve(grpc_addr, grpc_rib_tx).await;
    });

    // Spawn peer sessions
    let peer_configs = config.to_peer_configs();
    let mut handles: Vec<(PeerHandle, String)> = Vec::with_capacity(peer_configs.len());

    for (transport_config, label) in peer_configs {
        info!(
            peer = %transport_config.remote_addr,
            label = %label,
            remote_asn = transport_config.peer.remote_asn,
            "spawning peer session"
        );
        let handle = PeerHandle::spawn(transport_config, metrics.clone(), rib_tx.clone());
        if let Err(e) = handle.start().await {
            error!(label = %label, error = %e, "failed to start peer session");
        }
        handles.push((handle, label));
    }

    // Wait for shutdown signal
    match tokio::signal::ctrl_c().await {
        Ok(()) => info!("received shutdown signal"),
        Err(e) => error!(error = %e, "failed to listen for shutdown signal"),
    }

    // Graceful shutdown: stop all peers
    info!("shutting down {} peer sessions", handles.len());
    for (handle, label) in handles {
        info!(label = %label, "shutting down peer");
        match handle.shutdown().await {
            Ok(Ok(())) => info!(label = %label, "peer shut down cleanly"),
            Ok(Err(e)) => error!(label = %label, error = %e, "peer shutdown error"),
            Err(e) => error!(label = %label, error = %e, "peer task join error"),
        }
    }

    info!("rustbgpd exiting");
}
