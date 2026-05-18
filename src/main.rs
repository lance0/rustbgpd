//! rustbgpd — API-first BGP daemon
//!
//! Binary entry point. Loads config, wires components, starts runtime.

#![cfg_attr(
    not(any(feature = "jemalloc", feature = "dhat-heap")),
    deny(unsafe_code)
)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

mod blackhole;
mod config;
mod config_persister;
mod evpn_dataplane;
mod evpn_imet;
mod evpn_l3_originator;
mod evpn_originator;
mod evpn_segment;
mod evpn_svi;
mod fib;
mod fib_common;
mod fib_runtime;
mod looking_glass;
mod metrics_server;
mod peer_manager;
mod policy_admin;
mod reload;

use std::net::Ipv4Addr;
use std::path::Path;
use std::process;
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant, SystemTime, UNIX_EPOCH};

use rustbgpd_rib::{RibManager, RibUpdate};
use rustbgpd_telemetry::{BgpMetrics, init_logging};
use rustbgpd_transport::BgpListener;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::config::{Config, GrpcAccessMode, GrpcListener};
use crate::config_persister::{ConfigMutation, ConfigPersister};
use crate::peer_manager::PeerManager;
use crate::reload::{ReloadedConfig, apply_reload_outcome, reload_config, run_config_bridge};
use rustbgpd_api::peer_types::{PeerManagerCommand, PeerManagerNeighborConfig};
use rustbgpd_api::server::{
    AccessMode as GrpcServerAccessMode, ListenerConfig as GrpcListenerConfig, ListenerEndpoint,
    ServeConfig,
};

#[cfg(test)]
use crate::peer_manager::InternalCommand;

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

impl From<GrpcAccessMode> for GrpcServerAccessMode {
    fn from(value: GrpcAccessMode) -> Self {
        match value {
            GrpcAccessMode::ReadOnly => Self::ReadOnly,
            GrpcAccessMode::ReadWrite => Self::ReadWrite,
        }
    }
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

fn load_grpc_token(path: &Path) -> Result<String, String> {
    let token = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read gRPC token file {}: {e}", path.display()))?;
    let token = token.trim_end().to_string();
    if token.is_empty() {
        return Err(format!(
            "gRPC token file {} must contain a non-empty token",
            path.display()
        ));
    }
    Ok(token)
}

fn load_grpc_pem(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    let bytes = std::fs::read(path)
        .map_err(|e| format!("failed to read gRPC {label} file {}: {e}", path.display()))?;
    if bytes.is_empty() {
        return Err(format!("gRPC {label} file {} is empty", path.display()));
    }
    Ok(bytes)
}

fn resolve_grpc_listeners(config: &Config) -> Result<Vec<GrpcListenerConfig>, String> {
    config
        .grpc_listeners()
        .into_iter()
        .map(|listener| match listener {
            GrpcListener::Tcp {
                addr,
                access_mode,
                token_file,
                tls,
            } => {
                let tls_params = tls
                    .map(|paths| {
                        Ok::<_, String>(rustbgpd_api::server::TlsParams {
                            cert_pem: load_grpc_pem(&paths.cert_file, "tls_cert_file")?,
                            key_pem: load_grpc_pem(&paths.key_file, "tls_key_file")?,
                            client_ca_pem: load_grpc_pem(
                                &paths.client_ca_file,
                                "tls_client_ca_file",
                            )?,
                        })
                    })
                    .transpose()?;
                Ok(GrpcListenerConfig {
                    endpoint: ListenerEndpoint::Tcp(addr),
                    access_mode: access_mode.into(),
                    auth_token: token_file.as_deref().map(load_grpc_token).transpose()?,
                    tls: tls_params,
                })
            }
            GrpcListener::Uds {
                path,
                mode,
                access_mode,
                token_file,
            } => Ok(GrpcListenerConfig {
                endpoint: ListenerEndpoint::Uds { path, mode },
                access_mode: access_mode.into(),
                auth_token: token_file.as_deref().map(load_grpc_token).transpose()?,
                tls: None,
            }),
        })
        .collect()
}

fn remove_gr_restart_marker(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn print_config_diff(diff: &config::ConfigDiff) {
    use owo_colors::OwoColorize;

    let reload_header = "Reload-applied changes:".green().to_string();
    let restart_header = "Restart-required changes:".yellow().to_string();
    let add_marker = "+".green().to_string();
    let remove_marker = "-".red().to_string();
    let change_marker = "~".yellow().to_string();
    let restart_marker = "!".yellow().to_string();
    let inline_policy_hint =
        "(migrate inline policy to named definitions + import_chain/export_chain for hot reload)"
            .dimmed()
            .to_string();
    let style = config::ConfigDiffTextStyle {
        reload_header: reload_header.into(),
        restart_header: restart_header.into(),
        add_marker: add_marker.into(),
        remove_marker: remove_marker.into(),
        change_marker: change_marker.into(),
        restart_marker: restart_marker.into(),
        inline_policy_hint: inline_policy_hint.into(),
        no_changes: "No changes.".into(),
    };
    print!("{}", config::format_config_diff_with_style(diff, &style));
}

fn print_startup_banner(config: &Config, grpc_listeners: &[GrpcListenerConfig]) {
    let ebgp = config
        .neighbors
        .iter()
        .filter(|n| n.remote_asn != config.global.asn)
        .count();
    let ibgp = config.neighbors.len() - ebgp;
    let peer_groups = config.peer_groups.len();
    let policies = config.policy.definitions.len();
    let neighbor_sets = config.policy.neighbor_sets.len();

    eprintln!();
    eprintln!(
        "  rustbgpd {} | AS {} | router-id {}",
        env!("CARGO_PKG_VERSION"),
        config.global.asn,
        config.global.router_id,
    );

    // Peers
    let mut peer_parts = Vec::new();
    if ebgp > 0 {
        peer_parts.push(format!("{ebgp} eBGP"));
    }
    if ibgp > 0 {
        peer_parts.push(format!("{ibgp} iBGP"));
    }
    let peer_summary = if peer_parts.is_empty() {
        "0 peers (dynamic-only)".to_string()
    } else {
        format!(
            "{} peers ({})",
            config.neighbors.len(),
            peer_parts.join(", ")
        )
    };
    let pg_suffix = if peer_groups > 0 {
        format!(
            " in {peer_groups} peer group{}",
            if peer_groups == 1 { "" } else { "s" }
        )
    } else {
        String::new()
    };
    eprintln!("  |- {peer_summary}{pg_suffix}");

    // Policy
    if policies > 0 || neighbor_sets > 0 {
        let mut parts = Vec::new();
        if policies > 0 {
            parts.push(format!(
                "{policies} named polic{}",
                if policies == 1 { "y" } else { "ies" }
            ));
        }
        if neighbor_sets > 0 {
            parts.push(format!(
                "{neighbor_sets} neighbor set{}",
                if neighbor_sets == 1 { "" } else { "s" }
            ));
        }
        eprintln!("  |- {}", parts.join(", "));
    }

    // Listeners
    for listener in grpc_listeners {
        let label = match &listener.endpoint {
            ListenerEndpoint::Tcp(addr) => format!("grpc: tcp://{addr}"),
            ListenerEndpoint::Uds { path, .. } => format!("grpc: unix://{}", path.display()),
        };
        let auth = if listener.auth_token.is_some() {
            " (token auth)"
        } else {
            ""
        };
        let access = match listener.access_mode {
            GrpcServerAccessMode::ReadOnly => " (read-only)",
            GrpcServerAccessMode::ReadWrite => "",
        };
        eprintln!("  |- {label}{access}{auth}");
    }

    // Metrics
    if let Some(addr) = config.prometheus_addr() {
        eprintln!("  |- metrics: http://{addr}/metrics");
    }

    // Looking glass
    if let Some(addr) = config.looking_glass_addr() {
        eprintln!("  |- looking glass: http://{addr}/status");
    }

    // Optional subsystems
    if let Some(ref rpki) = config.rpki {
        let n = rpki.cache_servers.len();
        if n > 0 {
            eprintln!("  |- rpki: {n} cache{}", if n == 1 { "" } else { "s" });
        }
    }
    if let Some(ref bmp) = config.bmp {
        let n = bmp.collectors.len();
        if n > 0 {
            eprintln!("  |- bmp: {n} collector{}", if n == 1 { "" } else { "s" });
        }
    }
    if let Some(ref mrt) = config.mrt {
        eprintln!("  |- mrt: {}", mrt.output_dir);
    }

    eprintln!();
}

#[expect(clippy::too_many_lines)]
fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Handle --version / -V before anything else.
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("rustbgpd {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    // Handle --help / -h.
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "rustbgpd {} — API-first BGP daemon\n\n\
             Usage: rustbgpd [OPTIONS] [CONFIG_PATH]\n\n\
             Arguments:\n  \
               CONFIG_PATH  Path to TOML config file [default: /etc/rustbgpd/config.toml]\n\n\
             Options:\n  \
               --check      Validate config and exit without starting the daemon\n  \
               --diff PATH  Compare config against PATH and show what SIGHUP would change\n  \
               --json       Output diff as JSON (only with --diff)\n  \
               --version    Print version and exit\n  \
               --help       Print this help message",
            env!("CARGO_PKG_VERSION")
        );
        return;
    }

    // Parse flags and config path from remaining args.
    let mut check_only = false;
    let mut diff_path: Option<String> = None;
    let mut json_output = false;
    let mut config_path = "/etc/rustbgpd/config.toml".to_string();
    let mut expect_diff_path = false;
    for arg in &args[1..] {
        if expect_diff_path {
            diff_path = Some(arg.clone());
            expect_diff_path = false;
        } else if arg == "--check" {
            check_only = true;
        } else if arg == "--diff" {
            expect_diff_path = true;
        } else if arg == "--json" {
            json_output = true;
        } else if !arg.starts_with('-') {
            config_path.clone_from(arg);
        } else {
            eprintln!("error: unknown option: {arg}");
            eprintln!("usage: rustbgpd [--check] [--diff PATH] [--json] [--version] [CONFIG_PATH]");
            process::exit(1);
        }
    }
    if expect_diff_path {
        eprintln!("error: --diff requires a path argument");
        process::exit(2);
    }
    if json_output && diff_path.is_none() {
        eprintln!("error: --json can only be used with --diff");
        process::exit(2);
    }

    let config = match Config::load_with_diagnostics(&config_path) {
        Ok(c) => c,
        Err(diagnostic) => {
            eprintln!("{diagnostic}");
            process::exit(1);
        }
    };

    if check_only {
        println!("config OK: {config_path}");
        return;
    }

    if let Some(ref diff_target) = diff_path {
        let new_config = match Config::load_with_diagnostics(diff_target) {
            Ok(c) => c,
            Err(diagnostic) => {
                eprintln!("{diagnostic}");
                process::exit(2);
            }
        };
        let diff = config::diff_config(&config, &new_config);
        if json_output {
            let output = config::config_diff_json_value(&diff);
            match serde_json::to_string_pretty(&output) {
                Ok(json) => println!("{json}"),
                Err(e) => {
                    eprintln!("error: failed to serialize diff: {e}");
                    process::exit(2);
                }
            }
        } else {
            print_config_diff(&diff);
        }
        process::exit(i32::from(diff.has_actionable_changes()));
    }

    let log_directives = config.per_peer_log_directives();
    if let Err(e) = init_logging(&log_directives) {
        eprintln!("error: failed to initialize logging: {e}");
        process::exit(1);
    }

    #[cfg(feature = "dhat-heap")]
    let profiler = Some(
        dhat::Profiler::builder()
            .file_name("dhat-heap.json")
            .build(),
    );
    #[cfg(not(feature = "dhat-heap"))]
    let profiler: Option<()> = None;

    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(run(config, profiler));
}

#[expect(clippy::too_many_lines)]
async fn run<T>(mut config: Config, profiler: Option<T>) {
    // Snapshot the gRPC listener config as it was at process start.
    // The live TCP/UDS listeners bind once and are not rebuilt on
    // SIGHUP; this snapshot is what they're actually serving. Reload
    // compares the new declared config against THIS snapshot (not
    // against the in-memory mutable `config`) so drift between
    // declared listener config and live state stays visible across
    // every reload, not just the first one. The runtime config is
    // patched on reload to keep these two listener fields equal to
    // the live state — no other reload semantics change.
    let live_grpc_tcp = config.global.telemetry.grpc_tcp.clone();
    let live_grpc_uds = config.global.telemetry.grpc_uds.clone();

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
    let grpc_listeners = resolve_grpc_listeners(&config).unwrap_or_else(|e| {
        error!(error = %e, "invalid gRPC listener configuration");
        process::exit(1);
    });

    // Startup banner — human-friendly topology summary on stderr.
    print_startup_banner(&config, &grpc_listeners);
    let router_id: Ipv4Addr = config
        .global
        .router_id
        .parse()
        .expect("validated in Config::load");

    // Spawn metrics HTTP server (if configured)
    if let Some(prometheus_addr) = config.prometheus_addr() {
        let metrics_clone = metrics.clone();
        tokio::spawn(async move {
            metrics_server::serve_metrics(prometheus_addr, metrics_clone).await;
        });
    }

    // Build global export policy chain for RIB manager fallback
    let export_policy = config.export_chain().unwrap_or_else(|e| {
        error!("invalid global export policy: {e}");
        process::exit(1);
    });

    // Spawn RIB manager
    let cluster_id = config.cluster_id();
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(4096);
    let (rib_query_tx, rib_query_rx) = mpsc::channel::<RibUpdate>(256);
    tokio::spawn(
        RibManager::new(
            rib_rx,
            rib_query_rx,
            export_policy,
            cluster_id,
            metrics.clone(),
        )
        .run(),
    );

    // Validation snapshot channel: broadcast VRP + ASPA tables to transport
    // sessions for import-time route validation.  Starts empty — sessions fall
    // back to NotFound/Unknown until the first cache update arrives.
    let (validation_watch_tx, validation_watch_rx) =
        tokio::sync::watch::channel(rustbgpd_rpki::ValidationSnapshot::default());

    // Spawn RPKI subsystem (VRP manager + per-cache RTR clients)
    if let Some(ref rpki_config) = config.rpki
        && !rpki_config.cache_servers.is_empty()
    {
        let (vrp_update_tx, vrp_update_rx) = mpsc::channel(256);
        let (rpki_table_tx, mut rpki_table_rx) = mpsc::channel(16);

        // ASPA table channel (VrpManager → RIB)
        let (aspa_table_tx, mut aspa_table_rx) = mpsc::channel(16);

        // Spawn VRP + ASPA manager
        let vrp_mgr = rustbgpd_rpki::VrpManager::new(vrp_update_rx, rpki_table_tx)
            .with_aspa_tx(aspa_table_tx);
        tokio::spawn(vrp_mgr.run());

        // Forward VRP table updates to RIB manager + validation watch
        let rpki_rib_tx = rib_tx.clone();
        let validation_tx_vrp = validation_watch_tx.clone();
        tokio::spawn(async move {
            while let Some(update) = rpki_table_rx.recv().await {
                validation_tx_vrp.send_modify(|snapshot| {
                    snapshot.vrp_table = Some(std::sync::Arc::clone(&update.table));
                });
                let _ = rpki_rib_tx
                    .send(RibUpdate::RpkiCacheUpdate {
                        table: update.table,
                    })
                    .await;
            }
        });

        // Forward ASPA table updates to RIB manager + validation watch
        let aspa_rib_tx = rib_tx.clone();
        let validation_tx_aspa = validation_watch_tx.clone();
        tokio::spawn(async move {
            while let Some(update) = aspa_table_rx.recv().await {
                validation_tx_aspa.send_modify(|snapshot| {
                    snapshot.aspa_table = Some(std::sync::Arc::clone(&update.table));
                });
                let _ = aspa_rib_tx
                    .send(RibUpdate::AspaTableUpdate {
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

        let mut collectors: Vec<(std::net::SocketAddr, mpsc::Sender<bytes::Bytes>)> = Vec::new();
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
            let collector_id = collectors.len();
            collectors.push((addr, msg_tx));
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
                metrics.clone(),
            );
            info!(collector = %addr, "spawning BMP client");
            client_handles.push(tokio::spawn(client.run()));
        }

        let mgr = rustbgpd_bmp::BmpManager::new(
            bmp_event_rx,
            bmp_control_rx,
            collectors,
            metrics.clone(),
        );
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

    // Spawn MRT manager (periodic TABLE_DUMP_V2 snapshots)
    let mrt_trigger_tx: Option<mpsc::Sender<oneshot::Sender<Result<std::path::PathBuf, String>>>> =
        if let Some(ref mrt_config) = config.mrt {
            let writer_config = rustbgpd_mrt::MrtWriterConfig {
                output_dir: std::path::PathBuf::from(&mrt_config.output_dir),
                dump_interval: mrt_config.dump_interval,
                compress: mrt_config.compress,
                file_prefix: mrt_config.file_prefix.clone(),
            };
            let (trigger_tx, trigger_rx) = mpsc::channel(16);
            let mgr =
                rustbgpd_mrt::MrtManager::new(writer_config, rib_tx.clone(), trigger_rx, router_id);
            info!(
                output_dir = %mrt_config.output_dir,
                interval = mrt_config.dump_interval,
                "spawning MRT dump manager"
            );
            tokio::spawn(mgr.run());
            Some(trigger_tx)
        } else {
            None
        };

    // Spawn PeerManager (keep JoinHandle for coordinated shutdown)
    let (peer_mgr_tx, peer_mgr_rx) = mpsc::channel::<PeerManagerCommand>(64);
    let (peer_mgr_internal_tx, peer_mgr_internal_rx) = mpsc::unbounded_channel();
    let peer_mgr = PeerManager::new_with_config(
        peer_mgr_rx,
        peer_mgr_internal_rx,
        config.global.asn,
        router_id,
        cluster_id,
        local_gr_restart_until,
        metrics.clone(),
        rib_tx.clone(),
        bmp_tx,
        Some(validation_watch_rx),
        config.clone(),
    );
    let peer_mgr_handle = tokio::spawn(peer_mgr.run());

    // Spawn config persister (converts gRPC config events → disk writes).
    //
    // Two inputs feed the persister:
    //   * `event_tx` — gRPC layer pushes per-mutation `ConfigEvent`s;
    //     the bridge applies each onto its locally held snapshot and
    //     then forwards a full `ReplaceConfig` to the persister.
    //   * `bridge_replace_tx` — the SIGHUP path pushes the desired
    //     reloaded TOML snapshot. The bridge swaps it into its
    //     locally held snapshot and refreshes the persister base
    //     without writing it back to disk. Runtime may stay pinned for
    //     restart-required fields; disk must preserve the operator's
    //     edit-then-restart intent.
    //
    // The replace path MUST go through the bridge (not directly to
    // the persister) so the bridge's snapshot stays consistent with
    // what's on disk. Otherwise the next gRPC mutation would apply
    // to a stale pre-reload snapshot and overwrite the persisted
    // file with `stale_pre_reload + one_mutation`.
    let (config_event_tx, bridge_replace_tx) = if let Some(ref path) = config.file_path {
        let (event_tx, event_rx) = mpsc::channel::<rustbgpd_api::peer_types::ConfigEvent>(64);
        let (mutation_tx, mutation_rx) = mpsc::channel::<ConfigMutation>(64);
        let (bridge_replace_tx, bridge_replace_rx) = mpsc::unbounded_channel::<Box<Config>>();
        let persister = ConfigPersister::new(mutation_rx, path.clone(), config.clone());
        tokio::spawn(persister.run());
        tokio::spawn(run_config_bridge(
            event_rx,
            bridge_replace_rx,
            mutation_tx,
            config.clone(),
        ));
        (Some(event_tx), Some(bridge_replace_tx))
    } else {
        (None, None)
    };

    // Shutdown channels:
    // - grpc_shutdown: signals all tonic listeners to stop
    // - rpc_shutdown: given to ControlService so Shutdown RPC can trigger exit
    let (grpc_shutdown_tx, grpc_shutdown_rx) = oneshot::channel::<()>();
    let (rpc_shutdown_tx, mut rpc_shutdown_rx) = watch::channel(false);

    for listener in &grpc_listeners {
        match &listener.endpoint {
            ListenerEndpoint::Tcp(addr) => {
                info!(
                    %addr,
                    auth_enabled = listener.auth_token.is_some(),
                    "configured gRPC TCP listener"
                );
                if !addr.ip().is_loopback() && listener.auth_token.is_none() {
                    warn!(
                        %addr,
                        "gRPC TCP listener bound to a non-loopback address without authentication; prefer UDS for local administration or a proxy with mTLS for remote access"
                    );
                } else if !addr.ip().is_loopback() {
                    warn!(
                        %addr,
                        "gRPC TCP listener bound to a non-loopback address with bearer authentication but no transport encryption; prefer a proxy with mTLS for remote access"
                    );
                }
            }
            ListenerEndpoint::Uds { path, mode } => {
                info!(
                    path = %path.display(),
                    mode = format_args!("{mode:o}"),
                    auth_enabled = listener.auth_token.is_some(),
                    "configured gRPC UDS listener"
                );
            }
        }
    }

    // Spawn birdwatcher-compatible looking glass HTTP server (if configured)
    if let Some(lg_addr) = config.looking_glass_addr() {
        let lg_state = std::sync::Arc::new(looking_glass::LookingGlassState::new(
            rib_query_tx.clone(),
            peer_mgr_tx.clone(),
            config.global.asn,
            config.global.router_id.clone(),
        ));
        tokio::spawn(looking_glass::serve(lg_addr, lg_state));
    }

    // Resolve declared EVPN instances once at startup and hand the
    // gRPC layer a shared `Arc`. The validation pass at config load
    // already proved this resolution succeeds, so a second failure
    // here would be a programming error rather than operator input —
    // but we still surface it as a daemon-fatal `expect` to avoid
    // silently dropping instances if a future code path skips
    // validation.
    let evpn_instances = std::sync::Arc::new(
        config
            .resolve_evpn_instances()
            .expect("EVPN instances re-resolve cleanly after Config::validate"),
    );

    // Gate 9 IP-VRFs (`[[evpn_ip_vrfs]]`). Same expect-after-validate
    // pattern as `evpn_instances`. Empty for any deployment without
    // Gate 9 config; the dataplane short-circuits `probe_ip_vrfs` when
    // empty so L2-only and RR-only deployments incur zero added cost.
    let evpn_ip_vrfs = std::sync::Arc::new(
        config
            .resolve_evpn_ip_vrfs()
            .expect("EVPN IP-VRFs re-resolve cleanly after Config::validate"),
    );

    // EVPN Linux dataplane reconciler (Gate 7b). Returns None when
    // [[evpn_instances]] is empty — RR-only deployments don't open a
    // netlink socket and don't spawn the actor. The handle is moved
    // into the coordinated shutdown block at the bottom of main where
    // we await its bounded drain.
    let evpn_dataplane_shutdown = tokio_util::sync::CancellationToken::new();
    let supervisor_config = {
        let mut cfg = evpn_dataplane::SupervisorConfig::default();
        cfg.actor_config.apply_bum_enforcement = config.apply_bum_enforcement;
        cfg
    };
    let mut evpn_dataplane_handle = evpn_dataplane::spawn(
        supervisor_config,
        &evpn_instances,
        &evpn_ip_vrfs,
        rib_tx.clone(),
        metrics.clone(),
        evpn_dataplane_shutdown.clone(),
    )
    .await;

    // EVPN local-MAC originator (Gate 7b+1). Spawned alongside the
    // dataplane supervisor under the same `[[evpn_instances]]` gate.
    // Consumes the upward `LocalMacObservation` channel surfaced by
    // the dataplane (Phase D); kernel-learned MACs become BGP EVPN
    // Type 2 originations per RFC 7432 §15.1. RR-only deployments
    // skip this entirely — `evpn_dataplane::spawn` returned `None`
    // and `local_mac_rx` is therefore `None`.
    let evpn_originator_shutdown = tokio_util::sync::CancellationToken::new();
    let evpn_originated_local_mac_counts = evpn_originator::OriginatedLocalMacCounts::default();
    // Resolve `[[ethernet_segments]]` early so the originator can
    // attach the right ESI to Type 2 routes for MACs learned on
    // multi-homed VNIs (Gate 8b ESI-aware MAC origination). The
    // same resolved table is consumed by `evpn_segment::spawn`
    // below.
    let ethernet_segments = config
        .resolve_ethernet_segments()
        .expect("validated in Config::load");
    let vni_to_esi: std::sync::Arc<
        std::collections::BTreeMap<
            rustbgpd_evpn::EvpnInstanceId,
            rustbgpd_wire::EthernetSegmentIdentifier,
        >,
    > = {
        let mut map = std::collections::BTreeMap::new();
        for seg in &ethernet_segments {
            for &vni in &seg.member_vnis {
                // `Config::resolve_ethernet_segments` rejects
                // duplicate member-VNI across segments at config
                // load, so a `vni` appearing here twice is a logic
                // bug, not an operator misconfiguration. The first
                // write is the only write.
                debug_assert!(!map.contains_key(&vni));
                map.insert(vni, seg.esi);
            }
        }
        std::sync::Arc::new(map)
    };
    let evpn_originator_handle = if let Some(handle) = evpn_dataplane_handle.as_mut() {
        evpn_originator::spawn(
            evpn_originator::OriginatorConfig::default(),
            &evpn_instances,
            rib_tx.clone(),
            handle.local_mac_rx.take(),
            metrics.clone(),
            evpn_originated_local_mac_counts.clone(),
            evpn_originator_shutdown.clone(),
            vni_to_esi.clone(),
        )
    } else {
        None
    };

    // EVPN Type 3 IMET origination (Gate 7b+1 phase F). One Type 3
    // per L2VNI announcing this VTEP's BGP-level VNI membership; not
    // conditioned on kernel readiness. Originated at startup, with
    // the keys retained for shutdown-time withdraw. RR-only paths
    // (empty `evpn_instances`) skip origination entirely — IMET
    // requires a VTEP IP, which an RR doesn't have.
    let evpn_imet_keys: Vec<rustbgpd_wire::EvpnRouteKey> = if evpn_instances.is_empty() {
        Vec::new()
    } else {
        evpn_imet::originate_all(evpn_instances.iter().cloned().collect::<Vec<_>>(), &rib_tx).await
    };

    // EVPN SVI-MAC origination (RFC 9135 §6.1) — gated on any
    // instance setting `advertise_svi_mac = true`. Subscribes to the
    // dataplane handle's report broadcast and originates a Type 2
    // for each Ready bridge's own MAC. `evpn_svi::spawn` returns
    // `None` when no instance opts in, so RR-only and SVI-MAC-off
    // deployments incur zero cost.
    let evpn_svi_shutdown = tokio_util::sync::CancellationToken::new();
    let evpn_svi_handle = if let Some(handle) = evpn_dataplane_handle.as_ref() {
        evpn_svi::spawn(
            &evpn_instances,
            rib_tx.clone(),
            handle.subscribe_reports(),
            metrics.clone(),
            evpn_originated_local_mac_counts.clone(),
            evpn_svi_shutdown.clone(),
        )
    } else {
        None
    };

    // EVPN Ethernet Segment orchestrator (Gate 8 multihoming
    // foundation — observable DF election, no enforcement). Spawned
    // when `[[ethernet_segments]]` has at least one entry and at
    // least one configured `[[evpn_instances]]` exists for the
    // member-VNI table to resolve against. Returns `None` for
    // single-homed deployments and route reflectors.
    let evpn_segment_shutdown = tokio_util::sync::CancellationToken::new();
    // `ethernet_segments` was resolved upstream so the originator
    // could build its `vni_to_esi` lookup before we got here.
    let evpn_segment_handle = if ethernet_segments.is_empty() {
        None
    } else {
        let bum_enforcement_tx = evpn_dataplane_handle
            .as_ref()
            .map(evpn_dataplane::EvpnDataplaneHandle::bum_enforcement_sender);
        evpn_segment::spawn(
            &evpn_instances,
            ethernet_segments,
            rib_tx.clone(),
            bum_enforcement_tx,
            metrics.clone(),
            evpn_segment_shutdown.clone(),
        )
    };

    // Latest snapshot of `DataplaneReport.ip_vrf_status` rows for the
    // gRPC `ListIpVrfs` / `GetIpVrf` surface (Gate 9 slice 5). Backed
    // by a `tokio::sync::watch` so gRPC handlers can read the latest
    // value lock-free (`.borrow().clone()`) without blocking a tokio
    // worker; the subscriber task replaces the value on every
    // dataplane report. RR-only deployments
    // (`evpn_dataplane_handle.is_none()`) leave the initial empty Vec
    // in place — `probe_ip_vrfs` would short-circuit to empty even if
    // the actor ran, so the gRPC surface stays consistent without any
    // wiring.
    let (evpn_ip_vrf_status_tx, evpn_ip_vrf_status_rx) =
        tokio::sync::watch::channel(Vec::<rustbgpd_evpn::IpVrfDataplaneStatus>::new());

    // Latest snapshot of `DataplaneReport.ip_vrf_routes.observations`
    // for the Gate 9 slice 6b L3 originator subscriber and for
    // Prometheus gauge updates. Stays empty on RR-only deployments and
    // when `[[evpn_ip_vrfs]]` is unset — `dump_ip_vrf_routes`
    // short-circuits in both cases.
    let (evpn_ip_vrf_routes_tx, evpn_ip_vrf_routes_rx) =
        tokio::sync::watch::channel(std::sync::Arc::new(std::collections::HashMap::<
            rustbgpd_evpn::IpVrfId,
            Vec<rustbgpd_evpn::LocalIpRouteObservation>,
        >::new()));

    // Latest per-VRF installed-route counts (Gate 9 slice 6c). The
    // reconcile actor's L3 install pipeline emits these on every
    // report; the daemon mirrors them onto a watch channel that the
    // gRPC `IpVrfState.installed_routes_count` field reads
    // lock-free.
    let (evpn_ip_vrf_installed_routes_tx, evpn_ip_vrf_installed_routes_rx) =
        tokio::sync::watch::channel(std::sync::Arc::new(std::collections::HashMap::<
            rustbgpd_evpn::IpVrfId,
            u32,
        >::new()));
    // Latest owned FDB nexthop-group state (ADR-0059). The reconciler
    // publishes the actor-owned group/refcount snapshot on every
    // report; gRPC reads this watch channel lock-free for
    // `EvpnService.ListEvpnNexthops`.
    let (evpn_fdb_nexthops_tx, evpn_fdb_nexthops_rx) =
        tokio::sync::watch::channel(rustbgpd_evpn::FdbNexthopDataplaneStatus::default());
    if let Some(handle) = evpn_dataplane_handle.as_ref() {
        let mut reports = handle.subscribe_reports();
        // Resolve IpVrfId → operator-facing name for the metric labels
        // — same labelling the gRPC surface uses.
        let vrf_id_to_name: std::collections::HashMap<rustbgpd_evpn::IpVrfId, String> =
            evpn_ip_vrfs
                .iter()
                .map(|v| (v.id, v.name.clone()))
                .collect();
        let metrics_for_routes = metrics.clone();
        tokio::spawn(async move {
            loop {
                match reports.recv().await {
                    Ok(report) => {
                        // `send_replace` is the no-await write —
                        // updates the value in place and wakes any
                        // pending watchers. Safe to call from inside
                        // a tokio task without blocking the worker.
                        evpn_fdb_nexthops_tx.send_replace(report.fdb_nexthops);
                        evpn_ip_vrf_status_tx.send_replace(report.ip_vrf_status);
                        // Slice 6a: publish per-VRF observed-routes
                        // gauge values and bump filtered-routes
                        // counters by the per-pass deltas. The
                        // observations themselves are forwarded onto
                        // a watch channel for the L3 originator
                        // (slice 6b) to subscribe to.
                        //
                        // `ip_vrf_routes = None` signals a transient
                        // kernel-dump failure (ADR-0054 §6). Preserve
                        // the watch's last-good value and do not
                        // increment Prometheus counters — the next
                        // successful reconcile pass will re-publish
                        // and bump filter counts from a fresh dump.
                        if let Some(dump) = report.ip_vrf_routes {
                            for (vrf_id, observations) in &dump.observations {
                                let label = vrf_id_to_name
                                    .get(vrf_id)
                                    .cloned()
                                    .unwrap_or_else(|| vrf_id.as_u32().to_string());
                                metrics_for_routes.set_evpn_ip_vrf_observed_routes(
                                    &label,
                                    i64::try_from(observations.len()).unwrap_or(i64::MAX),
                                );
                            }
                            for ((vrf_id, reason), delta) in &dump.filter_counts {
                                let label = vrf_id_to_name
                                    .get(vrf_id)
                                    .cloned()
                                    .unwrap_or_else(|| vrf_id.as_u32().to_string());
                                metrics_for_routes.add_evpn_ip_vrf_observed_routes_filtered(
                                    &label,
                                    reason.label(),
                                    *delta,
                                );
                            }
                            evpn_ip_vrf_routes_tx
                                .send_replace(std::sync::Arc::new(dump.observations));
                        } else {
                            tracing::debug!(
                                "ip-vrf route dump failed this reconcile pass; preserving \
                                 last-good observation snapshot"
                            );
                        }
                        // Slice 6c: publish installed-route counts to
                        // the watch channel + Prometheus gauge. The
                        // reconcile actor populates
                        // `report.ip_vrf_installed_routes` from its
                        // L3 owned set on every pass; this is
                        // authoritative (no `Option` wrap needed
                        // because a kernel dump failure during L3
                        // install just leaves the count at its prior
                        // value — the owned set itself doesn't
                        // change on failure).
                        for (vrf_id, count) in &report.ip_vrf_installed_routes {
                            let label = vrf_id_to_name
                                .get(vrf_id)
                                .cloned()
                                .unwrap_or_else(|| vrf_id.as_u32().to_string());
                            metrics_for_routes
                                .set_evpn_ip_vrf_installed_routes(&label, i64::from(*count));
                        }
                        evpn_ip_vrf_installed_routes_tx
                            .send_replace(std::sync::Arc::new(report.ip_vrf_installed_routes));
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        // The reconcile actor emits at most one report
                        // per pass (5 s default); if this subscriber
                        // fell behind that bound, the broadcast buffer
                        // already replaced the missed entries with
                        // newer ones. Keep going — the next received
                        // report supersedes whatever we missed.
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                }
            }
        });
    }

    // EVPN Type 5 originator (Gate 9 slice 6b). Subscribes to the
    // route-observation watch channel populated above and the slice-5
    // IP-VRF status watch. Returns `None` when no `[[evpn_ip_vrfs]]`
    // are configured, so L2-only and RR-only deployments incur zero
    // cost. The shared `OriginatedIpVrfRouteCounts` is read-only on
    // the gRPC side (below) so handlers can surface
    // `originated_routes_count` without coordinating with the actor.
    let evpn_l3_originator_shutdown = tokio_util::sync::CancellationToken::new();
    let evpn_originated_ip_vrf_route_counts =
        evpn_l3_originator::OriginatedIpVrfRouteCounts::default();
    let evpn_l3_originator_handle = evpn_l3_originator::spawn(evpn_l3_originator::SpawnConfig {
        ip_vrfs: evpn_ip_vrfs.clone(),
        rib_tx: rib_tx.clone(),
        route_observations_rx: evpn_ip_vrf_routes_rx.clone(),
        ip_vrf_status_rx: evpn_ip_vrf_status_rx.clone(),
        metrics: metrics.clone(),
        originated_counts: evpn_originated_ip_vrf_route_counts.clone(),
        shutdown: evpn_l3_originator_shutdown.clone(),
    });

    // RFC 7999 BLACKHOLE kernel-discard reconciler (ADR-0060 FIB
    // slice). Completely opt-in: `install_blackhole_discard = true`
    // is effective only alongside `honor_blackhole = true`, and the
    // actor itself still enforces host-prefix-only by default.
    let (blackhole_status_tx, blackhole_status_rx) =
        tokio::sync::watch::channel(Vec::<blackhole::BlackholeStatus>::new());
    let blackhole_shutdown = tokio_util::sync::CancellationToken::new();
    let blackhole_handle = blackhole::spawn(
        blackhole::BlackholeConfig {
            enabled: config.global.honor_blackhole && config.global.install_blackhole_discard,
            allow_broad_prefixes: config.global.allow_blackhole_broad_prefixes,
        },
        rib_tx.clone(),
        metrics.clone(),
        blackhole_status_tx,
        blackhole_shutdown.clone(),
    );

    // ADR-0061 general unicast FIB reconciler. Completely opt-in:
    // an empty `[[fib_tables]]` list returns `None` and leaves
    // route-server / route-reflector deployments control-plane-only.
    let (fib_status_tx, fib_status_rx) =
        tokio::sync::watch::channel(Vec::<fib_runtime::FibRuntimeStatus>::new());
    let fib_runtime_shutdown = tokio_util::sync::CancellationToken::new();
    let fib_runtime_handle = fib_runtime::spawn(
        fib_runtime::FibRuntimeConfig {
            tables: config.fib_tables.clone(),
            owned_state_path: Some(config.runtime_state_dir().join("fib-owned.json")),
        },
        rib_tx.clone(),
        rib_query_tx.clone(),
        metrics.clone(),
        fib_status_tx,
        fib_runtime_shutdown.clone(),
    );

    // Spawn gRPC API server (keep JoinHandle for supervision)
    let grpc_rib_tx = rib_tx.clone();
    let grpc_rib_query_tx = rib_query_tx;
    let grpc_peer_mgr_tx = peer_mgr_tx.clone();
    let serve_config = ServeConfig {
        asn: config.global.asn,
        router_id: config.global.router_id.clone(),
        listen_port: u32::from(config.global.listen_port),
        metrics: metrics.clone(),
        start_time,
        mrt_trigger_tx,
        evpn_instances,
        evpn_originated_local_mac_count: {
            let counts = evpn_originated_local_mac_counts.clone();
            Arc::new(move |vni| {
                rustbgpd_evpn::EvpnInstanceId::new(vni).map_or(0, |id| counts.count(id))
            })
        },
        evpn_ip_vrfs: evpn_ip_vrfs.clone(),
        evpn_ip_vrf_status_snapshot: {
            // `borrow()` on a watch receiver is lock-free (internal
            // seqlock); cloning the Vec releases the borrow before
            // the gRPC handler returns.
            let rx = evpn_ip_vrf_status_rx.clone();
            Arc::new(move || rx.borrow().clone())
        },
        evpn_originated_ip_vrf_route_count: {
            let counts = evpn_originated_ip_vrf_route_counts.clone();
            Arc::new(move |vni| rustbgpd_evpn::IpVrfId::new(vni).map_or(0, |id| counts.count(id)))
        },
        evpn_installed_ip_vrf_route_count: {
            let rx = evpn_ip_vrf_installed_routes_rx.clone();
            Arc::new(move |vni| {
                rustbgpd_evpn::IpVrfId::new(vni).map_or(0, |id| {
                    u64::from(rx.borrow().get(&id).copied().unwrap_or(0))
                })
            })
        },
        evpn_fdb_nexthop_snapshot: {
            let rx = evpn_fdb_nexthops_rx.clone();
            Arc::new(move || rx.borrow().clone())
        },
        blackhole_discard_snapshot: {
            let rx = blackhole_status_rx.clone();
            Arc::new(move || {
                rx.borrow()
                    .iter()
                    .map(|status| rustbgpd_api::proto::BlackholeDiscard {
                        prefix: status.prefix.addr_string(),
                        prefix_length: u32::from(status.prefix.prefix_len()),
                        peer_address: status.peer.to_string(),
                        state: match status.state {
                            blackhole::BlackholeState::Installed => {
                                rustbgpd_api::proto::BlackholeDiscardState::Installed as i32
                            }
                            blackhole::BlackholeState::Rejected => {
                                rustbgpd_api::proto::BlackholeDiscardState::Rejected as i32
                            }
                            blackhole::BlackholeState::Failed => {
                                rustbgpd_api::proto::BlackholeDiscardState::Failed as i32
                            }
                        },
                        reason: status.reason.clone(),
                    })
                    .collect()
            })
        },
        fib_route_snapshot: {
            let rx = fib_status_rx.clone();
            Arc::new(move || {
                rx.borrow()
                    .iter()
                    .map(|status| rustbgpd_api::proto::FibRouteStatus {
                        table_name: status.table_name.clone(),
                        table_id: status.table_id,
                        metric: status.metric,
                        prefix: status.prefix.addr_string(),
                        prefix_length: u32::from(status.prefix.prefix_len()),
                        next_hop: status
                            .next_hop
                            .map_or_else(String::new, |ip| ip.to_string()),
                        peer_address: status.peer.map_or_else(String::new, |ip| ip.to_string()),
                        state: match status.state {
                            fib_runtime::FibRuntimeState::Installed => {
                                rustbgpd_api::proto::FibRouteState::Installed as i32
                            }
                            fib_runtime::FibRuntimeState::Rejected => {
                                rustbgpd_api::proto::FibRouteState::Rejected as i32
                            }
                            fib_runtime::FibRuntimeState::Failed => {
                                rustbgpd_api::proto::FibRouteState::Failed as i32
                            }
                        },
                        reason: status.reason.clone(),
                    })
                    .collect()
            })
        },
    };
    let mut grpc_handle = tokio::spawn(async move {
        rustbgpd_api::server::serve(
            grpc_listeners,
            grpc_rib_tx,
            grpc_rib_query_tx,
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
    let peer_configs = config.resolved_neighbors().unwrap_or_else(|e| {
        error!("invalid policy configuration: {e}");
        process::exit(1);
    });
    for neighbor in peer_configs {
        let transport_config = neighbor.transport_config;
        let label = neighbor.label;
        let import_policy = neighbor.import_policy;
        let export_policy = neighbor.export_policy;
        let peer_group = neighbor.peer_group;
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
                    peer_group,
                    hold_time: Some(transport_config.peer.hold_time),
                    max_prefixes: transport_config.max_prefixes,
                    md5_password: transport_config.md5_password.clone(),
                    ttl_security: transport_config.ttl_security,
                    families: transport_config.peer.families.clone(),
                    graceful_restart: transport_config.peer.graceful_restart,
                    gr_restart_time: transport_config.peer.gr_restart_time,
                    gr_stale_routes_time: transport_config.gr_stale_routes_time,
                    llgr_stale_time: transport_config.llgr_stale_time,
                    gr_restart_eligible: true,
                    local_ipv6_nexthop: transport_config.local_ipv6_nexthop,
                    route_reflector_client: transport_config.route_reflector_client,
                    route_server_client: transport_config.route_server_client,
                    remove_private_as: transport_config.remove_private_as,
                    add_path_receive: transport_config.peer.add_path_receive,
                    add_path_send: transport_config.peer.add_path_send,
                    add_path_send_max: transport_config.peer.add_path_send_max,
                    import_policy,
                    export_policy,
                },
                sync_config_snapshot: false,
                reply: reply_tx,
            })
            .await;
        match reply_rx.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => error!(label = %label, error = %e, "failed to add peer"),
            Err(e) => error!(label = %label, error = %e, "peer manager reply dropped"),
        }
    }

    // Signal handlers (unix-only, which is our target)
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to register SIGTERM handler");
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .expect("failed to register SIGHUP handler");

    // Wait for shutdown signal: SIGINT, SIGTERM, Shutdown RPC, unexpected gRPC exit, or SIGHUP
    //
    // SIGHUP runs `reload_config` on a dedicated tokio task so the
    // signal-arm dispatch returns immediately. Without this, the SIGHUP
    // arm's inline `.await` would block the same `select!` from
    // observing SIGINT/SIGTERM for the duration of the reload (up to
    // ~7 round-trip commands × 500 ms `PEER_POLICY_UPDATE_TIMEOUT` plus
    // reconcile round-trip). Operators hitting Ctrl-C mid-reload should
    // see the daemon respond.
    //
    // Concurrency invariant: at most one reload in flight. Concurrent
    // reloads would race on `peer_mgr_tx` ordering (interleaved
    // SetPolicy / ReconcilePeers commands) and double-fire the
    // post-reload sync. A SIGHUP that arrives while a reload is still
    // running is logged and dropped — the operator-facing back-pressure
    // surface.
    let mut reload_in_flight: Option<tokio::task::JoinHandle<Option<ReloadedConfig>>> = None;
    loop {
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                match result {
                    Ok(()) => info!("received SIGINT"),
                    Err(e) => error!(error = %e, "failed to listen for SIGINT"),
                }
                break;
            }
            _ = sigterm.recv() => {
                info!("received SIGTERM");
                break;
            }
            changed = rpc_shutdown_rx.changed() => {
                if changed.is_err() || !*rpc_shutdown_rx.borrow() {
                    continue;
                }
                info!("shutdown initiated via gRPC");
                break;
            }
            result = &mut grpc_handle => {
                error!(?result, "gRPC server exited unexpectedly");
                info!("initiating shutdown due to gRPC server failure");
                break;
            }
            _ = sighup.recv() => {
                if reload_in_flight.is_some() {
                    warn!("SIGHUP received while previous reload still in flight; ignoring");
                    continue;
                }
                info!("SIGHUP received, reloading configuration");
                let path = config.file_path.as_ref().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
                let snapshot = config.clone();
                let live_tcp = live_grpc_tcp.clone();
                let live_uds = live_grpc_uds.clone();
                let pm_tx = peer_mgr_tx.clone();
                reload_in_flight = Some(tokio::spawn(async move {
                    reload_config(
                        &path,
                        &snapshot,
                        live_tcp.as_ref(),
                        live_uds.as_ref(),
                        &pm_tx,
                    )
                    .await
                }));
            }
            // Only polled when a reload is in flight. Standard tokio
            // idiom: `std::future::pending().await` parks the arm
            // forever in the no-handle case so `select!` ignores it.
            // The `take()` drops the borrow before we touch
            // `reload_in_flight` again in the body, sidestepping the
            // borrow-across-await complaint.
            outcome = async {
                match reload_in_flight.as_mut() {
                    Some(handle) => handle.await,
                    None => std::future::pending().await,
                }
            } => {
                reload_in_flight = None;
                match outcome {
                    Ok(Some(new_config)) => {
                        match apply_reload_outcome(
                            new_config,
                            &peer_mgr_internal_tx,
                            bridge_replace_tx.as_ref(),
                        )
                        .await
                        {
                            Ok(advanced) => config = advanced,
                            Err(stage) => error!(
                                stage,
                                "post-reload sync failed mid-flight; in-memory config not advanced — next SIGHUP will retry"
                            ),
                        }
                    }
                    Ok(None) => {
                        // reload_config already logged the failure.
                    }
                    Err(e) => error!(error = %e, "reload task panicked"),
                }
            }
        }
    }

    // If a reload is still in flight at shutdown, abort it before
    // tearing down the peer manager. Letting it run would race the
    // peer manager's Shutdown command and potentially queue commands
    // against an already-draining manager.
    if let Some(handle) = reload_in_flight.take() {
        handle.abort();
        let _ = handle.await;
    }

    // Drop the profiler now while all data structures are still alive,
    // so the heap snapshot captures the live working set.
    drop(profiler);

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
    // 1.9a Drain the EVPN local-MAC originator first — BEFORE the
    // peer manager shutdown — so its Type 2 Withdraws ride the still-
    // open BGP sessions to peers. `RibUpdate::WithdrawEvpn` recomputes
    // and stages outbound updates before replying, so the transport
    // path picks them up if (and only if) the peer sessions are still
    // alive. Doing this after `PeerManagerCommand::Shutdown` would
    // leave peers with stale Type 2 routes on their LocRib until our
    // hold-timer expired on their side.
    //
    // Bounded 5 s drain — the originator's `drain_to_withdraws`
    // emits one Withdraw per still-advertised MAC.
    if let Some(handle) = evpn_originator_handle {
        info!("draining EVPN originator");
        handle.shutdown().await;
    }

    // 1.9a' Drain the SVI-MAC originator first — same ordering
    // rationale as the local-MAC originator: SVI Type 2 withdraws
    // must land while peer sessions are still up.
    if let Some(handle) = evpn_svi_handle {
        info!("draining EVPN SVI-MAC originator");
        handle.shutdown().await;
    }

    // 1.9a''' Drain the EVPN L3 (Type 5) originator. Same ordering
    // rationale: Type 5 withdraws must reach peers before BGP
    // sessions tear down so remote VTEPs flush their kernel FIBs
    // cleanly. The originator's diff loop emits one
    // `RibUpdate::WithdrawEvpn` per currently-originated prefix.
    if let Some(handle) = evpn_l3_originator_handle {
        info!("draining EVPN L3 originator");
        handle.shutdown().await;
    }

    // 1.9a'' Drain the EVPN segment orchestrator — withdraws all
    // Type 4 ES + Type 1 EAD-per-ES + Type 1 EAD-per-EVI routes
    // before peer sessions tear down. Same ordering rationale as
    // the originator + SVI tasks.
    if let Some(handle) = evpn_segment_handle {
        info!("draining EVPN segment orchestrator");
        handle.shutdown().await;
    }

    // 1.9b Withdraw the Type 3 IMET routes we originated at startup
    // so peers cleanly remove us from their ingress-replication
    // lists. Same ordering rationale as the Type 2 drain — must land
    // before peer sessions tear down.
    if !evpn_imet_keys.is_empty() {
        info!(
            count = evpn_imet_keys.len(),
            "withdrawing EVPN Type 3 IMET routes"
        );
        evpn_imet::withdraw_all(evpn_imet_keys, &rib_tx).await;
    }

    let _ = peer_mgr_tx.send(PeerManagerCommand::Shutdown).await;

    // 2. Wait for PeerManager to finish draining all peers
    if let Err(e) = peer_mgr_handle.await {
        error!(error = %e, "peer manager task panicked");
    }

    // 2.4 Drain daemon-owned BLACKHOLE discard routes. This is local
    // kernel state only, so it does not need live BGP sessions. The
    // actor removes only prefixes it successfully installed during
    // this daemon lifetime.
    if let Some(handle) = blackhole_handle {
        info!("draining BLACKHOLE discard routes");
        handle.shutdown().await;
    }

    // 2.45 Drain daemon-owned ADR-0061 general FIB routes. This is
    // local kernel state only, so it does not need live BGP sessions.
    if let Some(handle) = fib_runtime_handle {
        info!("draining general FIB routes");
        handle.shutdown().await;
    }

    // 2.5 Drain the EVPN Linux dataplane reconciler. The actor
    // withdraws every owned remote-MAC FDB entry under a bounded
    // 5 s drain (ADR-0054 §7) and exits; foreign entries
    // (kernel-learned local MACs, operator-static FDB entries) are
    // structurally untouched by the diff loop and survive the drain.
    // This runs after the peer manager because the kernel-side FDB
    // teardown does not need an active BGP session.
    if let Some(handle) = evpn_dataplane_handle {
        info!("draining EVPN dataplane");
        handle.shutdown().await;
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
        let expires_at = SystemTime::now() + Duration::from_mins(2);
        write_gr_restart_marker(&path, expires_at).unwrap();
        let read_back = read_gr_restart_marker(&path).unwrap().unwrap();
        let diff = read_back
            .duration_since(expires_at)
            .unwrap_or_else(|e| e.duration());
        assert!(diff < Duration::from_secs(1));
        remove_gr_restart_marker(&path).unwrap();
    }

    /// SIGHUP that adds mTLS to `grpc_tcp` must NOT advance the
    /// in-memory config's `grpc_tcp` field — the live listener is
    /// still serving the prior config (no listener rebind on
    /// reload), so the runtime snapshot has to keep pointing at the
    /// live state. Without this, future reloads compare against the
    /// already-mutated snapshot and the drift error stops firing.
    #[tokio::test]
    async fn reload_pins_grpc_tcp_to_live_listener_snapshot() {
        let path = unique_temp_path("reload-grpc-tcp-pin");

        // Initial config: grpc_tcp present but plaintext (no TLS).
        std::fs::write(
            &path,
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[global.telemetry.grpc_tcp]
address = "0.0.0.0:50051"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90
"#,
        )
        .unwrap();

        let initial = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();
        assert!(
            live_grpc_tcp
                .as_ref()
                .is_some_and(|cfg| cfg.tls_cert_file.is_none()),
            "initial listener must be plaintext"
        );

        // Operator overwrites the file with an mTLS-enabled config.
        // Validation now reads PEM material at config load, so the
        // paths must point at real PEM-shaped files.
        let cert = unique_temp_path("reload-pin-cert.pem");
        let key = unique_temp_path("reload-pin-key.pem");
        let ca = unique_temp_path("reload-pin-ca.pem");
        std::fs::write(
            &cert,
            "-----BEGIN CERTIFICATE-----\nMIIBstub\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        std::fs::write(
            &key,
            "-----BEGIN PRIVATE KEY-----\nMIIBstub\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();
        std::fs::write(
            &ca,
            "-----BEGIN CERTIFICATE-----\nMIIBstub\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let mtls_toml = format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[global.telemetry.grpc_tcp]
address = "0.0.0.0:50051"
tls_cert_file = {cert:?}
tls_key_file = {key:?}
tls_client_ca_file = {ca:?}

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90
"#,
            cert = cert.to_str().unwrap(),
            key = key.to_str().unwrap(),
            ca = ca.to_str().unwrap(),
        );
        std::fs::write(&path, mtls_toml).unwrap();

        let (peer_mgr_tx, _peer_mgr_rx) = mpsc::channel(8);
        let returned = reload_config(
            path.to_str().unwrap(),
            &initial,
            live_grpc_tcp.as_ref(),
            live_grpc_uds.as_ref(),
            &peer_mgr_tx,
        )
        .await
        .expect("reload should return a config even when grpc_tcp drifts");

        // The returned config's grpc_tcp MUST equal the live listener
        // snapshot, NOT the new declared mTLS config. Otherwise a
        // second reload would compare new declared vs already-updated
        // snapshot and stop warning.
        assert_eq!(
            returned.global.telemetry.grpc_tcp, live_grpc_tcp,
            "reload must pin grpc_tcp to the live listener snapshot until the daemon restarts"
        );
        assert!(
            returned
                .global
                .telemetry
                .grpc_tcp
                .as_ref()
                .is_some_and(|cfg| cfg.tls_cert_file.is_none()),
            "returned grpc_tcp must NOT carry the newly declared TLS material"
        );

        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&cert).ok();
        std::fs::remove_file(&key).ok();
        std::fs::remove_file(&ca).ok();
    }

    /// SIGHUP that edits `[[evpn_instances]]` must NOT advance the
    /// in-memory config's `evpn_instances` field — the gRPC
    /// `EvpnService` is still serving the startup `Arc<EvpnInstanceTable>`
    /// (no swap surface yet, ADR-0052). Without pinning, the next
    /// reload would compare against the already-mutated snapshot and
    /// the drift error would silently stop firing — operators would
    /// believe their edits had taken effect when in fact the gRPC
    /// surface is still on the prior instance set.
    #[tokio::test]
    async fn reload_pins_evpn_instances_to_startup_snapshot() {
        let path = unique_temp_path("reload-evpn-pin");

        // Initial config: one EVPN instance.
        std::fs::write(
            &path,
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"
"#,
        )
        .unwrap();

        let initial = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();
        assert_eq!(initial.evpn_instances.len(), 1);
        assert_eq!(initial.evpn_instances[0].vni, 100);

        // Operator rewrites the file: VNI changes, RTs expand, a new
        // instance appears. None of this can take effect on a SIGHUP
        // in the foundation slice, but the reload path must surface
        // the drift and pin the snapshot.
        std::fs::write(
            &path,
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100", "65000:200"]
local_vtep_ip = "10.0.0.1"

[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.1"
"#,
        )
        .unwrap();

        let (peer_mgr_tx, _peer_mgr_rx) = mpsc::channel(8);
        let returned = reload_config(
            path.to_str().unwrap(),
            &initial,
            live_grpc_tcp.as_ref(),
            live_grpc_uds.as_ref(),
            &peer_mgr_tx,
        )
        .await
        .expect("reload should return a config even when only evpn_instances drift");

        // The returned config's evpn_instances MUST equal the startup
        // snapshot, NOT the new declared block. Otherwise a second
        // reload would compare new declared vs already-updated snapshot
        // and stop warning.
        assert_eq!(
            returned.evpn_instances, initial.evpn_instances,
            "reload must pin evpn_instances to the startup snapshot until the daemon restarts"
        );
        assert_eq!(
            returned.evpn_instances.len(),
            1,
            "second instance must NOT have advanced into the runtime snapshot"
        );
        assert_eq!(
            returned.evpn_instances[0].route_targets.len(),
            1,
            "RT-list expansion must NOT have advanced into the runtime snapshot"
        );

        std::fs::remove_file(&path).ok();
    }

    /// SIGHUP that edits `[[evpn_ip_vrfs]]` must not advance the
    /// in-memory snapshot. Gate 9 currently validates IP-VRF schema
    /// at startup only; letting reload adopt the new table would make
    /// the next reload stop reporting drift even though no Type 5 /
    /// L3VNI runtime state changed.
    #[tokio::test]
    async fn reload_pins_evpn_ip_vrfs_to_startup_snapshot() {
        let path = unique_temp_path("reload-evpn-ip-vrf-pin");

        std::fs::write(
            &path,
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.1"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#,
        )
        .unwrap();

        let initial = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();
        assert_eq!(initial.evpn_ip_vrfs.len(), 1);
        assert_eq!(initial.evpn_ip_vrfs[0].name, "tenant-blue");

        std::fs::write(
            &path,
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000", "65000:6000"]
local_vtep_ip = "10.0.0.1"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000

[[evpn_ip_vrfs]]
name = "tenant-red"
vni = 5001
rd = "65000:5001"
route_targets = ["65000:5001"]
local_vtep_ip = "10.0.0.1"
router_mac = "02:00:00:00:00:02"
vrf_device = "vrf-red"
l3vxlan_device = "vni5001"
table_id = 5001
"#,
        )
        .unwrap();

        let (peer_mgr_tx, _peer_mgr_rx) = mpsc::channel(8);
        let returned = reload_config(
            path.to_str().unwrap(),
            &initial,
            live_grpc_tcp.as_ref(),
            live_grpc_uds.as_ref(),
            &peer_mgr_tx,
        )
        .await
        .expect("reload should return a config even when only evpn_ip_vrfs drift");

        assert_eq!(
            returned.evpn_ip_vrfs, initial.evpn_ip_vrfs,
            "reload must pin evpn_ip_vrfs to the startup snapshot until restart"
        );
        assert_eq!(
            returned.evpn_ip_vrfs.len(),
            1,
            "new IP-VRF must not advance into the runtime snapshot"
        );
        assert_eq!(
            returned.evpn_ip_vrfs[0].route_targets.len(),
            1,
            "RT-list expansion must not advance into the runtime snapshot"
        );

        std::fs::remove_file(&path).ok();
    }

    /// SIGHUP must also pin Gate 8 startup-only EVPN surfaces that
    /// feed long-lived actors: the Ethernet Segment table and the
    /// kernel-enforcement opt-in. Otherwise a reload would advance
    /// `current`, the actor would still be on its startup state, and
    /// the next reload would stop reporting drift.
    #[tokio::test]
    async fn reload_pins_ethernet_segments_and_bum_enforcement_to_startup_snapshot() {
        let path = unique_temp_path("reload-evpn-gate8-pin");

        std::fs::write(
            &path,
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"
"#,
        )
        .unwrap();

        let initial = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();
        assert!(initial.ethernet_segments.is_empty());
        assert!(!initial.apply_bum_enforcement);

        std::fs::write(
            &path,
            r#"
apply_bum_enforcement = true

[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.1"
"#,
        )
        .unwrap();

        let (peer_mgr_tx, _peer_mgr_rx) = mpsc::channel(8);
        let returned = reload_config(
            path.to_str().unwrap(),
            &initial,
            live_grpc_tcp.as_ref(),
            live_grpc_uds.as_ref(),
            &peer_mgr_tx,
        )
        .await
        .expect("reload should return a config even when only Gate 8 surfaces drift");

        assert_eq!(
            returned.ethernet_segments, initial.ethernet_segments,
            "reload must pin ethernet_segments to the startup snapshot until restart"
        );
        assert_eq!(
            returned.apply_bum_enforcement, initial.apply_bum_enforcement,
            "reload must pin apply_bum_enforcement to the startup snapshot until restart"
        );

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn reload_hot_applies_honor_graceful_shutdown() {
        let path = unique_temp_path("reload-honor-gshut-hot-apply");

        // Initial: honor knob OFF (default).
        std::fs::write(
            &path,
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90
"#,
        )
        .unwrap();
        let initial = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();
        assert!(!initial.global.honor_graceful_shutdown);

        // Operator rewrites: turns the knob ON. Reload must advance
        // the runtime snapshot and ask the peer manager to recompute
        // EBGP runtime policies so the implicit chain-tail rule lands
        // on already-running sessions.
        std::fs::write(
            &path,
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
honor_graceful_shutdown = true

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90
"#,
        )
        .unwrap();

        let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel(8);
        let peer_mgr = tokio::spawn(async move {
            match peer_mgr_rx.recv().await {
                Some(PeerManagerCommand::SetHonorGracefulShutdown { enabled, reply }) => {
                    let _ = reply.send(Ok(()));
                    enabled
                }
                _ => panic!("expected SetHonorGracefulShutdown command"),
            }
        });
        let returned = reload_config(
            path.to_str().unwrap(),
            &initial,
            live_grpc_tcp.as_ref(),
            live_grpc_uds.as_ref(),
            &peer_mgr_tx,
        )
        .await
        .expect("reload should hot-apply honor_graceful_shutdown");

        assert!(
            returned.global.honor_graceful_shutdown,
            "reload must advance honor_graceful_shutdown after peer manager hot-apply succeeds"
        );
        assert!(
            peer_mgr.await.unwrap(),
            "peer manager command must carry enabled=true"
        );

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn reload_hot_applies_honor_blackhole() {
        let path = unique_temp_path("reload-honor-blackhole-hot-apply");

        std::fs::write(
            &path,
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90
"#,
        )
        .unwrap();
        let initial = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();
        assert!(!initial.global.honor_blackhole);

        std::fs::write(
            &path,
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
honor_blackhole = true

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90
"#,
        )
        .unwrap();

        let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel(8);
        let peer_mgr = tokio::spawn(async move {
            match peer_mgr_rx.recv().await {
                Some(PeerManagerCommand::SetHonorBlackhole { enabled, reply }) => {
                    let _ = reply.send(Ok(()));
                    enabled
                }
                _ => panic!("expected SetHonorBlackhole command"),
            }
        });
        let returned = reload_config(
            path.to_str().unwrap(),
            &initial,
            live_grpc_tcp.as_ref(),
            live_grpc_uds.as_ref(),
            &peer_mgr_tx,
        )
        .await
        .expect("reload should hot-apply honor_blackhole");

        assert!(
            returned.global.honor_blackhole,
            "reload must advance honor_blackhole after peer manager hot-apply succeeds"
        );
        assert!(
            peer_mgr.await.unwrap(),
            "peer manager command must carry enabled=true"
        );

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn reload_pins_honor_blackhole_when_fib_discard_enabled() {
        let path = unique_temp_path("reload-pins-honor-blackhole-with-fib");

        std::fs::write(
            &path,
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
honor_blackhole = true
install_blackhole_discard = true

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90
"#,
        )
        .unwrap();
        let initial = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();

        std::fs::write(
            &path,
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
honor_blackhole = false
install_blackhole_discard = true

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90
"#,
        )
        .unwrap();

        let (peer_mgr_tx, _peer_mgr_rx) = mpsc::channel(8);
        let returned = reload_config(
            path.to_str().unwrap(),
            &initial,
            live_grpc_tcp.as_ref(),
            live_grpc_uds.as_ref(),
            &peer_mgr_tx,
        )
        .await
        .expect("reload should pin honor_blackhole to the startup FIB snapshot");

        assert!(
            returned.global.honor_blackhole,
            "honor_blackhole must stay pinned while the FIB reconciler is running"
        );
        assert!(returned.global.install_blackhole_discard);

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn reload_hot_applies_graceful_shutdown_and_blackhole_together() {
        let path = unique_temp_path("reload-honor-gshut-blackhole-hot-apply");

        std::fs::write(
            &path,
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90
"#,
        )
        .unwrap();
        let initial = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();
        assert!(!initial.global.honor_graceful_shutdown);
        assert!(!initial.global.honor_blackhole);

        std::fs::write(
            &path,
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
honor_graceful_shutdown = true
honor_blackhole = true

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90
"#,
        )
        .unwrap();

        let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel(8);
        let peer_mgr = tokio::spawn(async move {
            let mut commands = Vec::new();
            for _ in 0..2 {
                match peer_mgr_rx.recv().await {
                    Some(PeerManagerCommand::SetHonorGracefulShutdown { enabled, reply }) => {
                        let _ = reply.send(Ok(()));
                        commands.push(("gshut", enabled));
                    }
                    Some(PeerManagerCommand::SetHonorBlackhole { enabled, reply }) => {
                        let _ = reply.send(Ok(()));
                        commands.push(("blackhole", enabled));
                    }
                    _ => panic!("unexpected peer manager command"),
                }
            }
            commands
        });
        let returned = reload_config(
            path.to_str().unwrap(),
            &initial,
            live_grpc_tcp.as_ref(),
            live_grpc_uds.as_ref(),
            &peer_mgr_tx,
        )
        .await
        .expect("reload should hot-apply both honor knobs");

        assert!(returned.global.honor_graceful_shutdown);
        assert!(returned.global.honor_blackhole);
        assert_eq!(
            peer_mgr.await.unwrap(),
            vec![("gshut", true), ("blackhole", true)]
        );

        std::fs::remove_file(&path).ok();
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
    #[expect(clippy::too_many_lines)]
    fn max_gr_restart_time_uses_largest_enabled_peer() {
        let config = crate::config::Config {
            global: crate::config::Global {
                asn: 65001,
                router_id: "10.0.0.1".to_string(),
                listen_port: 179,
                cluster_id: None,
                runtime_state_dir: "/tmp".to_string(),
                telemetry: crate::config::TelemetryConfig {
                    prometheus_addr: Some("127.0.0.1:9179".to_string()),
                    log_format: "json".to_string(),
                    grpc_tcp: None,
                    grpc_uds: None,
                    looking_glass: None,
                },
                dynamic_neighbor_limit: None,
                honor_graceful_shutdown: false,
                honor_blackhole: false,
                install_blackhole_discard: false,
                allow_blackhole_broad_prefixes: false,
            },
            neighbors: vec![
                crate::config::Neighbor {
                    address: "10.0.0.2".to_string(),
                    remote_asn: 65002,
                    description: None,
                    peer_group: None,
                    hold_time: None,
                    max_prefixes: None,
                    md5_password: None,
                    ttl_security: Some(false),
                    families: Vec::new(),
                    graceful_restart: Some(true),
                    gr_restart_time: Some(90),
                    gr_stale_routes_time: None,
                    llgr_stale_time: None,
                    local_ipv6_nexthop: None,
                    route_reflector_client: Some(false),
                    route_server_client: Some(false),
                    remove_private_as: None,
                    add_path: None,
                    import_policy: Vec::new(),
                    export_policy: Vec::new(),
                    import_policy_chain: Vec::new(),
                    export_policy_chain: Vec::new(),
                    log_level: None,
                },
                crate::config::Neighbor {
                    address: "10.0.0.3".to_string(),
                    remote_asn: 65003,
                    description: None,
                    peer_group: None,
                    hold_time: None,
                    max_prefixes: None,
                    md5_password: None,
                    ttl_security: Some(false),
                    families: Vec::new(),
                    graceful_restart: Some(true),
                    gr_restart_time: Some(180),
                    gr_stale_routes_time: None,
                    llgr_stale_time: None,
                    local_ipv6_nexthop: None,
                    route_reflector_client: Some(false),
                    route_server_client: Some(false),
                    remove_private_as: None,
                    add_path: None,
                    import_policy: Vec::new(),
                    export_policy: Vec::new(),
                    import_policy_chain: Vec::new(),
                    export_policy_chain: Vec::new(),
                    log_level: None,
                },
                crate::config::Neighbor {
                    address: "10.0.0.4".to_string(),
                    remote_asn: 65004,
                    description: None,
                    peer_group: None,
                    hold_time: None,
                    max_prefixes: None,
                    md5_password: None,
                    ttl_security: Some(false),
                    families: Vec::new(),
                    graceful_restart: Some(false),
                    gr_restart_time: Some(300),
                    gr_stale_routes_time: None,
                    llgr_stale_time: None,
                    local_ipv6_nexthop: None,
                    route_reflector_client: Some(false),
                    route_server_client: Some(false),
                    remove_private_as: None,
                    add_path: None,
                    import_policy: Vec::new(),
                    export_policy: Vec::new(),
                    import_policy_chain: Vec::new(),
                    export_policy_chain: Vec::new(),
                    log_level: None,
                },
            ],
            peer_groups: std::collections::HashMap::new(),
            policy: crate::config::PolicyConfig::default(),
            rpki: None,
            bmp: None,
            mrt: None,
            file_path: None,
            dynamic_neighbors: Vec::new(),
            evpn_instances: Vec::new(),
            ethernet_segments: Vec::new(),
            evpn_ip_vrfs: Vec::new(),
            fib_tables: Vec::new(),
            apply_bum_enforcement: false,
        };

        assert_eq!(max_gr_restart_time_secs(&config), Some(180));
    }

    /// Tag string identifying the kind of `PeerManagerCommand` the
    /// mock observed during a reload — used by reload tests to
    /// assert the right sequence of commands fired without coupling
    /// to the full command struct.
    fn cmd_tag(cmd: &PeerManagerCommand) -> String {
        match cmd {
            PeerManagerCommand::SetPolicy { name, .. } => format!("SetPolicy({name})"),
            PeerManagerCommand::DeletePolicy { name, .. } => format!("DeletePolicy({name})"),
            PeerManagerCommand::SetNeighborSet { name, .. } => format!("SetNeighborSet({name})"),
            PeerManagerCommand::DeleteNeighborSet { name, .. } => {
                format!("DeleteNeighborSet({name})")
            }
            PeerManagerCommand::SetPeerGroup { name, .. } => format!("SetPeerGroup({name})"),
            PeerManagerCommand::DeletePeerGroup { name, .. } => format!("DeletePeerGroup({name})"),
            PeerManagerCommand::SetGlobalImportChain { policy_names, .. } => {
                format!("SetGlobalImportChain({})", policy_names.join(","))
            }
            PeerManagerCommand::SetGlobalExportChain { policy_names, .. } => {
                format!("SetGlobalExportChain({})", policy_names.join(","))
            }
            PeerManagerCommand::ClearGlobalImportChain { .. } => {
                "ClearGlobalImportChain".to_string()
            }
            PeerManagerCommand::ClearGlobalExportChain { .. } => {
                "ClearGlobalExportChain".to_string()
            }
            PeerManagerCommand::ReconcilePeers {
                added,
                removed,
                changed,
                ..
            } => {
                format!(
                    "ReconcilePeers(+{},-{},~{})",
                    added.len(),
                    removed.len(),
                    changed.len(),
                )
            }
            PeerManagerCommand::SoftResetIn { address, .. } => {
                format!("SoftResetIn({address})")
            }
            _ => "Other".to_string(),
        }
    }

    /// Drive a reload against the given initial+next TOML and return
    /// the commands the mock peer manager observed, in order.
    /// Replies `Ok(())` to every command that carries a reply channel.
    async fn drive_reload(
        initial_toml: &str,
        new_toml: &str,
    ) -> (Option<ReloadedConfig>, Vec<String>) {
        let path = unique_temp_path("reload-driver");
        std::fs::write(&path, initial_toml).unwrap();
        let initial = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();

        std::fs::write(&path, new_toml).unwrap();

        let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel::<PeerManagerCommand>(64);
        let mock = tokio::spawn(async move {
            use rustbgpd_api::peer_types::ReconcileResult;
            let mut tags = Vec::new();
            while let Some(cmd) = peer_mgr_rx.recv().await {
                tags.push(cmd_tag(&cmd));
                // Respond Ok(()) to every command that has a reply
                // channel so reload_config doesn't hang.
                match cmd {
                    PeerManagerCommand::SetPolicy { reply, .. }
                    | PeerManagerCommand::DeletePolicy { reply, .. }
                    | PeerManagerCommand::SetNeighborSet { reply, .. }
                    | PeerManagerCommand::DeleteNeighborSet { reply, .. }
                    | PeerManagerCommand::SetPeerGroup { reply, .. }
                    | PeerManagerCommand::DeletePeerGroup { reply, .. }
                    | PeerManagerCommand::SetGlobalImportChain { reply, .. }
                    | PeerManagerCommand::SetGlobalExportChain { reply, .. }
                    | PeerManagerCommand::ClearGlobalImportChain { reply }
                    | PeerManagerCommand::ClearGlobalExportChain { reply }
                    | PeerManagerCommand::SoftResetIn { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    PeerManagerCommand::ReconcilePeers { reply, .. } => {
                        let _ = reply.send(ReconcileResult::default());
                    }
                    _ => {}
                }
            }
            tags
        });

        let returned = reload_config(
            path.to_str().unwrap(),
            &initial,
            live_grpc_tcp.as_ref(),
            live_grpc_uds.as_ref(),
            &peer_mgr_tx,
        )
        .await;
        drop(peer_mgr_tx);
        let tags = mock.await.unwrap();
        std::fs::remove_file(&path).ok();
        (returned, tags)
    }

    fn baseline_toml() -> &'static str {
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90
"#
    }

    fn load_config_from_toml(name: &str, toml: &str) -> Config {
        let path = unique_temp_path(name);
        std::fs::write(&path, toml).unwrap();
        let config = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&path).ok();
        config
    }

    #[test]
    fn config_diff_json_includes_hot_applied_global_flags() {
        let old = load_config_from_toml("diff-json-old", baseline_toml());
        let new_toml = baseline_toml().replace(
            "listen_port = 179",
            "listen_port = 179\nhonor_graceful_shutdown = true\nhonor_blackhole = true",
        );
        let new = load_config_from_toml("diff-json-new", &new_toml);
        let diff = config::diff_config(&old, &new);
        let value = config::config_diff_json_value(&diff);

        assert_eq!(
            value["reload_applied"]["honor_graceful_shutdown_changed"],
            true
        );
        assert_eq!(value["reload_applied"]["honor_blackhole_changed"], true);
        assert_eq!(value["restart_required"]["global_changed"], false);
        assert_eq!(value["has_actionable_changes"], true);
    }

    #[test]
    fn config_diff_human_bucket_lists_hot_applied_global_flags() {
        let old = load_config_from_toml("diff-human-old", baseline_toml());
        let new_toml = baseline_toml().replace(
            "listen_port = 179",
            "listen_port = 179\nhonor_graceful_shutdown = true\nhonor_blackhole = true",
        );
        let new = load_config_from_toml("diff-human-new", &new_toml);
        let diff = config::diff_config(&old, &new);

        assert!(
            diff.has_reload_applied_changes(),
            "hot-applied global flags must keep the diff in the reload-applied bucket"
        );
        let rendered = config::format_config_diff(&diff);
        assert!(
            rendered.contains("Global hot-applied flags:"),
            "rendered diff should include the hot-applied flags bucket: {rendered}"
        );
        assert!(rendered.contains("honor_graceful_shutdown"), "{rendered}");
        assert!(rendered.contains("honor_blackhole"), "{rendered}");
    }

    /// Adding a named policy definition on reload must surface as a
    /// `SetPolicy` command to the peer manager — proving the reload
    /// path no longer silently ignores `[policy.definitions.*]` edits.
    #[tokio::test]
    async fn reload_applies_named_policy_addition() {
        let new_toml = format!(
            "{}\n[policy.definitions.block-private]\ndefault_action = \"deny\"\n",
            baseline_toml()
        );
        let (returned, tags) = drive_reload(baseline_toml(), &new_toml).await;
        assert!(returned.is_some(), "reload must succeed");
        assert!(
            tags.contains(&"SetPolicy(block-private)".to_string()),
            "expected SetPolicy(block-private) — saw {tags:?}"
        );
    }

    /// Adding a peer-group definition on reload must surface as a
    /// `SetPeerGroup` command. Catches the silent-ignore failure mode
    /// where peer-group edits would only be detected, not applied.
    #[tokio::test]
    async fn reload_applies_peer_group_addition() {
        let new_toml = format!(
            "{}\n[peer_groups.external]\nhold_time = 60\n",
            baseline_toml()
        );
        let (returned, tags) = drive_reload(baseline_toml(), &new_toml).await;
        assert!(returned.is_some(), "reload must succeed");
        assert!(
            tags.contains(&"SetPeerGroup(external)".to_string()),
            "expected SetPeerGroup(external) — saw {tags:?}"
        );
    }

    /// Changing the global `import_chain` on reload must surface as
    /// `SetGlobalImportChain` (or `ClearGlobalImportChain` when empty).
    #[tokio::test]
    async fn reload_applies_global_import_chain_change() {
        let initial = format!(
            "{}\n[policy.definitions.foo]\ndefault_action = \"permit\"\n",
            baseline_toml()
        );
        let new_toml = format!(
            "{}\n[policy.definitions.foo]\ndefault_action = \"permit\"\n[policy]\nimport_chain = [\"foo\"]\n",
            baseline_toml()
        );
        let (returned, tags) = drive_reload(&initial, &new_toml).await;
        assert!(returned.is_some(), "reload must succeed");
        assert!(
            tags.iter().any(|t| t.starts_with("SetGlobalImportChain")),
            "expected SetGlobalImportChain — saw {tags:?}"
        );
    }

    /// Removing a policy definition must surface as `DeletePolicy`
    /// AFTER any neighbor reconciliation, so the still-referenced
    /// rejection path doesn't fire transiently.
    #[tokio::test]
    async fn reload_applies_policy_removal_after_neighbor_reconcile() {
        let initial = format!(
            "{}\n[policy.definitions.old]\ndefault_action = \"permit\"\n",
            baseline_toml()
        );
        let (returned, tags) = drive_reload(&initial, baseline_toml()).await;
        assert!(returned.is_some(), "reload must succeed");
        assert!(
            tags.contains(&"DeletePolicy(old)".to_string()),
            "expected DeletePolicy(old) — saw {tags:?}"
        );
    }

    /// When a step early in the reload sequence succeeds and a later
    /// step fails, reload returns a partial-state snapshot so the
    /// daemon's in-memory config matches what the peer manager
    /// actually applied — instead of the previous behaviour where it
    /// returned `None` ("kept current") while the manager already had
    /// half the new state in effect. `SetPolicy` lands, then
    /// `ReconcilePeers` fails; the returned config must contain the
    /// new policy but not the new neighbors.
    #[tokio::test]
    async fn reload_halts_on_failure_with_honest_partial_snapshot() {
        use rustbgpd_api::peer_types::{ReconcileFailure, ReconcileFailureKind, ReconcileResult};

        let initial_toml = baseline_toml().to_string();
        let new_toml = format!(
            "{baseline}\n[policy.definitions.block-private]\ndefault_action = \"deny\"\n\n[[neighbors]]\naddress = \"10.0.0.99\"\nremote_asn = 65099\nhold_time = 90\n",
            baseline = baseline_toml()
        );

        let path = unique_temp_path("reload-halt-partial");
        std::fs::write(&path, &initial_toml).unwrap();
        let initial = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();
        std::fs::write(&path, &new_toml).unwrap();

        let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel::<PeerManagerCommand>(32);
        let mock = tokio::spawn(async move {
            // Reply Ok to every non-reconcile command; reply with a
            // reconcile failure to simulate a runtime rejection from
            // the peer manager. Models a valid TOML that fails for
            // an operational reason at the manager (port bind, TCP
            // setup, MD5 key push, etc.). Track command tags so the
            // test can assert which earlier steps successfully fired.
            let mut tags: Vec<String> = Vec::new();
            while let Some(cmd) = peer_mgr_rx.recv().await {
                tags.push(cmd_tag(&cmd));
                match cmd {
                    PeerManagerCommand::SetPolicy { reply, .. }
                    | PeerManagerCommand::DeletePolicy { reply, .. }
                    | PeerManagerCommand::SetNeighborSet { reply, .. }
                    | PeerManagerCommand::DeleteNeighborSet { reply, .. }
                    | PeerManagerCommand::SetPeerGroup { reply, .. }
                    | PeerManagerCommand::DeletePeerGroup { reply, .. }
                    | PeerManagerCommand::SetGlobalImportChain { reply, .. }
                    | PeerManagerCommand::SetGlobalExportChain { reply, .. }
                    | PeerManagerCommand::ClearGlobalImportChain { reply }
                    | PeerManagerCommand::ClearGlobalExportChain { reply } => {
                        let _ = reply.send(Ok(()));
                    }
                    PeerManagerCommand::ReconcilePeers { reply, .. } => {
                        let result = ReconcileResult {
                            failures: vec![ReconcileFailure {
                                kind: ReconcileFailureKind::Add,
                                address: "10.0.0.99".parse().unwrap(),
                                error: "simulated reconcile failure".to_string(),
                            }],
                        };
                        let _ = reply.send(result);
                    }
                    _ => {}
                }
            }
            tags
        });

        let returned = reload_config(
            path.to_str().unwrap(),
            &initial,
            live_grpc_tcp.as_ref(),
            live_grpc_uds.as_ref(),
            &peer_mgr_tx,
        )
        .await;
        drop(peer_mgr_tx);
        let tags = mock.await.unwrap();
        std::fs::remove_file(&path).ok();

        // Reconcile partial failure returns None: live peer-manager
        // state is ambiguous (delete-then-readd ordering, independent
        // adds/removes), so guessing a snapshot would let the next
        // reload diff against a config that doesn't match reality.
        // Operators investigate live state via `rustbgpctl neighbor
        // list`. Earlier reload steps (the SetPolicy here) DID land
        // at the manager and remain in effect — assert via the mock's
        // command log, since the in-memory config doesn't advance for
        // this failure class.
        assert!(
            returned.is_none(),
            "reconcile partial failure must return None — guessing a snapshot \
             when live state is ambiguous would let the next reload diff against \
             a fictional config"
        );
        assert!(
            tags.contains(&"SetPolicy(block-private)".to_string()),
            "earlier reload steps must still have fired before the reconcile failure — saw {tags:?}"
        );
    }

    /// `apply_reload_outcome` must send to the peer manager FIRST, so
    /// the authoritative runtime view always advances even if the
    /// optional bridge channel later fails. Drives the helper directly
    /// with a closed bridge channel to assert the failure stage name
    /// matches and the peer manager already received the snapshot
    /// before the bridge send was attempted.
    #[tokio::test]
    async fn apply_reload_outcome_bridge_failure_after_peer_mgr_snapshot() {
        let (peer_mgr_internal_tx, mut peer_mgr_internal_rx) =
            mpsc::unbounded_channel::<InternalCommand>();
        let (bridge_tx, bridge_rx) = mpsc::unbounded_channel::<Box<Config>>();
        // Drop the bridge rx so the helper's send fails immediately
        // with a closed-channel error.
        drop(bridge_rx);

        let path = unique_temp_path("apply-reload-outcome");
        std::fs::write(&path, baseline_toml()).unwrap();
        let cfg = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&path).ok();

        let result = apply_reload_outcome(
            ReloadedConfig::new(cfg.clone(), cfg.clone()),
            &peer_mgr_internal_tx,
            Some(&bridge_tx),
        )
        .await;

        assert_eq!(
            result.err(),
            Some("config_bridge"),
            "bridge failure must surface as the named stage so the caller's log line is actionable"
        );
        let snapshot = peer_mgr_internal_rx
            .try_recv()
            .expect("peer manager must receive the snapshot before the bridge send is attempted");
        match snapshot {
            InternalCommand::ReplaceConfigSnapshot(received) => {
                assert_eq!(received.global.asn, cfg.global.asn);
            }
        }
    }

    /// Bridge-disabled mode (no `file_path`, so no persister and no
    /// bridge) must succeed: the helper takes `Option<&Sender>`, and a
    /// `None` bridge is the runtime configuration when rustbgpd starts
    /// without a `--config` file (gRPC mutations are non-persistent in
    /// that mode by design).
    #[tokio::test]
    async fn apply_reload_outcome_succeeds_without_bridge() {
        let (peer_mgr_internal_tx, mut peer_mgr_internal_rx) =
            mpsc::unbounded_channel::<InternalCommand>();

        let path = unique_temp_path("apply-reload-outcome-nobridge");
        std::fs::write(&path, baseline_toml()).unwrap();
        let cfg = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&path).ok();

        let advanced = apply_reload_outcome(
            ReloadedConfig::new(cfg.clone(), cfg.clone()),
            &peer_mgr_internal_tx,
            None,
        )
        .await
        .expect("no-bridge mode must succeed");
        assert_eq!(advanced.global.asn, cfg.global.asn);
        assert!(peer_mgr_internal_rx.try_recv().is_ok());
    }

    /// Regression test for the bridge stale-snapshot bug. The bridge
    /// owns the pre-persist snapshot used by gRPC mutations. A
    /// SIGHUP-driven refresh must update that snapshot without writing
    /// the reloaded file back out, otherwise restart-required pinning
    /// would destroy an operator's edit-then-restart TOML.
    /// This test drives the bridge directly: send a snapshot
    /// replacement, then a `ConfigEvent` that adds a named policy,
    /// and assert the resulting persisted `ReplaceConfig` was computed
    /// against the *replacement* base — i.e. the bridge's internal
    /// snapshot was successfully swapped.
    #[tokio::test]
    async fn config_bridge_replacement_makes_subsequent_events_apply_to_new_snapshot() {
        use rustbgpd_api::peer_types::{ConfigEvent, NamedPolicyDefinition};

        let stale_path = unique_temp_path("bridge-replace-stale");
        std::fs::write(&stale_path, baseline_toml()).unwrap();
        let stale = Config::load_with_diagnostics(stale_path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&stale_path).ok();

        let new_toml = format!(
            "{baseline}\n[peer_groups.upstream]\nhold_time = 90\n",
            baseline = baseline_toml()
        );
        let new_path = unique_temp_path("bridge-replace-new");
        std::fs::write(&new_path, &new_toml).unwrap();
        let reloaded = Config::load_with_diagnostics(new_path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&new_path).ok();

        assert!(
            stale.peer_groups.is_empty(),
            "stale baseline must not have peer groups (preconditions)"
        );
        assert!(
            reloaded.peer_groups.contains_key("upstream"),
            "reloaded baseline must have the new peer_groups.upstream (preconditions)"
        );

        let (event_tx, event_rx) = mpsc::channel::<ConfigEvent>(8);
        let (replace_tx, replace_rx) = mpsc::unbounded_channel::<Box<Config>>();
        let (mutation_tx, mut mutation_rx) = mpsc::channel::<ConfigMutation>(8);

        let bridge = tokio::spawn(run_config_bridge(event_rx, replace_rx, mutation_tx, stale));

        // Push the SIGHUP-style replacement first.
        replace_tx.send(Box::new(reloaded.clone())).unwrap();
        // Then a gRPC mutation that adds a policy definition. If the
        // bridge missed the swap, this would compute against `stale`
        // and the resulting ReplaceConfig wouldn't carry the new
        // peer_groups.upstream entry.
        event_tx
            .send(ConfigEvent::SetPolicy {
                name: "block-private".to_string(),
                definition: NamedPolicyDefinition {
                    default_action: "deny".to_string(),
                    statements: Vec::new(),
                },
            })
            .await
            .unwrap();

        // First persister message is the replacement itself, but as a
        // no-persist refresh. The on-disk TOML is already the
        // operator's desired snapshot; rewriting it here would clobber
        // restart-required edits that runtime intentionally pinned.
        let replace_msg = mutation_rx.recv().await.expect("replacement forwarded");
        let ConfigMutation::RefreshSnapshotNoPersist(received_replace) = replace_msg else {
            panic!("bridge must forward replacement as RefreshSnapshotNoPersist");
        };
        assert!(
            received_replace.peer_groups.contains_key("upstream"),
            "replacement message must carry the new peer_groups.upstream"
        );

        // Second persister message is the post-event snapshot — must
        // contain BOTH the replacement-supplied peer_groups.upstream
        // AND the event-applied policy. If the bridge had missed the
        // swap, peer_groups.upstream would be absent (proving the
        // event applied to stale).
        let event_msg = mutation_rx.recv().await.expect("event forwarded");
        let ConfigMutation::ReplaceConfig(received_event) = event_msg else {
            panic!("bridge must forward event-derived snapshot as ReplaceConfig");
        };
        assert!(
            received_event.peer_groups.contains_key("upstream"),
            "post-event snapshot must still carry the replacement-supplied peer group — \
             absence here would mean the bridge applied the event to a stale snapshot"
        );
        assert!(
            received_event
                .policy
                .definitions
                .contains_key("block-private"),
            "post-event snapshot must carry the event-applied policy"
        );

        drop(replace_tx);
        drop(event_tx);
        bridge.await.unwrap();
    }

    async fn reload_then_persist_policy_after_desired_refresh(new_toml: &str) -> (Config, Config) {
        use rustbgpd_api::peer_types::{ConfigEvent, NamedPolicyDefinition};

        let path = unique_temp_path("reload-desired-refresh");
        std::fs::write(&path, baseline_toml()).unwrap();
        let initial = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();

        let (event_tx, event_rx) = mpsc::channel::<ConfigEvent>(8);
        let (replace_tx, replace_rx) = mpsc::unbounded_channel::<Box<Config>>();
        let (mutation_tx, mutation_rx) = mpsc::channel::<ConfigMutation>(8);
        let persister =
            tokio::spawn(ConfigPersister::new(mutation_rx, path.clone(), initial.clone()).run());
        let bridge = tokio::spawn(run_config_bridge(
            event_rx,
            replace_rx,
            mutation_tx,
            initial.clone(),
        ));

        std::fs::write(&path, new_toml).unwrap();
        let (peer_mgr_tx, _peer_mgr_rx) = mpsc::channel(8);
        let reloaded = reload_config(
            path.to_str().unwrap(),
            &initial,
            live_grpc_tcp.as_ref(),
            live_grpc_uds.as_ref(),
            &peer_mgr_tx,
        )
        .await
        .expect("reload should return pinned runtime plus desired config");

        let (peer_mgr_internal_tx, mut peer_mgr_internal_rx) =
            mpsc::unbounded_channel::<InternalCommand>();
        let runtime = apply_reload_outcome(reloaded, &peer_mgr_internal_tx, Some(&replace_tx))
            .await
            .expect("post-reload sync should succeed");
        assert!(
            peer_mgr_internal_rx.try_recv().is_ok(),
            "peer manager snapshot must be refreshed"
        );

        event_tx
            .send(ConfigEvent::SetPolicy {
                name: "after-reload".to_string(),
                definition: NamedPolicyDefinition {
                    default_action: "deny".to_string(),
                    statements: Vec::new(),
                },
            })
            .await
            .unwrap();

        drop(event_tx);
        drop(replace_tx);
        bridge.await.unwrap();
        persister.await.unwrap();

        let disk = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&path).ok();
        assert!(
            disk.policy.definitions.contains_key("after-reload"),
            "gRPC-style mutation after SIGHUP must persist on top of refreshed desired base"
        );
        (runtime, disk)
    }

    #[tokio::test]
    async fn reload_pin_grpc_uds_preserves_desired_toml_for_later_persistence() {
        let new_toml = format!(
            "{}\n[global.telemetry.grpc_uds]\npath = \"/tmp/rustbgpd-edited.sock\"\n",
            baseline_toml()
        );
        let (runtime, disk) = reload_then_persist_policy_after_desired_refresh(&new_toml).await;

        assert_ne!(
            runtime.global.telemetry.grpc_uds, disk.global.telemetry.grpc_uds,
            "runtime must stay pinned to the live listener while disk keeps the operator edit"
        );
        assert_eq!(
            disk.global
                .telemetry
                .grpc_uds
                .as_ref()
                .unwrap()
                .path
                .as_deref(),
            Some("/tmp/rustbgpd-edited.sock")
        );
    }

    #[tokio::test]
    async fn reload_pin_apply_bum_preserves_desired_toml_for_later_persistence() {
        let new_toml = format!("apply_bum_enforcement = true\n{}", baseline_toml());
        let (runtime, disk) = reload_then_persist_policy_after_desired_refresh(&new_toml).await;

        assert!(!runtime.apply_bum_enforcement);
        assert!(disk.apply_bum_enforcement);
    }

    #[tokio::test]
    async fn reload_pin_evpn_instances_preserves_desired_toml_for_later_persistence() {
        let new_toml = format!(
            "{}\n[[evpn_instances]]\nvni = 100\nrd = \"65000:100\"\nroute_targets = [\"65000:100\"]\nlocal_vtep_ip = \"10.0.0.1\"\n",
            baseline_toml()
        );
        let (runtime, disk) = reload_then_persist_policy_after_desired_refresh(&new_toml).await;

        assert!(runtime.evpn_instances.is_empty());
        assert_eq!(disk.evpn_instances.len(), 1);
    }

    #[tokio::test]
    async fn reload_pin_blackhole_fib_preserves_desired_toml_for_later_persistence() {
        let new_toml = baseline_toml().replace(
            "listen_port = 179",
            "listen_port = 179\nhonor_blackhole = true\ninstall_blackhole_discard = true",
        );
        let (runtime, disk) = reload_then_persist_policy_after_desired_refresh(&new_toml).await;

        assert!(!runtime.global.honor_blackhole);
        assert!(!runtime.global.install_blackhole_discard);
        assert!(disk.global.honor_blackhole);
        assert!(disk.global.install_blackhole_discard);
    }

    // SoftResetIn-on-import-policy-change coverage is now PM-side:
    // `update_runtime_policies` fires `soft_reset_in` automatically
    // when import policy materially changes, for any peer in
    // `self.peers` (which includes dynamic peers — the original
    // motivation for moving this out of the binary's reload loop).
    // Asserting that behavior at this layer would require a real
    // `PeerManager` task with established peers; that level of
    // integration coverage belongs in `peer_manager::tests`. The
    // reload tests above already prove the SetPolicy / SetPeerGroup
    // / chain commands fire on the right edits — that's the seam
    // this layer can exercise without a real peer.

    /// Effective-impact must catch a *changed policy definition*
    /// referenced via the global `import_chain`, even when the chain
    /// list itself is unchanged. Regression for the reviewer's
    /// transitive-reference finding: prior heuristic only flagged
    /// changes when the chain list moved, missing the common edit
    /// shape where operators tweak a definition in place.
    #[test]
    fn effective_impact_flags_global_chain_policy_definition_change() {
        let old_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"

[policy.definitions.block-private]
default_action = "permit"

[policy]
import_chain = ["block-private"]

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
"#;
        let new_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"

[policy.definitions.block-private]
default_action = "deny"

[policy]
import_chain = ["block-private"]

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
"#;
        let path_a = unique_temp_path("eff-impact-global-old");
        let path_b = unique_temp_path("eff-impact-global-new");
        std::fs::write(&path_a, old_toml).unwrap();
        std::fs::write(&path_b, new_toml).unwrap();
        let old = Config::load_with_diagnostics(path_a.to_str().unwrap()).unwrap();
        let new = Config::load_with_diagnostics(path_b.to_str().unwrap()).unwrap();
        let diff = config::diff_config(&old, &new);
        let impacted: Vec<_> = diff
            .effective_neighbor_impact
            .iter()
            .map(|i| i.address.as_str())
            .collect();
        assert!(
            impacted.contains(&"10.0.0.2"),
            "neighbor must be flagged when a definition referenced via the unchanged global \
             import_chain changes — got {impacted:?}"
        );
        std::fs::remove_file(&path_a).ok();
        std::fs::remove_file(&path_b).ok();
    }

    /// Same shape but for a peer-group chain reference: a definition
    /// changes; the peer-group's chain list is unchanged; the
    /// peer-group record is unchanged. Members must still be flagged.
    #[test]
    fn effective_impact_flags_peer_group_chain_policy_definition_change() {
        let old_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"

[policy.definitions.block-private]
default_action = "permit"

[peer_groups.ix]
hold_time = 90
import_policy_chain = ["block-private"]

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "ix"
"#;
        let new_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"

[policy.definitions.block-private]
default_action = "deny"

[peer_groups.ix]
hold_time = 90
import_policy_chain = ["block-private"]

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "ix"
"#;
        let path_a = unique_temp_path("eff-impact-pg-chain-old");
        let path_b = unique_temp_path("eff-impact-pg-chain-new");
        std::fs::write(&path_a, old_toml).unwrap();
        std::fs::write(&path_b, new_toml).unwrap();
        let old = Config::load_with_diagnostics(path_a.to_str().unwrap()).unwrap();
        let new = Config::load_with_diagnostics(path_b.to_str().unwrap()).unwrap();
        let diff = config::diff_config(&old, &new);
        let impacted: Vec<_> = diff
            .effective_neighbor_impact
            .iter()
            .map(|i| i.address.as_str())
            .collect();
        assert!(
            impacted.contains(&"10.0.0.2"),
            "neighbor must be flagged when a definition referenced via its peer-group's \
             import_policy_chain changes — got {impacted:?}"
        );
        std::fs::remove_file(&path_a).ok();
        std::fs::remove_file(&path_b).ok();
    }

    /// Effective neighbor impact view: when only a peer-group field
    /// changes, the diff must flag every member neighbor as
    /// effectively impacted (cascade via inheritance) even though
    /// their direct neighbor records are unchanged.
    #[test]
    fn effective_impact_flags_peer_group_members() {
        let old_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"

[peer_groups.ix]
hold_time = 90

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "ix"

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "ix"
"#;
        let new_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"

[peer_groups.ix]
hold_time = 60

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "ix"

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "ix"
"#;
        let path_a = unique_temp_path("eff-impact-old");
        let path_b = unique_temp_path("eff-impact-new");
        std::fs::write(&path_a, old_toml).unwrap();
        std::fs::write(&path_b, new_toml).unwrap();
        let old = Config::load_with_diagnostics(path_a.to_str().unwrap()).unwrap();
        let new = Config::load_with_diagnostics(path_b.to_str().unwrap()).unwrap();
        let diff = config::diff_config(&old, &new);
        let impacted: Vec<_> = diff
            .effective_neighbor_impact
            .iter()
            .map(|i| i.address.as_str())
            .collect();
        assert!(
            impacted.contains(&"10.0.0.2") && impacted.contains(&"10.0.0.3"),
            "both ix members must be flagged as effectively impacted — got {impacted:?}"
        );
        std::fs::remove_file(&path_a).ok();
        std::fs::remove_file(&path_b).ok();
    }
}
