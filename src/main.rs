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

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process;
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant, SystemTime, UNIX_EPOCH};

use rustbgpd_rib::{RibManager, RibUpdate};
use rustbgpd_telemetry::{BgpMetrics, init_logging};
use rustbgpd_transport::{BgpListener, ListenerSocketOptions, TcpAoListenerKey};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::config::{
    Config, GrpcAccessMode, GrpcEnforcementConfig, GrpcListener, GrpcMaxTier, GrpcRoleConfig,
};
use crate::config_persister::{ConfigMutation, ConfigPersister};
use crate::peer_manager::PeerManager;
use crate::reload::{ReloadedConfig, apply_reload_outcome, reload_config, run_config_bridge};
use rustbgpd_api::peer_types::{PeerManagerCommand, PeerManagerNeighborConfig};
use rustbgpd_api::server::{
    AccessMode as GrpcServerAccessMode, ListenerConfig as GrpcListenerConfig, ListenerEndpoint,
    ServeConfig,
};

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

const fn grpc_max_tier_to_auth_tier(value: GrpcMaxTier) -> rustbgpd_api::authz::AuthTier {
    match value {
        GrpcMaxTier::Read => rustbgpd_api::authz::AuthTier::Read,
        GrpcMaxTier::SensitiveRead => rustbgpd_api::authz::AuthTier::SensitiveRead,
        GrpcMaxTier::Mutating => rustbgpd_api::authz::AuthTier::Mutating,
        GrpcMaxTier::OperatorOnly => rustbgpd_api::authz::AuthTier::OperatorOnly,
    }
}

const fn grpc_enforcement_to_auth_enforcement(
    value: GrpcEnforcementConfig,
) -> rustbgpd_api::authz::AuthEnforcement {
    match value {
        GrpcEnforcementConfig::Legacy => rustbgpd_api::authz::AuthEnforcement::Legacy,
        GrpcEnforcementConfig::Tier => rustbgpd_api::authz::AuthEnforcement::Tier,
    }
}

const fn grpc_role_to_principal_role(value: GrpcRoleConfig) -> rustbgpd_api::authz::PrincipalRole {
    match value {
        GrpcRoleConfig::Observer => rustbgpd_api::authz::PrincipalRole::Observer,
        GrpcRoleConfig::Automation => rustbgpd_api::authz::PrincipalRole::Automation,
        GrpcRoleConfig::Operator => rustbgpd_api::authz::PrincipalRole::Operator,
    }
}

fn grpc_principal_roles(config: &Config) -> BTreeMap<String, rustbgpd_api::authz::PrincipalRole> {
    config
        .security
        .grpc
        .roles
        .iter()
        .map(|(principal, role)| (principal.clone(), grpc_role_to_principal_role(*role)))
        .collect()
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
    let enforcement = grpc_enforcement_to_auth_enforcement(config.security.grpc.enforcement);
    let roles = Arc::new(grpc_principal_roles(config));
    config
        .grpc_listeners()
        .into_iter()
        .map(|listener| match listener {
            GrpcListener::Tcp {
                addr,
                access_mode,
                max_tier,
                token_file,
                principal,
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
                    max_tier: grpc_max_tier_to_auth_tier(max_tier),
                    enforcement,
                    roles: Arc::clone(&roles),
                    auth_token: token_file.as_deref().map(load_grpc_token).transpose()?,
                    principal,
                    tls: tls_params,
                })
            }
            GrpcListener::Uds {
                path,
                mode,
                access_mode,
                max_tier,
                token_file,
                principal,
            } => Ok(GrpcListenerConfig {
                endpoint: ListenerEndpoint::Uds { path, mode },
                access_mode: access_mode.into(),
                max_tier: grpc_max_tier_to_auth_tier(max_tier),
                enforcement,
                roles: Arc::clone(&roles),
                auth_token: token_file.as_deref().map(load_grpc_token).transpose()?,
                principal,
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

fn tcp_ao_listener_key_for_neighbor(
    listen_addr: SocketAddr,
    neighbor: &config::ResolvedNeighbor,
) -> Option<TcpAoListenerKey> {
    let tcp_ao = neighbor.transport_config.tcp_ao.as_ref()?;
    let peer = neighbor.transport_config.remote_addr.ip();
    if listen_addr.is_ipv4() != peer.is_ipv4() {
        return None;
    }
    Some(TcpAoListenerKey {
        peer,
        config: tcp_ao.clone(),
    })
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

    let (evpn_duplicate_mac_quarantine_tx, evpn_duplicate_mac_quarantine_rx) =
        tokio::sync::watch::channel(std::sync::Arc::new(std::collections::BTreeSet::<
            rustbgpd_evpn::DuplicateMacKey,
        >::new()));

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
    let mut evpn_dataplane_handle = evpn_dataplane::spawn_with_quarantine(
        supervisor_config,
        &evpn_instances,
        &evpn_ip_vrfs,
        rib_tx.clone(),
        metrics.clone(),
        evpn_dataplane_shutdown.clone(),
        evpn_duplicate_mac_quarantine_rx,
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
        evpn_originator::spawn_with_quarantine(
            evpn_originator::OriginatorConfig::default(),
            &evpn_instances,
            rib_tx.clone(),
            handle.local_mac_rx.take(),
            metrics.clone(),
            evpn_originated_local_mac_counts.clone(),
            evpn_originator_shutdown.clone(),
            vni_to_esi.clone(),
            evpn_duplicate_mac_quarantine_tx.clone(),
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

    let peer_configs = config.resolved_neighbors().unwrap_or_else(|e| {
        error!("invalid policy configuration: {e}");
        process::exit(1);
    });
    // Spawn BGP inbound TCP listener. The current daemon opens one
    // listener socket from `Config::listen_addr()`; only install TCP-AO
    // MKTs whose peer family can match that socket. Outbound active-open
    // sockets still install their per-neighbor key independently below.
    let listen_addr = config.listen_addr();
    let listener_options = ListenerSocketOptions {
        tcp_ao_keys: peer_configs
            .iter()
            .filter_map(|neighbor| tcp_ao_listener_key_for_neighbor(listen_addr, neighbor))
            .collect(),
    };

    let tcp_ao_listener_required = !listener_options.tcp_ao_keys.is_empty();
    let (accept_tx, mut accept_rx) = mpsc::channel::<rustbgpd_transport::AcceptedConnection>(64);
    match BgpListener::bind_with_options(listen_addr, accept_tx, listener_options).await {
        Ok(listener) => {
            let listener_peer_mgr_tx = peer_mgr_tx.clone();
            tokio::spawn(async move {
                while let Some(conn) = accept_rx.recv().await {
                    if let Err(e) = listener_peer_mgr_tx
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
            tokio::spawn(listener.run());
        }
        Err(e) => {
            if tcp_ao_listener_required {
                error!(
                    %listen_addr,
                    error = %e,
                    "failed to start BGP listener with TCP-AO-protected peers configured; refusing to run partially protected"
                );
                process::exit(1);
            }
            warn!(%listen_addr, error = %e, "failed to bind BGP listener");
        }
    }

    // Add initial peers from config via PeerManager
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
                    tcp_ao: transport_config.tcp_ao.clone(),
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

    fn load_config_from_toml(name: &str, toml: &str) -> Config {
        let path = unique_temp_path(name);
        std::fs::write(&path, toml).unwrap();
        let config = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&path).ok();
        config
    }

    fn tcp_ao_neighbor_toml(address: &str) -> String {
        format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "{address}"
remote_asn = 65002
tcp_ao = {{ key = "secret", send_id = 1, recv_id = 1, algorithm = "hmac(sha256)" }}
"#
        )
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

    #[test]
    fn gr_restart_marker_invalid_version_rejected() {
        let path = unique_temp_path("gr-restart-bad-version");
        std::fs::write(&path, "version = 2\nexpires_at_unix = 1\n").unwrap();
        let err = read_gr_restart_marker(&path).unwrap_err();
        assert!(err.contains("unsupported marker version"));
        remove_gr_restart_marker(&path).unwrap();
    }

    #[test]
    fn tcp_ao_listener_key_includes_peer_matching_listener_family() {
        let config = load_config_from_toml("listener-tcp-ao-v4", &tcp_ao_neighbor_toml("10.0.0.2"));
        let peer = config.resolved_neighbors().unwrap().pop().unwrap();

        let key = tcp_ao_listener_key_for_neighbor(config.listen_addr(), &peer).unwrap();

        assert_eq!(key.peer.to_string(), "10.0.0.2");
    }

    #[test]
    fn tcp_ao_listener_key_skips_peer_outside_listener_family() {
        let config =
            load_config_from_toml("listener-tcp-ao-v6", &tcp_ao_neighbor_toml("2001:db8::2"));
        let peer = config.resolved_neighbors().unwrap().pop().unwrap();

        assert!(tcp_ao_listener_key_for_neighbor(config.listen_addr(), &peer).is_none());
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
            security: crate::config::SecurityConfig::default(),
            neighbors: vec![
                crate::config::Neighbor {
                    address: "10.0.0.2".to_string(),
                    remote_asn: 65002,
                    description: None,
                    peer_group: None,
                    hold_time: None,
                    max_prefixes: None,
                    md5_password: None,
                    tcp_ao: None,
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
                    tcp_ao: None,
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
                    tcp_ao: None,
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
}
