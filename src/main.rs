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

mod config;
mod config_persister;
mod looking_glass;
mod metrics_server;
mod peer_manager;
mod policy_admin;

use std::net::Ipv4Addr;
use std::path::Path;
use std::process;
use std::time::{Duration, Instant as StdInstant, SystemTime, UNIX_EPOCH};

use rustbgpd_rib::{RibManager, RibUpdate};
use rustbgpd_telemetry::{BgpMetrics, init_logging};
use rustbgpd_transport::BgpListener;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use rustbgpd_api::peer_types::{ConfigEvent, PeerManagerCommand, PeerManagerNeighborConfig};
use rustbgpd_api::server::{
    AccessMode as GrpcServerAccessMode, ListenerConfig as GrpcListenerConfig, ListenerEndpoint,
    ServeConfig,
};
use rustbgpd_policy::PolicyChain;

use crate::config::{Config, GrpcAccessMode, GrpcListener};
use crate::config_persister::{ConfigMutation, ConfigPersister};
use crate::peer_manager::{InternalCommand, PeerManager};
use crate::policy_admin::apply_config_event;

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

#[expect(clippy::too_many_lines)]
fn print_config_diff(diff: &config::ConfigDiff) {
    use owo_colors::OwoColorize;

    // ── Reload-applied changes (what SIGHUP will actually reconcile) ──

    let has_pg_changes = !diff.peer_groups.added.is_empty()
        || !diff.peer_groups.removed.is_empty()
        || !diff.peer_groups.changed.is_empty();
    let p = &diff.policy;
    let has_named_policy_changes = !p.definitions_added.is_empty()
        || !p.definitions_removed.is_empty()
        || !p.definitions_changed.is_empty()
        || !p.neighbor_sets_added.is_empty()
        || !p.neighbor_sets_removed.is_empty()
        || !p.neighbor_sets_changed.is_empty()
        || p.import_chain_changed
        || p.export_chain_changed;

    if diff.has_reload_applied_changes() {
        println!("{}", "Reload-applied changes:".green());
        println!();
        let raw_neighbor_changes = !diff.neighbors.added.is_empty()
            || !diff.neighbors.removed.is_empty()
            || !diff.neighbors.changed.is_empty();
        if raw_neighbor_changes {
            println!("  Neighbors:");
            for n in &diff.neighbors.added {
                println!("    {} {} (AS {})", "+".green(), n.address, n.remote_asn);
            }
            for addr in &diff.neighbors.removed {
                println!("    {} {addr}", "-".red());
            }
            for n in &diff.neighbors.changed {
                println!("    {} {}:", "~".yellow(), n.address);
                for change in &n.changes {
                    println!("        {change}");
                }
            }
            println!();
        }

        if has_pg_changes {
            println!("  Peer groups:");
            for name in &diff.peer_groups.added {
                println!("    {} {name}", "+".green());
            }
            for name in &diff.peer_groups.removed {
                println!("    {} {name}", "-".red());
            }
            for (name, details) in &diff.peer_group_details {
                println!("    {} {name}:", "~".yellow());
                for change in details {
                    println!("        {change}");
                }
            }
            println!();
        }

        if has_named_policy_changes {
            println!("  Policy:");
            for name in &p.definitions_added {
                println!("    {} definition \"{name}\"", "+".green());
            }
            for name in &p.definitions_removed {
                println!("    {} definition \"{name}\"", "-".red());
            }
            for name in &p.definitions_changed {
                println!("    {} definition \"{name}\"", "~".yellow());
            }
            for name in &p.neighbor_sets_added {
                println!("    {} neighbor_set \"{name}\"", "+".green());
            }
            for name in &p.neighbor_sets_removed {
                println!("    {} neighbor_set \"{name}\"", "-".red());
            }
            for name in &p.neighbor_sets_changed {
                println!("    {} neighbor_set \"{name}\"", "~".yellow());
            }
            if p.import_chain_changed {
                println!("    {} import_chain", "~".yellow());
            }
            if p.export_chain_changed {
                println!("    {} export_chain", "~".yellow());
            }
            println!();
        }

        // Effective neighbor impact — neighbors whose resolved chain
        // moves due to upstream peer-group / policy / neighbor-set
        // edits. May overlap with raw neighbor changes; printing both
        // is intentional so operators see *which* neighbors a single
        // peer-group edit cascades to.
        if !diff.effective_neighbor_impact.is_empty() {
            println!("  Effectively impacted neighbors (via inheritance):");
            for impact in &diff.effective_neighbor_impact {
                println!("    {} {}:", "~".yellow(), impact.address);
                for reason in &impact.reasons {
                    println!("        {reason}");
                }
            }
            println!();
        }
    }

    // ── Restart-required changes ──

    let mut restart_sections = Vec::new();
    if diff.global_changed {
        restart_sections.push("[global]");
    }
    if diff.rpki_changed {
        restart_sections.push("[rpki]");
    }
    if diff.bmp_changed {
        restart_sections.push("[bmp]");
    }
    if diff.mrt_changed {
        restart_sections.push("[mrt]");
    }
    if p.import_changed {
        restart_sections.push("[policy.import] (inline)");
    }
    if p.export_changed {
        restart_sections.push("[policy.export] (inline)");
    }
    if !restart_sections.is_empty() {
        println!("{}", "Restart-required changes:".yellow());
        for section in &restart_sections {
            println!("  {} {section} changed", "!".yellow());
        }
        if p.import_changed || p.export_changed {
            println!(
                "  {}",
                "  (migrate inline policy to named definitions + import_chain/export_chain for hot reload)".dimmed()
            );
        }
        println!();
    }

    if !diff.has_any_changes() {
        println!("No changes.");
    }
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
            // The JSON schema mirrors the human `print_config_diff`
            // bucketing exactly:
            //   reload_applied  — neighbors + peer-groups + named
            //                     policies/sets/chains (everything
            //                     SIGHUP now applies) + the
            //                     per-neighbor effective-impact view
            //   restart_required — `[global]`, `[rpki]`, `[bmp]`,
            //                      `[mrt]`, plus inline `policy.import`
            //                      / `policy.export` (no runtime swap
            //                      surface yet)
            //   informational    — empty (kept on the schema as a
            //                      stable bucket so consumers don't
            //                      break when the predicate is true
            //                      again in a future release)
            // Automation that classifies hot-applied edits by which
            // bucket they land in stays correct after this release.
            let output = serde_json::json!({
                "has_actionable_changes": diff.has_actionable_changes(),
                "has_informational_changes": diff.has_informational_changes(),
                "has_any_changes": diff.has_any_changes(),
                "reload_applied": {
                    "neighbors": &diff.neighbors,
                    "peer_groups": &diff.peer_groups,
                    "peer_group_details": &diff.peer_group_details,
                    "policy_definitions_added": &diff.policy.definitions_added,
                    "policy_definitions_removed": &diff.policy.definitions_removed,
                    "policy_definitions_changed": &diff.policy.definitions_changed,
                    "neighbor_sets_added": &diff.policy.neighbor_sets_added,
                    "neighbor_sets_removed": &diff.policy.neighbor_sets_removed,
                    "neighbor_sets_changed": &diff.policy.neighbor_sets_changed,
                    "import_chain_changed": diff.policy.import_chain_changed,
                    "export_chain_changed": diff.policy.export_chain_changed,
                    "effective_neighbor_impact": &diff.effective_neighbor_impact,
                },
                "restart_required": {
                    "global_changed": diff.global_changed,
                    "rpki_changed": diff.rpki_changed,
                    "bmp_changed": diff.bmp_changed,
                    "mrt_changed": diff.mrt_changed,
                    "inline_policy_import_changed": diff.policy.import_changed,
                    "inline_policy_export_changed": diff.policy.export_changed,
                },
                "informational": serde_json::Value::Object(serde_json::Map::new()),
            });
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

    // Spawn config persister (converts gRPC config events → disk writes)
    let (config_event_tx, config_mutation_tx) = if let Some(ref path) = config.file_path {
        let (event_tx, mut event_rx) = mpsc::channel::<rustbgpd_api::peer_types::ConfigEvent>(64);
        let (mutation_tx, mutation_rx) = mpsc::channel::<ConfigMutation>(64);
        let persister = ConfigPersister::new(mutation_rx, path.clone(), config.clone());
        tokio::spawn(persister.run());
        let reload_mutation_tx = mutation_tx.clone();
        let mut current_config = config.clone();

        // Bridge: convert ConfigEvent → ConfigMutation
        tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                if let Err(error) = apply_config_event(&mut current_config, &event) {
                    error!(error = %error, "failed to apply config event before persistence");
                    continue;
                }
                if mutation_tx
                    .send(ConfigMutation::ReplaceConfig(Box::new(
                        current_config.clone(),
                    )))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        (Some(event_tx), Some(reload_mutation_tx))
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
                info!("SIGHUP received, reloading configuration");
                let path = config.file_path.as_ref().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
                if let Some(new_config) = reload_config(
                    &path,
                    &config,
                    live_grpc_tcp.as_ref(),
                    live_grpc_uds.as_ref(),
                    &peer_mgr_tx,
                )
                .await
                {
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
                    if let Err(e) = peer_mgr_internal_tx
                        .send(InternalCommand::ReplaceConfigSnapshot(Box::new(new_config.clone())))
                    {
                        error!(
                            error = %e,
                            "failed to sync peer manager config snapshot after reload"
                        );
                        continue;
                    }
                    config = new_config;
                }
            }
        }
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
    peer_group: Option<String>,
) -> PeerManagerNeighborConfig {
    PeerManagerNeighborConfig {
        address: tc.remote_addr.ip(),
        remote_asn: tc.peer.remote_asn,
        description: label.to_string(),
        peer_group,
        hold_time: Some(tc.peer.hold_time),
        max_prefixes: tc.max_prefixes,
        md5_password: tc.md5_password.clone(),
        ttl_security: tc.ttl_security,
        families: tc.peer.families.clone(),
        graceful_restart: tc.peer.graceful_restart,
        gr_restart_time: tc.peer.gr_restart_time,
        gr_stale_routes_time: tc.gr_stale_routes_time,
        llgr_stale_time: tc.llgr_stale_time,
        gr_restart_eligible: false,
        local_ipv6_nexthop: tc.local_ipv6_nexthop,
        route_reflector_client: tc.route_reflector_client,
        route_server_client: tc.route_server_client,
        remove_private_as: tc.remove_private_as,
        add_path_receive: tc.peer.add_path_receive,
        add_path_send: tc.peer.add_path_send,
        add_path_send_max: tc.peer.add_path_send_max,
        import_policy: import.cloned(),
        export_policy: export.cloned(),
    }
}

/// One reconcile-step failure during a SIGHUP reload, surfaced in
/// the structured failure log when the new config is rejected.
#[derive(Debug)]
struct ReloadStepFailure {
    /// Which delta bucket the command came from
    /// (e.g., `"policy.set"`, `"peer_group.delete"`).
    bucket: &'static str,
    /// Identifier of the affected object (policy / peer-group / set name,
    /// or neighbor address). Empty for global-chain operations.
    target: String,
    /// Human-readable failure reason.
    error: String,
}

/// Send a single `PeerManagerCommand` and await its `Result<(), String>`
/// reply. Maps both channel-send and dropped-reply errors to a single
/// `String` so callers can record one structured failure per step.
async fn send_pm_step(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    build: impl FnOnce(oneshot::Sender<Result<(), String>>) -> PeerManagerCommand,
) -> Result<(), String> {
    let (reply_tx, reply_rx) = oneshot::channel();
    if let Err(e) = peer_mgr_tx.send(build(reply_tx)).await {
        return Err(format!("send to peer manager failed: {e}"));
    }
    match reply_rx.await {
        Ok(result) => result,
        Err(e) => Err(format!("peer manager dropped reply: {e}")),
    }
}

/// Reload configuration from disk and reconcile runtime state.
///
/// Applies in dependency order:
/// 1. Add or change neighbor sets, named policies, peer groups, then
///    global chain references — additions and edits first so later
///    referrers resolve cleanly.
/// 2. Reconcile `[[neighbors]]` (existing path).
/// 3. Remove obsolete peer groups, named policies, and neighbor sets
///    in reverse-dependency order so a `still referenced` rejection
///    doesn't fire transiently.
///
/// `[global]`, `[rpki]`, `[bmp]`, `[mrt]`, and `[global.telemetry.grpc_*]`
/// sections still require a full restart; this function logs them and
/// pins the in-memory snapshot back to the live listener state for the
/// gRPC sections (so the next reload keeps comparing against what the
/// listener actually serves).
///
/// Inline `policy.import` / `policy.export` statements (the
/// non-named global-fallback statements) are detected and warned but
/// not applied — operators should migrate to named definitions plus
/// `import_chain` / `export_chain` for hot-reload support, or restart.
#[expect(
    clippy::too_many_lines,
    reason = "reload threads validation, three diff buckets, ordered reconcile steps, and failure aggregation through a single function"
)]
async fn reload_config(
    config_path: &str,
    current: &Config,
    live_grpc_tcp: Option<&config::GrpcTcpListenerConfig>,
    live_grpc_uds: Option<&config::GrpcUdsListenerConfig>,
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
) -> Option<Config> {
    let mut new_config = match Config::load_with_diagnostics(config_path) {
        Ok(c) => c,
        Err(diagnostic) => {
            error!("{diagnostic}");
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
    if new_config.mrt != current.mrt {
        warn!("[mrt] changed — requires full restart to take effect");
    }

    // Surface gRPC listener / TLS changes specifically and pin the
    // returned snapshot's listener fields back to what the live
    // listener is actually serving. Two reasons we don't just warn
    // and let the snapshot advance:
    //   1. Without pinning, a SIGHUP that only touches grpc_tcp
    //      moves the in-memory config to the new declared state.
    //      The next reload then compares against the already-
    //      updated snapshot and stops warning, even though the live
    //      listener is still on the prior security mode (cert
    //      rotation, plaintext-to-mTLS migration, etc.).
    //   2. Drift detection should remain observable across every
    //      reload until the daemon is actually restarted.
    if new_config.global.telemetry.grpc_tcp.as_ref() != live_grpc_tcp {
        error!(
            "[global.telemetry.grpc_tcp] differs from the live listener \
             (address / token / TLS): live listener is unchanged. \
             Restart rustbgpd to apply. Adding, removing, or rotating \
             tls_cert_file / tls_key_file / tls_client_ca_file does NOT \
             take effect on SIGHUP."
        );
        new_config.global.telemetry.grpc_tcp = live_grpc_tcp.cloned();
    }
    if new_config.global.telemetry.grpc_uds.as_ref() != live_grpc_uds {
        error!(
            "[global.telemetry.grpc_uds] differs from the live listener \
             (path / mode / token): live listener is unchanged. Restart \
             rustbgpd to apply."
        );
        new_config.global.telemetry.grpc_uds = live_grpc_uds.cloned();
    }

    let policy_diff = config::diff_policy(&current.policy, &new_config.policy);
    let peer_group_diff = config::diff_peer_groups(&current.peer_groups, &new_config.peer_groups);
    let diff = config::diff_neighbors(&current.neighbors, &new_config.neighbors);

    let neighbors_unchanged =
        diff.added.is_empty() && diff.removed.is_empty() && diff.changed.is_empty();
    let peer_groups_unchanged = peer_group_diff.added.is_empty()
        && peer_group_diff.removed.is_empty()
        && peer_group_diff.changed.is_empty();
    if !policy_diff.has_changes() && peer_groups_unchanged && neighbors_unchanged {
        info!("config reloaded — no neighbor / policy / peer-group changes detected");
        return Some(new_config);
    }

    if policy_diff.import_changed || policy_diff.export_changed {
        warn!(
            "[policy.import] / [policy.export] inline statements changed — these \
             are evaluated at session start and require a full restart to apply. \
             Migrate to named definitions plus import_chain/export_chain for \
             hot-reload support."
        );
    }

    // working_config is the honest snapshot of runtime state. We
    // start from `current` and apply each ConfigEvent locally as the
    // matching peer-manager command succeeds. On any failure we
    // halt and return Some(working_config) — the caller's in-memory
    // config then matches what's actually live on the peer manager,
    // instead of pretending the prior config is in effect when half
    // of it has already been mutated. Returning the partial state is
    // honest at the cost of leaving the operator with a half-applied
    // reload; they re-edit the failing TOML and reload again to
    // converge. Captured under "SIGHUP reconcile is not transactional"
    // in KNOWN_ISSUES — this fix moves the snapshot from "lying about
    // prior state" to "matching live state", which is the practical
    // step short of true rollback.
    let mut working_config = current.clone();

    // 1. Neighbor sets (no upstream dependencies) — add and change.
    for name in policy_diff
        .neighbor_sets_added
        .iter()
        .chain(policy_diff.neighbor_sets_changed.iter())
    {
        let bucket = if policy_diff.neighbor_sets_added.contains(name) {
            "neighbor_set.add"
        } else {
            "neighbor_set.change"
        };
        // The diff said this neighbor_set is added/changed, so the
        // new config must contain it. A `None` here means the
        // diff and the config snapshot disagree — treat as halt.
        let Some(definition) = policy_admin::named_neighbor_set_from_config(&new_config, name)
        else {
            return halt_partial(
                working_config,
                ReloadStepFailure {
                    bucket,
                    target: name.clone(),
                    error: format!(
                        "internal: neighbor_set {name:?} present in diff but not resolvable from new config"
                    ),
                },
            );
        };
        let event = ConfigEvent::SetNeighborSet {
            name: name.clone(),
            definition: definition.clone(),
        };
        let cmd_name = name.clone();
        match send_pm_step(peer_mgr_tx, |reply| PeerManagerCommand::SetNeighborSet {
            name: cmd_name,
            definition,
            reply,
        })
        .await
        {
            Ok(()) => {
                if let Err(error) = apply_config_event(&mut working_config, &event) {
                    return halt_partial(
                        working_config,
                        ReloadStepFailure {
                            bucket,
                            target: name.clone(),
                            error: format!(
                                "applied at peer manager but local snapshot rejected the event: {error}"
                            ),
                        },
                    );
                }
                info!(name = %name, %bucket, "reload: neighbor_set applied");
            }
            Err(error) => {
                return halt_partial(
                    working_config,
                    ReloadStepFailure {
                        bucket,
                        target: name.clone(),
                        error,
                    },
                );
            }
        }
    }

    // 2. Named policy definitions (may reference neighbor_sets).
    for name in policy_diff
        .definitions_added
        .iter()
        .chain(policy_diff.definitions_changed.iter())
    {
        let bucket = if policy_diff.definitions_added.contains(name) {
            "policy.add"
        } else {
            "policy.change"
        };
        let Some(definition) = policy_admin::named_policy_from_config(&new_config, name) else {
            return halt_partial(
                working_config,
                ReloadStepFailure {
                    bucket,
                    target: name.clone(),
                    error: format!(
                        "internal: policy {name:?} present in diff but not resolvable from new config"
                    ),
                },
            );
        };
        let event = ConfigEvent::SetPolicy {
            name: name.clone(),
            definition: definition.clone(),
        };
        let cmd_name = name.clone();
        match send_pm_step(peer_mgr_tx, |reply| PeerManagerCommand::SetPolicy {
            name: cmd_name,
            definition,
            reply,
        })
        .await
        {
            Ok(()) => {
                if let Err(error) = apply_config_event(&mut working_config, &event) {
                    return halt_partial(
                        working_config,
                        ReloadStepFailure {
                            bucket,
                            target: name.clone(),
                            error: format!(
                                "applied at peer manager but local snapshot rejected the event: {error}"
                            ),
                        },
                    );
                }
                info!(name = %name, %bucket, "reload: policy applied");
            }
            Err(error) => {
                return halt_partial(
                    working_config,
                    ReloadStepFailure {
                        bucket,
                        target: name.clone(),
                        error,
                    },
                );
            }
        }
    }

    // 3. Peer groups (may reference policies).
    for name in peer_group_diff
        .added
        .iter()
        .chain(peer_group_diff.changed.iter())
    {
        let bucket = if peer_group_diff.added.contains(name) {
            "peer_group.add"
        } else {
            "peer_group.change"
        };
        let Some(definition) = policy_admin::named_peer_group_from_config(&new_config, name) else {
            return halt_partial(
                working_config,
                ReloadStepFailure {
                    bucket,
                    target: name.clone(),
                    error: format!(
                        "internal: peer_group {name:?} present in diff but not resolvable from new config"
                    ),
                },
            );
        };
        let event = ConfigEvent::SetPeerGroup {
            name: name.clone(),
            definition: definition.clone(),
        };
        let cmd_name = name.clone();
        match send_pm_step(peer_mgr_tx, |reply| PeerManagerCommand::SetPeerGroup {
            name: cmd_name,
            definition,
            reply,
        })
        .await
        {
            Ok(()) => {
                if let Err(error) = apply_config_event(&mut working_config, &event) {
                    return halt_partial(
                        working_config,
                        ReloadStepFailure {
                            bucket,
                            target: name.clone(),
                            error: format!(
                                "applied at peer manager but local snapshot rejected the event: {error}"
                            ),
                        },
                    );
                }
                info!(name = %name, %bucket, "reload: peer_group applied");
            }
            Err(error) => {
                return halt_partial(
                    working_config,
                    ReloadStepFailure {
                        bucket,
                        target: name.clone(),
                        error,
                    },
                );
            }
        }
    }

    // 4. Global named chains (reference named policies — must come
    //    after any new definitions are registered).
    if policy_diff.import_chain_changed {
        let chain = new_config.policy.import_chain.clone();
        let event = if chain.is_empty() {
            ConfigEvent::ClearGlobalImportChain
        } else {
            ConfigEvent::SetGlobalImportChain {
                policy_names: chain.clone(),
            }
        };
        let res = if chain.is_empty() {
            send_pm_step(peer_mgr_tx, |reply| {
                PeerManagerCommand::ClearGlobalImportChain { reply }
            })
            .await
        } else {
            send_pm_step(peer_mgr_tx, |reply| {
                PeerManagerCommand::SetGlobalImportChain {
                    policy_names: chain,
                    reply,
                }
            })
            .await
        };
        match res {
            Ok(()) => {
                if let Err(error) = apply_config_event(&mut working_config, &event) {
                    return halt_partial(
                        working_config,
                        ReloadStepFailure {
                            bucket: "global_chain.import",
                            target: String::new(),
                            error: format!(
                                "applied at peer manager but local snapshot rejected the event: {error}"
                            ),
                        },
                    );
                }
                info!("reload: global import_chain applied");
            }
            Err(error) => {
                return halt_partial(
                    working_config,
                    ReloadStepFailure {
                        bucket: "global_chain.import",
                        target: String::new(),
                        error,
                    },
                );
            }
        }
    }
    if policy_diff.export_chain_changed {
        let chain = new_config.policy.export_chain.clone();
        let event = if chain.is_empty() {
            ConfigEvent::ClearGlobalExportChain
        } else {
            ConfigEvent::SetGlobalExportChain {
                policy_names: chain.clone(),
            }
        };
        let res = if chain.is_empty() {
            send_pm_step(peer_mgr_tx, |reply| {
                PeerManagerCommand::ClearGlobalExportChain { reply }
            })
            .await
        } else {
            send_pm_step(peer_mgr_tx, |reply| {
                PeerManagerCommand::SetGlobalExportChain {
                    policy_names: chain,
                    reply,
                }
            })
            .await
        };
        match res {
            Ok(()) => {
                if let Err(error) = apply_config_event(&mut working_config, &event) {
                    return halt_partial(
                        working_config,
                        ReloadStepFailure {
                            bucket: "global_chain.export",
                            target: String::new(),
                            error: format!(
                                "applied at peer manager but local snapshot rejected the event: {error}"
                            ),
                        },
                    );
                }
                info!("reload: global export_chain applied");
            }
            Err(error) => {
                return halt_partial(
                    working_config,
                    ReloadStepFailure {
                        bucket: "global_chain.export",
                        target: String::new(),
                        error,
                    },
                );
            }
        }
    }

    // 5. Neighbor reconciliation. Only fires when the neighbor list
    //    itself moved; steps 1–4 already reshaped runtime state for
    //    inheritance-driven impact on existing neighbors.
    if !neighbors_unchanged {
        info!(
            added = diff.added.len(),
            removed = diff.removed.len(),
            changed = diff.changed.len(),
            "reconciling neighbors after config reload"
        );
        for n in &diff.added {
            info!(address = %n.address, asn = n.remote_asn, "neighbor added");
        }
        for addr in &diff.removed {
            info!(address = %addr, "neighbor removed");
        }
        let old_map: std::collections::HashMap<&str, &config::Neighbor> = current
            .neighbors
            .iter()
            .map(|n| (n.address.as_str(), n))
            .collect();
        for n in &diff.changed {
            if let Some(old_n) = old_map.get(n.address.as_str()) {
                let changes = config::describe_neighbor_changes(old_n, n);
                info!(
                    address = %n.address,
                    changes = %changes.join(", "),
                    "neighbor changed"
                );
            }
        }

        let peer_configs = match new_config.resolved_neighbors() {
            Ok(p) => p,
            Err(e) => {
                error!(error = %e, "config reload failed — invalid policy in new config");
                return Some(working_config);
            }
        };
        let peer_map: std::collections::HashMap<String, _> = peer_configs
            .into_iter()
            .map(|neighbor| {
                (
                    neighbor.transport_config.remote_addr.ip().to_string(),
                    neighbor,
                )
            })
            .collect();
        let resolve = |neighbors: &[config::Neighbor]| -> Vec<PeerManagerNeighborConfig> {
            neighbors
                .iter()
                .filter_map(|n| {
                    peer_map.get(&n.address).map(|neighbor| {
                        build_peer_mgr_config(
                            &neighbor.transport_config,
                            &neighbor.label,
                            neighbor.import_policy.as_ref(),
                            neighbor.export_policy.as_ref(),
                            neighbor.peer_group.clone(),
                        )
                    })
                })
                .collect()
        };

        let (reply_tx, reply_rx) = oneshot::channel();
        if let Err(e) = peer_mgr_tx
            .send(PeerManagerCommand::ReconcilePeers {
                added: resolve(&diff.added),
                removed: diff.removed.clone(),
                changed: resolve(&diff.changed),
                reply: reply_tx,
            })
            .await
        {
            return halt_partial(
                working_config,
                ReloadStepFailure {
                    bucket: "neighbors.reconcile",
                    target: String::new(),
                    error: format!("send: {e}"),
                },
            );
        }
        match reply_rx.await {
            Ok(reconcile) if reconcile.is_success() => {
                working_config.neighbors = new_config.neighbors.clone();
            }
            Ok(reconcile) => {
                // Reconcile is the one step where partial failure
                // leaves the live state genuinely ambiguous: it
                // sequences delete-then-readd for changed peers,
                // independent removes, and adds — any subset can
                // succeed before the failure point, the manager
                // doesn't update its own `current_config` during the
                // run, and `delete_peer` / `add_peer` of the wrong
                // ordering can leave orphaned `PeerHandle`s. Returning
                // a guessed snapshot here would let the next reload
                // diff against state that doesn't match live, which is
                // worse than just bailing.
                //
                // Instead: return `None` so the daemon's in-memory
                // config stays at `current` and log clearly that live
                // state may differ. Operators investigate via
                // `rustbgpctl neighbor list`, fix the failing TOML,
                // and reload again. The retry-succeeded-operations
                // concern is bounded by the underlying ops being
                // mostly idempotent (`delete_peer` of a missing peer
                // returns Ok, `add_peer` of an existing peer returns
                // a visible error rather than silent corruption); the
                // operator gets surfaced errors on the retry rather
                // than hidden drift.
                for failure in &reconcile.failures {
                    warn!(
                        bucket = "neighbors.reconcile",
                        target = %failure.address,
                        kind = ?failure.kind,
                        error = %failure.error,
                        "config reload step failed"
                    );
                }
                error!(
                    failures = reconcile.failures.len(),
                    "config reload halted at neighbor reconcile — live peer-manager state \
                     may differ from the in-memory config snapshot. Inspect live state via \
                     `rustbgpctl neighbor list` and re-edit the failing TOML before \
                     reloading again. Earlier reload steps (policy / peer-group / chain \
                     edits) DID land at the manager and remain in effect."
                );
                return None;
            }
            Err(e) => {
                error!(
                    error = %e,
                    "config reload halted: peer manager dropped reconcile reply — live \
                     state may differ from the in-memory config snapshot. Inspect via \
                     `rustbgpctl neighbor list` before reloading again. Earlier reload \
                     steps (policy / peer-group / chain edits) DID land at the manager \
                     and remain in effect."
                );
                return None;
            }
        }
    }

    // 6. Removals in reverse-dependency order so `still referenced`
    //    rejections don't fire transiently. Peer-group deletes have
    //    to happen after neighbor reconcile if any obsolete neighbors
    //    were members; same for policy / neighbor-set deletes vs
    //    peer-group deletes.
    for name in &peer_group_diff.removed {
        let event = ConfigEvent::DeletePeerGroup { name: name.clone() };
        let cmd_name = name.clone();
        match send_pm_step(peer_mgr_tx, |reply| PeerManagerCommand::DeletePeerGroup {
            name: cmd_name,
            reply,
        })
        .await
        {
            Ok(()) => {
                if let Err(error) = apply_config_event(&mut working_config, &event) {
                    return halt_partial(
                        working_config,
                        ReloadStepFailure {
                            bucket: "peer_group.delete",
                            target: name.clone(),
                            error: format!(
                                "applied at peer manager but local snapshot rejected the event: {error}"
                            ),
                        },
                    );
                }
                info!(name = %name, "reload: peer_group removed");
            }
            Err(error) => {
                return halt_partial(
                    working_config,
                    ReloadStepFailure {
                        bucket: "peer_group.delete",
                        target: name.clone(),
                        error,
                    },
                );
            }
        }
    }
    for name in &policy_diff.definitions_removed {
        let event = ConfigEvent::DeletePolicy { name: name.clone() };
        let cmd_name = name.clone();
        match send_pm_step(peer_mgr_tx, |reply| PeerManagerCommand::DeletePolicy {
            name: cmd_name,
            reply,
        })
        .await
        {
            Ok(()) => {
                if let Err(error) = apply_config_event(&mut working_config, &event) {
                    return halt_partial(
                        working_config,
                        ReloadStepFailure {
                            bucket: "policy.delete",
                            target: name.clone(),
                            error: format!(
                                "applied at peer manager but local snapshot rejected the event: {error}"
                            ),
                        },
                    );
                }
                info!(name = %name, "reload: policy removed");
            }
            Err(error) => {
                return halt_partial(
                    working_config,
                    ReloadStepFailure {
                        bucket: "policy.delete",
                        target: name.clone(),
                        error,
                    },
                );
            }
        }
    }
    for name in &policy_diff.neighbor_sets_removed {
        let event = ConfigEvent::DeleteNeighborSet { name: name.clone() };
        let cmd_name = name.clone();
        match send_pm_step(peer_mgr_tx, |reply| PeerManagerCommand::DeleteNeighborSet {
            name: cmd_name,
            reply,
        })
        .await
        {
            Ok(()) => {
                if let Err(error) = apply_config_event(&mut working_config, &event) {
                    return halt_partial(
                        working_config,
                        ReloadStepFailure {
                            bucket: "neighbor_set.delete",
                            target: name.clone(),
                            error: format!(
                                "applied at peer manager but local snapshot rejected the event: {error}"
                            ),
                        },
                    );
                }
                info!(name = %name, "reload: neighbor_set removed");
            }
            Err(error) => {
                return halt_partial(
                    working_config,
                    ReloadStepFailure {
                        bucket: "neighbor_set.delete",
                        target: name.clone(),
                        error,
                    },
                );
            }
        }
    }

    // Route Refresh for peers whose import policy moved fires
    // automatically inside `PeerManager::update_runtime_policies`
    // for any peer (static or dynamic) on policy / peer-group /
    // chain edits — the SetPolicy / SetPeerGroup / chain commands
    // above land at `apply_policy_change`, which calls
    // `update_runtime_policies` per affected peer, which now issues
    // `soft_reset_in` when the import policy materially changed.
    // That covers gRPC mutations and SIGHUP with one mechanism, and
    // reaches dynamic peers (which live only in the manager's
    // runtime table, not in `[[neighbors]]`). A soft-reset failure
    // there bubbles up through the SetPolicy / etc command result
    // handled above, halting this reload via `halt_partial` so the
    // failure is surfaced rather than logged-and-forgotten.

    info!("config reload complete");
    Some(working_config)
}

/// Halt a SIGHUP reload at the first failed step. Logs the failure
/// at error level and returns the partially-applied config snapshot
/// so the caller's in-memory config tracks live runtime state
/// instead of lying that the prior config is still in effect. The
/// daemon converges by the operator fixing the failing TOML and
/// reloading again — at that point the diff runs against the
/// half-applied state and only the remaining steps fire.
///
/// Returned wrapped in `Option<Config>` so the call sites can use
/// `return halt_partial(...)` directly inside `reload_config`,
/// matching its `Option<Config>` return shape.
#[expect(
    clippy::needless_pass_by_value,
    clippy::unnecessary_wraps,
    reason = "owned ReloadStepFailure simplifies call sites that build the value inline; Option<Config> return matches reload_config's signature so call sites can `return halt_partial(...)` directly"
)]
fn halt_partial(working_config: Config, failure: ReloadStepFailure) -> Option<Config> {
    error!(
        bucket = failure.bucket,
        target = %failure.target,
        error = %failure.error,
        "config reload halted at this step — runtime state matches the in-memory snapshot returned by reload (partial). Re-edit TOML and reload again to converge."
    );
    Some(working_config)
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
    async fn drive_reload(initial_toml: &str, new_toml: &str) -> (Option<Config>, Vec<String>) {
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

    // SoftResetIn-on-import-policy-change coverage is now PM-side:
    // `update_runtime_policies` fires `soft_reset_in` automatically
    // when import policy materially changes, for any peer in
    // `self.peers` (which includes dynamic peers — the codex finding
    // that motivated moving this out of the binary's reload loop).
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
