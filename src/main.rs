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
mod looking_glass;
mod metrics_server;
mod peer_manager;
mod policy_admin;

use std::net::Ipv4Addr;
use std::ops::Deref;
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
    if diff.evpn_instances_changed {
        restart_sections.push("[[evpn_instances]]");
    }
    if diff.evpn_ip_vrfs_changed {
        restart_sections.push("[[evpn_ip_vrfs]]");
    }
    if diff.ethernet_segments_changed {
        restart_sections.push("[[ethernet_segments]]");
    }
    if diff.apply_bum_enforcement_changed {
        restart_sections.push("apply_bum_enforcement");
    }
    if diff.blackhole_fib_discard_changed {
        restart_sections.push("BLACKHOLE FIB discard");
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
            //                      `[mrt]`, EVPN startup-only
            //                      surfaces, plus inline
            //                      `policy.import` / `policy.export`
            //                      (no runtime swap surface yet)
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
                    "evpn_instances_changed": diff.evpn_instances_changed,
                    "evpn_ip_vrfs_changed": diff.evpn_ip_vrfs_changed,
                    "ethernet_segments_changed": diff.ethernet_segments_changed,
                    "apply_bum_enforcement_changed": diff.apply_bum_enforcement_changed,
                    "blackhole_fib_discard_changed": diff.blackhole_fib_discard_changed,
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

#[derive(Clone)]
struct ReloadedConfig {
    runtime: Config,
    desired: Config,
}

impl ReloadedConfig {
    fn new(runtime: Config, desired: Config) -> Self {
        Self { runtime, desired }
    }
}

impl Deref for ReloadedConfig {
    type Target = Config;

    fn deref(&self) -> &Self::Target {
        &self.runtime
    }
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

/// Bridge between gRPC config events, SIGHUP-driven snapshot
/// replacements, and the on-disk persister. The bridge owns the
/// authoritative pre-persist snapshot — both inputs route through
/// here so the snapshot, the persister, and downstream consumers
/// stay consistent.
///
/// Two inputs:
///   * `event_rx` — per-mutation events from the gRPC layer. Each
///     event is folded onto the bridge-held snapshot via
///     `apply_config_event`, then the full result is forwarded to
///     the persister as `ReplaceConfig`.
///   * `bridge_replace_rx` — SIGHUP-reloaded desired snapshots. The
///     bridge swaps its held snapshot and forwards a no-persist
///     refresh to the persister so future gRPC mutations apply on top
///     of the operator's edited TOML without writing a pinned runtime
///     snapshot back to disk.
///
/// Replacement is `biased` over events so a backlog of events
/// cannot delay reload visibility — without this, an operator who
/// SIGHUPs while gRPC is hammering policy mutations would see the
/// reload sit behind the queue and the next mutation would still
/// apply to the stale pre-reload base.
///
/// Persister send failure (`mutation_tx` closed or full past the
/// task's tolerance) terminates the bridge — the persister task is
/// dead, the daemon is shutting down, and there's nothing useful
/// left to do here.
async fn run_config_bridge(
    mut event_rx: mpsc::Receiver<rustbgpd_api::peer_types::ConfigEvent>,
    mut bridge_replace_rx: mpsc::UnboundedReceiver<Box<Config>>,
    mutation_tx: mpsc::Sender<ConfigMutation>,
    initial: Config,
) {
    let mut current_config = initial;
    let mut event_rx_open = true;
    let mut bridge_replace_rx_open = true;
    loop {
        if !event_rx_open && !bridge_replace_rx_open {
            break;
        }

        tokio::select! {
            biased;
            replace = bridge_replace_rx.recv(), if bridge_replace_rx_open => {
                match replace {
                    Some(new_snapshot) => {
                        current_config = *new_snapshot;
                        if mutation_tx
                            .send(ConfigMutation::RefreshSnapshotNoPersist(Box::new(
                                current_config.clone(),
                            )))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    None => bridge_replace_rx_open = false,
                }
            }
            event = event_rx.recv(), if event_rx_open => {
                match event {
                    Some(event) => {
                        if let Err(error) = apply_config_event(&mut current_config, &event) {
                            error!(error = %error, "failed to apply config event before persistence");
                            continue;
                        }
                        if mutation_tx
                            .send(ConfigMutation::ReplaceConfig(Box::new(current_config.clone())))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    None => event_rx_open = false,
                }
            }
        }
    }
}

/// Forward a freshly reloaded config to the peer manager and the
/// config bridge, in that order. Returns the runtime `Config` on success
/// so the caller can advance its in-memory snapshot in one step
/// (`config = apply_reload_outcome(...).await?;`).
///
/// Order matters. `peer_mgr_internal_tx` is unbounded and can only fail
/// on receiver-drop (peer manager task is dead — fatal anyway). The
/// bridge channel is also unbounded; it can only fail on receiver-drop
/// (bridge task is dead — same fatality class as a dead persister, since
/// the bridge owns the persister-facing channel). Sending the peer
/// manager first means the authoritative runtime view always advances
/// first.
///
/// The bridge — not a direct persister send — is the right
/// destination for the reloaded desired snapshot. `reload_config`
/// may pin restart-required fields back in the runtime snapshot, but
/// the bridge/persister must refresh their base from the operator's
/// edited TOML without writing the pinned runtime view back to disk.
/// Otherwise an edit-then-restart workflow gets destroyed by SIGHUP
/// and the next gRPC mutation applies to the wrong base.
///
/// Both `Err` returns name the failing stage (`peer_mgr_snapshot` or
/// `config_bridge`) so the caller's log line carries actionable
/// context. The "in-memory config not advanced" decision is the
/// caller's — leaving it explicit at the call site keeps the SIGHUP
/// retry semantics readable.
///
/// Async only because the SIGHUP-arm caller awaits in the same
/// position; both internal sends are unbounded and never block.
#[expect(
    clippy::unused_async,
    reason = "uniform async caller signature in the SIGHUP path"
)]
async fn apply_reload_outcome(
    reloaded: ReloadedConfig,
    peer_mgr_internal_tx: &mpsc::UnboundedSender<InternalCommand>,
    bridge_replace_tx: Option<&mpsc::UnboundedSender<Box<Config>>>,
) -> Result<Config, &'static str> {
    if peer_mgr_internal_tx
        .send(InternalCommand::ReplaceConfigSnapshot(Box::new(
            reloaded.runtime.clone(),
        )))
        .is_err()
    {
        return Err("peer_mgr_snapshot");
    }
    if let Some(tx) = bridge_replace_tx
        && tx.send(Box::new(reloaded.desired.clone())).is_err()
    {
        return Err("config_bridge");
    }
    Ok(reloaded.runtime)
}

/// Reload configuration from disk and reconcile runtime state.
///
/// Applies in dependency order:
/// 1. Add or change neighbor sets, named policies, peer groups, then
///    global chain references — additions and edits first so later
///    referrers resolve cleanly.
/// 2. Reconcile `[[neighbors]]` (existing path).
/// 3. Hot-apply implicit receiver-behavior knobs if they changed.
/// 4. Remove obsolete peer groups, named policies, and neighbor sets
///    in reverse-dependency order so a `still referenced` rejection
///    doesn't fire transiently.
///
/// Most `[global]` fields, `[rpki]`, `[bmp]`, `[mrt]`, and
/// `[global.telemetry.grpc_*]` sections still require a full restart;
/// this function logs them and pins the in-memory snapshot back to the
/// live listener state for the gRPC sections (so the next reload keeps
/// comparing against what the listener actually serves).
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
) -> Option<ReloadedConfig> {
    let desired_config = match Config::load_with_diagnostics(config_path) {
        Ok(c) => c,
        Err(diagnostic) => {
            error!("{diagnostic}");
            return None;
        }
    };
    let mut new_config = desired_config.clone();

    let honor_graceful_shutdown_changed =
        new_config.global.honor_graceful_shutdown != current.global.honor_graceful_shutdown;
    let mut honor_blackhole_changed =
        new_config.global.honor_blackhole != current.global.honor_blackhole;
    let blackhole_fib_reload_touches_spawn_gate =
        current.global.install_blackhole_discard || new_config.global.install_blackhole_discard;

    // Warn about sections that require restart. The implicit receiver
    // honor knobs are hot-applied below, so ignore them for this broad
    // restart warning.
    let mut restart_new_global = new_config.global.clone();
    let restart_current_global = current.global.clone();
    restart_new_global.honor_graceful_shutdown = restart_current_global.honor_graceful_shutdown;
    restart_new_global.honor_blackhole = restart_current_global.honor_blackhole;
    if restart_new_global != restart_current_global {
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

    // [[evpn_instances]] follows the gRPC-listener pinning pattern.
    // The Phase-2 foundation slice (ADR-0052) shares the resolved
    // `EvpnInstanceTable` to gRPC via an `Arc` built once at startup;
    // there is no swap surface yet, so a SIGHUP can't apply edits.
    // Without pinning, the in-memory `current` config would silently
    // advance to the new declaration on reload, the next reload would
    // see "no change", and drift would become invisible. Pin
    // new_config.evpn_instances back to current.evpn_instances so
    // (a) the gRPC `EvpnInstanceTable` stays consistent with the
    // returned snapshot and (b) drift detection remains observable
    // across every reload until the daemon is actually restarted.
    if new_config.evpn_instances != current.evpn_instances {
        error!(
            "[[evpn_instances]] differs from the live config: the \
             gRPC EvpnService is still serving the startup snapshot. \
             Restart rustbgpd to apply EVPN instance edits. Reload-time \
             mutation lands with the kernel-reconciliation slice (Gate 7b \
             — see docs/evpn-enablement.md)."
        );
        new_config
            .evpn_instances
            .clone_from(&current.evpn_instances);
    }
    if new_config.evpn_ip_vrfs != current.evpn_ip_vrfs {
        error!(
            "[[evpn_ip_vrfs]] differs from the live config: Gate 9 \
             IP-VRF/L3VNI state is resolved from the startup snapshot. \
             Restart rustbgpd to apply EVPN IP-VRF edits."
        );
        new_config.evpn_ip_vrfs.clone_from(&current.evpn_ip_vrfs);
    }
    if new_config.ethernet_segments != current.ethernet_segments {
        error!(
            "[[ethernet_segments]] differs from the live config: the \
             EVPN segment orchestrator resolved the startup snapshot. \
             Restart rustbgpd to apply Ethernet Segment edits."
        );
        new_config
            .ethernet_segments
            .clone_from(&current.ethernet_segments);
    }
    if new_config.apply_bum_enforcement != current.apply_bum_enforcement {
        error!(
            "apply_bum_enforcement differs from the live config: the \
             EVPN dataplane reconciler read this startup-only setting \
             when it was spawned. Restart rustbgpd to apply the Gate 8b \
             kernel-enforcement opt-in."
        );
        new_config.apply_bum_enforcement = current.apply_bum_enforcement;
    }
    if new_config.global.install_blackhole_discard != current.global.install_blackhole_discard
        || new_config.global.allow_blackhole_broad_prefixes
            != current.global.allow_blackhole_broad_prefixes
    {
        error!(
            "[global] BLACKHOLE FIB discard settings differ from the live config: \
             the RFC 7999 kernel-discard reconciler is spawned only at startup. \
             Restart rustbgpd to apply install_blackhole_discard or \
             allow_blackhole_broad_prefixes edits."
        );
        new_config.global.install_blackhole_discard = current.global.install_blackhole_discard;
        new_config.global.allow_blackhole_broad_prefixes =
            current.global.allow_blackhole_broad_prefixes;
    }
    if blackhole_fib_reload_touches_spawn_gate && honor_blackhole_changed {
        error!(
            "[global] honor_blackhole differs from the live config while \
             BLACKHOLE FIB discard is configured: the RFC 7999 \
             kernel-discard reconciler is spawned only at startup from \
             honor_blackhole && install_blackhole_discard. Restart \
             rustbgpd to apply this edit."
        );
        new_config.global.honor_blackhole = current.global.honor_blackhole;
        honor_blackhole_changed = false;
    }

    let policy_diff = config::diff_policy(&current.policy, &new_config.policy);
    let peer_group_diff = config::diff_peer_groups(&current.peer_groups, &new_config.peer_groups);
    let diff = config::diff_neighbors(&current.neighbors, &new_config.neighbors);

    let neighbors_unchanged =
        diff.added.is_empty() && diff.removed.is_empty() && diff.changed.is_empty();
    let peer_groups_unchanged = peer_group_diff.added.is_empty()
        && peer_group_diff.removed.is_empty()
        && peer_group_diff.changed.is_empty();
    if !policy_diff.has_changes()
        && peer_groups_unchanged
        && neighbors_unchanged
        && !honor_graceful_shutdown_changed
        && !honor_blackhole_changed
    {
        info!("config reloaded — no neighbor / policy / peer-group changes detected");
        return Some(ReloadedConfig::new(new_config, desired_config));
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
                &desired_config,
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
                        &desired_config,
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
                    &desired_config,
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
                &desired_config,
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
                        &desired_config,
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
                    &desired_config,
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
                &desired_config,
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
                        &desired_config,
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
                    &desired_config,
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
                        &desired_config,
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
                    &desired_config,
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
                        &desired_config,
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
                    &desired_config,
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
                return halt_partial(
                    working_config,
                    &desired_config,
                    ReloadStepFailure {
                        bucket: "neighbors.resolve",
                        target: "new_config.resolved_neighbors".to_string(),
                        error: e.to_string(),
                    },
                );
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
                &desired_config,
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

    // 6. Hot-apply implicit receiver behavior. This must run after
    //    policy/peer-group/global-chain edits and neighbor reconcile
    //    so the peer manager recomputes effective chains from the
    //    same live snapshot the rest of this reload has just shaped.
    if honor_graceful_shutdown_changed {
        let enabled = new_config.global.honor_graceful_shutdown;
        match send_pm_step(peer_mgr_tx, |reply| {
            PeerManagerCommand::SetHonorGracefulShutdown { enabled, reply }
        })
        .await
        {
            Ok(()) => {
                working_config.global.honor_graceful_shutdown = enabled;
                info!(
                    enabled,
                    "reload: [global] honor_graceful_shutdown hot-applied"
                );
            }
            Err(error) => {
                // `set_honor_graceful_shutdown` is intentionally best-
                // effort: on the peer-manager side it advances its own
                // `current_config` *unconditionally* and applies to as
                // many EBGP peers as it can, returning Err only to
                // surface which peers failed. Halting the reload here
                // would roll the daemon's `working_config` back to the
                // old value while the peer manager's snapshot stays
                // advanced — the same hard-to-debug drift the
                // best-effort design exists to avoid. Mirror the
                // peer-manager's snapshot advance in the daemon view,
                // and surface the failure list as a warn rather than
                // a halt. Failed peers retry on their next
                // `update_runtime_policies` call via the existing
                // bail-and-carry plumbing (`pending_refresh` /
                // `pending_export_apply`).
                warn!(
                    enabled,
                    error,
                    "reload: [global] honor_graceful_shutdown partial-apply — snapshot \
                     advanced anyway; bail-and-carry will retry failed peers on next \
                     policy edit"
                );
                working_config.global.honor_graceful_shutdown = enabled;
            }
        }
    }
    if honor_blackhole_changed {
        let enabled = new_config.global.honor_blackhole;
        match send_pm_step(peer_mgr_tx, |reply| PeerManagerCommand::SetHonorBlackhole {
            enabled,
            reply,
        })
        .await
        {
            Ok(()) => {
                working_config.global.honor_blackhole = enabled;
                info!(enabled, "reload: [global] honor_blackhole hot-applied");
            }
            Err(error) => {
                warn!(
                    enabled,
                    error,
                    "reload: [global] honor_blackhole partial-apply — snapshot \
                     advanced anyway; bail-and-carry will retry failed peers on next \
                     policy edit"
                );
                working_config.global.honor_blackhole = enabled;
            }
        }
    }

    // 7. Removals in reverse-dependency order so `still referenced`
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
                        &desired_config,
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
                    &desired_config,
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
                        &desired_config,
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
                    &desired_config,
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
                        &desired_config,
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
                    &desired_config,
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
    Some(ReloadedConfig::new(working_config, desired_config))
}

/// Halt a SIGHUP reload at the first failed step. Logs the failure
/// at error level and returns the partially-applied config snapshot
/// so the caller's in-memory config tracks live runtime state
/// instead of lying that the prior config is still in effect. The
/// daemon converges by the operator fixing the failing TOML and
/// reloading again — at that point the diff runs against the
/// half-applied state and only the remaining steps fire.
///
/// Returned wrapped in `Option<ReloadedConfig>` so the call sites can use
/// `return halt_partial(...)` directly inside `reload_config`,
/// matching its `Option<ReloadedConfig>` return shape.
#[expect(
    clippy::needless_pass_by_value,
    clippy::unnecessary_wraps,
    reason = "owned ReloadStepFailure simplifies call sites that build the value inline; Option<ReloadedConfig> return matches reload_config's signature so call sites can `return halt_partial(...)` directly"
)]
fn halt_partial(
    working_config: Config,
    desired_config: &Config,
    failure: ReloadStepFailure,
) -> Option<ReloadedConfig> {
    error!(
        bucket = failure.bucket,
        target = %failure.target,
        error = %failure.error,
        "config reload halted at this step — runtime state matches the in-memory snapshot returned by reload (partial). Re-edit TOML and reload again to converge."
    );
    Some(ReloadedConfig::new(working_config, desired_config.clone()))
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
