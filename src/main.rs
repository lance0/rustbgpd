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

#[cfg(all(feature = "jemalloc", not(feature = "dhat-heap")))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

mod bfd_runtime;
mod blackhole;
mod config;
mod config_persister;
mod config_transaction_control;
mod evpn_dataplane;
mod evpn_imet;
mod evpn_l3_originator;
mod evpn_originator;
mod evpn_runtime_converger;
mod evpn_segment;
mod evpn_svi;
mod fib;
mod fib_common;
mod fib_runtime;
mod fib_table_control;
mod gnmi_set_bridge;
mod looking_glass;
mod metrics_server;
mod peer_manager;
mod policy_admin;
mod reload;

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant as StdInstant, SystemTime, UNIX_EPOCH};

use rustbgpd_rib::{RibManager, RibUpdate};
use rustbgpd_telemetry::{BgpMetrics, init_logging};
use rustbgpd_transport::{BgpListener, ListenerSocketOptions, TcpAoListenerKey};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::config::{
    Config, GrpcAccessMode, GrpcEnforcementConfig, GrpcListener, GrpcMaxTier, GrpcRoleConfig,
};
use crate::config_persister::{ConfigMutation, ConfigPersister};
use crate::peer_manager::PeerManager;
use crate::reload::{
    apply_reload_outcome, reload_config, run_config_bridge, runtime_config_snapshot,
};
use rustbgpd_api::peer_types::{
    ImportValidationDependency, PeerManagerCommand, PeerManagerNeighborConfig,
};
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

fn fib_runtime_event_to_bgp_event(
    event: fib_runtime::FibRuntimeEvent,
) -> rustbgpd_api::proto::BgpEvent {
    let (event_type, action, severity) = match event.kind {
        fib_runtime::FibRuntimeEventKind::Installed => (
            rustbgpd_api::proto::BgpEventType::DataplaneRouteInstalled,
            "installed",
            rustbgpd_api::proto::EventSeverity::Info,
        ),
        fib_runtime::FibRuntimeEventKind::Withdrawn => (
            rustbgpd_api::proto::BgpEventType::DataplaneRouteWithdrawn,
            "withdrawn",
            rustbgpd_api::proto::EventSeverity::Info,
        ),
        fib_runtime::FibRuntimeEventKind::Failed => (
            rustbgpd_api::proto::BgpEventType::DataplaneRouteFailed,
            "failed",
            rustbgpd_api::proto::EventSeverity::Warning,
        ),
    };
    let prefix = event.prefix.addr_string();
    let prefix_length = u32::from(event.prefix.prefix_len());
    let next_hop = event.next_hop.map_or_else(String::new, |ip| ip.to_string());
    let peer_address = event.peer.map_or_else(String::new, |ip| ip.to_string());
    let afi_safi = match event.prefix {
        rustbgpd_wire::Prefix::V4(_) => rustbgpd_api::proto::AddressFamily::Ipv4Unicast,
        rustbgpd_wire::Prefix::V6(_) => rustbgpd_api::proto::AddressFamily::Ipv6Unicast,
    } as i32;
    let route = rustbgpd_api::proto::DataplaneRouteEvent {
        source: "fib".to_string(),
        action: action.to_string(),
        table_name: event.table_name.clone(),
        table_id: event.table_id,
        metric: event.metric,
        prefix: prefix.clone(),
        prefix_length,
        next_hop,
        peer_address: peer_address.clone(),
        timestamp: event.timestamp.clone(),
        reason: event.reason.clone(),
    };

    rustbgpd_api::proto::BgpEvent {
        timestamp: event.timestamp,
        category: rustbgpd_api::proto::EventCategory::Dataplane as i32,
        event_type: event_type as i32,
        severity: severity as i32,
        peer_address,
        previous_peer_address: String::new(),
        prefix: prefix.clone(),
        prefix_length,
        afi_safi,
        summary: format!(
            "dataplane fib route {action} {prefix}/{prefix_length}: {}",
            event.reason
        ),
        target_peer_address: String::new(),
        event_id: None,
        payload: Some(rustbgpd_api::proto::bgp_event::Payload::DataplaneRoute(
            route,
        )),
    }
}

fn spawn_fib_dataplane_event_bridge(
    mut fib_events: broadcast::Receiver<fib_runtime::FibRuntimeEvent>,
    bgp_events: broadcast::Sender<rustbgpd_api::proto::BgpEvent>,
    event_history: Option<rustbgpd_event_history::EventHistoryHandle>,
    metrics: rustbgpd_telemetry::BgpMetrics,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match fib_events.recv().await {
                Ok(event) => {
                    // Capture the typed peer before consuming `event`
                    // into the proto converter. The proto envelope's
                    // peer field is a stringified IpAddr, so parsing
                    // it back is wasted work when the source struct
                    // already carries `Option<IpAddr>` directly.
                    let envelope_peer = event.peer;
                    let proto_event = fib_runtime_event_to_bgp_event(event);
                    // ADR-0072 PR-FU1: durable outbox enqueue. The
                    // legacy `bgp_events` broadcast (consumed by
                    // WatchEvents) stays unchanged. Per-route FIB
                    // events carry peer (when sourced from a
                    // BGP path) and prefix on the envelope so
                    // collectors can filter by either.
                    if let Some(handle) = &event_history {
                        let envelope = rustbgpd_api::event_history_sinks::envelope_from_bgp_event(
                            &proto_event,
                            rustbgpd_event_history::Category::Dataplane,
                            envelope_peer,
                            None,
                        );
                        rustbgpd_api::event_history_sinks::try_send_envelope(
                            handle, &metrics, envelope,
                        );
                    }
                    let _ = bgp_events.send(proto_event);
                }
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    // The bridge consumes `fib_events` via a bounded
                    // tokio broadcast; if the bridge falls behind the
                    // FIB runtime, those `missed` events never reach
                    // the bridge body and therefore never reach EHM.
                    // When EHM is the durable producer for this
                    // category, that's a real cursor gap — call
                    // `record_source_lag` so the drop counter, the
                    // Prometheus degraded gauge, AND EHM's in-process
                    // degraded state are all flipped together. When
                    // EHM is disabled the lag is purely a live-stream
                    // concern (matches pre-ADR-0072 behavior); leave
                    // the bookkeeping alone in that case.
                    warn!(
                        missed,
                        "FIB dataplane event bridge lagged; dropping stale route events"
                    );
                    if let Some(handle) = &event_history {
                        rustbgpd_api::event_history_sinks::record_source_lag(
                            handle,
                            &metrics,
                            "dataplane",
                            missed,
                        );
                    }
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    })
}

/// Convert a BFD actor state-change event into a unified gRPC `BgpEvent`
/// (ADR-0067 step 3b). Up → `BfdSessionUp`, any down (Down/`AdminDown`) →
/// `BfdSessionDown`, otherwise `BfdSessionStateChanged`; the full old/new
/// states are always carried in the `BfdSessionEvent` payload.
fn bfd_runtime_event_to_bgp_event(
    event: &bfd_runtime::BfdRuntimeEvent,
) -> rustbgpd_api::proto::BgpEvent {
    use rustbgpd_api::proto;
    let (event_type, severity) = match event.new_state {
        rustbgpd_bfd::SessionState::Up => (
            proto::BgpEventType::BfdSessionUp,
            proto::EventSeverity::Info,
        ),
        rustbgpd_bfd::SessionState::Down | rustbgpd_bfd::SessionState::AdminDown => (
            proto::BgpEventType::BfdSessionDown,
            proto::EventSeverity::Warning,
        ),
        rustbgpd_bfd::SessionState::Init => (
            proto::BgpEventType::BfdSessionStateChanged,
            proto::EventSeverity::Info,
        ),
    };
    let timestamp = rustbgpd_rib::event::unix_timestamp_now();
    let peer_address = event.peer.to_string();
    let old_state = bfd_session_state_to_proto(event.old_state);
    let new_state = bfd_session_state_to_proto(event.new_state);
    let diagnostic = bfd_diagnostic_to_str(event.diagnostic).to_string();
    let summary = format!("bfd {peer_address} {old_state:?} → {new_state:?} ({diagnostic})");
    proto::BgpEvent {
        timestamp: timestamp.clone(),
        category: proto::EventCategory::Bfd as i32,
        event_type: event_type as i32,
        severity: severity as i32,
        peer_address: peer_address.clone(),
        previous_peer_address: String::new(),
        prefix: String::new(),
        prefix_length: 0,
        afi_safi: proto::AddressFamily::Unspecified as i32,
        summary,
        target_peer_address: String::new(),
        event_id: None,
        payload: Some(proto::bgp_event::Payload::Bfd(proto::BfdSessionEvent {
            event_type: event_type as i32,
            peer_address,
            timestamp,
            old_state: old_state as i32,
            new_state: new_state as i32,
            diagnostic,
            reason: String::new(),
        })),
    }
}

/// Translate the operator-facing `[event_history]` TOML block into
/// the `EventHistoryConfig` shape the `rustbgpd-event-history` crate
/// understands. The validation pass on the parent `Config` has
/// already enforced the field invariants (synchronous / overflow
/// values, positive sizes).
fn build_event_history_config(
    config: &Config,
    metrics: &BgpMetrics,
) -> rustbgpd_event_history::EventHistoryConfig {
    let block = &config.event_history;
    let synchronous = if block.synchronous.eq_ignore_ascii_case("normal") {
        rustbgpd_event_history::SynchronousMode::Normal
    } else {
        rustbgpd_event_history::SynchronousMode::Full
    };
    rustbgpd_event_history::EventHistoryConfig {
        path: config.event_history_db_path(),
        max_events: block.max_events,
        max_bytes: block.max_bytes,
        synchronous,
        required: block.required,
        queue_capacity: block.queue_capacity,
        batch_size: block.batch_size,
        batch_interval: std::time::Duration::from_millis(block.batch_interval_ms),
        metrics: Some(metrics.clone()),
        ..rustbgpd_event_history::EventHistoryConfig::default()
    }
}

fn spawn_bfd_event_bridge(
    mut bfd_events: broadcast::Receiver<bfd_runtime::BfdRuntimeEvent>,
    bgp_events: broadcast::Sender<rustbgpd_api::proto::BgpEvent>,
    event_history: Option<rustbgpd_event_history::EventHistoryHandle>,
    metrics: rustbgpd_telemetry::BgpMetrics,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match bfd_events.recv().await {
                Ok(event) => {
                    let proto_event = bfd_runtime_event_to_bgp_event(&event);
                    // ADR-0072 durable outbox enqueue. The legacy live
                    // `bgp_events` broadcast (consumed by WatchEvents +
                    // the EVPN service) stays unchanged.
                    if let Some(handle) = &event_history {
                        let envelope = rustbgpd_api::event_history_sinks::envelope_from_bgp_event(
                            &proto_event,
                            rustbgpd_event_history::Category::Bfd,
                            // BFD events are keyed by peer address;
                            // pull it from the proto envelope so the
                            // payload->envelope mapping stays in one
                            // place (the proto field is the source of
                            // truth for outbox-side filtering by peer).
                            proto_event.peer_address.parse().ok(),
                            None,
                        );
                        rustbgpd_api::event_history_sinks::try_send_envelope(
                            handle, &metrics, envelope,
                        );
                    }
                    let _ = bgp_events.send(proto_event);
                }
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    // See FIB bridge above: when EHM is the durable
                    // producer for this category, broadcast lag at
                    // the bridge boundary is a real cursor gap.
                    // `record_source_lag` flips the drop counter,
                    // the Prometheus degraded gauge, AND EHM's
                    // in-process degraded state together. Pre-PR
                    // behavior (no EHM) leaves the bookkeeping
                    // alone.
                    warn!(
                        missed,
                        "BFD event bridge lagged; dropping stale session events"
                    );
                    if let Some(handle) = &event_history {
                        rustbgpd_api::event_history_sinks::record_source_lag(
                            handle, &metrics, "bfd", missed,
                        );
                    }
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    })
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

async fn trigger_import_validation_refresh(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    dependency: ImportValidationDependency,
) {
    let (reply_tx, reply_rx) = oneshot::channel();
    if peer_mgr_tx
        .send(PeerManagerCommand::SoftResetImportValidationDependents {
            dependency,
            reply: reply_tx,
        })
        .await
        .is_err()
    {
        warn!(
            ?dependency,
            "peer manager unavailable while forwarding validation-cache update"
        );
        return;
    }

    match reply_rx.await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => warn!(
            ?dependency,
            error = %error,
            "validation-cache import refresh reported failures"
        ),
        Err(error) => warn!(
            ?dependency,
            error = %error,
            "validation-cache import refresh reply dropped"
        ),
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

fn fatal_startup_error(message: &'static str, error: impl std::fmt::Display) -> ! {
    error!(error = %error, "{message}");
    process::exit(1);
}

/// Map a BFD session state to its gRPC proto enum (ADR-0067).
fn bfd_session_state_to_proto(
    state: rustbgpd_bfd::SessionState,
) -> rustbgpd_api::proto::BfdSessionState {
    use rustbgpd_api::proto::BfdSessionState;
    match state {
        rustbgpd_bfd::SessionState::AdminDown => BfdSessionState::AdminDown,
        rustbgpd_bfd::SessionState::Down => BfdSessionState::Down,
        rustbgpd_bfd::SessionState::Init => BfdSessionState::Init,
        rustbgpd_bfd::SessionState::Up => BfdSessionState::Up,
    }
}

/// Stable `snake_case` name for a BFD diagnostic (RFC 5880 §4.1), for the gRPC
/// surface. Mirrors the names documented on `BfdSession.diagnostic`.
fn bfd_diagnostic_to_str(diag: rustbgpd_bfd::Diagnostic) -> &'static str {
    use rustbgpd_bfd::Diagnostic;
    match diag {
        Diagnostic::None => "none",
        Diagnostic::ControlDetectionTimeExpired => "control_detection_time_expired",
        Diagnostic::EchoFailed => "echo_function_failed",
        Diagnostic::NeighborSignaledDown => "neighbor_signaled_session_down",
        Diagnostic::ForwardingPlaneReset => "forwarding_plane_reset",
        Diagnostic::PathDown => "path_down",
        Diagnostic::ConcatenatedPathDown => "concatenated_path_down",
        Diagnostic::AdministrativelyDown => "administratively_down",
        Diagnostic::ReverseConcatenatedPathDown => "reverse_concatenated_path_down",
        Diagnostic::Reserved(_) => "reserved",
    }
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
               --check               Validate config and exit without starting the daemon\n  \
               --diff PATH           Compare config against PATH and show what SIGHUP would change\n  \
               --json                Output diff as JSON (only with --diff)\n  \
               --init-config PROFILE Print a starter config to stdout and exit (needs --stdout).\n                        \
                                     Profiles: lab, edge\n  \
               --stdout              Write --init-config output to stdout (the only target for now)\n  \
               --version             Print version and exit\n  \
               --help                Print this help message",
            env!("CARGO_PKG_VERSION")
        );
        return;
    }

    // Parse flags and config path from remaining args.
    let mut check_only = false;
    let mut diff_path: Option<String> = None;
    let mut json_output = false;
    let mut init_profile: Option<String> = None;
    let mut to_stdout = false;
    let mut config_path = "/etc/rustbgpd/config.toml".to_string();
    let mut expect_diff_path = false;
    let mut expect_init_profile = false;
    for arg in &args[1..] {
        if expect_diff_path {
            diff_path = Some(arg.clone());
            expect_diff_path = false;
        } else if expect_init_profile {
            init_profile = Some(arg.clone());
            expect_init_profile = false;
        } else if arg == "--check" {
            check_only = true;
        } else if arg == "--diff" {
            expect_diff_path = true;
        } else if arg == "--json" {
            json_output = true;
        } else if arg == "--init-config" {
            expect_init_profile = true;
        } else if arg == "--stdout" {
            to_stdout = true;
        } else if !arg.starts_with('-') {
            config_path.clone_from(arg);
        } else {
            eprintln!("error: unknown option: {arg}");
            eprintln!(
                "usage: rustbgpd [--check] [--diff PATH] [--json] [--init-config PROFILE --stdout] [--version] [CONFIG_PATH]"
            );
            process::exit(1);
        }
    }
    if expect_diff_path {
        eprintln!("error: --diff requires a path argument");
        process::exit(2);
    }
    if expect_init_profile {
        eprintln!(
            "error: --init-config requires a profile name (one of: {})",
            crate::config::profiles::PROFILE_NAMES.join(", ")
        );
        process::exit(2);
    }
    if json_output && diff_path.is_none() {
        eprintln!("error: --json can only be used with --diff");
        process::exit(2);
    }
    // `--stdout` is only the `--init-config` output target. Without it,
    // a bare `--stdout` would otherwise fall through to normal daemon
    // startup (silently, on a box with /etc/rustbgpd/config.toml).
    if to_stdout && init_profile.is_none() {
        eprintln!("error: --stdout can only be used with --init-config");
        process::exit(2);
    }
    // `--init-config` is a standalone mode, not a modifier on a daemon
    // run — reject combining it with the other one-shot modes rather
    // than silently letting init win and ignoring them.
    if init_profile.is_some() && (check_only || diff_path.is_some()) {
        eprintln!("error: --init-config cannot be combined with --check or --diff");
        process::exit(2);
    }

    // `--init-config PROFILE --stdout` prints a curated starter config and
    // exits — handled before loading any runtime config, since config
    // generation must work before a config file (or daemon) exists.
    if let Some(profile) = init_profile {
        if !to_stdout {
            eprintln!(
                "error: --init-config currently requires --stdout (file output is not yet supported)"
            );
            process::exit(2);
        }
        let Some(toml) = crate::config::profiles::profile_toml(&profile) else {
            eprintln!(
                "error: unknown profile {profile:?}; available: {}",
                crate::config::profiles::PROFILE_NAMES.join(", ")
            );
            process::exit(2);
        };
        // Self-check: the built-in template must validate. A failure here
        // is a bug in the profile, not operator error — fail loud so it's
        // never emitted as broken bootstrap.
        if let Err(diagnostic) =
            Config::load_toml_with_diagnostics(toml, &format!("--init-config {profile}"))
        {
            eprintln!(
                "internal error: built-in profile {profile:?} failed validation:\n{diagnostic}"
            );
            process::exit(70);
        }
        print!("{toml}");
        return;
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

    let worker_threads = resolve_worker_threads(config.global.worker_threads);
    info!(worker_threads, "initializing tokio runtime");
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()
        .unwrap_or_else(|e| fatal_startup_error("failed to create tokio runtime", e));
    rt.block_on(run(config, profiler));
}

/// Default tokio worker-thread cap when neither env nor config specifies one.
const DEFAULT_WORKER_THREAD_CAP: usize = 8;

/// Resolve the tokio worker-thread count: `RUSTBGPD_WORKER_THREADS` (if a
/// positive integer) overrides the `[global] worker_threads` config field,
/// which in turn overrides the default of `min(available parallelism, 8)`.
/// A zero or unparseable value is ignored in favor of the next source. The
/// cap right-sizes the async runtime for an I/O-bound daemon — reducing
/// virtual-address reservation and scheduler footprint (it is RSS-neutral)
/// rather than spawning one worker per core on high-core-count hosts.
fn resolve_worker_threads(configured: Option<usize>) -> usize {
    let env = match std::env::var("RUSTBGPD_WORKER_THREADS") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            warn!("ignoring non-unicode RUSTBGPD_WORKER_THREADS");
            None
        }
    };
    resolve_worker_threads_from(env, configured)
}

/// Pure core of [`resolve_worker_threads`] with the environment value injected,
/// so the precedence (env > config > capped default) is unit-testable without
/// touching process-global env state.
fn resolve_worker_threads_from(env: Option<String>, configured: Option<usize>) -> usize {
    if let Some(raw) = env {
        match raw.trim().parse::<usize>() {
            Ok(n) if n > 0 => return n,
            // An explicit `0` means "unset" — fall through silently.
            Ok(_) => {}
            Err(_) => warn!(
                value = %raw,
                "ignoring invalid RUSTBGPD_WORKER_THREADS (expected a positive integer)"
            ),
        }
    }
    if let Some(n) = configured.filter(|n| *n > 0) {
        return n;
    }
    std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .min(DEFAULT_WORKER_THREAD_CAP)
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
    let router_id: Ipv4Addr = config.global.router_id.parse().unwrap_or_else(|e| {
        error!(
            router_id = %config.global.router_id,
            error = %e,
            "invalid router-id after configuration validation"
        );
        process::exit(1);
    });

    // Spawn metrics HTTP server (if configured)
    if let Some(prometheus_addr) = config.prometheus_addr() {
        let metrics_clone = metrics.clone();
        tokio::spawn(async move {
            metrics_server::serve_metrics(prometheus_addr, metrics_clone).await;
        });
    }

    // ── ADR-0072: Durable event outbox (EventHistoryManager) ───────
    //
    // Spawned before any producer so the handle is available when
    // constructing the RIB sink + plumbing into PeerManager,
    // EventService, and the BFD bridge. On start failure the
    // behavior depends on `[event_history].required`: required=true
    // bails out; required=false logs an error, flips the degraded
    // gauge, and continues in live-only mode (SubscribeFromEvent
    // returns FAILED_PRECONDITION while the rest of the live
    // surface keeps working).
    let (event_history_manager, event_history_handle) = if config.event_history.enabled {
        let ehm_config = build_event_history_config(&config, &metrics);
        match rustbgpd_event_history::EventHistoryManager::start(ehm_config).await {
            Ok(mgr) => {
                let handle = mgr.handle();
                info!(
                    path = %config.event_history_db_path().display(),
                    "event history manager started",
                );
                (Some(mgr), Some(handle))
            }
            Err(e) if config.event_history.required => {
                error!(
                    error = %e,
                    path = %config.event_history_db_path().display(),
                    "[event_history].required = true but EHM failed to start"
                );
                process::exit(1);
            }
            Err(e) => {
                error!(
                    error = %e,
                    path = %config.event_history_db_path().display(),
                    "event_history open failed; continuing in live-only mode"
                );
                metrics.record_event_outbox_open_failure();
                (None, None)
            }
        }
    } else {
        info!("event history disabled via [event_history].enabled = false");
        (None, None)
    };

    // Build global export policy chain for RIB manager fallback
    let export_policy = config.export_chain().unwrap_or_else(|e| {
        error!("invalid global export policy: {e}");
        process::exit(1);
    });

    // Spawn RIB manager. When EHM is enabled, install an EHM-backed
    // event sink so route + EVPN events flow into the durable
    // outbox alongside the existing process-local ring + broadcast.
    let cluster_id = config.cluster_id();
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(4096);
    let (rib_query_tx, rib_query_rx) = mpsc::channel::<RibUpdate>(256);
    let mut rib_manager = RibManager::new(
        rib_rx,
        rib_query_rx,
        export_policy,
        cluster_id,
        metrics.clone(),
    );
    if let Some(handle) = event_history_handle.clone() {
        rib_manager = rib_manager.with_event_sink(
            rustbgpd_api::event_history_sinks::make_rib_event_sink(handle, metrics.clone()),
        );
    }
    tokio::spawn(rib_manager.run());

    // Validation snapshot channel: broadcast VRP + ASPA tables to transport
    // sessions for import-time route validation.  Starts empty — sessions fall
    // back to NotFound/Unknown until the first cache update arrives.
    let (validation_watch_tx, validation_watch_rx) =
        tokio::sync::watch::channel(rustbgpd_rpki::ValidationSnapshot::default());

    let (peer_mgr_tx, peer_mgr_rx) = mpsc::channel::<PeerManagerCommand>(64);
    let (peer_mgr_internal_tx, peer_mgr_internal_rx) = mpsc::unbounded_channel();

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
        let rpki_peer_mgr_tx = peer_mgr_tx.clone();
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
                trigger_import_validation_refresh(
                    &rpki_peer_mgr_tx,
                    ImportValidationDependency::Rpki,
                )
                .await;
            }
        });

        // Forward ASPA table updates to RIB manager + validation watch
        let aspa_rib_tx = rib_tx.clone();
        let aspa_peer_mgr_tx = peer_mgr_tx.clone();
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
                trigger_import_validation_refresh(
                    &aspa_peer_mgr_tx,
                    ImportValidationDependency::Aspa,
                )
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
    // ADR-0067 step 4 — BFD/BGP coupling channels. Created here so PeerManager
    // (the desired-set owner) can take the sender + state-change receiver; the
    // BFD actor takes the matching receiver + sender when it spawns below.
    let bfd_initial = bfd_runtime::BfdRuntimeConfig::from_config(&config);
    let (bfd_desired_tx, bfd_desired_rx) = tokio::sync::watch::channel(bfd_initial.clone());
    let (bfd_state_change_tx, bfd_state_change_rx) =
        tokio::sync::mpsc::unbounded_channel::<bfd_runtime::BfdStateChange>();

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
    )
    .with_event_history(event_history_handle.clone())
    .with_transport_event_sink(event_history_handle.clone().map(|handle| {
        rustbgpd_api::event_history_sinks::make_transport_event_sink(handle, metrics.clone())
    }));
    // Wire BFD coupling only when BFD is configured; otherwise the unused ends
    // are dropped (the actor won't spawn either). PeerManager holds the desired
    // sender for life and never recreates it (the actor treats sender drop as
    // shutdown).
    let peer_mgr = if bfd_initial.enabled() {
        let configured: std::collections::HashMap<_, _> = bfd_initial
            .sessions
            .iter()
            .map(|s| (s.peer, s.clone()))
            .collect();
        peer_mgr.with_bfd_coupling(bfd_desired_tx, bfd_state_change_rx, configured)
    } else {
        drop(bfd_desired_tx);
        drop(bfd_state_change_rx);
        peer_mgr
    };
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
    // here would be a programming error rather than operator input,
    // but we still surface it as a daemon-fatal diagnostic to avoid
    // silently dropping instances if a future code path skips validation.
    let evpn_instances = std::sync::Arc::new(config.resolve_evpn_instances().unwrap_or_else(|e| {
        fatal_startup_error(
            "EVPN instances failed to re-resolve after configuration validation",
            e,
        );
    }));

    // Gate 9 IP-VRFs (`[[evpn_ip_vrfs]]`). Same fatal-after-validate
    // pattern as `evpn_instances`. Empty for any deployment without
    // Gate 9 config; the dataplane short-circuits `probe_ip_vrfs` when
    // empty so L2-only and RR-only deployments incur zero added cost.
    let evpn_ip_vrfs = std::sync::Arc::new(config.resolve_evpn_ip_vrfs().unwrap_or_else(|e| {
        fatal_startup_error(
            "EVPN IP-VRFs failed to re-resolve after configuration validation",
            e,
        );
    }));

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
    let evpn_dataplane_runtime_control = evpn_dataplane_handle
        .as_ref()
        .map(evpn_dataplane::EvpnDataplaneHandle::runtime_control);

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
    let ethernet_segments = config.resolve_ethernet_segments().unwrap_or_else(|e| {
        fatal_startup_error(
            "Ethernet segments failed to re-resolve after configuration validation",
            e,
        );
    });
    let vni_to_esi = evpn_runtime_converger::evpn_vni_to_esi_map(&ethernet_segments);
    // ADR-0063 EVPN runtime coordinator. The public API validates full
    // candidates through this handle and commits only after daemon
    // actor convergence accepts the planned mutation. SIGHUP remains
    // restart-required for EVPN edits.
    let evpn_runtime_coordinator =
        Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
            evpn_instances.clone(),
            evpn_ip_vrfs.clone(),
            ethernet_segments.clone(),
        )));
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
    let evpn_originator_runtime_control = evpn_originator_handle
        .as_ref()
        .map(evpn_originator::EvpnOriginatorHandle::runtime_control);

    // EVPN Type 3 IMET origination (Gate 7b+1 phase F). One Type 3
    // per L2VNI announcing this VTEP's BGP-level VNI membership; not
    // conditioned on kernel readiness. Originated at startup, with
    // controller-owned keys retained for shutdown-time withdraw.
    // RR-only paths (empty `evpn_instances`) skip origination entirely
    // — IMET requires a VTEP IP, which an RR doesn't have.
    let evpn_imet_controller =
        Arc::new(tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new()));
    if !evpn_instances.is_empty() {
        evpn_imet_controller
            .lock()
            .await
            .originate_all(evpn_instances.iter().cloned().collect::<Vec<_>>(), &rib_tx)
            .await;
    }

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
    let evpn_svi_runtime_control = evpn_svi_handle
        .as_ref()
        .map(evpn_svi::EvpnSviHandle::runtime_control);

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
    let evpn_segment_runtime_control = evpn_segment_handle
        .as_ref()
        .map(evpn_segment::EvpnSegmentHandle::runtime_control);

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
    let evpn_remote_ip_prefix_drop_counts_rx = evpn_dataplane_handle.as_ref().map_or_else(
        || {
            let (_, rx) = tokio::sync::watch::channel(std::sync::Arc::new(
                evpn_dataplane::RemoteIpPrefixDropCounts::new(),
            ));
            rx
        },
        evpn_dataplane::EvpnDataplaneHandle::remote_prefix_drop_counts_receiver,
    );
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
    let evpn_l3_originator_runtime_control = evpn_l3_originator_handle
        .as_ref()
        .map(evpn_l3_originator::EvpnL3OriginatorHandle::runtime_control);
    let evpn_runtime_apply_lock = Arc::new(tokio::sync::Mutex::new(()));
    let evpn_runtime_converger = Arc::new(evpn_runtime_converger::EvpnRuntimeActorConverger::new(
        rib_tx.clone(),
        evpn_imet_controller.clone(),
        evpn_dataplane_runtime_control,
        evpn_originator_runtime_control,
        evpn_svi_runtime_control,
        evpn_l3_originator_runtime_control,
        evpn_segment_runtime_control,
    ));
    let evpn_runtime_reload_apply = evpn_runtime_converger::EvpnRuntimeReloadApply::new(
        evpn_runtime_coordinator.clone(),
        evpn_runtime_apply_lock.clone(),
        evpn_runtime_converger.clone(),
        config.clone(),
    );

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
    let (fib_event_tx, fib_event_rx) =
        tokio::sync::broadcast::channel::<fib_runtime::FibRuntimeEvent>(4096);
    let (fib_bgp_event_tx, _) =
        tokio::sync::broadcast::channel::<rustbgpd_api::proto::BgpEvent>(4096);
    let _fib_event_bridge_handle = spawn_fib_dataplane_event_bridge(
        fib_event_rx,
        fib_bgp_event_tx.clone(),
        event_history_handle.clone(),
        metrics.clone(),
    );
    let fib_runtime_shutdown = tokio_util::sync::CancellationToken::new();
    let fib_runtime_handle = fib_runtime::spawn(
        fib_runtime::FibRuntimeConfig {
            tables: config.fib_tables.clone(),
            owned_state_path: Some(config.runtime_state_dir().join("fib-owned.json")),
            multipath_relax: config.global.multipath_relax,
            link_bandwidth_weighted: config.global.link_bandwidth_weighted,
        },
        rib_tx.clone(),
        rib_query_tx.clone(),
        metrics.clone(),
        fib_status_tx,
        fib_event_tx,
        fib_runtime_shutdown.clone(),
    );
    // Command sender for runtime `[[fib_tables]]` hot-swap (SIGHUP reload now;
    // gRPC CRUD later). `Some` iff the FIB reconciler actually spawned at
    // startup (≥1 table, Linux, netlink ok).
    let fib_cmd_tx = fib_runtime_handle
        .as_ref()
        .map(fib_runtime::FibRuntimeHandle::command_sender);

    // Spawn the BFD actor (single-hop async, ADR-0067). Runs the sessions in the
    // PeerManager-owned desired set, publishes their state, and emits state
    // changes that PeerManager couples to BGP (non-strict RFC 5882 teardown).
    // No-op when no neighbor has BFD configured (or off Linux).
    let (bfd_status_tx, bfd_status_rx) =
        tokio::sync::watch::channel(Vec::<bfd_runtime::BfdStatus>::new());
    // Actor state-change events (ADR-0067 step 3b): the actor broadcasts
    // BfdRuntimeEvent; a bridge converts each to a proto BgpEvent that
    // EventService surfaces over WatchEvents. The proto `bfd_bgp_event_tx`
    // (held in ServeConfig) is the long-lived sink, so the WatchEvents BFD
    // stream stays open even when no sessions are configured. The actor event
    // channel (`bfd_event_tx`) is dropped if the actor doesn't start (no
    // sessions / off Linux), which simply ends the bridge task.
    let (bfd_event_tx, bfd_event_rx) =
        tokio::sync::broadcast::channel::<bfd_runtime::BfdRuntimeEvent>(1024);
    let (bfd_bgp_event_tx, _) =
        tokio::sync::broadcast::channel::<rustbgpd_api::proto::BgpEvent>(1024);
    let _bfd_event_bridge = spawn_bfd_event_bridge(
        bfd_event_rx,
        bfd_bgp_event_tx.clone(),
        event_history_handle.clone(),
        metrics.clone(),
    );
    // The desired-set receiver + state-change sender are the actor's ends of the
    // coupling channels created above (PeerManager owns the other ends).
    let bfd_runtime_shutdown = tokio_util::sync::CancellationToken::new();
    let bfd_runtime_handle = bfd_runtime::spawn(
        bfd_desired_rx,
        metrics.clone(),
        bfd_status_tx,
        bfd_event_tx,
        bfd_state_change_tx,
        bfd_runtime_shutdown.clone(),
    );

    // Spawn gRPC API server (keep JoinHandle for supervision)
    let grpc_rib_tx = rib_tx.clone();
    let grpc_rib_query_tx = rib_query_tx;
    let grpc_peer_mgr_tx = peer_mgr_tx.clone();
    let evpn_duplicate_mac_clear = evpn_originator_handle.as_ref().map(|handle| {
        let control = handle.control();
        Arc::new(move |vni, mac| {
            let control = control.clone();
            Box::pin(async move {
                match control
                    .clear_duplicate_mac_quarantine(rustbgpd_evpn::DuplicateMacKey::new(vni, mac))
                    .await
                {
                    Ok(evpn_originator::ClearDuplicateMacQuarantineResult::Cleared) => {
                        Ok(rustbgpd_api::evpn_service::DuplicateMacClearOutcome { cleared: true })
                    }
                    Ok(evpn_originator::ClearDuplicateMacQuarantineResult::NotActive) => {
                        Ok(rustbgpd_api::evpn_service::DuplicateMacClearOutcome { cleared: false })
                    }
                    Ok(evpn_originator::ClearDuplicateMacQuarantineResult::UnknownVni) => Err(
                        rustbgpd_api::evpn_service::DuplicateMacClearError::NotFound(format!(
                            "no EVPN instance configured for VNI {vni}"
                        )),
                    ),
                    Err(evpn_originator::EvpnOriginatorControlError::Closed) => Err(
                        rustbgpd_api::evpn_service::DuplicateMacClearError::Unavailable(
                            "EVPN originator control channel is closed".to_string(),
                        ),
                    ),
                    Err(evpn_originator::EvpnOriginatorControlError::ReplyDropped) => Err(
                        rustbgpd_api::evpn_service::DuplicateMacClearError::Unavailable(
                            "EVPN originator control response channel dropped".to_string(),
                        ),
                    ),
                }
            }) as rustbgpd_api::evpn_service::DuplicateMacClearFuture
        }) as rustbgpd_api::evpn_service::DuplicateMacClearFn
    });
    // Coordinator lock serializing persisted runtime config mutations with
    // SIGHUP reload. FIB-table CRUD, dynamic-neighbor CRUD, and the SIGHUP
    // reload path hold it across their read/apply/persist sequence so stale
    // TOML snapshots cannot clobber accepted runtime changes.
    let runtime_config_lock = std::sync::Arc::new(tokio::sync::Mutex::new(()));
    let config_transaction_controller =
        config_transaction_control::ConfigTransactionController::new(
            fib_table_control::FibTableControlDeps {
                fib_cmd_tx: fib_cmd_tx.clone(),
                peer_mgr_tx: peer_mgr_tx.clone(),
                config_tx: config_event_tx.clone(),
                lock: runtime_config_lock.clone(),
                config_mutation_gate: None,
                startup_tables: config.fib_tables.clone(),
            },
            metrics.clone(),
        );
    let config_mutation_gate = config_transaction_controller.mutation_gate_fn();
    let serve_config = ServeConfig {
        asn: config.global.asn,
        router_id: config.global.router_id.clone(),
        listen_port: u32::from(config.global.listen_port),
        metrics: metrics.clone(),
        start_time,
        mrt_trigger_tx,
        evpn_originated_local_mac_count: {
            let counts = evpn_originated_local_mac_counts.clone();
            Arc::new(move |vni| {
                rustbgpd_evpn::EvpnInstanceId::new(vni).map_or(0, |id| counts.count(id))
            })
        },
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
        evpn_remote_ip_prefix_drop_counts: {
            let rx = evpn_remote_ip_prefix_drop_counts_rx.clone();
            Arc::new(move || {
                rx.borrow()
                    .iter()
                    .map(|((vrf, reason), count)| {
                        rustbgpd_api::evpn_service::RemoteIpPrefixDropCount {
                            vrf: vrf.clone(),
                            reason: reason.clone(),
                            count: *count,
                        }
                    })
                    .collect()
            })
        },
        evpn_fdb_nexthop_snapshot: {
            let rx = evpn_fdb_nexthops_rx.clone();
            Arc::new(move || rx.borrow().clone())
        },
        evpn_runtime_model: {
            let coordinator = evpn_runtime_coordinator.clone();
            Arc::new(move || match coordinator.lock() {
                Ok(guard) => guard.model().clone(),
                Err(poisoned) => poisoned.into_inner().model().clone(),
            })
        },
        evpn_runtime_apply: {
            let reload_apply = evpn_runtime_reload_apply.clone();
            Some(Arc::new(move |request| {
                let reload_apply = reload_apply.clone();
                Box::pin(async move { reload_apply.apply_request(&request).await })
                    as rustbgpd_api::evpn_service::EvpnRuntimeApplyFuture
            })
                as rustbgpd_api::evpn_service::EvpnRuntimeApplyFn)
        },
        evpn_duplicate_mac_clear,
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
                    .map(|status| {
                        let sampling = status.sampling.as_ref();
                        rustbgpd_api::proto::FibRouteStatus {
                            table_name: status.table_name.clone(),
                            table_id: status.table_id,
                            metric: status.metric,
                            prefix: status.prefix.addr_string(),
                            prefix_length: u32::from(status.prefix.prefix_len()),
                            next_hop: status
                                .next_hop
                                .map_or_else(String::new, |ip| ip.to_string()),
                            next_hops: status.next_hops.iter().map(ToString::to_string).collect(),
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
                            sampling_sampled_rows: sampling.map_or(0, |s| s.sampled_rows),
                            sampling_suppressed_rows: sampling.map_or(0, |s| s.suppressed_rows),
                            sampling_total_rows: sampling.map_or(0, |s| s.total_rows),
                            sampling_max_routes: sampling.map_or(0, |s| s.max_routes),
                            sampling_sample_limit: sampling.map_or(0, |s| s.sample_limit),
                            sampling_complete: sampling.is_some_and(|s| s.suppressed_rows == 0),
                        }
                    })
                    .collect()
            })
        },
        fib_table_control: Some(fib_table_control::make_fib_table_control_fn(
            fib_table_control::FibTableControlDeps {
                fib_cmd_tx: fib_cmd_tx.clone(),
                peer_mgr_tx: peer_mgr_tx.clone(),
                config_tx: config_event_tx.clone(),
                lock: runtime_config_lock.clone(),
                config_mutation_gate: Some(config_mutation_gate.clone()),
                startup_tables: config.fib_tables.clone(),
            },
        )),
        gnmi_set: Some(config_transaction_controller.gnmi_set_fn()),
        config_transaction_apply: Some(config_transaction_controller.apply_fn()),
        config_transaction_confirm: Some(config_transaction_controller.confirm_fn()),
        config_transaction_abort: Some(config_transaction_controller.abort_fn()),
        config_transaction_status: Some(config_transaction_controller.status_fn()),
        config_mutation_gate: Some(config_mutation_gate.clone()),
        runtime_config_lock: runtime_config_lock.clone(),
        dataplane_route_events: Some(fib_bgp_event_tx),
        bfd_session_snapshot: {
            let rx = bfd_status_rx.clone();
            Arc::new(move || {
                rx.borrow()
                    .iter()
                    .map(|status| rustbgpd_api::proto::BfdSession {
                        peer_address: status.peer.to_string(),
                        state: bfd_session_state_to_proto(status.state) as i32,
                        diagnostic: bfd_diagnostic_to_str(status.diagnostic).to_string(),
                        strict: status.strict,
                    })
                    .collect()
            })
        },
        bfd_events: Some(bfd_bgp_event_tx),
        event_history: event_history_handle.clone(),
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
                    interface: transport_config.peer_interface.clone(),
                    scope_id: transport_config.peer_scope_id,
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
                    local_role: transport_config.peer.local_role,
                    strict_role: transport_config.peer.strict_role,
                    prefix_orf_receive: transport_config.peer.prefix_orf_receive,
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
        .unwrap_or_else(|e| fatal_startup_error("failed to register SIGTERM handler", e));
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .unwrap_or_else(|e| fatal_startup_error("failed to register SIGHUP handler", e));

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
    let mut reload_in_flight: Option<
        tokio::task::JoinHandle<Option<Result<Config, &'static str>>>,
    > = None;
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
                let live_tcp = live_grpc_tcp.clone();
                let live_uds = live_grpc_uds.clone();
                let pm_tx = peer_mgr_tx.clone();
                let fib_cmd = fib_cmd_tx.clone();
                let evpn_runtime_reload_apply = evpn_runtime_reload_apply.clone();
                // Hold the runtime-config coordinator lock across BOTH the
                // reload and the outcome application (peer-manager +
                // config-bridge snapshot refresh), so concurrent persisted
                // runtime CRUD can't slip into the gap and have its
                // applied/persisted state clobbered by a stale reload snapshot.
                let runtime_config_lock = runtime_config_lock.clone();
                let config_transaction_controller = config_transaction_controller.clone();
                let pm_internal = peer_mgr_internal_tx.clone();
                let bridge_replace = bridge_replace_tx.clone();
                reload_in_flight = Some(tokio::spawn(async move {
                    let _runtime_config_guard = runtime_config_lock.lock().await;
                    if let Err(error) = config_transaction_controller
                        .reject_if_pending("SIGHUP reload")
                        .await
                    {
                        warn!(
                            error = %error,
                            "SIGHUP reload ignored while confirmed config transaction is applying or pending"
                        );
                        return None;
                    }
                    let snapshot = match runtime_config_snapshot(&pm_tx).await {
                        Ok(snapshot) => snapshot,
                        Err(error) => {
                            error!(
                                error = %error,
                                "failed to read live runtime config snapshot for SIGHUP reload"
                            );
                            return None;
                        }
                    };
                    let reloaded = reload_config(
                        &path,
                        &snapshot,
                        live_tcp.as_ref(),
                        live_uds.as_ref(),
                        &pm_tx,
                        fib_cmd.as_ref(),
                        Some(&evpn_runtime_reload_apply),
                    )
                    .await?;
                    Some(apply_reload_outcome(reloaded, &pm_internal, bridge_replace.as_ref()).await)
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
                    Ok(Some(Ok(advanced))) => config = advanced,
                    Ok(Some(Err(stage))) => error!(
                        stage,
                        "post-reload sync failed mid-flight; in-memory config not advanced — next SIGHUP will retry"
                    ),
                    Ok(None) => {
                        // reload_config returned None (failure) or short-circuited.
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
    let mut imet_controller = evpn_imet_controller.lock().await;
    if !imet_controller.is_empty() {
        info!(
            count = imet_controller.len(),
            "withdrawing EVPN Type 3 IMET routes"
        );
        imet_controller.withdraw_all(&rib_tx).await;
    }
    drop(imet_controller);

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

    // Drain BFD sessions (emits AdminDown so peers go Down promptly).
    if let Some(handle) = bfd_runtime_handle {
        info!("draining BFD sessions");
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

    // 5. Shut down the durable event outbox (ADR-0072) after the
    // producers and gRPC have drained. EHM owns its own bounded
    // 5-second hard timeout on the storage thread; we don't await
    // unconditionally because a wedged SQLite must not stall the
    // daemon exit. Holding EHM alive across the producer + gRPC
    // drain means any final SubscribeFromEvent observers see their
    // last committed events and any in-flight `try_send` reaches
    // disk before shutdown.
    if let Some(manager) = event_history_manager {
        info!("flushing event history outbox");
        manager.shutdown().await;
    }

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
    fn worker_thread_resolution_precedence() {
        // env (positive) wins over config and default.
        assert_eq!(
            resolve_worker_threads_from(Some("4".to_string()), Some(2)),
            4
        );
        // config wins when env is absent; an explicit value is NOT capped.
        assert_eq!(resolve_worker_threads_from(None, Some(16)), 16);
        // zero / unparseable env is ignored, falling through to config.
        assert_eq!(
            resolve_worker_threads_from(Some("0".to_string()), Some(3)),
            3
        );
        assert_eq!(
            resolve_worker_threads_from(Some("nope".to_string()), Some(3)),
            3
        );
        // zero config is ignored, falling through to the capped default.
        let default_zero = resolve_worker_threads_from(None, Some(0));
        assert!((1..=DEFAULT_WORKER_THREAD_CAP).contains(&default_zero));
        // no env, no config → capped default in [1, 8].
        let default = resolve_worker_threads_from(None, None);
        assert!((1..=DEFAULT_WORKER_THREAD_CAP).contains(&default));
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
                worker_threads: None,
                honor_graceful_shutdown: false,
                honor_blackhole: false,
                multipath_relax: false,
                link_bandwidth_weighted: false,
                install_blackhole_discard: false,
                allow_blackhole_broad_prefixes: false,
            },
            security: crate::config::SecurityConfig::default(),
            neighbors: vec![
                crate::config::Neighbor {
                    address: "10.0.0.2".to_string(),
                    interface: None,
                    remote_asn: 65002,
                    description: None,
                    peer_group: None,
                    hold_time: None,
                    max_prefixes: None,
                    md5_password: None,
                    tcp_ao: None,
                    bfd: None,
                    ttl_security: Some(false),
                    families: Vec::new(),
                    graceful_restart: Some(true),
                    gr_restart_time: Some(90),
                    gr_stale_routes_time: None,
                    llgr_stale_time: None,
                    local_ipv6_nexthop: None,
                    route_reflector_client: Some(false),
                    route_server_client: Some(false),
                    role: None,
                    strict_role: None,
                    prefix_orf_receive: None,
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
                    interface: None,
                    remote_asn: 65003,
                    description: None,
                    peer_group: None,
                    hold_time: None,
                    max_prefixes: None,
                    md5_password: None,
                    tcp_ao: None,
                    bfd: None,
                    ttl_security: Some(false),
                    families: Vec::new(),
                    graceful_restart: Some(true),
                    gr_restart_time: Some(180),
                    gr_stale_routes_time: None,
                    llgr_stale_time: None,
                    local_ipv6_nexthop: None,
                    route_reflector_client: Some(false),
                    route_server_client: Some(false),
                    role: None,
                    strict_role: None,
                    prefix_orf_receive: None,
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
                    interface: None,
                    remote_asn: 65004,
                    description: None,
                    peer_group: None,
                    hold_time: None,
                    max_prefixes: None,
                    md5_password: None,
                    tcp_ao: None,
                    bfd: None,
                    ttl_security: Some(false),
                    families: Vec::new(),
                    graceful_restart: Some(false),
                    gr_restart_time: Some(300),
                    gr_stale_routes_time: None,
                    llgr_stale_time: None,
                    local_ipv6_nexthop: None,
                    route_reflector_client: Some(false),
                    route_server_client: Some(false),
                    role: None,
                    strict_role: None,
                    prefix_orf_receive: None,
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
            bfd_profiles: Vec::new(),
            apply_bum_enforcement: false,
            event_history: crate::config::EventHistoryConfig::default(),
        };

        assert_eq!(max_gr_restart_time_secs(&config), Some(180));
    }
}
