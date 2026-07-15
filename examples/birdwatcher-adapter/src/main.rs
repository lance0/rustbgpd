//! Birdwatcher-shaped REST looking glass adapter for rustbgpd.
//!
//! Standalone HTTP server that serves the status, peer, and accepted-route
//! subset consumed by Alice-LG and similar looking glass frontends, sourcing
//! all data from a running rustbgpd over gRPC. This replaces the removed
//! in-daemon `[global.telemetry.looking_glass]` server's four endpoints. It is
//! not a complete Alice-LG backend: filtered/noexport views and structured
//! reject reasons are not exposed.
//!
//! **Supported endpoints** (single-table mode):
//! - `GET /status` — daemon status
//! - `GET /protocols/bgp` — BGP neighbor list
//! - `GET /routes/protocol/{id}` — received routes by neighbor address
//! - `GET /routes/peer/{peer}` — received routes by peer IP
//!
//! Response shapes use Birdwatcher field names so Alice-LG can parse this
//! subset without adapter code. Fields that have no rustbgpd equivalent are
//! present but empty/zero.

use std::net::{IpAddr, SocketAddr};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Json, Router, routing::get};
use clap::Parser;
use rustbgpd_api::proto;
use serde_json::Value;
use tonic::transport::Channel;
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(
    name = "birdwatcher-adapter",
    about = "Birdwatcher-shaped status, peer, and accepted-route REST subset, served from rustbgpd's gRPC API"
)]
struct Args {
    /// rustbgpd gRPC endpoint, e.g. `http://127.0.0.1:50051`.
    #[arg(long, env = "BIRDWATCHER_ADAPTER_GRPC_ADDR")]
    grpc_addr: String,

    /// HTTP listen address for the birdwatcher REST surface.
    #[arg(
        long,
        env = "BIRDWATCHER_ADAPTER_LISTEN",
        default_value = "127.0.0.1:8080"
    )]
    listen: SocketAddr,
}

/// Shared state: one multiplexed gRPC channel; per-request clients are
/// cheap clones of it.
#[derive(Clone)]
struct AppState {
    channel: Channel,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();

    info!(grpc_addr = %args.grpc_addr, "connecting to rustbgpd");
    // `connect_lazy` so the adapter can start before/independently of
    // the daemon; requests fail with 502 until the daemon is reachable.
    let channel = Channel::from_shared(args.grpc_addr.clone())?.connect_lazy();
    let state = AppState { channel };

    let app = Router::new()
        .route("/status", get(status))
        .route("/protocols/bgp", get(protocols_bgp))
        .route("/routes/protocol/{id}", get(routes_protocol))
        .route("/routes/peer/{peer}", get(routes_peer))
        .with_state(state);

    info!(addr = %args.listen, "starting Birdwatcher-shaped looking glass subset");
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Map a gRPC error to 502 Bad Gateway — the adapter is healthy, the
/// upstream daemon call failed.
fn bad_gateway(context: &str, status: &tonic::Status) -> StatusCode {
    error!(context, error = %status, "upstream gRPC call failed");
    StatusCode::BAD_GATEWAY
}

// ---------------------------------------------------------------------------
// Birdwatcher-shaped response pieces for the status/peer/accepted-route subset
// (shapes match the removed in-daemon looking glass server).
// ---------------------------------------------------------------------------

/// Top-level `api` block included in every birdwatcher response.
fn api_block() -> Value {
    serde_json::json!({
        "Version": format!("rustbgpd {}", env!("CARGO_PKG_VERSION")),
        "result_from_cache": false,
    })
}

// ---------------------------------------------------------------------------
// GET /status  →  GlobalService.GetGlobal + ControlService.GetHealth
// ---------------------------------------------------------------------------

async fn status(State(state): State<AppState>) -> Result<Json<Value>, StatusCode> {
    let mut global = proto::global_service_client::GlobalServiceClient::new(state.channel.clone());
    let g = global
        .get_global(proto::GetGlobalRequest {})
        .await
        .map_err(|e| bad_gateway("GetGlobal", &e))?
        .into_inner();

    let mut control =
        proto::control_service_client::ControlServiceClient::new(state.channel.clone());
    let h = control
        .get_health(proto::HealthRequest {})
        .await
        .map_err(|e| bad_gateway("GetHealth", &e))?
        .into_inner();

    Ok(Json(serde_json::json!({
        "api": api_block(),
        "status": {
            "router_id": g.router_id,
            "current_server": format_timestamp_now(),
            "last_reboot": format_secs_ago(h.uptime_seconds),
            // Not tracked by the daemon — same empty-string fallback as
            // the in-daemon server; Alice-LG parses it as zero time.
            "last_reconfig": "",
            "message": format!("rustbgpd AS{}", g.asn),
            "version": format!("rustbgpd {}", env!("CARGO_PKG_VERSION")),
        }
    })))
}

// ---------------------------------------------------------------------------
// GET /protocols/bgp  →  NeighborService.ListNeighbors
// ---------------------------------------------------------------------------

async fn protocols_bgp(State(state): State<AppState>) -> Result<Json<Value>, StatusCode> {
    let mut client =
        proto::neighbor_service_client::NeighborServiceClient::new(state.channel.clone());
    let resp = client
        .list_neighbors(proto::ListNeighborsRequest {})
        .await
        .map_err(|e| bad_gateway("ListNeighbors", &e))?
        .into_inner();

    // Birdwatcher returns protocols as a map keyed by protocol name.
    // Alice-LG iterates this map and reads fields like `neighbor_address`,
    // `neighbor_as`, `state`, `description`, `routes`, `state_changed`.
    let mut protocols = serde_json::Map::new();
    for n in &resp.neighbors {
        let cfg = n.config.clone().unwrap_or_default();
        let protocol_id = format!("bgp_{}", cfg.address).replace(':', "_");
        protocols.insert(
            protocol_id,
            serde_json::json!({
                "bird_protocol": "BGP",
                "state": format_bird_state(n.state),
                "neighbor_address": cfg.address,
                "neighbor_as": cfg.remote_asn,
                "description": cfg.description,
                "table": "master",
                "state_changed": format_secs_ago(n.uptime_seconds),
                "routes": {
                    // Same sources the in-daemon server used: current
                    // Adj-RIB-In count and current advertised count.
                    "imported": n.prefixes_received,
                    "filtered": 0,
                    "exported": n.prefixes_sent,
                    "preferred": 0
                }
            }),
        );
    }

    Ok(Json(serde_json::json!({
        "api": api_block(),
        "protocols": protocols,
    })))
}

// ---------------------------------------------------------------------------
// GET /routes/protocol/{id}  — Alice-LG accepted-route single-table view
// GET /routes/peer/{peer}    — Alice-LG accepted-route multi-table view
//                            →  RibService.ListReceivedRoutes
// ---------------------------------------------------------------------------

async fn routes_protocol(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    // Protocol IDs are "bgp_<addr>" — extract the address.
    let addr_str = id.strip_prefix("bgp_").unwrap_or(&id).replace('_', ":");
    let peer_addr: IpAddr = addr_str.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
    serve_routes_for_peer(&state, peer_addr).await
}

async fn routes_peer(
    State(state): State<AppState>,
    Path(peer): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    let peer_addr: IpAddr = peer.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
    serve_routes_for_peer(&state, peer_addr).await
}

async fn serve_routes_for_peer(state: &AppState, peer: IpAddr) -> Result<Json<Value>, StatusCode> {
    let mut client = proto::rib_service_client::RibServiceClient::new(state.channel.clone());
    let mut routes: Vec<Value> = Vec::new();
    let mut page_token = String::new();
    loop {
        let resp = client
            .list_received_routes(proto::ListRoutesRequest {
                neighbor_address: peer.to_string(),
                // UNSPECIFIED = all unicast families, matching the
                // in-daemon server's unfiltered per-peer query.
                afi_safi: proto::AddressFamily::Unspecified as i32,
                page_size: 1000,
                page_token,
                ..Default::default()
            })
            .await
            .map_err(|e| bad_gateway("ListReceivedRoutes", &e))?
            .into_inner();
        routes.extend(resp.routes.iter().map(route_to_birdwatcher));
        if resp.next_page_token.is_empty() {
            break;
        }
        page_token = resp.next_page_token;
    }

    Ok(Json(serde_json::json!({
        "api": api_block(),
        "routes": routes,
    })))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Format peer state as birdwatcher/BIRD protocol state string.
/// Alice-LG lowercases this and maps "established" → "up" display.
fn format_bird_state(state: i32) -> &'static str {
    match proto::SessionState::try_from(state) {
        Ok(proto::SessionState::Connect) => "start",
        Ok(proto::SessionState::Active) => "active",
        Ok(proto::SessionState::OpenSent) => "opensent",
        Ok(proto::SessionState::OpenConfirm) => "openconfirm",
        Ok(proto::SessionState::Established) => "established",
        // Idle, Unspecified, or unknown enum value.
        _ => "down",
    }
}

/// Convert a gRPC `Route` to the birdwatcher route JSON shape.
///
/// Alice-LG reads: `network`, `gateway`, `from_protocol`, `interface`,
/// `metric`, `age`, `type`, `primary`, `learnt_from`, and `bgp` sub-object
/// with `origin`, `as_path`, `next_hop`, `local_pref`, `med`, `communities`,
/// `large_communities`.
fn route_to_birdwatcher(route: &proto::Route) -> Value {
    // Wire encoding of the ORIGIN attribute (RFC 4271): 0=IGP, 1=EGP,
    // 2=INCOMPLETE. Default IGP, matching the in-daemon server.
    let origin = match route.origin {
        1 => "EGP",
        2 => "Incomplete",
        _ => "IGP",
    };

    let communities: Vec<Vec<u32>> = route
        .communities
        .iter()
        .map(|c| vec![(*c >> 16) & 0xffff, *c & 0xffff])
        .collect();

    // gRPC encodes large communities as "global_admin:data1:data2".
    let large_communities: Vec<Vec<u64>> = route
        .large_communities
        .iter()
        .filter_map(|lc| {
            let parts: Vec<u64> = lc.split(':').filter_map(|p| p.parse().ok()).collect();
            (parts.len() == 3).then_some(parts)
        })
        .collect();

    let from_protocol = format!("bgp_{}", route.peer_address).replace(':', "_");

    // Receive wall time, same source and format as the in-daemon
    // server's `age`. 0 (unknown) renders as the empty string, which
    // Alice-LG parses as zero time (benign).
    let age = if route.received_at_epoch_seconds > 0 {
        format_epoch_secs(route.received_at_epoch_seconds)
    } else {
        String::new()
    };

    serde_json::json!({
        "network": format!("{}/{}", route.prefix, route.prefix_length),
        "gateway": route.next_hop,
        "from_protocol": from_protocol,
        "interface": "",
        "metric": 0,
        "age": age,
        "type": ["BGP", "unicast", "univ"],
        "primary": false,
        "learnt_from": route.peer_address,
        "bgp": {
            "origin": origin,
            "as_path": route.as_path,
            "next_hop": route.next_hop,
            "local_pref": route.local_pref,
            "med": route.med,
            "communities": communities,
            "large_communities": large_communities,
        }
    })
}

/// Format a "now" timestamp in the layout Alice-LG expects for
/// `ServerTimeShort`. Birdwatcher uses BIRD's `current_server` format:
/// `"2025-03-14 12:34:56"`.
fn format_timestamp_now() -> String {
    format_secs_ago(0)
}

/// Produce a timestamp for an event `secs` seconds in the past
/// (`last_reboot`, `state_changed`).
fn format_secs_ago(secs: u64) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format_epoch_secs(now.saturating_sub(secs))
}

/// Format epoch seconds as `"YYYY-MM-DD HH:MM:SS"` (UTC, no chrono dep).
fn format_epoch_secs(epoch_secs: u64) -> String {
    let (days, day_secs) = (epoch_secs / 86400, epoch_secs % 86400);
    let (hour, rem) = (day_secs / 3600, day_secs % 3600);
    let (min, sec) = (rem / 60, rem % 60);
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{min:02}:{sec:02}")
}

/// Convert days since epoch to (year, month, day). Minimal implementation.
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm from Howard Hinnant's `civil_from_days`
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_conversion_matches_birdwatcher_shape() {
        let route = proto::Route {
            prefix: "10.1.0.0".to_string(),
            prefix_length: 24,
            next_hop: "192.0.2.1".to_string(),
            peer_address: "192.0.2.1".to_string(),
            origin: 2,
            as_path: vec![65010, 65020],
            local_pref: 200,
            med: 50,
            communities: vec![(65001 << 16) | 100],
            large_communities: vec!["65001:1:2".to_string()],
            // 2026-01-02 03:04:05 UTC
            received_at_epoch_seconds: 1_767_323_045,
            ..Default::default()
        };
        let json = route_to_birdwatcher(&route);

        assert_eq!(json["network"], "10.1.0.0/24");
        assert_eq!(json["gateway"], "192.0.2.1");
        assert_eq!(json["from_protocol"], "bgp_192.0.2.1");
        assert_eq!(json["learnt_from"], "192.0.2.1");
        assert_eq!(json["age"], "2026-01-02 03:04:05");
        assert_eq!(json["primary"], false);
        assert_eq!(json["type"], serde_json::json!(["BGP", "unicast", "univ"]));
        assert_eq!(json["bgp"]["origin"], "Incomplete");
        assert_eq!(json["bgp"]["as_path"], serde_json::json!([65010, 65020]));
        assert_eq!(json["bgp"]["next_hop"], "192.0.2.1");
        assert_eq!(json["bgp"]["local_pref"], 200);
        assert_eq!(json["bgp"]["med"], 50);
        assert_eq!(
            json["bgp"]["communities"],
            serde_json::json!([[65001, 100]])
        );
        assert_eq!(
            json["bgp"]["large_communities"],
            serde_json::json!([[65001, 1, 2]])
        );
    }

    #[test]
    fn ipv6_peer_protocol_id_uses_underscores() {
        let route = proto::Route {
            prefix: "2001:db8::".to_string(),
            prefix_length: 32,
            next_hop: "2001:db8::1".to_string(),
            peer_address: "2001:db8::1".to_string(),
            ..Default::default()
        };
        let json = route_to_birdwatcher(&route);
        assert_eq!(json["network"], "2001:db8::/32");
        // No receive timestamp → empty age (Alice-LG zero-time fallback).
        assert_eq!(json["age"], "");
        assert_eq!(json["from_protocol"], "bgp_2001_db8__1");
        assert_eq!(json["learnt_from"], "2001:db8::1");
        assert_eq!(json["bgp"]["origin"], "IGP");
    }

    #[test]
    fn bird_state_mapping() {
        assert_eq!(
            format_bird_state(proto::SessionState::Established as i32),
            "established"
        );
        assert_eq!(format_bird_state(proto::SessionState::Idle as i32), "down");
        assert_eq!(format_bird_state(999), "down");
    }
}
