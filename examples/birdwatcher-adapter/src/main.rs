//! Birdwatcher-shaped REST looking glass adapter for rustbgpd.
//!
//! Standalone HTTP server that serves the status, peer, accepted-route,
//! filtered-route, and noexport subset consumed by Alice-LG and similar
//! looking glass frontends, sourcing all data from a running rustbgpd over
//! gRPC. This replaces the removed in-daemon
//! `[global.telemetry.looking_glass]` server's four endpoints and adds the
//! filtered and noexport views on top.
//!
//! **Supported endpoints** (single-table mode):
//! - `GET /status` — daemon status
//! - `GET /protocols/bgp` — BGP neighbor list (with real filtered counts)
//! - `GET /routes/protocol/{id}` — received routes by neighbor address
//! - `GET /routes/peer/{peer}` — received routes by peer IP
//! - `GET /routes/filtered/{id}` — rejected routes retained by the peer's
//!   session (`PolicyService.ListRejectedRoutes`), tagged with a synthesized
//!   reject-reason large community (see the README mapping table)
//! - `GET /routes/noexport/{id}` — Loc-RIB best routes NOT advertised to the
//!   peer (`ListBestRoutes` minus `ListAdvertisedRoutes`), each explained by
//!   the live export gate ladder (`RibService.ExplainAdvertisedRoute`) and
//!   tagged with a synthesized noexport-reason large community
//!
//! Coverage is honest, not complete: routes are IPv4/IPv6 unicast only
//! (no VPN/EVPN views), the noexport view is prefix-granular and covers
//! every export-ladder suppression (split horizon, RR reflection, family,
//! LLGR, ORF, RT membership, export policy) — not only NO_EXPORT-community
//! routes — and multi-table endpoints beyond `/routes/peer` are absent.
//!
//! Response shapes use Birdwatcher field names so Alice-LG can parse this
//! subset without adapter code. Fields that have no rustbgpd equivalent are
//! present but empty/zero.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path as FsPath, PathBuf};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Json, Router, routing::get};
use clap::Parser;
use rustbgpd_api::proto;
use serde_json::Value;
use tonic::metadata::AsciiMetadataValue;
use tonic::service::{Interceptor, interceptor::InterceptedService};
use tonic::transport::Channel;
use tonic::{Request, Status};
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(
    name = "birdwatcher-adapter",
    about = "Birdwatcher-shaped status, peer, accepted-route, filtered-route, and noexport REST subset, served from rustbgpd's gRPC API"
)]
struct Args {
    /// rustbgpd gRPC endpoint, e.g. `http://127.0.0.1:50051`.
    #[arg(long, env = "BIRDWATCHER_ADAPTER_GRPC_ADDR")]
    grpc_addr: String,

    /// Optional bearer-token file for rustbgpd gRPC authentication.
    #[arg(long, env = "BIRDWATCHER_ADAPTER_GRPC_TOKEN_FILE")]
    grpc_token_file: Option<PathBuf>,

    /// HTTP listen address for the birdwatcher REST surface.
    #[arg(
        long,
        env = "BIRDWATCHER_ADAPTER_LISTEN",
        default_value = "127.0.0.1:8080"
    )]
    listen: SocketAddr,
}

#[derive(Clone, Debug, Default)]
struct BearerInterceptor {
    authorization: Option<AsciiMetadataValue>,
}

impl Interceptor for BearerInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        if let Some(authorization) = self.authorization.clone() {
            request
                .metadata_mut()
                .insert("authorization", authorization);
        }
        Ok(request)
    }
}

fn load_bearer_authorization(
    token_file: Option<&FsPath>,
) -> Result<Option<AsciiMetadataValue>, std::io::Error> {
    let Some(token_file) = token_file else {
        return Ok(None);
    };
    let raw = std::fs::read_to_string(token_file)?;
    let token = raw.trim_end();
    if token.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("token file is empty: {}", token_file.display()),
        ));
    }
    if !token.is_ascii() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "invalid token file {}: authorization value must be valid ASCII gRPC metadata",
                token_file.display()
            ),
        ));
    }
    let mut authorization =
        AsciiMetadataValue::try_from(format!("Bearer {token}")).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "invalid token file {}: authorization value must be valid ASCII gRPC metadata",
                    token_file.display()
                ),
            )
        })?;
    authorization.set_sensitive(true);
    Ok(Some(authorization))
}

type Upstream = InterceptedService<Channel, BearerInterceptor>;

/// Shared state: one multiplexed, optionally authenticated gRPC service;
/// per-request clients are cheap clones of it.
#[derive(Clone)]
struct AppState {
    upstream: Upstream,
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
    let authorization = load_bearer_authorization(args.grpc_token_file.as_deref())?;
    let upstream = InterceptedService::new(channel, BearerInterceptor { authorization });
    let state = AppState { upstream };

    let app = Router::new()
        .route("/status", get(status))
        .route("/protocols/bgp", get(protocols_bgp))
        .route("/routes/protocol/{id}", get(routes_protocol))
        .route("/routes/peer/{peer}", get(routes_peer))
        .route("/routes/filtered/{id}", get(routes_filtered))
        .route("/routes/noexport/{id}", get(routes_noexport))
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
    let mut global = proto::global_service_client::GlobalServiceClient::new(state.upstream.clone());
    let g = global
        .get_global(proto::GetGlobalRequest {})
        .await
        .map_err(|e| bad_gateway("GetGlobal", &e))?
        .into_inner();

    let mut control =
        proto::control_service_client::ControlServiceClient::new(state.upstream.clone());
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
        proto::neighbor_service_client::NeighborServiceClient::new(state.upstream.clone());
    let resp = client
        .list_neighbors(proto::ListNeighborsRequest {})
        .await
        .map_err(|e| bad_gateway("ListNeighbors", &e))?
        .into_inner();

    // Birdwatcher returns protocols as a map keyed by protocol name.
    // Alice-LG iterates this map and reads fields like `neighbor_address`,
    // `neighbor_as`, `state`, `description`, `routes`, `state_changed`.
    let mut policy = proto::policy_service_client::PolicyServiceClient::new(state.upstream.clone());
    let mut protocols = serde_json::Map::new();
    for n in &resp.neighbors {
        let cfg = n.config.clone().unwrap_or_default();
        let protocol_id = format!("bgp_{}", cfg.address).replace(':', "_");
        // Real filtered count from the session's reject-retention store.
        // NOT_FOUND = no live session = no store, honestly zero. The store
        // is bounded ([policy.reject_retention] capacity, default 1024), so
        // one unpaged call returns everything.
        let filtered = match policy
            .list_rejected_routes(proto::ListRejectedRoutesRequest {
                peer_address: cfg.address.clone(),
            })
            .await
        {
            Ok(r) => r.into_inner().routes.len(),
            Err(s) if s.code() == tonic::Code::NotFound => 0,
            Err(e) => return Err(bad_gateway("ListRejectedRoutes", &e)),
        };
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
                    "filtered": filtered,
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
    let mut client = proto::rib_service_client::RibServiceClient::new(state.upstream.clone());
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
// GET /routes/filtered/{id}  — Alice-LG filtered-route view
//                            →  PolicyService.ListRejectedRoutes
// ---------------------------------------------------------------------------

async fn routes_filtered(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    // Accepts both the "bgp_<addr>" protocol id and a bare peer IP.
    let addr_str = id.strip_prefix("bgp_").unwrap_or(&id).replace('_', ":");
    let peer_addr: IpAddr = addr_str.parse().map_err(|_| StatusCode::BAD_REQUEST)?;

    let mut client = proto::policy_service_client::PolicyServiceClient::new(state.upstream.clone());
    let resp = match client
        .list_rejected_routes(proto::ListRejectedRoutesRequest {
            peer_address: peer_addr.to_string(),
        })
        .await
    {
        Ok(r) => r.into_inner(),
        // No live session: the session-local retention store is gone.
        // An empty filtered view is the correct answer, not an error.
        Err(s) if s.code() == tonic::Code::NotFound => {
            info!(peer = %peer_addr, "no live session; serving empty filtered view");
            return Ok(Json(serde_json::json!({
                "api": api_block(),
                "routes": [],
            })));
        }
        Err(e) => return Err(bad_gateway("ListRejectedRoutes", &e)),
    };
    Ok(Json(filtered_routes_body(&resp, peer_addr)))
}

/// Build the filtered-view response body from a `ListRejectedRoutes`
/// reply. The store is bounded (`[policy.reject_retention]` capacity,
/// default 1024) and the RPC is unpaged — one call returns everything.
fn filtered_routes_body(resp: &proto::ListRejectedRoutesResponse, peer: IpAddr) -> Value {
    if !resp.retention_enabled {
        info!(
            peer = %peer,
            "reject retention disabled ([policy.reject_retention]); \
             serving empty filtered view"
        );
    }
    let routes: Vec<Value> = resp
        .routes
        .iter()
        .map(|r| rejected_route_to_birdwatcher(r, peer))
        .collect();
    serde_json::json!({
        "api": api_block(),
        "routes": routes,
    })
}

/// Synthesized reject-reason large community, `64496:65520:<reason id>`.
///
/// Alice-LG identifies why a route was filtered by matching communities
/// against its `[rejection]`/`[rejection_reasons]` config (the BIRD /
/// arouteserver convention — reject reasons ride on a large community).
/// rustbgpd deliberately retains structured reason tokens instead of
/// polluting the RIB with tag communities, so this adapter synthesizes
/// the community representation at the edge:
///
/// - global administrator `64496`: RFC 5398 documentation ASN — can
///   never collide with a community a route actually carried;
/// - function `65520`: the arouteserver reject-reason function value;
/// - value: a stable id per canonical reason token (`0` = token not
///   recognized by this adapter build, still marked rejected).
///
/// The token vocabulary is release-stable; ids here are append-only.
fn reject_reason_community(reason: &str) -> [u64; 3] {
    let id = match reason {
        "policy_reject" => 1,
        "otc_route_leak" => 2,
        "next_hop_ownership" => 3,
        "as_path_loop" => 4,
        "rr_loop" => 5,
        "treat_as_withdraw" => 6,
        _ => 0,
    };
    [64496, 65520, id]
}

/// Convert a retained rejection to the birdwatcher route JSON shape.
///
/// Same shape as `route_to_birdwatcher`, with the reject reason surfaced
/// twice: as the synthesized large community (what Alice-LG matches) and
/// as human-readable `reject_reason` / `reject_reason_detail` fields
/// (extra keys, ignored by parsers that don't know them). Attribute
/// fields are best-effort — the pre-policy safety gates retain what was
/// decodable — so absent attributes render as the usual empty sentinels.
fn rejected_route_to_birdwatcher(route: &proto::RejectedRoute, peer: IpAddr) -> Value {
    let communities: Vec<Vec<u32>> = route
        .communities
        .iter()
        .map(|c| vec![(*c >> 16) & 0xffff, *c & 0xffff])
        .collect();

    // Wire large communities the route carried, then the synthesized
    // reason triplet appended last.
    let mut large_communities: Vec<Vec<u64>> = route
        .large_communities
        .iter()
        .filter_map(|lc| {
            let parts: Vec<u64> = lc.split(':').filter_map(|p| p.parse().ok()).collect();
            (parts.len() == 3).then_some(parts)
        })
        .collect();
    large_communities.push(reject_reason_community(&route.reason).to_vec());

    // The retained AS_PATH is a lossless display string ("65001 {65002
    // 65003}"); birdwatcher wants an ASN array, so flatten it (AS_SET
    // members included) best-effort.
    let as_path: Vec<u32> = route
        .as_path
        .split(|c: char| !c.is_ascii_digit())
        .filter(|p| !p.is_empty())
        .filter_map(|p| p.parse().ok())
        .collect();

    let from_protocol = format!("bgp_{peer}").replace(':', "_");
    let age = if route.rejected_at_unix_ns > 0 {
        format_epoch_secs(u64::try_from(route.rejected_at_unix_ns).unwrap_or(0) / 1_000_000_000)
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
        "learnt_from": peer.to_string(),
        "reject_reason": route.reason,
        "reject_reason_detail": route.reason_detail,
        "rpki_validation": route.rpki_validation,
        "aspa_validation": route.aspa_validation,
        "bgp": {
            // ORIGIN is not retained for rejected routes; empty parses
            // as unknown in Alice-LG.
            "origin": "",
            "as_path": as_path,
            "next_hop": route.next_hop,
            "local_pref": 0,
            "med": 0,
            "communities": communities,
            "large_communities": large_communities,
        }
    })
}

// ---------------------------------------------------------------------------
// GET /routes/noexport/{id}  — Alice-LG not-exported view
//   →  RibService.ListBestRoutes − RibService.ListAdvertisedRoutes,
//      each missing prefix explained by RibService.ExplainAdvertisedRoute
// ---------------------------------------------------------------------------

async fn routes_noexport(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    // Accepts both the "bgp_<addr>" protocol id and a bare peer IP.
    let addr_str = id.strip_prefix("bgp_").unwrap_or(&id).replace('_', ":");
    let peer_addr: IpAddr = addr_str.parse().map_err(|_| StatusCode::BAD_REQUEST)?;

    let mut rib = proto::rib_service_client::RibServiceClient::new(state.upstream.clone());

    // Adj-RIB-Out prefix set. Prefix-granular on purpose: any advertised
    // path for a prefix means the prefix is exported (an Add-Path peer's
    // partially-suppressed extra paths are not reported as noexport).
    let mut advertised: HashSet<(String, u32)> = HashSet::new();
    let mut page_token = String::new();
    loop {
        let resp = rib
            .list_advertised_routes(proto::ListRoutesRequest {
                neighbor_address: peer_addr.to_string(),
                afi_safi: proto::AddressFamily::Unspecified as i32,
                page_size: 1000,
                page_token,
                ..Default::default()
            })
            .await
            .map_err(|e| bad_gateway("ListAdvertisedRoutes", &e))?
            .into_inner();
        advertised.extend(
            resp.routes
                .iter()
                .map(|r| (r.prefix.clone(), r.prefix_length)),
        );
        if resp.next_page_token.is_empty() {
            break;
        }
        page_token = resp.next_page_token;
    }

    // Loc-RIB best — the export candidate set (single-best send mode;
    // only best routes are export candidates).
    let mut best: Vec<proto::Route> = Vec::new();
    let mut page_token = String::new();
    loop {
        let resp = rib
            .list_best_routes(proto::ListRoutesRequest {
                afi_safi: proto::AddressFamily::Unspecified as i32,
                page_size: 1000,
                page_token,
                ..Default::default()
            })
            .await
            .map_err(|e| bad_gateway("ListBestRoutes", &e))?
            .into_inner();
        best.extend(resp.routes);
        if resp.next_page_token.is_empty() {
            break;
        }
        page_token = resp.next_page_token;
    }

    // One explain per suppressed prefix — a dry run of the same staging
    // body the live export path executes, so the reason cannot drift
    // from the real decision. O(suppressed prefixes) RPCs; pair with
    // Alice-LG's `[noexport] load_on_demand` (its own default) so this
    // is only computed when an operator opens the view.
    let mut routes: Vec<Value> = Vec::new();
    for route in noexport_candidates(&best, &advertised) {
        let explain = match rib
            .explain_advertised_route(proto::ExplainAdvertisedRouteRequest {
                peer_address: peer_addr.to_string(),
                prefix: route.prefix.clone(),
                prefix_length: route.prefix_length,
                ..Default::default()
            })
            .await
        {
            Ok(r) => r.into_inner(),
            // Peer not registered for outbound updates (no live
            // session): nothing is being exported *or* withheld — an
            // empty noexport view, same posture as the filtered view.
            Err(s) if s.code() == tonic::Code::NotFound => {
                info!(
                    peer = %peer_addr,
                    "peer has no outbound export state; serving empty noexport view"
                );
                return Ok(Json(serde_json::json!({
                    "api": api_block(),
                    "routes": [],
                })));
            }
            Err(e) => return Err(bad_gateway("ExplainAdvertisedRoute", &e)),
        };
        if let Some(v) = noexport_route_to_birdwatcher(route, &explain) {
            routes.push(v);
        }
    }

    Ok(Json(serde_json::json!({
        "api": api_block(),
        "routes": routes,
    })))
}

/// Loc-RIB best routes whose prefix is absent from the peer's advertised
/// set — the not-exported candidates, deduped per prefix (multipath /
/// Add-Path can put several best paths on one prefix).
fn noexport_candidates<'a>(
    best: &'a [proto::Route],
    advertised: &HashSet<(String, u32)>,
) -> Vec<&'a proto::Route> {
    let mut seen: HashSet<(&str, u32)> = HashSet::new();
    best.iter()
        .filter(|r| !advertised.contains(&(r.prefix.clone(), r.prefix_length)))
        .filter(|r| seen.insert((r.prefix.as_str(), r.prefix_length)))
        .collect()
}

/// Synthesized noexport-reason large community, `64496:65521:<gate id>`.
///
/// Same edge-synthesis convention as `reject_reason_community`: global
/// administrator `64496` (RFC 5398 documentation ASN, collision-free with
/// wire communities), function `65521` (adjacent to the reject-reason
/// function `65520`, distinct so Alice-LG's `[rejection]` and `[noexport]`
/// matchers never overlap), and a stable id per export gate that stopped
/// the route (`0` = gate not recognized by this adapter build). Gate names
/// are the daemon's stable export-ladder vocabulary; ids are append-only.
fn noexport_reason_community(gate: &str) -> [u64; 3] {
    let id = match gate {
        "split_horizon" => 1,
        "rr_reflection" => 2,
        "family" => 3,
        "llgr" => 4,
        "orf" => 5,
        "rt_membership" => 6,
        "export_policy" => 7,
        _ => 0,
    };
    [64496, 65521, id]
}

/// Convert a suppressed best route plus its export explain to the
/// birdwatcher route JSON shape.
///
/// Same shape as `route_to_birdwatcher` (the route carries its full
/// Loc-RIB attributes), with the suppression surfaced twice: as the
/// synthesized noexport-reason large community (what Alice-LG matches)
/// and as human-readable `noexport_reason` / `noexport_reason_detail`
/// extra keys (the stopping gate name and its detail line, ignored by
/// parsers that don't know them).
///
/// Returns `None` when the explain does not actually deny the route —
/// an advertisement the snapshot diff raced (the daemon decided
/// ADVERTISE between the two listings). Serving that as "not exported"
/// would be a fabrication; it disappears from the view instead.
fn noexport_route_to_birdwatcher(
    route: &proto::Route,
    explain: &proto::ExplainAdvertisedRouteResponse,
) -> Option<Value> {
    if explain.decision != proto::ExplainDecision::Deny as i32 {
        return None;
    }
    let stop = explain
        .gates
        .iter()
        .find(|g| g.verdict == proto::ExportGateVerdict::Stop as i32);
    let (gate, detail) = stop.map_or(("", ""), |g| (g.gate.as_str(), g.detail.as_str()));

    let mut json = route_to_birdwatcher(route);
    json["noexport_reason"] = Value::from(gate);
    json["noexport_reason_detail"] = Value::from(detail);
    json["bgp"]["large_communities"]
        .as_array_mut()
        .expect("route_to_birdwatcher always renders bgp.large_communities")
        .push(serde_json::json!(noexport_reason_community(gate)));
    Some(json)
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
    use clap::CommandFactory;

    fn token_file(name: &str, contents: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "rustbgpd-birdwatcher-{name}-{}",
            std::process::id()
        ));
        std::fs::write(&path, contents).unwrap();
        path
    }

    /// Mutation proof: removing token loading, trailing-whitespace trimming,
    /// sensitivity marking, or interceptor insertion makes an assertion red.
    #[test]
    fn bearer_token_file_is_loaded_once_as_sensitive_authorization() {
        let path = token_file("valid-token", "secret-token\n");
        let authorization = load_bearer_authorization(Some(&path)).unwrap().unwrap();
        let _ = std::fs::remove_file(path);
        assert_eq!(authorization, "Bearer secret-token");
        assert!(authorization.is_sensitive());

        let mut interceptor = BearerInterceptor {
            authorization: Some(authorization),
        };
        let request = interceptor.call(Request::new(())).unwrap();
        let inserted = request.metadata().get("authorization").unwrap();
        assert_eq!(inserted, "Bearer secret-token");
        assert!(inserted.is_sensitive());
    }

    /// Mutation proof: making authentication mandatory when the flag is
    /// absent inserts metadata and makes this compatibility assertion red.
    #[test]
    fn absent_token_file_preserves_unauthenticated_compatibility() {
        assert!(load_bearer_authorization(None).unwrap().is_none());
        let mut interceptor = BearerInterceptor::default();
        let request = interceptor.call(Request::new(())).unwrap();
        assert!(request.metadata().get("authorization").is_none());
    }

    /// Mutation proof: accepting empty, non-ASCII, or control-bearing token
    /// contents makes the corresponding case succeed and this test red.
    #[test]
    fn bearer_token_file_rejects_invalid_values_without_disclosure() {
        for (name, contents, expected) in [
            ("empty-token", "\n", "token file is empty"),
            (
                "non-ascii-token",
                "secret-\u{e9}",
                "authorization value must be valid ASCII gRPC metadata",
            ),
            (
                "control-token",
                "secret\nother",
                "authorization value must be valid ASCII gRPC metadata",
            ),
        ] {
            let path = token_file(name, contents);
            let error = load_bearer_authorization(Some(&path)).unwrap_err();
            let _ = std::fs::remove_file(path);
            let rendered = error.to_string();
            assert!(rendered.contains(expected), "{rendered}");
            let secret = contents.trim_end();
            if !secret.is_empty() {
                assert!(!rendered.contains(secret), "{rendered}");
            }
        }
    }

    /// Mutation proof: removing the CLI flag, changing its destination, or
    /// changing its exact environment binding makes an assertion red.
    #[test]
    fn grpc_token_file_flag_parses() {
        let args = Args::try_parse_from([
            "birdwatcher-adapter",
            "--grpc-addr",
            "http://127.0.0.1:50051",
            "--grpc-token-file",
            "/run/secrets/rustbgpd-token",
        ])
        .unwrap();
        assert_eq!(
            args.grpc_token_file.as_deref(),
            Some(FsPath::new("/run/secrets/rustbgpd-token"))
        );

        let command = Args::command();
        let token_arg = command
            .get_arguments()
            .find(|arg| arg.get_id() == "grpc_token_file")
            .expect("grpc_token_file argument must exist");
        assert_eq!(
            token_arg.get_env(),
            Some(std::ffi::OsStr::new("BIRDWATCHER_ADAPTER_GRPC_TOKEN_FILE"))
        );
    }

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

    /// Every canonical reason token maps to its pinned triplet, and an
    /// unknown (future) token degrades to the generic id 0. The ids are
    /// part of the adapter's documented Alice-LG contract — changing one
    /// silently breaks deployed `[rejection_reasons]` configs.
    #[test]
    fn reject_reason_community_mapping_is_stable() {
        for (token, id) in [
            ("policy_reject", 1),
            ("otc_route_leak", 2),
            ("next_hop_ownership", 3),
            ("as_path_loop", 4),
            ("rr_loop", 5),
            ("treat_as_withdraw", 6),
            ("some_future_token", 0),
        ] {
            assert_eq!(
                reject_reason_community(token),
                [64496, 65520, id],
                "token {token:?}"
            );
        }
    }

    #[test]
    fn rejected_route_conversion_matches_birdwatcher_shape() {
        let route = proto::RejectedRoute {
            prefix: "10.66.0.0".to_string(),
            prefix_length: 24,
            reason: "policy_reject".to_string(),
            reason_detail: "customer-in".to_string(),
            next_hop: "192.0.2.99".to_string(),
            // Lossless display form incl. an AS_SET — must flatten.
            as_path: "65020 {65030 65031}".to_string(),
            communities: vec![(65001 << 16) | 666],
            large_communities: vec!["65001:1000:1".to_string()],
            rpki_validation: "not_found".to_string(),
            aspa_validation: "unverified".to_string(),
            // 2026-01-02 03:04:05 UTC
            rejected_at_unix_ns: 1_767_323_045_000_000_000,
            ..Default::default()
        };
        let peer: IpAddr = "192.0.2.1".parse().unwrap();
        let json = rejected_route_to_birdwatcher(&route, peer);

        assert_eq!(json["network"], "10.66.0.0/24");
        assert_eq!(json["gateway"], "192.0.2.99");
        assert_eq!(json["from_protocol"], "bgp_192.0.2.1");
        assert_eq!(json["learnt_from"], "192.0.2.1");
        assert_eq!(json["age"], "2026-01-02 03:04:05");
        assert_eq!(json["reject_reason"], "policy_reject");
        assert_eq!(json["reject_reason_detail"], "customer-in");
        assert_eq!(json["rpki_validation"], "not_found");
        assert_eq!(json["aspa_validation"], "unverified");
        assert_eq!(
            json["bgp"]["as_path"],
            serde_json::json!([65020, 65030, 65031])
        );
        assert_eq!(
            json["bgp"]["communities"],
            serde_json::json!([[65001, 666]])
        );
        // Wire large communities first, synthesized reason triplet last.
        assert_eq!(
            json["bgp"]["large_communities"],
            serde_json::json!([[65001, 1000, 1], [64496, 65520, 1]])
        );
    }

    /// Sparse retention entries (pre-policy safety gates keep only what
    /// was decodable) render with empty sentinels, and the reason
    /// community is still present.
    #[test]
    fn rejected_route_conversion_handles_sparse_entry() {
        let route = proto::RejectedRoute {
            prefix: "2001:db8:bad::".to_string(),
            prefix_length: 48,
            reason: "treat_as_withdraw".to_string(),
            ..Default::default()
        };
        let peer: IpAddr = "2001:db8::1".parse().unwrap();
        let json = rejected_route_to_birdwatcher(&route, peer);
        assert_eq!(json["network"], "2001:db8:bad::/48");
        assert_eq!(json["from_protocol"], "bgp_2001_db8__1");
        assert_eq!(json["age"], "");
        assert_eq!(json["bgp"]["as_path"], serde_json::json!([]));
        assert_eq!(
            json["bgp"]["large_communities"],
            serde_json::json!([[64496, 65520, 6]])
        );
    }

    /// Retention disabled and enabled-but-empty both produce the full
    /// envelope with an empty routes array — configuration facts, not
    /// errors.
    #[test]
    fn filtered_body_empty_and_disabled_cases() {
        let peer: IpAddr = "192.0.2.1".parse().unwrap();
        for enabled in [false, true] {
            let resp = proto::ListRejectedRoutesResponse {
                peer_address: peer.to_string(),
                retention_enabled: enabled,
                capacity: 1024,
                routes: vec![],
            };
            let body = filtered_routes_body(&resp, peer);
            assert!(body["api"].is_object(), "{body}");
            assert_eq!(body["routes"], serde_json::json!([]), "{body}");
        }
    }

    /// The set diff behind the noexport view: a route suppressed for the
    /// peer appears, an exported route does not, duplicate best paths
    /// for one prefix render once, and an empty Loc-RIB yields an empty
    /// view. This is the mutation-proof core — flipping the membership
    /// test either way fails it.
    #[test]
    fn noexport_candidates_keep_suppressed_and_exclude_exported() {
        let mk = |prefix: &str, len: u32, path_id: u32| proto::Route {
            prefix: prefix.to_string(),
            prefix_length: len,
            path_id,
            ..Default::default()
        };
        let best = vec![
            mk("10.1.0.0", 24, 0), // suppressed
            mk("10.2.0.0", 24, 0), // exported
            mk("10.1.0.0", 24, 1), // second best path, same prefix
        ];
        let advertised: HashSet<(String, u32)> = [("10.2.0.0".to_string(), 24)].into();

        let candidates = noexport_candidates(&best, &advertised);
        let networks: Vec<(&str, u32)> = candidates
            .iter()
            .map(|r| (r.prefix.as_str(), r.prefix_length))
            .collect();
        assert_eq!(
            networks,
            vec![("10.1.0.0", 24)],
            "suppressed once, exported absent"
        );

        assert!(
            noexport_candidates(&[], &advertised).is_empty(),
            "empty Loc-RIB yields an empty noexport view"
        );
    }

    /// Every export-ladder gate maps to its pinned triplet, and an
    /// unknown (future) gate degrades to the generic id 0. Like the
    /// reject-reason ids, these are part of the documented Alice-LG
    /// contract — append-only.
    #[test]
    fn noexport_reason_community_mapping_is_stable() {
        for (gate, id) in [
            ("split_horizon", 1),
            ("rr_reflection", 2),
            ("family", 3),
            ("llgr", 4),
            ("orf", 5),
            ("rt_membership", 6),
            ("export_policy", 7),
            ("some_future_gate", 0),
        ] {
            assert_eq!(
                noexport_reason_community(gate),
                [64496, 65521, id],
                "gate {gate:?}"
            );
        }
    }

    #[test]
    fn noexport_route_conversion_matches_birdwatcher_shape() {
        let route = proto::Route {
            prefix: "10.1.0.0".to_string(),
            prefix_length: 24,
            next_hop: "192.0.2.9".to_string(),
            peer_address: "192.0.2.9".to_string(),
            as_path: vec![65010],
            local_pref: 100,
            large_communities: vec!["65001:1:2".to_string()],
            ..Default::default()
        };
        let explain = proto::ExplainAdvertisedRouteResponse {
            decision: proto::ExplainDecision::Deny as i32,
            gates: vec![
                proto::ExportGateStep {
                    gate: "best_route".to_string(),
                    code: "learned".to_string(),
                    verdict: proto::ExportGateVerdict::Pass as i32,
                    detail: "Loc-RIB best".to_string(),
                },
                proto::ExportGateStep {
                    gate: "export_policy".to_string(),
                    code: "policy_denied".to_string(),
                    verdict: proto::ExportGateVerdict::Stop as i32,
                    detail: "denied by term no-transit".to_string(),
                },
            ],
            ..Default::default()
        };

        let json =
            noexport_route_to_birdwatcher(&route, &explain).expect("denied route must render");
        // Base birdwatcher route shape is preserved…
        assert_eq!(json["network"], "10.1.0.0/24");
        assert_eq!(json["gateway"], "192.0.2.9");
        assert_eq!(json["learnt_from"], "192.0.2.9");
        assert_eq!(json["bgp"]["as_path"], serde_json::json!([65010]));
        assert_eq!(json["bgp"]["local_pref"], 100);
        // …the stopping gate is surfaced as the reason…
        assert_eq!(json["noexport_reason"], "export_policy");
        assert_eq!(json["noexport_reason_detail"], "denied by term no-transit");
        // …and the synthesized triplet rides last after wire communities.
        assert_eq!(
            json["bgp"]["large_communities"],
            serde_json::json!([[65001, 1, 2], [64496, 65521, 7]])
        );
    }

    /// An explain that does not deny (the snapshot diff raced an
    /// in-flight advertisement) renders nothing — the view never
    /// fabricates a "not exported" claim.
    #[test]
    fn noexport_route_conversion_skips_non_denied() {
        let route = proto::Route {
            prefix: "10.1.0.0".to_string(),
            prefix_length: 24,
            ..Default::default()
        };
        for decision in [
            proto::ExplainDecision::Advertise,
            proto::ExplainDecision::Unspecified,
            proto::ExplainDecision::NoBestRoute,
        ] {
            let explain = proto::ExplainAdvertisedRouteResponse {
                decision: decision as i32,
                ..Default::default()
            };
            assert!(
                noexport_route_to_birdwatcher(&route, &explain).is_none(),
                "decision {decision:?} must not render as noexport"
            );
        }
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
