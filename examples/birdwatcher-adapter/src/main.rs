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
//! - `GET /protocol/{id}` — one live BGP neighbor detail row
//! - `GET /symbols` — sorted live protocol identities
//! - `GET /routes/protocol/{id}` — received routes by neighbor address
//! - `GET /routes/export/{id}` — routes advertised to a neighbor
//! - `GET /route/{prefix}/protocol/{id}` — exact received-route candidates
//! - `GET /route/{prefix}/export/{id}` — exact advertised-route candidates
//! - `GET /routes/peer/{peer}` — received routes by peer IP
//! - `GET /routes/filtered/{id}` — rejected routes retained by the peer's
//!   session (`PolicyService.ListRejectedRoutes`), tagged with a synthesized
//!   reject-reason large community (see the README mapping table)
//! - `GET /routes/lc-zwild/protocol/{id}/{x}/{y}` — the IXP Manager v7.4
//!   filtered-prefix query for this daemon's `{asn}:1101:*` reason namespace
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

#![deny(unsafe_code)]

use std::collections::{HashMap, HashSet};
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
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Status};
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(
    name = "birdwatcher-adapter",
    about = "Birdwatcher-shaped status, peer, accepted-route, filtered-route, and noexport REST subset, served from rustbgpd's gRPC API"
)]
struct Args {
    /// rustbgpd gRPC endpoint: `http://host:port` or `unix:///absolute/path`.
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

    /// Bird's Eye presentation alias: `PROTOCOL=PEER_IP@TABLE` (repeatable).
    #[arg(
        long = "protocol-alias",
        env = "BIRDWATCHER_ADAPTER_PROTOCOL_ALIASES",
        value_delimiter = ';'
    )]
    protocol_aliases: Vec<String>,

    /// Maximum routes returned by any route-array endpoint.
    #[arg(
        long,
        env = "BIRDWATCHER_ADAPTER_MAX_ROUTES",
        default_value_t = 1000,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    max_routes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProtocolIdentity {
    protocol: String,
    peer: IpAddr,
    table: String,
}

#[derive(Clone, Debug, Default)]
struct IdentityResolver {
    by_protocol: HashMap<String, ProtocolIdentity>,
    by_peer: HashMap<IpAddr, ProtocolIdentity>,
}

impl IdentityResolver {
    fn parse(values: &[String]) -> Result<Self, String> {
        let mut resolver = Self::default();
        for value in values {
            let (protocol, target) = value.split_once('=').ok_or_else(|| {
                format!("invalid protocol alias {value:?}: expected PROTOCOL=PEER_IP@TABLE")
            })?;
            let (peer, table) = target.rsplit_once('@').ok_or_else(|| {
                format!("invalid protocol alias {value:?}: expected PROTOCOL=PEER_IP@TABLE")
            })?;
            if target[..target.len() - table.len() - 1].contains('@')
                || protocol.contains('=')
                || protocol.starts_with("bgp_")
                || !valid_identifier(protocol)
                || !valid_identifier(table)
            {
                return Err(format!(
                    "invalid protocol alias {value:?}: unsafe identifier or separator"
                ));
            }
            let peer: IpAddr = peer
                .parse()
                .map_err(|_| format!("invalid protocol alias {value:?}: malformed peer IP"))?;
            let identity = ProtocolIdentity {
                protocol: protocol.to_string(),
                peer,
                table: table.to_string(),
            };
            if resolver
                .by_protocol
                .insert(protocol.to_string(), identity.clone())
                .is_some()
            {
                return Err(format!("duplicate protocol alias id {protocol:?}"));
            }
            if resolver.by_peer.insert(peer, identity).is_some() {
                return Err(format!("duplicate protocol alias peer {peer}"));
            }
        }
        Ok(resolver)
    }

    fn identity(&self, peer: IpAddr) -> ProtocolIdentity {
        self.by_peer
            .get(&peer)
            .cloned()
            .unwrap_or_else(|| ProtocolIdentity {
                protocol: format!("bgp_{peer}").replace(':', "_"),
                peer,
                table: "master".to_string(),
            })
    }

    fn resolve(&self, id: &str) -> Result<IpAddr, HttpError> {
        if let Some(identity) = self.by_protocol.get(id) {
            return Ok(identity.peer);
        }
        if let Ok(peer) = id.parse() {
            return Ok(peer);
        }
        if let Some(encoded) = id.strip_prefix("bgp_")
            && let Ok(peer) = encoded.replace('_', ":").parse()
        {
            return Ok(peer);
        }
        Err(json_error(StatusCode::NOT_FOUND, "Protocol not found"))
    }
}

fn valid_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
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

#[derive(Clone, Debug, PartialEq, Eq)]
enum DaemonEndpoint {
    Tcp(String),
    Uds(PathBuf),
}

impl DaemonEndpoint {
    fn channel_uri(&self) -> String {
        match self {
            Self::Tcp(uri) => uri.clone(),
            Self::Uds(path) => format!("unix://{}", path.display()),
        }
    }
}

/// Parse the adapter's two endpoint families: complete HTTP(S) TCP endpoints
/// and an absolute Unix-domain socket path. Tonic's lazy channel
/// owns the actual connector and retries it on later requests, which lets the
/// adapter start before either endpoint exists.
fn parse_daemon_endpoint(addr: &str) -> Result<DaemonEndpoint, std::io::Error> {
    if let Some(path) = addr.strip_prefix("unix://") {
        if path.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid gRPC endpoint: unix:// path must not be empty",
            ));
        }
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "invalid gRPC endpoint: Unix socket path must be absolute: {}",
                    path.display()
                ),
            ));
        }
        return Ok(DaemonEndpoint::Uds(path));
    }

    if addr.starts_with("unix:") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid gRPC endpoint: use unix:///absolute/path",
        ));
    }

    if !(addr.starts_with("http://") || addr.starts_with("https://")) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid gRPC endpoint: expected http://, https://, or unix:///absolute/path",
        ));
    }

    // Preserve the existing TCP contract: callers supply a complete HTTP(S)
    // URI and tonic remains the authority for URI validation.
    Endpoint::from_shared(addr.to_string()).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid gRPC endpoint: {error}"),
        )
    })?;
    Ok(DaemonEndpoint::Tcp(addr.to_string()))
}

/// Shared state: one multiplexed, optionally authenticated gRPC service;
/// per-request clients are cheap clones of it.
#[derive(Clone)]
struct AppState {
    upstream: Upstream,
    identities: IdentityResolver,
    max_routes: u64,
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

    let endpoint = parse_daemon_endpoint(&args.grpc_addr)?;
    info!(grpc_addr = %args.grpc_addr, "connecting to rustbgpd");
    // `connect_lazy` so the adapter can start before/independently of
    // the daemon; requests fail with 502 until the daemon is reachable.
    let channel = Endpoint::from_shared(endpoint.channel_uri())?.connect_lazy();
    let authorization = load_bearer_authorization(args.grpc_token_file.as_deref())?;
    let upstream = InterceptedService::new(channel, BearerInterceptor { authorization });
    let identities = IdentityResolver::parse(&args.protocol_aliases)
        .map_err(|message| std::io::Error::new(std::io::ErrorKind::InvalidInput, message))?;
    let state = AppState {
        upstream,
        identities,
        max_routes: args.max_routes,
    };

    let app = Router::new()
        .route("/status", get(status))
        .route("/protocols/bgp", get(protocols_bgp))
        .route("/protocol/{id}", get(protocol_detail))
        .route("/symbols", get(symbols))
        .route("/routes/protocol/{id}", get(routes_protocol))
        .route("/routes/export/{id}", get(routes_export))
        .route("/route/{prefix}/protocol/{id}", get(route_protocol))
        .route("/route/{prefix}/export/{id}", get(route_export))
        .route("/routes/peer/{peer}", get(routes_peer))
        .route("/routes/filtered/{id}", get(routes_filtered))
        .route(
            "/routes/lc-zwild/protocol/{id}/{x}/{y}",
            get(routes_protocol_large_community_wild_xy),
        )
        .route("/routes/noexport/{id}", get(routes_noexport))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    // Log the address actually bound rather than the one requested: with a
    // `:0` port the two differ, and only the bound one is reachable.
    let addr = listener.local_addr().unwrap_or(args.listen);
    info!(%addr, "starting Birdwatcher-shaped looking glass subset");
    axum::serve(listener, app).await?;
    Ok(())
}

/// Map a gRPC error to 502 Bad Gateway — the adapter is healthy, the
/// upstream daemon call failed.
type HttpError = (StatusCode, Json<Value>);

fn json_error(status: StatusCode, message: impl Into<String>) -> HttpError {
    (
        status,
        Json(serde_json::json!({ "message": message.into() })),
    )
}

fn bad_gateway(context: &str, status: &tonic::Status) -> HttpError {
    error!(context, error = %status, "upstream gRPC call failed");
    json_error(StatusCode::BAD_GATEWAY, "Upstream daemon request failed")
}

fn enforce_max(actual: u64, max: u64) -> Result<(), HttpError> {
    if actual > max {
        return Err(json_error(
            StatusCode::FORBIDDEN,
            format!("Number of routes exceeds maximum allowed ({actual}/{max})"),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Birdwatcher-shaped response pieces for the status/peer/accepted-route subset
// (shapes match the removed in-daemon looking glass server).
// ---------------------------------------------------------------------------

/// Top-level `api` block included in every birdwatcher response.
fn api_block(max_routes: u64) -> Value {
    let version = format!("rustbgpd {}", env!("CARGO_PKG_VERSION"));
    serde_json::json!({
        "Version": version,
        "result_from_cache": false,
        "version": version,
        "from_cache": false,
        "max_routes": max_routes,
    })
}

// ---------------------------------------------------------------------------
// GET /status  →  GlobalService.GetGlobal + ControlService.GetHealth
// ---------------------------------------------------------------------------

async fn status(State(state): State<AppState>) -> Result<Json<Value>, HttpError> {
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
        "api": api_block(state.max_routes),
        "status": {
            "router_id": g.router_id,
            "current_server": format_timestamp_now(),
            "server_time": format_rfc3339_secs_ago(0),
            "last_reboot": format_rfc3339_secs_ago(h.uptime_seconds),
            "last_reconfig": format_optional_rfc3339_epoch_secs(
                g.policy_generation_loaded_timestamp_seconds
            ),
            "message": format!("rustbgpd AS{}", g.asn),
            "version": format!("rustbgpd {}", env!("CARGO_PKG_VERSION")),
        }
    })))
}

// ---------------------------------------------------------------------------
// GET /protocols/bgp  →  NeighborService.ListNeighbors
// ---------------------------------------------------------------------------

async fn list_neighbors(state: &AppState) -> Result<Vec<proto::NeighborState>, HttpError> {
    let mut client =
        proto::neighbor_service_client::NeighborServiceClient::new(state.upstream.clone());
    Ok(client
        .list_neighbors(proto::ListNeighborsRequest {})
        .await
        .map_err(|e| bad_gateway("ListNeighbors", &e))?
        .into_inner()
        .neighbors)
}

fn parse_upstream_peer_address(address: &str) -> Result<IpAddr, HttpError> {
    address.parse().map_err(|_| {
        error!("upstream daemon returned an invalid neighbor address");
        json_error(
            StatusCode::BAD_GATEWAY,
            "Upstream daemon returned an invalid neighbor address",
        )
    })
}

async fn protocol_rows(state: &AppState) -> Result<serde_json::Map<String, Value>, HttpError> {
    let neighbors = list_neighbors(state).await?;

    // Birdwatcher returns protocols as a map keyed by protocol name.
    // Alice-LG iterates this map and reads fields like `neighbor_address`,
    // `neighbor_as`, `state`, `description`, `routes`, `state_changed`.
    let mut policy = proto::policy_service_client::PolicyServiceClient::new(state.upstream.clone());
    let mut protocols = serde_json::Map::new();
    for n in &neighbors {
        let cfg = n.config.clone().unwrap_or_default();
        let peer = parse_upstream_peer_address(&cfg.address)?;
        let identity = state.identities.identity(peer);
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
        let mut row = serde_json::json!({
            "protocol": identity.protocol,
            "bird_protocol": "BGP",
            "state": format_ixp_state(n.state),
            "bgp_state": format_bgp_state(n.state),
            "neighbor_address": cfg.address,
            "neighbor_as": cfg.remote_asn,
            "description": cfg.description,
            "table": identity.table,
            "state_changed": format_rfc3339_secs_ago(n.uptime_seconds),
            "routes": {
                // Same sources the in-daemon server used: current
                // Adj-RIB-In count and current advertised count.
                //
                // `preferred` is deliberately absent, not zero: the
                // gRPC surface has no per-peer Loc-RIB best count, and
                // deriving one means paging the whole Loc-RIB
                // (`ListBestRoutes`, tallying `Route.peer_address`) on
                // every poll of this endpoint — a full-table walk per
                // refresh at IXP scale. Serve it here once the daemon
                // exposes the count on `NeighborState`.
                "imported": n.prefixes_received,
                "filtered": filtered,
                "exported": n.prefixes_sent
            }
        });
        if let Some(limit) = n.effective_max_prefixes {
            row["import_limit"] = Value::from(limit);
            row["import_limit_action"] = Value::from(n.max_prefix_action.clone());
        }
        if let Some(negotiated) = &n.negotiated_session {
            if let Some(router_id) = &negotiated.remote_router_id {
                row["neighbor_id"] = Value::from(router_id.clone());
            }
            if let Some(hold_time) = negotiated.hold_time_seconds {
                row["hold_timer"] = Value::from(hold_time);
            }
            let mut capabilities = Vec::new();
            if negotiated.peer_route_refresh == Some(true) {
                capabilities.push("refresh");
            }
            if negotiated.four_octet_as == Some(true) {
                capabilities.push("AS4");
            }
            if !capabilities.is_empty() {
                row["neighbor_capabilities"] = serde_json::json!(capabilities);
            }
        }
        protocols.insert(identity.protocol, row);
    }

    Ok(protocols)
}

async fn protocols_bgp(State(state): State<AppState>) -> Result<Json<Value>, HttpError> {
    let protocols = protocol_rows(&state).await?;

    Ok(Json(serde_json::json!({
        "api": api_block(state.max_routes),
        "protocols": protocols,
    })))
}

async fn protocol_detail(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, HttpError> {
    let peer = state.identities.resolve(&id)?;
    let identity = state.identities.identity(peer);
    let protocols = protocol_rows(&state).await?;
    let row = protocols
        .get(&identity.protocol)
        .cloned()
        .ok_or_else(|| json_error(StatusCode::NOT_FOUND, "Protocol not found"))?;
    Ok(Json(serde_json::json!({
        "api": api_block(state.max_routes),
        "protocol": row,
    })))
}

async fn symbols(State(state): State<AppState>) -> Result<Json<Value>, HttpError> {
    // Symbols need identities only. Keep this a single ListNeighbors RPC:
    // enriching inventory rows would add one ListRejectedRoutes RPC per peer.
    let neighbors = list_neighbors(&state).await?;
    let identities = symbol_identities(neighbors, &state.identities)?;
    Ok(Json(serde_json::json!({
        "api": api_block(state.max_routes),
        "symbols": {
            "protocol": identities,
            "routing table": [],
        }
    })))
}

fn symbol_identities(
    neighbors: Vec<proto::NeighborState>,
    resolver: &IdentityResolver,
) -> Result<Vec<String>, HttpError> {
    let mut identities = Vec::with_capacity(neighbors.len());
    for neighbor in neighbors {
        let cfg = neighbor.config.unwrap_or_default();
        let peer = parse_upstream_peer_address(&cfg.address)?;
        identities.push(resolver.identity(peer).protocol);
    }
    identities.sort_unstable();
    identities.dedup();
    Ok(identities)
}

// ---------------------------------------------------------------------------
// GET /routes/protocol/{id}  — Alice-LG accepted-route single-table view
// GET /routes/peer/{peer}    — Alice-LG accepted-route multi-table view
//                            →  RibService.ListReceivedRoutes
// ---------------------------------------------------------------------------

async fn routes_protocol(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, HttpError> {
    let peer_addr = state.identities.resolve(&id)?;
    serve_routes_for_peer(&state, peer_addr).await
}

async fn routes_peer(
    State(state): State<AppState>,
    Path(peer): Path<String>,
) -> Result<Json<Value>, HttpError> {
    let peer_addr: IpAddr = peer
        .parse()
        .map_err(|_| json_error(StatusCode::BAD_REQUEST, "Invalid peer address"))?;
    serve_routes_for_peer(&state, peer_addr).await
}

async fn serve_routes_for_peer(state: &AppState, peer: IpAddr) -> Result<Json<Value>, HttpError> {
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
                page_token: page_token.clone(),
                ..Default::default()
            })
            .await
            .map_err(|e| bad_gateway("ListReceivedRoutes", &e))?
            .into_inner();
        if page_token.is_empty() {
            enforce_max(resp.total_count, state.max_routes)?;
        }
        routes.extend(
            resp.routes
                .iter()
                .map(|route| route_to_birdwatcher(route, &state.identities)),
        );
        enforce_max(routes.len() as u64, state.max_routes)?;
        if resp.next_page_token.is_empty() {
            break;
        }
        page_token = resp.next_page_token;
    }

    Ok(Json(serde_json::json!({
        "api": api_block(state.max_routes),
        "routes": routes,
    })))
}

async fn routes_export(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, HttpError> {
    let peer = state.identities.resolve(&id)?;
    let mut client = proto::rib_service_client::RibServiceClient::new(state.upstream.clone());
    let mut routes = Vec::new();
    let mut page_token = String::new();
    loop {
        let resp = client
            .list_advertised_routes(proto::ListRoutesRequest {
                neighbor_address: peer.to_string(),
                afi_safi: proto::AddressFamily::Unspecified as i32,
                page_size: 1000,
                page_token: page_token.clone(),
                ..Default::default()
            })
            .await
            .map_err(|e| bad_gateway("ListAdvertisedRoutes", &e))?
            .into_inner();
        if page_token.is_empty() {
            enforce_max(resp.total_count, state.max_routes)?;
        }
        routes.extend(
            resp.routes
                .iter()
                .map(|route| route_to_birdwatcher(route, &state.identities)),
        );
        enforce_max(routes.len() as u64, state.max_routes)?;
        if resp.next_page_token.is_empty() {
            break;
        }
        page_token = resp.next_page_token;
    }
    Ok(Json(serde_json::json!({
        "api": api_block(state.max_routes),
        "routes": routes,
    })))
}

// ---------------------------------------------------------------------------
// GET /route/{prefix}/protocol/{id} — exact received-route candidates
// GET /route/{prefix}/export/{id}   — exact advertised-route candidates
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExactRouteSource {
    Received,
    Advertised,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExactPrefix {
    address: IpAddr,
    length: u32,
}

impl ExactPrefix {
    fn parse(value: &str) -> Result<Self, HttpError> {
        let invalid = || json_error(StatusCode::BAD_REQUEST, "Invalid route prefix");
        let (address, length) = value.split_once('/').ok_or_else(invalid)?;
        if address.is_empty() || length.is_empty() || length.contains('/') {
            return Err(invalid());
        }
        let address: IpAddr = address.parse().map_err(|_| invalid())?;
        let length: u32 = length.parse().map_err(|_| invalid())?;
        let width = if address.is_ipv4() { 32 } else { 128 };
        if length > width || !network_aligned(address, length) {
            return Err(invalid());
        }
        Ok(Self { address, length })
    }

    fn matches(self, route: &proto::Route) -> bool {
        route.prefix == self.address.to_string() && route.prefix_length == self.length
    }
}

fn network_aligned(address: IpAddr, length: u32) -> bool {
    match address {
        IpAddr::V4(address) => {
            let mask = if length == 0 {
                0
            } else {
                u32::MAX << (32 - length)
            };
            u32::from(address) & !mask == 0
        }
        IpAddr::V6(address) => {
            let mask = if length == 0 {
                0
            } else {
                u128::MAX << (128 - length)
            };
            u128::from(address) & !mask == 0
        }
    }
}

#[allow(
    clippy::match_same_arms,
    reason = "separate arms keep each exact IXP consumer journey mutation-testable"
)]
fn exact_route_request(
    peer: IpAddr,
    prefix: ExactPrefix,
    page_token: String,
    source: ExactRouteSource,
) -> proto::ListRoutesRequest {
    let prefix_filter = match source {
        ExactRouteSource::Received => prefix.address.to_string(),
        ExactRouteSource::Advertised => prefix.address.to_string(),
    };
    proto::ListRoutesRequest {
        neighbor_address: peer.to_string(),
        afi_safi: proto::AddressFamily::Unspecified as i32,
        page_size: 1000,
        page_token,
        prefix_filter,
        prefix_filter_length: prefix.length,
        longer_prefixes: false,
        ..Default::default()
    }
}

fn append_exact_routes(
    routes: &mut Vec<proto::Route>,
    page: Vec<proto::Route>,
    prefix: ExactPrefix,
    max_routes: u64,
) -> Result<(), HttpError> {
    routes.extend(page.into_iter().filter(|route| prefix.matches(route)));
    enforce_max(routes.len() as u64, max_routes)
}

async fn route_protocol(
    State(state): State<AppState>,
    Path((prefix, id)): Path<(String, String)>,
) -> Result<Json<Value>, HttpError> {
    serve_exact_route(&state, &prefix, &id, ExactRouteSource::Received).await
}

async fn route_export(
    State(state): State<AppState>,
    Path((prefix, id)): Path<(String, String)>,
) -> Result<Json<Value>, HttpError> {
    serve_exact_route(&state, &prefix, &id, ExactRouteSource::Advertised).await
}

async fn serve_exact_route(
    state: &AppState,
    raw_prefix: &str,
    id: &str,
    source: ExactRouteSource,
) -> Result<Json<Value>, HttpError> {
    let prefix = ExactPrefix::parse(raw_prefix)?;
    let peer = state.identities.resolve(id)?;
    let mut client = proto::rib_service_client::RibServiceClient::new(state.upstream.clone());
    let mut routes = Vec::new();
    let mut page_token = String::new();
    loop {
        let request = exact_route_request(peer, prefix, page_token, source);
        let response = match source {
            ExactRouteSource::Received => client
                .list_received_routes(request)
                .await
                .map_err(|error| bad_gateway("ListReceivedRoutes", &error))?,
            ExactRouteSource::Advertised => client
                .list_advertised_routes(request)
                .await
                .map_err(|error| bad_gateway("ListAdvertisedRoutes", &error))?,
        }
        .into_inner();
        append_exact_routes(&mut routes, response.routes, prefix, state.max_routes)?;
        if response.next_page_token.is_empty() {
            break;
        }
        page_token = response.next_page_token;
    }

    Ok(Json(serde_json::json!({
        "api": api_block(state.max_routes),
        "routes": routes
            .iter()
            .map(|route| route_to_birdwatcher(route, &state.identities))
            .collect::<Vec<_>>(),
    })))
}

// ---------------------------------------------------------------------------
// GET /routes/filtered/{id}  — Alice-LG filtered-route view
//                            →  PolicyService.ListRejectedRoutes
// ---------------------------------------------------------------------------

async fn routes_filtered(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, HttpError> {
    let peer_addr = state.identities.resolve(&id)?;

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
                "api": api_block(state.max_routes),
                "routes": [],
            })));
        }
        Err(e) => return Err(bad_gateway("ListRejectedRoutes", &e)),
    };
    enforce_max(resp.routes.len() as u64, state.max_routes)?;
    Ok(Json(filtered_routes_body(
        &resp,
        peer_addr,
        &state.identities,
        state.max_routes,
    )))
}

const IXP_MANAGER_REJECT_FUNCTION: u64 = 1101;

/// IXP Manager v7.4's member-facing filtered-prefix query. Only the daemon's
/// own rejection namespace is meaningful; a different `(x, y)` is a valid
/// query with no matches.
async fn routes_protocol_large_community_wild_xy(
    State(state): State<AppState>,
    Path((id, x, y)): Path<(String, u64, u64)>,
) -> Result<Json<Value>, HttpError> {
    let peer = state.identities.resolve(&id)?;
    if y != IXP_MANAGER_REJECT_FUNCTION {
        return Ok(Json(empty_routes_body(state.max_routes)));
    }
    let mut global = proto::global_service_client::GlobalServiceClient::new(state.upstream.clone());
    let daemon_asn = u64::from(
        global
            .get_global(proto::GetGlobalRequest {})
            .await
            .map_err(|error| bad_gateway("GetGlobal", &error))?
            .into_inner()
            .asn,
    );
    if !ixp_manager_reason_namespace_matches(daemon_asn, x, y) {
        return Ok(Json(empty_routes_body(state.max_routes)));
    }
    let mut policy = proto::policy_service_client::PolicyServiceClient::new(state.upstream.clone());
    let response = match policy
        .list_rejected_routes(proto::ListRejectedRoutesRequest {
            peer_address: peer.to_string(),
        })
        .await
    {
        Ok(response) => response.into_inner(),
        Err(status) if status.code() == tonic::Code::NotFound => {
            return Ok(Json(empty_routes_body(state.max_routes)));
        }
        Err(error) => return Err(bad_gateway("ListRejectedRoutes", &error)),
    };
    enforce_max(response.routes.len() as u64, state.max_routes)?;
    let routes = response
        .routes
        .iter()
        .map(|route| {
            ixp_manager_rejected_route_to_birdwatcher(route, peer, &state.identities, daemon_asn)
        })
        .collect::<Vec<_>>();
    Ok(Json(serde_json::json!({
        "api": api_block(state.max_routes),
        "routes": routes,
    })))
}

fn empty_routes_body(max_routes: u64) -> Value {
    serde_json::json!({ "api": api_block(max_routes), "routes": [] })
}

fn ixp_manager_reason_namespace_matches(daemon_asn: u64, x: u64, y: u64) -> bool {
    x == daemon_asn && y == IXP_MANAGER_REJECT_FUNCTION
}

/// Build the filtered-view response body from a `ListRejectedRoutes`
/// reply. The store is bounded (`[policy.reject_retention]` capacity,
/// default 1024) and the RPC is unpaged — one call returns everything.
fn filtered_routes_body(
    resp: &proto::ListRejectedRoutesResponse,
    peer: IpAddr,
    identities: &IdentityResolver,
    max_routes: u64,
) -> Value {
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
        .map(|r| rejected_route_to_birdwatcher(r, peer, identities))
        .collect();
    serde_json::json!({
        "api": api_block(max_routes),
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
fn rejected_route_to_birdwatcher(
    route: &proto::RejectedRoute,
    peer: IpAddr,
    identities: &IdentityResolver,
) -> Value {
    render_rejected_route(
        route,
        peer,
        identities,
        reject_reason_community(&route.reason),
        None,
    )
}

fn ixp_manager_rejected_route_to_birdwatcher(
    route: &proto::RejectedRoute,
    peer: IpAddr,
    identities: &IdentityResolver,
    daemon_asn: u64,
) -> Value {
    render_rejected_route(
        route,
        peer,
        identities,
        [
            daemon_asn,
            IXP_MANAGER_REJECT_FUNCTION,
            ixp_manager_reject_reason_id(route),
        ],
        Some([daemon_asn, IXP_MANAGER_REJECT_FUNCTION]),
    )
}

fn ixp_manager_reject_reason_id(route: &proto::RejectedRoute) -> u64 {
    match (route.reason.as_str(), route.reason_detail.as_str()) {
        ("policy_reject", detail) if detail.ends_with(":reject-too-specific") => 1,
        ("policy_reject", detail) if detail.ends_with(":reject-non-global") => 3,
        ("treat_as_withdraw", "aspa_first_as_mismatch") => 7,
        ("next_hop_ownership", _) => 8,
        ("policy_reject", detail)
            if detail.ends_with(":reject-rpki-invalid") && route.rpki_validation == "invalid" =>
        {
            13
        }
        ("policy_reject", detail) if detail.ends_with(":reject-transit-leak") => 14,
        _ => 0,
    }
}

fn render_rejected_route(
    route: &proto::RejectedRoute,
    peer: IpAddr,
    identities: &IdentityResolver,
    reason_community: [u64; 3],
    reserved_namespace: Option<[u64; 2]>,
) -> Value {
    let communities: Vec<Vec<u32>> = route
        .communities
        .iter()
        .map(|c| vec![(*c >> 16) & 0xffff, *c & 0xffff])
        .collect();

    // Wire large communities the route carried, then the synthesized reason
    // triplet appended last. IXP Manager's namespace is adapter-owned: scrub
    // every wire-supplied value in it so a peer cannot forge the displayed
    // rejection cause.
    let mut large_communities: Vec<Vec<u64>> = route
        .large_communities
        .iter()
        .filter_map(|lc| {
            let parts: Vec<u64> = lc.split(':').filter_map(|p| p.parse().ok()).collect();
            (parts.len() == 3
                && reserved_namespace
                    .is_none_or(|reserved| parts[0] != reserved[0] || parts[1] != reserved[1]))
            .then_some(parts)
        })
        .collect();
    large_communities.push(reason_community.to_vec());

    // The retained AS_PATH is a lossless display string ("65001 {65002
    // 65003}"); birdwatcher wants an ASN array, so flatten it (AS_SET
    // members included) best-effort.
    let as_path: Vec<u32> = route
        .as_path
        .split(|c: char| !c.is_ascii_digit())
        .filter(|p| !p.is_empty())
        .filter_map(|p| p.parse().ok())
        .collect();

    let from_protocol = identities.identity(peer).protocol;
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
) -> Result<Json<Value>, HttpError> {
    let peer_addr = state.identities.resolve(&id)?;

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
    let candidates = noexport_candidates(&best, &advertised);
    enforce_max(candidates.len() as u64, state.max_routes)?;
    let mut routes: Vec<Value> = Vec::new();
    for route in candidates {
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
                    "api": api_block(state.max_routes),
                    "routes": [],
                })));
            }
            Err(e) => return Err(bad_gateway("ExplainAdvertisedRoute", &e)),
        };
        if let Some(v) = noexport_route_to_birdwatcher(route, &explain, &state.identities) {
            routes.push(v);
        }
    }

    Ok(Json(serde_json::json!({
        "api": api_block(state.max_routes),
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
    identities: &IdentityResolver,
) -> Option<Value> {
    if explain.decision != proto::ExplainDecision::Deny as i32 {
        return None;
    }
    let stop = explain
        .gates
        .iter()
        .find(|g| g.verdict == proto::ExportGateVerdict::Stop as i32);
    let (gate, detail) = stop.map_or(("", ""), |g| (g.gate.as_str(), g.detail.as_str()));

    let mut json = route_to_birdwatcher(route, identities);
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
fn format_ixp_state(state: i32) -> &'static str {
    match proto::SessionState::try_from(state) {
        Ok(proto::SessionState::Established) => "up",
        Ok(proto::SessionState::Connect) => "start",
        Ok(proto::SessionState::Active) => "active",
        Ok(proto::SessionState::OpenSent) => "opensent",
        Ok(proto::SessionState::OpenConfirm) => "openconfirm",
        // Idle, Unspecified, or unknown enum value.
        _ => "down",
    }
}

fn format_bgp_state(state: i32) -> &'static str {
    match proto::SessionState::try_from(state) {
        Ok(proto::SessionState::Connect) => "Connect",
        Ok(proto::SessionState::Active) => "Active",
        Ok(proto::SessionState::OpenSent) => "OpenSent",
        Ok(proto::SessionState::OpenConfirm) => "OpenConfirm",
        Ok(proto::SessionState::Established) => "Established",
        _ => "Idle",
    }
}

/// Convert a gRPC `Route` to the birdwatcher route JSON shape.
///
/// Alice-LG reads: `network`, `gateway`, `from_protocol`, `interface`,
/// `metric`, `age`, `type`, `primary`, `learnt_from`, and `bgp` sub-object
/// with `origin`, `as_path`, `next_hop`, `local_pref`, `med`, `communities`,
/// `large_communities`.
fn route_to_birdwatcher(route: &proto::Route, identities: &IdentityResolver) -> Value {
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

    let from_protocol = route
        .peer_address
        .parse()
        .map(|peer| identities.identity(peer).protocol)
        .unwrap_or_else(|_| format!("bgp_{}", route.peer_address).replace(':', "_"));

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

fn format_rfc3339_secs_ago(secs: u64) -> String {
    format!("{}+00:00", format_secs_ago(secs).replace(' ', "T"))
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

/// Format a daemon-supplied epoch timestamp, preserving birdwatcher's empty
/// string for an unavailable (zero or negative) value.
fn format_optional_epoch_secs(epoch_secs: i64) -> String {
    u64::try_from(epoch_secs)
        .ok()
        .filter(|seconds| *seconds > 0)
        .map_or_else(String::new, format_epoch_secs)
}

fn format_optional_rfc3339_epoch_secs(epoch_secs: i64) -> String {
    let legacy = format_optional_epoch_secs(epoch_secs);
    if legacy.is_empty() {
        legacy
    } else {
        format!("{}+00:00", legacy.replace(' ', "T"))
    }
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
    fn daemon_endpoint_accepts_tcp_and_absolute_unix_socket() {
        assert_eq!(
            parse_daemon_endpoint("http://127.0.0.1:50051").unwrap(),
            DaemonEndpoint::Tcp("http://127.0.0.1:50051".into())
        );
        assert_eq!(
            parse_daemon_endpoint("unix:///run/rustbgpd/grpc.sock").unwrap(),
            DaemonEndpoint::Uds(PathBuf::from("/run/rustbgpd/grpc.sock"))
        );
    }

    #[test]
    fn daemon_endpoint_rejects_invalid_targets() {
        for (endpoint, expected) in [
            ("unix://", "unix:// path must not be empty"),
            (
                "unix://run/rustbgpd/grpc.sock",
                "Unix socket path must be absolute: run/rustbgpd/grpc.sock",
            ),
            ("unix:grpc.sock", "use unix:///absolute/path"),
            (
                "ftp://127.0.0.1:50051",
                "expected http://, https://, or unix:///absolute/path",
            ),
        ] {
            let error = parse_daemon_endpoint(endpoint).unwrap_err().to_string();
            assert!(error.contains(expected), "{endpoint}: {error}");
        }
    }

    #[test]
    fn malformed_upstream_neighbor_address_fails_closed_without_echoing_input() {
        let invalid = "not-an-ip\nsecret";
        let (status, Json(body)) = parse_upstream_peer_address(invalid).unwrap_err();
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(
            body,
            serde_json::json!({
                "message": "Upstream daemon returned an invalid neighbor address"
            })
        );
        assert!(!body.to_string().contains(invalid));
    }

    #[test]
    fn symbols_are_alias_resolved_sorted_and_do_not_use_enriched_inventory() {
        let resolver = IdentityResolver::parse(&[
            "pb_0002=192.0.2.2@master4".to_string(),
            "pb_0001=192.0.2.1@master4".to_string(),
        ])
        .unwrap();
        let neighbors = ["192.0.2.2", "192.0.2.1", "192.0.2.1"]
            .into_iter()
            .map(|address| proto::NeighborState {
                config: Some(proto::NeighborConfig {
                    address: address.to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            })
            .collect();
        assert_eq!(
            symbol_identities(neighbors, &resolver).unwrap(),
            ["pb_0001", "pb_0002"]
        );

        // Load-bearing call-geometry proof: reverting /symbols to the
        // enriched inventory path restores the per-neighbor policy RPC and
        // makes this contract red.
        let source = include_str!("main.rs");
        let body = source
            .split_once("async fn symbols(")
            .unwrap()
            .1
            .split_once("fn symbol_identities(")
            .unwrap()
            .0;
        assert!(body.contains("list_neighbors(&state).await?"), "{body}");
        assert!(!body.contains("protocol_rows"), "{body}");
        assert!(!body.contains(".list_rejected_routes("), "{body}");
    }

    #[test]
    fn optional_epoch_timestamp_formats_positive_and_leaves_unavailable_empty() {
        assert_eq!(
            format_optional_epoch_secs(1_700_000_000),
            "2023-11-14 22:13:20"
        );
        assert!(format_optional_epoch_secs(0).is_empty());
        assert!(format_optional_epoch_secs(-1).is_empty());
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
        let json = route_to_birdwatcher(&route, &IdentityResolver::default());

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
        let json = route_to_birdwatcher(&route, &IdentityResolver::default());
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
        let json = rejected_route_to_birdwatcher(&route, peer, &IdentityResolver::default());

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
        let json = rejected_route_to_birdwatcher(&route, peer, &IdentityResolver::default());
        assert_eq!(json["network"], "2001:db8:bad::/48");
        assert_eq!(json["from_protocol"], "bgp_2001_db8__1");
        assert_eq!(json["age"], "");
        assert_eq!(json["bgp"]["as_path"], serde_json::json!([]));
        assert_eq!(
            json["bgp"]["large_communities"],
            serde_json::json!([[64496, 65520, 6]])
        );
    }

    #[test]
    fn ixp_manager_reason_mapping_is_conservative_and_stable() {
        let route = |reason: &str, detail: &str, rpki: &str| proto::RejectedRoute {
            reason: reason.to_string(),
            reason_detail: detail.to_string(),
            rpki_validation: rpki.to_string(),
            ..Default::default()
        };
        for (entry, id) in [
            (
                route("policy_reject", "ixp:reject-too-specific", "valid"),
                1,
            ),
            (route("policy_reject", "ixp:reject-non-global", "valid"), 3),
            (
                route("treat_as_withdraw", "aspa_first_as_mismatch", "not_found"),
                7,
            ),
            (route("next_hop_ownership", "strict_peer", "valid"), 8),
            (
                route("policy_reject", "ixp:reject-rpki-invalid", "invalid"),
                13,
            ),
            (
                route("policy_reject", "ixp:reject-transit-leak", "valid"),
                14,
            ),
            (
                route("policy_reject", "ixp:reject-rpki-invalid", "valid"),
                0,
            ),
            (route("otc_route_leak", "ingress_from_peer", "valid"), 0),
            (route("rr_loop", "cluster_list", "valid"), 0),
            (route("policy_reject", "custom:unknown", "invalid"), 0),
        ] {
            assert_eq!(ixp_manager_reject_reason_id(&entry), id, "{entry:?}");
        }
    }

    #[test]
    fn ixp_manager_reason_namespace_is_scrubbed_and_replaced_once() {
        let route = proto::RejectedRoute {
            reason: "next_hop_ownership".to_string(),
            large_communities: vec![
                "65001:1101:99".to_string(),
                "65001:1101:8".to_string(),
                "65001:999:7".to_string(),
                "64496:1101:4".to_string(),
            ],
            ..Default::default()
        };
        let peer = "192.0.2.1".parse().unwrap();
        let json = ixp_manager_rejected_route_to_birdwatcher(
            &route,
            peer,
            &IdentityResolver::default(),
            65001,
        );
        assert_eq!(
            json["bgp"]["large_communities"],
            serde_json::json!([[65001, 999, 7], [64496, 1101, 4], [65001, 1101, 8]])
        );
    }

    #[test]
    fn ixp_manager_filtered_handler_uses_only_retained_rejects() {
        let source = include_str!("main.rs");
        assert!(source.contains(".route(\n            \"/routes/lc-zwild/protocol/{id}/{x}/{y}\""));
        let body = source
            .split_once("async fn routes_protocol_large_community_wild_xy(")
            .unwrap()
            .1
            .split_once("fn empty_routes_body(")
            .unwrap()
            .0;
        assert!(body.contains(".list_rejected_routes("), "{body}");
        assert!(!body.contains("list_received_routes"), "{body}");
        assert!(!body.contains("list_best_routes"), "{body}");
        assert!(!body.contains("serve_routes_for_peer"), "{body}");
        assert!(body.contains("enforce_max(response.routes.len() as u64, state.max_routes)?"));
        assert!(
            body.find("if y != IXP_MANAGER_REJECT_FUNCTION").unwrap()
                < body.find(".get_global(").unwrap(),
            "{body}"
        );
        assert!(ixp_manager_reason_namespace_matches(65001, 65001, 1101));
        assert!(!ixp_manager_reason_namespace_matches(65001, 65002, 1101));
        assert!(!ixp_manager_reason_namespace_matches(65001, 65001, 1102));
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
            let body = filtered_routes_body(&resp, peer, &IdentityResolver::default(), 1000);
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

        let json = noexport_route_to_birdwatcher(&route, &explain, &IdentityResolver::default())
            .expect("denied route must render");
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
                noexport_route_to_birdwatcher(&route, &explain, &IdentityResolver::default())
                    .is_none(),
                "decision {decision:?} must not render as noexport"
            );
        }
    }

    #[test]
    fn bird_state_mapping() {
        assert_eq!(
            format_ixp_state(proto::SessionState::Established as i32),
            "up"
        );
        assert_eq!(
            format_bgp_state(proto::SessionState::Established as i32),
            "Established"
        );
        assert_eq!(format_ixp_state(proto::SessionState::Idle as i32), "down");
        assert_eq!(format_ixp_state(999), "down");
    }

    #[test]
    fn aliases_validate_and_resolve_one_identity_everywhere() {
        let resolver = IdentityResolver::parse(&[
            "pb_0001_as64496=198.51.100.1@master4".to_string(),
            "pb_v6_as64497=2001:db8::1@master6".to_string(),
        ])
        .unwrap();
        let peer: IpAddr = "198.51.100.1".parse().unwrap();
        assert_eq!(resolver.resolve("pb_0001_as64496").unwrap(), peer);
        assert_eq!(resolver.resolve("198.51.100.1").unwrap(), peer);
        assert_eq!(resolver.resolve("bgp_198.51.100.1").unwrap(), peer);
        assert_eq!(resolver.identity(peer).protocol, "pb_0001_as64496");
        assert_eq!(resolver.identity(peer).table, "master4");

        let route = proto::Route {
            peer_address: peer.to_string(),
            ..Default::default()
        };
        assert_eq!(
            route_to_birdwatcher(&route, &resolver)["from_protocol"],
            "pb_0001_as64496"
        );
    }

    #[test]
    fn aliases_reject_ambiguous_or_unsafe_startup_configuration() {
        for aliases in [
            vec!["1bad=198.51.100.1@master4"],
            vec!["bgp_reserved=198.51.100.1@master4"],
            vec!["good=not-an-ip@master4"],
            vec!["good=2001:db8::1"],
            vec!["good=2001:db8::1@master4@extra"],
            vec!["same=198.51.100.1@master4", "same=198.51.100.2@master4"],
            vec!["one=198.51.100.1@master4", "two=198.51.100.1@master4"],
        ] {
            let values: Vec<String> = aliases.into_iter().map(str::to_string).collect();
            assert!(IdentityResolver::parse(&values).is_err(), "{values:?}");
        }
    }

    #[test]
    fn maximum_and_api_contract_are_exact() {
        assert!(enforce_max(1000, 1000).is_ok());
        let (status, body) = enforce_max(1001, 1000).unwrap_err();
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            body.0,
            serde_json::json!({
                "message": "Number of routes exceeds maximum allowed (1001/1000)"
            })
        );
        let api = api_block(1000);
        for key in [
            "Version",
            "result_from_cache",
            "version",
            "from_cache",
            "max_routes",
        ] {
            assert!(api.get(key).is_some(), "missing {key}: {api}");
        }
        assert_eq!(api["Version"], api["version"]);
        assert!(api["version"].as_str().unwrap().starts_with("rustbgpd "));

        assert!(
            Args::try_parse_from([
                "birdwatcher-adapter",
                "--grpc-addr",
                "http://127.0.0.1:50051",
                "--max-routes",
                "0",
            ])
            .is_err()
        );
    }

    #[test]
    fn exact_prefix_parser_accepts_networks_and_rejects_malformed_or_host_values() {
        for (input, address, length) in [
            ("192.0.2.0/24", "192.0.2.0", 24),
            ("0.0.0.0/0", "0.0.0.0", 0),
            ("2001:db8::/32", "2001:db8::", 32),
            ("::/0", "::", 0),
        ] {
            let parsed = ExactPrefix::parse(input).unwrap();
            assert_eq!(parsed.address.to_string(), address);
            assert_eq!(parsed.length, length);
        }
        for input in [
            "192.0.2.0",
            "192.0.2.0/",
            "192.0.2.0/24/extra",
            "not-an-ip/24",
            "192.0.2.0/nope",
            "192.0.2.0/33",
            "192.0.2.1/24",
            "2001:db8::/129",
            "2001:db8::1/64",
        ] {
            let (status, Json(body)) = ExactPrefix::parse(input).unwrap_err();
            assert_eq!(status, StatusCode::BAD_REQUEST, "{input}");
            assert_eq!(body, serde_json::json!({"message":"Invalid route prefix"}));
            assert!(!body.to_string().contains(input));
        }
    }

    #[test]
    fn exact_route_requests_pin_every_filter_on_every_page_and_unknown_id_is_404() {
        let peer: IpAddr = "192.0.2.1".parse().unwrap();
        let prefix = ExactPrefix::parse("2001:db8::/32").unwrap();
        for source in [ExactRouteSource::Received, ExactRouteSource::Advertised] {
            for token in ["", "opaque-page-2"] {
                let request = exact_route_request(peer, prefix, token.to_string(), source);
                assert_eq!(request.neighbor_address, peer.to_string(), "{source:?}");
                assert_eq!(request.prefix_filter, "2001:db8::", "{source:?}");
                assert_eq!(request.prefix_filter_length, 32, "{source:?}");
                assert!(!request.longer_prefixes, "{source:?}");
                assert_eq!(
                    request.afi_safi,
                    proto::AddressFamily::Unspecified as i32,
                    "{source:?}"
                );
                assert_eq!(request.page_token, token, "{source:?}");
            }
        }
        let resolver = IdentityResolver::default();
        let (status, Json(body)) = resolver.resolve("missing-alias").unwrap_err();
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, serde_json::json!({"message":"Protocol not found"}));
    }

    #[test]
    fn exact_route_pages_preserve_add_path_order_and_cap_only_exact_candidates() {
        let prefix = ExactPrefix::parse("192.0.2.0/24").unwrap();
        let route = |network: &str, path_id: u32, med: u32| proto::Route {
            prefix: network.to_string(),
            prefix_length: 24,
            path_id,
            med,
            ..Default::default()
        };
        for source in [ExactRouteSource::Received, ExactRouteSource::Advertised] {
            let mut routes = Vec::new();
            append_exact_routes(
                &mut routes,
                vec![
                    route("198.51.100.0", 1, 99),
                    route("192.0.2.0", 11, 10),
                    route("192.0.2.0", 22, 20),
                ],
                prefix,
                2,
            )
            .unwrap();
            assert_eq!(
                routes.iter().map(|route| route.path_id).collect::<Vec<_>>(),
                [11, 22],
                "{source:?}"
            );
            let (status, Json(body)) =
                append_exact_routes(&mut routes, vec![route("192.0.2.0", 33, 30)], prefix, 2)
                    .unwrap_err();
            assert_eq!(status, StatusCode::FORBIDDEN, "{source:?}");
            assert_eq!(
                body,
                serde_json::json!({"message":"Number of routes exceeds maximum allowed (3/2)"})
            );
        }
    }

    #[test]
    fn upstream_error_mapping_is_stable_and_sanitized() {
        let status = tonic::Status::internal("secret upstream detail");
        let (http_status, Json(body)) = bad_gateway("ListReceivedRoutes", &status);
        assert_eq!(http_status, StatusCode::BAD_GATEWAY);
        assert_eq!(
            body,
            serde_json::json!({"message":"Upstream daemon request failed"})
        );
        assert!(!body.to_string().contains("secret"));
    }

    #[test]
    fn ixp_timestamps_include_rfc3339_utc_offset() {
        assert_eq!(
            format_optional_rfc3339_epoch_secs(1_700_000_000),
            "2023-11-14T22:13:20+00:00"
        );
        assert!(format_optional_rfc3339_epoch_secs(0).is_empty());
        assert!(format_rfc3339_secs_ago(0).ends_with("+00:00"));
    }
}
