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
//! - `GET /route/{prefix}/protocol/{id}` — received-route candidates, longest match
//! - `GET /route/{prefix}/export/{id}` — advertised-route candidates, longest match
//! - `GET /route/{prefix}/table/{table}` — global Loc-RIB LPM winner and alternatives
//! - `GET /routes/peer/{peer}` — received routes by peer IP
//! - `GET /routes/filtered/{id}` — rejected routes retained by the peer's
//!   session (`PolicyService.ListRejectedRoutes`), tagged with a synthesized
//!   reject-reason large community (see the README mapping table)
//! - `GET /routes/lc-zwild/protocol/{id}/{x}/{y}` — the IXP Manager v7.4
//!   filtered-prefix query for this daemon's `{asn}:1101:*` reason namespace;
//!   any other `(x, y)` follows Bird's Eye wildcard semantics over the
//!   member's accepted routes carrying `(x, y, *)`
//! - `GET /routes/noexport/{id}` — Loc-RIB best routes NOT advertised to the
//!   peer (`ListBestRoutes` minus `ListAdvertisedRoutes`), each explained by
//!   the live export gate ladder (`RibService.ExplainAdvertisedRoute`) and
//!   tagged with a synthesized noexport-reason large community
//!
//! Coverage is honest, not complete: routes are IPv4/IPv6 unicast only
//! (no VPN/EVPN views), the noexport view is prefix-granular and covers
//! every export-ladder suppression (split horizon, RR reflection, family,
//! LLGR, ORF, RT membership, export policy) — not only NO_EXPORT-community
//! routes — and table names are presentation aliases over one global RIB.
//!
//! Response shapes use Birdwatcher field names so Alice-LG can parse this
//! subset without adapter code. Fields that have no rustbgpd equivalent are
//! present but empty/zero.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path as FsPath, PathBuf};
use std::sync::{Arc, RwLock};

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

    /// Alias file: one `PROTOCOL=PEER_IP@TABLE` per line; reloads on Unix SIGHUP.
    #[arg(
        long,
        env = "BIRDWATCHER_ADAPTER_PROTOCOL_ALIAS_FILE",
        conflicts_with = "protocol_aliases"
    )]
    protocol_alias_file: Option<PathBuf>,

    #[arg(long, env = "BIRDWATCHER_ADAPTER_AROUTESERVER_REJECT_COMMUNITIES_FILE")]
    arouteserver_reject_communities_file: Option<PathBuf>,

    /// Maximum routes returned by RIB-derived route-array endpoints.
    #[arg(
        long,
        env = "BIRDWATCHER_ADAPTER_MAX_ROUTES",
        default_value_t = 1000,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    max_routes: u64,

    /// Maximum route rows scanned by a longest-match fallback.
    #[arg(
        long,
        env = "BIRDWATCHER_ADAPTER_MAX_LPM_SCAN_ROUTES",
        default_value_t = 10_000,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    max_lpm_scan_routes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProtocolIdentity {
    protocol: String,
    peer: IpAddr,
    table: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct IdentityResolver {
    by_protocol: HashMap<String, ProtocolIdentity>,
    by_peer: HashMap<IpAddr, ProtocolIdentity>,
}

const MAX_ALIAS_FILE_BYTES: usize = 1024 * 1024;
const MAX_ALIAS_FILE_ENTRIES: usize = 4096;
const ARS_REJECT_SCHEMA: &str = "rustbgpd.arouteserver-reject-communities.v1";
struct ArsRejectCommunities {
    peers: Vec<IpAddr>,
    std: Option<ArsCommunityFamily>,
    lrg: Option<ArsCommunityFamily>,
}

struct ArsCommunityFamily {
    dynamic: Option<Vec<u64>>,
    cause_map: BTreeMap<u8, Vec<u64>>,
}

fn ars_artifact_error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid ARouteServer artifact")
}

fn load_arouteserver_reject_communities(path: &FsPath) -> io::Result<ArsRejectCommunities> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take((MAX_ALIAS_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_ALIAS_FILE_BYTES {
        return Err(ars_artifact_error());
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| ars_artifact_error())?;
    let root = ars_object(&value, &["schema", "peers", "std", "lrg"])?;
    if root.get("schema").and_then(Value::as_str) != Some(ARS_REJECT_SCHEMA) {
        return Err(ars_artifact_error());
    }
    let peer_values = root
        .get("peers")
        .and_then(Value::as_array)
        .ok_or_else(ars_artifact_error)?;
    if peer_values.len() > MAX_ALIAS_FILE_ENTRIES {
        return Err(ars_artifact_error());
    }
    let peer_text = peer_values
        .iter()
        .map(Value::as_str)
        .collect::<Option<Vec<_>>>()
        .ok_or_else(ars_artifact_error)?;
    if peer_text.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(ars_artifact_error());
    }
    let peers = peer_text
        .into_iter()
        .map(str::parse)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ars_artifact_error())?;
    let family = |name, count, max| {
        root.get(name)
            .map(|value| parse_ars_family(value, count, max))
            .transpose()
    };
    let std = family("std", 2, u64::from(u16::MAX))?;
    let lrg = family("lrg", 3, u64::from(u32::MAX))?;
    if std.is_none() && lrg.is_none() {
        return Err(ars_artifact_error());
    }
    Ok(ArsRejectCommunities { peers, std, lrg })
}

fn ars_object<'a>(
    value: &'a Value,
    allowed: &[&str],
) -> io::Result<&'a serde_json::Map<String, Value>> {
    let object = value.as_object().ok_or_else(ars_artifact_error)?;
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(ars_artifact_error());
    }
    Ok(object)
}

fn parse_ars_family(value: &Value, count: usize, max: u64) -> io::Result<ArsCommunityFamily> {
    let family = ars_object(value, &["dynamic", "cause_map"])?;
    let dynamic = family
        .get("dynamic")
        .map(|value| {
            parse_ars_parts(
                value
                    .as_str()
                    .and_then(|value| value.strip_suffix(":dyn_val"))
                    .ok_or_else(ars_artifact_error)?,
                count - 1,
                max,
            )
        })
        .transpose()?;
    let mut cause_map = BTreeMap::new();
    let causes = family
        .get("cause_map")
        .map(|value| value.as_object().ok_or_else(ars_artifact_error))
        .transpose()?;
    for (code, value) in causes.into_iter().flatten() {
        let code = code.parse::<u8>().map_err(|_| ars_artifact_error())?;
        if !(1..=15).contains(&code) {
            return Err(ars_artifact_error());
        }
        cause_map.insert(
            code,
            parse_ars_parts(value.as_str().ok_or_else(ars_artifact_error)?, count, max)?,
        );
    }
    if dynamic.is_none() && cause_map.is_empty() {
        return Err(ars_artifact_error());
    }
    Ok(ArsCommunityFamily { dynamic, cause_map })
}

fn parse_ars_parts(text: &str, count: usize, max: u64) -> io::Result<Vec<u64>> {
    let parts = text
        .split(':')
        .map(|part| part.parse::<u64>().ok().filter(|value| *value <= max))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(ars_artifact_error)?;
    (parts.len() == count)
        .then_some(parts)
        .ok_or_else(ars_artifact_error)
}

fn load_alias_file(path: &FsPath) -> io::Result<IdentityResolver> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take((MAX_ALIAS_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_ALIAS_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "protocol alias file exceeds 1 MiB",
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid alias file"))?;
    let values: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect();
    if values.len() > MAX_ALIAS_FILE_ENTRIES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "protocol alias file exceeds 4096 entries",
        ));
    }
    IdentityResolver::parse(&values)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid alias file"))
}

#[derive(Debug)]
struct ResolverGeneration {
    number: u64,
    resolver: Arc<IdentityResolver>,
}

#[derive(Debug)]
struct ResolverStore(RwLock<ResolverGeneration>);

impl ResolverStore {
    fn new(resolver: IdentityResolver) -> Self {
        Self(RwLock::new(ResolverGeneration {
            number: 1,
            resolver: Arc::new(resolver),
        }))
    }

    fn snapshot(&self) -> Arc<IdentityResolver> {
        self.0
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .resolver
            .clone()
    }

    fn replace(&self, resolver: IdentityResolver) -> Result<(u64, bool), String> {
        let mut current = self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *current.resolver == resolver {
            return Ok((current.number, false));
        }
        let number = current
            .number
            .checked_add(1)
            .ok_or_else(|| "protocol alias generation exhausted".to_string())?;
        *current = ResolverGeneration {
            number,
            resolver: Arc::new(resolver),
        };
        Ok((number, true))
    }
}

#[cfg(unix)]
fn spawn_alias_reloader(path: PathBuf, store: Arc<ResolverStore>) -> io::Result<()> {
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    tokio::spawn(async move {
        while sighup.recv().await.is_some() {
            match load_alias_file(&path)
                .and_then(|resolver| store.replace(resolver).map_err(io::Error::other))
            {
                Ok((generation, true)) => {
                    info!(generation, path = %path.display(), "reloaded protocol aliases");
                }
                Ok((generation, false)) => {
                    info!(generation, path = %path.display(), "protocol aliases unchanged");
                }
                Err(error) => {
                    error!(%error, path = %path.display(), "protocol alias reload rejected; retaining prior generation");
                }
            }
        }
    });
    Ok(())
}

#[cfg(not(unix))]
fn spawn_alias_reloader(_path: PathBuf, _store: Arc<ResolverStore>) -> io::Result<()> {
    Ok(())
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
struct AppState {
    upstream: Upstream,
    identities: Arc<IdentityResolver>,
    identity_store: Arc<ResolverStore>,
    max_routes: u64,
    max_lpm_scan_routes: u64,
    arouteserver_reject_communities: Option<Arc<ArsRejectCommunities>>,
}

impl Clone for AppState {
    fn clone(&self) -> Self {
        Self {
            upstream: self.upstream.clone(),
            identities: self.identity_store.snapshot(),
            identity_store: Arc::clone(&self.identity_store),
            max_routes: self.max_routes,
            max_lpm_scan_routes: self.max_lpm_scan_routes,
            arouteserver_reject_communities: self.arouteserver_reject_communities.clone(),
        }
    }
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
    let identities = if let Some(path) = args.protocol_alias_file.as_deref() {
        load_alias_file(path)?
    } else {
        IdentityResolver::parse(&args.protocol_aliases)
            .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?
    };
    let identity_store = Arc::new(ResolverStore::new(identities));
    if let Some(path) = args.protocol_alias_file {
        spawn_alias_reloader(path, Arc::clone(&identity_store))?;
    }
    let state = AppState {
        upstream,
        identities: identity_store.snapshot(),
        identity_store,
        max_routes: args.max_routes,
        max_lpm_scan_routes: args.max_lpm_scan_routes,
        arouteserver_reject_communities: args
            .arouteserver_reject_communities_file
            .as_deref()
            .map(load_arouteserver_reject_communities)
            .transpose()?
            .map(Arc::new),
    };

    let app = Router::new()
        .route("/status", get(status))
        .route("/protocols/bgp", get(protocols_bgp))
        .route("/protocol/{id}", get(protocol_detail))
        .route("/symbols", get(symbols))
        .route("/routes/protocol/{id}", get(routes_protocol))
        .route("/routes/export/{id}", get(routes_export))
        .route("/routes/table/{table}", get(routes_table))
        .route("/routes/table/{table}/filtered", get(routes_table_filtered))
        .route("/route/{prefix}/protocol/{id}", get(route_protocol))
        .route("/route/{prefix}/export/{id}", get(route_export))
        .route("/route/{prefix}/table/{table}", get(route_table))
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
    let mut protocols = serde_json::Map::new();
    for n in &neighbors {
        let (protocol, row) = protocol_row(state, n)?;
        protocols.insert(protocol, row);
    }

    Ok(protocols)
}

fn retained_reject_count(n: &proto::NeighborState) -> Result<u64, HttpError> {
    n.rejected_routes_retained
        .filter(|_| !n.stale)
        .ok_or_else(|| {
            error!("upstream daemon did not report an authoritative retained-reject count");
            json_error(
                StatusCode::BAD_GATEWAY,
                "Upstream daemon returned incomplete neighbor state",
            )
        })
}

fn protocol_row(state: &AppState, n: &proto::NeighborState) -> Result<(String, Value), HttpError> {
    let cfg = n.config.clone().unwrap_or_default();
    let peer = parse_upstream_peer_address(&cfg.address)?;
    let identity = state.identities.identity(peer);
    let filtered = retained_reject_count(n)?;
    let protocol = identity.protocol;
    let mut row = serde_json::json!({
        "protocol": protocol,
        "bird_protocol": "BGP",
        "state": format_ixp_state(n.state),
        "bgp_state": format_bgp_state(n.state),
        "connection": format_connection(n.state),
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
        },
        "route_limit_at": n.prefixes_received
    });
    if let Some(limit) = n.effective_max_prefixes {
        row["import_limit"] = Value::from(limit);
        row["limit_action"] = Value::from(n.max_prefix_action.clone());
    }
    if let Some(negotiated) = &n.negotiated_session {
        if let Some(address) = &negotiated.local_address {
            row["source_address"] = Value::from(address.clone());
        }
        if let Some(seconds) = negotiated.keepalive_interval_seconds {
            row["keepalive"] = Value::from(seconds);
        }
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
        if cfg.route_server_client {
            let mut session = vec!["external", "route-server"];
            if negotiated.four_octet_as == Some(true) {
                session.push("AS4");
            }
            row["bgp_session"] = serde_json::json!(session);
        }
    }
    Ok((protocol, row))
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
    let (identities, tables) = symbol_names(neighbors, &state.identities)?;
    Ok(Json(serde_json::json!({
        "api": api_block(state.max_routes),
        "symbols": {
            "protocol": identities,
            "routing table": tables,
        }
    })))
}

fn symbol_names(
    neighbors: Vec<proto::NeighborState>,
    resolver: &IdentityResolver,
) -> Result<(Vec<String>, Vec<String>), HttpError> {
    let mut identities = Vec::with_capacity(neighbors.len());
    let mut tables = Vec::with_capacity(neighbors.len());
    for neighbor in neighbors {
        let cfg = neighbor.config.unwrap_or_default();
        let peer = parse_upstream_peer_address(&cfg.address)?;
        let identity = resolver.identity(peer);
        identities.push(identity.protocol);
        tables.push(identity.table);
    }
    identities.sort_unstable();
    identities.dedup();
    tables.sort_unstable();
    tables.dedup();
    Ok((identities, tables))
}

// ---------------------------------------------------------------------------
// GET /routes/protocol/{id}  — Alice-LG accepted-route single-table view
// GET /routes/peer/{peer}    — Alice-LG accepted-route multi-table view
//                            →  RibService.ListReceivedRoutes
// ---------------------------------------------------------------------------

/// Identity key of one route row across the paged route scopes:
/// (prefix, prefix length, source peer, Add-Path id). Advertised rows
/// keep their source identity, so the same key joins every scope.
fn route_key(route: &proto::Route) -> (String, u32, String, u32) {
    (
        route.prefix.clone(),
        route.prefix_length,
        route.peer_address.clone(),
        route.path_id,
    )
}

type RouteCaptureVersion = (u64, u64);
const CAPTURE_ATTEMPTS: usize = 3;

#[derive(Debug)]
enum CaptureError {
    Retry,
    Fatal(HttpError),
}

fn capture_error(what: &'static str, error: &tonic::Status) -> CaptureError {
    if error.code() == tonic::Code::Aborted {
        CaptureError::Retry
    } else {
        CaptureError::Fatal(bad_gateway(what, error))
    }
}

fn capture_version(
    expected: &mut Option<RouteCaptureVersion>,
    actual: Option<&proto::RoutePageVersion>,
) -> Result<(), CaptureError> {
    let actual = actual
        .map(|version| (version.epoch, version.generation))
        .ok_or_else(|| CaptureError::Fatal(invalid_table_snapshot()))?;
    if expected.is_some_and(|expected| expected != actual) {
        return Err(CaptureError::Retry);
    }
    *expected = Some(actual);
    Ok(())
}

/// Loc-RIB best-route identity keys, used to report `primary` truthfully
/// in the received and export views (Bird's Eye marks the selected route
/// in every view). `prefix` narrows the walk to one exact prefix for the
/// exact-route lookups; `None` walks the whole table — the same
/// per-request full-table read the atomic table view already performs.
async fn capture_best_route_keys(
    state: &AppState,
    prefix: Option<ExactPrefix>,
) -> Result<(HashSet<(String, u32, String, u32)>, RouteCaptureVersion), CaptureError> {
    let mut client = proto::rib_service_client::RibServiceClient::new(state.upstream.clone());
    let mut keys = HashSet::new();
    let mut page_token = String::new();
    let mut version = None;
    loop {
        let response = client
            .list_best_routes(proto::ListRoutesRequest {
                afi_safi: proto::AddressFamily::Unspecified as i32,
                page_size: 1000,
                page_token,
                prefix_filter: prefix.map(|p| p.address.to_string()).unwrap_or_default(),
                prefix_filter_length: prefix.map_or(0, |p| p.length),
                ..Default::default()
            })
            .await
            .map_err(|error| capture_error("ListBestRoutes", &error))?
            .into_inner();
        capture_version(&mut version, response.page_version.as_ref())?;
        // Marker set, not a served view: the max-routes cap applies to
        // the view being rendered, not to this lookup.
        keys.extend(response.routes.iter().map(route_key));
        if response.next_page_token.is_empty() {
            break;
        }
        page_token = response.next_page_token;
    }
    Ok((
        keys,
        version.expect("a completed capture has at least one versioned page"),
    ))
}

async fn best_route_keys(
    state: &AppState,
    prefix: Option<ExactPrefix>,
) -> Result<HashSet<(String, u32, String, u32)>, HttpError> {
    let mut client = proto::rib_service_client::RibServiceClient::new(state.upstream.clone());
    let mut keys = HashSet::new();
    let mut page_token = String::new();
    loop {
        let response = client
            .list_best_routes(proto::ListRoutesRequest {
                afi_safi: proto::AddressFamily::Unspecified as i32,
                page_size: 1000,
                page_token,
                prefix_filter: prefix.map(|p| p.address.to_string()).unwrap_or_default(),
                prefix_filter_length: prefix.map_or(0, |p| p.length),
                ..Default::default()
            })
            .await
            .map_err(|error| bad_gateway("ListBestRoutes", &error))?
            .into_inner();
        keys.extend(response.routes.iter().map(route_key));
        if response.next_page_token.is_empty() {
            break;
        }
        page_token = response.next_page_token;
    }
    Ok(keys)
}

async fn routes_protocol(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, HttpError> {
    let peer_addr = state.identities.resolve(&id)?;
    serve_routes_for_peer(&state, peer_addr, None).await
}

async fn routes_peer(
    State(state): State<AppState>,
    Path(peer): Path<String>,
) -> Result<Json<Value>, HttpError> {
    let peer_addr: IpAddr = peer
        .parse()
        .map_err(|_| json_error(StatusCode::BAD_REQUEST, "Invalid peer address"))?;
    serve_routes_for_peer(&state, peer_addr, None).await
}

/// One member's accepted-route view; with `wildcard: Some((x, y))` only the
/// routes carrying a large community `(x, y, *)` are rendered (Bird's Eye's
/// `lc-zwild` semantics, an O(n) scan over the member's paged view).
async fn serve_routes_for_peer(
    state: &AppState,
    peer: IpAddr,
    wildcard: Option<(u64, u64)>,
) -> Result<Json<Value>, HttpError> {
    for _ in 0..CAPTURE_ATTEMPTS {
        let (best, best_version) = match capture_best_route_keys(state, None).await {
            Ok(capture) => capture,
            Err(CaptureError::Retry) => continue,
            Err(CaptureError::Fatal(error)) => return Err(error),
        };
        let mut client = proto::rib_service_client::RibServiceClient::new(state.upstream.clone());
        let mut captured = Vec::new();
        let mut page_token = String::new();
        let mut received_version = None;
        loop {
            let resp = match client
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
            {
                Ok(response) => response.into_inner(),
                Err(error) if error.code() == tonic::Code::Aborted => break,
                Err(error) => return Err(bad_gateway("ListReceivedRoutes", &error)),
            };
            match capture_version(&mut received_version, resp.page_version.as_ref()) {
                Ok(()) => {}
                Err(CaptureError::Retry) => break,
                Err(CaptureError::Fatal(error)) => return Err(error),
            }
            // The generic cap applies to the rows this view renders: the whole
            // received view, or only the wildcard matches (Bird's Eye's
            // MAX_ROUTES likewise counts parsed result rows).
            if page_token.is_empty() && wildcard.is_none() {
                enforce_max(resp.total_count, state.max_routes)?;
            }
            retain_received_page(&mut captured, resp.routes, wildcard, state.max_routes)?;
            if resp.next_page_token.is_empty() {
                if received_version == Some(best_version) {
                    let routes = captured
                        .iter()
                        .map(|route| {
                            route_to_birdwatcher_with_primary(
                                route,
                                &state.identities,
                                best.contains(&route_key(route)),
                            )
                        })
                        .collect::<Vec<_>>();
                    enforce_max(routes.len() as u64, state.max_routes)?;
                    return Ok(Json(serde_json::json!({
                        "api": api_block(state.max_routes),
                        "routes": routes,
                    })));
                }
                break;
            }
            page_token = resp.next_page_token;
        }
    }
    Err(invalid_table_snapshot())
}

fn retain_received_page(
    captured: &mut Vec<proto::Route>,
    routes: Vec<proto::Route>,
    wildcard: Option<(u64, u64)>,
    max_routes: u64,
) -> Result<(), HttpError> {
    let retained = if let Some((x, y)) = wildcard {
        routes
            .into_iter()
            .filter(|route| carries_large_community(route, x, y))
            .collect::<Vec<_>>()
    } else {
        routes
    };
    let accumulated = (captured.len() as u64).saturating_add(retained.len() as u64);
    enforce_max(accumulated, max_routes)?;
    captured.extend(retained);
    Ok(())
}

type TableRouteKey = (ExactPrefix, IpAddr, u32);

#[derive(Default)]
struct TableRouteSet {
    version: Option<(u64, u64)>,
    routes: BTreeMap<TableRouteKey, (proto::Route, bool)>,
    seen: HashSet<(bool, TableRouteKey)>,
    installed: HashSet<ExactPrefix>,
}

impl TableRouteSet {
    fn check_version(
        &mut self,
        version: Option<&proto::RoutePageVersion>,
    ) -> Result<(), CaptureError> {
        let version = version
            .map(|version| (version.epoch, version.generation))
            .ok_or_else(|| CaptureError::Fatal(invalid_table_snapshot()))?;
        if self.version.is_some_and(|expected| expected != version) {
            return Err(CaptureError::Retry);
        }
        self.version = Some(version);
        Ok(())
    }

    fn insert(
        &mut self,
        route: proto::Route,
        best: bool,
        family: i32,
        max_routes: u64,
    ) -> Result<(), HttpError> {
        let prefix = ExactPrefix::from_route(&route.prefix, route.prefix_length)
            .ok_or_else(invalid_table_snapshot)?;
        if (family == proto::AddressFamily::Ipv4Unicast as i32 && !prefix.address.is_ipv4())
            || (family == proto::AddressFamily::Ipv6Unicast as i32 && !prefix.address.is_ipv6())
        {
            return Err(invalid_table_snapshot());
        }
        let key = (
            prefix,
            route
                .peer_address
                .parse()
                .map_err(|_| invalid_table_snapshot())?,
            route.path_id,
        );
        if !self.seen.insert((best, key)) || (best && !self.installed.insert(prefix)) {
            return Err(invalid_table_snapshot());
        }
        if let Some((existing, installed)) = self.routes.get_mut(&key) {
            let mut actual = route;
            actual.best = false;
            let mut expected = existing.clone();
            expected.best = false;
            if actual != expected {
                return Err(invalid_table_snapshot());
            }
            *installed |= best;
        } else {
            enforce_max(self.routes.len() as u64 + 1, max_routes)?;
            self.routes.insert(key, (route, best));
        }
        Ok(())
    }

    fn body(self, identities: &IdentityResolver, max_routes: u64) -> Value {
        let mut routes: Vec<_> = self.routes.into_iter().collect();
        routes.sort_by_key(|(key, (_, primary))| (key.0, Reverse(*primary), key.1, key.2));
        serde_json::json!({
            "api": api_block(max_routes),
            "routes": routes.into_iter().map(|(_, (route, primary))|
                route_to_birdwatcher_with_primary(&route, identities, primary)
            ).collect::<Vec<_>>(),
        })
    }
}

fn invalid_table_snapshot() -> HttpError {
    json_error(
        StatusCode::BAD_GATEWAY,
        "Upstream daemon returned an invalid route response",
    )
}

fn table_address_family(
    neighbors: &[proto::NeighborState],
    identities: &IdentityResolver,
    table: &str,
) -> Result<i32, HttpError> {
    let mut families = 0_u8;
    for neighbor in neighbors {
        let config = neighbor.config.clone().unwrap_or_default();
        let peer = parse_upstream_peer_address(&config.address)?;
        if identities.identity(peer).table == table {
            families |= if peer.is_ipv4() { 1 } else { 2 };
        }
    }
    match families {
        0 => Err(json_error(StatusCode::NOT_FOUND, "Table not found")),
        1 => Ok(proto::AddressFamily::Ipv4Unicast as i32),
        2 => Ok(proto::AddressFamily::Ipv6Unicast as i32),
        _ => Ok(proto::AddressFamily::Unspecified as i32),
    }
}

async fn routes_table(
    State(state): State<AppState>,
    Path(table): Path<String>,
) -> Result<Json<Value>, HttpError> {
    let family = table_address_family(&list_neighbors(&state).await?, &state.identities, &table)?;
    for _ in 0..CAPTURE_ATTEMPTS {
        let mut client = proto::rib_service_client::RibServiceClient::new(state.upstream.clone());
        let mut routes = TableRouteSet::default();
        let mut retry = false;
        for best in [false, true] {
            let mut page_token = String::new();
            let mut seen_tokens = HashSet::new();
            let mut expected_total = None;
            let mut rows_seen = 0_u64;
            loop {
                let request = proto::ListRoutesRequest {
                    neighbor_address: String::new(),
                    afi_safi: family,
                    page_size: 1000,
                    page_token: page_token.clone(),
                    ..Default::default()
                };
                let response = match if best {
                    client.list_best_routes(request).await
                } else {
                    client.list_received_routes(request).await
                } {
                    Ok(response) => response.into_inner(),
                    Err(error) if error.code() == tonic::Code::Aborted => {
                        retry = true;
                        break;
                    }
                    Err(error) => {
                        return Err(bad_gateway(
                            if best {
                                "ListBestRoutes"
                            } else {
                                "ListReceivedRoutes"
                            },
                            &error,
                        ));
                    }
                };
                match routes.check_version(response.page_version.as_ref()) {
                    Ok(()) => {}
                    Err(CaptureError::Retry) => {
                        retry = true;
                        break;
                    }
                    Err(CaptureError::Fatal(error)) => return Err(error),
                }
                if expected_total.is_some_and(|total| total != response.total_count) {
                    return Err(invalid_table_snapshot());
                }
                if expected_total.is_none() {
                    enforce_max(response.total_count, state.max_routes)?;
                    expected_total = Some(response.total_count);
                }
                rows_seen += response.routes.len() as u64;
                if rows_seen > response.total_count {
                    return Err(invalid_table_snapshot());
                }
                for route in response.routes {
                    routes.insert(route, best, family, state.max_routes)?;
                }
                if response.next_page_token.is_empty() {
                    if rows_seen != response.total_count {
                        return Err(invalid_table_snapshot());
                    }
                    break;
                }
                if rows_seen == response.total_count
                    || !seen_tokens.insert(response.next_page_token.clone())
                {
                    return Err(invalid_table_snapshot());
                }
                page_token = response.next_page_token;
            }
            if retry {
                break;
            }
        }
        if !retry {
            return Ok(Json(routes.body(&state.identities, state.max_routes)));
        }
    }
    Err(invalid_table_snapshot())
}

async fn routes_export(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, HttpError> {
    let peer = state.identities.resolve(&id)?;
    let best = best_route_keys(&state, None).await?;
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
        routes.extend(resp.routes.iter().map(|route| {
            route_to_birdwatcher_with_primary(
                route,
                &state.identities,
                best.contains(&route_key(route)),
            )
        }));
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
// GET /route/{prefix}/protocol/{id} — received-route candidates, longest match
// GET /route/{prefix}/export/{id}   — advertised-route candidates, longest match
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExactRouteSource {
    Received,
    Advertised,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct ExactPrefix {
    address: IpAddr,
    length: u32,
}

impl ExactPrefix {
    /// `Ok(Some)` is a network-aligned prefix. `Ok(None)` is a well-formed
    /// address/length whose host bits are set: BIRD rejects that literal in
    /// `show route for`, so Bird's Eye answers HTTP 200 with no routes and
    /// the lookup handlers do the same. Anything else is HTTP 400, matching
    /// Bird's Eye's own parameter validation.
    fn parse(value: &str) -> Result<Option<Self>, HttpError> {
        let invalid = || json_error(StatusCode::BAD_REQUEST, "Invalid route prefix");
        let (address, length) = value.split_once('/').ok_or_else(invalid)?;
        if address.is_empty() || length.is_empty() || length.contains('/') {
            return Err(invalid());
        }
        let address: IpAddr = address.parse().map_err(|_| invalid())?;
        let length: u32 = length.parse().map_err(|_| invalid())?;
        let width = if address.is_ipv4() { 32 } else { 128 };
        if length > width {
            return Err(invalid());
        }
        Ok(network_aligned(address, length).then_some(Self { address, length }))
    }

    fn from_route(address: &str, length: u32) -> Option<Self> {
        let address: IpAddr = address.parse().ok()?;
        let width = if address.is_ipv4() { 32 } else { 128 };
        (length <= width && network_aligned(address, length)).then_some(Self { address, length })
    }

    fn family(self) -> i32 {
        match self.address {
            IpAddr::V4(_) => proto::AddressFamily::Ipv4Unicast as i32,
            IpAddr::V6(_) => proto::AddressFamily::Ipv6Unicast as i32,
        }
    }

    fn covers(self, query: Self) -> bool {
        if self.length > query.length {
            return false;
        }
        match (self.address, query.address) {
            (IpAddr::V4(prefix), IpAddr::V4(address)) => {
                let shift = 32 - self.length;
                u32::from(prefix).checked_shr(shift).unwrap_or(0)
                    == u32::from(address).checked_shr(shift).unwrap_or(0)
            }
            (IpAddr::V6(prefix), IpAddr::V6(address)) => {
                let shift = 128 - self.length;
                u128::from(prefix).checked_shr(shift).unwrap_or(0)
                    == u128::from(address).checked_shr(shift).unwrap_or(0)
            }
            _ => false,
        }
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

/// Most-specific network among `routes` that covers `query` — the selection
/// Bird's Eye's `show route for` makes when the query has no exact entry.
/// The RPC surface offers exact and longer-prefix filters only, so covering
/// prefixes come from a linear scan over one member's paged view.
fn longest_match(routes: &[proto::Route], query: ExactPrefix) -> Option<ExactPrefix> {
    routes
        .iter()
        .filter_map(|route| ExactPrefix::from_route(&route.prefix, route.prefix_length))
        .filter(|network| network.covers(query))
        .max_by_key(|network| network.length)
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
        afi_safi: prefix.family(),
        page_size: 1000,
        page_token,
        prefix_filter,
        prefix_filter_length: prefix.length,
        longer_prefixes: false,
        ..Default::default()
    }
}

fn view_route_request(
    peer: IpAddr,
    prefix: ExactPrefix,
    page_token: String,
    remaining: u64,
) -> proto::ListRoutesRequest {
    proto::ListRoutesRequest {
        neighbor_address: peer.to_string(),
        afi_safi: prefix.family(),
        page_size: remaining.min(1000) as u32,
        page_token,
        ..Default::default()
    }
}

fn lpm_scan_limit(max_scan_routes: u64) -> HttpError {
    json_error(
        StatusCode::FORBIDDEN,
        format!(
            "Longest-match scan limit reached before the peer view was exhausted ({max_scan_routes}/{max_scan_routes} routes)"
        ),
    )
}

fn append_view_page(
    view: &mut Vec<proto::Route>,
    page: Vec<proto::Route>,
    next_page_token: &str,
    max_scan_routes: u64,
) -> Result<(), HttpError> {
    let remaining = max_scan_routes.saturating_sub(view.len() as u64);
    if page.len() as u64 > remaining {
        return Err(lpm_scan_limit(max_scan_routes));
    }
    let accumulated = view.len() as u64 + page.len() as u64;
    if accumulated == max_scan_routes && !next_page_token.is_empty() {
        return Err(lpm_scan_limit(max_scan_routes));
    }
    view.extend(page);
    Ok(())
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

/// One member's complete received or advertised view, paged unfiltered.
/// Backs the longest-match fallback of the exact-route lookups.
async fn view_routes(
    client: &mut proto::rib_service_client::RibServiceClient<Upstream>,
    peer: IpAddr,
    prefix: ExactPrefix,
    source: ExactRouteSource,
    max_scan_routes: u64,
) -> Result<Vec<proto::Route>, HttpError> {
    let mut view = Vec::new();
    let mut page_token = String::new();
    loop {
        let remaining = max_scan_routes.saturating_sub(view.len() as u64);
        let request = view_route_request(peer, prefix, page_token, remaining);
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
        let next_page_token = response.next_page_token;
        append_view_page(
            &mut view,
            response.routes,
            &next_page_token,
            max_scan_routes,
        )?;
        if next_page_token.is_empty() {
            break;
        }
        page_token = next_page_token;
    }
    Ok(view)
}

async fn serve_exact_route(
    state: &AppState,
    raw_prefix: &str,
    id: &str,
    source: ExactRouteSource,
) -> Result<Json<Value>, HttpError> {
    let prefix = ExactPrefix::parse(raw_prefix)?;
    let peer = state.identities.resolve(id)?;
    let Some(prefix) = prefix else {
        return Ok(Json(empty_routes_body(state.max_routes)));
    };
    if source == ExactRouteSource::Received {
        return serve_exact_received_route(state, peer, prefix).await;
    }
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

    // Bird's Eye's `show route for` is longest-match: with no exact entry it
    // answers with the view's most-specific covering prefix, and with no
    // covering prefix it answers with no routes. The cap applies to the one
    // matched prefix's candidates, not to the scanned view.
    let mut matched = prefix;
    if routes.is_empty() {
        let view =
            view_routes(&mut client, peer, prefix, source, state.max_lpm_scan_routes).await?;
        if let Some(covering) = longest_match(&view, prefix) {
            routes = view
                .into_iter()
                .filter(|route| {
                    ExactPrefix::from_route(&route.prefix, route.prefix_length) == Some(covering)
                })
                .collect();
            enforce_max(routes.len() as u64, state.max_routes)?;
            matched = covering;
        }
    }

    let best = best_route_keys(state, Some(matched)).await?;
    Ok(Json(serde_json::json!({
        "api": api_block(state.max_routes),
        "routes": routes
            .iter()
            .map(|route| {
                route_to_birdwatcher_with_primary(
                    route,
                    &state.identities,
                    best.contains(&route_key(route)),
                )
            })
            .collect::<Vec<_>>(),
    })))
}

/// One page of a version-checked received-route capture. `Retry` means the
/// upstream generation moved under the capture, which starts over.
async fn received_routes_page(
    client: &mut proto::rib_service_client::RibServiceClient<Upstream>,
    request: proto::ListRoutesRequest,
    version: &mut Option<RouteCaptureVersion>,
) -> Result<proto::ListRoutesResponse, CaptureError> {
    let response = client
        .list_received_routes(request)
        .await
        .map_err(|error| capture_error("ListReceivedRoutes", &error))?
        .into_inner();
    capture_version(version, response.page_version.as_ref())?;
    Ok(response)
}

async fn serve_exact_received_route(
    state: &AppState,
    peer: IpAddr,
    prefix: ExactPrefix,
) -> Result<Json<Value>, HttpError> {
    for _ in 0..CAPTURE_ATTEMPTS {
        let mut client = proto::rib_service_client::RibServiceClient::new(state.upstream.clone());
        let mut routes = Vec::new();
        let mut page_token = String::new();
        let mut received_version = None;
        let mut retry = false;
        loop {
            let request = exact_route_request(peer, prefix, page_token, ExactRouteSource::Received);
            let response =
                match received_routes_page(&mut client, request, &mut received_version).await {
                    Ok(response) => response,
                    Err(CaptureError::Retry) => {
                        retry = true;
                        break;
                    }
                    Err(CaptureError::Fatal(error)) => return Err(error),
                };
            append_exact_routes(&mut routes, response.routes, prefix, state.max_routes)?;
            if response.next_page_token.is_empty() {
                break;
            }
            page_token = response.next_page_token;
        }
        if retry {
            continue;
        }

        let mut matched = prefix;
        if routes.is_empty() {
            let mut view = Vec::new();
            page_token = String::new();
            loop {
                let remaining = state.max_lpm_scan_routes.saturating_sub(view.len() as u64);
                let request = view_route_request(peer, prefix, page_token, remaining);
                let response =
                    match received_routes_page(&mut client, request, &mut received_version).await {
                        Ok(response) => response,
                        Err(CaptureError::Retry) => {
                            retry = true;
                            break;
                        }
                        Err(CaptureError::Fatal(error)) => return Err(error),
                    };
                let next = response.next_page_token;
                append_view_page(&mut view, response.routes, &next, state.max_lpm_scan_routes)?;
                if next.is_empty() {
                    break;
                }
                page_token = next;
            }
            if retry {
                continue;
            }
            if let Some(covering) = longest_match(&view, prefix) {
                routes = view
                    .into_iter()
                    .filter(|route| {
                        ExactPrefix::from_route(&route.prefix, route.prefix_length)
                            == Some(covering)
                    })
                    .collect();
                enforce_max(routes.len() as u64, state.max_routes)?;
                matched = covering;
            }
        }

        let (best, best_version) = match capture_best_route_keys(state, Some(matched)).await {
            Ok(capture) => capture,
            Err(CaptureError::Retry) => continue,
            Err(CaptureError::Fatal(error)) => return Err(error),
        };
        if received_version != Some(best_version) {
            continue;
        }
        return Ok(Json(serde_json::json!({
            "api": api_block(state.max_routes),
            "routes": routes.iter().map(|route| route_to_birdwatcher_with_primary(
                route,
                &state.identities,
                best.contains(&route_key(route)),
            )).collect::<Vec<_>>(),
        })));
    }
    Err(invalid_table_snapshot())
}

// ---------------------------------------------------------------------------
// GET /route/{prefix}/table/{table} — IXP Manager global LPM table search
//                                  → RibService.LookupBestPath
// ---------------------------------------------------------------------------

async fn route_table(
    State(state): State<AppState>,
    Path((prefix, table)): Path<(String, String)>,
) -> Result<Json<Value>, HttpError> {
    let prefix = ExactPrefix::parse(&prefix)?;
    let (_, tables) = symbol_names(list_neighbors(&state).await?, &state.identities)?;
    if tables.binary_search(&table).is_err() {
        return Err(json_error(StatusCode::NOT_FOUND, "Table not found"));
    }
    let Some(prefix) = prefix else {
        return Ok(Json(empty_routes_body(state.max_routes)));
    };

    let mut client = proto::rib_service_client::RibServiceClient::new(state.upstream.clone());
    let response = match client
        .lookup_best_path(proto::LookupBestPathRequest {
            prefix: prefix.address.to_string(),
            prefix_length: prefix.length,
        })
        .await
    {
        Ok(response) => response.into_inner(),
        Err(status) if status.code() == tonic::Code::NotFound => {
            return Ok(Json(empty_routes_body(state.max_routes)));
        }
        Err(status) => return Err(bad_gateway("LookupBestPath", &status)),
    };
    Ok(Json(table_lookup_body(
        &response,
        prefix,
        &state.identities,
        state.max_routes,
    )?))
}

fn table_lookup_body(
    response: &proto::ExplainBestPathResponse,
    query: ExactPrefix,
    identities: &IdentityResolver,
    max_routes: u64,
) -> Result<Value, HttpError> {
    let malformed = || {
        error!("LookupBestPath returned an incomplete or inconsistent route set");
        json_error(
            StatusCode::BAD_GATEWAY,
            "Upstream daemon returned an invalid route response",
        )
    };
    let matched =
        ExactPrefix::from_route(&response.prefix, response.prefix_length).ok_or_else(malformed)?;
    if !matched.covers(query) {
        return Err(malformed());
    }
    let best = response.best_route.as_ref().ok_or_else(malformed)?;
    let mut identities_seen = HashSet::new();
    let mut routes = Vec::with_capacity(response.candidates.len() + 1);
    let valid_route = |route: &proto::Route| {
        ExactPrefix::from_route(&route.prefix, route.prefix_length) == Some(matched)
    };
    if !valid_route(best) || !identities_seen.insert((best.peer_address.as_str(), best.path_id)) {
        return Err(malformed());
    }
    routes.push(best);
    for candidate in &response.candidates {
        let route = candidate.route.as_ref().ok_or_else(malformed)?;
        if !valid_route(route)
            || !identities_seen.insert((route.peer_address.as_str(), route.path_id))
        {
            return Err(malformed());
        }
        routes.push(route);
    }
    enforce_max(routes.len() as u64, max_routes)?;
    Ok(serde_json::json!({
        "api": api_block(max_routes),
        "routes": routes
            .into_iter()
            .enumerate()
            .map(|(index, route)| route_to_birdwatcher_with_primary(route, identities, index == 0))
            .collect::<Vec<_>>(),
    }))
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
                "retention": retention_metadata(None),
            })));
        }
        Err(e) => return Err(bad_gateway("ListRejectedRoutes", &e)),
    };
    Ok(Json(filtered_routes_body(
        &resp,
        peer_addr,
        &state.identities,
        state.arouteserver_reject_communities.as_deref(),
    )))
}

// ---------------------------------------------------------------------------
// GET /routes/table/{table}/filtered  — Alice-LG single-table routes-store
//   dump: every retained reject of every peer aliased to the table
//   →  one NeighborService.ListNeighbors snapshot, one
//      PolicyService.ListRejectedRoutes per peer, then a second
//      ListNeighbors snapshot for an inventory-stability retry
// ---------------------------------------------------------------------------

/// The per-table neighbor facts checked by the inventory-stability retry:
/// membership, session state, staleness, and the actor-authoritative retained count.
type TableRejectInventory = Vec<(IpAddr, i32, bool, Option<u64>)>;

fn table_reject_inventory(
    neighbors: &[proto::NeighborState],
    identities: &IdentityResolver,
    table: &str,
) -> Result<TableRejectInventory, HttpError> {
    let mut inventory = Vec::new();
    for neighbor in neighbors {
        let config = neighbor.config.clone().unwrap_or_default();
        let peer = parse_upstream_peer_address(&config.address)?;
        if identities.identity(peer).table == table {
            inventory.push((
                peer,
                neighbor.state,
                neighbor.stale,
                neighbor.rejected_routes_retained,
            ));
        }
    }
    Ok(inventory)
}

async fn routes_table_filtered(
    State(state): State<AppState>,
    Path(table): Path<String>,
) -> Result<Json<Value>, HttpError> {
    let mut policy = proto::policy_service_client::PolicyServiceClient::new(state.upstream.clone());
    for _ in 0..CAPTURE_ATTEMPTS {
        let neighbors = list_neighbors(&state).await?;
        let family = table_address_family(&neighbors, &state.identities, &table)?;
        let inventory = table_reject_inventory(&neighbors, &state.identities, &table)?;
        let mut stores = Vec::with_capacity(inventory.len());
        for (peer, ..) in &inventory {
            let response = match policy
                .list_rejected_routes(proto::ListRejectedRoutesRequest {
                    peer_address: peer.to_string(),
                })
                .await
            {
                Ok(response) => Some(response.into_inner()),
                // No live session: nothing is retained, nothing is served.
                Err(status) if status.code() == tonic::Code::NotFound => None,
                Err(error) => return Err(bad_gateway("ListRejectedRoutes", &error)),
            };
            stores.push((*peer, response));
        }
        // The session-local reject stores carry no version. Retry when the
        // surrounding inventory changes; this is not a store-content fence.
        let after =
            table_reject_inventory(&list_neighbors(&state).await?, &state.identities, &table)?;
        if after == inventory {
            return Ok(Json(filtered_table_body(
                &stores,
                family,
                &state.identities,
                state.arouteserver_reject_communities.as_deref(),
                state.max_routes,
            )));
        }
    }
    Err(invalid_table_snapshot())
}

/// One table-wide retention envelope in the per-peer shape: capacities
/// and evictions sum over the live sessions, `enabled` is true when any
/// session retains, and an older daemon's absent eviction count keeps the
/// whole view's completeness unknown. `None` when no session is live.
fn aggregate_retention(
    stores: &[(IpAddr, Option<proto::ListRejectedRoutesResponse>)],
) -> Option<proto::ListRejectedRoutesResponse> {
    let mut aggregate: Option<proto::ListRejectedRoutesResponse> = None;
    for response in stores.iter().filter_map(|(_, response)| response.as_ref()) {
        let total = aggregate.get_or_insert_with(|| proto::ListRejectedRoutesResponse {
            evictions_since_reset: Some(0),
            ..Default::default()
        });
        total.retention_enabled |= response.retention_enabled;
        total.capacity = total.capacity.saturating_add(response.capacity);
        total.evictions_since_reset =
            match (total.evictions_since_reset, response.evictions_since_reset) {
                (Some(sum), Some(count)) => Some(sum.saturating_add(count)),
                _ => None,
            };
    }
    aggregate
}

/// Every retained reject of every live session in the table, rendered
/// exactly like the peer's own filtered view (alias, `ARouteServer`
/// presentation, synthesized reason) and scoped to the table's family.
fn filtered_table_body(
    stores: &[(IpAddr, Option<proto::ListRejectedRoutesResponse>)],
    family: i32,
    identities: &IdentityResolver,
    arouteserver: Option<&ArsRejectCommunities>,
    max_routes: u64,
) -> Value {
    let mut routes = Vec::new();
    for (peer, response) in stores {
        let Some(response) = response
            .as_ref()
            .filter(|response| response.retention_enabled)
        else {
            continue;
        };
        let arouteserver = arouteserver.filter(|config| config.peers.contains(peer));
        routes.extend(
            response
                .routes
                .iter()
                .filter(|route| {
                    family == proto::AddressFamily::Unspecified as i32 || route.afi_safi == family
                })
                .map(|route| rejected_route_to_birdwatcher(route, *peer, identities, arouteserver)),
        );
    }
    let aggregate = aggregate_retention(stores);
    serde_json::json!({
        "api": api_block(
            aggregate
                .as_ref()
                .map_or(max_routes, |total| u64::from(total.capacity))
        ),
        "routes": routes,
        "retention": retention_metadata(aggregate.as_ref()),
    })
}

const IXP_MANAGER_REJECT_FUNCTION: u64 = 1101;

/// IXP Manager v7.4's member-facing filtered-prefix query, with Bird's Eye
/// wildcard semantics for every ordinary pair: the daemon's own rejection
/// namespace `({daemon ASN}, 1101)` serves the session's retained rejects,
/// and any other `(x, y)` returns the member's accepted routes carrying a
/// large community `(x, y, *)`.
async fn routes_protocol_large_community_wild_xy(
    State(state): State<AppState>,
    Path((id, x, y)): Path<(String, u64, u64)>,
) -> Result<Json<Value>, HttpError> {
    let peer = state.identities.resolve(&id)?;
    let mut global = proto::global_service_client::GlobalServiceClient::new(state.upstream.clone());
    let daemon_asn = u64::from(
        global
            .get_global(proto::GetGlobalRequest {})
            .await
            .map_err(|error| bad_gateway("GetGlobal", &error))?
            .into_inner()
            .asn,
    );
    // Hybrid dispatch: only the daemon's own rejection namespace reads the
    // retained rejects; every other pair is an accepted-route wildcard scan.
    if !ixp_manager_reason_namespace_matches(daemon_asn, x, y) {
        return serve_routes_for_peer(&state, peer, Some((x, y))).await;
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
            return Ok(Json(empty_filtered_routes_body(state.max_routes)));
        }
        Err(error) => return Err(bad_gateway("ListRejectedRoutes", &error)),
    };
    let routes = response
        .routes
        .iter()
        .map(|route| {
            ixp_manager_rejected_route_to_birdwatcher(route, peer, &state.identities, daemon_asn)
        })
        .collect::<Vec<_>>();
    Ok(Json(serde_json::json!({
        "api": api_block(u64::from(response.capacity)),
        "routes": routes,
        "retention": retention_metadata(Some(&response)),
    })))
}

fn empty_routes_body(max_routes: u64) -> Value {
    serde_json::json!({ "api": api_block(max_routes), "routes": [] })
}

fn empty_filtered_routes_body(max_routes: u64) -> Value {
    serde_json::json!({
        "api": api_block(max_routes),
        "routes": [],
        "retention": retention_metadata(None),
    })
}

fn retention_metadata(resp: Option<&proto::ListRejectedRoutesResponse>) -> Value {
    let evictions = resp.and_then(|response| response.evictions_since_reset);
    serde_json::json!({
        "enabled": resp.map(|response| response.retention_enabled),
        "capacity": resp.map(|response| response.capacity),
        "evictions_since_reset": evictions,
        "may_be_incomplete": evictions.map(|count| count > 0),
    })
}

fn ixp_manager_reason_namespace_matches(daemon_asn: u64, x: u64, y: u64) -> bool {
    x == daemon_asn && y == IXP_MANAGER_REJECT_FUNCTION
}

/// True when the route carries a large community `(x, y, *)` — the Bird's
/// Eye `lc-zwild` wildcard. gRPC encodes each large community as
/// `"global_admin:data1:data2"`; anything else never matches.
fn carries_large_community(route: &proto::Route, x: u64, y: u64) -> bool {
    route.large_communities.iter().any(|lc| {
        let parts: Vec<u64> = lc.split(':').filter_map(|p| p.parse().ok()).collect();
        parts.len() == 3 && parts[0] == x && parts[1] == y
    })
}

/// Build the filtered-view response body from a `ListRejectedRoutes`
/// reply. The store is bounded (`[policy.reject_retention]` capacity,
/// default 1024) and the RPC is unpaged — one call returns everything.
fn filtered_routes_body(
    resp: &proto::ListRejectedRoutesResponse,
    peer: IpAddr,
    identities: &IdentityResolver,
    arouteserver: Option<&ArsRejectCommunities>,
) -> Value {
    let arouteserver = arouteserver.filter(|config| config.peers.contains(&peer));
    if !resp.retention_enabled {
        info!(
            peer = %peer,
            "reject retention disabled ([policy.reject_retention]); \
             serving empty filtered view"
        );
    }
    let routes: Vec<Value> = if resp.retention_enabled {
        resp.routes
            .iter()
            .map(|r| rejected_route_to_birdwatcher(r, peer, identities, arouteserver))
            .collect()
    } else {
        Vec::new()
    };
    serde_json::json!({
        "api": api_block(u64::from(resp.capacity)),
        "routes": routes,
        "retention": retention_metadata(Some(resp)),
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
    arouteserver: Option<&ArsRejectCommunities>,
) -> Value {
    render_rejected_route(
        route,
        peer,
        identities,
        reject_reason_community(&route.reason),
        None,
        arouteserver,
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
        None,
    )
}

fn arouteserver_reject_cause(route: &proto::RejectedRoute) -> Option<u8> {
    let detail = route.reason_detail.as_str();
    let late_cause = || {
        !route.as_path.contains('{')
            && !route.communities.contains(&0xffff_029a)
            && match route.prefix.parse::<IpAddr>() {
                Ok(IpAddr::V4(_)) => route.prefix_length <= 32,
                Ok(IpAddr::V6(address)) => {
                    (3..=128).contains(&route.prefix_length)
                        && address.segments()[0] & 0xe000 == 0x2000
                }
                Err(_) => false,
            }
    };
    match (route.reason.as_str(), detail) {
        ("policy_reject", "rs-hygiene:reject-long-as-path") => Some(1),
        ("next_hop_ownership", _) => Some(5),
        ("policy_reject", "rs-hygiene:reject-black-list-prefix") if late_cause() => Some(3),
        ("policy_reject", detail)
            if late_cause() && detail.ends_with(":reject-irrdb-origin-as-filtered") =>
        {
            Some(9)
        }
        ("policy_reject", detail)
            if late_cause() && detail.ends_with(":reject-irrdb-prefix-filtered") =>
        {
            Some(12)
        }
        _ => None,
    }
}

fn apply_ars_family(values: &mut Vec<Vec<u64>>, family: &ArsCommunityFamily, cause: Option<u8>) {
    values.retain(|value| {
        family
            .dynamic
            .as_ref()
            .is_none_or(|prefix| !value.starts_with(prefix))
            && !family.cause_map.values().any(|mapped| value == mapped)
    });
    if let Some(prefix) = &family.dynamic {
        for suffix in [Some(0), cause.map(u64::from)].into_iter().flatten() {
            values.push(prefix.iter().copied().chain([suffix]).collect());
        }
    }
    if let Some(value) = cause.and_then(|cause| family.cause_map.get(&cause)) {
        values.push(value.clone());
    }
}

fn stable_dedupe<T: Clone + Eq + std::hash::Hash>(values: &mut Vec<T>) {
    let mut seen = HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

fn ixp_manager_reject_reason_id(route: &proto::RejectedRoute) -> u64 {
    match (route.reason.as_str(), route.reason_detail.as_str()) {
        ("policy_reject", "ixp-manager-hygiene:reject-too-specific") => 1,
        ("policy_reject", "reject-special-purpose:reject-non-global") => 3,
        ("policy_reject", "ixp-manager-hygiene:reject-as-path-too-long") => 5,
        ("policy_reject", "ixp-manager-hygiene:reject-as-path-too-short") => 6,
        ("treat_as_withdraw", "aspa_first_as_mismatch") if route.as_path.is_empty() => 6,
        ("treat_as_withdraw", "aspa_first_as_mismatch") => 7,
        ("policy_reject", detail)
            if ixp_manager_client_term(detail, "reject-first-as-not-peer-as") =>
        {
            7
        }
        ("next_hop_ownership", _) => 8,
        ("policy_reject", detail)
            if ixp_manager_client_term(detail, "reject-irrdb-prefix-filtered") =>
        {
            9
        }
        ("policy_reject", detail)
            if ixp_manager_client_term(detail, "reject-irrdb-origin-as-filtered") =>
        {
            10
        }
        ("policy_reject", "ixp-manager-hygiene:reject-rpki-invalid")
            if route.rpki_validation == "invalid" =>
        {
            13
        }
        ("policy_reject", "ixp-manager-hygiene:reject-transit-leak") => 14,
        _ => 0,
    }
}

fn ixp_manager_client_term(detail: &str, expected: &str) -> bool {
    detail.rsplit_once(':').is_some_and(|(policy, term)| {
        term == expected
            && policy
                .strip_prefix("client-")
                .is_some_and(|id| !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit()))
    })
}

fn render_rejected_route(
    route: &proto::RejectedRoute,
    peer: IpAddr,
    identities: &IdentityResolver,
    reason_community: [u64; 3],
    reserved_namespace: Option<[u64; 2]>,
    arouteserver: Option<&ArsRejectCommunities>,
) -> Value {
    let mut communities: Vec<Vec<u64>> = route
        .communities
        .iter()
        .map(|c| vec![u64::from((*c >> 16) & 0xffff), u64::from(*c & 0xffff)])
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
    if let Some(config) = arouteserver {
        let cause = arouteserver_reject_cause(route);
        if let Some(family) = &config.std {
            apply_ars_family(&mut communities, family, cause);
        }
        if let Some(family) = &config.lrg {
            apply_ars_family(&mut large_communities, family, cause);
        }
        stable_dedupe(&mut communities);
        stable_dedupe(&mut large_communities);
    } else {
        large_communities.push(reason_community.to_vec());
    }

    // The retained AS_PATH is a lossless display string ("65001 {65002
    // 65003}"); birdwatcher wants an ASN array, so flatten it (AS_SET
    // members included) best-effort. Elements are strings, the same
    // Bird's Eye shape the accepted-route views emit.
    let as_path: Vec<String> = route
        .as_path
        .split(|c: char| !c.is_ascii_digit())
        .filter(|p| !p.is_empty())
        .filter_map(|p| p.parse::<u32>().ok())
        .map(|asn| asn.to_string())
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
        "type": ["BGP", "univ"],
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
            // Retention keeps no LOCAL_PREF/MED: render the effective
            // default local preference (the same rule as the accepted
            // views on a route without the attribute) and omit `med`,
            // matching BIRD's absence semantics.
            "local_pref": "100",
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
    // only best routes are export candidates) — diffed page by page so
    // the request retains only the suppressed candidates (capped at
    // `max_routes`, like every other route view), never the whole
    // Loc-RIB with its attribute payloads.
    let mut excluded = advertised;
    let mut candidates: Vec<proto::Route> = Vec::new();
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
        retain_noexport_page(
            &mut candidates,
            &mut excluded,
            resp.routes,
            state.max_routes,
        )?;
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
    for route in &candidates {
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

/// Retain the not-exported candidates of one Loc-RIB best page: routes
/// whose prefix is absent from `excluded`, which starts as the peer's
/// advertised prefix set and grows with every retained prefix so the
/// candidates stay deduped per prefix (multipath / Add-Path can put
/// several best paths on one prefix). The generic cap applies to the
/// retained rows before they are kept, so an oversized view fails on the
/// page that crosses the cap instead of after the whole Loc-RIB is paged.
fn retain_noexport_page(
    candidates: &mut Vec<proto::Route>,
    excluded: &mut HashSet<(String, u32)>,
    page: Vec<proto::Route>,
    max_routes: u64,
) -> Result<(), HttpError> {
    let retained = page
        .into_iter()
        .filter(|route| excluded.insert((route.prefix.clone(), route.prefix_length)))
        .collect::<Vec<_>>();
    let accumulated = (candidates.len() as u64).saturating_add(retained.len() as u64);
    enforce_max(accumulated, max_routes)?;
    candidates.extend(retained);
    Ok(())
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

fn format_connection(state: i32) -> &'static str {
    match proto::SessionState::try_from(state) {
        Ok(proto::SessionState::Connect) => " Connect",
        Ok(proto::SessionState::Active) => " Active",
        Ok(proto::SessionState::OpenSent) => " OpenSent",
        Ok(proto::SessionState::OpenConfirm) => " OpenConfirm",
        Ok(proto::SessionState::Established) => " Established",
        _ => "",
    }
}

/// Convert a gRPC `Route` to the birdwatcher route JSON shape.
///
/// Alice-LG reads: `network`, `gateway`, `from_protocol`, `interface`,
/// `metric`, `age`, `type`, `primary`, `learnt_from`, and `bgp` sub-object
/// with `origin`, `as_path`, `next_hop`, `local_pref`, `med`, `communities`,
/// `large_communities`, `ext_communities`.
///
/// `primary` reports what the response itself carries (`Route.best`);
/// views whose upstream scope never marks best-ness pass an explicit
/// value from a Loc-RIB lookup instead.
fn route_to_birdwatcher(route: &proto::Route, identities: &IdentityResolver) -> Value {
    route_to_birdwatcher_with_primary(route, identities, route.best)
}

fn route_to_birdwatcher_with_primary(
    route: &proto::Route,
    identities: &IdentityResolver,
    primary: bool,
) -> Value {
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

    let ext_communities: Vec<Value> = route
        .extended_communities
        .iter()
        .copied()
        .map(extended_community_to_birdwatcher)
        .collect();

    let from_protocol = route.peer_address.parse().map_or_else(
        |_| format!("bgp_{}", route.peer_address).replace(':', "_"),
        |peer| identities.identity(peer).protocol,
    );

    // Receive wall time, same source and format as the in-daemon
    // server's `age`. 0 (unknown) renders as the empty string, which
    // Alice-LG parses as zero time (benign).
    let age = if route.received_at_epoch_seconds > 0 {
        format_epoch_secs(route.received_at_epoch_seconds)
    } else {
        String::new()
    };

    // Bird's Eye splits BIRD's `BGP.as_path` text, so path elements are
    // strings, and BIRD assigns its default local preference at import,
    // so a (string) `local_pref` prints for every route — the gRPC field
    // carries the same effective value (default 100 when the attribute
    // is absent). Both shapes are pinned by the populated oracle leg.
    let as_path: Vec<String> = route.as_path.iter().map(u32::to_string).collect();
    let mut bgp = serde_json::json!({
        "origin": origin,
        "as_path": as_path,
        "next_hop": route.next_hop,
        "local_pref": route.local_pref.to_string(),
        "communities": communities,
        "large_communities": large_communities,
        "ext_communities": ext_communities,
    });
    // BIRD omits `BGP.med` entirely when the route carries no MED
    // attribute; mirror that presence semantics from the wire-presence
    // field (the bare `med` encodes absent as 0).
    if let Some(med) = route.med_attr {
        bgp["med"] = med.into();
    }
    // Bird's Eye prints AGGREGATOR as "<address> AS<asn>" and
    // ATOMIC_AGGREGATE as a bare key (empty value), each only when the
    // route carries the attribute; mirror that presence semantics.
    if let Some(aggregator) = &route.aggregator {
        bgp["aggregator"] = Value::String(format!("{} AS{}", aggregator.router_id, aggregator.asn));
    }
    if route.atomic_aggregate {
        bgp["atomic_aggr"] = Value::String(String::new());
    }

    serde_json::json!({
        "network": format!("{}/{}", route.prefix, route.prefix_length),
        "gateway": route.next_hop,
        "from_protocol": from_protocol,
        "interface": "",
        "metric": 0,
        "age": age,
        // BIRD 2's `Type: BGP univ` pair, as Bird's Eye splits it.
        "type": ["BGP", "univ"],
        "primary": primary,
        "learnt_from": route.peer_address,
        "bgp": bgp
    })
}

/// Render one extended community as birdwatcher does: three strings,
/// `[kind, key, value]`, captured from BIRD's `BGP.ext_community` text
/// (birdwatcher `bird/parser.go` `parseRoutesExtendedCommunities`, which
/// Alice-LG's `parseExtBgpCommunities` reads back with `strconv.Atoi` on
/// the two values). The text itself follows BIRD 2.0.12 `ec_format`
/// (`nest/a-set.c`): the kind is `rt` (subtype 0x02) or `ro` (subtype
/// 0x03) for transitive two-octet-AS, IPv4-address, and four-octet-AS
/// communities, any other subtype prints as `unknown 0x<type><subtype>`,
/// and the key/value split follows the type byte (RFC 4360 §3.1/§3.2,
/// RFC 5668). Every other type byte, including the non-transitive
/// opaque family, renders as `generic` with the two 32-bit halves in hex.
fn extended_community_to_birdwatcher(raw: u64) -> Value {
    let type_field = (raw >> 48) as u32;
    let kind = match type_field & 0xf0ff {
        0x0002 => "rt".to_string(),
        0x0003 => "ro".to_string(),
        _ => format!("unknown {type_field:#x}"),
    };
    let (key, value) = match raw >> 56 {
        0x00 | 0x40 => (
            ((raw >> 32) & 0xffff).to_string(),
            (raw & 0xffff_ffff).to_string(),
        ),
        0x01 | 0x41 => (
            Ipv4Addr::from(((raw >> 16) & 0xffff_ffff) as u32).to_string(),
            (raw & 0xffff).to_string(),
        ),
        0x02 | 0x42 => (
            ((raw >> 16) & 0xffff_ffff).to_string(),
            (raw & 0xffff).to_string(),
        ),
        _ => {
            return serde_json::json!([
                "generic",
                format!("{:#x}", (raw >> 32) as u32),
                format!("{:#x}", raw & 0xffff_ffff),
            ]);
        }
    };
    serde_json::json!([kind, key, value])
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

    /// `asn:value` as the RFC 1997 32-bit community.
    fn community(asn: u16, value: u16) -> u32 {
        (u32::from(asn) << 16) | u32::from(value)
    }

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
    fn protocol_inventory_refuses_absent_or_stale_retained_count() {
        let mut neighbor = proto::NeighborState::default();
        for (count, stale) in [(None, false), (Some(0), true)] {
            neighbor.rejected_routes_retained = count;
            neighbor.stale = stale;
            let (status, Json(body)) = retained_reject_count(&neighbor).unwrap_err();
            assert_eq!(status, StatusCode::BAD_GATEWAY);
            assert_eq!(
                body["message"],
                "Upstream daemon returned incomplete neighbor state"
            );
        }
        neighbor.stale = false;
        neighbor.rejected_routes_retained = Some(9);
        assert_eq!(retained_reject_count(&neighbor).unwrap(), 9);
    }

    #[tokio::test]
    async fn protocol_detail_preserves_old_daemon_and_non_session_absence() {
        let store = Arc::new(ResolverStore::new(IdentityResolver::default()));
        let state = AppState {
            upstream: InterceptedService::new(
                Endpoint::from_static("http://127.0.0.1:50051").connect_lazy(),
                BearerInterceptor::default(),
            ),
            identities: store.snapshot(),
            identity_store: store,
            max_routes: 1,
            max_lpm_scan_routes: 10_000,
            arouteserver_reject_communities: None,
        };
        let mut neighbor = proto::NeighborState {
            config: Some(proto::NeighborConfig {
                address: "192.0.2.1".to_string(),
                remote_asn: 64_496,
                route_server_client: true,
                ..Default::default()
            }),
            state: proto::SessionState::Established as i32,
            rejected_routes_retained: Some(0),
            negotiated_session: Some(proto::NegotiatedSessionState::default()),
            ..Default::default()
        };
        let (_, older) = protocol_row(&state, &neighbor).unwrap();
        assert_eq!(
            older["bgp_session"],
            serde_json::json!(["external", "route-server"])
        );
        for field in ["source_address", "keepalive"] {
            assert!(older.get(field).is_none(), "{field}");
        }
        neighbor
            .negotiated_session
            .as_mut()
            .unwrap()
            .keepalive_interval_seconds = Some(0);
        assert_eq!(protocol_row(&state, &neighbor).unwrap().1["keepalive"], 0);
        neighbor.config.as_mut().unwrap().route_server_client = false;
        assert!(
            protocol_row(&state, &neighbor)
                .unwrap()
                .1
                .get("bgp_session")
                .is_none()
        );
        neighbor.negotiated_session = None;
        neighbor.state = proto::SessionState::Idle as i32;
        let (_, down) = protocol_row(&state, &neighbor).unwrap();
        for field in ["source_address", "keepalive", "bgp_session"] {
            assert!(down.get(field).is_none(), "{field}");
        }
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
        let (protocols, tables) = symbol_names(neighbors, &resolver).unwrap();
        assert_eq!(protocols, ["pb_0001", "pb_0002"]);
        assert_eq!(tables, ["master4"]);

        // Load-bearing call-geometry proof: reverting /symbols to the
        // enriched inventory path restores the per-neighbor policy RPC and
        // makes this contract red.
        let source = include_str!("main.rs");
        let body = source
            .split_once("async fn symbols(")
            .unwrap()
            .1
            .split_once("fn symbol_names(")
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
            med_attr: Some(50),
            communities: vec![community(65001, 100)],
            large_communities: vec!["65001:1:2".to_string()],
            // 2026-01-02 03:04:05 UTC
            received_at_epoch_seconds: 1_767_323_045,
            aggregator: Some(proto::RouteAggregator {
                asn: 64496,
                router_id: "203.0.113.1".to_string(),
            }),
            atomic_aggregate: true,
            ..Default::default()
        };
        let json = route_to_birdwatcher(&route, &IdentityResolver::default());

        assert_eq!(json["network"], "10.1.0.0/24");
        assert_eq!(json["gateway"], "192.0.2.1");
        assert_eq!(json["from_protocol"], "bgp_192.0.2.1");
        assert_eq!(json["learnt_from"], "192.0.2.1");
        assert_eq!(json["age"], "2026-01-02 03:04:05");
        assert_eq!(json["primary"], false);
        assert_eq!(json["type"], serde_json::json!(["BGP", "univ"]));
        assert_eq!(json["bgp"]["origin"], "Incomplete");
        assert_eq!(
            json["bgp"]["as_path"],
            serde_json::json!(["65010", "65020"])
        );
        assert_eq!(json["bgp"]["next_hop"], "192.0.2.1");
        assert_eq!(json["bgp"]["local_pref"], "200");
        assert_eq!(json["bgp"]["med"], 50);
        assert_eq!(
            json["bgp"]["communities"],
            serde_json::json!([[65001, 100]])
        );
        assert_eq!(
            json["bgp"]["large_communities"],
            serde_json::json!([[65001, 1, 2]])
        );
        // No extended communities on the route: an empty array, like
        // `communities` (Alice-LG reads the key on every route).
        assert_eq!(json["bgp"]["ext_communities"], serde_json::json!([]));
        // Bird's Eye shapes from the populated-oracle fixture.
        assert_eq!(json["bgp"]["aggregator"], "203.0.113.1 AS64496");
        assert_eq!(json["bgp"]["atomic_aggr"], "");
    }

    /// Extended communities render as birdwatcher parses BIRD 2.0.12's
    /// `BGP.ext_community` text: `[kind, key, value]` as three strings,
    /// with the key/value split by type byte, `rt`/`ro` kinds for the
    /// transitive AS/IPv4 families, `unknown 0x<type>` for other
    /// subtypes of those families, and `generic` hex halves for every
    /// other type byte (here RFC 8097 origin validation state, 0x43/0x00).
    #[test]
    fn route_conversion_renders_extended_communities_as_birdwatcher_triples() {
        let route = proto::Route {
            prefix: "10.1.0.0".to_string(),
            prefix_length: 24,
            extended_communities: vec![
                // Two-octet AS route target 65000:100 (RFC 4360 §3.1).
                0x0002_fde8_0000_0064,
                // Four-octet AS route target 4200000000:5 (RFC 5668).
                (0x0202 << 48) | (4_200_000_000u64 << 16) | 5,
                // IPv4-address route origin 192.0.2.1:200 (RFC 4360 §3.2).
                (0x0103 << 48) | (0xc000_0201u64 << 16) | 0xc8,
                // Non-transitive two-octet AS route target: BIRD 2.0.12
                // names only the transitive rt/ro subtypes.
                0x4002_fde8_0000_0064,
                // Two-octet AS, unassigned subtype 0x05.
                0x0005_fde8_0000_0001,
                // Non-transitive opaque origin validation state (RFC
                // 8097) carrying 65000 in the low half: generic form.
                0x4300_0000_0000_fde8,
            ],
            ..Default::default()
        };
        let json = route_to_birdwatcher(&route, &IdentityResolver::default());

        assert_eq!(
            json["bgp"]["ext_communities"],
            serde_json::json!([
                ["rt", "65000", "100"],
                ["rt", "4200000000", "5"],
                ["ro", "192.0.2.1", "200"],
                ["unknown 0x4002", "65000", "100"],
                ["unknown 0x5", "65000", "1"],
                ["generic", "0x43000000", "0xfde8"],
            ])
        );
    }

    #[test]
    fn ipv6_peer_protocol_id_uses_underscores() {
        let route = proto::Route {
            prefix: "2001:db8::".to_string(),
            prefix_length: 32,
            next_hop: "2001:db8::1".to_string(),
            peer_address: "2001:db8::1".to_string(),
            local_pref: 100,
            best: true,
            ..Default::default()
        };
        let json = route_to_birdwatcher(&route, &IdentityResolver::default());
        assert_eq!(json["network"], "2001:db8::/32");
        // The response's own best flag is the primary marker.
        assert_eq!(json["primary"], true);
        // Effective local preference prints for every route; an absent
        // MED attribute omits the key, matching BIRD.
        assert_eq!(json["bgp"]["local_pref"], "100");
        assert!(json["bgp"].get("med").is_none());
        // No receive timestamp → empty age (Alice-LG zero-time fallback).
        assert_eq!(json["age"], "");
        assert_eq!(json["from_protocol"], "bgp_2001_db8__1");
        assert_eq!(json["learnt_from"], "2001:db8::1");
        assert_eq!(json["bgp"]["origin"], "IGP");
        // No AGGREGATOR / ATOMIC_AGGREGATE on the route -> keys absent,
        // matching the oracle's presence semantics.
        assert!(json["bgp"].get("aggregator").is_none());
        assert!(json["bgp"].get("atomic_aggr").is_none());
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
            communities: vec![community(65001, 666)],
            large_communities: vec!["65001:1000:1".to_string()],
            rpki_validation: "not_found".to_string(),
            aspa_validation: "unverified".to_string(),
            // 2026-01-02 03:04:05 UTC
            rejected_at_unix_ns: 1_767_323_045_000_000_000,
            ..Default::default()
        };
        let peer: IpAddr = "192.0.2.1".parse().unwrap();
        let json = rejected_route_to_birdwatcher(&route, peer, &IdentityResolver::default(), None);

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
            serde_json::json!(["65020", "65030", "65031"])
        );
        // Retained rejects render the effective default local preference
        // and omit the unretained MED, in the BIRD 2 type pair.
        assert_eq!(json["bgp"]["local_pref"], "100");
        assert!(json["bgp"].get("med").is_none());
        assert_eq!(json["type"], serde_json::json!(["BGP", "univ"]));
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

    fn ars_config(peer: IpAddr) -> ArsRejectCommunities {
        let family = |dynamic, cause| ArsCommunityFamily {
            dynamic: Some(dynamic),
            cause_map: [(3, cause)].into(),
        };
        ArsRejectCommunities {
            peers: [peer].into(),
            std: Some(family(vec![65520], vec![64512, 3])),
            lrg: Some(family(vec![64496, 65520], vec![64496, 65521, 3])),
        }
    }

    #[test]
    fn arouteserver_translation_is_scoped_scrubbed_deduped_and_conservative() {
        let peer = "192.0.2.1".parse().unwrap();
        let config = ars_config(peer);
        let render = |route: &proto::RejectedRoute, peer| {
            let configured = Some(&config).filter(|config| config.peers.contains(&peer));
            rejected_route_to_birdwatcher(route, peer, &IdentityResolver::default(), configured)
        };
        let cause = |prefix: &str, length, reason: &str, detail: &str| {
            arouteserver_reject_cause(&proto::RejectedRoute {
                prefix: prefix.into(),
                prefix_length: length,
                reason: reason.into(),
                reason_detail: detail.into(),
                ..Default::default()
            })
        };
        for (reason, detail, expected) in [
            ("policy_reject", "rs-hygiene:reject-long-as-path", 1),
            ("next_hop_ownership", "foreign_next_hop", 5),
        ] {
            assert_eq!(cause("fc00::", 7, reason, detail), Some(expected));
        }
        for (detail, expected) in [
            ("rs-hygiene:reject-black-list-prefix", 3),
            ("client:x:reject-irrdb-origin-as-filtered", 9),
            ("client:x:reject-irrdb-prefix-filtered", 12),
        ] {
            let actual = cause("2001:db8::", 32, "policy_reject", detail);
            assert_eq!(actual, Some(expected));
            for (prefix, length) in [
                ("fc00::", 7),
                ("2000::", 2),
                ("2001:db8::", 129),
                ("192.0.2.0", 33),
                ("malformed", 24),
            ] {
                assert_eq!(cause(prefix, length, "policy_reject", detail), None);
            }
        }
        for (reason, detail) in [
            ("policy_reject", "rs-hygiene:reject-bogon-prefix"),
            ("treat_as_withdraw", "aspa_first_as_mismatch"),
            ("policy_reject", "rs-hygiene:reject-invalid-asn"),
            ("policy_reject", "rs-hygiene:reject-transit-free-in-path"),
            ("policy_reject", "rs-hygiene:reject-never-via-rs"),
            ("policy_reject", "reject-special-purpose:reject-non-global"),
            ("policy_reject", "rs-hygiene:reject-v4-len-outside-window"),
            ("policy_reject", "client:x:reject-rpki-invalid"),
        ] {
            assert_eq!(cause("192.0.2.0", 24, reason, detail), None);
        }
        let mut route = proto::RejectedRoute {
            prefix: "192.0.2.0".into(),
            prefix_length: 24,
            reason: "policy_reject".into(),
            reason_detail: "rs-hygiene:reject-black-list-prefix".into(),
            communities: vec![
                community(65520, 99),
                community(64512, 3),
                community(65000, 7),
                community(65000, 7),
            ],
            large_communities: vec![
                "64496:65520:99".into(),
                "64496:65521:3".into(),
                "65000:7:1".into(),
                "65000:7:1".into(),
            ],
            ..Default::default()
        };
        route.as_path = "{64500}".into();
        assert_eq!(arouteserver_reject_cause(&route), None);
        route.as_path.clear();
        route.communities.push(0xffff_029a);
        assert_eq!(arouteserver_reject_cause(&route), None);
        route.communities.pop();
        let translated = render(&route, peer);
        assert_eq!(
            translated["bgp"]["communities"].to_string(),
            "[[65000,7],[65520,0],[65520,3],[64512,3]]"
        );
        assert_eq!(
            translated["bgp"]["large_communities"].to_string(),
            "[[65000,7,1],[64496,65520,0],[64496,65520,3],[64496,65521,3]]"
        );
        route.reason_detail = "unknown".into();
        route.large_communities.clear();
        let large = |peer| render(&route, peer)["bgp"]["large_communities"].to_string();
        let other = "192.0.2.2".parse().unwrap();
        assert_eq!(large(peer), "[[64496,65520,0]]");
        assert_eq!(large(other), "[[64496,65520,1]]");
    }

    #[test]
    fn arouteserver_artifact_parser_is_strict_and_bounded() {
        let path = std::env::temp_dir().join(format!("ars-{}.json", std::process::id()));
        let write = |bytes| std::fs::write(&path, bytes).unwrap();
        let valid = r#"{"schema":"rustbgpd.arouteserver-reject-communities.v1","peers":["192.0.2.1"],"std":{"dynamic":"65520:dyn_val","cause_map":{"3":"64512:3"}},"lrg":{"dynamic":"64496:65520:dyn_val"}}"#;
        for invalid in [
            valid.replace("\"schema\"", "\"unknown\":1,\"schema\""),
            valid.replace("\"3\"", "\"0\""),
            valid.replace("\"3\"", "\"16\""),
            valid.replace("65520:dyn_val", "dyn_val:65520"),
            valid.replace(
                "\"dynamic\":\"65520:dyn_val\"",
                "\"dynamic\":\"65520:dyn_val\",\"ext\":\"RT:1:1\"",
            ),
            valid.replace("\"192.0.2.1\"", "\"192.0.2.2\",\"192.0.2.1\""),
        ] {
            write(invalid.into_bytes());
            assert!(load_arouteserver_reject_communities(&path).is_err());
        }
        write(vec![b' '; MAX_ALIAS_FILE_BYTES + 1]);
        assert!(load_arouteserver_reject_communities(&path).is_err());
        let peers = (0..=MAX_ALIAS_FILE_ENTRIES)
            .map(|index| format!(r#""2001:db8::{index:x}""#))
            .collect::<Vec<_>>()
            .join(",");
        write(format!(r#"{{"schema":"{ARS_REJECT_SCHEMA}","peers":[{peers}],"std":{{"dynamic":"65520:dyn_val"}}}}"#).into_bytes());
        assert!(load_arouteserver_reject_communities(&path).is_err());
        std::fs::remove_file(path).unwrap();
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
        let json = rejected_route_to_birdwatcher(&route, peer, &IdentityResolver::default(), None);
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
        const TOO_SPECIFIC: &str = "ixp-manager-hygiene:reject-too-specific";
        const NON_GLOBAL: &str = "reject-special-purpose:reject-non-global";
        const PATH_LONG: &str = "ixp-manager-hygiene:reject-as-path-too-long";
        const PATH_SHORT: &str = "ixp-manager-hygiene:reject-as-path-too-short";
        const FIRST_AS: &str = "client-3:reject-first-as-not-peer-as";
        const IRR_PREFIX: &str = "client-3:reject-irrdb-prefix-filtered";
        const IRR_ORIGIN: &str = "client-3:reject-irrdb-origin-as-filtered";
        const RPKI: &str = "ixp-manager-hygiene:reject-rpki-invalid";
        const TRANSIT: &str = "ixp-manager-hygiene:reject-transit-leak";
        let route = |reason: &str, detail: &str, rpki: &str| proto::RejectedRoute {
            reason: reason.to_string(),
            reason_detail: detail.to_string(),
            rpki_validation: rpki.to_string(),
            ..Default::default()
        };
        let mut core_first_as = route("treat_as_withdraw", "aspa_first_as_mismatch", "not_found");
        assert_eq!(ixp_manager_reject_reason_id(&core_first_as), 6);
        core_first_as.as_path = "43 42".to_string();
        assert_eq!(ixp_manager_reject_reason_id(&core_first_as), 7);
        for (reason, detail, rpki, id) in [
            ("policy_reject", TOO_SPECIFIC, "valid", 1),
            ("policy_reject", NON_GLOBAL, "valid", 3),
            ("policy_reject", PATH_LONG, "valid", 5),
            ("policy_reject", PATH_SHORT, "valid", 6),
            ("policy_reject", FIRST_AS, "valid", 7),
            ("next_hop_ownership", "strict_peer", "valid", 8),
            ("policy_reject", IRR_PREFIX, "valid", 9),
            ("policy_reject", IRR_ORIGIN, "valid", 10),
            ("policy_reject", RPKI, "invalid", 13),
            ("policy_reject", TRANSIT, "valid", 14),
            ("policy_reject", RPKI, "valid", 0),
            (
                "policy_reject",
                "custom:reject-as-path-too-long",
                "valid",
                0,
            ),
            (
                "policy_reject",
                "client-x:reject-irrdb-prefix-filtered",
                "valid",
                0,
            ),
            ("otc_route_leak", "ingress_from_peer", "valid", 0),
            ("rr_loop", "cluster_list", "valid", 0),
            ("policy_reject", "custom:unknown", "invalid", 0),
        ] {
            let entry = route(reason, detail, rpki);
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
    fn ixp_manager_filtered_handler_dispatches_rejects_and_wildcard_scan() {
        let source = include_str!("main.rs");
        assert!(source.contains(".route(\n            \"/routes/lc-zwild/protocol/{id}/{x}/{y}\""));
        let body = source
            .split_once("async fn routes_protocol_large_community_wild_xy(")
            .unwrap()
            .1
            .split_once("fn empty_routes_body(")
            .unwrap()
            .0;
        // The daemon ASN is read before the dispatch, and an ordinary pair
        // hands off to the accepted-route wildcard scan before any
        // rejected-route sourcing happens.
        assert!(
            body.find(".get_global(").unwrap()
                < body.find("ixp_manager_reason_namespace_matches").unwrap(),
            "{body}"
        );
        assert!(
            body.find("serve_routes_for_peer(&state, peer, Some((x, y)))")
                .unwrap()
                < body.find(".list_rejected_routes(").unwrap(),
            "{body}"
        );
        // The retained-rejects tail keeps its capacity-based api block and
        // never trips the generic RIB cap.
        assert!(!body.contains("enforce_max("), "{body}");
        assert!(
            body.contains("api_block(u64::from(response.capacity))"),
            "{body}"
        );
        let ordinary = source
            .split_once("async fn routes_filtered(")
            .unwrap()
            .1
            .split_once("const IXP_MANAGER_REJECT_FUNCTION")
            .unwrap()
            .0;
        assert!(!ordinary.contains("enforce_max("), "{ordinary}");
        assert!(ixp_manager_reason_namespace_matches(65001, 65001, 1101));
        assert!(!ixp_manager_reason_namespace_matches(65001, 65002, 1101));
        assert!(!ixp_manager_reason_namespace_matches(65001, 65001, 1102));
    }

    #[test]
    fn wildcard_scan_matches_only_x_y_star_large_communities() {
        let route = |lcs: &[&str]| proto::Route {
            large_communities: lcs.iter().map(ToString::to_string).collect(),
            ..Default::default()
        };
        assert!(carries_large_community(&route(&["64496:1:1"]), 64496, 1));
        assert!(carries_large_community(
            &route(&["65001:999:7", "64496:1:2"]),
            64496,
            1
        ));
        // A different admin or function, short encodings, and malformed
        // parts never match.
        assert!(!carries_large_community(&route(&["64497:1:1"]), 64496, 1));
        assert!(!carries_large_community(&route(&["64496:2:1"]), 64496, 1));
        assert!(!carries_large_community(&route(&["64496:1"]), 64496, 1));
        assert!(!carries_large_community(&route(&["64496:one:1"]), 64496, 1));
        assert!(!carries_large_community(&route(&[]), 64496, 1));

        let mut retained = Vec::new();
        retain_received_page(
            &mut retained,
            vec![route(&["64497:1:1"]), route(&["64496:1:1"])],
            Some((64496, 1)),
            1,
        )
        .unwrap();
        assert_eq!(retained.len(), 1);
        assert!(carries_large_community(&retained[0], 64496, 1));

        let error = retain_received_page(
            &mut retained,
            vec![route(&["64497:1:2"]), route(&["64496:1:2"])],
            Some((64496, 1)),
            1,
        )
        .unwrap_err();
        assert_eq!(error.0, StatusCode::FORBIDDEN);
        assert_eq!(
            error.1.0["message"],
            "Number of routes exceeds maximum allowed (2/1)"
        );
        assert_eq!(retained.len(), 1);

        let mut ordinary = vec![route(&[])];
        let error = retain_received_page(&mut ordinary, vec![route(&[])], None, 1).unwrap_err();
        assert_eq!(error.0, StatusCode::FORBIDDEN);
        assert_eq!(
            error.1.0["message"],
            "Number of routes exceeds maximum allowed (2/1)"
        );
        assert_eq!(ordinary.len(), 1);
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
                routes: if enabled {
                    Vec::new()
                } else {
                    vec![proto::RejectedRoute::default()]
                },
                evictions_since_reset: Some(0),
            };
            let body = filtered_routes_body(&resp, peer, &IdentityResolver::default(), None);
            assert!(body["api"].is_object(), "{body}");
            assert_eq!(body["api"]["max_routes"], 1024, "{body}");
            assert_eq!(body["routes"], serde_json::json!([]), "{body}");
            assert_eq!(body["retention"]["enabled"], enabled, "{body}");
            assert_eq!(body["retention"]["may_be_incomplete"], false, "{body}");
        }
        let mut response = proto::ListRejectedRoutesResponse {
            retention_enabled: true,
            capacity: 1024,
            evictions_since_reset: None,
            ..Default::default()
        };
        let unknown = retention_metadata(Some(&response));
        assert_eq!(unknown["evictions_since_reset"], Value::Null);
        assert_eq!(unknown["may_be_incomplete"], Value::Null);
        response.evictions_since_reset = Some(2);
        assert_eq!(
            retention_metadata(Some(&response))["may_be_incomplete"],
            true
        );
        assert!(
            retention_metadata(None)
                .as_object()
                .unwrap()
                .values()
                .all(Value::is_null)
        );
    }

    /// The table-wide filtered view unions every live session's retained
    /// rejects under the peer's own alias, scopes them to the table's
    /// family, and aggregates the retention envelope: no live session
    /// leaves completeness unknown, disabled retention contributes no
    /// rows, and one eviction anywhere marks the whole view incomplete.
    #[test]
    #[expect(clippy::too_many_lines, reason = "one linear behavior arc")]
    fn filtered_table_body_unions_live_stores_and_aggregates_retention() {
        let identities = IdentityResolver::parse(&[
            "pb_as64496=192.0.2.1@master4".into(),
            "pb6_as64496=2001:db8::1@master4".into(),
        ])
        .unwrap();
        let v4: IpAddr = "192.0.2.1".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        let down: IpAddr = "192.0.2.9".parse().unwrap();
        let reject =
            |prefix: &str, length: u32, family: proto::AddressFamily| proto::RejectedRoute {
                prefix: prefix.into(),
                prefix_length: length,
                afi_safi: family as i32,
                reason: "as_path_loop".into(),
                ..Default::default()
            };
        let store = |routes: Vec<proto::RejectedRoute>, evictions: Option<u64>| {
            Some(proto::ListRejectedRoutesResponse {
                retention_enabled: true,
                capacity: 1024,
                routes,
                evictions_since_reset: evictions,
                ..Default::default()
            })
        };
        let ipv4 = proto::AddressFamily::Ipv4Unicast as i32;
        let any = proto::AddressFamily::Unspecified as i32;
        let networks = |body: &Value| {
            body["routes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|route| {
                    (
                        route["network"].as_str().unwrap().to_owned(),
                        route["from_protocol"].as_str().unwrap().to_owned(),
                    )
                })
                .collect::<Vec<_>>()
        };

        // Empty: no live session, so completeness is unknown and the
        // generic cap is reported.
        let empty = filtered_table_body(&[(down, None)], ipv4, &identities, None, 7);
        assert_eq!(empty["routes"], serde_json::json!([]), "{empty}");
        assert_eq!(empty["api"]["max_routes"], 7, "{empty}");
        assert!(
            empty["retention"]
                .as_object()
                .unwrap()
                .values()
                .all(Value::is_null),
            "{empty}"
        );

        // Populated: two live peers and one down peer, family-scoped and
        // aliased per peer, with the summed capacity as the cap.
        let stores = vec![
            (
                v4,
                store(
                    vec![reject("10.98.0.0", 24, proto::AddressFamily::Ipv4Unicast)],
                    Some(0),
                ),
            ),
            (down, None),
            (
                v6,
                store(
                    vec![reject(
                        "2001:db8:ffff::",
                        48,
                        proto::AddressFamily::Ipv6Unicast,
                    )],
                    Some(0),
                ),
            ),
        ];
        let table = filtered_table_body(&stores, ipv4, &identities, None, 7);
        assert_eq!(
            networks(&table),
            [("10.98.0.0/24".to_owned(), "pb_as64496".to_owned())],
            "{table}"
        );
        assert_eq!(
            table["routes"][0]["reject_reason"], "as_path_loop",
            "{table}"
        );
        assert_eq!(
            table["routes"][0]["bgp"]["large_communities"],
            serde_json::json!([[64496, 65520, 4]]),
            "{table}"
        );
        assert_eq!(table["api"]["max_routes"], 2048, "{table}");
        assert_eq!(
            table["retention"],
            serde_json::json!({
                "enabled": true,
                "capacity": 2048,
                "evictions_since_reset": 0,
                "may_be_incomplete": false,
            }),
            "{table}"
        );
        let mixed = filtered_table_body(&stores, any, &identities, None, 7);
        assert_eq!(
            networks(&mixed),
            [
                ("10.98.0.0/24".to_owned(), "pb_as64496".to_owned()),
                ("2001:db8:ffff::/48".to_owned(), "pb6_as64496".to_owned()),
            ],
            "{mixed}"
        );

        // Capacity warning: one eviction anywhere flags the view, an older
        // daemon's absent count keeps it unknown, and disabled retention
        // contributes no rows while the envelope still says enabled.
        let mut warned = stores.clone();
        warned[2].1.as_mut().unwrap().evictions_since_reset = Some(3);
        let flagged = filtered_table_body(&warned, any, &identities, None, 7);
        assert_eq!(
            flagged["retention"]["evictions_since_reset"], 3,
            "{flagged}"
        );
        assert_eq!(flagged["retention"]["may_be_incomplete"], true, "{flagged}");
        warned[0].1.as_mut().unwrap().evictions_since_reset = None;
        let unknown = filtered_table_body(&warned, any, &identities, None, 7);
        assert_eq!(unknown["retention"]["evictions_since_reset"], Value::Null);
        assert_eq!(unknown["retention"]["may_be_incomplete"], Value::Null);
        warned[0].1.as_mut().unwrap().retention_enabled = false;
        let disabled = filtered_table_body(&warned, any, &identities, None, 7);
        assert_eq!(
            networks(&disabled),
            [("2001:db8:ffff::/48".to_owned(), "pb6_as64496".to_owned())],
            "{disabled}"
        );
        assert_eq!(disabled["retention"]["enabled"], true, "{disabled}");
        assert_eq!(disabled["api"]["max_routes"], 2048, "{disabled}");
    }

    /// The inventory-stability retry behind the table-wide filtered walk:
    /// only the table's peers count, keepalive-driven counters do not, and any
    /// membership, state, staleness, or retained-count change between the
    /// two snapshots triggers a retry.
    #[test]
    fn filtered_table_inventory_stability_sees_membership_state_and_count_changes() {
        let identities = IdentityResolver::parse(&[
            "pb_as64496=192.0.2.1@master4".into(),
            "pb_as64497=192.0.2.2@master4".into(),
        ])
        .unwrap();
        let neighbor =
            |address: &str, state: i32, stale: bool, retained: Option<u64>| proto::NeighborState {
                config: Some(proto::NeighborConfig {
                    address: address.into(),
                    ..Default::default()
                }),
                state,
                stale,
                rejected_routes_retained: retained,
                ..Default::default()
            };
        let before = vec![
            neighbor("192.0.2.1", 6, false, Some(1)),
            neighbor("2001:db8::1", 6, false, Some(4)),
        ];
        let inventory = table_reject_inventory(&before, &identities, "master4").unwrap();
        assert_eq!(
            inventory,
            vec![("192.0.2.1".parse::<IpAddr>().unwrap(), 6, false, Some(1))]
        );
        assert_eq!(
            table_reject_inventory(&before, &identities, "master")
                .unwrap()
                .len(),
            1
        );
        assert!(
            table_reject_inventory(&before, &identities, "master6")
                .unwrap()
                .is_empty()
        );
        for changed in [
            vec![neighbor("192.0.2.1", 6, false, Some(2))],
            vec![neighbor("192.0.2.1", 1, false, Some(1))],
            vec![neighbor("192.0.2.1", 6, true, Some(1))],
            vec![neighbor("192.0.2.1", 6, false, None)],
            vec![],
            vec![
                neighbor("192.0.2.1", 6, false, Some(1)),
                neighbor("192.0.2.2", 6, false, Some(0)),
            ],
        ] {
            assert_ne!(
                table_reject_inventory(&changed, &identities, "master4").unwrap(),
                inventory,
                "{changed:?}"
            );
        }
        let mut busy = before.clone();
        busy[0].uptime_seconds += 30;
        busy[0].prefixes_received += 1;
        assert_eq!(
            table_reject_inventory(&busy, &identities, "master4").unwrap(),
            inventory
        );
        assert!(
            table_reject_inventory(&[neighbor("bogus", 6, false, None)], &identities, "master4")
                .is_err()
        );
    }

    /// Source pin for the inventory-stability retry: the handler reads one
    /// inventory, walks every peer's store once, re-reads the inventory, and
    /// refuses after bounded changes; the generic RIB cap never applies.
    #[test]
    fn filtered_table_handler_uses_inventory_stability_retry() {
        let source = include_str!("main.rs");
        assert_eq!(
            source
                .matches(".route(\"/routes/table/{table}/filtered\", get(routes_table_filtered))")
                .count(),
            1
        );
        let body = source
            .split_once("async fn routes_table_filtered(")
            .unwrap()
            .1
            .split_once("fn aggregate_retention(")
            .unwrap()
            .0;
        assert!(body.contains("for _ in 0..CAPTURE_ATTEMPTS"), "{body}");
        assert_eq!(
            body.matches("list_neighbors(&state).await?").count(),
            2,
            "{body}"
        );
        assert_eq!(body.matches(".list_rejected_routes(").count(), 1, "{body}");
        assert!(
            body.find("table_address_family(").unwrap()
                < body.find(".list_rejected_routes(").unwrap(),
            "{body}"
        );
        assert!(body.contains("if after == inventory"), "{body}");
        assert_eq!(
            body.matches("    Err(invalid_table_snapshot())\n}\n")
                .count(),
            1,
            "{body}"
        );
        assert!(!body.contains("enforce_max("), "{body}");
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

        let mut candidates = Vec::new();
        let mut excluded = advertised.clone();
        retain_noexport_page(&mut candidates, &mut excluded, best, u64::MAX).unwrap();
        let networks: Vec<(&str, u32)> = candidates
            .iter()
            .map(|r| (r.prefix.as_str(), r.prefix_length))
            .collect();
        assert_eq!(
            networks,
            vec![("10.1.0.0", 24)],
            "suppressed once, exported absent"
        );

        let mut candidates = Vec::new();
        let mut excluded = advertised;
        retain_noexport_page(&mut candidates, &mut excluded, Vec::new(), u64::MAX).unwrap();
        assert!(
            candidates.is_empty(),
            "empty Loc-RIB yields an empty noexport view"
        );
    }

    /// The whole-Loc-RIB diff the handler used to compute after paging
    /// everything in: the oracle the page-wise diff must reproduce.
    fn noexport_candidates_oracle<'a>(
        best: &'a [proto::Route],
        advertised: &HashSet<(String, u32)>,
    ) -> Vec<&'a proto::Route> {
        let mut seen: HashSet<(&str, u32)> = HashSet::new();
        best.iter()
            .filter(|r| !advertised.contains(&(r.prefix.clone(), r.prefix_length)))
            .filter(|r| seen.insert((r.prefix.as_str(), r.prefix_length)))
            .collect()
    }

    /// Paging the Loc-RIB through the per-page diff yields exactly the
    /// rows the whole-Loc-RIB diff produced, in the same order, across
    /// page boundaries that split a prefix's Add-Path duplicates and
    /// interleave exported prefixes.
    #[test]
    fn noexport_page_diff_matches_whole_loc_rib_diff() {
        let mk = |prefix: &str, path_id: u32| proto::Route {
            prefix: prefix.to_string(),
            prefix_length: 24,
            path_id,
            ..Default::default()
        };
        let pages = vec![
            vec![mk("10.1.0.0", 0), mk("10.2.0.0", 0), mk("10.1.0.0", 1)],
            vec![mk("10.3.0.0", 0), mk("10.1.0.0", 2), mk("10.2.0.0", 1)],
            vec![mk("10.4.0.0", 0), mk("10.3.0.0", 1)],
        ];
        let advertised: HashSet<(String, u32)> =
            [("10.2.0.0".to_string(), 24), ("10.4.0.0".to_string(), 24)].into();

        let best = pages.concat();
        let expected = noexport_candidates_oracle(&best, &advertised)
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();

        let mut candidates = Vec::new();
        let mut excluded = advertised;
        for page in pages {
            retain_noexport_page(&mut candidates, &mut excluded, page, 2).unwrap();
        }
        assert_eq!(candidates, expected);
        assert_eq!(
            candidates
                .iter()
                .map(|r| (r.prefix.as_str(), r.path_id))
                .collect::<Vec<_>>(),
            vec![("10.1.0.0", 0), ("10.3.0.0", 0)]
        );
    }

    /// The cap trips on the page that crosses it: with `max_routes = 2`,
    /// two suppressed routes on page one are retained and the third on
    /// page two is refused with the generic cap error before it is kept,
    /// so the retained candidates never exceed the cap.
    #[test]
    fn noexport_page_diff_enforces_cap_before_retaining_the_page() {
        let mk = |prefix: &str| proto::Route {
            prefix: prefix.to_string(),
            prefix_length: 24,
            ..Default::default()
        };
        let advertised: HashSet<(String, u32)> = [("10.9.0.0".to_string(), 24)].into();
        let mut candidates = Vec::new();
        let mut excluded = advertised;

        retain_noexport_page(
            &mut candidates,
            &mut excluded,
            vec![mk("10.1.0.0"), mk("10.9.0.0"), mk("10.2.0.0")],
            2,
        )
        .unwrap();
        assert_eq!(candidates.len(), 2);

        let error = retain_noexport_page(
            &mut candidates,
            &mut excluded,
            vec![mk("10.9.0.0"), mk("10.3.0.0")],
            2,
        )
        .unwrap_err();
        assert_eq!(error.0, StatusCode::FORBIDDEN);
        assert_eq!(
            error.1.0["message"],
            "Number of routes exceeds maximum allowed (3/2)"
        );
        assert_eq!(candidates.len(), 2, "the refused page is not retained");
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
        assert_eq!(json["bgp"]["as_path"], serde_json::json!(["65010"]));
        assert_eq!(json["bgp"]["local_pref"], "100");
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
        for (state, expected) in [
            (proto::SessionState::Idle, ""),
            (proto::SessionState::Connect, " Connect"),
            (proto::SessionState::Active, " Active"),
            (proto::SessionState::OpenSent, " OpenSent"),
            (proto::SessionState::OpenConfirm, " OpenConfirm"),
            (proto::SessionState::Established, " Established"),
        ] {
            assert_eq!(format_connection(state as i32), expected);
        }
        assert_eq!(format_connection(999), "");
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
    fn alias_file_is_bounded_utf8_and_reuses_exact_alias_grammar() {
        let path = std::env::temp_dir().join(format!("birdwatcher-aliases-{}", std::process::id()));
        let load = |bytes: &[u8]| {
            std::fs::write(&path, bytes).unwrap();
            load_alias_file(&path)
        };
        let resolver = load(b"# comment\n pb_a=192.0.2.1@master4\n\n").unwrap();
        assert_eq!(
            resolver.resolve("pb_a").unwrap(),
            "192.0.2.1".parse::<IpAddr>().unwrap()
        );
        for invalid in [
            b"pb_a=192.0.2.1@master4 # member\n".as_slice(),
            b"secret_member=192.0.2.1@master4@secret_peer\n".as_slice(),
            b"a=192.0.2.1@master4\na=192.0.2.2@master4\n",
            b"a=192.0.2.1@master4\nb=192.0.2.1@master4\n",
            b"a=192.0.2.1@master4\n\xff",
        ] {
            assert_eq!(load(invalid).unwrap_err().to_string(), "invalid alias file");
        }
        assert!(load(&vec![b'#'; MAX_ALIAS_FILE_BYTES]).is_ok());
        assert!(load(&vec![b'#'; MAX_ALIAS_FILE_BYTES + 1]).is_err());
        let aliases = (0..=MAX_ALIAS_FILE_ENTRIES)
            .map(|i| format!("p{i}=2001:db8::{i:x}@master6\n"))
            .collect::<Vec<_>>()
            .concat();
        assert!(load(aliases.trim_end().rsplit_once('\n').unwrap().0.as_bytes()).is_ok());
        assert!(load(aliases.as_bytes()).is_err());
        std::fs::remove_file(path).unwrap();

        assert!(
            Args::try_parse_from([
                "birdwatcher-adapter",
                "--grpc-addr",
                "http://127.0.0.1:50051",
                "--protocol-alias",
                "a=192.0.2.1@master4",
                "--protocol-alias-file",
                "/tmp/aliases",
            ])
            .is_err()
        );
    }

    #[tokio::test]
    async fn resolver_swap_is_atomic_noop_stable_and_request_snapshotted() {
        let parse =
            |name: &str| IdentityResolver::parse(&[format!("{name}=192.0.2.1@master4")]).unwrap();
        let store = Arc::new(ResolverStore::new(parse("old")));
        let upstream = InterceptedService::new(
            Endpoint::from_static("http://127.0.0.1:50051").connect_lazy(),
            BearerInterceptor::default(),
        );
        let state = AppState {
            upstream,
            identities: store.snapshot(),
            identity_store: Arc::clone(&store),
            max_routes: 1,
            max_lpm_scan_routes: 10_000,
            arouteserver_reject_communities: None,
        };
        let request_a = state.clone();
        assert_eq!(store.replace(parse("old")).unwrap(), (1, false));
        assert!(IdentityResolver::parse(&["malformed".to_string()]).is_err());
        assert_eq!(
            store.snapshot().resolve("old").unwrap(),
            "192.0.2.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(store.replace(parse("new")).unwrap(), (2, true));
        let request_b = state.clone();
        assert!(request_a.identities.resolve("old").is_ok());
        assert!(request_a.identities.resolve("new").is_err());
        assert!(request_b.identities.resolve("new").is_ok());
        assert!(request_b.identities.resolve("old").is_err());
        assert_eq!(store.replace(parse("new")).unwrap(), (2, false));
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

        let defaults = Args::try_parse_from([
            "birdwatcher-adapter",
            "--grpc-addr",
            "http://127.0.0.1:50051",
        ])
        .unwrap();
        assert_eq!(defaults.max_lpm_scan_routes, 10_000);

        for flag in ["--max-routes", "--max-lpm-scan-routes"] {
            assert!(
                Args::try_parse_from([
                    "birdwatcher-adapter",
                    "--grpc-addr",
                    "http://127.0.0.1:50051",
                    flag,
                    "0",
                ])
                .is_err()
            );
        }
    }

    #[test]
    fn exact_prefix_parser_distinguishes_networks_host_bit_input_and_malformed_input() {
        for (input, address, length) in [
            ("192.0.2.0/24", "192.0.2.0", 24),
            ("0.0.0.0/0", "0.0.0.0", 0),
            ("2001:db8::/32", "2001:db8::", 32),
            ("::/0", "::", 0),
        ] {
            let parsed = ExactPrefix::parse(input).unwrap().unwrap();
            assert_eq!(parsed.address.to_string(), address);
            assert_eq!(parsed.length, length);
        }
        // Well-formed but with host bits set: BIRD rejects the literal, so
        // the lookups answer HTTP 200 with no routes rather than HTTP 400.
        for input in ["192.0.2.1/24", "2001:db8::1/64"] {
            assert_eq!(ExactPrefix::parse(input).unwrap(), None, "{input}");
        }
        for input in [
            "192.0.2.0",
            "192.0.2.0/",
            "192.0.2.0/24/extra",
            "not-an-ip/24",
            "192.0.2.0/nope",
            "192.0.2.0/33",
            "2001:db8::/129",
        ] {
            let (status, Json(body)) = ExactPrefix::parse(input).unwrap_err();
            assert_eq!(status, StatusCode::BAD_REQUEST, "{input}");
            assert_eq!(body, serde_json::json!({"message":"Invalid route prefix"}));
            assert!(!body.to_string().contains(input));
        }
    }

    #[test]
    fn longest_match_selects_the_most_specific_covering_view_prefix() {
        let route = |prefix: &str, length: u32| proto::Route {
            prefix: prefix.to_string(),
            prefix_length: length,
            ..Default::default()
        };
        let view = vec![
            route("203.0.113.0", 24),
            route("203.0.113.128", 25),
            route("203.0.113.64", 26),
            route("2001:db8:a::", 48),
        ];
        let query = |value: &str| ExactPrefix::parse(value).unwrap().unwrap();
        // An exact entry is its own longest match.
        assert_eq!(
            longest_match(&view, query("203.0.113.128/25")),
            Some(query("203.0.113.128/25"))
        );
        // A covering-only prefix and a host address fall back to the cover.
        assert_eq!(
            longest_match(&view, query("203.0.113.0/25")),
            Some(query("203.0.113.0/24"))
        );
        assert_eq!(
            longest_match(&view, query("203.0.113.1/32")),
            Some(query("203.0.113.0/24"))
        );
        // The most specific covering entry wins over a shorter one.
        assert_eq!(
            longest_match(&view, query("203.0.113.192/26")),
            Some(query("203.0.113.128/25"))
        );
        // Nothing covering, and never across address families.
        assert_eq!(longest_match(&view, query("198.51.100.0/24")), None);
        assert_eq!(longest_match(&view, query("2001:db8:c::/48")), None);
    }

    #[tokio::test]
    async fn host_bit_lookups_answer_empty_success_without_an_upstream_call() {
        let store = Arc::new(ResolverStore::new(
            IdentityResolver::parse(&["pb_as64496=192.0.2.1@master4".to_string()]).unwrap(),
        ));
        let state = AppState {
            upstream: InterceptedService::new(
                Endpoint::from_static("http://127.0.0.1:50051").connect_lazy(),
                BearerInterceptor::default(),
            ),
            identities: store.snapshot(),
            identity_store: store,
            max_routes: 7,
            max_lpm_scan_routes: 10_000,
            arouteserver_reject_communities: None,
        };
        for source in [ExactRouteSource::Received, ExactRouteSource::Advertised] {
            let Json(body) = serve_exact_route(&state, "192.0.2.1/24", "pb_as64496", source)
                .await
                .unwrap();
            assert_eq!(body["routes"], serde_json::json!([]), "{source:?}");
            assert_eq!(body["api"]["max_routes"], 7, "{source:?}");
        }
        // Identity resolution still precedes the host-bit answer, and
        // genuinely malformed input is still rejected.
        let (status, _) = serve_exact_route(
            &state,
            "192.0.2.1/24",
            "missing",
            ExactRouteSource::Received,
        )
        .await
        .unwrap_err();
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = serve_exact_route(
            &state,
            "not-an-ip/24",
            "pb_as64496",
            ExactRouteSource::Received,
        )
        .await
        .unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn exact_route_requests_pin_every_filter_on_every_page_and_unknown_id_is_404() {
        let peer: IpAddr = "192.0.2.1".parse().unwrap();
        for (value, address, length, family) in [
            (
                "192.0.2.0/24",
                "192.0.2.0",
                24,
                proto::AddressFamily::Ipv4Unicast,
            ),
            (
                "2001:db8::/32",
                "2001:db8::",
                32,
                proto::AddressFamily::Ipv6Unicast,
            ),
        ] {
            let prefix = ExactPrefix::parse(value).unwrap().unwrap();
            for (source, token) in [
                (ExactRouteSource::Received, ""),
                (ExactRouteSource::Received, "opaque-page-2"),
                (ExactRouteSource::Advertised, ""),
                (ExactRouteSource::Advertised, "opaque-page-2"),
            ] {
                let request = exact_route_request(peer, prefix, token.to_string(), source);
                assert_eq!(request.neighbor_address, peer.to_string(), "{source:?}");
                assert_eq!(request.prefix_filter, address, "{source:?}");
                assert_eq!(request.prefix_filter_length, length, "{source:?}");
                assert!(!request.longer_prefixes, "{source:?}");
                assert_eq!(request.afi_safi, family as i32, "{source:?}");
                assert_eq!(request.page_token, token, "{source:?}");
            }
        }
        let resolver = IdentityResolver::default();
        let (status, Json(body)) = resolver.resolve("missing-alias").unwrap_err();
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, serde_json::json!({"message":"Protocol not found"}));
    }

    #[test]
    fn fallback_pages_pin_family_token_shrinking_budget_and_complete_view() {
        let peer: IpAddr = "192.0.2.1".parse().unwrap();
        for (value, family) in [
            ("192.0.2.1/32", proto::AddressFamily::Ipv4Unicast),
            ("2001:db8::1/128", proto::AddressFamily::Ipv6Unicast),
        ] {
            let prefix = ExactPrefix::parse(value).unwrap().unwrap();
            for (token, remaining, page_size) in [("", 10_000, 1000), ("opaque-page-2", 999, 999)] {
                let request = view_route_request(peer, prefix, token.to_string(), remaining);
                assert_eq!(request.neighbor_address, peer.to_string());
                assert_eq!(request.afi_safi, family as i32);
                assert_eq!(request.page_token, token);
                assert_eq!(request.page_size, page_size);
            }
        }

        let route = || proto::Route::default();
        let mut below = Vec::new();
        append_view_page(&mut below, vec![route()], "next", 3).unwrap();
        append_view_page(&mut below, vec![route()], "", 3).unwrap();
        assert_eq!(below.len(), 2);

        let mut exact = vec![route(), route()];
        append_view_page(&mut exact, vec![route()], "", 3).unwrap();
        assert_eq!(exact.len(), 3);

        for (mut view, page, token) in [
            (vec![route(), route()], vec![route()], "next"),
            (vec![route(), route()], vec![route(), route()], ""),
        ] {
            let before = view.len();
            let (status, Json(body)) = append_view_page(&mut view, page, token, 3).unwrap_err();
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(
                body,
                serde_json::json!({
                    "message": "Longest-match scan limit reached before the peer view was exhausted (3/3 routes)"
                })
            );
            assert_eq!(view.len(), before, "a refused page must not be evaluated");
        }

        let (status, Json(body)) = lpm_scan_limit(10_000);
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            body,
            serde_json::json!({
                "message": "Longest-match scan limit reached before the peer view was exhausted (10000/10000 routes)"
            })
        );
    }

    #[test]
    fn exact_route_pages_preserve_add_path_order_and_cap_only_exact_candidates() {
        let prefix = ExactPrefix::parse("192.0.2.0/24").unwrap().unwrap();
        let route = |network: &str, path_id: u32, med: u32| proto::Route {
            prefix: network.to_string(),
            prefix_length: 24,
            path_id,
            med,
            med_attr: Some(med),
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
    #[expect(clippy::too_many_lines, reason = "one linear behavior arc")]
    fn table_lookup_is_selected_first_all_path_capped_and_fail_closed() {
        let route = |peer: &str, med: u32| proto::Route {
            prefix: "192.0.2.0".to_string(),
            prefix_length: 24,
            peer_address: peer.to_string(),
            med,
            med_attr: Some(med),
            ..Default::default()
        };
        let response = proto::ExplainBestPathResponse {
            prefix: "192.0.2.0".to_string(),
            prefix_length: 24,
            best_route: Some(route("198.51.100.1", 10)),
            candidates: vec![proto::BestPathCandidate {
                route: Some(route("198.51.100.2", 20)),
                ..Default::default()
            }],
            ..Default::default()
        };
        let query = ExactPrefix::parse("192.0.2.128/25").unwrap().unwrap();
        let body = table_lookup_body(&response, query, &IdentityResolver::default(), 2).unwrap();
        assert_eq!(body["routes"][0]["bgp"]["med"], 10);
        assert_eq!(body["routes"][1]["bgp"]["med"], 20);

        let (status, _) = table_lookup_body(&response, query, &IdentityResolver::default(), 1)
            .expect_err("winner plus alternative exceeds cap");
        assert_eq!(status, StatusCode::FORBIDDEN);
        let rejects = |response: &proto::ExplainBestPathResponse, query, max_routes| {
            let (status, Json(body)) =
                table_lookup_body(response, query, &IdentityResolver::default(), max_routes)
                    .unwrap_err();
            assert_eq!(status, StatusCode::BAD_GATEWAY);
            assert_eq!(
                body["message"],
                "Upstream daemon returned an invalid route response"
            );
        };
        let mut invalid = response.clone();
        invalid.prefix = "not-an-ip".to_string();
        rejects(&invalid, query, 2);
        let mut unrelated = response.clone();
        unrelated.prefix = "198.51.100.0".to_string();
        unrelated
            .best_route
            .as_mut()
            .unwrap()
            .prefix
            .clone_from(&unrelated.prefix);
        unrelated.candidates[0]
            .route
            .as_mut()
            .unwrap()
            .prefix
            .clone_from(&unrelated.prefix);
        rejects(&unrelated, query, 2);
        rejects(
            &response,
            ExactPrefix::parse("192.0.2.0/23").unwrap().unwrap(),
            2,
        );
        let mut missing = response.clone();
        missing.best_route = None;
        rejects(&missing, query, 2);
        let mut malformed_over_cap = response.clone();
        malformed_over_cap.candidates[0].route = None;
        rejects(&malformed_over_cap, query, 1);
        let mut duplicate = response.clone();
        duplicate.candidates[0].route.as_mut().unwrap().peer_address = "198.51.100.1".to_string();
        rejects(&duplicate, query, 2);
        let mut repeated_alternative = response.clone();
        repeated_alternative
            .candidates
            .push(repeated_alternative.candidates[0].clone());
        rejects(&repeated_alternative, query, 3);

        let family = proto::AddressFamily::Ipv4Unicast as i32;
        let insert =
            |set: &mut TableRouteSet, route, best, max| set.insert(route, best, family, max);
        let winner = response.best_route.clone().unwrap();
        let mut inactive = response.candidates[0].route.clone().unwrap();
        inactive.peer_address = "198.51.100.0".to_string();
        let mut best_only = winner.clone();
        best_only.prefix = "203.0.113.0".to_string();
        best_only.peer_address = "198.51.100.3".to_string();
        let version = proto::RoutePageVersion {
            epoch: 7,
            generation: 9,
        };
        let mut set = TableRouteSet::default();
        assert!(set.check_version(None).is_err());
        set.check_version(Some(&version)).unwrap();
        let mut changed = version;
        changed.generation += 1;
        assert!(set.check_version(Some(&changed)).is_err());
        insert(&mut set, inactive.clone(), false, 3).unwrap();
        insert(&mut set, winner.clone(), false, 3).unwrap();
        insert(&mut set, winner.clone(), true, 3).unwrap();
        assert!(insert(&mut set, inactive.clone(), true, 3).is_err());
        insert(&mut set, best_only, true, 3).unwrap();
        let rows = set.body(&IdentityResolver::default(), 3)["routes"].clone();
        assert_eq!(
            rows.as_array()
                .unwrap()
                .iter()
                .map(|row| row["primary"].as_bool().unwrap())
                .collect::<Vec<_>>(),
            [true, false, true]
        );
        assert_eq!(rows[1]["learnt_from"], "198.51.100.0");
        let mut bad = TableRouteSet::default();
        insert(&mut bad, winner.clone(), false, 1).unwrap();
        assert!(insert(&mut bad, winner.clone(), false, 1).is_err());
        let mut conflict = winner;
        conflict.med += 1;
        assert!(insert(&mut bad, conflict, true, 1).is_err());
        assert_eq!(
            insert(&mut bad, inactive, false, 1).unwrap_err().0,
            StatusCode::FORBIDDEN
        );

        let source = include_str!("main.rs");
        let handler = source
            .split_once("async fn route_table(")
            .unwrap()
            .1
            .split_once("fn table_lookup_body(")
            .unwrap()
            .0;
        assert!(handler.contains(".lookup_best_path("), "{handler}");
        assert!(handler.contains("tonic::Code::NotFound"), "{handler}");
        assert!(
            handler.contains("bad_gateway(\"LookupBestPath\""),
            "{handler}"
        );
        assert!(!handler.contains("Unimplemented"), "{handler}");
        assert!(!handler.contains("explain_best_path"), "{handler}");
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
    fn received_best_capture_retry_contract_is_bounded_and_path_id_exact() {
        let version = |generation| proto::RoutePageVersion {
            epoch: 7,
            generation,
        };
        let mut expected = None;
        capture_version(&mut expected, Some(&version(1))).unwrap();
        assert!(matches!(
            capture_version(&mut expected, Some(&version(2))),
            Err(CaptureError::Retry)
        ));
        assert!(matches!(
            capture_version(&mut None, None),
            Err(CaptureError::Fatal(_))
        ));
        for _ in 0..CAPTURE_ATTEMPTS {
            assert!(matches!(
                capture_error(
                    "ListReceivedRoutes",
                    &tonic::Status::aborted("generation moved")
                ),
                CaptureError::Retry
            ));
        }
        assert_eq!(CAPTURE_ATTEMPTS, 3);

        let mut attempts = 0;
        let winner = loop {
            attempts += 1;
            if attempts == 1 {
                assert!(matches!(
                    capture_version(&mut Some((7, 1)), Some(&version(2))),
                    Err(CaptureError::Retry)
                ));
                continue;
            }
            break "same-version-winner";
        };
        assert_eq!(attempts, 2);
        assert_eq!(winner, "same-version-winner");

        let mut first = proto::Route {
            prefix: "203.0.113.0".into(),
            prefix_length: 24,
            peer_address: "192.0.2.1".into(),
            path_id: 10,
            ..Default::default()
        };
        let first_key = route_key(&first);
        first.path_id = 20;
        assert_ne!(first_key, route_key(&first));
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
