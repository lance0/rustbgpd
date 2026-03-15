//! Birdwatcher-compatible REST API for looking glass frontends.
//!
//! Optional axum HTTP server implementing a subset of the birdwatcher API
//! contract consumed by Alice-LG and similar looking glass UIs.
//!
//! **Supported endpoints** (single-table mode):
//! - `GET /status` — daemon status
//! - `GET /protocols/bgp` — BGP neighbor list
//! - `GET /routes/protocol/{id}` — received routes by neighbor address
//! - `GET /routes/peer/{peer}` — received routes by peer IP
//!
//! Response shapes match birdwatcher field names so Alice-LG can parse them
//! without adapter code. Fields that have no rustbgpd equivalent are present
//! but empty/zero.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Json, Router, routing::get};
use rustbgpd_api::peer_types::{PeerInfo, PeerManagerCommand};
use rustbgpd_rib::{RibUpdate, Route};
use rustbgpd_wire::{AsPathSegment, PathAttribute, Prefix};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info};

/// Shared state for the looking glass HTTP server.
pub struct LookingGlassState {
    pub rib_query_tx: mpsc::Sender<RibUpdate>,
    pub peer_cmd_tx: mpsc::Sender<PeerManagerCommand>,
    pub asn: u32,
    pub router_id: String,
    pub start_time: Instant,
}

impl LookingGlassState {
    pub fn new(
        rib_query_tx: mpsc::Sender<RibUpdate>,
        peer_cmd_tx: mpsc::Sender<PeerManagerCommand>,
        asn: u32,
        router_id: String,
    ) -> Self {
        Self {
            rib_query_tx,
            peer_cmd_tx,
            asn,
            router_id,
            start_time: Instant::now(),
        }
    }
}

/// Start the looking glass HTTP server.
pub async fn serve(addr: SocketAddr, state: Arc<LookingGlassState>) {
    let app = Router::new()
        .route("/status", get(status))
        .route("/protocols/bgp", get(protocols_bgp))
        .route("/routes/protocol/{id}", get(routes_protocol))
        .route("/routes/peer/{peer}", get(routes_peer))
        .with_state(state);

    info!(addr = %addr, "starting looking glass HTTP server");
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(addr = %addr, error = %e, "failed to bind looking glass listener");
            return;
        }
    };
    if let Err(e) = axum::serve(listener, app).await {
        error!(error = %e, "looking glass server error");
    }
}

// ---------------------------------------------------------------------------
// Birdwatcher-compatible response types
//
// Field names match the birdwatcher JSON contract that Alice-LG parses via
// `parseAPIStatus`, `parseBirdwatcherStatus`, `parseNeighbors`, and
// `parseRouteData`.
// ---------------------------------------------------------------------------

/// Top-level `api` block included in every birdwatcher response.
#[derive(Serialize, Clone)]
struct BirdwatcherApi {
    #[serde(rename = "Version")]
    version: String,
    result_from_cache: bool,
}

fn api_block() -> BirdwatcherApi {
    BirdwatcherApi {
        version: format!("rustbgpd {}", env!("CARGO_PKG_VERSION")),
        result_from_cache: false,
    }
}

// ---------------------------------------------------------------------------
// GET /status
// ---------------------------------------------------------------------------

async fn status(State(state): State<Arc<LookingGlassState>>) -> Json<Value> {
    Json(serde_json::json!({
        "api": api_block(),
        "status": {
            "router_id": state.router_id,
            "current_server": format_timestamp_now(),
            "last_reboot": format_instant_as_timestamp(state.start_time),
            // Not tracked — SIGHUP reload does not update a persistent timestamp.
            // Empty string causes Alice-LG to parse as zero time, which is benign.
            "last_reconfig": "",
            "message": format!("rustbgpd AS{}", state.asn),
            "version": format!("rustbgpd {}", env!("CARGO_PKG_VERSION")),
        }
    }))
}

// ---------------------------------------------------------------------------
// GET /protocols/bgp
// ---------------------------------------------------------------------------

async fn protocols_bgp(
    State(state): State<Arc<LookingGlassState>>,
) -> Result<Json<Value>, StatusCode> {
    let peers = query_peers(&state).await?;

    // Birdwatcher returns protocols as a map keyed by protocol name.
    // Alice-LG iterates this map and reads fields like `neighbor_address`,
    // `neighbor_as`, `state`, `description`, `routes`, `state_changed`.
    let mut protocols: HashMap<String, Value> = HashMap::new();
    for p in &peers {
        let protocol_id = format!("bgp_{}", p.address).replace(':', "_");
        let state_str = format_bird_state(p);

        // Query advertised count for this peer to populate routes_exported
        let exported = query_advertised_count(&state, p.address).await?;

        protocols.insert(
            protocol_id,
            serde_json::json!({
                "bird_protocol": "BGP",
                "state": state_str,
                "neighbor_address": p.address.to_string(),
                "neighbor_as": p.remote_asn,
                "description": p.description,
                "table": "master",
                "state_changed": format_uptime_timestamp(p.uptime_secs),
                "routes": {
                    "imported": p.prefix_count,
                    "filtered": 0,
                    "exported": exported,
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
// GET /routes/protocol/{id}  — Alice-LG single-table mode
// GET /routes/peer/{peer}    — Alice-LG multi-table mode
// ---------------------------------------------------------------------------

async fn routes_protocol(
    State(state): State<Arc<LookingGlassState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    // Protocol IDs are "bgp_<addr>" — extract the address.
    let addr_str = id.strip_prefix("bgp_").unwrap_or(&id).replace('_', ":");
    let peer_addr: IpAddr = addr_str.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
    serve_routes_for_peer(&state, peer_addr).await
}

async fn routes_peer(
    State(state): State<Arc<LookingGlassState>>,
    Path(peer): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    let peer_addr: IpAddr = peer.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
    serve_routes_for_peer(&state, peer_addr).await
}

async fn serve_routes_for_peer(
    state: &LookingGlassState,
    peer: IpAddr,
) -> Result<Json<Value>, StatusCode> {
    let (reply_tx, reply_rx) = oneshot::channel();
    state
        .rib_query_tx
        .send(RibUpdate::QueryReceivedRoutes {
            peer: Some(peer),
            reply: reply_tx,
        })
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let routes = reply_rx
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let routes_json: Vec<Value> = routes.iter().map(route_to_birdwatcher).collect();

    Ok(Json(serde_json::json!({
        "api": api_block(),
        "routes": routes_json,
    })))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn query_peers(state: &LookingGlassState) -> Result<Vec<PeerInfo>, StatusCode> {
    let (reply_tx, reply_rx) = oneshot::channel();
    state
        .peer_cmd_tx
        .send(PeerManagerCommand::ListPeers { reply: reply_tx })
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    reply_rx
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn query_advertised_count(
    state: &LookingGlassState,
    peer: IpAddr,
) -> Result<usize, StatusCode> {
    let (reply_tx, reply_rx) = oneshot::channel();
    state
        .rib_query_tx
        .send(RibUpdate::QueryAdvertisedCount {
            peer,
            reply: reply_tx,
        })
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    reply_rx
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Format peer state as birdwatcher/BIRD protocol state string.
/// Alice-LG lowercases this and maps "established" → "up" display.
fn format_bird_state(peer: &PeerInfo) -> String {
    use rustbgpd_fsm::SessionState;
    match peer.state {
        SessionState::Idle => "down",
        SessionState::Connect => "start",
        SessionState::Active => "active",
        SessionState::OpenSent => "opensent",
        SessionState::OpenConfirm => "openconfirm",
        SessionState::Established => "established",
    }
    .to_string()
}

/// Convert a rustbgpd Route to the birdwatcher route JSON shape.
///
/// Alice-LG reads: `network`, `gateway`, `from_protocol`, `interface`,
/// `metric`, `age`, `type`, `primary`, `learnt_from`, and `bgp` sub-object
/// with `origin`, `as_path`, `next_hop`, `local_pref`, `med`, `communities`,
/// `large_communities`.
fn route_to_birdwatcher(route: &Route) -> Value {
    let mut origin = "IGP";
    let mut as_path_asns: Vec<u32> = Vec::new();
    let mut local_pref = 0u32;
    let mut med = 0u32;
    let mut communities: Vec<Vec<u32>> = Vec::new();
    let mut large_communities: Vec<Vec<u64>> = Vec::new();

    for attr in route.attributes.iter() {
        match attr {
            PathAttribute::Origin(o) => {
                origin = match o {
                    rustbgpd_wire::Origin::Igp => "IGP",
                    rustbgpd_wire::Origin::Egp => "EGP",
                    rustbgpd_wire::Origin::Incomplete => "Incomplete",
                };
            }
            PathAttribute::AsPath(asp) => {
                for seg in &asp.segments {
                    match seg {
                        AsPathSegment::AsSequence(asns) | AsPathSegment::AsSet(asns) => {
                            as_path_asns.extend(asns);
                        }
                    }
                }
            }
            PathAttribute::LocalPref(lp) => local_pref = *lp,
            PathAttribute::Med(m) => med = *m,
            PathAttribute::Communities(cs) => {
                for c in cs {
                    communities.push(vec![(*c >> 16) & 0xffff, *c & 0xffff]);
                }
            }
            PathAttribute::LargeCommunities(lcs) => {
                for lc in lcs {
                    large_communities.push(vec![
                        u64::from(lc.global_admin),
                        u64::from(lc.local_data1),
                        u64::from(lc.local_data2),
                    ]);
                }
            }
            _ => {}
        }
    }

    let network = match route.prefix {
        Prefix::V4(p) => format!("{}/{}", p.addr, p.len),
        Prefix::V6(p) => format!("{}/{}", p.addr, p.len),
    };

    let from_protocol = format!("bgp_{}", route.peer).replace(':', "_");

    serde_json::json!({
        "network": network,
        "gateway": route.next_hop.to_string(),
        "from_protocol": from_protocol,
        "interface": "",
        "metric": 0,
        "age": format_instant_as_timestamp(route.received_at),
        "type": ["BGP", "unicast", "univ"],
        "primary": false,
        "learnt_from": route.peer.to_string(),
        "bgp": {
            "origin": origin,
            "as_path": as_path_asns,
            "next_hop": route.next_hop.to_string(),
            "local_pref": local_pref,
            "med": med,
            "communities": communities,
            "large_communities": large_communities,
        }
    })
}

/// Format an `Instant` as a wall-clock timestamp by computing the offset from now.
fn format_instant_as_timestamp(instant: Instant) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let elapsed = instant.elapsed();
    let now_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format_epoch_secs(now_epoch.saturating_sub(elapsed.as_secs()))
}

/// Format a "now" timestamp in the layout Alice-LG expects for `ServerTimeShort`.
/// Birdwatcher uses BIRD's `current_server` format: `"2025-03-14 12:34:56"`.
fn format_timestamp_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let epoch_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format_epoch_secs(epoch_secs)
}

/// Produce a timestamp for `state_changed` (`uptime_secs` ago).
fn format_uptime_timestamp(uptime_secs: u64) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format_epoch_secs(now.saturating_sub(uptime_secs))
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
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use rustbgpd_api::peer_types::PeerManagerCommand;
    use rustbgpd_rib::RibUpdate;
    use tokio::sync::mpsc;
    use tower::ServiceExt;

    use super::*;

    fn test_state() -> (
        Arc<LookingGlassState>,
        mpsc::Receiver<RibUpdate>,
        mpsc::Receiver<PeerManagerCommand>,
    ) {
        let (rib_tx, rib_rx) = mpsc::channel(16);
        let (peer_tx, peer_rx) = mpsc::channel(16);
        let state = Arc::new(LookingGlassState::new(
            rib_tx,
            peer_tx,
            65001,
            "10.0.0.1".to_string(),
        ));
        (state, rib_rx, peer_rx)
    }

    fn app(state: Arc<LookingGlassState>) -> Router {
        Router::new()
            .route("/status", get(status))
            .route("/protocols/bgp", get(protocols_bgp))
            .route("/routes/peer/{peer}", get(routes_peer))
            .with_state(state)
    }

    #[tokio::test]
    async fn status_endpoint_has_birdwatcher_shape() {
        let (state, _rib_rx, _peer_rx) = test_state();
        let resp = app(state)
            .oneshot(
                Request::builder()
                    .uri("/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1_000_000)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // api block
        assert!(json["api"]["Version"].is_string());
        assert_eq!(json["api"]["result_from_cache"], false);

        // status block
        assert_eq!(json["status"]["router_id"], "10.0.0.1");
        assert!(json["status"]["current_server"].is_string());
        assert!(json["status"]["last_reboot"].is_string());
        assert!(
            json["status"]["version"]
                .as_str()
                .unwrap()
                .contains("rustbgpd")
        );
        assert!(
            json["status"]["message"]
                .as_str()
                .unwrap()
                .contains("65001")
        );
    }

    #[tokio::test]
    async fn protocols_bgp_returns_protocols_map() {
        let (state, _rib_rx, mut peer_rx) = test_state();
        let app = app(state);

        let resp_fut = app.oneshot(
            Request::builder()
                .uri("/protocols/bgp")
                .body(Body::empty())
                .unwrap(),
        );

        // The handler sends ListPeers to peer_cmd_tx — reply with empty list.
        tokio::spawn(async move {
            if let Some(PeerManagerCommand::ListPeers { reply }) = peer_rx.recv().await {
                let _ = reply.send(vec![]);
            }
        });

        let resp = resp_fut.await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1_000_000)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(json["api"]["Version"].is_string());
        assert!(json["protocols"].is_object());
    }

    #[tokio::test]
    async fn routes_peer_returns_routes_array() {
        let (state, mut rib_rx, _peer_rx) = test_state();
        let app = app(state);

        let resp_fut = app.oneshot(
            Request::builder()
                .uri("/routes/peer/10.0.0.2")
                .body(Body::empty())
                .unwrap(),
        );

        // Reply to QueryReceivedRoutes with empty list.
        tokio::spawn(async move {
            if let Some(RibUpdate::QueryReceivedRoutes { reply, .. }) = rib_rx.recv().await {
                let _ = reply.send(vec![]);
            }
        });

        let resp = resp_fut.await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1_000_000)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(json["api"]["Version"].is_string());
        assert!(json["routes"].is_array());
    }

    #[tokio::test]
    async fn routes_peer_invalid_addr_returns_400() {
        let (state, _rib_rx, _peer_rx) = test_state();
        let resp = app(state)
            .oneshot(
                Request::builder()
                    .uri("/routes/peer/not-an-ip")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn status_last_reboot_is_not_current_time() {
        let (state, _rib_rx, _peer_rx) = test_state();
        let resp = app(Arc::clone(&state))
            .oneshot(
                Request::builder()
                    .uri("/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(resp.into_body(), 1_000_000)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let current = json["status"]["current_server"].as_str().unwrap();
        let reboot = json["status"]["last_reboot"].as_str().unwrap();
        // last_reboot should be <= current_server (boot time, not request time).
        // They could be equal if the test runs within the same second, but
        // last_reboot must never be *after* current_server.
        assert!(reboot <= current);
    }
}
