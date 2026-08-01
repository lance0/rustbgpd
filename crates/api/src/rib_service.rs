//! gRPC RIB service — route listing, filtering, and streaming.

use std::net::IpAddr;
use std::pin::Pin;
#[cfg(feature = "bench-internals")]
use std::time::Instant;

use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::{Stream, StreamExt, wrappers::BroadcastStream};
use tonic::{Request, Response, Status};
use tracing::debug;

use crate::event_service::{route_event_to_bgp_event, stream_lag_bgp_event};
use crate::proto;
use rustbgpd_rib::{
    BgpLsFamily, BgpLsRibRoute, EvpnRibRoute, ExplainAdvertisedRoute, ExplainAdvertisedRouteError,
    ExplainBestPath, ExplainDecision, ExportGateVerdict, FlowSpecRoute, LabeledRibRoute,
    OrrLinkSnapshot, OrrNodeSnapshot, OrrStatusSnapshot, OrrTopologySnapshot, OrrVantageStatus,
    RibUpdate, Route, RouteEventType, RoutePage, RoutePageError, RoutePageVersion,
    RouteQueryFilter, RouteQueryKey, RouteQueryScope, RouteSourceIdentity, RtcRibRoute,
    VpnRibRoute, route_query_key,
};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{
    Afi, AsPathSegment, EvpnRoute, LargeCommunity, PathAttribute, Prefix, bgpls::BgpLsNlriType,
};

/// Live snapshot provider for daemon-owned BLACKHOLE discard status.
pub type BlackholeDiscardSnapshotFn =
    std::sync::Arc<dyn Fn() -> Vec<proto::BlackholeDiscard> + Send + Sync + 'static>;

/// Live snapshot provider for daemon-owned general FIB route status.
pub type FibRouteSnapshotFn =
    std::sync::Arc<dyn Fn() -> Vec<proto::FibRouteStatus> + Send + Sync + 'static>;

fn explain_advertised_error_status(error: ExplainAdvertisedRouteError) -> Status {
    match error {
        ExplainAdvertisedRouteError::NotFound(message) => Status::not_found(message),
        ExplainAdvertisedRouteError::FailedPrecondition(message) => {
            Status::failed_precondition(message)
        }
    }
}

fn parse_optional_peer_filter(value: &str) -> Result<Option<IpAddr>, Status> {
    if value.is_empty() {
        return Ok(None);
    }
    value.parse::<IpAddr>().map(Some).map_err(|error| {
        Status::invalid_argument(format!("invalid peer_filter {value:?}: {error}"))
    })
}

/// One CRUD operation for the daemon FIB-table control hook (`[[fib_tables]]`).
///
/// The binary-owned closure behind [`FibTableControlFn`] interprets these:
/// it reads the FIB reconciler's current table set, applies the op, validates
/// the candidate against the live config, hot-applies it through the reconciler,
/// and persists the accepted set — all under a coordinator lock shared with the
/// SIGHUP reload path so concurrent edits can't interleave.
pub enum FibTableControlRequest {
    /// Create-or-replace a table by name (upsert); carries the full definition.
    Set(proto::FibTableConfig),
    /// Remove a table by name.
    Delete { name: String },
    /// Read the current accepted table set + runtime availability.
    List,
}

/// Error returned by the daemon FIB-table control hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FibTableControlError {
    /// Candidate validation failed (bad `table_id` / family / caps / refs).
    InvalidArgument(String),
    /// Delete target name does not exist in the current set.
    NotFound(String),
    /// The FIB reconciler is not running: either no `[[fib_tables]]` entry was
    /// present at startup (enabling FIB is restart-required) or the runtime is
    /// unavailable (non-Linux platform / netlink setup failure).
    FailedPrecondition(String),
    /// The persistence channel is saturated or closed.
    Unavailable(String),
    /// Coordinator lock poisoned, actor channel closed, or other internal fault.
    Internal(String),
}

impl FibTableControlError {
    fn into_status(self) -> Status {
        match self {
            Self::InvalidArgument(message) => Status::invalid_argument(message),
            Self::NotFound(message) => Status::not_found(message),
            Self::FailedPrecondition(message) => Status::failed_precondition(message),
            Self::Unavailable(message) => Status::unavailable(message),
            Self::Internal(message) => Status::internal(message),
        }
    }
}

impl std::fmt::Display for FibTableControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArgument(message)
            | Self::NotFound(message)
            | Self::FailedPrecondition(message)
            | Self::Unavailable(message)
            | Self::Internal(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for FibTableControlError {}

/// Future returned by the FIB-table control hook.
pub type FibTableControlFuture = Pin<
    Box<
        dyn std::future::Future<Output = Result<proto::ListFibTablesResponse, FibTableControlError>>
            + Send,
    >,
>;
/// Daemon-owned hook that performs `[[fib_tables]]` CRUD. Wired in `main.rs`
/// where the binary config types, validator, FIB actor sender, and config
/// persistence channel are all visible; injected here so this API crate never
/// needs to reach across the crate boundary into the binary.
pub type FibTableControlFn =
    std::sync::Arc<dyn Fn(FibTableControlRequest) -> FibTableControlFuture + Send + Sync + 'static>;

/// Benchmark-only receipt for work performed after the RIB actor snapshot.
#[cfg(feature = "bench-internals")]
#[derive(Debug, Clone, Copy)]
pub struct VpnQueryServiceReceipt {
    pub post_actor_ns: u64,
    pub returned_rows: usize,
}

/// gRPC service for querying the RIB (received, best, advertised routes).
pub struct RibService {
    rib_tx: mpsc::Sender<RibUpdate>,
    blackhole_discard_snapshot: BlackholeDiscardSnapshotFn,
    fib_route_snapshot: FibRouteSnapshotFn,
    metrics: BgpMetrics,
    /// Per-listener access mode; gates the mutating FIB-table RPCs as
    /// defense-in-depth behind the authz interceptor's `Mutating` tier.
    access_mode: crate::server::AccessMode,
    /// Daemon FIB-table CRUD hook. `None` when the service was built without
    /// it (tests, or a build without FIB control) — the mutating RPCs then
    /// return `FAILED_PRECONDITION`.
    fib_table_control: Option<FibTableControlFn>,
    #[cfg(feature = "bench-internals")]
    vpn_query_bench_receipts: Option<mpsc::Sender<VpnQueryServiceReceipt>>,
}

impl RibService {
    /// Create a new RIB service backed by the given RIB channel.
    #[allow(dead_code)]
    pub fn new(rib_tx: mpsc::Sender<RibUpdate>) -> Self {
        Self {
            rib_tx,
            blackhole_discard_snapshot: std::sync::Arc::new(Vec::new),
            fib_route_snapshot: std::sync::Arc::new(Vec::new),
            metrics: BgpMetrics::new(),
            // Fail closed: callers opt into mutations via `with_fib_table_control`.
            access_mode: crate::server::AccessMode::ReadOnly,
            fib_table_control: None,
            #[cfg(feature = "bench-internals")]
            vpn_query_bench_receipts: None,
        }
    }

    /// Create a RIB service with live kernel route status snapshots.
    #[allow(dead_code)]
    pub fn with_status_snapshots(
        rib_tx: mpsc::Sender<RibUpdate>,
        blackhole_discard_snapshot: BlackholeDiscardSnapshotFn,
        fib_route_snapshot: FibRouteSnapshotFn,
    ) -> Self {
        Self::with_status_snapshots_and_metrics(
            rib_tx,
            blackhole_discard_snapshot,
            fib_route_snapshot,
            BgpMetrics::new(),
        )
    }

    /// Create a RIB service with live kernel route status snapshots and
    /// shared metrics.
    pub fn with_status_snapshots_and_metrics(
        rib_tx: mpsc::Sender<RibUpdate>,
        blackhole_discard_snapshot: BlackholeDiscardSnapshotFn,
        fib_route_snapshot: FibRouteSnapshotFn,
        metrics: BgpMetrics,
    ) -> Self {
        Self {
            rib_tx,
            blackhole_discard_snapshot,
            fib_route_snapshot,
            metrics,
            access_mode: crate::server::AccessMode::ReadOnly,
            fib_table_control: None,
            #[cfg(feature = "bench-internals")]
            vpn_query_bench_receipts: None,
        }
    }

    /// Arm bounded benchmark receipts for VPN query post-actor work.
    #[cfg(feature = "bench-internals")]
    #[must_use]
    pub fn with_vpn_query_bench_receipts(
        mut self,
        receipts: mpsc::Sender<VpnQueryServiceReceipt>,
    ) -> Self {
        self.vpn_query_bench_receipts = Some(receipts);
        self
    }

    /// Attach the per-listener access mode and the daemon FIB-table CRUD hook,
    /// enabling `SetFibTable` / `DeleteFibTable` / `ListFibTables`. Without this
    /// the mutating RPCs report the runtime as unavailable.
    #[must_use]
    pub fn with_fib_table_control(
        mut self,
        access_mode: crate::server::AccessMode,
        fib_table_control: Option<FibTableControlFn>,
    ) -> Self {
        self.access_mode = access_mode;
        self.fib_table_control = fib_table_control;
        self
    }

    async fn query_orr_topology(&self) -> Result<OrrTopologySnapshot, Status> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::QueryOrrTopology { reply: reply_tx })
            .await
            .map_err(|_| Status::internal("RIB manager unavailable"))?;
        reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))
    }

    async fn query_orr_status(&self) -> Result<OrrStatusSnapshot, Status> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::QueryOrrStatus { reply: reply_tx })
            .await
            .map_err(|_| Status::internal("RIB manager unavailable"))?;
        reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))
    }

    /// One bounded, resumable page from the RIB task. Filtering and
    /// pagination run inside the actor; the reply channel doubles as
    /// the cancellation token (dropping this future drops the receiver,
    /// so an already-enqueued page query is skipped by the actor).
    async fn query_routes_page(
        &self,
        scope: RouteQueryScope,
        filter: Option<RouteQueryFilter>,
        after: Option<RouteQueryKey>,
        expected_version: Option<RoutePageVersion>,
        page_size: usize,
    ) -> Result<RoutePage, Status> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::QueryRoutesPage {
                scope,
                filter,
                after,
                expected_version,
                page_size,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("RIB manager unavailable"))?;

        reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?
            .map_err(|error| match error {
                RoutePageError::Invalidated => Status::aborted(
                    "route table changed during pagination; restart with an empty page_token",
                ),
                RoutePageError::GenerationExhausted => Status::unavailable(
                    "route pagination unavailable because its process-local generation is exhausted",
                ),
            })
    }

    async fn query_explain_advertised_route(
        &self,
        peer: IpAddr,
        prefix: Prefix,
        rd: Option<rustbgpd_wire::RouteDistinguisher>,
        labeled: bool,
        source: Option<RouteSourceIdentity>,
    ) -> Result<ExplainAdvertisedRoute, Status> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::ExplainAdvertisedRoute {
                peer,
                prefix,
                rd,
                labeled,
                source,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("RIB manager unavailable"))?;

        reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?
            .map_err(explain_advertised_error_status)
    }

    async fn query_explain_best_path(
        &self,
        prefix: Prefix,
        peer: Option<IpAddr>,
    ) -> Result<Option<ExplainBestPath>, Status> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::ExplainBestPath {
                prefix,
                peer,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("RIB manager unavailable"))?;

        reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))
    }
}

/// Validate the requested unicast route-listing address family.
/// 0 = UNSPECIFIED (treat as "any"), 1-2 = valid unicast families.
fn validate_unicast_afi_safi(value: i32) -> Result<(), Status> {
    if value != 0
        && value != proto::AddressFamily::Ipv4Unicast as i32
        && value != proto::AddressFamily::Ipv6Unicast as i32
    {
        return Err(Status::invalid_argument(
            "route listing supports only IPv4/IPv6 unicast address families",
        ));
    }
    Ok(())
}

/// Validate the requested `FlowSpec` route-listing address family.
/// 0 = UNSPECIFIED (treat as "any"), 3-4 = valid `FlowSpec` families.
fn validate_flowspec_afi_safi(value: i32) -> Result<(), Status> {
    if value != 0
        && value != proto::AddressFamily::Ipv4Flowspec as i32
        && value != proto::AddressFamily::Ipv6Flowspec as i32
    {
        return Err(Status::invalid_argument(
            "FlowSpec route listing supports only IPv4/IPv6 FlowSpec address families",
        ));
    }
    Ok(())
}

/// Whether a route matches the requested address family.
/// `afi_safi == 0` (UNSPECIFIED) matches all routes.
fn route_matches_family(route: &Route, afi_safi: i32) -> bool {
    match afi_safi {
        x if x == proto::AddressFamily::Ipv4Unicast as i32 => {
            matches!(route.prefix, Prefix::V4(_))
        }
        x if x == proto::AddressFamily::Ipv6Unicast as i32 => {
            matches!(route.prefix, Prefix::V6(_))
        }
        _ => true,
    }
}

/// Whether `afi_safi` leaves every route matching — i.e. `route_matches_family`
/// is `true` for all routes, so the family filter does not narrow the snapshot.
fn family_filter_is_noop(afi_safi: i32) -> bool {
    afi_safi != proto::AddressFamily::Ipv4Unicast as i32
        && afi_safi != proto::AddressFamily::Ipv6Unicast as i32
}

/// Parsed route filters extracted from a `ListRoutesRequest`.
struct RouteFilters {
    /// Exact or covering prefix to match against.
    prefix: Option<Prefix>,
    /// If true, match any prefix that falls within `prefix` (longer-or-equal).
    longer: bool,
    /// Origin ASN (last ASN in `AS_PATH`). 0 = no filter.
    origin_asn: u32,
    /// Community values to match (OR logic).
    communities: Vec<u32>,
    /// Whether a large-community filter was requested.
    large_community_filter_active: bool,
    /// Canonical large community values to match (OR logic).
    large_communities: Vec<LargeCommunity>,
}

struct RouteFilterAttrs<'a> {
    origin_asn: Option<u32>,
    communities: &'a [u32],
    large_communities: &'a [LargeCommunity],
}

impl<'a> RouteFilterAttrs<'a> {
    fn from_route(route: &'a Route) -> Self {
        let mut origin_asn = None;
        let mut as_path_seen = false;
        let mut communities = None;
        let mut large_communities = None;

        for attr in route.attributes.iter() {
            match attr {
                PathAttribute::AsPath(path) if !as_path_seen => {
                    origin_asn = path.origin_asn();
                    as_path_seen = true;
                }
                PathAttribute::Communities(values) if communities.is_none() => {
                    communities = Some(values.as_slice());
                }
                PathAttribute::LargeCommunities(values) if large_communities.is_none() => {
                    large_communities = Some(values.as_slice());
                }
                _ => {}
            }
        }

        Self {
            origin_asn,
            communities: communities.unwrap_or(&[]),
            large_communities: large_communities.unwrap_or(&[]),
        }
    }
}

impl RouteFilters {
    fn from_request(req: &proto::ListRoutesRequest) -> Result<Self, Status> {
        let prefix = if req.prefix_filter.is_empty() {
            if req.prefix_filter_length != 0 {
                return Err(Status::invalid_argument(
                    "prefix_filter_length requires a non-empty prefix_filter",
                ));
            }
            None
        } else {
            let addr: IpAddr = req.prefix_filter.parse().map_err(|e| {
                Status::invalid_argument(format!("invalid prefix_filter address: {e}"))
            })?;
            match addr {
                IpAddr::V4(_) if req.prefix_filter_length > 32 => {
                    return Err(Status::invalid_argument(
                        "prefix_filter_length must be 0-32 for IPv4",
                    ));
                }
                IpAddr::V6(_) if req.prefix_filter_length > 128 => {
                    return Err(Status::invalid_argument(
                        "prefix_filter_length must be 0-128 for IPv6",
                    ));
                }
                _ => {}
            }
            let len = u8::try_from(req.prefix_filter_length)
                .expect("validated prefix_filter_length fits in u8");
            Some(match addr {
                IpAddr::V4(v4) => Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(v4, len)),
                IpAddr::V6(v6) => Prefix::V6(rustbgpd_wire::Ipv6Prefix::new(v6, len)),
            })
        };

        let large_communities = req
            .large_community_filter
            .iter()
            .filter_map(|value| parse_canonical_large_community(value))
            .collect();

        Ok(Self {
            prefix,
            longer: req.longer_prefixes,
            origin_asn: req.origin_asn,
            communities: req.community_filter.clone(),
            large_community_filter_active: !req.large_community_filter.is_empty(),
            large_communities,
        })
    }

    fn is_empty(&self) -> bool {
        self.prefix.is_none()
            && self.origin_asn == 0
            && self.communities.is_empty()
            && !self.large_community_filter_active
    }

    fn matches(&self, route: &Route) -> bool {
        if let Some(ref filter_prefix) = self.prefix {
            if self.longer {
                if !prefix_contains(filter_prefix, &route.prefix) {
                    return false;
                }
            } else if route.prefix != *filter_prefix {
                return false;
            }
        }

        if self.origin_asn != 0
            || !self.communities.is_empty()
            || self.large_community_filter_active
        {
            let attrs = RouteFilterAttrs::from_route(route);

            if self.origin_asn != 0 && attrs.origin_asn != Some(self.origin_asn) {
                return false;
            }

            if !self.communities.is_empty()
                && !self
                    .communities
                    .iter()
                    .any(|c| attrs.communities.contains(c))
            {
                return false;
            }

            if self.large_community_filter_active
                && (self.large_communities.is_empty()
                    || !self
                        .large_communities
                        .iter()
                        .any(|lc| attrs.large_communities.contains(lc)))
            {
                return false;
            }
        }

        true
    }
}

fn parse_canonical_large_community(value: &str) -> Option<LargeCommunity> {
    let mut parts = value.split(':');
    let global_admin = parts.next()?.parse::<u32>().ok()?;
    let local_data1 = parts.next()?.parse::<u32>().ok()?;
    let local_data2 = parts.next()?.parse::<u32>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    let parsed = LargeCommunity::new(global_admin, local_data1, local_data2);
    (parsed.to_string() == value).then_some(parsed)
}

/// Check if `container` prefix contains `candidate` (candidate is equal or more specific).
fn prefix_contains(container: &Prefix, candidate: &Prefix) -> bool {
    match (container, candidate) {
        (Prefix::V4(c), Prefix::V4(p)) => {
            if p.len < c.len {
                return false;
            }
            let mask = if c.len == 0 {
                0u32
            } else {
                u32::MAX << (32 - c.len)
            };
            u32::from(c.addr) & mask == u32::from(p.addr) & mask
        }
        (Prefix::V6(c), Prefix::V6(p)) => {
            if p.len < c.len {
                return false;
            }
            let mask = if c.len == 0 {
                0u128
            } else {
                u128::MAX << (128 - c.len)
            };
            u128::from(c.addr) & mask == u128::from(p.addr) & mask
        }
        _ => false, // V4 vs V6 never matches
    }
}

struct FibRouteFilters {
    table_name: Option<String>,
    state: Option<proto::FibRouteState>,
    reason: Option<String>,
    prefix: Option<(String, u32)>,
    peer_address: Option<String>,
}

impl FibRouteFilters {
    fn from_request(req: &proto::ListFibRoutesRequest) -> Result<Self, Status> {
        let table_name = (!req.table_name.is_empty()).then(|| req.table_name.clone());
        let reason = (!req.reason.is_empty()).then(|| req.reason.clone());
        let prefix =
            parse_route_event_prefix_filter(&req.prefix, req.prefix_length, None)?.map(|prefix| {
                let (addr, len) = prefix_parts(prefix);
                (addr, len)
            });
        let peer_address = if req.peer_address.is_empty() {
            None
        } else {
            let addr: IpAddr = req
                .peer_address
                .parse()
                .map_err(|e| Status::invalid_argument(format!("invalid peer_address: {e}")))?;
            Some(addr.to_string())
        };
        let state = match proto::FibRouteState::try_from(req.state) {
            Ok(proto::FibRouteState::Unspecified) => None,
            Ok(state) => Some(state),
            Err(_) => {
                return Err(Status::invalid_argument(format!(
                    "invalid fib route state: {}",
                    req.state
                )));
            }
        };

        Ok(Self {
            table_name,
            state,
            reason,
            prefix,
            peer_address,
        })
    }

    fn matches(&self, row: &proto::FibRouteStatus) -> bool {
        if let Some(table_name) = &self.table_name
            && &row.table_name != table_name
        {
            return false;
        }
        if let Some(state) = self.state
            && proto::FibRouteState::try_from(row.state).ok() != Some(state)
        {
            return false;
        }
        if let Some(reason) = &self.reason
            && &row.reason != reason
        {
            return false;
        }
        if let Some((prefix, prefix_length)) = &self.prefix
            && (&row.prefix != prefix || row.prefix_length != *prefix_length)
        {
            return false;
        }
        if let Some(peer_address) = &self.peer_address
            && &row.peer_address != peer_address
        {
            return false;
        }
        true
    }
}

struct FibRoutePageParams {
    offset: usize,
    page_size: usize,
}

fn parse_fib_page_params(
    req: &proto::ListFibRoutesRequest,
) -> Result<Option<FibRoutePageParams>, &'static str> {
    if req.page_size == 0 {
        if req.page_token.is_empty() {
            return Ok(None);
        }
        return Err("page_token requires page_size");
    }

    let offset: usize = if req.page_token.is_empty() {
        0
    } else {
        req.page_token.parse().map_err(|_| "invalid page_token")?
    };

    Ok(Some(FibRoutePageParams {
        offset,
        page_size: req.page_size as usize,
    }))
}

fn sort_fib_routes(routes: &mut [proto::FibRouteStatus]) {
    routes.sort_by(|a, b| {
        a.table_name
            .cmp(&b.table_name)
            .then_with(|| a.table_id.cmp(&b.table_id))
            .then_with(|| a.metric.cmp(&b.metric))
            .then_with(|| a.prefix.cmp(&b.prefix))
            .then_with(|| a.prefix_length.cmp(&b.prefix_length))
            .then_with(|| a.next_hop.cmp(&b.next_hop))
            .then_with(|| a.peer_address.cmp(&b.peer_address))
            .then_with(|| a.state.cmp(&b.state))
            .then_with(|| a.reason.cmp(&b.reason))
    });
}

fn build_fib_response(
    routes: Vec<proto::FibRouteStatus>,
    page: Option<FibRoutePageParams>,
) -> proto::ListFibRoutesResponse {
    let total_count = u64::try_from(routes.len()).unwrap_or(u64::MAX);
    let Some(page) = page else {
        return proto::ListFibRoutesResponse {
            routes,
            next_page_token: String::new(),
            total_count,
        };
    };

    let routes_len = routes.len();
    let page_routes: Vec<proto::FibRouteStatus> = routes
        .into_iter()
        .skip(page.offset)
        .take(page.page_size)
        .collect();
    let next_offset = page
        .offset
        .checked_add(page_routes.len())
        .unwrap_or(routes_len);
    let next_page_token = if next_offset < routes_len {
        next_offset.to_string()
    } else {
        String::new()
    };

    proto::ListFibRoutesResponse {
        routes: page_routes,
        next_page_token,
        total_count,
    }
}

fn prefix_parts(prefix: Prefix) -> (String, u32) {
    match prefix {
        Prefix::V4(prefix) => (prefix.addr.to_string(), u32::from(prefix.len)),
        Prefix::V6(prefix) => (prefix.addr.to_string(), u32::from(prefix.len)),
    }
}

/// Default page size when the request leaves `page_size` at 0.
const DEFAULT_ROUTE_PAGE_SIZE: usize = 100;

/// Decode the pagination fields of a route-listing request: the resume
/// cursor (from the opaque `page_token`) and the requested page size.
fn parse_route_page_params(
    req: &proto::ListRoutesRequest,
    scope: RouteQueryScope,
    query_identity: &str,
) -> Result<(Option<RouteQueryKey>, Option<RoutePageVersion>, usize), Status> {
    let (after, expected_version) = if req.page_token.is_empty() {
        (None, None)
    } else {
        let cursor = decode_route_page_token(&req.page_token)?;
        if cursor.scope != scope {
            return Err(Status::invalid_argument(
                "page_token belongs to a different route scope",
            ));
        }
        if cursor.query_identity != query_identity {
            return Err(Status::invalid_argument(
                "page_token belongs to different route filters",
            ));
        }
        (Some(cursor.after), Some(cursor.version))
    };
    let page_size = if req.page_size == 0 {
        DEFAULT_ROUTE_PAGE_SIZE
    } else {
        req.page_size as usize
    };
    Ok((after, expected_version, page_size))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RoutePageCursor {
    scope: RouteQueryScope,
    query_identity: String,
    after: RouteQueryKey,
    version: RoutePageVersion,
}

fn route_page_scope_token(scope: RouteQueryScope) -> String {
    match scope {
        RouteQueryScope::Received { peer: None } => "received:*".to_string(),
        RouteQueryScope::Received { peer: Some(peer) } => format!("received:{peer}"),
        RouteQueryScope::Best => "best".to_string(),
        RouteQueryScope::Advertised { peer } => format!("advertised:{peer}"),
    }
}

fn parse_route_page_scope_token(token: &str) -> Option<RouteQueryScope> {
    if token == "best" {
        return Some(RouteQueryScope::Best);
    }
    if token == "received:*" {
        return Some(RouteQueryScope::Received { peer: None });
    }
    if let Some(peer) = token.strip_prefix("received:") {
        return Some(RouteQueryScope::Received {
            peer: Some(peer.parse().ok()?),
        });
    }
    token
        .strip_prefix("advertised:")
        .and_then(|peer| peer.parse().ok())
        .map(|peer| RouteQueryScope::Advertised { peer })
}

/// Canonical semantic identity of every route-listing predicate. OR filters
/// are sorted and deduplicated, prefixes are already network-normalized by
/// `RouteFilters::from_request`, and `longer` is ignored when no prefix exists.
/// The fixed-size digest bounds response tokens independently of filter count.
fn route_page_query_identity(afi_safi: i32, filters: &RouteFilters) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut bytes = Vec::new();
    bytes.push(1); // identity encoding version
    bytes.extend_from_slice(&afi_safi.to_be_bytes());
    match filters.prefix {
        None => bytes.push(0),
        Some(Prefix::V4(prefix)) => {
            bytes.push(4);
            bytes.extend_from_slice(&prefix.addr.octets());
            bytes.push(prefix.len);
        }
        Some(Prefix::V6(prefix)) => {
            bytes.push(6);
            bytes.extend_from_slice(&prefix.addr.octets());
            bytes.push(prefix.len);
        }
    }
    bytes.push(u8::from(filters.prefix.is_some() && filters.longer));
    bytes.extend_from_slice(&filters.origin_asn.to_be_bytes());

    let mut communities = filters.communities.clone();
    communities.sort_unstable();
    communities.dedup();
    bytes.extend_from_slice(
        &u64::try_from(communities.len())
            .expect("route filter count fits in u64")
            .to_be_bytes(),
    );
    for community in communities {
        bytes.extend_from_slice(&community.to_be_bytes());
    }

    bytes.push(u8::from(filters.large_community_filter_active));
    let mut large_communities = filters.large_communities.clone();
    large_communities.sort_unstable_by_key(|community| {
        (
            community.global_admin,
            community.local_data1,
            community.local_data2,
        )
    });
    large_communities.dedup();
    bytes.extend_from_slice(
        &u64::try_from(large_communities.len())
            .expect("large-community filter count fits in u64")
            .to_be_bytes(),
    );
    for community in large_communities {
        bytes.extend_from_slice(&community.global_admin.to_be_bytes());
        bytes.extend_from_slice(&community.local_data1.to_be_bytes());
        bytes.extend_from_slice(&community.local_data2.to_be_bytes());
    }

    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

/// Encode a self-contained opaque cursor. Scope binding rejects cross-RPC or
/// cross-peer reuse; the process-local version makes mutation a visible
/// restart instead of a silently skipped or duplicated row.
fn encode_route_page_token(
    scope: RouteQueryScope,
    query_identity: &str,
    key: &RouteQueryKey,
    version: RoutePageVersion,
) -> String {
    let (prefix, peer, path_id) = key;
    let (addr, len) = prefix_parts(*prefix);
    format!(
        "rp3|{:016x}|{:016x}|{}|{query_identity}|{addr}/{len}|{peer}|{path_id}",
        version.epoch,
        version.generation,
        route_page_scope_token(scope)
    )
}

fn decode_route_page_token(token: &str) -> Result<RoutePageCursor, Status> {
    let invalid = || Status::invalid_argument("invalid page_token");
    let mut parts = token.split('|');
    let (
        Some("rp3"),
        Some(epoch),
        Some(generation),
        Some(scope),
        Some(query_identity),
        Some(prefix),
        Some(peer),
        Some(path_id),
        None,
    ) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    )
    else {
        return Err(invalid());
    };
    let epoch = u64::from_str_radix(epoch, 16).map_err(|_| invalid())?;
    let generation = u64::from_str_radix(generation, 16).map_err(|_| invalid())?;
    let scope = parse_route_page_scope_token(scope).ok_or_else(invalid)?;
    if query_identity.len() != 64
        || !query_identity
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid());
    }
    let (addr, len) = prefix.split_once('/').ok_or_else(invalid)?;
    let len: u32 = len.parse().map_err(|_| invalid())?;
    let prefix = parse_prefix_request(addr, len).map_err(|_| invalid())?;
    let peer: IpAddr = peer.parse().map_err(|_| invalid())?;
    let path_id: u32 = path_id.parse().map_err(|_| invalid())?;
    Ok(RoutePageCursor {
        scope,
        query_identity: query_identity.to_string(),
        after: (prefix, peer, path_id),
        version: RoutePageVersion { epoch, generation },
    })
}

/// Build the row filter evaluated inside the RIB task. `None` when
/// neither the family filter nor the route filters narrow the scope, so
/// the actor skips per-route predicate calls entirely.
fn build_route_query_filter(afi_safi: i32, filters: RouteFilters) -> Option<RouteQueryFilter> {
    if filters.is_empty() && family_filter_is_noop(afi_safi) {
        return None;
    }
    Some(Box::new(move |route| {
        route_matches_family(route, afi_safi) && filters.matches(route)
    }))
}

fn route_page_to_response(
    page: &RoutePage,
    scope: RouteQueryScope,
    query_identity: &str,
    best: bool,
) -> proto::ListRoutesResponse {
    let next_page_token = if page.has_more {
        page.routes
            .last()
            .map(|route| {
                encode_route_page_token(
                    scope,
                    query_identity,
                    &route_query_key(route),
                    page.version,
                )
            })
            .unwrap_or_default()
    } else {
        String::new()
    };
    proto::ListRoutesResponse {
        routes: page
            .routes
            .iter()
            .map(|route| route_to_proto(route, best))
            .collect(),
        next_page_token,
        total_count: page.total,
        page_version: Some(proto::RoutePageVersion {
            epoch: page.version.epoch,
            generation: page.version.generation,
        }),
    }
}

fn parse_prefix_request(prefix: &str, prefix_length: u32) -> Result<Prefix, Status> {
    let addr: IpAddr = prefix
        .parse()
        .map_err(|e| Status::invalid_argument(format!("invalid prefix address: {e}")))?;
    Ok(match addr {
        IpAddr::V4(_) if prefix_length > 32 => {
            return Err(Status::invalid_argument(
                "prefix_length must be 0-32 for IPv4",
            ));
        }
        IpAddr::V6(_) if prefix_length > 128 => {
            return Err(Status::invalid_argument(
                "prefix_length must be 0-128 for IPv6",
            ));
        }
        IpAddr::V4(v4) => Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
            v4,
            u8::try_from(prefix_length).expect("validated IPv4 prefix_length fits in u8"),
        )),
        IpAddr::V6(v6) => Prefix::V6(rustbgpd_wire::Ipv6Prefix::new(
            v6,
            u8::try_from(prefix_length).expect("validated IPv6 prefix_length fits in u8"),
        )),
    })
}

pub(crate) fn parse_route_event_prefix_filter(
    prefix: &str,
    prefix_length: u32,
    afi: Option<Afi>,
) -> Result<Option<Prefix>, Status> {
    if prefix.is_empty() {
        if prefix_length != 0 {
            return Err(Status::invalid_argument(
                "prefix_length requires a non-empty prefix",
            ));
        }
        return Ok(None);
    }

    let parsed = parse_prefix_request(prefix, prefix_length)?;
    match (afi, parsed) {
        (Some(Afi::Ipv4), Prefix::V6(_)) | (Some(Afi::Ipv6), Prefix::V4(_)) => Err(
            Status::invalid_argument("prefix family does not match requested address family"),
        ),
        (_, prefix) => Ok(Some(prefix)),
    }
}

fn explain_modifications_to_proto(
    modifications: &rustbgpd_policy::RouteModifications,
) -> proto::ExplainModifications {
    let (as_path_prepend_asn, as_path_prepend_count) = modifications
        .as_path_prepend
        .map_or((None, None), |(asn, count)| {
            (Some(asn), Some(u32::from(count)))
        });
    proto::ExplainModifications {
        set_local_pref: modifications.set_local_pref,
        set_med: modifications.set_med,
        set_next_hop: modifications
            .set_next_hop
            .as_ref()
            .map_or_else(String::new, |nh| match nh {
                rustbgpd_policy::NextHopAction::Self_ => "self".to_string(),
                rustbgpd_policy::NextHopAction::Specific(addr) => addr.to_string(),
            }),
        communities_add: modifications.communities_add.clone(),
        communities_remove: modifications.communities_remove.clone(),
        extended_communities_add: modifications
            .extended_communities_add
            .iter()
            .map(|ec| ec.as_u64())
            .collect(),
        extended_communities_remove: modifications
            .extended_communities_remove
            .iter()
            .map(|ec| ec.as_u64())
            .collect(),
        large_communities_add: modifications
            .large_communities_add
            .iter()
            .map(ToString::to_string)
            .collect(),
        large_communities_remove: modifications
            .large_communities_remove
            .iter()
            .map(ToString::to_string)
            .collect(),
        as_path_prepend_asn,
        as_path_prepend_count,
    }
}

fn explain_to_proto(explain: ExplainAdvertisedRoute) -> proto::ExplainAdvertisedRouteResponse {
    proto::ExplainAdvertisedRouteResponse {
        decision: match explain.decision {
            ExplainDecision::Advertise => proto::ExplainDecision::Advertise as i32,
            ExplainDecision::Deny => proto::ExplainDecision::Deny as i32,
            ExplainDecision::NoBestRoute => proto::ExplainDecision::NoBestRoute as i32,
            ExplainDecision::UnsupportedFamily => proto::ExplainDecision::UnsupportedFamily as i32,
        },
        peer_address: explain.peer.to_string(),
        prefix: explain.prefix.addr_string(),
        prefix_length: u32::from(explain.prefix.prefix_len()),
        next_hop: explain
            .next_hop
            .map_or_else(String::new, |nh| nh.to_string()),
        path_id: explain.path_id,
        route_peer_address: explain
            .route_peer
            .map_or_else(String::new, |peer| peer.to_string()),
        route_type: explain.route_type.map_or_else(String::new, |route_type| {
            match route_type {
                rustbgpd_policy::RouteType::Local => "local",
                rustbgpd_policy::RouteType::Internal => "internal",
                rustbgpd_policy::RouteType::External => "external",
            }
            .to_string()
        }),
        reasons: explain
            .reasons
            .into_iter()
            .map(|reason| proto::ExplainReason {
                code: reason.code.to_string(),
                message: reason.message,
            })
            .collect(),
        modifications: Some(explain_modifications_to_proto(&explain.modifications)),
        orr_vantage: explain
            .orr_vantage
            .map_or_else(String::new, |vantage| vantage.to_string()),
        orr_candidates: explain
            .orr_candidates
            .into_iter()
            .map(|candidate| proto::OrrExplainCandidate {
                peer_address: candidate.peer.to_string(),
                path_id: candidate.path_id,
                next_hop: candidate.next_hop.to_string(),
                cost: candidate.cost,
                selected: candidate.selected,
            })
            .collect(),
        gates: explain
            .gates
            .into_iter()
            .map(|step| proto::ExportGateStep {
                gate: step.gate.to_string(),
                code: step.code.to_string(),
                verdict: match step.verdict {
                    ExportGateVerdict::Pass => proto::ExportGateVerdict::Pass as i32,
                    ExportGateVerdict::Stop => proto::ExportGateVerdict::Stop as i32,
                    ExportGateVerdict::NotApplicable => {
                        proto::ExportGateVerdict::NotApplicable as i32
                    }
                },
                detail: step.detail,
            })
            .collect(),
        update_group_id: explain.update_group_id,
        already_advertised: explain.already_advertised,
        rd: explain.rd.map_or_else(String::new, |rd| rd.to_string()),
        source: explain.source.map(|source| proto::RouteSourceIdentity {
            peer_address: source.peer.to_string(),
            path_id: source.path_id,
        }),
    }
}

fn explain_best_path_to_proto(explain: ExplainBestPath) -> proto::ExplainBestPathResponse {
    proto::ExplainBestPathResponse {
        prefix: explain.prefix.addr_string(),
        prefix_length: u32::from(explain.prefix.prefix_len()),
        best_route: explain.best.as_ref().map(|r| route_to_proto(r, true)),
        // The step that selected the winner (vs the runner-up). A best
        // route with no competing candidates is the trivial winner:
        // "only_path". The no-best-route case never reaches this
        // conversion — the handler maps it to NOT_FOUND.
        best_reason: explain.best_reason.map_or_else(
            || {
                if explain.best.is_some() {
                    "only_path".to_string()
                } else {
                    String::new()
                }
            },
            |reason| reason.to_string(),
        ),
        best_reason_detail: explain.best_reason_detail,
        candidates: explain
            .candidates
            .into_iter()
            .map(|c| {
                // Candidates never include the winner (filtered in RIB manager).
                proto::BestPathCandidate {
                    route: Some(route_to_proto(&c.route, false)),
                    vs_best_reason: c.vs_best_reason.to_string(),
                    vs_best_ordering: match c.vs_best_ordering {
                        std::cmp::Ordering::Less => "better".to_string(),
                        std::cmp::Ordering::Equal => "equal".to_string(),
                        std::cmp::Ordering::Greater => "worse".to_string(),
                    },
                    advertised_path_id: c.advertised_path_id,
                    vs_best_detail: c.vs_best_detail,
                    multipath: c.multipath.to_string(),
                }
            })
            .collect(),
        peer_address: explain.peer.map(|p| p.to_string()).unwrap_or_default(),
        add_path_send_max: explain.add_path_send_max,
    }
}

fn route_to_proto(route: &Route, best: bool) -> proto::Route {
    let mut origin = 0u32;
    let mut as_path = Vec::new();
    let mut local_pref = 0u32;
    let mut med = 0u32;
    let mut communities = Vec::new();
    let mut extended_communities = Vec::new();
    let mut large_communities = Vec::new();

    for attr in route.attributes.iter() {
        match attr {
            PathAttribute::Origin(o) => origin = *o as u32,
            PathAttribute::AsPath(path) => {
                for segment in &path.segments {
                    let asns = match segment {
                        AsPathSegment::AsSequence(a) | AsPathSegment::AsSet(a) => a,
                    };
                    as_path.extend(asns);
                }
            }
            PathAttribute::LocalPref(lp) => local_pref = *lp,
            PathAttribute::Med(m) => med = *m,
            PathAttribute::Communities(c) => communities.extend(c),
            PathAttribute::ExtendedCommunities(ec) => {
                extended_communities.extend(ec.iter().map(|c| c.as_u64()));
            }
            PathAttribute::LargeCommunities(lc) => {
                large_communities.extend(lc.iter().map(ToString::to_string));
            }
            _ => {}
        }
    }

    proto::Route {
        prefix: route.prefix.addr_string(),
        prefix_length: u32::from(route.prefix.prefix_len()),
        next_hop: route.next_hop.to_string(),
        peer_address: route.peer.to_string(),
        origin,
        as_path,
        local_pref,
        med,
        best,
        communities,
        extended_communities,
        large_communities,
        path_id: route.path_id,
        validation_state: route.validation_state.to_string(),
        aspa_state: route.aspa_state.to_string(),
        // GR stale flags, same population as the VPN/labeled/RTC/BGP-LS
        // route entries (LAN-347: unicast was the only family that
        // dropped them on conversion).
        stale: route.is_stale,
        llgr_stale: route.is_llgr_stale,
        // Distinguishes "explicit LOCAL_PREF attribute" from "no
        // attribute" — required for the M35 interop test to assert
        // that the RFC 8326 implicit demotion actually fired on a
        // tagged route (otherwise local_pref=0 is ambiguous between
        // "policy set it" and "no LOCAL_PREF on EBGP wire").
        local_pref_attr: route.local_pref_attr(),
        // Distinguishes "explicit MED attribute" from "no attribute" —
        // the bare `med` field encodes absent as 0 (LAN-313).
        med_attr: route.med_attr(),
        // Receive wall time recovered from the monotonic receive
        // instant, the same recovery the BMP Loc-RIB dump uses for its
        // RFC 9069 per-peer header timestamp. Approximation: `now()` and
        // `received_at.elapsed()` are two independent clock reads, so a
        // wall-clock step between them skews the recovered epoch by that
        // step. Acceptable for a display timestamp; not re-architected
        // into a single stored wall time.
        received_at_epoch_seconds: std::time::SystemTime::now()
            .checked_sub(route.received_at.elapsed())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs()),
    }
}

pub(crate) fn route_event_to_proto(event: rustbgpd_rib::RouteEvent) -> proto::RouteEvent {
    let event_type = match event.event_type {
        RouteEventType::Added => proto::RouteEventType::Added,
        RouteEventType::Withdrawn => proto::RouteEventType::Withdrawn,
        RouteEventType::BestChanged => proto::RouteEventType::BestChanged,
        RouteEventType::PolicyFiltered => proto::RouteEventType::PolicyFiltered,
    };

    proto::RouteEvent {
        event_type: event_type.into(),
        prefix: event.prefix.addr_string(),
        prefix_length: u32::from(event.prefix.prefix_len()),
        peer_address: event
            .peer
            .map_or_else(String::new, |p: IpAddr| p.to_string()),
        afi_safi: match event.prefix {
            Prefix::V4(_) => proto::AddressFamily::Ipv4Unicast,
            Prefix::V6(_) => proto::AddressFamily::Ipv6Unicast,
        }
        .into(),
        timestamp: event.timestamp,
        previous_peer_address: event
            .previous_peer
            .map_or_else(String::new, |p: IpAddr| p.to_string()),
        path_id: event.path_id,
        event_id: event.event_id,
        target_peer_address: event
            .target_peer
            .map_or_else(String::new, |p: IpAddr| p.to_string()),
        reason: event.reason,
    }
}

fn route_event_matches_watch_filter(
    event: &rustbgpd_rib::RouteEvent,
    afi_safi_filter: i32,
    peer_filter: Option<IpAddr>,
) -> bool {
    if afi_safi_filter != 0 {
        let is_v4 = matches!(event.prefix, Prefix::V4(_));
        let want_v4 = afi_safi_filter == proto::AddressFamily::Ipv4Unicast as i32;
        if is_v4 != want_v4 {
            return false;
        }
    }

    if let Some(filter_addr) = peer_filter {
        let matches_current = event.peer == Some(filter_addr);
        let matches_previous = event.previous_peer == Some(filter_addr);
        let matches_target = event.target_peer == Some(filter_addr);
        if !matches_current && !matches_previous && !matches_target {
            return false;
        }
    }

    true
}

pub(crate) fn route_event_afi_filter(afi_safi: i32) -> Result<Option<Afi>, Status> {
    match afi_safi {
        0 => Ok(None),
        x if x == proto::AddressFamily::Ipv4Unicast as i32 => Ok(Some(Afi::Ipv4)),
        x if x == proto::AddressFamily::Ipv6Unicast as i32 => Ok(Some(Afi::Ipv6)),
        _ => Err(Status::invalid_argument(
            "route event history supports only IPv4/IPv6 unicast families",
        )),
    }
}

#[tonic::async_trait]
impl proto::rib_service_server::RibService for RibService {
    type WatchRoutesStream =
        Pin<Box<dyn Stream<Item = Result<proto::RouteEvent, Status>> + Send + 'static>>;
    type WatchRouteEventsStream =
        Pin<Box<dyn Stream<Item = Result<proto::BgpEvent, Status>> + Send + 'static>>;

    async fn list_received_routes(
        &self,
        request: Request<proto::ListRoutesRequest>,
    ) -> Result<Response<proto::ListRoutesResponse>, Status> {
        let req = request.into_inner();
        validate_unicast_afi_safi(req.afi_safi)?;

        let peer = if req.neighbor_address.is_empty() {
            None
        } else {
            Some(
                req.neighbor_address
                    .parse::<IpAddr>()
                    .map_err(|e| Status::invalid_argument(format!("invalid address: {e}")))?,
            )
        };

        let filters = RouteFilters::from_request(&req)?;
        let query_identity = route_page_query_identity(req.afi_safi, &filters);
        let scope = RouteQueryScope::Received { peer };
        let (after, expected_version, page_size) =
            parse_route_page_params(&req, scope, &query_identity)?;
        let page = self
            .query_routes_page(
                scope,
                build_route_query_filter(req.afi_safi, filters),
                after,
                expected_version,
                page_size,
            )
            .await?;
        Ok(Response::new(route_page_to_response(
            &page,
            scope,
            &query_identity,
            false,
        )))
    }

    async fn list_best_routes(
        &self,
        request: Request<proto::ListRoutesRequest>,
    ) -> Result<Response<proto::ListRoutesResponse>, Status> {
        let req = request.into_inner();
        validate_unicast_afi_safi(req.afi_safi)?;
        let filters = RouteFilters::from_request(&req)?;
        let query_identity = route_page_query_identity(req.afi_safi, &filters);
        let scope = RouteQueryScope::Best;
        let (after, expected_version, page_size) =
            parse_route_page_params(&req, scope, &query_identity)?;
        let page = self
            .query_routes_page(
                scope,
                build_route_query_filter(req.afi_safi, filters),
                after,
                expected_version,
                page_size,
            )
            .await?;
        Ok(Response::new(route_page_to_response(
            &page,
            scope,
            &query_identity,
            true,
        )))
    }

    async fn list_advertised_routes(
        &self,
        request: Request<proto::ListRoutesRequest>,
    ) -> Result<Response<proto::ListRoutesResponse>, Status> {
        let req = request.into_inner();
        validate_unicast_afi_safi(req.afi_safi)?;

        if req.neighbor_address.is_empty() {
            return Err(Status::invalid_argument(
                "neighbor_address is required for advertised routes",
            ));
        }

        let peer: IpAddr = req
            .neighbor_address
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid address: {e}")))?;

        let filters = RouteFilters::from_request(&req)?;
        let query_identity = route_page_query_identity(req.afi_safi, &filters);
        let scope = RouteQueryScope::Advertised { peer };
        let (after, expected_version, page_size) =
            parse_route_page_params(&req, scope, &query_identity)?;
        let page = self
            .query_routes_page(
                scope,
                build_route_query_filter(req.afi_safi, filters),
                after,
                expected_version,
                page_size,
            )
            .await?;
        Ok(Response::new(route_page_to_response(
            &page,
            scope,
            &query_identity,
            false,
        )))
    }

    async fn explain_advertised_route(
        &self,
        request: Request<proto::ExplainAdvertisedRouteRequest>,
    ) -> Result<Response<proto::ExplainAdvertisedRouteResponse>, Status> {
        let req = request.into_inner();
        let peer: IpAddr = req
            .peer_address
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid address: {e}")))?;
        let prefix = parse_prefix_request(&req.prefix, req.prefix_length)?;
        let rd = if req.rd.is_empty() {
            None
        } else {
            Some(
                req.rd
                    .parse::<rustbgpd_wire::RouteDistinguisher>()
                    .map_err(|e| Status::invalid_argument(format!("invalid rd: {e}")))?,
            )
        };
        if req.labeled && rd.is_some() {
            return Err(Status::invalid_argument(
                "rd and labeled are mutually exclusive: a route is VPN or labeled-unicast, not both",
            ));
        }
        if req.source.is_some() && (rd.is_some() || req.labeled) {
            return Err(Status::invalid_argument(
                "source is mutually exclusive with rd and labeled",
            ));
        }
        let source = req
            .source
            .map(|source| {
                source
                    .peer_address
                    .parse::<IpAddr>()
                    .map(|peer| RouteSourceIdentity {
                        peer,
                        path_id: source.path_id,
                    })
                    .map_err(|_| {
                        Status::invalid_argument(format!(
                            "invalid source peer_address: {}",
                            source.peer_address
                        ))
                    })
            })
            .transpose()?;
        let explain = self
            .query_explain_advertised_route(peer, prefix, rd, req.labeled, source)
            .await?;
        Ok(Response::new(explain_to_proto(explain)))
    }

    async fn explain_best_path(
        &self,
        request: Request<proto::ExplainBestPathRequest>,
    ) -> Result<Response<proto::ExplainBestPathResponse>, Status> {
        let req = request.into_inner();
        let prefix = parse_prefix_request(&req.prefix, req.prefix_length)?;
        let peer = if req.peer_address.is_empty() {
            None
        } else {
            Some(req.peer_address.parse::<IpAddr>().map_err(|_| {
                Status::invalid_argument(format!("invalid peer_address: {}", req.peer_address))
            })?)
        };
        let explain = self
            .query_explain_best_path(prefix, peer)
            .await?
            .ok_or_else(|| {
                Status::not_found(format!(
                    "peer {} not registered with this RIB",
                    req.peer_address
                ))
            })?;
        // No paths in any Adj-RIB-In for this prefix: there is nothing
        // to explain, so say so instead of returning an empty trace.
        if explain.best.is_none() {
            return Err(Status::not_found(format!(
                "no paths for prefix {}/{} in any Adj-RIB-In",
                req.prefix, req.prefix_length
            )));
        }
        Ok(Response::new(explain_best_path_to_proto(explain)))
    }

    async fn list_blackhole_discards(
        &self,
        _request: Request<proto::ListBlackholeDiscardsRequest>,
    ) -> Result<Response<proto::ListBlackholeDiscardsResponse>, Status> {
        Ok(Response::new(proto::ListBlackholeDiscardsResponse {
            discards: (self.blackhole_discard_snapshot)(),
        }))
    }

    async fn list_fib_routes(
        &self,
        request: Request<proto::ListFibRoutesRequest>,
    ) -> Result<Response<proto::ListFibRoutesResponse>, Status> {
        let req = request.into_inner();
        let filters = FibRouteFilters::from_request(&req)?;
        let page = parse_fib_page_params(&req).map_err(Status::invalid_argument)?;
        let mut routes: Vec<proto::FibRouteStatus> = (self.fib_route_snapshot)()
            .into_iter()
            .filter(|route| filters.matches(route))
            .collect();
        if page.is_some() {
            sort_fib_routes(&mut routes);
        }
        if let Some(page) = page.as_ref()
            && page.offset > routes.len()
        {
            return Err(Status::invalid_argument("page_token is out of range"));
        }
        Ok(Response::new(build_fib_response(routes, page)))
    }

    async fn list_route_events(
        &self,
        request: Request<proto::ListRouteEventsRequest>,
    ) -> Result<Response<proto::ListRouteEventsResponse>, Status> {
        let req = request.into_inner();
        let afi = route_event_afi_filter(req.afi_safi)?;
        let prefix = parse_route_event_prefix_filter(&req.prefix, req.prefix_length, afi)?;
        let peer: Option<IpAddr> = if req.neighbor_address.is_empty() {
            None
        } else {
            Some(
                req.neighbor_address
                    .parse()
                    .map_err(|e| Status::invalid_argument(format!("invalid address: {e}")))?,
            )
        };

        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::QueryRouteEventHistory {
                peer,
                afi,
                prefix,
                limit: req.limit as usize,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("RIB manager unavailable"))?;

        let events = reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?;
        Ok(Response::new(proto::ListRouteEventsResponse {
            events: events.into_iter().map(route_event_to_proto).collect(),
        }))
    }

    async fn watch_routes(
        &self,
        request: Request<proto::WatchRoutesRequest>,
    ) -> Result<Response<Self::WatchRoutesStream>, Status> {
        let req = request.into_inner();
        validate_unicast_afi_safi(req.afi_safi)?;

        let afi_safi_filter = req.afi_safi;
        let peer_filter: Option<IpAddr> = if req.neighbor_address.is_empty() {
            None
        } else {
            Some(
                req.neighbor_address
                    .parse()
                    .map_err(|e| Status::invalid_argument(format!("invalid address: {e}")))?,
            )
        };

        // Subscribe to route events from the RIB manager
        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::SubscribeRouteEvents { reply: reply_tx })
            .await
            .map_err(|_| Status::internal("RIB manager unavailable"))?;

        let broadcast_rx = reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?;

        let metrics = self.metrics.clone();
        let subscriber_guard = metrics.event_stream_subscriber_guard("watch_routes", "route");
        let stream = BroadcastStream::new(broadcast_rx).filter_map(move |result| match result {
            Ok(event) => {
                let _subscriber_guard = &subscriber_guard;
                route_event_matches_watch_filter(&event, afi_safi_filter, peer_filter)
                    .then(|| Ok(route_event_to_proto(event)))
            }
            Err(BroadcastStreamRecvError::Lagged(missed)) => {
                let _subscriber_guard = &subscriber_guard;
                metrics.record_event_stream_lagged("watch_routes", "route", missed);
                debug!(
                    missed,
                    "WatchRoutes subscriber lagged, skipping missed events"
                );
                None
            }
        });

        Ok(Response::new(Box::pin(stream)))
    }

    async fn watch_route_events(
        &self,
        request: Request<proto::WatchRoutesRequest>,
    ) -> Result<Response<Self::WatchRouteEventsStream>, Status> {
        let req = request.into_inner();
        validate_unicast_afi_safi(req.afi_safi)?;

        let afi_safi_filter = req.afi_safi;
        let peer_filter: Option<IpAddr> = if req.neighbor_address.is_empty() {
            None
        } else {
            Some(
                req.neighbor_address
                    .parse()
                    .map_err(|e| Status::invalid_argument(format!("invalid address: {e}")))?,
            )
        };

        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::SubscribeRouteEvents { reply: reply_tx })
            .await
            .map_err(|_| Status::internal("RIB manager unavailable"))?;

        let broadcast_rx = reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?;

        let metrics = self.metrics.clone();
        let subscriber_guard = metrics.event_stream_subscriber_guard("watch_route_events", "route");
        let stream = BroadcastStream::new(broadcast_rx).filter_map(move |result| match result {
            Ok(event) => {
                let _subscriber_guard = &subscriber_guard;
                route_event_matches_watch_filter(&event, afi_safi_filter, peer_filter)
                    .then(|| Ok(route_event_to_bgp_event(event)))
            }
            Err(BroadcastStreamRecvError::Lagged(missed)) => {
                let _subscriber_guard = &subscriber_guard;
                metrics.record_event_stream_lagged("watch_route_events", "route", missed);
                debug!(
                    missed,
                    "WatchRouteEvents subscriber lagged, emitting missed-event signal"
                );
                Some(Ok(stream_lag_bgp_event(
                    proto::EventCategory::Route,
                    missed,
                )))
            }
        });

        Ok(Response::new(Box::pin(stream)))
    }

    async fn list_flow_spec_routes(
        &self,
        request: Request<proto::ListFlowSpecRequest>,
    ) -> Result<Response<proto::ListFlowSpecResponse>, Status> {
        let req = request.into_inner();
        validate_flowspec_afi_safi(req.afi_safi)?;

        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::QueryFlowSpecRoutes { reply: reply_tx })
            .await
            .map_err(|_| Status::internal("RIB manager unavailable"))?;

        let all_routes = reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?;

        // Filter by AFI if requested
        let filtered: Vec<&FlowSpecRoute> = all_routes
            .iter()
            .filter(|r| {
                if req.afi_safi == proto::AddressFamily::Ipv4Flowspec as i32 {
                    r.afi == Afi::Ipv4
                } else if req.afi_safi == proto::AddressFamily::Ipv6Flowspec as i32 {
                    r.afi == Afi::Ipv6
                } else {
                    true // unspecified = all
                }
            })
            .collect();

        let routes: Vec<proto::FlowSpecRouteEntry> = filtered
            .iter()
            .map(|r| flowspec_route_to_proto(r))
            .collect();

        Ok(Response::new(proto::ListFlowSpecResponse { routes }))
    }

    async fn list_evpn_routes(
        &self,
        request: Request<proto::ListEvpnRequest>,
    ) -> Result<Response<proto::ListEvpnResponse>, Status> {
        let req = request.into_inner();
        if req.route_type_filter > 5 {
            return Err(Status::invalid_argument(format!(
                "invalid route_type_filter {}: expected 0 or 1..=5",
                req.route_type_filter
            )));
        }
        let peer_filter = parse_optional_peer_filter(&req.peer_filter)?;
        let rd_filter = if req.rd_filter.is_empty() {
            None
        } else {
            Some(
                req.rd_filter
                    .parse::<rustbgpd_wire::RouteDistinguisher>()
                    .map_err(|error| {
                        Status::invalid_argument(format!(
                            "invalid rd_filter {:?}: {error}",
                            req.rd_filter
                        ))
                    })?,
            )
        };

        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::QueryEvpnRoutes { reply: reply_tx })
            .await
            .map_err(|_| Status::internal("RIB manager unavailable"))?;

        let all_routes = reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?;

        let type_filter = req.route_type_filter;

        let routes: Vec<proto::EvpnRouteEntry> = all_routes
            .iter()
            .filter(|r| {
                if type_filter != 0 && u32::from(r.route_type()) != type_filter {
                    return false;
                }
                if peer_filter.is_some_and(|peer| r.peer != peer) {
                    return false;
                }
                if let Some(rd_filter) = rd_filter {
                    let entry_rd = match &r.route {
                        EvpnRoute::EadPerEs(e) => e.rd,
                        EvpnRoute::EadPerEvi(e) => e.rd,
                        EvpnRoute::MacIp(e) => e.rd,
                        EvpnRoute::Imet(e) => e.rd,
                        EvpnRoute::Es(e) => e.rd,
                        EvpnRoute::IpPrefix(e) => e.rd,
                        // Unmodeled route types never match an RD filter.
                        _ => return false,
                    };
                    if entry_rd != rd_filter {
                        return false;
                    }
                }
                true
            })
            .map(evpn_route_to_proto)
            .collect();

        Ok(Response::new(proto::ListEvpnResponse { routes }))
    }

    async fn list_bgp_ls_routes(
        &self,
        request: Request<proto::ListBgpLsRequest>,
    ) -> Result<Response<proto::ListBgpLsResponse>, Status> {
        let req = request.into_inner();
        if !matches!(
            req.afi_safi,
            x if x == proto::AddressFamily::Unspecified as i32
                || x == proto::AddressFamily::BgpLs as i32
                || x == proto::AddressFamily::BgpLsVpn as i32
        ) {
            return Err(Status::invalid_argument(format!(
                "invalid afi_safi {}: expected BGP-LS, BGP-LS VPN, or unspecified",
                req.afi_safi
            )));
        }
        let peer_filter = parse_optional_peer_filter(&req.peer_filter)?;

        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::QueryBgpLsRoutes { reply: reply_tx })
            .await
            .map_err(|_| Status::internal("RIB manager unavailable"))?;

        let all_routes = reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?;

        let family_filter = req.afi_safi;
        let type_filter = req.nlri_type_filter;
        let routes = all_routes
            .iter()
            .filter(|route| {
                if family_filter != proto::AddressFamily::Unspecified as i32
                    && bgpls_family_to_proto(route.family) as i32 != family_filter
                {
                    return false;
                }
                if peer_filter.is_some_and(|peer| route.peer != peer) {
                    return false;
                }
                if type_filter != 0 && u32::from(route.nlri.nlri_type.as_u16()) != type_filter {
                    return false;
                }
                true
            })
            .map(bgpls_route_to_proto)
            .collect();

        Ok(Response::new(proto::ListBgpLsResponse { routes }))
    }

    async fn list_vpn_routes(
        &self,
        request: Request<proto::ListVpnRoutesRequest>,
    ) -> Result<Response<proto::ListVpnRoutesResponse>, Status> {
        let req = request.into_inner();
        let peer_filter = parse_optional_peer_filter(&req.peer_filter)?;

        if !req.afi_safi.is_empty()
            && req.afi_safi != "l3vpn_ipv4_unicast"
            && req.afi_safi != "l3vpn_ipv6_unicast"
        {
            return Err(Status::invalid_argument(format!(
                "unknown VPN family {:?}, expected \"l3vpn_ipv4_unicast\" or \"l3vpn_ipv6_unicast\"",
                req.afi_safi
            )));
        }

        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::QueryVpnRoutes { reply: reply_tx })
            .await
            .map_err(|_| Status::internal("RIB manager unavailable"))?;

        let all_routes = reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?;

        #[cfg(feature = "bench-internals")]
        let post_actor_started = Instant::now();
        let family_filter = req.afi_safi;
        let routes: Vec<_> = all_routes
            .iter()
            .filter(|route| {
                if !family_filter.is_empty() && vpn_family_label(route) != family_filter {
                    return false;
                }
                if peer_filter.is_some_and(|peer| route.peer != peer) {
                    return false;
                }
                true
            })
            .map(vpn_route_to_proto)
            .collect();
        #[cfg(feature = "bench-internals")]
        if let Some(receipts) = &self.vpn_query_bench_receipts {
            let post_actor_ns =
                u64::try_from(post_actor_started.elapsed().as_nanos()).unwrap_or(u64::MAX);
            let _ = receipts.try_send(VpnQueryServiceReceipt {
                post_actor_ns,
                returned_rows: routes.len(),
            });
        }

        Ok(Response::new(proto::ListVpnRoutesResponse { routes }))
    }

    async fn list_labeled_routes(
        &self,
        request: Request<proto::ListLabeledRoutesRequest>,
    ) -> Result<Response<proto::ListLabeledRoutesResponse>, Status> {
        let req = request.into_inner();
        let peer_filter = parse_optional_peer_filter(&req.peer_filter)?;

        if !req.afi_safi.is_empty()
            && req.afi_safi != "ipv4_labeled_unicast"
            && req.afi_safi != "ipv6_labeled_unicast"
        {
            return Err(Status::invalid_argument(format!(
                "unknown labeled family {:?}, expected \"ipv4_labeled_unicast\" or \"ipv6_labeled_unicast\"",
                req.afi_safi
            )));
        }

        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::QueryLabeledRoutes { reply: reply_tx })
            .await
            .map_err(|_| Status::internal("RIB manager unavailable"))?;

        let all_routes = reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?;

        let family_filter = req.afi_safi;
        let routes = all_routes
            .iter()
            .filter(|route| {
                if !family_filter.is_empty() && labeled_family_label(route) != family_filter {
                    return false;
                }
                if peer_filter.is_some_and(|peer| route.peer != peer) {
                    return false;
                }
                true
            })
            .map(labeled_route_to_proto)
            .collect();

        Ok(Response::new(proto::ListLabeledRoutesResponse { routes }))
    }

    async fn list_rtc_routes(
        &self,
        request: Request<proto::ListRtcRoutesRequest>,
    ) -> Result<Response<proto::ListRtcRoutesResponse>, Status> {
        let req = request.into_inner();
        let peer_filter = parse_optional_peer_filter(&req.peer_filter)?;

        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::QueryRtcRoutes { reply: reply_tx })
            .await
            .map_err(|_| Status::internal("RIB manager unavailable"))?;

        let all_routes = reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?;

        let routes = all_routes
            .iter()
            .filter(|route| peer_filter.is_none_or(|peer| route.peer == peer))
            .map(rtc_route_to_proto)
            .collect();

        Ok(Response::new(proto::ListRtcRoutesResponse { routes }))
    }

    async fn list_topology_nodes(
        &self,
        _request: Request<proto::ListTopologyNodesRequest>,
    ) -> Result<Response<proto::ListTopologyNodesResponse>, Status> {
        let snapshot = self.query_orr_topology().await?;
        Ok(Response::new(proto::ListTopologyNodesResponse {
            nodes: snapshot.nodes.iter().map(topology_node_to_proto).collect(),
        }))
    }

    async fn list_topology_links(
        &self,
        _request: Request<proto::ListTopologyLinksRequest>,
    ) -> Result<Response<proto::ListTopologyLinksResponse>, Status> {
        let snapshot = self.query_orr_topology().await?;
        Ok(Response::new(proto::ListTopologyLinksResponse {
            links: snapshot.links.iter().map(topology_link_to_proto).collect(),
        }))
    }

    async fn list_orr_status(
        &self,
        _request: Request<proto::ListOrrStatusRequest>,
    ) -> Result<Response<proto::ListOrrStatusResponse>, Status> {
        let snapshot = self.query_orr_status().await?;
        Ok(Response::new(proto::ListOrrStatusResponse {
            vantages: snapshot
                .vantages
                .iter()
                .map(orr_vantage_status_to_proto)
                .collect(),
            topology_nodes: snapshot.topology_nodes,
            topology_links: snapshot.topology_links,
            input_diagnostics: Some(proto::OrrInputDiagnostics {
                included_default: snapshot.input_diagnostics.included_default,
                excluded_nondefault: snapshot.input_diagnostics.excluded_nondefault,
                malformed_topology: snapshot.input_diagnostics.malformed_topology,
                malformed_attribute_29: snapshot.input_diagnostics.malformed_attribute_29,
                default_with_ignored_flex_algo: snapshot
                    .input_diagnostics
                    .default_with_ignored_flex_algo,
            }),
        }))
    }

    async fn set_fib_table(
        &self,
        request: Request<proto::SetFibTableRequest>,
    ) -> Result<Response<proto::ListFibTablesResponse>, Status> {
        if let Some(status) = crate::server::read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let table = request
            .into_inner()
            .table
            .ok_or_else(|| Status::invalid_argument("set_fib_table: missing table definition"))?;
        dispatch_fib_table_control(
            self.fib_table_control.as_ref(),
            FibTableControlRequest::Set(table),
        )
        .await
    }

    async fn delete_fib_table(
        &self,
        request: Request<proto::DeleteFibTableRequest>,
    ) -> Result<Response<proto::ListFibTablesResponse>, Status> {
        if let Some(status) = crate::server::read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let name = request.into_inner().name;
        if name.trim().is_empty() {
            return Err(Status::invalid_argument(
                "delete_fib_table: table name is required",
            ));
        }
        dispatch_fib_table_control(
            self.fib_table_control.as_ref(),
            FibTableControlRequest::Delete { name },
        )
        .await
    }

    async fn list_fib_tables(
        &self,
        _request: Request<proto::ListFibTablesRequest>,
    ) -> Result<Response<proto::ListFibTablesResponse>, Status> {
        // Read-only: no access-mode gate. The hook reports runtime availability
        // even when the reconciler is not running (configured-but-not-started).
        dispatch_fib_table_control(
            self.fib_table_control.as_ref(),
            FibTableControlRequest::List,
        )
        .await
    }
}

/// Forward a FIB-table CRUD request to the daemon control hook, mapping the
/// hook's typed error to a gRPC `Status`. A missing hook means the daemon was
/// built without FIB-table control (tests / non-gRPC builds).
async fn dispatch_fib_table_control(
    control: Option<&FibTableControlFn>,
    request: FibTableControlRequest,
) -> Result<Response<proto::ListFibTablesResponse>, Status> {
    let control = control.ok_or_else(|| {
        Status::failed_precondition(
            "FIB-table control is unavailable (the FIB reconciler was not started)",
        )
    })?;
    control(request)
        .await
        .map(Response::new)
        .map_err(FibTableControlError::into_status)
}

#[expect(
    clippy::too_many_lines,
    reason = "FlowSpec route conversion keeps every component and action mapping adjacent"
)]
fn flowspec_route_to_proto(route: &FlowSpecRoute) -> proto::FlowSpecRouteEntry {
    let mut as_path = Vec::new();
    let mut communities = Vec::new();
    let mut extended_communities = Vec::new();

    for attr in &route.attributes {
        match attr {
            PathAttribute::AsPath(path) => {
                for segment in &path.segments {
                    let asns = match segment {
                        AsPathSegment::AsSequence(a) | AsPathSegment::AsSet(a) => a,
                    };
                    as_path.extend(asns);
                }
            }
            PathAttribute::Communities(c) => communities.extend(c),
            PathAttribute::ExtendedCommunities(ec) => {
                extended_communities.extend(ec.iter().map(|c| c.as_u64()));
            }
            _ => {}
        }
    }

    let components: Vec<proto::FlowSpecComponent> = route
        .rule
        .components
        .iter()
        .map(|c| {
            use rustbgpd_wire::FlowSpecComponent as FC;
            match c {
                FC::DestinationPrefix(p) => proto::FlowSpecComponent {
                    r#type: 1,
                    prefix: format_flowspec_prefix(p),
                    value: String::new(),
                    offset: flowspec_prefix_offset(p),
                },
                FC::SourcePrefix(p) => proto::FlowSpecComponent {
                    r#type: 2,
                    prefix: format_flowspec_prefix(p),
                    value: String::new(),
                    offset: flowspec_prefix_offset(p),
                },
                FC::IpProtocol(ops) => proto::FlowSpecComponent {
                    r#type: 3,
                    prefix: String::new(),
                    value: format_numeric_ops(ops),
                    offset: 0,
                },
                FC::Port(ops) => proto::FlowSpecComponent {
                    r#type: 4,
                    prefix: String::new(),
                    value: format_numeric_ops(ops),
                    offset: 0,
                },
                FC::DestinationPort(ops) => proto::FlowSpecComponent {
                    r#type: 5,
                    prefix: String::new(),
                    value: format_numeric_ops(ops),
                    offset: 0,
                },
                FC::SourcePort(ops) => proto::FlowSpecComponent {
                    r#type: 6,
                    prefix: String::new(),
                    value: format_numeric_ops(ops),
                    offset: 0,
                },
                FC::IcmpType(ops) => proto::FlowSpecComponent {
                    r#type: 7,
                    prefix: String::new(),
                    value: format_numeric_ops(ops),
                    offset: 0,
                },
                FC::IcmpCode(ops) => proto::FlowSpecComponent {
                    r#type: 8,
                    prefix: String::new(),
                    value: format_numeric_ops(ops),
                    offset: 0,
                },
                FC::TcpFlags(ops) => proto::FlowSpecComponent {
                    r#type: 9,
                    prefix: String::new(),
                    value: format_bitmask_ops(ops),
                    offset: 0,
                },
                FC::PacketLength(ops) => proto::FlowSpecComponent {
                    r#type: 10,
                    prefix: String::new(),
                    value: format_numeric_ops(ops),
                    offset: 0,
                },
                FC::Dscp(ops) => proto::FlowSpecComponent {
                    r#type: 11,
                    prefix: String::new(),
                    value: format_numeric_ops(ops),
                    offset: 0,
                },
                FC::Fragment(ops) => proto::FlowSpecComponent {
                    r#type: 12,
                    prefix: String::new(),
                    value: format_bitmask_ops(ops),
                    offset: 0,
                },
                FC::FlowLabel(ops) => proto::FlowSpecComponent {
                    r#type: 13,
                    prefix: String::new(),
                    value: format_numeric_ops(ops),
                    offset: 0,
                },
                // Non-exhaustive: component types this build does not model
                // surface as type 0 with empty fields.
                _ => proto::FlowSpecComponent {
                    r#type: 0,
                    prefix: String::new(),
                    value: String::new(),
                    offset: 0,
                },
            }
        })
        .collect();

    // Extract FlowSpec actions from extended communities
    let actions: Vec<proto::FlowSpecAction> = route
        .attributes
        .iter()
        .filter_map(|attr| match attr {
            PathAttribute::ExtendedCommunities(ecs) => Some(ecs),
            _ => None,
        })
        .flatten()
        .filter_map(|ec| {
            use rustbgpd_wire::flowspec::FlowSpecAction as FA;
            let action = ec.as_flowspec_action()?;
            let inner = match action {
                FA::TrafficRateBytes { rate, .. } => {
                    proto::flow_spec_action::Action::TrafficRate(proto::FlowSpecTrafficRate {
                        rate,
                    })
                }
                FA::TrafficAction { sample, terminal } => {
                    proto::flow_spec_action::Action::TrafficAction(proto::FlowSpecTrafficAction {
                        sample,
                        terminal,
                    })
                }
                FA::TrafficMarking { dscp } => {
                    proto::flow_spec_action::Action::TrafficMarking(proto::FlowSpecTrafficMarking {
                        dscp: u32::from(dscp),
                    })
                }
                FA::Redirect2Octet { asn, value } => {
                    proto::flow_spec_action::Action::Redirect(proto::FlowSpecRedirect {
                        route_target: format!("{asn}:{value}"),
                    })
                }
                _ => return None,
            };
            Some(proto::FlowSpecAction {
                action: Some(inner),
            })
        })
        .collect();

    // FlowSpec routes never carry AFI L2VPN; map any unexpected variant
    // to UNSPECIFIED rather than panicking inside the async gRPC handler
    // (an `unreachable!` here would abort the task and drop the
    // connection, masking an upstream invariant violation as a transport
    // error). Debug builds still surface the bug via debug_assert.
    debug_assert!(
        !matches!(route.afi, Afi::L2Vpn),
        "FlowSpec route with AFI L2VPN — upstream invariant violation"
    );
    let afi_safi = match route.afi {
        Afi::Ipv4 => proto::AddressFamily::Ipv4Flowspec,
        Afi::Ipv6 => proto::AddressFamily::Ipv6Flowspec,
        _ => proto::AddressFamily::Unspecified,
    };

    proto::FlowSpecRouteEntry {
        components,
        actions,
        peer_address: route.peer.to_string(),
        afi_safi: afi_safi.into(),
        as_path,
        communities,
        extended_communities,
    }
}

fn bgpls_family_to_proto(family: BgpLsFamily) -> proto::AddressFamily {
    match family {
        BgpLsFamily::LinkState => proto::AddressFamily::BgpLs,
        BgpLsFamily::LinkStateVpn => proto::AddressFamily::BgpLsVpn,
    }
}

fn bgpls_family_label(family: BgpLsFamily) -> &'static str {
    match family {
        BgpLsFamily::LinkState => "linkstate",
        BgpLsFamily::LinkStateVpn => "linkstate_vpn",
    }
}

fn bgpls_nlri_type_name(nlri_type: BgpLsNlriType) -> String {
    match nlri_type {
        BgpLsNlriType::Node => "node".to_string(),
        BgpLsNlriType::Link => "link".to_string(),
        BgpLsNlriType::Ipv4TopologyPrefix => "ipv4_topology_prefix".to_string(),
        BgpLsNlriType::Ipv6TopologyPrefix => "ipv6_topology_prefix".to_string(),
        BgpLsNlriType::Unknown(value) => format!("unknown_{value}"),
        // Non-exhaustive: NLRI types this build does not model.
        _ => "unmodeled".to_string(),
    }
}

pub(crate) fn bgpls_route_to_proto(route: &BgpLsRibRoute) -> proto::BgpLsRouteEntry {
    let mut as_path = Vec::new();
    let mut communities = Vec::new();
    let mut extended_communities = Vec::new();
    let mut bgp_ls_attribute = Vec::new();

    for attr in route.attributes.iter() {
        match attr {
            PathAttribute::AsPath(path) => {
                for segment in &path.segments {
                    let asns = match segment {
                        AsPathSegment::AsSequence(a) | AsPathSegment::AsSet(a) => a,
                    };
                    as_path.extend(asns);
                }
            }
            PathAttribute::Communities(c) => communities.extend(c),
            PathAttribute::ExtendedCommunities(ecs) => {
                extended_communities.extend(ecs.iter().map(|ec| ec.as_u64()));
            }
            PathAttribute::Unknown(raw) if raw.type_code == 29 => {
                bgp_ls_attribute = raw.data.to_vec();
            }
            _ => {}
        }
    }

    proto::BgpLsRouteEntry {
        afi_safi: bgpls_family_to_proto(route.family) as i32,
        family: bgpls_family_label(route.family).to_string(),
        nlri_type: u32::from(route.nlri.nlri_type.as_u16()),
        nlri_type_name: bgpls_nlri_type_name(route.nlri.nlri_type),
        route_distinguisher: route.nlri.route_distinguisher.unwrap_or_default().to_vec(),
        payload: route.nlri.payload.to_vec(),
        descriptor: route
            .nlri
            .descriptor_bytes()
            .map_or_else(Vec::new, ToOwned::to_owned),
        next_hop: route.next_hop.to_string(),
        peer_address: route.peer.to_string(),
        as_path,
        communities,
        extended_communities,
        stale: route.is_stale,
        llgr_stale: route.is_llgr_stale,
        path_id: route.path_id,
        bgp_ls_attribute,
    }
}

fn vpn_family_label(route: &VpnRibRoute) -> &'static str {
    match route.family() {
        rustbgpd_wire::VpnAddressFamily::V4 => "l3vpn_ipv4_unicast",
        rustbgpd_wire::VpnAddressFamily::V6 => "l3vpn_ipv6_unicast",
    }
}

pub(crate) fn vpn_route_to_proto(route: &VpnRibRoute) -> proto::VpnRouteEntry {
    let mut as_path = Vec::new();
    let mut communities = Vec::new();
    let mut extended_communities = Vec::new();

    for attr in route.attributes.iter() {
        match attr {
            PathAttribute::AsPath(path) => {
                for segment in &path.segments {
                    let asns = match segment {
                        AsPathSegment::AsSequence(a) | AsPathSegment::AsSet(a) => a,
                    };
                    as_path.extend(asns);
                }
            }
            PathAttribute::Communities(c) => {
                communities.extend(c.iter().map(|c| format!("{}:{}", c >> 16, c & 0xFFFF)));
            }
            PathAttribute::ExtendedCommunities(ecs) => {
                extended_communities.extend(ecs.iter().map(ToString::to_string));
            }
            _ => {}
        }
    }

    proto::VpnRouteEntry {
        afi_safi: vpn_family_label(route).to_string(),
        route_distinguisher: route.nlri.route_distinguisher.0.to_vec(),
        route_distinguisher_str: route.nlri.route_distinguisher.to_string(),
        prefix: route.nlri.prefix.to_string(),
        labels: route.nlri.labels.iter().map(|l| l.label).collect(),
        next_hop: route.next_hop.to_string(),
        peer_address: route.peer.to_string(),
        as_path,
        communities,
        extended_communities,
        stale: route.is_stale,
        llgr_stale: route.is_llgr_stale,
        path_id: route.path_id,
    }
}

fn labeled_family_label(route: &LabeledRibRoute) -> &'static str {
    match route.nlri.family() {
        rustbgpd_wire::LabeledAddressFamily::V4 => "ipv4_labeled_unicast",
        rustbgpd_wire::LabeledAddressFamily::V6 => "ipv6_labeled_unicast",
    }
}

pub(crate) fn labeled_route_to_proto(route: &LabeledRibRoute) -> proto::LabeledRouteEntry {
    let mut as_path = Vec::new();
    let mut communities = Vec::new();
    let mut extended_communities = Vec::new();

    for attr in route.attributes.iter() {
        match attr {
            PathAttribute::AsPath(path) => {
                for segment in &path.segments {
                    let asns = match segment {
                        AsPathSegment::AsSequence(a) | AsPathSegment::AsSet(a) => a,
                    };
                    as_path.extend(asns);
                }
            }
            PathAttribute::Communities(c) => {
                communities.extend(c.iter().map(|c| format!("{}:{}", c >> 16, c & 0xFFFF)));
            }
            PathAttribute::ExtendedCommunities(ecs) => {
                extended_communities.extend(ecs.iter().map(ToString::to_string));
            }
            _ => {}
        }
    }

    proto::LabeledRouteEntry {
        afi_safi: labeled_family_label(route).to_string(),
        prefix: route.nlri.prefix.to_string(),
        labels: route.nlri.labels.iter().map(|l| l.label).collect(),
        next_hop: route.next_hop.to_string(),
        peer_address: route.peer.to_string(),
        as_path,
        communities,
        extended_communities,
        stale: route.is_stale,
        llgr_stale: route.is_llgr_stale,
        path_id: route.path_id,
    }
}

pub(crate) fn rtc_route_to_proto(route: &RtcRibRoute) -> proto::RtcRouteEntry {
    let mut as_path = Vec::new();
    let mut communities = Vec::new();

    for attr in route.attributes.iter() {
        match attr {
            PathAttribute::AsPath(path) => {
                for segment in &path.segments {
                    let asns = match segment {
                        AsPathSegment::AsSequence(a) | AsPathSegment::AsSet(a) => a,
                    };
                    as_path.extend(asns);
                }
            }
            PathAttribute::Communities(c) => {
                communities.extend(c.iter().map(|c| format!("{}:{}", c >> 16, c & 0xFFFF)));
            }
            _ => {}
        }
    }

    let route_target = if route.nlri.is_default() {
        String::new()
    } else {
        rustbgpd_wire::ExtendedCommunity::new(route.nlri.route_target_bits).to_string()
    };

    proto::RtcRouteEntry {
        is_default: route.nlri.is_default(),
        origin_as: route.nlri.origin_as,
        route_target,
        prefix_len: u32::from(route.nlri.prefix_len),
        next_hop: route.next_hop.to_string(),
        peer_address: route.peer.to_string(),
        as_path,
        communities,
        stale: route.is_stale,
        llgr_stale: route.is_llgr_stale,
        path_id: route.path_id,
    }
}

pub(crate) fn topology_node_to_proto(node: &OrrNodeSnapshot) -> proto::TopologyNodeEntry {
    proto::TopologyNodeEntry {
        key: node.key_hex.clone(),
        asn: node.asn.unwrap_or(0),
        bgp_ls_id: node.bgp_ls_id.unwrap_or(0),
        router_id: node.router_id_hex.clone(),
        link_count: node.link_count,
    }
}

pub(crate) fn orr_vantage_status_to_proto(
    status: &OrrVantageStatus,
) -> proto::OrrVantageStatusEntry {
    proto::OrrVantageStatusEntry {
        vantage: status.vantage.to_string(),
        resolved: status.resolved,
        node_key: status.node_key_hex.clone(),
        asn: status.asn.unwrap_or(0),
        bgp_ls_id: status.bgp_ls_id.unwrap_or(0),
        router_id: status.router_id_hex.clone(),
        reachable_nodes: status.reachable_nodes,
        peers: status.peers.iter().map(ToString::to_string).collect(),
    }
}

pub(crate) fn topology_link_to_proto(link: &OrrLinkSnapshot) -> proto::TopologyLinkEntry {
    proto::TopologyLinkEntry {
        local_key: link.local_key_hex.clone(),
        local_router_id: link.local_router_id_hex.clone(),
        remote_key: link.remote_key_hex.clone(),
        remote_router_id: link.remote_router_id_hex.clone(),
        cost: link.cost,
        addresses: link.addresses.clone(),
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "EVPN route conversion keeps per-route-type field mapping in one audited place"
)]
pub(crate) fn evpn_route_to_proto(route: &EvpnRibRoute) -> proto::EvpnRouteEntry {
    let mut as_path = Vec::new();
    let mut communities = Vec::new();
    let mut extended_communities = Vec::new();
    let mut tunnel_type = 0u32;

    for attr in route.attributes.iter() {
        match attr {
            PathAttribute::AsPath(path) => {
                for segment in &path.segments {
                    let asns = match segment {
                        AsPathSegment::AsSequence(a) | AsPathSegment::AsSet(a) => a,
                    };
                    as_path.extend(asns);
                }
            }
            PathAttribute::Communities(c) => {
                communities.extend(c);
            }
            PathAttribute::ExtendedCommunities(ecs) => {
                for ec in ecs {
                    extended_communities.push(ec.as_u64());
                    if let Some(tt) = ec.as_bgp_encapsulation() {
                        tunnel_type = u32::from(tt);
                    }
                }
            }
            _ => {}
        }
    }

    let (rd, esi, ethernet_tag, mac, ip, prefix, gateway, label, label2) = match &route.route {
        EvpnRoute::EadPerEs(e) => (
            e.rd.to_string(),
            e.esi.to_string(),
            e.ethernet_tag.to_string(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            e.label.value(),
            0,
        ),
        EvpnRoute::EadPerEvi(e) => (
            e.rd.to_string(),
            e.esi.to_string(),
            e.ethernet_tag.to_string(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            e.label.value(),
            0,
        ),
        EvpnRoute::MacIp(e) => (
            e.rd.to_string(),
            e.esi.to_string(),
            e.ethernet_tag.to_string(),
            e.mac.to_string(),
            e.ip.map(|ip| ip.to_string()).unwrap_or_default(),
            String::new(),
            String::new(),
            e.label1.value(),
            e.label2.map_or(0, |l| l.value()),
        ),
        EvpnRoute::Imet(e) => (
            e.rd.to_string(),
            String::new(),
            e.ethernet_tag.to_string(),
            String::new(),
            e.originator_ip.to_string(),
            String::new(),
            String::new(),
            0,
            0,
        ),
        EvpnRoute::Es(e) => (
            e.rd.to_string(),
            e.esi.to_string(),
            String::new(),
            String::new(),
            e.originator_ip.to_string(),
            String::new(),
            String::new(),
            0,
            0,
        ),
        EvpnRoute::IpPrefix(e) => (
            e.rd.to_string(),
            e.esi.to_string(),
            e.ethernet_tag.to_string(),
            String::new(),
            String::new(),
            e.prefix.to_string(),
            e.gateway.to_string(),
            e.label.value(),
            0,
        ),
        // Non-exhaustive: route types this build does not model render with
        // empty fields; the numeric route type is still reported alongside.
        _ => (
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            0,
            0,
        ),
    };

    proto::EvpnRouteEntry {
        route_type: u32::from(route.route_type()),
        rd,
        esi,
        ethernet_tag,
        mac,
        ip,
        prefix,
        gateway,
        label,
        label2,
        next_hop: route.next_hop.to_string(),
        peer_address: route.peer.to_string(),
        as_path,
        communities,
        extended_communities,
        tunnel_type,
    }
}

fn format_flowspec_prefix(p: &rustbgpd_wire::FlowSpecPrefix) -> String {
    match p {
        rustbgpd_wire::FlowSpecPrefix::V4(v4) => format!("{}/{}", v4.addr, v4.len),
        rustbgpd_wire::FlowSpecPrefix::V6(v6) => {
            format!("{}/{}", v6.prefix.addr, v6.prefix.len)
        }
    }
}

fn flowspec_prefix_offset(p: &rustbgpd_wire::FlowSpecPrefix) -> u32 {
    match p {
        rustbgpd_wire::FlowSpecPrefix::V4(_) => 0,
        rustbgpd_wire::FlowSpecPrefix::V6(v6) => u32::from(v6.offset),
    }
}

fn format_numeric_ops(ops: &[rustbgpd_wire::NumericMatch]) -> String {
    use std::fmt::Write;
    let mut rendered = String::new();
    for (idx, o) in ops.iter().enumerate() {
        if idx > 0 {
            if o.and_bit {
                rendered.push_str(" & ");
            } else {
                rendered.push_str(", ");
            }
        }
        let cmp = match (o.lt, o.gt, o.eq) {
            (false, false, true) => "==",
            (true, false, false) => "<",
            (false, true, false) => ">",
            (true, false, true) => "<=",
            (false, true, true) => ">=",
            (true, true, false) => "!=",
            _ => "?",
        };
        let _ = write!(rendered, "{cmp}{}", o.value);
    }
    rendered
}

fn format_bitmask_ops(ops: &[rustbgpd_wire::BitmaskMatch]) -> String {
    use std::fmt::Write;
    let mut rendered = String::new();
    for (idx, o) in ops.iter().enumerate() {
        if idx > 0 {
            if o.and_bit {
                rendered.push_str(" & ");
            } else {
                rendered.push_str(", ");
            }
        }
        if o.not_bit {
            rendered.push('!');
        }
        let _ = write!(rendered, "0x{:04x}", o.value);
        if o.match_bit {
            rendered.push_str("/match");
        }
    }
    rendered
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    use bytes::Bytes;
    use tokio::sync::broadcast;
    use tokio_stream::StreamExt;

    use rustbgpd_wire::{
        AsPath, Ipv4Prefix, Ipv6Prefix, RawAttribute, bgpls::decode_bgpls_vpn_nlri,
    };

    use super::*;
    use crate::test_support::metrics_text as gather_text;
    use proto::rib_service_server::RibService as _;

    fn make_service() -> RibService {
        let (tx, _rx) = mpsc::channel(16);
        RibService::new(tx)
    }

    fn bgpls_test_routes(peer: IpAddr) -> Vec<BgpLsRibRoute> {
        use rustbgpd_wire::bgpls::{decode_bgpls_nlri, decode_bgpls_vpn_nlri};

        let base = BgpLsRibRoute {
            family: BgpLsFamily::LinkState,
            nlri: decode_bgpls_nlri(&[0xfd, 0xe8, 0, 3, 0xaa, 0xbb, 0xcc])
                .unwrap()
                .pop()
                .unwrap(),
            next_hop: peer,
            peer,
            attributes: Arc::new(Vec::new()),
            received_at: Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ibgp,
            peer_router_id: Ipv4Addr::new(192, 0, 2, 1),
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
        };
        let vpn = BgpLsRibRoute {
            family: BgpLsFamily::LinkStateVpn,
            nlri: decode_bgpls_vpn_nlri(&[
                0xfd, 0xe8, 0, 11, // type, length = RD + opaque payload
                0, 0, 0xfd, 0xe8, 0, 0, 0, 100, 0xaa, 0xbb, 0xcc,
            ])
            .unwrap()
            .pop()
            .unwrap(),
            ..base.clone()
        };
        vec![base, vpn]
    }

    fn non_unicast_routes(
        peer: IpAddr,
    ) -> (
        EvpnRibRoute,
        Vec<BgpLsRibRoute>,
        VpnRibRoute,
        LabeledRibRoute,
        RtcRibRoute,
    ) {
        use rustbgpd_wire::{
            EthernetTagId, EvpnImet, LabeledNlri, MplsLabelEntry, VpnNlri, VpnPrefix,
        };
        let rd: rustbgpd_wire::RouteDistinguisher = "65000:100".parse().unwrap();
        let common = (
            peer,
            Arc::new(Vec::new()),
            Instant::now(),
            rustbgpd_rib::RouteOrigin::Ibgp,
            Ipv4Addr::new(192, 0, 2, 1),
        );
        let evpn = EvpnRibRoute {
            route: EvpnRoute::Imet(EvpnImet {
                rd,
                ethernet_tag: EthernetTagId(100),
                originator_ip: "2001:db8::10".parse().unwrap(),
            }),
            next_hop: peer,
            link_local_next_hop: None,
            peer: common.0,
            attributes: Arc::clone(&common.1),
            received_at: common.2,
            origin_type: common.3,
            peer_router_id: common.4,
            is_stale: false,
            is_llgr_stale: false,
        };
        let bgpls = bgpls_test_routes(peer);
        let vpn = VpnRibRoute {
            nlri: VpnNlri {
                labels: vec![MplsLabelEntry::try_new(16_000, 0, true).unwrap()],
                route_distinguisher: rd,
                prefix: VpnPrefix::v6("2001:db8:100::".parse::<Ipv6Addr>().unwrap(), 64).unwrap(),
            },
            next_hop: peer,
            link_local_next_hop: None,
            peer: common.0,
            attributes: Arc::clone(&common.1),
            received_at: common.2,
            origin_type: common.3,
            peer_router_id: common.4,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
        };
        let labeled = LabeledRibRoute {
            nlri: LabeledNlri {
                labels: vec![MplsLabelEntry::try_new(16_001, 0, true).unwrap()],
                prefix: Prefix::V6(Ipv6Prefix::new("2001:db8:200::".parse().unwrap(), 64)),
            },
            next_hop: peer,
            link_local_next_hop: None,
            peer: common.0,
            attributes: Arc::clone(&common.1),
            received_at: common.2,
            origin_type: common.3,
            peer_router_id: common.4,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
        };
        let rtc = RtcRibRoute {
            nlri: rustbgpd_wire::RtcNlri::DEFAULT,
            next_hop: peer,
            peer: common.0,
            attributes: common.1,
            received_at: common.2,
            origin_type: common.3,
            peer_router_id: common.4,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
        };
        (evpn, bgpls, vpn, labeled, rtc)
    }

    fn non_unicast_service(peer: IpAddr) -> RibService {
        let routes = non_unicast_routes(peer);
        let (tx, mut rx) = mpsc::channel(16);
        tokio::spawn(async move {
            while let Some(update) = rx.recv().await {
                match update {
                    RibUpdate::QueryEvpnRoutes { reply } => {
                        let _ = reply.send(vec![routes.0.clone()]);
                    }
                    RibUpdate::QueryBgpLsRoutes { reply } => {
                        let _ = reply.send(routes.1.clone());
                    }
                    RibUpdate::QueryVpnRoutes { reply } => {
                        let _ = reply.send(vec![routes.2.clone()]);
                    }
                    RibUpdate::QueryLabeledRoutes { reply } => {
                        let _ = reply.send(vec![routes.3.clone()]);
                    }
                    RibUpdate::QueryRtcRoutes { reply } => {
                        let _ = reply.send(vec![routes.4.clone()]);
                    }
                    _ => panic!("unexpected RIB update"),
                }
            }
        });
        RibService::new(tx)
    }

    fn counting_non_unicast_service() -> (RibService, Arc<AtomicUsize>, tokio::task::JoinHandle<()>)
    {
        let (tx, mut rx) = mpsc::channel(16);
        let queries = Arc::new(AtomicUsize::new(0));
        let actor_queries = Arc::clone(&queries);
        let actor = tokio::spawn(async move {
            while let Some(update) = rx.recv().await {
                actor_queries.fetch_add(1, Ordering::Relaxed);
                match update {
                    RibUpdate::QueryEvpnRoutes { reply } => {
                        let _ = reply.send(Vec::new());
                    }
                    RibUpdate::QueryBgpLsRoutes { reply } => {
                        let _ = reply.send(Vec::new());
                    }
                    RibUpdate::QueryVpnRoutes { reply } => {
                        let _ = reply.send(Vec::new());
                    }
                    RibUpdate::QueryLabeledRoutes { reply } => {
                        let _ = reply.send(Vec::new());
                    }
                    RibUpdate::QueryRtcRoutes { reply } => {
                        let _ = reply.send(Vec::new());
                    }
                    _ => panic!("unexpected RIB update"),
                }
            }
        });
        (RibService::new(tx), queries, actor)
    }

    async fn assert_empty_non_unicast_filters_noop(svc: &RibService) {
        assert_eq!(
            svc.list_evpn_routes(Request::new(proto::ListEvpnRequest::default()))
                .await
                .unwrap()
                .into_inner()
                .routes
                .len(),
            1
        );
        assert_eq!(
            svc.list_bgp_ls_routes(Request::new(proto::ListBgpLsRequest::default()))
                .await
                .unwrap()
                .into_inner()
                .routes
                .len(),
            2
        );
        assert_eq!(
            svc.list_vpn_routes(Request::new(proto::ListVpnRoutesRequest::default()))
                .await
                .unwrap()
                .into_inner()
                .routes
                .len(),
            1
        );
        assert_eq!(
            svc.list_labeled_routes(Request::new(proto::ListLabeledRoutesRequest::default()))
                .await
                .unwrap()
                .into_inner()
                .routes
                .len(),
            1
        );
        assert_eq!(
            svc.list_rtc_routes(Request::new(proto::ListRtcRoutesRequest::default()))
                .await
                .unwrap()
                .into_inner()
                .routes
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn non_unicast_peer_and_rd_filters_are_typed_and_empty_is_noop() {
        let peer: IpAddr = "2001:db8::1".parse().unwrap();
        let expanded_peer = "2001:0db8:0:0:0:0:0:1";
        let svc = non_unicast_service(peer);

        let evpn = svc
            .list_evpn_routes(Request::new(proto::ListEvpnRequest {
                route_type_filter: 3,
                peer_filter: expanded_peer.to_string(),
                rd_filter: "065000:000100".to_string(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(evpn.routes.len(), 1);
        let bgpls = svc
            .list_bgp_ls_routes(Request::new(proto::ListBgpLsRequest {
                afi_safi: proto::AddressFamily::BgpLs as i32,
                peer_filter: expanded_peer.to_string(),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(bgpls.routes.len(), 1);
        assert_eq!(
            svc.list_bgp_ls_routes(Request::new(proto::ListBgpLsRequest {
                afi_safi: proto::AddressFamily::BgpLsVpn as i32,
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner()
            .routes
            .len(),
            1
        );
        let vpn = svc
            .list_vpn_routes(Request::new(proto::ListVpnRoutesRequest {
                peer_filter: expanded_peer.to_string(),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(vpn.routes.len(), 1);
        let labeled = svc
            .list_labeled_routes(Request::new(proto::ListLabeledRoutesRequest {
                peer_filter: expanded_peer.to_string(),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(labeled.routes.len(), 1);
        let rtc = svc
            .list_rtc_routes(Request::new(proto::ListRtcRoutesRequest {
                peer_filter: expanded_peer.to_string(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(rtc.routes.len(), 1);

        assert_empty_non_unicast_filters_noop(&svc).await;
    }

    #[tokio::test]
    async fn invalid_non_unicast_filters_fail_before_rib_query() {
        let (svc, queries, actor) = counting_non_unicast_service();

        for status in [
            svc.list_evpn_routes(Request::new(proto::ListEvpnRequest {
                peer_filter: "not-an-ip".to_string(),
                ..Default::default()
            }))
            .await
            .unwrap_err(),
            svc.list_bgp_ls_routes(Request::new(proto::ListBgpLsRequest {
                peer_filter: "not-an-ip".to_string(),
                ..Default::default()
            }))
            .await
            .unwrap_err(),
            svc.list_vpn_routes(Request::new(proto::ListVpnRoutesRequest {
                peer_filter: "not-an-ip".to_string(),
                ..Default::default()
            }))
            .await
            .unwrap_err(),
            svc.list_labeled_routes(Request::new(proto::ListLabeledRoutesRequest {
                peer_filter: "not-an-ip".to_string(),
                ..Default::default()
            }))
            .await
            .unwrap_err(),
            svc.list_rtc_routes(Request::new(proto::ListRtcRoutesRequest {
                peer_filter: "not-an-ip".to_string(),
            }))
            .await
            .unwrap_err(),
        ] {
            assert_eq!(status.code(), tonic::Code::InvalidArgument);
            assert!(status.message().contains("peer_filter"));
        }

        for (status, field) in [
            (
                svc.list_evpn_routes(Request::new(proto::ListEvpnRequest {
                    rd_filter: "not-an-rd".to_string(),
                    ..Default::default()
                }))
                .await
                .unwrap_err(),
                "rd_filter",
            ),
            (
                svc.list_evpn_routes(Request::new(proto::ListEvpnRequest {
                    route_type_filter: 6,
                    ..Default::default()
                }))
                .await
                .unwrap_err(),
                "route_type_filter",
            ),
            (
                svc.list_bgp_ls_routes(Request::new(proto::ListBgpLsRequest {
                    afi_safi: 99,
                    ..Default::default()
                }))
                .await
                .unwrap_err(),
                "afi_safi",
            ),
        ] {
            assert_eq!(status.code(), tonic::Code::InvalidArgument);
            assert!(status.message().contains(field));
        }

        drop(svc);
        actor.await.unwrap();
        assert_eq!(
            queries.load(Ordering::Relaxed),
            0,
            "invalid filters must not query the RIB actor"
        );
    }

    fn fib_table_proto(name: &str) -> proto::FibTableConfig {
        proto::FibTableConfig {
            name: name.to_string(),
            table_id: 1000,
            metric: 200,
            ..Default::default()
        }
    }

    #[test]
    fn bgpls_route_to_proto_preserves_opaque_vpn_fields() {
        let nlri = decode_bgpls_vpn_nlri(&[
            0xfd, 0xe8, 0, 12, // type 65000, length = RD + 4 bytes
            0, 0, 0xfd, 0xe8, 0, 0, 0, 42, // RD
            0xde, 0xad, 0xbe, 0xef, // opaque payload
        ])
        .expect("fixture BGP-LS VPN NLRI decodes")
        .pop()
        .expect("fixture contains one NLRI");

        let route = BgpLsRibRoute {
            family: BgpLsFamily::LinkStateVpn,
            nlri,
            next_hop: Ipv4Addr::new(192, 0, 2, 1).into(),
            peer: Ipv4Addr::new(192, 0, 2, 2).into(),
            attributes: Arc::new(vec![
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![64512, 64513])],
                }),
                PathAttribute::Communities(vec![0x0001_0002]),
                PathAttribute::Unknown(RawAttribute {
                    flags: 0x80,
                    type_code: 29,
                    data: Bytes::from_static(&[0xba, 0xdc, 0x0d, 0xe0]),
                }),
            ]),
            received_at: Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ibgp,
            peer_router_id: Ipv4Addr::new(192, 0, 2, 2),
            is_stale: true,
            is_llgr_stale: false,
            path_id: 9,
        };

        let entry = bgpls_route_to_proto(&route);
        assert_eq!(entry.afi_safi, proto::AddressFamily::BgpLsVpn as i32);
        assert_eq!(entry.family, "linkstate_vpn");
        assert_eq!(entry.nlri_type, 65_000);
        assert_eq!(entry.nlri_type_name, "unknown_65000");
        assert_eq!(entry.route_distinguisher, [0, 0, 0xfd, 0xe8, 0, 0, 0, 42]);
        assert_eq!(entry.payload, [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(entry.next_hop, "192.0.2.1");
        assert_eq!(entry.peer_address, "192.0.2.2");
        assert_eq!(entry.as_path, [64512, 64513]);
        assert_eq!(entry.communities, [0x0001_0002]);
        assert_eq!(entry.bgp_ls_attribute, [0xba, 0xdc, 0x0d, 0xe0]);
        assert!(entry.stale);
        assert_eq!(entry.path_id, 9);
    }

    #[test]
    fn vpn_route_to_proto_preserves_rd_prefix_labels_and_route_targets() {
        use rustbgpd_wire::{ExtendedCommunity, MplsLabelEntry, VpnNlri, VpnPrefix};

        let route = VpnRibRoute {
            nlri: VpnNlri {
                labels: vec![
                    MplsLabelEntry::try_new(16_000, 0, false).unwrap(),
                    MplsLabelEntry::try_new(24_017, 0, true).unwrap(),
                ],
                route_distinguisher: rustbgpd_wire::RouteDistinguisher([
                    0, 0, 0xFD, 0xE8, 0, 0, 0, 1,
                ]),
                prefix: VpnPrefix::v4(Ipv4Addr::new(10, 1, 0, 0), 24).unwrap(),
            },
            next_hop: Ipv4Addr::new(192, 0, 2, 1).into(),
            link_local_next_hop: None,
            peer: Ipv4Addr::new(192, 0, 2, 2).into(),
            attributes: Arc::new(vec![
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![64512, 64513])],
                }),
                PathAttribute::Communities(vec![0x0001_0002]),
                // 2-octet AS Route Target: RT:65000:1
                PathAttribute::ExtendedCommunities(vec![ExtendedCommunity::new(
                    0x0002_FDE8_0000_0001,
                )]),
            ]),
            received_at: Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ibgp,
            peer_router_id: Ipv4Addr::new(192, 0, 2, 2),
            is_stale: true,
            is_llgr_stale: false,
            path_id: 0,
        };

        let entry = vpn_route_to_proto(&route);
        assert_eq!(entry.afi_safi, "l3vpn_ipv4_unicast");
        assert_eq!(entry.route_distinguisher, [0, 0, 0xFD, 0xE8, 0, 0, 0, 1]);
        assert_eq!(entry.route_distinguisher_str, "65000:1");
        assert_eq!(entry.prefix, "10.1.0.0/24");
        assert_eq!(entry.labels, [16_000, 24_017]);
        assert_eq!(entry.next_hop, "192.0.2.1");
        assert_eq!(entry.peer_address, "192.0.2.2");
        assert_eq!(entry.as_path, [64512, 64513]);
        assert_eq!(entry.communities, ["1:2"]);
        assert_eq!(entry.extended_communities, ["RT:65000:1"]);
        assert!(entry.stale);
        assert!(!entry.llgr_stale);
        assert_eq!(entry.path_id, 0);
    }

    /// LAN-347: the unicast conversion dropped the GR stale flags, so
    /// `rbgp rib received` showed stale routes as normal during a
    /// graceful-restart window.
    #[test]
    fn route_to_proto_populates_gr_stale_flags() {
        let mut route = Route {
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
            next_hop: "192.0.2.1".parse().unwrap(),
            link_local_next_hop: None,
            next_hop_scope: None,
            peer: "192.0.2.2".parse().unwrap(),
            attributes: Arc::new(vec![]),
            received_at: Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: true,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            aspa_context: rustbgpd_wire::AspaValidationContext::default(),
        };

        let entry = route_to_proto(&route, true);
        assert_eq!(entry.prefix, "10.0.0.0");
        assert_eq!(entry.prefix_length, 24);
        assert!(entry.best);
        assert!(entry.stale);
        assert!(!entry.llgr_stale);

        route.is_llgr_stale = true;
        let entry = route_to_proto(&route, false);
        assert!(entry.stale);
        assert!(entry.llgr_stale);

        route.is_stale = false;
        route.is_llgr_stale = false;
        let entry = route_to_proto(&route, false);
        assert!(!entry.stale);
        assert!(!entry.llgr_stale);
    }

    #[test]
    fn rtc_route_to_proto_renders_default_and_full_nlri() {
        let full = RtcRibRoute {
            // RT:65001:100 from origin AS 65001, /96.
            nlri: rustbgpd_wire::RtcNlri::new(65001, 0x0002_FDE9_0000_0064, 96).unwrap(),
            next_hop: Ipv4Addr::new(192, 0, 2, 1).into(),
            peer: Ipv4Addr::new(192, 0, 2, 2).into(),
            attributes: Arc::new(vec![
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![64512, 64513])],
                }),
                PathAttribute::Communities(vec![0x0001_0002]),
            ]),
            received_at: Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ibgp,
            peer_router_id: Ipv4Addr::new(192, 0, 2, 2),
            is_stale: true,
            is_llgr_stale: false,
            path_id: 0,
        };
        let entry = rtc_route_to_proto(&full);
        assert!(!entry.is_default);
        assert_eq!(entry.origin_as, 65001);
        assert_eq!(entry.route_target, "RT:65001:100");
        assert_eq!(entry.prefix_len, 96);
        assert_eq!(entry.next_hop, "192.0.2.1");
        assert_eq!(entry.peer_address, "192.0.2.2");
        assert_eq!(entry.as_path, [64512, 64513]);
        assert_eq!(entry.communities, ["1:2"]);
        assert!(entry.stale);
        assert!(!entry.llgr_stale);

        let default = RtcRibRoute {
            nlri: rustbgpd_wire::RtcNlri::DEFAULT,
            next_hop: Ipv4Addr::UNSPECIFIED.into(),
            peer: Ipv4Addr::UNSPECIFIED.into(),
            attributes: Arc::new(vec![]),
            received_at: Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Local,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
        };
        let entry = rtc_route_to_proto(&default);
        assert!(entry.is_default);
        assert_eq!(entry.origin_as, 0);
        assert_eq!(entry.route_target, "");
        assert_eq!(entry.prefix_len, 0);
        assert_eq!(entry.peer_address, "0.0.0.0");
    }

    /// `ListTopologyNodes`/`ListTopologyLinks` round-trip: the service
    /// queries the manager channel and maps the snapshot to proto entries.
    #[tokio::test]
    async fn list_topology_nodes_and_links_round_trip_snapshot() {
        let (tx, mut rx) = mpsc::channel(16);
        let svc = RibService::new(tx);
        tokio::spawn(async move {
            while let Some(update) = rx.recv().await {
                let RibUpdate::QueryOrrTopology { reply } = update else {
                    panic!("unexpected RIB update");
                };
                let _ = reply.send(OrrTopologySnapshot {
                    nodes: vec![OrrNodeSnapshot {
                        key_hex: "02aabb".to_string(),
                        asn: Some(64512),
                        bgp_ls_id: None,
                        router_id_hex: "000000000001".to_string(),
                        link_count: 2,
                    }],
                    links: vec![OrrLinkSnapshot {
                        local_key_hex: "02aabb".to_string(),
                        local_router_id_hex: "000000000001".to_string(),
                        remote_key_hex: "02ccdd".to_string(),
                        remote_router_id_hex: String::new(),
                        cost: 10,
                        addresses: vec!["10.0.8.1".to_string()],
                    }],
                    prefixes: vec![],
                });
            }
        });

        let nodes = svc
            .list_topology_nodes(Request::new(proto::ListTopologyNodesRequest {}))
            .await
            .expect("nodes query succeeds")
            .into_inner()
            .nodes;
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].key, "02aabb");
        assert_eq!(nodes[0].asn, 64512);
        assert_eq!(nodes[0].bgp_ls_id, 0, "absent BGP-LS id flattens to 0");
        assert_eq!(nodes[0].router_id, "000000000001");
        assert_eq!(nodes[0].link_count, 2);

        let links = svc
            .list_topology_links(Request::new(proto::ListTopologyLinksRequest {}))
            .await
            .expect("links query succeeds")
            .into_inner()
            .links;
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].local_key, "02aabb");
        assert_eq!(links[0].remote_key, "02ccdd");
        assert_eq!(links[0].remote_router_id, "");
        assert_eq!(links[0].cost, 10);
        assert_eq!(links[0].addresses, ["10.0.8.1"]);
    }

    /// `ListOrrStatus` round-trip: the service queries the manager
    /// channel and maps the per-vantage status snapshot to proto entries
    /// (absent descriptors flatten to 0/empty).
    #[tokio::test]
    async fn list_orr_status_round_trips_snapshot() {
        use rustbgpd_rib::OrrVantageStatus;

        let (tx, mut rx) = mpsc::channel(16);
        let svc = RibService::new(tx);
        tokio::spawn(async move {
            while let Some(update) = rx.recv().await {
                let RibUpdate::QueryOrrStatus { reply } = update else {
                    panic!("unexpected RIB update");
                };
                let _ = reply.send(OrrStatusSnapshot {
                    vantages: vec![
                        OrrVantageStatus {
                            vantage: "10.0.8.1".parse().unwrap(),
                            resolved: true,
                            node_key_hex: "02aabb".to_string(),
                            asn: Some(64512),
                            bgp_ls_id: None,
                            router_id_hex: "000000000001".to_string(),
                            reachable_nodes: 3,
                            peers: vec!["192.0.2.1".parse().unwrap()],
                        },
                        OrrVantageStatus {
                            vantage: "203.0.113.9".parse().unwrap(),
                            resolved: false,
                            node_key_hex: String::new(),
                            asn: None,
                            bgp_ls_id: None,
                            router_id_hex: String::new(),
                            reachable_nodes: 0,
                            peers: vec!["192.0.2.2".parse().unwrap()],
                        },
                    ],
                    topology_nodes: 4,
                    topology_links: 4,
                    input_diagnostics: rustbgpd_rib::orr::OrrInputDiagnostics {
                        included_default: 8,
                        excluded_nondefault: 2,
                        malformed_topology: 1,
                        malformed_attribute_29: 3,
                        default_with_ignored_flex_algo: 4,
                    },
                });
            }
        });

        let resp = svc
            .list_orr_status(Request::new(proto::ListOrrStatusRequest {}))
            .await
            .expect("status query succeeds")
            .into_inner();
        assert_eq!(resp.topology_nodes, 4);
        assert_eq!(resp.topology_links, 4);
        assert_eq!(
            resp.input_diagnostics,
            Some(proto::OrrInputDiagnostics {
                included_default: 8,
                excluded_nondefault: 2,
                malformed_topology: 1,
                malformed_attribute_29: 3,
                default_with_ignored_flex_algo: 4,
            })
        );
        assert_eq!(resp.vantages.len(), 2);

        let resolved = &resp.vantages[0];
        assert_eq!(resolved.vantage, "10.0.8.1");
        assert!(resolved.resolved);
        assert_eq!(resolved.node_key, "02aabb");
        assert_eq!(resolved.asn, 64512);
        assert_eq!(resolved.bgp_ls_id, 0, "absent BGP-LS id flattens to 0");
        assert_eq!(resolved.router_id, "000000000001");
        assert_eq!(resolved.reachable_nodes, 3);
        assert_eq!(resolved.peers, ["192.0.2.1"]);

        let unresolved = &resp.vantages[1];
        assert_eq!(unresolved.vantage, "203.0.113.9");
        assert!(!unresolved.resolved);
        assert_eq!(unresolved.node_key, "");
        assert_eq!(unresolved.reachable_nodes, 0);
        assert_eq!(unresolved.peers, ["192.0.2.2"]);
    }

    #[tokio::test]
    async fn set_fib_table_rejected_when_read_only() {
        // make_service() defaults to ReadOnly with no control hook.
        let status = make_service()
            .set_fib_table(Request::new(proto::SetFibTableRequest {
                table: Some(fib_table_proto("edge")),
            }))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn set_fib_table_unavailable_without_control_hook() {
        let (tx, _rx) = mpsc::channel(16);
        let svc =
            RibService::new(tx).with_fib_table_control(crate::server::AccessMode::ReadWrite, None);
        let status = svc
            .set_fib_table(Request::new(proto::SetFibTableRequest {
                table: Some(fib_table_proto("edge")),
            }))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn set_fib_table_missing_table_is_invalid_argument() {
        let (tx, _rx) = mpsc::channel(16);
        let svc =
            RibService::new(tx).with_fib_table_control(crate::server::AccessMode::ReadWrite, None);
        let status = svc
            .set_fib_table(Request::new(proto::SetFibTableRequest { table: None }))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn list_fib_tables_unavailable_without_control_hook() {
        let status = make_service()
            .list_fib_tables(Request::new(proto::ListFibTablesRequest {}))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    }

    /// Service wired to a stub RIB manager that answers every
    /// `ExplainBestPath` query with the given canned explanation.
    fn make_explain_best_path_service(
        explanation: Option<rustbgpd_rib::ExplainBestPath>,
    ) -> RibService {
        let (tx, mut rx) = mpsc::channel(16);
        tokio::spawn(async move {
            while let Some(update) = rx.recv().await {
                if let RibUpdate::ExplainBestPath { reply, .. } = update {
                    let _ = reply.send(explanation.clone());
                }
            }
        });
        RibService::new(tx)
    }

    fn explain_best_path_request() -> proto::ExplainBestPathRequest {
        proto::ExplainBestPathRequest {
            prefix: "10.0.0.0".to_string(),
            prefix_length: 24,
            peer_address: String::new(),
        }
    }

    #[tokio::test]
    async fn explain_best_path_returns_tiebreaker_trace() {
        let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));
        let best = test_route(prefix, vec![PathAttribute::LocalPref(200)]);
        let mut loser = test_route(prefix, vec![PathAttribute::LocalPref(100)]);
        loser.peer = "10.0.0.2".parse().unwrap();
        let explanation = rustbgpd_rib::ExplainBestPath {
            prefix,
            best: Some(best),
            candidates: vec![rustbgpd_rib::BestPathCandidate {
                route: loser,
                vs_best_reason: rustbgpd_rib::BestPathReason::HigherLocalPref,
                vs_best_ordering: std::cmp::Ordering::Greater,
                advertised_path_id: 0,
                vs_best_detail: "local_pref 100 < 200".to_string(),
                multipath: rustbgpd_rib::MultipathEligibility::None,
            }],
            peer: None,
            add_path_send_max: 0,
            best_reason: Some(rustbgpd_rib::BestPathReason::HigherLocalPref),
            best_reason_detail: "local_pref 200 > 100".to_string(),
        };

        let resp = make_explain_best_path_service(Some(explanation))
            .explain_best_path(Request::new(explain_best_path_request()))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(resp.best_reason, "higher_local_pref");
        assert_eq!(resp.best_reason_detail, "local_pref 200 > 100");
        assert_eq!(resp.candidates.len(), 1);
        let cand = &resp.candidates[0];
        assert_eq!(cand.vs_best_reason, "higher_local_pref");
        assert_eq!(cand.vs_best_detail, "local_pref 100 < 200");
        assert_eq!(cand.vs_best_ordering, "worse");
        assert_eq!(cand.multipath, "none");
    }

    #[tokio::test]
    async fn explain_best_path_single_path_reports_only_path() {
        let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));
        let explanation = rustbgpd_rib::ExplainBestPath {
            prefix,
            best: Some(test_route(prefix, vec![PathAttribute::LocalPref(100)])),
            candidates: vec![],
            peer: None,
            add_path_send_max: 0,
            best_reason: None,
            best_reason_detail: String::new(),
        };

        let resp = make_explain_best_path_service(Some(explanation))
            .explain_best_path(Request::new(explain_best_path_request()))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(resp.best_reason, "only_path");
        assert!(resp.best_reason_detail.is_empty());
        assert!(resp.candidates.is_empty());
    }

    #[tokio::test]
    async fn explain_best_path_unknown_prefix_is_not_found() {
        let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));
        // No paths in any Adj-RIB-In: the manager reports an empty
        // explanation; the RPC maps it to NOT_FOUND.
        let explanation = rustbgpd_rib::ExplainBestPath {
            prefix,
            best: None,
            candidates: vec![],
            peer: None,
            add_path_send_max: 0,
            best_reason: None,
            best_reason_detail: String::new(),
        };

        let status = make_explain_best_path_service(Some(explanation))
            .explain_best_path(Request::new(explain_best_path_request()))
            .await
            .unwrap_err();

        assert_eq!(status.code(), tonic::Code::NotFound);
        assert!(
            status.message().contains("no paths for prefix 10.0.0.0/24"),
            "unexpected message: {}",
            status.message()
        );
    }

    #[tokio::test]
    async fn explain_best_path_unknown_peer_is_not_found() {
        // Manager replies None for an unregistered peer scope.
        let status = make_explain_best_path_service(None)
            .explain_best_path(Request::new(proto::ExplainBestPathRequest {
                peer_address: "192.0.2.99".to_string(),
                ..explain_best_path_request()
            }))
            .await
            .unwrap_err();

        assert_eq!(status.code(), tonic::Code::NotFound);
        assert!(
            status.message().contains("192.0.2.99"),
            "unexpected message: {}",
            status.message()
        );
    }

    fn list_routes_request() -> proto::ListRoutesRequest {
        proto::ListRoutesRequest {
            neighbor_address: String::new(),
            afi_safi: 0,
            page_size: 0,
            page_token: String::new(),
            prefix_filter: String::new(),
            prefix_filter_length: 0,
            longer_prefixes: false,
            origin_asn: 0,
            community_filter: vec![],
            large_community_filter: vec![],
        }
    }

    fn route_page_identity(req: &proto::ListRoutesRequest) -> String {
        let filters = RouteFilters::from_request(req).expect("valid route filters");
        route_page_query_identity(req.afi_safi, &filters)
    }

    fn route_event(prefix: Prefix, peer: IpAddr) -> rustbgpd_rib::RouteEvent {
        rustbgpd_rib::RouteEvent {
            event_id: 0,
            event_type: RouteEventType::Added,
            prefix,
            peer: Some(peer),
            previous_peer: None,
            target_peer: None,
            timestamp: "123".to_string(),
            path_id: 0,
            reason: String::new(),
        }
    }

    fn fib_status(
        table_name: &str,
        prefix: &str,
        prefix_length: u32,
        peer_address: &str,
        state: proto::FibRouteState,
        reason: &str,
    ) -> proto::FibRouteStatus {
        proto::FibRouteStatus {
            table_name: table_name.to_string(),
            table_id: 1000,
            metric: 200,
            prefix: prefix.to_string(),
            prefix_length,
            next_hop: "192.0.2.1".to_string(),
            peer_address: peer_address.to_string(),
            state: state as i32,
            reason: reason.to_string(),
            ..Default::default()
        }
    }

    fn make_watch_routes_service(
        metrics: BgpMetrics,
    ) -> (RibService, broadcast::Sender<rustbgpd_rib::RouteEvent>) {
        let (tx, mut rx) = mpsc::channel(16);
        let (events_tx, _) = broadcast::channel(16);
        let events_tx_for_task = events_tx.clone();
        tokio::spawn(async move {
            while let Some(update) = rx.recv().await {
                if let RibUpdate::SubscribeRouteEvents { reply } = update {
                    let _ = reply.send(events_tx_for_task.subscribe());
                }
            }
        });
        (
            RibService::with_status_snapshots_and_metrics(
                tx,
                Arc::new(Vec::new),
                Arc::new(Vec::new),
                metrics,
            ),
            events_tx,
        )
    }

    #[tokio::test]
    async fn watch_routes_subscriber_gauge_tracks_stream_lifecycle() {
        let metrics = BgpMetrics::new();
        let (svc, _events_tx) = make_watch_routes_service(metrics.clone());

        let response = svc
            .watch_routes(Request::new(proto::WatchRoutesRequest::default()))
            .await
            .unwrap();

        let text = gather_text(&metrics);
        assert!(
            text.contains(
                "bgp_event_stream_subscribers{service=\"watch_routes\",source=\"route\"} 1"
            )
        );

        drop(response);
        tokio::task::yield_now().await;

        let text = gather_text(&metrics);
        assert!(
            text.contains(
                "bgp_event_stream_subscribers{service=\"watch_routes\",source=\"route\"} 0"
            )
        );
    }

    #[tokio::test]
    async fn watch_routes_lagged_subscriber_increments_metric() {
        let metrics = BgpMetrics::new();
        let (svc, events_tx) = make_watch_routes_service(metrics.clone());

        let response = svc
            .watch_routes(Request::new(proto::WatchRoutesRequest::default()))
            .await
            .unwrap();
        let mut stream = response.into_inner();

        for index in 0..20 {
            events_tx
                .send(route_event(
                    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, index), 32)),
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                ))
                .unwrap();
        }

        let event = tokio::time::timeout(std::time::Duration::from_secs(1), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(event.event_type, proto::RouteEventType::Added as i32);

        let text = gather_text(&metrics);
        assert!(text.contains(
            "bgp_event_stream_lagged_total{service=\"watch_routes\",source=\"route\"} 4"
        ));
    }

    #[tokio::test]
    async fn watch_route_events_emits_bgp_route_event_and_applies_filters() {
        let metrics = BgpMetrics::new();
        let (svc, events_tx) = make_watch_routes_service(metrics);

        let response = svc
            .watch_route_events(Request::new(proto::WatchRoutesRequest {
                neighbor_address: "192.0.2.1".to_string(),
                afi_safi: proto::AddressFamily::Ipv4Unicast as i32,
            }))
            .await
            .unwrap();
        let mut stream = response.into_inner();

        events_tx
            .send(route_event(
                Prefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 64)),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            ))
            .unwrap();
        events_tx
            .send(route_event(
                Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 24)),
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            ))
            .unwrap();
        events_tx
            .send(route_event(
                Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 2, 0, 0), 24)),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            ))
            .unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_secs(1), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        assert_eq!(event.category, proto::EventCategory::Route as i32);
        assert_eq!(event.event_type, proto::BgpEventType::RouteAdded as i32);
        assert_eq!(event.peer_address, "192.0.2.1");
        assert_eq!(event.prefix, "10.2.0.0");
        assert_eq!(event.prefix_length, 24);
        assert_eq!(event.summary, "route added 10.2.0.0/24");
        assert!(matches!(
            event.payload,
            Some(proto::bgp_event::Payload::Route(_))
        ));
    }

    #[tokio::test]
    async fn watch_route_events_filter_matches_policy_filtered_target_peer() {
        let metrics = BgpMetrics::new();
        let (svc, events_tx) = make_watch_routes_service(metrics);

        let response = svc
            .watch_route_events(Request::new(proto::WatchRoutesRequest {
                neighbor_address: "192.0.2.1".to_string(),
                afi_safi: proto::AddressFamily::Ipv4Unicast as i32,
            }))
            .await
            .unwrap();
        let mut stream = response.into_inner();

        events_tx
            .send(rustbgpd_rib::RouteEvent {
                event_id: 0,
                event_type: RouteEventType::PolicyFiltered,
                prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 3, 0, 0), 24)),
                peer: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))),
                previous_peer: None,
                target_peer: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
                timestamp: "123".to_string(),
                path_id: 0,
                reason: "policy_denied".to_string(),
            })
            .unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_secs(1), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        assert_eq!(
            event.event_type,
            proto::BgpEventType::RoutePolicyFiltered as i32
        );
        assert_eq!(event.peer_address, "198.51.100.1");
        assert_eq!(event.target_peer_address, "192.0.2.1");
        match event.payload {
            Some(proto::bgp_event::Payload::Route(route)) => {
                assert_eq!(route.reason, "policy_denied");
            }
            other => panic!("expected route payload, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn watch_route_events_lagged_subscriber_emits_signal() {
        let metrics = BgpMetrics::new();
        let (svc, events_tx) = make_watch_routes_service(metrics.clone());

        let response = svc
            .watch_route_events(Request::new(proto::WatchRoutesRequest::default()))
            .await
            .unwrap();
        let mut stream = response.into_inner();

        for index in 0..20 {
            events_tx
                .send(route_event(
                    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 3, 0, index), 32)),
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                ))
                .unwrap();
        }

        let event = tokio::time::timeout(std::time::Duration::from_secs(1), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(event.category, proto::EventCategory::Route as i32);
        assert_eq!(event.event_type, proto::BgpEventType::StreamLagged as i32);
        assert_eq!(event.severity, proto::EventSeverity::Warning as i32);
        match event.payload {
            Some(proto::bgp_event::Payload::StreamLag(lag)) => {
                assert_eq!(lag.source_category, proto::EventCategory::Route as i32);
                assert_eq!(lag.missed_count, 4);
            }
            other => panic!("expected stream lag payload, got {other:?}"),
        }

        let text = gather_text(&metrics);
        assert!(text.contains(
            "bgp_event_stream_lagged_total{service=\"watch_route_events\",source=\"route\"} 4"
        ));
    }

    #[tokio::test]
    async fn list_route_events_forwards_filters_and_maps_response() {
        let (tx, mut rx) = mpsc::channel(16);
        let svc = RibService::new(tx);
        let req = Request::new(proto::ListRouteEventsRequest {
            neighbor_address: "192.0.2.1".to_string(),
            afi_safi: proto::AddressFamily::Ipv4Unicast as i32,
            limit: 7,
            prefix: "203.0.113.0".to_string(),
            prefix_length: 24,
        });

        let call = tokio::spawn(async move { svc.list_route_events(req).await });
        let update = rx.recv().await.unwrap();
        let reply = match update {
            RibUpdate::QueryRouteEventHistory {
                peer,
                afi,
                prefix,
                limit,
                reply,
            } => {
                assert_eq!(peer, Some("192.0.2.1".parse::<IpAddr>().unwrap()));
                assert_eq!(afi, Some(Afi::Ipv4));
                assert_eq!(
                    prefix,
                    Some(Prefix::V4(Ipv4Prefix::new(
                        "203.0.113.0".parse().unwrap(),
                        24
                    )))
                );
                assert_eq!(limit, 7);
                reply
            }
            _ => panic!("unexpected update variant"),
        };

        reply
            .send(vec![rustbgpd_rib::RouteEvent {
                event_id: 0,
                event_type: RouteEventType::BestChanged,
                prefix: Prefix::V4(Ipv4Prefix::new("203.0.113.0".parse().unwrap(), 24)),
                peer: Some("192.0.2.1".parse().unwrap()),
                previous_peer: Some("192.0.2.2".parse().unwrap()),
                target_peer: None,
                timestamp: "123".to_string(),
                path_id: 99,
                reason: String::new(),
            }])
            .unwrap();

        let response = call.await.unwrap().unwrap().into_inner();
        assert_eq!(response.events.len(), 1);
        let event = &response.events[0];
        assert_eq!(event.event_type, proto::RouteEventType::BestChanged as i32);
        assert_eq!(event.prefix, "203.0.113.0");
        assert_eq!(event.prefix_length, 24);
        assert_eq!(event.peer_address, "192.0.2.1");
        assert_eq!(event.previous_peer_address, "192.0.2.2");
        assert_eq!(event.path_id, 99);
    }

    #[test]
    fn filter_routes_unspecified_returns_all() {
        let v4 = Route {
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
            next_hop: "10.0.0.1".parse().unwrap(),
            link_local_next_hop: None,
            next_hop_scope: None,
            peer: "10.0.0.1".parse().unwrap(),
            attributes: Arc::new(vec![]),
            received_at: std::time::Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            aspa_context: rustbgpd_wire::AspaValidationContext::default(),
        };
        let v6 = Route {
            prefix: Prefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32)),
            next_hop: "2001:db8::1".parse().unwrap(),
            link_local_next_hop: None,
            next_hop_scope: None,
            peer: "2001:db8::1".parse().unwrap(),
            attributes: Arc::new(vec![]),
            received_at: std::time::Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            aspa_context: rustbgpd_wire::AspaValidationContext::default(),
        };

        // Unspecified matches all.
        assert!(route_matches_family(&v4, 0));
        assert!(route_matches_family(&v6, 0));

        // IPv4 filter.
        assert!(route_matches_family(
            &v4,
            proto::AddressFamily::Ipv4Unicast as i32,
        ));
        assert!(!route_matches_family(
            &v6,
            proto::AddressFamily::Ipv4Unicast as i32,
        ));

        // IPv6 filter.
        assert!(route_matches_family(
            &v6,
            proto::AddressFamily::Ipv6Unicast as i32,
        ));
        assert!(!route_matches_family(
            &v4,
            proto::AddressFamily::Ipv6Unicast as i32,
        ));
    }

    #[tokio::test]
    async fn list_received_routes_rejects_unsupported_afi() {
        let svc = make_service();
        let req = Request::new(proto::ListRoutesRequest {
            afi_safi: 99,
            ..list_routes_request()
        });
        let err = svc.list_received_routes(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn list_received_routes_rejects_flowspec_afi() {
        let svc = make_service();
        let req = Request::new(proto::ListRoutesRequest {
            afi_safi: proto::AddressFamily::Ipv4Flowspec as i32,
            ..list_routes_request()
        });
        let err = svc.list_received_routes(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn route_filters_reject_length_without_prefix() {
        let req = proto::ListRoutesRequest {
            prefix_filter_length: 24,
            ..list_routes_request()
        };
        let Err(err) = RouteFilters::from_request(&req) else {
            panic!("prefix_filter_length without prefix_filter should fail");
        };
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("prefix_filter"));
    }

    #[test]
    fn route_filters_reject_ipv4_length_over_32() {
        let req = proto::ListRoutesRequest {
            prefix_filter: "203.0.113.0".into(),
            prefix_filter_length: 33,
            ..list_routes_request()
        };
        let Err(err) = RouteFilters::from_request(&req) else {
            panic!("IPv4 prefix_filter_length over 32 should fail");
        };
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("0-32 for IPv4"));
    }

    #[test]
    fn route_filters_reject_ipv6_length_over_128() {
        let req = proto::ListRoutesRequest {
            prefix_filter: "2001:db8::".into(),
            prefix_filter_length: 129,
            ..list_routes_request()
        };
        let Err(err) = RouteFilters::from_request(&req) else {
            panic!("IPv6 prefix_filter_length over 128 should fail");
        };
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("0-128 for IPv6"));
    }

    #[tokio::test]
    async fn list_flowspec_routes_rejects_unicast_afi() {
        let svc = make_service();
        let req = Request::new(proto::ListFlowSpecRequest {
            afi_safi: proto::AddressFamily::Ipv4Unicast as i32,
        });
        let err = svc.list_flow_spec_routes(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn list_blackhole_discards_returns_live_snapshot() {
        let (tx, _rx) = mpsc::channel(16);
        let svc = RibService::with_status_snapshots(
            tx,
            Arc::new(|| {
                vec![proto::BlackholeDiscard {
                    prefix: "203.0.113.66".to_string(),
                    prefix_length: 32,
                    peer_address: "192.0.2.1".to_string(),
                    state: proto::BlackholeDiscardState::Installed as i32,
                    reason: "owned".to_string(),
                }]
            }),
            Arc::new(Vec::new),
        );

        let resp = svc
            .list_blackhole_discards(Request::new(proto::ListBlackholeDiscardsRequest {}))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(resp.discards.len(), 1);
        let row = &resp.discards[0];
        assert_eq!(row.prefix, "203.0.113.66");
        assert_eq!(row.prefix_length, 32);
        assert_eq!(row.peer_address, "192.0.2.1");
        assert_eq!(row.state, proto::BlackholeDiscardState::Installed as i32);
        assert_eq!(row.reason, "owned");
    }

    #[tokio::test]
    async fn list_fib_routes_returns_live_snapshot() {
        let (tx, _rx) = mpsc::channel(16);
        let svc = RibService::with_status_snapshots(
            tx,
            Arc::new(Vec::new),
            Arc::new(|| {
                vec![proto::FibRouteStatus {
                    table_name: "edge".to_string(),
                    table_id: 1000,
                    metric: 200,
                    prefix: "203.0.113.0".to_string(),
                    prefix_length: 24,
                    next_hop: "192.0.2.1".to_string(),
                    peer_address: "198.51.100.1".to_string(),
                    state: proto::FibRouteState::Installed as i32,
                    reason: "owned".to_string(),
                    ..Default::default()
                }]
            }),
        );

        let resp = svc
            .list_fib_routes(Request::new(proto::ListFibRoutesRequest::default()))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(resp.routes.len(), 1);
        let row = &resp.routes[0];
        assert_eq!(row.table_name, "edge");
        assert_eq!(row.table_id, 1000);
        assert_eq!(row.metric, 200);
        assert_eq!(row.prefix, "203.0.113.0");
        assert_eq!(row.prefix_length, 24);
        assert_eq!(row.next_hop, "192.0.2.1");
        assert_eq!(row.peer_address, "198.51.100.1");
        assert_eq!(row.state, proto::FibRouteState::Installed as i32);
        assert_eq!(row.reason, "owned");
    }

    #[tokio::test]
    async fn list_fib_routes_filters_snapshot_rows() {
        let (tx, _rx) = mpsc::channel(16);
        let svc = RibService::with_status_snapshots(
            tx,
            Arc::new(Vec::new),
            Arc::new(|| {
                vec![
                    fib_status(
                        "edge",
                        "203.0.113.0",
                        24,
                        "198.51.100.1",
                        proto::FibRouteState::Installed,
                        "owned",
                    ),
                    fib_status(
                        "edge",
                        "203.0.113.0",
                        24,
                        "198.51.100.2",
                        proto::FibRouteState::Rejected,
                        "route_limit_exceeded",
                    ),
                    fib_status(
                        "backup",
                        "2001:db8::",
                        64,
                        "2001:db8::1",
                        proto::FibRouteState::Installed,
                        "owned",
                    ),
                ]
            }),
        );

        let resp = svc
            .list_fib_routes(Request::new(proto::ListFibRoutesRequest {
                table_name: "edge".to_string(),
                state: proto::FibRouteState::Rejected as i32,
                reason: "route_limit_exceeded".to_string(),
                prefix: "203.0.113.0".to_string(),
                prefix_length: 24,
                peer_address: "198.51.100.2".to_string(),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(resp.routes.len(), 1);
        assert_eq!(resp.routes[0].peer_address, "198.51.100.2");
        assert_eq!(resp.routes[0].state, proto::FibRouteState::Rejected as i32);
    }

    #[tokio::test]
    async fn list_fib_routes_paginates_filtered_snapshot_deterministically() {
        let (tx, _rx) = mpsc::channel(16);
        let svc = RibService::with_status_snapshots(
            tx,
            Arc::new(Vec::new),
            Arc::new(|| {
                vec![
                    fib_status(
                        "edge",
                        "203.0.113.0",
                        24,
                        "198.51.100.3",
                        proto::FibRouteState::Installed,
                        "owned",
                    ),
                    fib_status(
                        "backup",
                        "2001:db8::",
                        64,
                        "2001:db8::1",
                        proto::FibRouteState::Installed,
                        "owned",
                    ),
                    fib_status(
                        "edge",
                        "203.0.113.0",
                        24,
                        "198.51.100.1",
                        proto::FibRouteState::Installed,
                        "owned",
                    ),
                ]
            }),
        );

        let first = svc
            .list_fib_routes(Request::new(proto::ListFibRoutesRequest {
                table_name: "edge".to_string(),
                page_size: 1,
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(first.total_count, 2);
        assert_eq!(first.next_page_token, "1");
        assert_eq!(first.routes.len(), 1);
        assert_eq!(first.routes[0].peer_address, "198.51.100.1");

        let second = svc
            .list_fib_routes(Request::new(proto::ListFibRoutesRequest {
                table_name: "edge".to_string(),
                page_size: 1,
                page_token: first.next_page_token,
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(second.total_count, 2);
        assert!(second.next_page_token.is_empty());
        assert_eq!(second.routes.len(), 1);
        assert_eq!(second.routes[0].peer_address, "198.51.100.3");
    }

    #[tokio::test]
    async fn list_fib_routes_unpaged_preserves_snapshot_order() {
        let (tx, _rx) = mpsc::channel(16);
        let svc = RibService::with_status_snapshots(
            tx,
            Arc::new(Vec::new),
            Arc::new(|| {
                vec![
                    fib_status(
                        "edge",
                        "203.0.113.0",
                        24,
                        "198.51.100.3",
                        proto::FibRouteState::Installed,
                        "owned",
                    ),
                    fib_status(
                        "edge",
                        "203.0.113.0",
                        24,
                        "198.51.100.1",
                        proto::FibRouteState::Installed,
                        "owned",
                    ),
                ]
            }),
        );

        let resp = svc
            .list_fib_routes(Request::new(proto::ListFibRoutesRequest::default()))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(resp.total_count, 2);
        assert!(resp.next_page_token.is_empty());
        assert_eq!(resp.routes[0].peer_address, "198.51.100.3");
        assert_eq!(resp.routes[1].peer_address, "198.51.100.1");
    }

    #[tokio::test]
    async fn list_fib_routes_rejects_bad_filters() {
        let (tx, _rx) = mpsc::channel(16);
        let svc = RibService::with_status_snapshots(tx, Arc::new(Vec::new), Arc::new(Vec::new));

        let err = svc
            .list_fib_routes(Request::new(proto::ListFibRoutesRequest {
                prefix: "203.0.113.0".to_string(),
                prefix_length: 33,
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("prefix_length"));

        let err = svc
            .list_fib_routes(Request::new(proto::ListFibRoutesRequest {
                peer_address: "not-an-ip".to_string(),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("peer_address"));

        let err = svc
            .list_fib_routes(Request::new(proto::ListFibRoutesRequest {
                state: 99,
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("invalid fib route state"));

        let err = svc
            .list_fib_routes(Request::new(proto::ListFibRoutesRequest {
                page_token: "1".to_string(),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("page_size"));

        let err = svc
            .list_fib_routes(Request::new(proto::ListFibRoutesRequest {
                page_size: 1,
                page_token: "not-a-token".to_string(),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("page_token"));

        let err = svc
            .list_fib_routes(Request::new(proto::ListFibRoutesRequest {
                page_size: 1,
                page_token: "1".to_string(),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("out of range"));
    }

    #[tokio::test]
    async fn explain_advertised_route_rejects_invalid_peer_address() {
        let svc = make_service();
        let req = Request::new(proto::ExplainAdvertisedRouteRequest {
            peer_address: "not-an-ip".to_string(),
            prefix: "203.0.113.0".to_string(),
            prefix_length: 24,
            rd: String::new(),
            labeled: false,
            source: None,
        });
        let err = svc.explain_advertised_route(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn explain_advertised_route_errors_map_to_grpc_codes() {
        let not_found = explain_advertised_error_status(ExplainAdvertisedRouteError::NotFound(
            "source path ID 9 is unknown".to_string(),
        ));
        assert_eq!(not_found.code(), tonic::Code::NotFound);
        assert!(not_found.message().contains("path ID 9"));

        let precondition = explain_advertised_error_status(
            ExplainAdvertisedRouteError::FailedPrecondition("Add-Path send not active".to_string()),
        );
        assert_eq!(precondition.code(), tonic::Code::FailedPrecondition);
        // Load-bearing proof: swapping or collapsing either mapping makes this test red.
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "one RPC round trip proves every export-explain field including source presence"
    )]
    async fn explain_advertised_route_round_trips() {
        let (tx, mut rx) = mpsc::channel(16);
        let svc = RibService::new(tx);
        let req = Request::new(proto::ExplainAdvertisedRouteRequest {
            peer_address: "192.0.2.1".to_string(),
            prefix: "203.0.113.0".to_string(),
            prefix_length: 24,
            rd: String::new(),
            labeled: false,
            source: Some(proto::RouteSourceIdentity {
                peer_address: "198.51.100.2".to_string(),
                path_id: 0,
            }),
        });

        let call = tokio::spawn(async move { svc.explain_advertised_route(req).await });
        let update = rx.recv().await.unwrap();
        let reply = match update {
            RibUpdate::ExplainAdvertisedRoute {
                peer,
                prefix,
                rd,
                labeled,
                source,
                reply,
            } => {
                assert_eq!(peer, "192.0.2.1".parse::<IpAddr>().unwrap());
                assert_eq!(rd, None);
                assert!(!labeled);
                assert_eq!(
                    source,
                    Some(RouteSourceIdentity {
                        peer: "198.51.100.2".parse().unwrap(),
                        path_id: 0,
                    })
                );
                assert_eq!(
                    prefix,
                    Prefix::V4(Ipv4Prefix::new("203.0.113.0".parse().unwrap(), 24))
                );
                reply
            }
            _ => panic!("unexpected update variant"),
        };
        reply
            .send(Ok(ExplainAdvertisedRoute {
                decision: ExplainDecision::Advertise,
                peer: "192.0.2.1".parse().unwrap(),
                prefix: Prefix::V4(Ipv4Prefix::new("203.0.113.0".parse().unwrap(), 24)),
                next_hop: Some("198.51.100.1".parse().unwrap()),
                path_id: 0,
                route_peer: Some("198.51.100.2".parse().unwrap()),
                route_type: Some(rustbgpd_policy::RouteType::External),
                reasons: vec![rustbgpd_rib::ExplainReason {
                    code: "policy_permitted",
                    message: "export policy permitted this route".to_string(),
                }],
                modifications: rustbgpd_policy::RouteModifications::default(),
                orr_vantage: Some("10.0.1.1".parse().unwrap()),
                orr_candidates: vec![
                    rustbgpd_rib::OrrExplainCandidate {
                        peer: "198.51.100.2".parse().unwrap(),
                        path_id: 0,
                        next_hop: "198.51.100.1".parse().unwrap(),
                        cost: Some(12),
                        selected: true,
                    },
                    rustbgpd_rib::OrrExplainCandidate {
                        peer: "198.51.100.3".parse().unwrap(),
                        path_id: 0,
                        next_hop: "198.51.100.4".parse().unwrap(),
                        cost: None,
                        selected: false,
                    },
                ],
                gates: vec![rustbgpd_rib::ExportGateStep {
                    gate: "export_policy",
                    code: "policy_permitted",
                    verdict: rustbgpd_rib::ExportGateVerdict::Pass,
                    detail: "export policy permitted this route".to_string(),
                }],
                update_group_id: Some(3),
                already_advertised: true,
                rd: None,
                source: Some(RouteSourceIdentity {
                    peer: "198.51.100.2".parse().unwrap(),
                    path_id: 0,
                }),
            }))
            .unwrap();

        let resp = call.await.unwrap().unwrap().into_inner();
        assert_eq!(resp.decision, proto::ExplainDecision::Advertise as i32);
        assert_eq!(resp.peer_address, "192.0.2.1");
        assert_eq!(resp.route_peer_address, "198.51.100.2");
        assert_eq!(resp.route_type, "external");
        assert_eq!(resp.reasons.len(), 1);
        assert_eq!(resp.orr_vantage, "10.0.1.1");
        assert_eq!(resp.orr_candidates.len(), 2);
        assert_eq!(resp.orr_candidates[0].next_hop, "198.51.100.1");
        assert_eq!(resp.orr_candidates[0].cost, Some(12));
        assert!(resp.orr_candidates[0].selected);
        assert_eq!(resp.orr_candidates[1].peer_address, "198.51.100.3");
        assert_eq!(
            resp.orr_candidates[1].cost, None,
            "unreachable maps to absent"
        );
        assert!(!resp.orr_candidates[1].selected);
        assert_eq!(resp.gates.len(), 1);
        assert_eq!(resp.gates[0].gate, "export_policy");
        assert_eq!(resp.gates[0].code, "policy_permitted");
        assert_eq!(resp.gates[0].verdict, proto::ExportGateVerdict::Pass as i32);
        assert_eq!(resp.update_group_id, Some(3));
        assert!(resp.already_advertised);
        assert_eq!(resp.rd, "");
        assert_eq!(resp.source.as_ref().map(|source| source.path_id), Some(0));
        assert_eq!(
            resp.source
                .as_ref()
                .map(|source| source.peer_address.as_str()),
            Some("198.51.100.2")
        );
        // Load-bearing proof: replacing presence with path_id != 0 drops this
        // source at either API boundary and makes both assertions red.
    }

    #[test]
    fn format_numeric_ops_preserves_and_bit() {
        let rendered = format_numeric_ops(&[
            rustbgpd_wire::NumericMatch {
                end_of_list: false,
                and_bit: false,
                lt: false,
                gt: true,
                eq: true,
                value: 1024,
            },
            rustbgpd_wire::NumericMatch {
                end_of_list: true,
                and_bit: true,
                lt: true,
                gt: false,
                eq: true,
                value: 65535,
            },
        ]);
        assert_eq!(rendered, ">=1024 & <=65535");
    }

    #[test]
    fn format_bitmask_ops_preserves_and_bit_and_not() {
        let rendered = format_bitmask_ops(&[
            rustbgpd_wire::BitmaskMatch {
                end_of_list: false,
                and_bit: false,
                not_bit: false,
                match_bit: true,
                value: 0x0002,
            },
            rustbgpd_wire::BitmaskMatch {
                end_of_list: true,
                and_bit: true,
                not_bit: true,
                match_bit: true,
                value: 0x0004,
            },
        ]);
        assert_eq!(rendered, "0x0002/match & !0x0004/match");
    }

    #[test]
    fn prefix_contains_exact_match() {
        let container = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8));
        assert!(prefix_contains(&container, &container));
    }

    #[test]
    fn prefix_contains_longer_match() {
        let container = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8));
        let longer = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 1, 2, 0), 24));
        assert!(prefix_contains(&container, &longer));
    }

    #[test]
    fn prefix_contains_rejects_shorter() {
        let container = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 16));
        let shorter = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8));
        assert!(!prefix_contains(&container, &shorter));
    }

    #[test]
    fn prefix_contains_rejects_different_network() {
        let container = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8));
        let other = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 12));
        assert!(!prefix_contains(&container, &other));
    }

    #[test]
    fn prefix_contains_v4_v6_never_matches() {
        let v4 = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8));
        let v6 = Prefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32));
        assert!(!prefix_contains(&v4, &v6));
        assert!(!prefix_contains(&v6, &v4));
    }

    #[test]
    fn route_event_prefix_filter_accepts_matching_family() {
        let prefix = parse_route_event_prefix_filter("203.0.113.0", 24, Some(Afi::Ipv4)).unwrap();
        assert_eq!(
            prefix,
            Some(Prefix::V4(Ipv4Prefix::new(
                Ipv4Addr::new(203, 0, 113, 0),
                24
            )))
        );
    }

    #[test]
    fn route_event_prefix_filter_rejects_family_mismatch() {
        let err = parse_route_event_prefix_filter("2001:db8::", 64, Some(Afi::Ipv4)).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("prefix family"));
    }

    #[test]
    fn route_event_prefix_filter_rejects_empty_prefix_with_length() {
        let err = parse_route_event_prefix_filter("", 24, None).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("non-empty prefix"));
    }

    #[test]
    fn route_event_prefix_filter_rejects_ipv4_length_over_32() {
        let err = parse_route_event_prefix_filter("203.0.113.0", 33, None).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("0-32 for IPv4"));
    }

    fn test_route(prefix: Prefix, attributes: Vec<PathAttribute>) -> Route {
        Route {
            prefix,
            next_hop: "10.0.0.1".parse().unwrap(),
            link_local_next_hop: None,
            next_hop_scope: None,
            peer: "10.0.0.1".parse().unwrap(),
            attributes: Arc::new(attributes),
            received_at: std::time::Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            aspa_context: rustbgpd_wire::AspaValidationContext::default(),
        }
    }

    #[test]
    fn route_filters_exact_prefix() {
        let route = Route {
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 24)),
            next_hop: "10.0.0.1".parse().unwrap(),
            link_local_next_hop: None,
            next_hop_scope: None,
            peer: "10.0.0.1".parse().unwrap(),
            attributes: Arc::new(vec![]),
            received_at: std::time::Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            aspa_context: rustbgpd_wire::AspaValidationContext::default(),
        };

        let filters = RouteFilters {
            prefix: Some(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 24))),
            longer: false,
            origin_asn: 0,
            communities: vec![],
            large_community_filter_active: false,
            large_communities: vec![],
        };
        assert!(filters.matches(&route));

        let wrong_prefix = RouteFilters {
            prefix: Some(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 2, 0, 0), 24))),
            longer: false,
            origin_asn: 0,
            communities: vec![],
            large_community_filter_active: false,
            large_communities: vec![],
        };
        assert!(!wrong_prefix.matches(&route));
    }

    #[test]
    fn route_filters_community_match() {
        let community_val = 65001u32 * 65536 + 100;
        let route = Route {
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
            next_hop: "10.0.0.1".parse().unwrap(),
            link_local_next_hop: None,
            next_hop_scope: None,
            peer: "10.0.0.1".parse().unwrap(),
            attributes: Arc::new(vec![PathAttribute::Communities(vec![community_val])]),
            received_at: std::time::Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            aspa_context: rustbgpd_wire::AspaValidationContext::default(),
        };

        let filters = RouteFilters {
            prefix: None,
            longer: false,
            origin_asn: 0,
            communities: vec![community_val],
            large_community_filter_active: false,
            large_communities: vec![],
        };
        assert!(filters.matches(&route));

        let wrong_community = RouteFilters {
            prefix: None,
            longer: false,
            origin_asn: 0,
            communities: vec![65002u32 * 65536 + 200],
            large_community_filter_active: false,
            large_communities: vec![],
        };
        assert!(!wrong_community.matches(&route));
    }

    #[test]
    fn route_filters_origin_asn() {
        let route = Route {
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
            next_hop: "10.0.0.1".parse().unwrap(),
            link_local_next_hop: None,
            next_hop_scope: None,
            peer: "10.0.0.1".parse().unwrap(),
            attributes: Arc::new(vec![PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65001, 65002, 65003])],
            })]),
            received_at: std::time::Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            aspa_context: rustbgpd_wire::AspaValidationContext::default(),
        };

        let filters = RouteFilters {
            prefix: None,
            longer: false,
            origin_asn: 65003,
            communities: vec![],
            large_community_filter_active: false,
            large_communities: vec![],
        };
        assert!(filters.matches(&route));

        let wrong_asn = RouteFilters {
            prefix: None,
            longer: false,
            origin_asn: 65001,
            communities: vec![],
            large_community_filter_active: false,
            large_communities: vec![],
        };
        assert!(!wrong_asn.matches(&route));
    }

    #[test]
    fn route_filter_attr_summary_preserves_first_as_path_semantics() {
        let route = test_route(
            Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
            vec![
                PathAttribute::AsPath(AsPath { segments: vec![] }),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65001, 65002])],
                }),
            ],
        );

        let filters = RouteFilters {
            prefix: None,
            longer: false,
            origin_asn: 65002,
            communities: vec![],
            large_community_filter_active: false,
            large_communities: vec![],
        };

        assert!(!filters.matches(&route));
    }

    #[test]
    fn route_filters_large_community_match_preserves_no_match_for_invalid_values() {
        let route = test_route(
            Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
            vec![PathAttribute::LargeCommunities(vec![LargeCommunity::new(
                65001, 100, 200,
            )])],
        );

        let req = proto::ListRoutesRequest {
            large_community_filter: vec!["65001:100:200".to_string()],
            ..list_routes_request()
        };
        let filters = RouteFilters::from_request(&req).unwrap();
        assert!(filters.matches(&route));

        let noncanonical = proto::ListRoutesRequest {
            large_community_filter: vec!["065001:100:200".to_string()],
            ..list_routes_request()
        };
        let filters = RouteFilters::from_request(&noncanonical).unwrap();
        assert!(!filters.matches(&route));

        let invalid = proto::ListRoutesRequest {
            large_community_filter: vec!["not-a-large-community".to_string()],
            ..list_routes_request()
        };
        let filters = RouteFilters::from_request(&invalid).unwrap();
        assert!(!filters.matches(&route));
    }

    #[test]
    fn route_page_token_round_trips() {
        let version = RoutePageVersion {
            epoch: 0x0123_4567_89ab_cdef,
            generation: 42,
        };
        let query_identity = route_page_identity(&list_routes_request());
        for key in [
            (
                Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
                "192.0.2.1".parse::<IpAddr>().unwrap(),
                0u32,
            ),
            (
                Prefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32)),
                "2001:db8::1".parse::<IpAddr>().unwrap(),
                7u32,
            ),
        ] {
            for scope in [
                RouteQueryScope::Received { peer: None },
                RouteQueryScope::Received {
                    peer: Some("2001:db8::5".parse().unwrap()),
                },
                RouteQueryScope::Best,
                RouteQueryScope::Advertised {
                    peer: "192.0.2.9".parse().unwrap(),
                },
            ] {
                let token = encode_route_page_token(scope, &query_identity, &key, version);
                assert_eq!(
                    decode_route_page_token(&token).unwrap(),
                    RoutePageCursor {
                        scope,
                        query_identity: query_identity.clone(),
                        after: key,
                        version
                    }
                );
            }
        }
    }

    /// Load-bearing response proof: removing `page_version` from
    /// `route_page_to_response` makes this empty terminal-page assertion red.
    #[test]
    fn empty_terminal_route_page_exposes_process_local_version() {
        use prost::Message;

        let version = RoutePageVersion {
            epoch: 0x0123_4567_89ab_cdef,
            generation: 42,
        };
        let response = route_page_to_response(
            &RoutePage {
                routes: Vec::new(),
                total: 0,
                has_more: false,
                version,
            },
            RouteQueryScope::Best,
            &route_page_identity(&list_routes_request()),
            true,
        );

        assert!(response.routes.is_empty());
        assert!(response.next_page_token.is_empty());
        assert_eq!(response.total_count, 0);
        assert_eq!(
            response.page_version,
            Some(proto::RoutePageVersion {
                epoch: version.epoch,
                generation: version.generation,
            })
        );

        let decoded = proto::ListRoutesResponse::decode(response.encode_to_vec().as_slice())
            .expect("route-page response round trip");
        assert_eq!(
            decoded.page_version,
            Some(proto::RoutePageVersion {
                epoch: version.epoch,
                generation: version.generation,
            })
        );
    }

    #[test]
    fn route_page_token_rejects_garbage() {
        let short_identity = format!("rp3|1|2|best|{}|10.0.0.0/24|192.0.2.1|0", "a".repeat(63));
        let uppercase_identity = format!("rp3|1|2|best|{}|10.0.0.0/24|192.0.2.1|0", "A".repeat(64));
        for token in [
            "",
            "5",
            "not-a-token",
            "10.0.0.0/24|192.0.2.1",
            "a|b|c|d",
            &short_identity,
            &uppercase_identity,
        ] {
            let err = decode_route_page_token(token).unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }
    }

    #[test]
    fn route_page_token_binds_canonical_filter_semantics() {
        let scope = RouteQueryScope::Best;
        let key = (
            Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
            "192.0.2.1".parse().unwrap(),
            7,
        );
        let version = RoutePageVersion {
            epoch: 11,
            generation: 13,
        };
        let base = proto::ListRoutesRequest {
            afi_safi: proto::AddressFamily::Ipv4Unicast as i32,
            page_size: 1,
            prefix_filter: "10.0.0.1".to_string(),
            prefix_filter_length: 24,
            longer_prefixes: true,
            origin_asn: 65001,
            community_filter: vec![20, 10, 20],
            large_community_filter: vec![
                "65001:2:3".to_string(),
                "65001:1:2".to_string(),
                "65001:2:3".to_string(),
                "not-a-large-community".to_string(),
            ],
            ..list_routes_request()
        };
        let base_identity = route_page_identity(&base);
        assert_eq!(base_identity.len(), 64);
        let token = encode_route_page_token(scope, &base_identity, &key, version);

        // Host bits, OR-filter ordering/duplicates, invalid large-community
        // spellings, and page size do not change the query's semantics.
        let equivalent = proto::ListRoutesRequest {
            page_size: 999,
            prefix_filter: "10.0.0.254".to_string(),
            community_filter: vec![10, 20],
            large_community_filter: vec![
                "another-invalid-value".to_string(),
                "65001:1:2".to_string(),
                "65001:2:3".to_string(),
            ],
            page_token: token.clone(),
            ..base.clone()
        };
        let equivalent_identity = route_page_identity(&equivalent);
        assert_eq!(equivalent_identity, base_identity);
        assert_eq!(
            parse_route_page_params(&equivalent, scope, &equivalent_identity).unwrap(),
            (Some(key), Some(version), 999)
        );

        let mut changed_requests = Vec::new();
        let mut changed = base.clone();
        changed.afi_safi = proto::AddressFamily::Ipv6Unicast as i32;
        changed_requests.push(changed);
        let mut changed = base.clone();
        changed.prefix_filter = "10.0.1.1".to_string();
        changed_requests.push(changed);
        let mut changed = base.clone();
        changed.longer_prefixes = false;
        changed_requests.push(changed);
        let mut changed = base.clone();
        changed.origin_asn = 65002;
        changed_requests.push(changed);
        let mut changed = base.clone();
        changed.community_filter = vec![10, 21];
        changed_requests.push(changed);
        let mut changed = base.clone();
        changed.large_community_filter = vec!["65001:1:2".to_string(), "65001:9:9".to_string()];
        changed_requests.push(changed);
        let mut changed = base.clone();
        changed.large_community_filter.clear();
        changed_requests.push(changed);

        for mut changed in changed_requests {
            let changed_identity = route_page_identity(&changed);
            assert_ne!(changed_identity, base_identity);
            changed.page_token = token.clone();
            let error = parse_route_page_params(&changed, scope, &changed_identity).unwrap_err();
            assert_eq!(error.code(), tonic::Code::InvalidArgument);
            assert!(error.message().contains("different route filters"));
        }
    }

    #[test]
    fn route_page_filter_identity_tracks_match_none_and_ignored_fields() {
        let invalid_a = proto::ListRoutesRequest {
            large_community_filter: vec!["invalid-a".to_string()],
            ..list_routes_request()
        };
        let invalid_b = proto::ListRoutesRequest {
            large_community_filter: vec!["invalid-b".to_string(), "invalid-c".to_string()],
            ..list_routes_request()
        };
        assert_eq!(
            route_page_identity(&invalid_a),
            route_page_identity(&invalid_b),
            "all invalid non-empty large-community filters have match-none semantics"
        );
        assert_ne!(
            route_page_identity(&invalid_a),
            route_page_identity(&list_routes_request()),
            "match-none must remain distinct from no large-community filter"
        );

        let longer_without_prefix = proto::ListRoutesRequest {
            longer_prefixes: true,
            ..list_routes_request()
        };
        assert_eq!(
            route_page_identity(&longer_without_prefix),
            route_page_identity(&list_routes_request()),
            "longer_prefixes is semantically ignored without prefix_filter"
        );
    }

    #[test]
    fn route_page_token_rejects_cross_scope_reuse() {
        let key = (
            Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
            "192.0.2.1".parse().unwrap(),
            0,
        );
        let mut request = list_routes_request();
        let query_identity = route_page_identity(&request);
        request.page_token = encode_route_page_token(
            RouteQueryScope::Best,
            &query_identity,
            &key,
            RoutePageVersion {
                epoch: 1,
                generation: 2,
            },
        );
        let error = parse_route_page_params(
            &request,
            RouteQueryScope::Received { peer: None },
            &query_identity,
        )
        .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(error.message().contains("different route scope"));
    }

    #[tokio::test]
    async fn stale_route_page_generation_maps_to_aborted_restart() {
        let (tx, mut rx) = mpsc::channel(1);
        tokio::spawn(async move {
            if let Some(RibUpdate::QueryRoutesPage { reply, .. }) = rx.recv().await {
                let _ = reply.send(Err(RoutePageError::Invalidated));
            }
        });
        let service = RibService::new(tx);
        let error = service
            .list_best_routes(Request::new(list_routes_request()))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Aborted);
        assert!(error.message().contains("empty page_token"));
    }

    #[tokio::test]
    async fn list_received_routes_pages_through_the_actor() {
        // The RPC forwards cursor + page size to the actor and turns the
        // page's last key into the next_page_token when more rows remain.
        let (tx, mut rx) = mpsc::channel(16);
        let peer: IpAddr = "192.0.2.1".parse().unwrap();
        let route = {
            let mut route = test_route(
                Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
                vec![],
            );
            route.peer = peer;
            route
        };
        let page_route = route.clone();
        tokio::spawn(async move {
            while let Some(update) = rx.recv().await {
                if let RibUpdate::QueryRoutesPage {
                    scope,
                    filter,
                    after,
                    expected_version,
                    page_size,
                    reply,
                } = update
                {
                    assert_eq!(scope, RouteQueryScope::Received { peer: None });
                    assert!(filter.is_none(), "unfiltered list sends no predicate");
                    assert!(after.is_none());
                    assert!(expected_version.is_none());
                    assert_eq!(page_size, 1);
                    let _ = reply.send(Ok(RoutePage {
                        routes: vec![page_route.clone()],
                        total: 2,
                        has_more: true,
                        version: RoutePageVersion {
                            epoch: 7,
                            generation: 9,
                        },
                    }));
                }
            }
        });

        let svc = RibService::new(tx);
        let resp = svc
            .list_received_routes(Request::new(proto::ListRoutesRequest {
                page_size: 1,
                ..list_routes_request()
            }))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(resp.total_count, 2);
        assert_eq!(resp.routes.len(), 1);
        assert_eq!(resp.routes[0].prefix, "10.0.0.0");
        let query_identity = route_page_identity(&proto::ListRoutesRequest {
            page_size: 1,
            ..list_routes_request()
        });
        assert_eq!(
            resp.next_page_token,
            encode_route_page_token(
                RouteQueryScope::Received { peer: None },
                &query_identity,
                &route_query_key(&route),
                RoutePageVersion {
                    epoch: 7,
                    generation: 9
                }
            )
        );
    }

    #[tokio::test]
    async fn continuation_token_forwards_scope_key_and_generation_to_actor() {
        let (tx, mut rx) = mpsc::channel(1);
        let scope = RouteQueryScope::Received { peer: None };
        let key = (
            Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
            "192.0.2.1".parse().unwrap(),
            7,
        );
        let version = RoutePageVersion {
            epoch: 11,
            generation: 13,
        };
        let query_identity = route_page_identity(&list_routes_request());
        tokio::spawn(async move {
            if let Some(RibUpdate::QueryRoutesPage {
                scope: actual_scope,
                after,
                expected_version,
                reply,
                ..
            }) = rx.recv().await
            {
                assert_eq!(actual_scope, scope);
                assert_eq!(after, Some(key));
                assert_eq!(expected_version, Some(version));
                let _ = reply.send(Ok(RoutePage {
                    routes: Vec::new(),
                    total: 1,
                    has_more: false,
                    version,
                }));
            }
        });

        let service = RibService::new(tx);
        let response = service
            .list_received_routes(Request::new(proto::ListRoutesRequest {
                page_size: 1,
                page_token: encode_route_page_token(scope, &query_identity, &key, version),
                ..list_routes_request()
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.total_count, 1);
        assert!(response.next_page_token.is_empty());
    }

    #[tokio::test]
    async fn list_routes_distinguishes_med_absent_from_med_zero() {
        // LAN-313: `med_attr` is the honest absence marker — a route
        // whose MED attribute is explicitly 0 and a route with no MED
        // attribute both encode bare `med = 0`, but must differ in
        // `med_attr` through the service and a wire round trip.
        use prost::Message;

        let (tx, mut rx) = mpsc::channel(16);
        let med_zero = test_route(
            Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
            vec![PathAttribute::Med(0)],
        );
        let med_absent = test_route(
            Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 1, 0), 24)),
            vec![],
        );
        let page = vec![med_zero, med_absent];
        tokio::spawn(async move {
            while let Some(update) = rx.recv().await {
                if let RibUpdate::QueryRoutesPage { reply, .. } = update {
                    let _ = reply.send(Ok(RoutePage {
                        routes: page.clone(),
                        total: 2,
                        has_more: false,
                        version: RoutePageVersion::default(),
                    }));
                }
            }
        });

        let svc = RibService::new(tx);
        let resp = svc
            .list_received_routes(Request::new(list_routes_request()))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(resp.routes.len(), 2);
        let zero = &resp.routes[0];
        let absent = &resp.routes[1];
        assert_eq!(zero.med, 0);
        assert_eq!(absent.med, 0, "bare med conflates absent with 0");
        assert_eq!(zero.med_attr, Some(0));
        assert_eq!(absent.med_attr, None);

        // The distinction must survive protobuf encode/decode.
        let decoded = proto::Route::decode(zero.encode_to_vec().as_slice()).unwrap();
        assert_eq!(decoded.med_attr, Some(0));
        let decoded = proto::Route::decode(absent.encode_to_vec().as_slice()).unwrap();
        assert_eq!(decoded.med_attr, None);
    }

    #[tokio::test]
    async fn list_received_routes_rejects_invalid_page_token() {
        let svc = make_service();
        let err = svc
            .list_received_routes(Request::new(proto::ListRoutesRequest {
                page_token: "not-a-token".to_string(),
                ..list_routes_request()
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("page_token"));
    }
}
