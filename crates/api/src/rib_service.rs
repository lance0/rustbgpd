//! gRPC RIB service — route listing, filtering, and streaming.

use std::net::IpAddr;
use std::pin::Pin;

use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::{Stream, StreamExt, wrappers::BroadcastStream};
use tonic::{Request, Response, Status};
use tracing::debug;

use crate::proto;
use rustbgpd_rib::{
    EvpnRibRoute, ExplainAdvertisedRoute, ExplainBestPath, ExplainDecision, FlowSpecRoute,
    RibUpdate, Route, RouteEventType,
};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{Afi, AsPath, AsPathSegment, EvpnRoute, PathAttribute, Prefix};

/// Live snapshot provider for daemon-owned BLACKHOLE discard status.
pub type BlackholeDiscardSnapshotFn =
    std::sync::Arc<dyn Fn() -> Vec<proto::BlackholeDiscard> + Send + Sync + 'static>;

/// Live snapshot provider for daemon-owned general FIB route status.
pub type FibRouteSnapshotFn =
    std::sync::Arc<dyn Fn() -> Vec<proto::FibRouteStatus> + Send + Sync + 'static>;

/// gRPC service for querying the RIB (received, best, advertised routes).
pub struct RibService {
    rib_tx: mpsc::Sender<RibUpdate>,
    blackhole_discard_snapshot: BlackholeDiscardSnapshotFn,
    fib_route_snapshot: FibRouteSnapshotFn,
    metrics: BgpMetrics,
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
        }
    }

    async fn query_routes(&self, peer: Option<IpAddr>) -> Result<Vec<Route>, Status> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::QueryReceivedRoutes {
                peer,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("RIB manager unavailable"))?;

        reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))
    }

    async fn query_best_routes(&self) -> Result<Vec<Route>, Status> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .map_err(|_| Status::internal("RIB manager unavailable"))?;

        reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))
    }

    async fn query_explain_advertised_route(
        &self,
        peer: IpAddr,
        prefix: Prefix,
    ) -> Result<Option<ExplainAdvertisedRoute>, Status> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::ExplainAdvertisedRoute {
                peer,
                prefix,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("RIB manager unavailable"))?;

        reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))
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
#[allow(clippy::result_large_err)]
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
#[allow(clippy::result_large_err)]
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

/// Filter routes by the requested address family.
/// `afi_safi == 0` (UNSPECIFIED) returns all routes.
fn filter_routes_by_family(routes: Vec<Route>, afi_safi: i32) -> Vec<Route> {
    match afi_safi {
        x if x == proto::AddressFamily::Ipv4Unicast as i32 => routes
            .into_iter()
            .filter(|r| matches!(r.prefix, Prefix::V4(_)))
            .collect(),
        x if x == proto::AddressFamily::Ipv6Unicast as i32 => routes
            .into_iter()
            .filter(|r| matches!(r.prefix, Prefix::V6(_)))
            .collect(),
        _ => routes, // 0 (unspecified) = all
    }
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
    /// Large community strings to match (OR logic).
    large_communities: Vec<String>,
}

impl RouteFilters {
    #[allow(clippy::result_large_err)]
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

        Ok(Self {
            prefix,
            longer: req.longer_prefixes,
            origin_asn: req.origin_asn,
            communities: req.community_filter.clone(),
            large_communities: req.large_community_filter.clone(),
        })
    }

    fn is_empty(&self) -> bool {
        self.prefix.is_none()
            && self.origin_asn == 0
            && self.communities.is_empty()
            && self.large_communities.is_empty()
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

        if self.origin_asn != 0 {
            let origin_asn = route.as_path().and_then(AsPath::origin_asn);
            if origin_asn != Some(self.origin_asn) {
                return false;
            }
        }

        if !self.communities.is_empty()
            && !self
                .communities
                .iter()
                .any(|c| route.communities().contains(c))
        {
            return false;
        }

        if !self.large_communities.is_empty() {
            let route_lcs: Vec<String> = route
                .large_communities()
                .iter()
                .map(ToString::to_string)
                .collect();
            if !self
                .large_communities
                .iter()
                .any(|lc| route_lcs.contains(lc))
            {
                return false;
            }
        }

        true
    }
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

/// Apply route filters to a list of routes.
fn apply_route_filters(routes: Vec<Route>, filters: &RouteFilters) -> Vec<Route> {
    if filters.is_empty() {
        return routes;
    }
    routes.into_iter().filter(|r| filters.matches(r)).collect()
}

struct FibRouteFilters {
    table_name: Option<String>,
    state: Option<proto::FibRouteState>,
    reason: Option<String>,
    prefix: Option<(String, u32)>,
    peer_address: Option<String>,
}

impl FibRouteFilters {
    #[allow(clippy::result_large_err)]
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

fn prefix_parts(prefix: Prefix) -> (String, u32) {
    match prefix {
        Prefix::V4(prefix) => (prefix.addr.to_string(), u32::from(prefix.len)),
        Prefix::V6(prefix) => (prefix.addr.to_string(), u32::from(prefix.len)),
    }
}

fn parse_page_params(req: &proto::ListRoutesRequest) -> Result<(usize, usize), &'static str> {
    let offset: usize = if req.page_token.is_empty() {
        0
    } else {
        req.page_token.parse().map_err(|_| "invalid page_token")?
    };

    let page_size = if req.page_size == 0 {
        100
    } else {
        req.page_size as usize
    };

    Ok((offset, page_size))
}

fn build_response(
    routes: &[Route],
    offset: usize,
    page_size: usize,
    best: bool,
) -> proto::ListRoutesResponse {
    let total_count = u64::try_from(routes.len()).unwrap_or(u64::MAX);
    let page: Vec<proto::Route> = routes
        .iter()
        .skip(offset)
        .take(page_size)
        .map(|r| route_to_proto(r, best))
        .collect();

    let next_offset = offset + page.len();
    let next_page_token = if next_offset < routes.len() {
        next_offset.to_string()
    } else {
        String::new()
    };

    proto::ListRoutesResponse {
        routes: page,
        next_page_token,
        total_count,
    }
}

#[allow(clippy::result_large_err)]
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

#[allow(clippy::result_large_err)]
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
    }
}

fn explain_best_path_to_proto(explain: ExplainBestPath) -> proto::ExplainBestPathResponse {
    proto::ExplainBestPathResponse {
        prefix: explain.prefix.addr_string(),
        prefix_length: u32::from(explain.prefix.prefix_len()),
        best_route: explain.best.as_ref().map(|r| route_to_proto(r, true)),
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
        // Distinguishes "explicit LOCAL_PREF attribute" from "no
        // attribute" — required for the M35 interop test to assert
        // that the RFC 8326 implicit demotion actually fired on a
        // tagged route (otherwise local_pref=0 is ambiguous between
        // "policy set it" and "no LOCAL_PREF on EBGP wire").
        local_pref_attr: route.local_pref_attr(),
    }
}

pub(crate) fn route_event_to_proto(event: rustbgpd_rib::RouteEvent) -> proto::RouteEvent {
    let event_type = match event.event_type {
        RouteEventType::Added => proto::RouteEventType::Added,
        RouteEventType::Withdrawn => proto::RouteEventType::Withdrawn,
        RouteEventType::BestChanged => proto::RouteEventType::BestChanged,
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
        if !matches_current && !matches_previous {
            return false;
        }
    }

    true
}

fn route_event_bgp_event_type(event_type: i32) -> proto::BgpEventType {
    match proto::RouteEventType::try_from(event_type) {
        Ok(proto::RouteEventType::Added) => proto::BgpEventType::RouteAdded,
        Ok(proto::RouteEventType::Withdrawn) => proto::BgpEventType::RouteWithdrawn,
        Ok(proto::RouteEventType::BestChanged) => proto::BgpEventType::RouteBestChanged,
        Ok(proto::RouteEventType::Unspecified) | Err(_) => proto::BgpEventType::Unspecified,
    }
}

fn route_event_to_bgp_event(event: rustbgpd_rib::RouteEvent) -> proto::BgpEvent {
    let route = route_event_to_proto(event);
    let event_type = route_event_bgp_event_type(route.event_type);
    let label = match event_type {
        proto::BgpEventType::RouteAdded => "added",
        proto::BgpEventType::RouteWithdrawn => "withdrawn",
        proto::BgpEventType::RouteBestChanged => "best changed",
        _ => "changed",
    };
    let summary = format!("route {label} {}/{}", route.prefix, route.prefix_length);

    proto::BgpEvent {
        timestamp: route.timestamp.clone(),
        category: proto::EventCategory::Route as i32,
        event_type: event_type as i32,
        severity: proto::EventSeverity::Info as i32,
        peer_address: route.peer_address.clone(),
        previous_peer_address: route.previous_peer_address.clone(),
        prefix: route.prefix.clone(),
        prefix_length: route.prefix_length,
        afi_safi: route.afi_safi,
        summary,
        payload: Some(proto::bgp_event::Payload::Route(route)),
    }
}

fn route_stream_lag_bgp_event(missed_count: u64) -> proto::BgpEvent {
    let summary = format!("route event stream lagged; missed {missed_count} event(s)");
    proto::BgpEvent {
        timestamp: rustbgpd_rib::event::unix_timestamp_now(),
        category: proto::EventCategory::Route as i32,
        event_type: proto::BgpEventType::StreamLagged as i32,
        severity: proto::EventSeverity::Warning as i32,
        peer_address: String::new(),
        previous_peer_address: String::new(),
        prefix: String::new(),
        prefix_length: 0,
        afi_safi: proto::AddressFamily::Unspecified as i32,
        summary: summary.clone(),
        payload: Some(proto::bgp_event::Payload::StreamLag(
            proto::StreamLagEvent {
                source_category: proto::EventCategory::Route as i32,
                missed_count,
                reason: summary,
            },
        )),
    }
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
        let all_routes = self.query_routes(peer).await?;
        let all_routes = filter_routes_by_family(all_routes, req.afi_safi);
        let all_routes = apply_route_filters(all_routes, &filters);
        let (offset, page_size) = parse_page_params(&req).map_err(Status::invalid_argument)?;
        Ok(Response::new(build_response(
            &all_routes,
            offset,
            page_size,
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
        let all_routes = self.query_best_routes().await?;
        let all_routes = filter_routes_by_family(all_routes, req.afi_safi);
        let all_routes = apply_route_filters(all_routes, &filters);
        let (offset, page_size) = parse_page_params(&req).map_err(Status::invalid_argument)?;
        Ok(Response::new(build_response(
            &all_routes,
            offset,
            page_size,
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

        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::QueryAdvertisedRoutes {
                peer,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("RIB manager unavailable"))?;

        let filters = RouteFilters::from_request(&req)?;
        let all_routes = reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?;
        let all_routes = filter_routes_by_family(all_routes, req.afi_safi);
        let all_routes = apply_route_filters(all_routes, &filters);

        let (offset, page_size) = parse_page_params(&req).map_err(Status::invalid_argument)?;
        Ok(Response::new(build_response(
            &all_routes,
            offset,
            page_size,
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
        let Some(explain) = self.query_explain_advertised_route(peer, prefix).await? else {
            return Err(Status::not_found(
                "peer not registered for outbound updates",
            ));
        };
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
        let filters = FibRouteFilters::from_request(&request.into_inner())?;
        let routes = (self.fib_route_snapshot)()
            .into_iter()
            .filter(|route| filters.matches(route))
            .collect();
        Ok(Response::new(proto::ListFibRoutesResponse { routes }))
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
                Some(Ok(route_stream_lag_bgp_event(missed)))
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

        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::QueryEvpnRoutes { reply: reply_tx })
            .await
            .map_err(|_| Status::internal("RIB manager unavailable"))?;

        let all_routes = reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?;

        let type_filter = req.route_type_filter;
        let peer_filter = req.peer_filter;
        let rd_filter = req.rd_filter;

        let routes: Vec<proto::EvpnRouteEntry> = all_routes
            .iter()
            .filter(|r| {
                if type_filter != 0 && u32::from(r.route_type()) != type_filter {
                    return false;
                }
                if !peer_filter.is_empty() && r.peer.to_string() != peer_filter {
                    return false;
                }
                if !rd_filter.is_empty() {
                    let entry_rd = match &r.route {
                        EvpnRoute::EadPerEs(e) => e.rd.to_string(),
                        EvpnRoute::EadPerEvi(e) => e.rd.to_string(),
                        EvpnRoute::MacIp(e) => e.rd.to_string(),
                        EvpnRoute::Imet(e) => e.rd.to_string(),
                        EvpnRoute::Es(e) => e.rd.to_string(),
                        EvpnRoute::IpPrefix(e) => e.rd.to_string(),
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
}

#[expect(clippy::too_many_lines)]
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
        Afi::L2Vpn => proto::AddressFamily::Unspecified,
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

#[expect(clippy::too_many_lines)]
fn evpn_route_to_proto(route: &EvpnRibRoute) -> proto::EvpnRouteEntry {
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
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use prometheus::Encoder;
    use tokio::sync::broadcast;
    use tokio_stream::StreamExt;

    use rustbgpd_wire::{Ipv4Prefix, Ipv6Prefix};

    use super::*;
    use proto::rib_service_server::RibService as _;

    fn gather_text(metrics: &BgpMetrics) -> String {
        let encoder = prometheus::TextEncoder::new();
        let families = metrics.registry().gather();
        let mut out = Vec::new();
        encoder.encode(&families, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    fn make_service() -> RibService {
        let (tx, _rx) = mpsc::channel(16);
        RibService::new(tx)
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

    fn route_event(prefix: Prefix, peer: IpAddr) -> rustbgpd_rib::RouteEvent {
        rustbgpd_rib::RouteEvent {
            event_id: 0,
            event_type: RouteEventType::Added,
            prefix,
            peer: Some(peer),
            previous_peer: None,
            timestamp: "123".to_string(),
            path_id: 0,
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
                timestamp: "123".to_string(),
                path_id: 99,
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
        };
        let v6 = Route {
            prefix: Prefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32)),
            next_hop: "2001:db8::1".parse().unwrap(),
            link_local_next_hop: None,
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
        };

        // Unspecified returns all
        let all = filter_routes_by_family(vec![v4.clone(), v6.clone()], 0);
        assert_eq!(all.len(), 2);

        // IPv4 filter
        let v4_only = filter_routes_by_family(
            vec![v4.clone(), v6.clone()],
            proto::AddressFamily::Ipv4Unicast as i32,
        );
        assert_eq!(v4_only.len(), 1);
        assert!(matches!(v4_only[0].prefix, Prefix::V4(_)));

        // IPv6 filter
        let v6_only =
            filter_routes_by_family(vec![v4, v6], proto::AddressFamily::Ipv6Unicast as i32);
        assert_eq!(v6_only.len(), 1);
        assert!(matches!(v6_only[0].prefix, Prefix::V6(_)));
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
            }))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(resp.routes.len(), 1);
        assert_eq!(resp.routes[0].peer_address, "198.51.100.2");
        assert_eq!(resp.routes[0].state, proto::FibRouteState::Rejected as i32);
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
    }

    #[tokio::test]
    async fn explain_advertised_route_rejects_invalid_peer_address() {
        let svc = make_service();
        let req = Request::new(proto::ExplainAdvertisedRouteRequest {
            peer_address: "not-an-ip".to_string(),
            prefix: "203.0.113.0".to_string(),
            prefix_length: 24,
        });
        let err = svc.explain_advertised_route(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn explain_advertised_route_round_trips() {
        let (tx, mut rx) = mpsc::channel(16);
        let svc = RibService::new(tx);
        let req = Request::new(proto::ExplainAdvertisedRouteRequest {
            peer_address: "192.0.2.1".to_string(),
            prefix: "203.0.113.0".to_string(),
            prefix_length: 24,
        });

        let call = tokio::spawn(async move { svc.explain_advertised_route(req).await });
        let update = rx.recv().await.unwrap();
        let reply = match update {
            RibUpdate::ExplainAdvertisedRoute {
                peer,
                prefix,
                reply,
            } => {
                assert_eq!(peer, "192.0.2.1".parse::<IpAddr>().unwrap());
                assert_eq!(
                    prefix,
                    Prefix::V4(Ipv4Prefix::new("203.0.113.0".parse().unwrap(), 24))
                );
                reply
            }
            _ => panic!("unexpected update variant"),
        };
        reply
            .send(Some(ExplainAdvertisedRoute {
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
            }))
            .unwrap();

        let resp = call.await.unwrap().unwrap().into_inner();
        assert_eq!(resp.decision, proto::ExplainDecision::Advertise as i32);
        assert_eq!(resp.peer_address, "192.0.2.1");
        assert_eq!(resp.route_peer_address, "198.51.100.2");
        assert_eq!(resp.route_type, "external");
        assert_eq!(resp.reasons.len(), 1);
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

    #[test]
    fn route_filters_exact_prefix() {
        let route = Route {
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 24)),
            next_hop: "10.0.0.1".parse().unwrap(),
            link_local_next_hop: None,
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
        };

        let filters = RouteFilters {
            prefix: Some(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 24))),
            longer: false,
            origin_asn: 0,
            communities: vec![],
            large_communities: vec![],
        };
        assert!(filters.matches(&route));

        let wrong_prefix = RouteFilters {
            prefix: Some(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 2, 0, 0), 24))),
            longer: false,
            origin_asn: 0,
            communities: vec![],
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
        };

        let filters = RouteFilters {
            prefix: None,
            longer: false,
            origin_asn: 0,
            communities: vec![community_val],
            large_communities: vec![],
        };
        assert!(filters.matches(&route));

        let wrong_community = RouteFilters {
            prefix: None,
            longer: false,
            origin_asn: 0,
            communities: vec![65002u32 * 65536 + 200],
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
        };

        let filters = RouteFilters {
            prefix: None,
            longer: false,
            origin_asn: 65003,
            communities: vec![],
            large_communities: vec![],
        };
        assert!(filters.matches(&route));

        let wrong_asn = RouteFilters {
            prefix: None,
            longer: false,
            origin_asn: 65001,
            communities: vec![],
            large_communities: vec![],
        };
        assert!(!wrong_asn.matches(&route));
    }
}
