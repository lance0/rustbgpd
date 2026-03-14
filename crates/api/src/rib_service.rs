//! gRPC RIB service — route listing, filtering, and streaming.

use std::net::IpAddr;
use std::pin::Pin;

use tokio::sync::{mpsc, oneshot};
use tokio_stream::{Stream, StreamExt, wrappers::BroadcastStream};
use tonic::{Request, Response, Status};
use tracing::debug;

use crate::proto;
use rustbgpd_rib::{
    ExplainAdvertisedRoute, ExplainDecision, FlowSpecRoute, RibUpdate, Route, RouteEventType,
};
use rustbgpd_wire::{Afi, AsPath, AsPathSegment, PathAttribute, Prefix};

/// gRPC service for querying the RIB (received, best, advertised routes).
pub struct RibService {
    rib_tx: mpsc::Sender<RibUpdate>,
}

impl RibService {
    /// Create a new RIB service backed by the given RIB channel.
    pub fn new(rib_tx: mpsc::Sender<RibUpdate>) -> Self {
        Self { rib_tx }
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
}

/// Validate the requested address family.
/// 0 = UNSPECIFIED (treat as "any"), 1-4 = valid families.
#[allow(clippy::result_large_err)]
fn validate_afi_safi(value: i32) -> Result<(), Status> {
    if value != 0
        && value != proto::AddressFamily::Ipv4Unicast as i32
        && value != proto::AddressFamily::Ipv6Unicast as i32
        && value != proto::AddressFamily::Ipv4Flowspec as i32
        && value != proto::AddressFamily::Ipv6Flowspec as i32
    {
        return Err(Status::invalid_argument("unsupported address family"));
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
            None
        } else {
            let addr: IpAddr = req.prefix_filter.parse().map_err(|e| {
                Status::invalid_argument(format!("invalid prefix_filter address: {e}"))
            })?;
            let len = u8::try_from(req.prefix_filter_length)
                .map_err(|_| Status::invalid_argument("prefix_filter_length must be 0-128"))?;
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
    let len = u8::try_from(prefix_length)
        .map_err(|_| Status::invalid_argument("prefix_length must be 0-128"))?;
    Ok(match addr {
        IpAddr::V4(v4) => Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(v4, len)),
        IpAddr::V6(v6) => Prefix::V6(rustbgpd_wire::Ipv6Prefix::new(v6, len)),
    })
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
    }
}

#[tonic::async_trait]
impl proto::rib_service_server::RibService for RibService {
    type WatchRoutesStream =
        Pin<Box<dyn Stream<Item = Result<proto::RouteEvent, Status>> + Send + 'static>>;

    async fn list_received_routes(
        &self,
        request: Request<proto::ListRoutesRequest>,
    ) -> Result<Response<proto::ListRoutesResponse>, Status> {
        let req = request.into_inner();
        validate_afi_safi(req.afi_safi)?;

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
        validate_afi_safi(req.afi_safi)?;
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
        validate_afi_safi(req.afi_safi)?;

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

    async fn watch_routes(
        &self,
        request: Request<proto::WatchRoutesRequest>,
    ) -> Result<Response<Self::WatchRoutesStream>, Status> {
        let req = request.into_inner();
        validate_afi_safi(req.afi_safi)?;

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

        let stream = BroadcastStream::new(broadcast_rx).filter_map(move |result| match result {
            Ok(event) => {
                // Filter by AFI/SAFI if requested
                if afi_safi_filter != 0 {
                    let is_v4 = matches!(event.prefix, Prefix::V4(_));
                    let want_v4 = afi_safi_filter == proto::AddressFamily::Ipv4Unicast as i32;
                    if is_v4 != want_v4 {
                        return None;
                    }
                }

                // Filter by peer address if requested — check both current
                // and previous peer so subscribers filtered to a specific peer
                // see BestChanged/Withdrawn events when the route moves away.
                if let Some(filter_addr) = peer_filter {
                    let matches_current = event.peer == Some(filter_addr);
                    let matches_previous = event.previous_peer == Some(filter_addr);
                    if !matches_current && !matches_previous {
                        return None;
                    }
                }

                let event_type = match event.event_type {
                    RouteEventType::Added => proto::RouteEventType::Added,
                    RouteEventType::Withdrawn => proto::RouteEventType::Withdrawn,
                    RouteEventType::BestChanged => proto::RouteEventType::BestChanged,
                };

                Some(Ok(proto::RouteEvent {
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
                }))
            }
            Err(_lagged) => {
                debug!("WatchRoutes subscriber lagged, skipping missed events");
                None
            }
        });

        Ok(Response::new(Box::pin(stream)))
    }

    async fn list_flow_spec_routes(
        &self,
        request: Request<proto::ListFlowSpecRequest>,
    ) -> Result<Response<proto::ListFlowSpecResponse>, Status> {
        let req = request.into_inner();

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

    let afi_safi = match route.afi {
        Afi::Ipv4 => proto::AddressFamily::Ipv4Flowspec,
        Afi::Ipv6 => proto::AddressFamily::Ipv6Flowspec,
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

    use rustbgpd_wire::{Ipv4Prefix, Ipv6Prefix};

    use super::*;
    use proto::rib_service_server::RibService as _;

    fn make_service() -> RibService {
        let (tx, _rx) = mpsc::channel(16);
        RibService::new(tx)
    }

    #[test]
    fn filter_routes_unspecified_returns_all() {
        let v4 = Route {
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
            next_hop: "10.0.0.1".parse().unwrap(),
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
            neighbor_address: String::new(),
            afi_safi: 99, // unsupported value
            page_size: 0,
            page_token: String::new(),
            prefix_filter: String::new(),
            prefix_filter_length: 0,
            longer_prefixes: false,
            origin_asn: 0,
            community_filter: vec![],
            large_community_filter: vec![],
        });
        let err = svc.list_received_routes(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
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
    fn route_filters_exact_prefix() {
        let route = Route {
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 24)),
            next_hop: "10.0.0.1".parse().unwrap(),
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
