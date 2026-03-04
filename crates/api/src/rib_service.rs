use std::net::IpAddr;
use std::pin::Pin;

use tokio::sync::{mpsc, oneshot};
use tokio_stream::{Stream, StreamExt, wrappers::BroadcastStream};
use tonic::{Request, Response, Status};
use tracing::debug;

use crate::proto;
use rustbgpd_rib::{FlowSpecRoute, RibUpdate, Route, RouteEventType};
use rustbgpd_wire::{Afi, AsPathSegment, PathAttribute, Prefix};

pub struct RibService {
    rib_tx: mpsc::Sender<RibUpdate>,
}

impl RibService {
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

fn route_to_proto(route: &Route, best: bool) -> proto::Route {
    let mut origin = 0u32;
    let mut as_path = Vec::new();
    let mut local_pref = 0u32;
    let mut med = 0u32;
    let mut communities = Vec::new();
    let mut extended_communities = Vec::new();
    let mut large_communities = Vec::new();

    for attr in &route.attributes {
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

        let all_routes = self.query_routes(peer).await?;
        let all_routes = filter_routes_by_family(all_routes, req.afi_safi);
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
        let all_routes = self.query_best_routes().await?;
        let all_routes = filter_routes_by_family(all_routes, req.afi_safi);
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

        let all_routes = reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?;
        let all_routes = filter_routes_by_family(all_routes, req.afi_safi);

        let (offset, page_size) = parse_page_params(&req).map_err(Status::invalid_argument)?;
        Ok(Response::new(build_response(
            &all_routes,
            offset,
            page_size,
            false,
        )))
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
    use super::*;
    use proto::rib_service_server::RibService as _;

    fn make_service() -> RibService {
        let (tx, _rx) = mpsc::channel(16);
        RibService::new(tx)
    }

    #[test]
    fn filter_routes_unspecified_returns_all() {
        use rustbgpd_wire::{Ipv4Prefix, Ipv6Prefix};
        use std::net::Ipv4Addr;

        let v4 = Route {
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
            next_hop: "10.0.0.1".parse().unwrap(),
            peer: "10.0.0.1".parse().unwrap(),
            attributes: vec![],
            received_at: std::time::Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        };
        let v6 = Route {
            prefix: Prefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32)),
            next_hop: "2001:db8::1".parse().unwrap(),
            peer: "2001:db8::1".parse().unwrap(),
            attributes: vec![],
            received_at: std::time::Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
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
        });
        let err = svc.list_received_routes(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
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
}
