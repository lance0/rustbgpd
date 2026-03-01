use std::net::IpAddr;
use std::pin::Pin;

use tokio::sync::{mpsc, oneshot};
use tokio_stream::{Stream, StreamExt, wrappers::BroadcastStream};
use tonic::{Request, Response, Status};
use tracing::debug;

use crate::proto;
use rustbgpd_rib::{RibUpdate, Route, RouteEventType};
use rustbgpd_wire::{AsPathSegment, PathAttribute, Prefix};

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
/// 0 = UNSPECIFIED (treat as "any"), 1 = `IPV4_UNICAST`, 2 = `IPV6_UNICAST`.
#[allow(clippy::result_large_err)]
fn validate_afi_safi(value: i32) -> Result<(), Status> {
    if value != 0
        && value != proto::AddressFamily::Ipv4Unicast as i32
        && value != proto::AddressFamily::Ipv6Unicast as i32
    {
        return Err(Status::invalid_argument(
            "unsupported address family",
        ));
    }
    Ok(())
}

/// Filter routes by the requested address family.
/// `afi_safi == 0` (UNSPECIFIED) returns all routes.
fn filter_routes_by_family(routes: Vec<Route>, afi_safi: i32) -> Vec<Route> {
    match afi_safi {
        x if x == proto::AddressFamily::Ipv4Unicast as i32 => {
            routes.into_iter().filter(|r| matches!(r.prefix, Prefix::V4(_))).collect()
        }
        x if x == proto::AddressFamily::Ipv6Unicast as i32 => {
            routes.into_iter().filter(|r| matches!(r.prefix, Prefix::V6(_))).collect()
        }
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
                }))
            }
            Err(_lagged) => {
                debug!("WatchRoutes subscriber lagged, skipping missed events");
                None
            }
        });

        Ok(Response::new(Box::pin(stream)))
    }
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
        use std::net::Ipv4Addr;
        use rustbgpd_wire::{Ipv4Prefix, Ipv6Prefix};

        let v4 = Route {
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
            next_hop: "10.0.0.1".parse().unwrap(),
            peer: "10.0.0.1".parse().unwrap(),
            attributes: vec![],
            received_at: std::time::Instant::now(),
            is_ebgp: false,
        };
        let v6 = Route {
            prefix: Prefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32)),
            next_hop: "2001:db8::1".parse().unwrap(),
            peer: "2001:db8::1".parse().unwrap(),
            attributes: vec![],
            received_at: std::time::Instant::now(),
            is_ebgp: false,
        };

        // Unspecified returns all
        let all = filter_routes_by_family(vec![v4.clone(), v6.clone()], 0);
        assert_eq!(all.len(), 2);

        // IPv4 filter
        let v4_only = filter_routes_by_family(vec![v4.clone(), v6.clone()], proto::AddressFamily::Ipv4Unicast as i32);
        assert_eq!(v4_only.len(), 1);
        assert!(matches!(v4_only[0].prefix, Prefix::V4(_)));

        // IPv6 filter
        let v6_only = filter_routes_by_family(vec![v4, v6], proto::AddressFamily::Ipv6Unicast as i32);
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
}
