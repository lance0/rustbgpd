use std::net::IpAddr;
use std::pin::Pin;

use tokio::sync::{mpsc, oneshot};
use tonic::codegen::tokio_stream::Stream;
use tonic::{Request, Response, Status};

use crate::proto;
use rustbgpd_rib::{RibUpdate, Route};
use rustbgpd_wire::{AsPathSegment, PathAttribute};

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

fn route_to_proto(route: &Route, best: bool) -> proto::Route {
    let mut origin = 0u32;
    let mut as_path = Vec::new();
    let mut local_pref = 0u32;
    let mut med = 0u32;

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
            _ => {}
        }
    }

    proto::Route {
        prefix: route.prefix.addr.to_string(),
        prefix_length: u32::from(route.prefix.len),
        next_hop: route.next_hop.to_string(),
        peer_address: route.peer.to_string(),
        origin,
        as_path,
        local_pref,
        med,
        best,
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
        let total_count = u64::try_from(all_routes.len()).unwrap_or(u64::MAX);

        let offset: usize = if req.page_token.is_empty() {
            0
        } else {
            req.page_token
                .parse()
                .map_err(|_| Status::invalid_argument("invalid page_token"))?
        };

        let page_size = if req.page_size == 0 {
            100
        } else {
            req.page_size as usize
        };

        let page: Vec<proto::Route> = all_routes
            .iter()
            .skip(offset)
            .take(page_size)
            .map(|r| route_to_proto(r, false))
            .collect();

        let next_offset = offset + page.len();
        let next_page_token = if next_offset < all_routes.len() {
            next_offset.to_string()
        } else {
            String::new()
        };

        Ok(Response::new(proto::ListRoutesResponse {
            routes: page,
            next_page_token,
            total_count,
        }))
    }

    async fn list_best_routes(
        &self,
        request: Request<proto::ListRoutesRequest>,
    ) -> Result<Response<proto::ListRoutesResponse>, Status> {
        let req = request.into_inner();
        let all_routes = self.query_best_routes().await?;
        let total_count = u64::try_from(all_routes.len()).unwrap_or(u64::MAX);

        let offset: usize = if req.page_token.is_empty() {
            0
        } else {
            req.page_token
                .parse()
                .map_err(|_| Status::invalid_argument("invalid page_token"))?
        };

        let page_size = if req.page_size == 0 {
            100
        } else {
            req.page_size as usize
        };

        let page: Vec<proto::Route> = all_routes
            .iter()
            .skip(offset)
            .take(page_size)
            .map(|r| route_to_proto(r, true))
            .collect();

        let next_offset = offset + page.len();
        let next_page_token = if next_offset < all_routes.len() {
            next_offset.to_string()
        } else {
            String::new()
        };

        Ok(Response::new(proto::ListRoutesResponse {
            routes: page,
            next_page_token,
            total_count,
        }))
    }

    async fn list_advertised_routes(
        &self,
        request: Request<proto::ListRoutesRequest>,
    ) -> Result<Response<proto::ListRoutesResponse>, Status> {
        let req = request.into_inner();

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

        let total_count = u64::try_from(all_routes.len()).unwrap_or(u64::MAX);

        let offset: usize = if req.page_token.is_empty() {
            0
        } else {
            req.page_token
                .parse()
                .map_err(|_| Status::invalid_argument("invalid page_token"))?
        };

        let page_size = if req.page_size == 0 {
            100
        } else {
            req.page_size as usize
        };

        let page: Vec<proto::Route> = all_routes
            .iter()
            .skip(offset)
            .take(page_size)
            .map(|r| route_to_proto(r, false))
            .collect();

        let next_offset = offset + page.len();
        let next_page_token = if next_offset < all_routes.len() {
            next_offset.to_string()
        } else {
            String::new()
        };

        Ok(Response::new(proto::ListRoutesResponse {
            routes: page,
            next_page_token,
            total_count,
        }))
    }

    async fn watch_routes(
        &self,
        _request: Request<proto::WatchRoutesRequest>,
    ) -> Result<Response<Self::WatchRoutesStream>, Status> {
        Err(Status::unimplemented("not yet implemented"))
    }
}
