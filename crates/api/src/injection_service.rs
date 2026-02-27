use std::net::Ipv4Addr;

use tokio::sync::{mpsc, oneshot};
use tonic::{Request, Response, Status};

use crate::proto;
use rustbgpd_rib::{RibUpdate, Route};
use rustbgpd_wire::{AsPath, AsPathSegment, Ipv4Prefix, Origin, PathAttribute};

pub struct InjectionService {
    rib_tx: mpsc::Sender<RibUpdate>,
}

impl InjectionService {
    pub fn new(rib_tx: mpsc::Sender<RibUpdate>) -> Self {
        Self { rib_tx }
    }
}

/// Sentinel peer address for locally-injected routes.
const LOCAL_PEER: std::net::IpAddr = std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED);

#[tonic::async_trait]
impl proto::injection_service_server::InjectionService for InjectionService {
    async fn add_path(
        &self,
        request: Request<proto::AddPathRequest>,
    ) -> Result<Response<proto::AddPathResponse>, Status> {
        let req = request.into_inner();

        let addr: Ipv4Addr = req
            .prefix
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid prefix address: {e}")))?;

        let len = u8::try_from(req.prefix_length)
            .ok()
            .filter(|&l| l <= 32)
            .ok_or_else(|| Status::invalid_argument("prefix_length must be 0..=32"))?;

        let prefix = Ipv4Prefix::new(addr, len);

        let next_hop: Ipv4Addr = req
            .next_hop
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid next_hop: {e}")))?;

        let origin = match req.origin {
            0 => Origin::Igp,
            1 => Origin::Egp,
            _ => Origin::Incomplete,
        };

        let mut attributes = vec![
            PathAttribute::Origin(origin),
            PathAttribute::NextHop(next_hop),
        ];

        if req.as_path.is_empty() {
            attributes.push(PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![])],
            }));
        } else {
            attributes.push(PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(req.as_path)],
            }));
        }

        if req.local_pref > 0 {
            attributes.push(PathAttribute::LocalPref(req.local_pref));
        }
        if req.med > 0 {
            attributes.push(PathAttribute::Med(req.med));
        }
        if !req.communities.is_empty() {
            attributes.push(PathAttribute::Communities(req.communities));
        }

        let route = Route {
            prefix,
            next_hop,
            peer: LOCAL_PEER,
            attributes,
            received_at: std::time::Instant::now(),
        };

        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::InjectRoute {
                route,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("RIB manager unavailable"))?;

        reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?
            .map_err(|e| Status::internal(format!("inject failed: {e}")))?;

        // UUID derived from prefix bytes
        let mut uuid = Vec::with_capacity(6);
        uuid.extend_from_slice(&addr.octets());
        uuid.push(len);
        uuid.push(0); // padding

        Ok(Response::new(proto::AddPathResponse { uuid }))
    }

    async fn delete_path(
        &self,
        request: Request<proto::DeletePathRequest>,
    ) -> Result<Response<proto::DeletePathResponse>, Status> {
        let req = request.into_inner();

        let addr: Ipv4Addr = req
            .prefix
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid prefix address: {e}")))?;

        let len = u8::try_from(req.prefix_length)
            .ok()
            .filter(|&l| l <= 32)
            .ok_or_else(|| Status::invalid_argument("prefix_length must be 0..=32"))?;

        let prefix = Ipv4Prefix::new(addr, len);

        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::WithdrawInjected {
                prefix,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("RIB manager unavailable"))?;

        reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?
            .map_err(|e| Status::internal(format!("withdraw failed: {e}")))?;

        Ok(Response::new(proto::DeletePathResponse {}))
    }
}
