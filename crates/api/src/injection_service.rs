use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tokio::sync::{mpsc, oneshot};
use tonic::{Request, Response, Status};

use crate::proto;
use rustbgpd_rib::{RibUpdate, Route};
use rustbgpd_wire::{AsPath, AsPathSegment, Ipv4Prefix, Ipv6Prefix, Origin, PathAttribute, Prefix};

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

        // Parse prefix address as IPv4 or IPv6
        let addr: IpAddr = req
            .prefix
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid prefix address: {e}")))?;

        let (prefix, next_hop_ip) = match addr {
            IpAddr::V4(v4) => {
                let len = u8::try_from(req.prefix_length)
                    .ok()
                    .filter(|&l| l <= 32)
                    .ok_or_else(|| Status::invalid_argument("prefix_length must be 0..=32"))?;
                let nh: Ipv4Addr = req
                    .next_hop
                    .parse()
                    .map_err(|e| Status::invalid_argument(format!("invalid next_hop: {e}")))?;
                if nh.is_unspecified() {
                    return Err(Status::invalid_argument("next_hop must not be 0.0.0.0"));
                }
                if nh.is_multicast() {
                    return Err(Status::invalid_argument("next_hop must not be multicast"));
                }
                (Prefix::V4(Ipv4Prefix::new(v4, len)), IpAddr::V4(nh))
            }
            IpAddr::V6(v6) => {
                let len = u8::try_from(req.prefix_length)
                    .ok()
                    .filter(|&l| l <= 128)
                    .ok_or_else(|| Status::invalid_argument("prefix_length must be 0..=128"))?;
                let nh: Ipv6Addr = req
                    .next_hop
                    .parse()
                    .map_err(|e| Status::invalid_argument(format!("invalid next_hop: {e}")))?;
                if nh.is_unspecified() {
                    return Err(Status::invalid_argument("next_hop must not be ::"));
                }
                if nh.is_multicast() {
                    return Err(Status::invalid_argument("next_hop must not be multicast"));
                }
                (Prefix::V6(Ipv6Prefix::new(v6, len)), IpAddr::V6(nh))
            }
        };

        let origin = match req.origin {
            0 => Origin::Igp,
            1 => Origin::Egp,
            _ => Origin::Incomplete,
        };

        let mut attributes = vec![PathAttribute::Origin(origin)];

        // NEXT_HOP attribute only for IPv4 (IPv6 uses MP_REACH_NLRI)
        if let IpAddr::V4(nh) = next_hop_ip {
            attributes.push(PathAttribute::NextHop(nh));
        }

        if req.as_path.is_empty() {
            attributes.push(PathAttribute::AsPath(AsPath { segments: vec![] }));
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
            next_hop: next_hop_ip,
            peer: LOCAL_PEER,
            attributes,
            received_at: std::time::Instant::now(),
            is_ebgp: false,
            is_stale: false,
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

        Ok(Response::new(proto::AddPathResponse {}))
    }

    async fn delete_path(
        &self,
        request: Request<proto::DeletePathRequest>,
    ) -> Result<Response<proto::DeletePathResponse>, Status> {
        let req = request.into_inner();

        let addr: IpAddr = req
            .prefix
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid prefix address: {e}")))?;

        let prefix = match addr {
            IpAddr::V4(v4) => {
                let len = u8::try_from(req.prefix_length)
                    .ok()
                    .filter(|&l| l <= 32)
                    .ok_or_else(|| Status::invalid_argument("prefix_length must be 0..=32"))?;
                Prefix::V4(Ipv4Prefix::new(v4, len))
            }
            IpAddr::V6(v6) => {
                let len = u8::try_from(req.prefix_length)
                    .ok()
                    .filter(|&l| l <= 128)
                    .ok_or_else(|| Status::invalid_argument("prefix_length must be 0..=128"))?;
                Prefix::V6(Ipv6Prefix::new(v6, len))
            }
        };

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

#[cfg(test)]
mod tests {
    use super::*;
    use proto::injection_service_server::InjectionService as _;

    fn make_service() -> InjectionService {
        let (tx, _rx) = mpsc::channel(16);
        InjectionService::new(tx)
    }

    #[tokio::test]
    async fn add_path_rejects_zero_next_hop() {
        let svc = make_service();
        let req = Request::new(proto::AddPathRequest {
            prefix: "10.0.0.0".into(),
            prefix_length: 24,
            next_hop: "0.0.0.0".into(),
            origin: 0,
            as_path: vec![],
            local_pref: 0,
            med: 0,
            communities: vec![],
        });
        let err = svc.add_path(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("0.0.0.0"));
    }

    #[tokio::test]
    async fn add_path_rejects_multicast_next_hop() {
        let svc = make_service();
        let req = Request::new(proto::AddPathRequest {
            prefix: "10.0.0.0".into(),
            prefix_length: 24,
            next_hop: "224.0.0.1".into(),
            origin: 0,
            as_path: vec![],
            local_pref: 0,
            med: 0,
            communities: vec![],
        });
        let err = svc.add_path(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("multicast"));
    }
}
