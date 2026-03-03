use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tokio::sync::{mpsc, oneshot};
use tonic::{Request, Response, Status};

use crate::proto;
use rustbgpd_rib::{RibUpdate, Route, RouteOrigin};
use rustbgpd_wire::{
    AsPath, AsPathSegment, ExtendedCommunity, Ipv4Prefix, Ipv6Prefix, LargeCommunity, Origin,
    PathAttribute, Prefix,
};

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

/// Parse a prefix address + length + next-hop from a gRPC request.
#[expect(clippy::result_large_err)]
fn parse_prefix_and_nexthop(
    prefix_str: &str,
    prefix_length: u32,
    next_hop_str: &str,
) -> Result<(Prefix, IpAddr), Status> {
    let addr: IpAddr = prefix_str
        .parse()
        .map_err(|e| Status::invalid_argument(format!("invalid prefix address: {e}")))?;
    match addr {
        IpAddr::V4(v4) => {
            let len = u8::try_from(prefix_length)
                .ok()
                .filter(|&l| l <= 32)
                .ok_or_else(|| Status::invalid_argument("prefix_length must be 0..=32"))?;
            let nh: Ipv4Addr = next_hop_str
                .parse()
                .map_err(|e| Status::invalid_argument(format!("invalid next_hop: {e}")))?;
            if nh.is_unspecified() {
                return Err(Status::invalid_argument("next_hop must not be 0.0.0.0"));
            }
            if nh.is_multicast() {
                return Err(Status::invalid_argument("next_hop must not be multicast"));
            }
            Ok((Prefix::V4(Ipv4Prefix::new(v4, len)), IpAddr::V4(nh)))
        }
        IpAddr::V6(v6) => {
            let len = u8::try_from(prefix_length)
                .ok()
                .filter(|&l| l <= 128)
                .ok_or_else(|| Status::invalid_argument("prefix_length must be 0..=128"))?;
            let nh: Ipv6Addr = next_hop_str
                .parse()
                .map_err(|e| Status::invalid_argument(format!("invalid next_hop: {e}")))?;
            if nh.is_unspecified() {
                return Err(Status::invalid_argument("next_hop must not be ::"));
            }
            if nh.is_multicast() {
                return Err(Status::invalid_argument("next_hop must not be multicast"));
            }
            Ok((Prefix::V6(Ipv6Prefix::new(v6, len)), IpAddr::V6(nh)))
        }
    }
}

/// Parse a Large Community string in `"global:local1:local2"` format.
fn parse_large_community(s: &str) -> Result<LargeCommunity, String> {
    let parts: Vec<&str> = s.splitn(3, ':').collect();
    if parts.len() != 3 {
        return Err("expected format global:local1:local2".to_string());
    }
    let global_admin: u32 = parts[0]
        .parse()
        .map_err(|_| format!("invalid global_admin {:?}", parts[0]))?;
    let local_data1: u32 = parts[1]
        .parse()
        .map_err(|_| format!("invalid local_data1 {:?}", parts[1]))?;
    let local_data2: u32 = parts[2]
        .parse()
        .map_err(|_| format!("invalid local_data2 {:?}", parts[2]))?;
    Ok(LargeCommunity::new(global_admin, local_data1, local_data2))
}

#[tonic::async_trait]
impl proto::injection_service_server::InjectionService for InjectionService {
    async fn add_path(
        &self,
        request: Request<proto::AddPathRequest>,
    ) -> Result<Response<proto::AddPathResponse>, Status> {
        let req = request.into_inner();

        let (prefix, next_hop_ip) =
            parse_prefix_and_nexthop(&req.prefix, req.prefix_length, &req.next_hop)?;

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
        if !req.extended_communities.is_empty() {
            attributes.push(PathAttribute::ExtendedCommunities(
                req.extended_communities
                    .iter()
                    .map(|&v| ExtendedCommunity::new(v))
                    .collect(),
            ));
        }
        if !req.large_communities.is_empty() {
            let mut lcs = Vec::with_capacity(req.large_communities.len());
            for s in &req.large_communities {
                let lc = parse_large_community(s).map_err(|e| {
                    Status::invalid_argument(format!("invalid large_community {s:?}: {e}"))
                })?;
                lcs.push(lc);
            }
            attributes.push(PathAttribute::LargeCommunities(lcs));
        }

        let route = Route {
            prefix,
            next_hop: next_hop_ip,
            peer: LOCAL_PEER,
            attributes,
            received_at: std::time::Instant::now(),
            origin_type: RouteOrigin::Local,
            peer_router_id: std::net::Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            path_id: req.path_id,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
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
                path_id: req.path_id,
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
            extended_communities: vec![],
            large_communities: vec![],
            path_id: 0,
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
            extended_communities: vec![],
            large_communities: vec![],
            path_id: 0,
        });
        let err = svc.add_path(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("multicast"));
    }
}
