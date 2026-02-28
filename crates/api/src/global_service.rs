use tonic::{Request, Response, Status};

use crate::proto;

/// Read-only view of daemon global configuration.
///
/// `GetGlobal` returns ASN, router-id, and listen port.
/// `SetGlobal` is intentionally unimplemented — runtime config mutation is deferred.
pub struct GlobalService {
    asn: u32,
    router_id: String,
    listen_port: u32,
}

impl GlobalService {
    /// Create a new `GlobalService` with the daemon's startup configuration.
    pub fn new(asn: u32, router_id: String, listen_port: u32) -> Self {
        Self {
            asn,
            router_id,
            listen_port,
        }
    }
}

#[tonic::async_trait]
impl proto::global_service_server::GlobalService for GlobalService {
    async fn get_global(
        &self,
        _request: Request<proto::GetGlobalRequest>,
    ) -> Result<Response<proto::GlobalState>, Status> {
        Ok(Response::new(proto::GlobalState {
            asn: self.asn,
            router_id: self.router_id.clone(),
            listen_port: self.listen_port,
        }))
    }

    async fn set_global(
        &self,
        _request: Request<proto::SetGlobalRequest>,
    ) -> Result<Response<proto::SetGlobalResponse>, Status> {
        Err(Status::unimplemented(
            "runtime global config mutation is not supported",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto::global_service_server::GlobalService as _;

    #[tokio::test]
    async fn get_global_returns_config() {
        let svc = GlobalService::new(65001, "10.0.0.1".into(), 179);
        let resp = svc
            .get_global(Request::new(proto::GetGlobalRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.asn, 65001);
        assert_eq!(resp.router_id, "10.0.0.1");
        assert_eq!(resp.listen_port, 179);
    }

    #[tokio::test]
    async fn set_global_returns_unimplemented() {
        let svc = GlobalService::new(65001, "10.0.0.1".into(), 179);
        let err = svc
            .set_global(Request::new(proto::SetGlobalRequest {
                asn: 65002,
                router_id: "10.0.0.2".into(),
                listen_port: 179,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);
    }
}
