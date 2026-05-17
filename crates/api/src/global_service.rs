use tonic::{Request, Response, Status};

use crate::proto;
use crate::server::{AccessMode, read_only_rejection};
use rustbgpd_transport::TcpAoSupport as TransportTcpAoSupport;

/// Read-only view of daemon global configuration.
///
/// `GetGlobal` returns ASN, router-id, listen port, and host TCP-AO
/// capability status.
/// `SetGlobal` is reserved for future use. It is still classified as a
/// mutating RPC for read-only listener enforcement.
pub struct GlobalService {
    access_mode: AccessMode,
    asn: u32,
    router_id: String,
    listen_port: u32,
    tcp_ao_support: TransportTcpAoSupport,
}

impl GlobalService {
    /// Create a new `GlobalService` with the daemon's startup configuration.
    pub fn new(access_mode: AccessMode, asn: u32, router_id: String, listen_port: u32) -> Self {
        Self::new_with_tcp_ao_support(
            access_mode,
            asn,
            router_id,
            listen_port,
            rustbgpd_transport::probe_tcp_ao_support(),
        )
    }

    fn new_with_tcp_ao_support(
        access_mode: AccessMode,
        asn: u32,
        router_id: String,
        listen_port: u32,
        tcp_ao_support: TransportTcpAoSupport,
    ) -> Self {
        Self {
            access_mode,
            asn,
            router_id,
            listen_port,
            tcp_ao_support,
        }
    }
}

fn tcp_ao_support_to_proto(support: &TransportTcpAoSupport) -> (proto::TcpAoSupport, String) {
    match support {
        TransportTcpAoSupport::Supported => (proto::TcpAoSupport::Supported, String::new()),
        TransportTcpAoSupport::Unsupported => (
            proto::TcpAoSupport::Unsupported,
            "TCP-AO is not supported by this platform/kernel".to_string(),
        ),
        TransportTcpAoSupport::ProbeFailed(err) => (proto::TcpAoSupport::ProbeFailed, err.clone()),
    }
}

#[tonic::async_trait]
impl proto::global_service_server::GlobalService for GlobalService {
    async fn get_global(
        &self,
        _request: Request<proto::GetGlobalRequest>,
    ) -> Result<Response<proto::GlobalState>, Status> {
        let (tcp_ao_support, tcp_ao_detail) = tcp_ao_support_to_proto(&self.tcp_ao_support);
        Ok(Response::new(proto::GlobalState {
            asn: self.asn,
            router_id: self.router_id.clone(),
            listen_port: self.listen_port,
            tcp_ao_support: tcp_ao_support as i32,
            tcp_ao_detail,
        }))
    }

    async fn set_global(
        &self,
        _request: Request<proto::SetGlobalRequest>,
    ) -> Result<Response<proto::SetGlobalResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
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
        let svc = GlobalService::new_with_tcp_ao_support(
            AccessMode::ReadWrite,
            65001,
            "10.0.0.1".into(),
            179,
            TransportTcpAoSupport::Supported,
        );
        let resp = svc
            .get_global(Request::new(proto::GetGlobalRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.asn, 65001);
        assert_eq!(resp.router_id, "10.0.0.1");
        assert_eq!(resp.listen_port, 179);
        assert_eq!(resp.tcp_ao_support, proto::TcpAoSupport::Supported as i32);
        assert!(resp.tcp_ao_detail.is_empty());
    }

    #[tokio::test]
    async fn get_global_returns_tcp_ao_probe_detail() {
        let svc = GlobalService::new_with_tcp_ao_support(
            AccessMode::ReadWrite,
            65001,
            "10.0.0.1".into(),
            179,
            TransportTcpAoSupport::ProbeFailed("setsockopt failed".into()),
        );
        let resp = svc
            .get_global(Request::new(proto::GetGlobalRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.tcp_ao_support, proto::TcpAoSupport::ProbeFailed as i32);
        assert_eq!(resp.tcp_ao_detail, "setsockopt failed");
    }

    #[tokio::test]
    async fn set_global_returns_unimplemented() {
        let svc = GlobalService::new(AccessMode::ReadWrite, 65001, "10.0.0.1".into(), 179);
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

    #[tokio::test]
    async fn set_global_rejected_on_read_only_listener() {
        let svc = GlobalService::new(AccessMode::ReadOnly, 65001, "10.0.0.1".into(), 179);
        let err = svc
            .set_global(Request::new(proto::SetGlobalRequest {
                asn: 65002,
                router_id: "10.0.0.2".into(),
                listen_port: 179,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }
}
