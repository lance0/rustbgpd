use tonic::{Request, Response, Status};

use crate::proto;
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_transport::TcpAoSupport as TransportTcpAoSupport;

/// Read-only view of daemon global configuration.
///
/// `GetGlobal` returns ASN, router-id, listen port, and host TCP-AO
/// capability status.
pub struct GlobalService {
    asn: u32,
    router_id: String,
    listen_port: u32,
    tcp_ao_support: TransportTcpAoSupport,
    metrics: BgpMetrics,
}

impl GlobalService {
    /// Create a new `GlobalService` with the daemon's startup configuration.
    pub fn new(asn: u32, router_id: String, listen_port: u32, metrics: BgpMetrics) -> Self {
        Self::new_with_tcp_ao_support(
            asn,
            router_id,
            listen_port,
            rustbgpd_transport::probe_tcp_ao_support(),
            metrics,
        )
    }

    fn new_with_tcp_ao_support(
        asn: u32,
        router_id: String,
        listen_port: u32,
        tcp_ao_support: TransportTcpAoSupport,
        metrics: BgpMetrics,
    ) -> Self {
        Self {
            asn,
            router_id,
            listen_port,
            tcp_ao_support,
            metrics,
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
            policy_generation_loaded_timestamp_seconds: self
                .metrics
                .policy_generation_loaded_timestamp_seconds(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto::global_service_server::GlobalService as _;

    #[tokio::test]
    async fn get_global_reads_live_policy_generation_timestamp() {
        let metrics = BgpMetrics::new();
        let svc = GlobalService::new_with_tcp_ao_support(
            65001,
            "10.0.0.1".into(),
            179,
            TransportTcpAoSupport::Supported,
            metrics.clone(),
        );
        let initial = svc
            .get_global(Request::new(proto::GetGlobalRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(initial.asn, 65001);
        assert_eq!(initial.router_id, "10.0.0.1");
        assert_eq!(initial.listen_port, 179);
        assert_eq!(
            initial.tcp_ao_support,
            proto::TcpAoSupport::Supported as i32
        );
        assert!(initial.tcp_ao_detail.is_empty());
        assert_eq!(initial.policy_generation_loaded_timestamp_seconds, 0);

        metrics.record_policy_generation_loaded();
        let updated = svc
            .get_global(Request::new(proto::GetGlobalRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(updated.policy_generation_loaded_timestamp_seconds > 0);
    }

    #[tokio::test]
    async fn get_global_returns_tcp_ao_probe_detail() {
        let svc = GlobalService::new_with_tcp_ao_support(
            65001,
            "10.0.0.1".into(),
            179,
            TransportTcpAoSupport::ProbeFailed("setsockopt failed".into()),
            BgpMetrics::new(),
        );
        let resp = svc
            .get_global(Request::new(proto::GetGlobalRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.tcp_ao_support, proto::TcpAoSupport::ProbeFailed as i32);
        assert_eq!(resp.tcp_ao_detail, "setsockopt failed");
    }
}
