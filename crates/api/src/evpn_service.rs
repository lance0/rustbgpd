//! gRPC `EvpnService` — read-only view of local EVPN instances.
//!
//! This service exposes the daemon's resolved
//! [`rustbgpd_evpn::EvpnInstanceTable`] so operators and SDN
//! controllers can confirm which local EVIs are installed without
//! parsing TOML themselves. It remains *intentionally read-only*:
//! kernel reconciliation and local Type 2/3 origination consume the
//! same resolved table through daemon-owned actors, while runtime EVI
//! mutation is still a follow-on phase.
//!
//! The service holds an `Arc<EvpnInstanceTable>` rather than building
//! a fresh table per call so the gRPC layer never re-parses config
//! state. The same `Arc` is the unit other phases will swap atomically
//! on SIGHUP / gRPC mutation.

use std::sync::Arc;

use rustbgpd_evpn::EvpnInstanceTable;
use tonic::{Request, Response, Status};

use crate::proto;

/// Read-side hook for per-instance local-MAC origination counts.
pub type OriginatedLocalMacCountFn = Arc<dyn Fn(u32) -> u64 + Send + Sync + 'static>;

/// Read-only EVPN service backed by a shared resolved instance table.
pub struct EvpnService {
    instances: Arc<EvpnInstanceTable>,
    originated_local_mac_count: OriginatedLocalMacCountFn,
}

impl EvpnService {
    /// Construct a service over the given resolved instance table.
    #[must_use]
    pub fn new(instances: Arc<EvpnInstanceTable>) -> Self {
        Self::with_originated_local_mac_count(instances, Arc::new(|_| 0))
    }

    /// Construct a service with a live local-MAC origination count
    /// provider. The daemon passes a closure backed by the EVPN
    /// originator's state; tests can inject deterministic counts.
    #[must_use]
    pub fn with_originated_local_mac_count(
        instances: Arc<EvpnInstanceTable>,
        originated_local_mac_count: OriginatedLocalMacCountFn,
    ) -> Self {
        Self {
            instances,
            originated_local_mac_count,
        }
    }
}

#[tonic::async_trait]
impl proto::evpn_service_server::EvpnService for EvpnService {
    async fn list_evpn_instances(
        &self,
        _request: Request<proto::ListEvpnInstancesRequest>,
    ) -> Result<Response<proto::ListEvpnInstancesResponse>, Status> {
        let instances = self
            .instances
            .sorted()
            .into_iter()
            .map(|inst| proto::EvpnInstanceState {
                vni: inst.id.as_u32(),
                rd: inst.rd.to_string(),
                route_targets: inst.route_targets.iter().map(ToString::to_string).collect(),
                local_vtep_ip: inst.local_vtep_ip.to_string(),
                bridge: inst.bridge.clone().unwrap_or_default(),
                advertise_svi_mac: inst.advertise_svi_mac,
                originated_local_macs_count: (self.originated_local_mac_count)(inst.id.as_u32()),
            })
            .collect();
        Ok(Response::new(proto::ListEvpnInstancesResponse {
            instances,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto::evpn_service_server::EvpnService as _;
    use rustbgpd_evpn::{EvpnInstance, EvpnInstanceId, RouteTarget};
    use rustbgpd_wire::RouteDistinguisher;
    use std::net::IpAddr;

    fn rt(s: &str) -> RouteTarget {
        s.parse().unwrap()
    }

    fn rd(s: &str) -> RouteDistinguisher {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn install(table: &mut EvpnInstanceTable, vni: u32, rd_str: &str, vtep: &str) {
        table
            .insert(
                EvpnInstance::new(
                    EvpnInstanceId::new(vni).unwrap(),
                    rd(rd_str),
                    vec![rt("65000:100")],
                    ip(vtep),
                    None,
                    false,
                )
                .unwrap(),
            )
            .unwrap();
    }

    #[tokio::test]
    async fn list_returns_empty_when_no_instances() {
        let svc = EvpnService::new(Arc::new(EvpnInstanceTable::new()));
        let resp = svc
            .list_evpn_instances(Request::new(proto::ListEvpnInstancesRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(resp.instances.is_empty());
    }

    #[tokio::test]
    async fn list_returns_instances_sorted_by_vni() {
        let mut table = EvpnInstanceTable::new();
        install(&mut table, 300, "65000:300", "10.0.0.3");
        install(&mut table, 100, "65000:100", "10.0.0.1");
        install(&mut table, 200, "65000:200", "10.0.0.2");
        let svc = EvpnService::new(Arc::new(table));

        let resp = svc
            .list_evpn_instances(Request::new(proto::ListEvpnInstancesRequest {}))
            .await
            .unwrap()
            .into_inner();
        let vnis: Vec<u32> = resp.instances.iter().map(|i| i.vni).collect();
        assert_eq!(vnis, vec![100, 200, 300]);
        // Spot-check the first row's serialization.
        assert_eq!(resp.instances[0].rd, "65000:100");
        assert_eq!(resp.instances[0].local_vtep_ip, "10.0.0.1");
        assert_eq!(resp.instances[0].route_targets, vec!["65000:100"]);
        assert!(resp.instances[0].bridge.is_empty());
        assert!(!resp.instances[0].advertise_svi_mac);
        assert_eq!(resp.instances[0].originated_local_macs_count, 0);
    }

    #[tokio::test]
    async fn list_surfaces_optional_fields() {
        let mut table = EvpnInstanceTable::new();
        let inst = EvpnInstance::new(
            EvpnInstanceId::new(100).unwrap(),
            rd("65000:100"),
            vec![rt("65000:100"), rt("65000:200")],
            ip("10.0.0.1"),
            Some("br100".into()),
            true,
        )
        .unwrap();
        table.insert(inst).unwrap();
        let svc = EvpnService::new(Arc::new(table));

        let resp = svc
            .list_evpn_instances(Request::new(proto::ListEvpnInstancesRequest {}))
            .await
            .unwrap()
            .into_inner();
        let row = &resp.instances[0];
        assert_eq!(row.bridge, "br100");
        assert!(row.advertise_svi_mac);
        assert_eq!(row.route_targets, vec!["65000:100", "65000:200"]);
    }

    #[tokio::test]
    async fn list_surfaces_originated_local_mac_counts() {
        let mut table = EvpnInstanceTable::new();
        install(&mut table, 100, "65000:100", "10.0.0.1");
        let svc = EvpnService::with_originated_local_mac_count(
            Arc::new(table),
            Arc::new(|vni| if vni == 100 { 7 } else { 0 }),
        );

        let resp = svc
            .list_evpn_instances(Request::new(proto::ListEvpnInstancesRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.instances[0].originated_local_macs_count, 7);
    }
}
