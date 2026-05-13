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

use std::collections::HashMap;
use std::sync::Arc;

use rustbgpd_evpn::ip_vrf::{IpVrfId, IpVrfNotReady, IpVrfStatus, IpVrfTable};
use rustbgpd_evpn::{EvpnInstanceTable, FdbNexthopDataplaneStatus, IpVrfDataplaneStatus};
use tonic::{Request, Response, Status};

use crate::proto;

/// Read-side hook for per-instance local-MAC origination counts.
pub type OriginatedLocalMacCountFn = Arc<dyn Fn(u32) -> u64 + Send + Sync + 'static>;

/// Read-side hook for per-IP-VRF Type 5 origination counts (Gate 9
/// slice 6b). Mirrors [`OriginatedLocalMacCountFn`] for the L3 case;
/// the daemon backs it with the `OriginatedIpVrfRouteCounts` shared
/// state.
pub type OriginatedIpVrfRouteCountFn = Arc<dyn Fn(u32) -> u64 + Send + Sync + 'static>;

/// Read-side hook for per-IP-VRF Type 5 installed-route counts
/// (Gate 9 slice 6c). The daemon backs it with a `tokio::sync::watch`
/// fed from `DataplaneReport.ip_vrf_installed_routes`.
pub type InstalledIpVrfRouteCountFn = Arc<dyn Fn(u32) -> u64 + Send + Sync + 'static>;

/// Read-side hook for the latest per-IP-VRF readiness snapshot.
///
/// The daemon subscribes to `DataplaneReport.ip_vrf_status` and
/// keeps the most recent rows in a shared `Arc`; this closure
/// returns a clone of that snapshot every call. Tests can inject a
/// deterministic snapshot.
pub type IpVrfStatusSnapshotFn = Arc<dyn Fn() -> Vec<IpVrfDataplaneStatus> + Send + Sync + 'static>;

/// Read-side hook for the latest FDB nexthop-group owned-state
/// snapshot. The daemon backs it with `DataplaneReport.fdb_nexthops`;
/// tests can inject a deterministic value.
pub type FdbNexthopSnapshotFn = Arc<dyn Fn() -> FdbNexthopDataplaneStatus + Send + Sync + 'static>;

/// Read-only EVPN service backed by shared resolved tables.
pub struct EvpnService {
    instances: Arc<EvpnInstanceTable>,
    ip_vrfs: Arc<IpVrfTable>,
    originated_local_mac_count: OriginatedLocalMacCountFn,
    ip_vrf_status_snapshot: IpVrfStatusSnapshotFn,
    originated_ip_vrf_route_count: OriginatedIpVrfRouteCountFn,
    installed_ip_vrf_route_count: InstalledIpVrfRouteCountFn,
    fdb_nexthop_snapshot: FdbNexthopSnapshotFn,
}

impl EvpnService {
    /// Construct a service over the given resolved instance table.
    /// IP-VRF table defaults to empty; the local-MAC origination
    /// count and IP-VRF readiness closures default to "unknown".
    #[must_use]
    pub fn new(instances: Arc<EvpnInstanceTable>) -> Self {
        Self {
            instances,
            ip_vrfs: Arc::new(IpVrfTable::new()),
            originated_local_mac_count: Arc::new(|_| 0),
            ip_vrf_status_snapshot: Arc::new(Vec::new),
            originated_ip_vrf_route_count: Arc::new(|_| 0),
            installed_ip_vrf_route_count: Arc::new(|_| 0),
            fdb_nexthop_snapshot: Arc::new(FdbNexthopDataplaneStatus::default),
        }
    }

    /// Construct a service with a live local-MAC origination count
    /// provider. The daemon passes a closure backed by the EVPN
    /// originator's state; tests can inject deterministic counts.
    /// IP-VRF table defaults to empty.
    #[must_use]
    pub fn with_originated_local_mac_count(
        instances: Arc<EvpnInstanceTable>,
        originated_local_mac_count: OriginatedLocalMacCountFn,
    ) -> Self {
        Self {
            instances,
            ip_vrfs: Arc::new(IpVrfTable::new()),
            originated_local_mac_count,
            ip_vrf_status_snapshot: Arc::new(Vec::new),
            originated_ip_vrf_route_count: Arc::new(|_| 0),
            installed_ip_vrf_route_count: Arc::new(|_| 0),
            fdb_nexthop_snapshot: Arc::new(FdbNexthopDataplaneStatus::default),
        }
    }

    /// Construct a service exposing the full Gate 9 surface — the
    /// L2 EVPN instance table, the L3 IP-VRF table, and a live read
    /// of the most recent `DataplaneReport.ip_vrf_status` rows. The
    /// daemon uses this constructor; older callers that only need
    /// the L2 surface stay on [`Self::new`] /
    /// [`Self::with_originated_local_mac_count`].
    #[must_use]
    pub fn with_full_surface(
        instances: Arc<EvpnInstanceTable>,
        ip_vrfs: Arc<IpVrfTable>,
        originated_local_mac_count: OriginatedLocalMacCountFn,
        ip_vrf_status_snapshot: IpVrfStatusSnapshotFn,
        originated_ip_vrf_route_count: OriginatedIpVrfRouteCountFn,
        installed_ip_vrf_route_count: InstalledIpVrfRouteCountFn,
        fdb_nexthop_snapshot: FdbNexthopSnapshotFn,
    ) -> Self {
        Self {
            instances,
            ip_vrfs,
            originated_local_mac_count,
            ip_vrf_status_snapshot,
            originated_ip_vrf_route_count,
            installed_ip_vrf_route_count,
            fdb_nexthop_snapshot,
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

    async fn list_evpn_nexthops(
        &self,
        _request: Request<proto::ListEvpnNexthopsRequest>,
    ) -> Result<Response<proto::ListEvpnNexthopsResponse>, Status> {
        let snapshot = (self.fdb_nexthop_snapshot)();
        let groups = snapshot
            .groups
            .iter()
            .map(|group| proto::EvpnFdbNexthopGroup {
                vni: group.vni.as_u32(),
                esi: group.esi.to_string(),
                ethernet_tag: group.ethernet_tag.to_string(),
                group_id: group.group_id,
                members: group
                    .members
                    .iter()
                    .map(|member| proto::EvpnFdbNexthopMember {
                        gateway: member.gateway.to_string(),
                        nexthop_id: member.nexthop_id,
                    })
                    .collect(),
                ref_macs: group.ref_macs.iter().map(ToString::to_string).collect(),
            })
            .collect();
        Ok(Response::new(proto::ListEvpnNexthopsResponse {
            groups,
            orphan_nexthops_count: snapshot.orphan_nexthops_count,
            pending_delete_count: snapshot.pending_delete_count,
            drift_recovery_disabled: snapshot.drift_recovery_disabled,
        }))
    }

    async fn list_ip_vrfs(
        &self,
        _request: Request<proto::ListIpVrfsRequest>,
    ) -> Result<Response<proto::ListIpVrfsResponse>, Status> {
        let snapshot = (self.ip_vrf_status_snapshot)();
        let by_id = snapshot_index(&snapshot);
        let ip_vrfs: Vec<proto::IpVrfState> = self
            .ip_vrfs
            .iter()
            .map(|vrf| {
                let originated = (self.originated_ip_vrf_route_count)(vrf.id.as_u32());
                let installed = (self.installed_ip_vrf_route_count)(vrf.id.as_u32());
                ip_vrf_to_proto(vrf, by_id.get(&vrf.id).copied(), originated, installed)
            })
            .collect();
        Ok(Response::new(proto::ListIpVrfsResponse { ip_vrfs }))
    }

    async fn get_ip_vrf(
        &self,
        request: Request<proto::GetIpVrfRequest>,
    ) -> Result<Response<proto::IpVrfState>, Status> {
        let name = request.into_inner().name;
        let vrf = self
            .ip_vrfs
            .get(&name)
            .ok_or_else(|| Status::not_found(format!("no IP-VRF named {name:?}")))?;
        let snapshot = (self.ip_vrf_status_snapshot)();
        let status = snapshot.iter().find(|r| r.vrf_id == vrf.id);
        let originated = (self.originated_ip_vrf_route_count)(vrf.id.as_u32());
        let installed = (self.installed_ip_vrf_route_count)(vrf.id.as_u32());
        Ok(Response::new(ip_vrf_to_proto(
            vrf, status, originated, installed,
        )))
    }
}

/// Build an `IpVrfId → &IpVrfDataplaneStatus` index from the per-call
/// snapshot Vec so `ListIpVrfs` joins config rows with status rows
/// in O(N) instead of O(N²). `GetIpVrf` doesn't need it (single
/// lookup) and uses a direct `iter().find` instead.
fn snapshot_index(snapshot: &[IpVrfDataplaneStatus]) -> HashMap<IpVrfId, &IpVrfDataplaneStatus> {
    snapshot.iter().map(|r| (r.vrf_id, r)).collect()
}

/// Join the config-time `IpVrf` shape with a snapshot row (if any)
/// into the wire `IpVrfState` message. Mirrored layout: cold-start
/// rows where no snapshot row exists yet surface as
/// `IP_VRF_READINESS_UNKNOWN` with all readiness fields empty.
fn ip_vrf_to_proto(
    vrf: &rustbgpd_evpn::ip_vrf::IpVrf,
    status: Option<&IpVrfDataplaneStatus>,
    originated_routes_count: u64,
    installed_routes_count: u64,
) -> proto::IpVrfState {
    let mut state = proto::IpVrfState {
        name: vrf.name.clone(),
        vni: vrf.id.as_u32(),
        rd: vrf.rd.to_string(),
        route_targets: vrf.route_targets.iter().map(ToString::to_string).collect(),
        local_vtep_ip: vrf.local_vtep_ip.to_string(),
        router_mac: vrf.router_mac.to_string(),
        vrf_device: vrf.vrf_device.clone(),
        l3vxlan_device: vrf.l3vxlan_device.clone(),
        table_id: vrf.table_id,
        readiness_state: proto::IpVrfReadinessState::IpVrfReadinessUnknown as i32,
        vrf_ifindex: 0,
        l3vxlan_ifindex: 0,
        not_ready_reasons: Vec::new(),
        originated_routes_count: u32::try_from(originated_routes_count).unwrap_or(u32::MAX),
        installed_routes_count: u32::try_from(installed_routes_count).unwrap_or(u32::MAX),
    };

    let Some(row) = status else {
        return state;
    };

    match &row.status {
        IpVrfStatus::Ready {
            vrf_ifindex,
            l3vxlan_ifindex,
            ..
        } => {
            state.readiness_state = proto::IpVrfReadinessState::IpVrfReadinessReady as i32;
            state.vrf_ifindex = *vrf_ifindex;
            state.l3vxlan_ifindex = *l3vxlan_ifindex;
        }
        IpVrfStatus::NotReady { reasons } => {
            state.readiness_state = proto::IpVrfReadinessState::IpVrfReadinessNotReady as i32;
            state.not_ready_reasons = reasons.iter().map(format_not_ready_reason).collect();
        }
    }
    state
}

/// Format one `IpVrfNotReady` predicate failure as a short
/// operator-facing line. Lines are stable English (no
/// machine-parsable shape); structured consumers should match the
/// proto variants on `readiness_state` and the field values
/// directly rather than parsing these strings.
fn format_not_ready_reason(reason: &IpVrfNotReady) -> String {
    match reason {
        IpVrfNotReady::VrfDeviceMissing => "vrf device missing".to_string(),
        IpVrfNotReady::VrfDeviceDown => "vrf device down".to_string(),
        IpVrfNotReady::VrfTableIdMismatch {
            observed,
            configured,
        } => format!("vrf table_id mismatch (observed {observed}, configured {configured})"),
        IpVrfNotReady::L3VxlanMissing => "l3vxlan device missing".to_string(),
        IpVrfNotReady::L3VxlanDown => "l3vxlan device down".to_string(),
        IpVrfNotReady::L3VxlanVniMismatch {
            observed,
            configured,
        } => format!("l3vxlan vni mismatch (observed {observed}, configured {configured})"),
        IpVrfNotReady::L3VxlanLocalMismatch {
            observed,
            configured,
        } => match observed {
            Some(o) => format!("l3vxlan local mismatch (observed {o}, configured {configured})"),
            None => format!("l3vxlan local missing (configured {configured})"),
        },
        IpVrfNotReady::L3VxlanNotInVrf {
            observed_master,
            expected_master,
        } => match observed_master {
            Some(m) => format!(
                "l3vxlan not in vrf (observed master ifindex {m}, expected {expected_master})"
            ),
            None => format!("l3vxlan unenslaved (expected master ifindex {expected_master})"),
        },
        IpVrfNotReady::RouterMacMismatch {
            observed,
            configured,
        } => match observed {
            Some(o) => format!("router_mac mismatch (observed {o}, configured {configured})"),
            None => format!("router_mac missing (configured {configured})"),
        },
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

    #[tokio::test]
    async fn list_evpn_nexthops_surfaces_owned_state() {
        let svc = EvpnService::with_full_surface(
            Arc::new(EvpnInstanceTable::new()),
            Arc::new(IpVrfTable::new()),
            Arc::new(|_| 0),
            Arc::new(Vec::new),
            Arc::new(|_| 0),
            Arc::new(|_| 0),
            Arc::new(|| rustbgpd_evpn::FdbNexthopDataplaneStatus {
                groups: vec![rustbgpd_evpn::FdbNexthopGroupStatus {
                    vni: EvpnInstanceId::new(100).unwrap(),
                    esi: rustbgpd_evpn::EthernetSegmentIdentifier::new([
                        3, 0, 0, 0, 0, 0, 0, 0, 0, 7,
                    ]),
                    ethernet_tag: rustbgpd_evpn::EthernetTagId(0),
                    group_id: 0x4000_0001,
                    members: vec![
                        rustbgpd_evpn::FdbNexthopMemberStatus {
                            gateway: "10.0.0.2".parse().unwrap(),
                            nexthop_id: 0x3000_0001,
                        },
                        rustbgpd_evpn::FdbNexthopMemberStatus {
                            gateway: "10.0.0.3".parse().unwrap(),
                            nexthop_id: 0x3000_0002,
                        },
                    ],
                    ref_macs: vec![
                        MacAddress::new([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01]),
                        MacAddress::new([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x02]),
                    ],
                }],
                orphan_nexthops_count: 2,
                pending_delete_count: 1,
                drift_recovery_disabled: true,
            }),
        );

        let resp = svc
            .list_evpn_nexthops(Request::new(proto::ListEvpnNexthopsRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.groups.len(), 1);
        let group = &resp.groups[0];
        assert_eq!(group.vni, 100);
        assert_eq!(group.esi, "03:00:00:00:00:00:00:00:00:07");
        assert_eq!(group.ethernet_tag, "0");
        assert_eq!(group.group_id, 0x4000_0001);
        assert_eq!(group.members.len(), 2);
        assert_eq!(group.members[0].gateway, "10.0.0.2");
        assert_eq!(group.members[0].nexthop_id, 0x3000_0001);
        assert_eq!(group.ref_macs.len(), 2);
        assert_eq!(resp.orphan_nexthops_count, 2);
        assert_eq!(resp.pending_delete_count, 1);
        assert!(resp.drift_recovery_disabled);
    }

    // -- Gate 9 IP-VRF surface --------------------------------------

    use rustbgpd_evpn::IpVrfDataplaneStatus;
    use rustbgpd_evpn::ip_vrf::IpVrfId;
    use rustbgpd_wire::MacAddress;

    fn mac(octets: [u8; 6]) -> MacAddress {
        MacAddress::new(octets)
    }

    fn install_vrf(
        table: &mut IpVrfTable,
        name: &str,
        vni: u32,
        rd_str: &str,
        vtep: &str,
        router_mac: [u8; 6],
    ) {
        table
            .insert(
                rustbgpd_evpn::ip_vrf::IpVrf::new(
                    name.to_string(),
                    IpVrfId::new(vni).unwrap(),
                    rd(rd_str),
                    vec![rt("65000:5000")],
                    ip(vtep),
                    mac(router_mac),
                    format!("vrf-{name}"),
                    format!("vni{vni}"),
                    vni,
                )
                .unwrap(),
            )
            .unwrap();
    }

    #[tokio::test]
    async fn list_ip_vrfs_empty_when_no_config() {
        let svc = EvpnService::new(Arc::new(EvpnInstanceTable::new()));
        let resp = svc
            .list_ip_vrfs(Request::new(proto::ListIpVrfsRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(resp.ip_vrfs.is_empty());
    }

    #[tokio::test]
    async fn list_ip_vrfs_surfaces_ready_state_with_ifindexes() {
        let mut table = IpVrfTable::new();
        install_vrf(
            &mut table,
            "blue",
            5000,
            "65000:5000",
            "10.0.0.1",
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        );
        let table = Arc::new(table);
        let svc = EvpnService::with_full_surface(
            Arc::new(EvpnInstanceTable::new()),
            table,
            Arc::new(|_| 0),
            Arc::new(move || {
                vec![IpVrfDataplaneStatus {
                    vrf_id: IpVrfId::new(5000).unwrap(),
                    vrf_name: "blue".into(),
                    status: IpVrfStatus::Ready {
                        vrf_ifindex: 11,
                        l3vxlan_ifindex: 12,
                        table_id: 5000,
                        router_mac: mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
                    },
                }]
            }),
            Arc::new(|_| 0),
            Arc::new(|_| 0),
            Arc::new(rustbgpd_evpn::FdbNexthopDataplaneStatus::default),
        );

        let resp = svc
            .list_ip_vrfs(Request::new(proto::ListIpVrfsRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.ip_vrfs.len(), 1);
        let row = &resp.ip_vrfs[0];
        assert_eq!(row.name, "blue");
        assert_eq!(row.vni, 5000);
        assert_eq!(
            row.readiness_state,
            proto::IpVrfReadinessState::IpVrfReadinessReady as i32
        );
        assert_eq!(row.vrf_ifindex, 11);
        assert_eq!(row.l3vxlan_ifindex, 12);
        assert!(row.not_ready_reasons.is_empty());
    }

    #[tokio::test]
    async fn list_ip_vrfs_surfaces_not_ready_reasons() {
        let mut table = IpVrfTable::new();
        install_vrf(
            &mut table,
            "red",
            6000,
            "65000:6000",
            "10.0.0.2",
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        );
        let svc = EvpnService::with_full_surface(
            Arc::new(EvpnInstanceTable::new()),
            Arc::new(table),
            Arc::new(|_| 0),
            Arc::new(move || {
                vec![IpVrfDataplaneStatus {
                    vrf_id: IpVrfId::new(6000).unwrap(),
                    vrf_name: "red".into(),
                    status: IpVrfStatus::NotReady {
                        reasons: vec![
                            IpVrfNotReady::VrfDeviceMissing,
                            IpVrfNotReady::L3VxlanVniMismatch {
                                observed: 99,
                                configured: 6000,
                            },
                        ],
                    },
                }]
            }),
            Arc::new(|_| 0),
            Arc::new(|_| 0),
            Arc::new(rustbgpd_evpn::FdbNexthopDataplaneStatus::default),
        );

        let resp = svc
            .list_ip_vrfs(Request::new(proto::ListIpVrfsRequest {}))
            .await
            .unwrap()
            .into_inner();
        let row = &resp.ip_vrfs[0];
        assert_eq!(
            row.readiness_state,
            proto::IpVrfReadinessState::IpVrfReadinessNotReady as i32
        );
        // ifindexes stay at zero in the NotReady arm.
        assert_eq!(row.vrf_ifindex, 0);
        assert_eq!(row.l3vxlan_ifindex, 0);
        assert_eq!(row.not_ready_reasons.len(), 2);
        assert!(
            row.not_ready_reasons[0].contains("vrf device missing"),
            "got: {:?}",
            row.not_ready_reasons
        );
        assert!(
            row.not_ready_reasons[1].contains("l3vxlan vni mismatch"),
            "got: {:?}",
            row.not_ready_reasons
        );
        assert!(
            row.not_ready_reasons[1].contains("99") && row.not_ready_reasons[1].contains("6000"),
            "expected observed=99 + configured=6000 in mismatch reason: {:?}",
            row.not_ready_reasons
        );
    }

    #[tokio::test]
    async fn list_ip_vrfs_reports_unknown_when_no_status_row() {
        // Configured but the reconcile actor hasn't reported yet
        // (cold start). Surface as IP_VRF_READINESS_UNKNOWN, no
        // ifindexes, no reasons — the operator knows the daemon
        // hasn't probed yet rather than seeing a confusing default.
        let mut table = IpVrfTable::new();
        install_vrf(
            &mut table,
            "blue",
            5000,
            "65000:5000",
            "10.0.0.1",
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        );
        let svc = EvpnService::with_full_surface(
            Arc::new(EvpnInstanceTable::new()),
            Arc::new(table),
            Arc::new(|_| 0),
            Arc::new(Vec::new),
            Arc::new(|_| 0),
            Arc::new(|_| 0),
            Arc::new(rustbgpd_evpn::FdbNexthopDataplaneStatus::default),
        );

        let resp = svc
            .list_ip_vrfs(Request::new(proto::ListIpVrfsRequest {}))
            .await
            .unwrap()
            .into_inner();
        let row = &resp.ip_vrfs[0];
        assert_eq!(
            row.readiness_state,
            proto::IpVrfReadinessState::IpVrfReadinessUnknown as i32
        );
        assert_eq!(row.vrf_ifindex, 0);
        assert_eq!(row.l3vxlan_ifindex, 0);
        assert!(row.not_ready_reasons.is_empty());
    }

    #[tokio::test]
    async fn get_ip_vrf_returns_not_found_for_missing_name() {
        let svc = EvpnService::new(Arc::new(EvpnInstanceTable::new()));
        let err = svc
            .get_ip_vrf(Request::new(proto::GetIpVrfRequest {
                name: "nope".into(),
            }))
            .await
            .expect_err("expected NotFound");
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn get_ip_vrf_returns_matching_row() {
        let mut table = IpVrfTable::new();
        install_vrf(
            &mut table,
            "blue",
            5000,
            "65000:5000",
            "10.0.0.1",
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        );
        let svc = EvpnService::with_full_surface(
            Arc::new(EvpnInstanceTable::new()),
            Arc::new(table),
            Arc::new(|_| 0),
            Arc::new(Vec::new),
            Arc::new(|_| 0),
            Arc::new(|_| 0),
            Arc::new(rustbgpd_evpn::FdbNexthopDataplaneStatus::default),
        );

        let resp = svc
            .get_ip_vrf(Request::new(proto::GetIpVrfRequest {
                name: "blue".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.name, "blue");
        assert_eq!(resp.vni, 5000);
    }
}
