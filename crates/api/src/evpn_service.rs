//! gRPC `EvpnService` — local EVPN instance state and bounded controls.
//!
//! This service exposes the daemon's resolved
//! [`rustbgpd_evpn::EvpnInstanceTable`] so operators and SDN
//! controllers can confirm which local EVIs are installed without
//! parsing TOML themselves. Read methods are backed by the
//! daemon-owned ADR-0063 runtime model provider. Bounded controls go
//! through daemon-owned hooks: duplicate-MAC clear targets one
//! quarantine key, and `ApplyEvpnRuntime` validates full candidate
//! TOML through the coordinator while non-noop mutations fail closed
//! until actor convergence commands exist.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use rustbgpd_evpn::ip_vrf::{IpVrfId, IpVrfNotReady, IpVrfStatus, IpVrfTable};
use rustbgpd_evpn::{
    BumEnforcementTable, DfAlgorithm, EthernetSegmentIdentifier, EvpnInstance, EvpnInstanceId,
    EvpnInstanceTable, EvpnRuntimeLifecycle, EvpnRuntimeModel, EvpnRuntimeMutationState,
    EvpnRuntimePlan, EvpnRuntimeSnapshot, FdbNexthopDataplaneStatus, InstanceDataplaneStatus,
    InstanceState, IpVrfDataplaneStatus, MacAddress, SameEsiBiasTable,
};
use tonic::{Request, Response, Status};

use crate::audit::{apply_evpn_runtime_summary, set_request_summary};
use crate::proto;
use crate::server::{AccessMode, read_only_rejection};

/// Read-side hook for per-instance local-MAC origination counts.
pub type OriginatedLocalMacCountFn = Arc<dyn Fn(u32) -> u64 + Send + Sync + 'static>;

/// Read-side hook for the latest per-L2VNI readiness snapshot.
///
/// The daemon subscribes to `DataplaneReport.instance_status` and
/// keeps the most recent rows in a shared watch channel; this closure
/// returns a clone of that snapshot every call. Tests can inject a
/// deterministic snapshot.
pub type InstanceStatusSnapshotFn =
    Arc<dyn Fn() -> Vec<InstanceDataplaneStatus> + Send + Sync + 'static>;

/// Read-side hook for per-IP-VRF Type 5 origination counts (Gate 9
/// slice 6b). Mirrors [`OriginatedLocalMacCountFn`] for the L3 case;
/// the daemon backs it with the `OriginatedIpVrfRouteCounts` shared
/// state.
pub type OriginatedIpVrfRouteCountFn = Arc<dyn Fn(u32) -> u64 + Send + Sync + 'static>;

/// Read-side hook for per-IP-VRF Type 5 installed-route counts
/// (Gate 9 slice 6c). The daemon backs it with a `tokio::sync::watch`
/// fed from `DataplaneReport.ip_vrf_installed_routes`.
pub type InstalledIpVrfRouteCountFn = Arc<dyn Fn(u32) -> u64 + Send + Sync + 'static>;

/// One bounded current projection-drop count for remote EVPN Type 5
/// routes. `vrf` and `reason` intentionally mirror the bounded label
/// set used by the Prometheus `evpn_ip_vrf_remote_prefix_drops`
/// gauge; per-route fields stay out of the API status surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteIpPrefixDropCount {
    pub vrf: String,
    pub reason: String,
    pub count: u64,
}

/// Read-side hook for current remote Type 5 projection-drop counts.
/// The daemon backs it with the same projection summary used for
/// Prometheus metrics.
pub type RemoteIpPrefixDropCountSnapshotFn =
    Arc<dyn Fn() -> Vec<RemoteIpPrefixDropCount> + Send + Sync + 'static>;

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

/// Read-side hook for the current BUM/AC-gate enforcement snapshot.
/// The daemon backs it with the segment actor's watch-published table;
/// empty means the segment actor has not published yet or is absent.
pub type BumEnforcementSnapshotFn =
    Arc<dyn Fn() -> Arc<BumEnforcementTable> + Send + Sync + 'static>;

/// Read-side hook for the current same-ESI local-bias eligibility
/// snapshot.
pub type SameEsiBiasSnapshotFn = Arc<dyn Fn() -> Arc<SameEsiBiasTable> + Send + Sync + 'static>;

/// Read-side hook for composed Ethernet Segment drain reasons.
pub type EthernetSegmentDrainReasonsFn =
    Arc<dyn Fn(EthernetSegmentIdentifier) -> Vec<String> + Send + Sync + 'static>;

/// Read-side hook for the current ADR-0063 EVPN runtime model.
pub type EvpnRuntimeModelFn = Arc<dyn Fn() -> EvpnRuntimeModel + Send + Sync + 'static>;

pub type EvpnRuntimeApplyFuture = Pin<
    Box<dyn Future<Output = Result<proto::ApplyEvpnRuntimeResponse, EvpnRuntimeApplyError>> + Send>,
>;
pub type EvpnRuntimeApplyFn =
    Arc<dyn Fn(proto::ApplyEvpnRuntimeRequest) -> EvpnRuntimeApplyFuture + Send + Sync + 'static>;

/// Error returned by the daemon EVPN runtime apply hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvpnRuntimeApplyError {
    InvalidArgument(String),
    FailedPrecondition(String),
    Unavailable(String),
    Internal(String),
}

impl EvpnRuntimeApplyError {
    fn into_status(self) -> Status {
        match self {
            Self::InvalidArgument(message) => Status::invalid_argument(message),
            Self::FailedPrecondition(message) => Status::failed_precondition(message),
            Self::Unavailable(message) => Status::unavailable(message),
            Self::Internal(message) => Status::internal(message),
        }
    }
}

/// Outcome returned by the daemon duplicate-MAC control hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateMacClearOutcome {
    pub cleared: bool,
}

/// Error returned by the daemon duplicate-MAC control hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DuplicateMacClearError {
    Unavailable(String),
    NotFound(String),
}

pub type DuplicateMacClearFuture =
    Pin<Box<dyn Future<Output = Result<DuplicateMacClearOutcome, DuplicateMacClearError>> + Send>>;
pub type DuplicateMacClearFn =
    Arc<dyn Fn(EvpnInstanceId, MacAddress) -> DuplicateMacClearFuture + Send + Sync + 'static>;

/// Outcome returned by the daemon ADR-0084 Ethernet Segment drain hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetSegmentDrainOutcome {
    /// Composed drain state after the request: `true` while ANY drain
    /// reason is held (ADR-0085 decision 2) — an operator undrain
    /// against a link-drained segment reports `true`.
    pub drained: bool,
    /// `false` for an idempotent no-op on the RPC's (operator) reason.
    pub changed: bool,
    /// Member VNIs of the targeted ES in the committed config.
    pub member_vni_count: usize,
    /// Drain reasons held after the request, as the lowercase wire
    /// strings (`operator`, `link`). Empty when undrained.
    pub reasons: Vec<String>,
}

/// Error returned by the daemon ADR-0084 Ethernet Segment drain hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EthernetSegmentDrainError {
    /// The ESI is not in the committed Ethernet Segment config.
    NotFound(String),
    /// An actor publish failed (actor exited / daemon tearing down).
    Unavailable(String),
}

pub type EthernetSegmentDrainFuture = Pin<
    Box<dyn Future<Output = Result<EthernetSegmentDrainOutcome, EthernetSegmentDrainError>> + Send>,
>;
pub type EthernetSegmentDrainFn = Arc<
    dyn Fn(rustbgpd_evpn::EthernetSegmentIdentifier, bool) -> EthernetSegmentDrainFuture
        + Send
        + Sync
        + 'static,
>;

/// EVPN service backed by shared resolved tables and optional actor controls.
pub struct EvpnService {
    access_mode: AccessMode,
    originated_local_mac_count: OriginatedLocalMacCountFn,
    instance_status_snapshot: InstanceStatusSnapshotFn,
    ip_vrf_status_snapshot: IpVrfStatusSnapshotFn,
    originated_ip_vrf_route_count: OriginatedIpVrfRouteCountFn,
    installed_ip_vrf_route_count: InstalledIpVrfRouteCountFn,
    remote_ip_prefix_drop_counts_snapshot: RemoteIpPrefixDropCountSnapshotFn,
    fdb_nexthop_snapshot: FdbNexthopSnapshotFn,
    bum_enforcement_snapshot: BumEnforcementSnapshotFn,
    same_esi_bias_snapshot: SameEsiBiasSnapshotFn,
    ethernet_segment_drain_reasons: EthernetSegmentDrainReasonsFn,
    runtime_model: EvpnRuntimeModelFn,
    runtime_apply: Option<EvpnRuntimeApplyFn>,
    duplicate_mac_clear: Option<DuplicateMacClearFn>,
    ethernet_segment_drain: Option<EthernetSegmentDrainFn>,
}

impl EvpnService {
    /// Construct a service over the given resolved instance table.
    /// IP-VRF table defaults to empty; the local-MAC origination
    /// count and IP-VRF readiness closures default to "unknown".
    #[must_use]
    pub fn new(instances: Arc<EvpnInstanceTable>) -> Self {
        let ip_vrfs = Arc::new(IpVrfTable::new());
        let runtime_model = startup_runtime_model_fn(instances, ip_vrfs);
        Self {
            access_mode: AccessMode::ReadWrite,
            originated_local_mac_count: Arc::new(|_| 0),
            instance_status_snapshot: Arc::new(Vec::new),
            ip_vrf_status_snapshot: Arc::new(Vec::new),
            originated_ip_vrf_route_count: Arc::new(|_| 0),
            installed_ip_vrf_route_count: Arc::new(|_| 0),
            remote_ip_prefix_drop_counts_snapshot: Arc::new(Vec::new),
            fdb_nexthop_snapshot: Arc::new(FdbNexthopDataplaneStatus::default),
            bum_enforcement_snapshot: Arc::new(|| Arc::new(BumEnforcementTable::new())),
            same_esi_bias_snapshot: Arc::new(|| Arc::new(SameEsiBiasTable::new())),
            ethernet_segment_drain_reasons: Arc::new(|_| Vec::new()),
            runtime_model,
            runtime_apply: None,
            duplicate_mac_clear: None,
            ethernet_segment_drain: None,
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
        let ip_vrfs = Arc::new(IpVrfTable::new());
        let runtime_model = startup_runtime_model_fn(instances, ip_vrfs);
        Self {
            access_mode: AccessMode::ReadWrite,
            originated_local_mac_count,
            instance_status_snapshot: Arc::new(Vec::new),
            ip_vrf_status_snapshot: Arc::new(Vec::new),
            originated_ip_vrf_route_count: Arc::new(|_| 0),
            installed_ip_vrf_route_count: Arc::new(|_| 0),
            remote_ip_prefix_drop_counts_snapshot: Arc::new(Vec::new),
            fdb_nexthop_snapshot: Arc::new(FdbNexthopDataplaneStatus::default),
            bum_enforcement_snapshot: Arc::new(|| Arc::new(BumEnforcementTable::new())),
            same_esi_bias_snapshot: Arc::new(|| Arc::new(SameEsiBiasTable::new())),
            ethernet_segment_drain_reasons: Arc::new(|_| Vec::new()),
            runtime_model,
            runtime_apply: None,
            duplicate_mac_clear: None,
            ethernet_segment_drain: None,
        }
    }

    /// Construct a service exposing the full EVPN surface — the L2
    /// EVPN instance table, the L3 IP-VRF table, a live read of the
    /// most recent `DataplaneReport.ip_vrf_status` rows (Gate 9),
    /// and a live read of the most recent
    /// `DataplaneReport.fdb_nexthops` projection (ADR-0059 slice
    /// 3.5 operator visibility — backs `ListEvpnNexthops`). The
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
        Self::with_full_surface_and_duplicate_mac_control(
            instances,
            ip_vrfs,
            originated_local_mac_count,
            ip_vrf_status_snapshot,
            originated_ip_vrf_route_count,
            installed_ip_vrf_route_count,
            fdb_nexthop_snapshot,
            AccessMode::ReadWrite,
            None,
        )
    }

    /// Construct a service exposing the full EVPN surface plus the
    /// optional duplicate-MAC manual-clear control hook.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn with_full_surface_and_duplicate_mac_control(
        instances: Arc<EvpnInstanceTable>,
        ip_vrfs: Arc<IpVrfTable>,
        originated_local_mac_count: OriginatedLocalMacCountFn,
        ip_vrf_status_snapshot: IpVrfStatusSnapshotFn,
        originated_ip_vrf_route_count: OriginatedIpVrfRouteCountFn,
        installed_ip_vrf_route_count: InstalledIpVrfRouteCountFn,
        fdb_nexthop_snapshot: FdbNexthopSnapshotFn,
        access_mode: AccessMode,
        duplicate_mac_clear: Option<DuplicateMacClearFn>,
    ) -> Self {
        let runtime_model = startup_runtime_model_fn(instances, ip_vrfs);
        Self::with_full_surface_runtime_and_duplicate_mac_control(
            originated_local_mac_count,
            ip_vrf_status_snapshot,
            originated_ip_vrf_route_count,
            installed_ip_vrf_route_count,
            fdb_nexthop_snapshot,
            runtime_model,
            None,
            access_mode,
            duplicate_mac_clear,
        )
    }

    /// Construct a service exposing the full EVPN surface with an
    /// explicit ADR-0063 runtime model provider and optional apply
    /// hook.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn with_full_surface_runtime_and_duplicate_mac_control(
        originated_local_mac_count: OriginatedLocalMacCountFn,
        ip_vrf_status_snapshot: IpVrfStatusSnapshotFn,
        originated_ip_vrf_route_count: OriginatedIpVrfRouteCountFn,
        installed_ip_vrf_route_count: InstalledIpVrfRouteCountFn,
        fdb_nexthop_snapshot: FdbNexthopSnapshotFn,
        runtime_model: EvpnRuntimeModelFn,
        runtime_apply: Option<EvpnRuntimeApplyFn>,
        access_mode: AccessMode,
        duplicate_mac_clear: Option<DuplicateMacClearFn>,
    ) -> Self {
        Self {
            access_mode,
            originated_local_mac_count,
            instance_status_snapshot: Arc::new(Vec::new),
            ip_vrf_status_snapshot,
            originated_ip_vrf_route_count,
            installed_ip_vrf_route_count,
            remote_ip_prefix_drop_counts_snapshot: Arc::new(Vec::new),
            fdb_nexthop_snapshot,
            bum_enforcement_snapshot: Arc::new(|| Arc::new(BumEnforcementTable::new())),
            same_esi_bias_snapshot: Arc::new(|| Arc::new(SameEsiBiasTable::new())),
            ethernet_segment_drain_reasons: Arc::new(|_| Vec::new()),
            runtime_model,
            runtime_apply,
            duplicate_mac_clear,
            ethernet_segment_drain: None,
        }
    }

    /// Override the L2VNI readiness snapshot provider. Kept as a
    /// builder-style setter so callers that only need the static L2
    /// surface can keep using the compact constructors.
    #[must_use]
    pub fn with_instance_status_snapshot(
        mut self,
        instance_status_snapshot: InstanceStatusSnapshotFn,
    ) -> Self {
        self.instance_status_snapshot = instance_status_snapshot;
        self
    }

    /// Override the remote Type 5 projection-drop count provider.
    /// Kept as a builder-style setter so callers that only need
    /// readiness and route counts can use the compact constructors.
    #[must_use]
    pub fn with_remote_ip_prefix_drop_counts(
        mut self,
        remote_ip_prefix_drop_counts_snapshot: RemoteIpPrefixDropCountSnapshotFn,
    ) -> Self {
        self.remote_ip_prefix_drop_counts_snapshot = remote_ip_prefix_drop_counts_snapshot;
        self
    }

    /// Attach live Ethernet Segment diagnose state providers. These
    /// are read-only snapshots consumed by `ListEthernetSegments`;
    /// absent providers default to empty runtime state so RR-only and
    /// unit-test surfaces still return configured ES rows without
    /// requiring dataplane actors.
    #[must_use]
    pub fn with_ethernet_segment_state(
        mut self,
        bum_enforcement_snapshot: BumEnforcementSnapshotFn,
        same_esi_bias_snapshot: SameEsiBiasSnapshotFn,
        ethernet_segment_drain_reasons: EthernetSegmentDrainReasonsFn,
    ) -> Self {
        self.bum_enforcement_snapshot = bum_enforcement_snapshot;
        self.same_esi_bias_snapshot = same_esi_bias_snapshot;
        self.ethernet_segment_drain_reasons = ethernet_segment_drain_reasons;
        self
    }

    /// Attach the optional ADR-0084 Ethernet Segment drain hook.
    /// Absent on RR-only / no-`[[ethernet_segments]]` deployments —
    /// the RPC then fails closed with `UNAVAILABLE`.
    #[must_use]
    pub fn with_ethernet_segment_drain(
        mut self,
        ethernet_segment_drain: Option<EthernetSegmentDrainFn>,
    ) -> Self {
        self.ethernet_segment_drain = ethernet_segment_drain;
        self
    }
}

#[tonic::async_trait]
impl proto::evpn_service_server::EvpnService for EvpnService {
    async fn get_evpn_runtime(
        &self,
        _request: Request<proto::GetEvpnRuntimeRequest>,
    ) -> Result<Response<proto::EvpnRuntimeState>, Status> {
        let model = (self.runtime_model)();
        let snapshot = model.snapshot();
        Ok(Response::new(runtime_snapshot_to_proto(&snapshot)))
    }

    async fn list_evpn_instances(
        &self,
        _request: Request<proto::ListEvpnInstancesRequest>,
    ) -> Result<Response<proto::ListEvpnInstancesResponse>, Status> {
        let snapshot = (self.instance_status_snapshot)();
        let by_vni = instance_status_index(&snapshot);
        let model = (self.runtime_model)();
        let instances = model
            .instances()
            .sorted()
            .into_iter()
            .map(|inst| {
                evpn_instance_to_proto(
                    inst,
                    by_vni.get(&inst.id).copied(),
                    (self.originated_local_mac_count)(inst.id.as_u32()),
                )
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

    async fn list_ethernet_segments(
        &self,
        request: Request<proto::ListEthernetSegmentsRequest>,
    ) -> Result<Response<proto::ListEthernetSegmentsResponse>, Status> {
        let req = request.into_inner();
        let filter = if req.esi.trim().is_empty() {
            None
        } else {
            Some(parse_esi(&req.esi).map_err(|err| {
                Status::invalid_argument(format!("invalid ESI {}: {err}", req.esi))
            })?)
        };
        let model = (self.runtime_model)();
        let bum = (self.bum_enforcement_snapshot)();
        let bias = (self.same_esi_bias_snapshot)();
        let fdb = (self.fdb_nexthop_snapshot)();
        let fdb_counts = fdb_nexthop_counts_by_esi(&fdb);
        let mut segments: Vec<&rustbgpd_evpn::EthernetSegment> =
            model.ethernet_segments().iter().collect();
        segments.sort_by_key(|segment| segment.esi);

        let segments = segments
            .into_iter()
            .filter(|segment| filter.is_none_or(|target| segment.esi == target))
            .map(|segment| {
                let mut drain_reasons = (self.ethernet_segment_drain_reasons)(segment.esi);
                drain_reasons.sort();
                drain_reasons.dedup();
                let ac_gate = bum.ac_gate(segment.esi);
                let members = segment
                    .member_vnis
                    .iter()
                    .map(|vni| {
                        let row = bum.get(segment.esi, *vni);
                        proto::EthernetSegmentMemberState {
                            vni: vni.as_u32(),
                            df_role: row
                                .map(|entry| entry.role.as_str().to_string())
                                .unwrap_or_default(),
                            bum_forwarding_action: row
                                .map(|entry| entry.action.as_str().to_string())
                                .unwrap_or_default(),
                            bridge: row
                                .map(|entry| entry.bridge.clone())
                                .or_else(|| {
                                    model
                                        .instances()
                                        .get(*vni)
                                        .and_then(|inst| inst.bridge.clone())
                                })
                                .unwrap_or_default(),
                            same_esi_bias_eligible: bias.is_eligible(segment.esi, *vni),
                        }
                    })
                    .collect();
                let (fdb_groups, fdb_refs) =
                    fdb_counts.get(&segment.esi).copied().unwrap_or_default();
                proto::EthernetSegmentState {
                    esi: segment.esi.to_string(),
                    member_vnis: segment.member_vnis.iter().map(|vni| vni.as_u32()).collect(),
                    redundancy_mode: segment.redundancy_mode.as_str().to_string(),
                    df_algorithm: df_algorithm_label(segment.df_algorithm).to_string(),
                    df_preference: segment.df_preference,
                    df_dont_preempt: segment.df_dont_preempt,
                    originator_ip: segment.originator_ip.to_string(),
                    drained: !drain_reasons.is_empty(),
                    drain_reasons,
                    members,
                    ac_gate_state: ac_gate
                        .map(|entry| entry.state.as_str().to_string())
                        .unwrap_or_default(),
                    ac_gate_interface: ac_gate
                        .map(|entry| entry.interface.clone())
                        .unwrap_or_default(),
                    fdb_nexthop_groups_count: fdb_groups,
                    fdb_nexthop_ref_macs_count: fdb_refs,
                }
            })
            .collect();
        Ok(Response::new(proto::ListEthernetSegmentsResponse {
            segments,
        }))
    }

    async fn list_ip_vrfs(
        &self,
        _request: Request<proto::ListIpVrfsRequest>,
    ) -> Result<Response<proto::ListIpVrfsResponse>, Status> {
        let snapshot = (self.ip_vrf_status_snapshot)();
        let by_id = snapshot_index(&snapshot);
        let drop_counts = (self.remote_ip_prefix_drop_counts_snapshot)();
        let drop_index = index_remote_ip_prefix_drop_counts(&drop_counts);
        let model = (self.runtime_model)();
        let ip_vrfs: Vec<proto::IpVrfState> = model
            .ip_vrfs()
            .iter()
            .map(|vrf| {
                let originated = (self.originated_ip_vrf_route_count)(vrf.id.as_u32());
                let installed = (self.installed_ip_vrf_route_count)(vrf.id.as_u32());
                ip_vrf_to_proto(
                    vrf,
                    by_id.get(&vrf.id).copied(),
                    originated,
                    installed,
                    drop_index
                        .get(vrf.name.as_str())
                        .cloned()
                        .unwrap_or_default(),
                )
            })
            .collect();
        Ok(Response::new(proto::ListIpVrfsResponse { ip_vrfs }))
    }

    async fn get_ip_vrf(
        &self,
        request: Request<proto::GetIpVrfRequest>,
    ) -> Result<Response<proto::IpVrfState>, Status> {
        let name = request.into_inner().name;
        let model = (self.runtime_model)();
        let vrf = model
            .ip_vrfs()
            .get(&name)
            .ok_or_else(|| Status::not_found(format!("no IP-VRF named {name:?}")))?;
        let snapshot = (self.ip_vrf_status_snapshot)();
        let status = snapshot.iter().find(|r| r.vrf_id == vrf.id);
        let drop_counts = (self.remote_ip_prefix_drop_counts_snapshot)();
        let originated = (self.originated_ip_vrf_route_count)(vrf.id.as_u32());
        let installed = (self.installed_ip_vrf_route_count)(vrf.id.as_u32());
        Ok(Response::new(ip_vrf_to_proto(
            vrf,
            status,
            originated,
            installed,
            remote_ip_prefix_drop_counts_to_proto(&vrf.name, &drop_counts),
        )))
    }

    async fn clear_duplicate_mac_quarantine(
        &self,
        request: Request<proto::ClearDuplicateMacQuarantineRequest>,
    ) -> Result<Response<proto::ClearDuplicateMacQuarantineResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let req = request.into_inner();
        let vni = EvpnInstanceId::new(req.vni)
            .map_err(|err| Status::invalid_argument(format!("invalid VNI: {err}")))?;
        let mac = MacAddress::new(crate::injection_service::parse_mac(&req.mac)?);
        let clear = self.duplicate_mac_clear.as_ref().ok_or_else(|| {
            Status::unavailable("EVPN duplicate-MAC clear control is unavailable")
        })?;
        let outcome = clear(vni, mac).await.map_err(|err| match err {
            DuplicateMacClearError::Unavailable(message) => Status::unavailable(message),
            DuplicateMacClearError::NotFound(message) => Status::not_found(message),
        })?;
        let message = if outcome.cleared {
            format!("duplicate-MAC quarantine cleared for VNI {vni} MAC {mac}")
        } else {
            format!("no active duplicate-MAC quarantine for VNI {vni} MAC {mac}")
        };
        Ok(Response::new(proto::ClearDuplicateMacQuarantineResponse {
            cleared: outcome.cleared,
            message,
        }))
    }

    async fn set_ethernet_segment_drain(
        &self,
        request: Request<proto::SetEthernetSegmentDrainRequest>,
    ) -> Result<Response<proto::SetEthernetSegmentDrainResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let req = request.into_inner();
        let esi = parse_esi(&req.esi)
            .map_err(|err| Status::invalid_argument(format!("invalid ESI {}: {err}", req.esi)))?;
        let drain = self.ethernet_segment_drain.as_ref().ok_or_else(|| {
            Status::unavailable("EVPN Ethernet Segment drain control is unavailable")
        })?;
        let outcome = drain(esi, req.drained).await.map_err(|err| match err {
            EthernetSegmentDrainError::NotFound(message) => Status::not_found(message),
            EthernetSegmentDrainError::Unavailable(message) => Status::unavailable(message),
        })?;
        let message = ethernet_segment_drain_message(&req.esi, req.drained, &outcome);
        Ok(Response::new(proto::SetEthernetSegmentDrainResponse {
            drained: outcome.drained,
            changed: outcome.changed,
            member_vni_count: u32::try_from(outcome.member_vni_count).unwrap_or(u32::MAX),
            message,
            reasons: outcome.reasons,
        }))
    }

    async fn apply_evpn_runtime(
        &self,
        request: Request<proto::ApplyEvpnRuntimeRequest>,
    ) -> Result<Response<proto::ApplyEvpnRuntimeResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        set_request_summary(
            &request,
            apply_evpn_runtime_summary(
                &request.get_ref().candidate_toml,
                request.get_ref().validate_only,
            ),
        );
        let apply = self
            .runtime_apply
            .as_ref()
            .ok_or_else(|| Status::unavailable("EVPN runtime apply control is unavailable"))?;
        apply(request.into_inner())
            .await
            .map(Response::new)
            .map_err(EvpnRuntimeApplyError::into_status)
    }
}

/// Parse a 10-byte ESI from the operator text form used across this
/// proto (`XX:XX:XX:XX:XX:XX:XX:XX:XX:XX`). Mirrors the daemon config
/// parser — the wire crate intentionally doesn't implement `FromStr`
/// for `EthernetSegmentIdentifier` (the on-the-wire form is raw
/// bytes), so the API layer owns its own parse of the display form.
fn parse_esi(raw: &str) -> Result<rustbgpd_evpn::EthernetSegmentIdentifier, &'static str> {
    let parts: Vec<&str> = raw.split(':').collect();
    if parts.len() != 10 {
        return Err("expected 10 colon-separated hex octets");
    }
    let mut bytes = [0u8; 10];
    for (i, octet) in parts.iter().enumerate() {
        if octet.len() != 2 {
            return Err("each octet must be exactly 2 hex digits");
        }
        bytes[i] = u8::from_str_radix(octet, 16).map_err(|_| "invalid hex octet")?;
    }
    Ok(rustbgpd_evpn::EthernetSegmentIdentifier::new(bytes))
}

/// Operator-facing summary for a drain request. `requested` is the
/// RPC's desired operator-reason state; `outcome.drained` is the
/// COMPOSED state after the request (ADR-0085 decision 2: reasons
/// compose, so removing the operator reason does not undrain a
/// segment whose bound link is down, and adding it to a link-drained
/// segment withdraws nothing new).
fn ethernet_segment_drain_message(
    esi: &str,
    requested: bool,
    outcome: &EthernetSegmentDrainOutcome,
) -> String {
    let vnis = outcome.member_vni_count;
    let reasons = if outcome.reasons.is_empty() {
        "none".to_string()
    } else {
        outcome.reasons.join(",")
    };
    let link_held = outcome.reasons.iter().any(|reason| reason == "link");
    match (requested, outcome.changed) {
        (true, true) if link_held => format!(
            "Ethernet Segment {esi} operator drain recorded; routes were already \
             withdrawn by the link drain (drain reasons: {reasons})"
        ),
        (true, true) => format!(
            "Ethernet Segment {esi} drained: withdrew Type 4 (ES), EAD-per-ES, EAD-per-EVI, \
             and local Type 2 MAC/MAC+IP routes for {vnis} member VNI(s); new local-MAC \
             origination suppressed while drained"
        ),
        (true, false) => {
            format!("Ethernet Segment {esi} is already drained (drain reasons: {reasons})")
        }
        (false, true) if outcome.drained => format!(
            "Ethernet Segment {esi} operator drain removed; segment remains drained \
             (drain reasons: {reasons}) — origination resumes when the attachment \
             circuit recovers"
        ),
        (false, true) => format!(
            "Ethernet Segment {esi} undrained: re-originated Type 4 (ES), EAD-per-ES, \
             EAD-per-EVI, re-ran DF election, and replayed cached local MAC/MAC+IP state \
             for {vnis} member VNI(s)"
        ),
        (false, false) if outcome.drained => format!(
            "Ethernet Segment {esi} has no operator drain; segment remains drained \
             (drain reasons: {reasons})"
        ),
        (false, false) => format!("Ethernet Segment {esi} is not drained"),
    }
}

fn df_algorithm_label(algorithm: DfAlgorithm) -> &'static str {
    match algorithm {
        DfAlgorithm::DefaultModulo => "default-modulo",
        DfAlgorithm::HighestRandomWeight => "hrw",
        DfAlgorithm::HighestPreference => "highest-preference",
        DfAlgorithm::LowestPreference => "lowest-preference",
    }
}

fn fdb_nexthop_counts_by_esi(
    snapshot: &FdbNexthopDataplaneStatus,
) -> BTreeMap<EthernetSegmentIdentifier, (u32, u32)> {
    let mut counts = BTreeMap::new();
    for group in &snapshot.groups {
        let (groups, refs) = counts.entry(group.esi).or_insert((0u32, 0u32));
        *groups = groups.saturating_add(1);
        *refs = refs.saturating_add(u32::try_from(group.ref_macs.len()).unwrap_or(u32::MAX));
    }
    counts
}

fn startup_runtime_model_fn(
    instances: Arc<EvpnInstanceTable>,
    ip_vrfs: Arc<IpVrfTable>,
) -> EvpnRuntimeModelFn {
    let model = EvpnRuntimeModel::startup(instances, ip_vrfs, Vec::new());
    Arc::new(move || model.clone())
}

/// Build an `EvpnInstanceId -> &InstanceDataplaneStatus` index from
/// the per-call snapshot so `ListEvpnInstances` joins config rows
/// with status rows in O(N) instead of O(N²).
fn instance_status_index(
    snapshot: &[InstanceDataplaneStatus],
) -> HashMap<EvpnInstanceId, &InstanceDataplaneStatus> {
    snapshot.iter().map(|row| (row.vni, row)).collect()
}

/// Join the config-time `EvpnInstance` shape with a snapshot row (if
/// any) into the wire `EvpnInstanceState` message. A bound instance
/// with no status is `UNKNOWN`; an unbound instance can be reported
/// directly from config even before the reconciler publishes.
fn evpn_instance_to_proto(
    inst: &EvpnInstance,
    status: Option<&InstanceDataplaneStatus>,
    originated_local_macs_count: u64,
) -> proto::EvpnInstanceState {
    let mut state = proto::EvpnInstanceState {
        vni: inst.id.as_u32(),
        rd: inst.rd.to_string(),
        route_targets: inst.route_targets.iter().map(ToString::to_string).collect(),
        local_vtep_ip: inst.local_vtep_ip.to_string(),
        bridge: inst.bridge.clone().unwrap_or_default(),
        advertise_svi_mac: inst.advertise_svi_mac,
        originated_local_macs_count,
        readiness_state: proto::EvpnInstanceReadinessState::EvpnInstanceReadinessUnknown as i32,
        not_ready_reason: String::new(),
    };

    let Some(row) = status else {
        if inst.bridge.is_none() {
            state.readiness_state =
                proto::EvpnInstanceReadinessState::EvpnInstanceReadinessUnbound as i32;
        }
        return state;
    };

    match row.state {
        InstanceState::Ready => {
            state.readiness_state =
                proto::EvpnInstanceReadinessState::EvpnInstanceReadinessReady as i32;
        }
        InstanceState::NotReady => {
            state.readiness_state =
                proto::EvpnInstanceReadinessState::EvpnInstanceReadinessNotReady as i32;
            state.not_ready_reason = row
                .message
                .clone()
                .unwrap_or_else(|| "dataplane reported not-ready without a reason".into());
        }
        InstanceState::Unbound => {
            state.readiness_state =
                proto::EvpnInstanceReadinessState::EvpnInstanceReadinessUnbound as i32;
        }
    }
    state
}

#[must_use]
pub fn runtime_snapshot_to_proto(snapshot: &EvpnRuntimeSnapshot) -> proto::EvpnRuntimeState {
    proto::EvpnRuntimeState {
        generation: snapshot.generation.as_u64(),
        lifecycle: match snapshot.lifecycle {
            EvpnRuntimeLifecycle::Active => proto::EvpnRuntimeLifecycle::Active as i32,
            EvpnRuntimeLifecycle::Activating => proto::EvpnRuntimeLifecycle::Activating as i32,
            EvpnRuntimeLifecycle::Deleting => proto::EvpnRuntimeLifecycle::Deleting as i32,
            EvpnRuntimeLifecycle::Degraded => proto::EvpnRuntimeLifecycle::Degraded as i32,
        },
        mutation_state: match snapshot.mutation_state {
            EvpnRuntimeMutationState::Disabled => {
                proto::EvpnRuntimeMutationState::EvpnRuntimeMutationDisabled as i32
            }
            EvpnRuntimeMutationState::Idle => {
                proto::EvpnRuntimeMutationState::EvpnRuntimeMutationIdle as i32
            }
            EvpnRuntimeMutationState::InProgress => {
                proto::EvpnRuntimeMutationState::EvpnRuntimeMutationInProgress as i32
            }
            EvpnRuntimeMutationState::Failed => {
                proto::EvpnRuntimeMutationState::EvpnRuntimeMutationFailed as i32
            }
        },
        evpn_instances_count: u32::try_from(snapshot.evpn_instances_count).unwrap_or(u32::MAX),
        evpn_ip_vrfs_count: u32::try_from(snapshot.evpn_ip_vrfs_count).unwrap_or(u32::MAX),
        ethernet_segments_count: u32::try_from(snapshot.ethernet_segments_count)
            .unwrap_or(u32::MAX),
        ethernet_segment_member_vnis_count: u32::try_from(
            snapshot.ethernet_segment_member_vnis_count,
        )
        .unwrap_or(u32::MAX),
        message: snapshot.message.to_string(),
    }
}

#[must_use]
pub fn runtime_plan_to_proto(plan: &EvpnRuntimePlan) -> proto::EvpnRuntimePlanSummary {
    proto::EvpnRuntimePlanSummary {
        current_generation: plan.current_generation.as_u64(),
        proposed_generation: plan.proposed_generation.as_u64(),
        evpn_instances: Some(change_set_to_proto(&plan.evpn_instances)),
        evpn_ip_vrfs: Some(change_set_to_proto(&plan.ip_vrfs)),
        ethernet_segments: Some(change_set_to_proto(&plan.ethernet_segments)),
        ip_vrf_references_changed: plan.ip_vrf_references_changed,
    }
}

#[must_use]
pub fn runtime_apply_outcome_to_proto(outcome: rustbgpd_evpn::EvpnRuntimeApplyOutcome) -> i32 {
    match outcome {
        rustbgpd_evpn::EvpnRuntimeApplyOutcome::Noop => {
            proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyNoop as i32
        }
        rustbgpd_evpn::EvpnRuntimeApplyOutcome::Committed => {
            proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyCommitted as i32
        }
    }
}

fn change_set_to_proto<K>(
    set: &rustbgpd_evpn::EvpnRuntimeChangeSet<K>,
) -> proto::EvpnRuntimeChangeSummary
where
    K: ToString,
{
    proto::EvpnRuntimeChangeSummary {
        added: set.added.iter().map(ToString::to_string).collect(),
        deleted: set.deleted.iter().map(ToString::to_string).collect(),
        redefined: set.redefined.iter().map(ToString::to_string).collect(),
        unchanged: set.unchanged.iter().map(ToString::to_string).collect(),
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
    remote_prefix_drop_counts: Vec<proto::IpVrfRemotePrefixDropCount>,
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
        remote_prefix_drop_counts,
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

fn remote_ip_prefix_drop_counts_to_proto(
    vrf_name: &str,
    counts: &[RemoteIpPrefixDropCount],
) -> Vec<proto::IpVrfRemotePrefixDropCount> {
    let mut rows: Vec<proto::IpVrfRemotePrefixDropCount> = counts
        .iter()
        .filter(|count| count.vrf == vrf_name)
        .map(|count| proto::IpVrfRemotePrefixDropCount {
            reason: count.reason.clone(),
            count: count.count,
        })
        .collect();
    rows.sort_by(|a, b| a.reason.cmp(&b.reason));
    rows
}

/// Group the flat drop-count snapshot by IP-VRF name once so
/// `list_ip_vrfs` can do an O(1) lookup per VRF instead of rescanning
/// the whole slice for each one. Each VRF's rows are reason-sorted;
/// the index itself is unordered (lookups are by VRF name and the
/// response order is driven by the model's VRF iteration).
fn index_remote_ip_prefix_drop_counts(
    counts: &[RemoteIpPrefixDropCount],
) -> HashMap<String, Vec<proto::IpVrfRemotePrefixDropCount>> {
    let mut index: HashMap<String, Vec<proto::IpVrfRemotePrefixDropCount>> = HashMap::new();
    for count in counts {
        index
            .entry(count.vrf.clone())
            .or_default()
            .push(proto::IpVrfRemotePrefixDropCount {
                reason: count.reason.clone(),
                count: count.count,
            });
    }
    for rows in index.values_mut() {
        rows.sort_by(|a, b| a.reason.cmp(&b.reason));
    }
    index
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

    fn service_with_duplicate_mac_clear(
        access_mode: crate::server::AccessMode,
        duplicate_mac_clear: Option<DuplicateMacClearFn>,
    ) -> EvpnService {
        EvpnService::with_full_surface_and_duplicate_mac_control(
            Arc::new(EvpnInstanceTable::new()),
            Arc::new(IpVrfTable::new()),
            Arc::new(|_| 0),
            Arc::new(Vec::new),
            Arc::new(|_| 0),
            Arc::new(|_| 0),
            Arc::new(FdbNexthopDataplaneStatus::default),
            access_mode,
            duplicate_mac_clear,
        )
    }

    fn fixed_duplicate_mac_clear(
        result: Result<DuplicateMacClearOutcome, DuplicateMacClearError>,
    ) -> DuplicateMacClearFn {
        Arc::new(move |_, _| {
            let result = result.clone();
            Box::pin(async move { result }) as DuplicateMacClearFuture
        })
    }

    fn service_with_runtime_apply(
        access_mode: crate::server::AccessMode,
        runtime_apply: Option<EvpnRuntimeApplyFn>,
    ) -> EvpnService {
        EvpnService::with_full_surface_runtime_and_duplicate_mac_control(
            Arc::new(|_| 0),
            Arc::new(Vec::new),
            Arc::new(|_| 0),
            Arc::new(|_| 0),
            Arc::new(FdbNexthopDataplaneStatus::default),
            Arc::new(|| {
                EvpnRuntimeModel::startup(EvpnInstanceTable::new(), IpVrfTable::new(), Vec::new())
            }),
            runtime_apply,
            access_mode,
            None,
        )
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
        assert_eq!(
            resp.instances[0].readiness_state,
            proto::EvpnInstanceReadinessState::EvpnInstanceReadinessUnbound as i32
        );
        assert!(resp.instances[0].not_ready_reason.is_empty());
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
        assert_eq!(
            row.readiness_state,
            proto::EvpnInstanceReadinessState::EvpnInstanceReadinessUnknown as i32
        );
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
    async fn list_evpn_instances_joins_l2_readiness_snapshot() {
        let mut table = EvpnInstanceTable::new();
        table
            .insert(
                EvpnInstance::new(
                    EvpnInstanceId::new(100).unwrap(),
                    rd("65000:100"),
                    vec![rt("65000:100")],
                    ip("10.0.0.1"),
                    None,
                    false,
                )
                .unwrap(),
            )
            .unwrap();
        table
            .insert(
                EvpnInstance::new(
                    EvpnInstanceId::new(200).unwrap(),
                    rd("65000:200"),
                    vec![rt("65000:200")],
                    ip("10.0.0.2"),
                    Some("br200".into()),
                    false,
                )
                .unwrap(),
            )
            .unwrap();
        table
            .insert(
                EvpnInstance::new(
                    EvpnInstanceId::new(300).unwrap(),
                    rd("65000:300"),
                    vec![rt("65000:300")],
                    ip("10.0.0.3"),
                    Some("br300".into()),
                    false,
                )
                .unwrap(),
            )
            .unwrap();
        table
            .insert(
                EvpnInstance::new(
                    EvpnInstanceId::new(400).unwrap(),
                    rd("65000:400"),
                    vec![rt("65000:400")],
                    ip("10.0.0.4"),
                    Some("br400".into()),
                    false,
                )
                .unwrap(),
            )
            .unwrap();

        let svc = EvpnService::new(Arc::new(table)).with_instance_status_snapshot(Arc::new(|| {
            vec![
                InstanceDataplaneStatus {
                    vni: EvpnInstanceId::new(300).unwrap(),
                    state: InstanceState::Ready,
                    message: None,
                    bridge_mac: Some(MacAddress::new([0x02, 0, 0, 0, 0, 3])),
                },
                InstanceDataplaneStatus {
                    vni: EvpnInstanceId::new(400).unwrap(),
                    state: InstanceState::NotReady,
                    message: Some(
                        "bridge br400 is VLAN-aware (vlan_filtering=1); not supported".into(),
                    ),
                    bridge_mac: None,
                },
            ]
        }));

        let resp = svc
            .list_evpn_instances(Request::new(proto::ListEvpnInstancesRequest {}))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(resp.instances.len(), 4);
        assert_eq!(
            resp.instances[0].readiness_state,
            proto::EvpnInstanceReadinessState::EvpnInstanceReadinessUnbound as i32
        );
        assert!(resp.instances[0].not_ready_reason.is_empty());
        assert_eq!(
            resp.instances[1].readiness_state,
            proto::EvpnInstanceReadinessState::EvpnInstanceReadinessUnknown as i32
        );
        assert!(resp.instances[1].not_ready_reason.is_empty());
        assert_eq!(
            resp.instances[2].readiness_state,
            proto::EvpnInstanceReadinessState::EvpnInstanceReadinessReady as i32
        );
        assert!(resp.instances[2].not_ready_reason.is_empty());
        assert_eq!(
            resp.instances[3].readiness_state,
            proto::EvpnInstanceReadinessState::EvpnInstanceReadinessNotReady as i32
        );
        assert!(resp.instances[3].not_ready_reason.contains("VLAN-aware"));
    }

    #[test]
    fn not_ready_without_message_gets_diagnostic_fallback() {
        let inst = EvpnInstance::new(
            EvpnInstanceId::new(500).unwrap(),
            rd("65000:500"),
            vec![rt("65000:500")],
            ip("10.0.0.5"),
            Some("br500".into()),
            false,
        )
        .unwrap();
        let status = InstanceDataplaneStatus {
            vni: EvpnInstanceId::new(500).unwrap(),
            state: InstanceState::NotReady,
            message: None,
            bridge_mac: None,
        };

        let row = evpn_instance_to_proto(&inst, Some(&status), 0);

        assert_eq!(
            row.readiness_state,
            proto::EvpnInstanceReadinessState::EvpnInstanceReadinessNotReady as i32
        );
        assert_eq!(
            row.not_ready_reason,
            "dataplane reported not-ready without a reason"
        );
    }

    #[tokio::test]
    async fn get_evpn_runtime_surfaces_committed_generation() {
        let mut table = EvpnInstanceTable::new();
        install(&mut table, 100, "65000:100", "10.0.0.1");
        install(&mut table, 200, "65000:200", "10.0.0.2");
        let model = EvpnRuntimeModel::startup(table, IpVrfTable::new(), Vec::new());
        let svc = EvpnService::with_full_surface_runtime_and_duplicate_mac_control(
            Arc::new(|_| 0),
            Arc::new(Vec::new),
            Arc::new(|_| 0),
            Arc::new(|_| 0),
            Arc::new(FdbNexthopDataplaneStatus::default),
            Arc::new(move || model.clone()),
            None,
            crate::server::AccessMode::ReadWrite,
            None,
        );

        let resp = svc
            .get_evpn_runtime(Request::new(proto::GetEvpnRuntimeRequest {}))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(resp.generation, 1);
        assert_eq!(resp.lifecycle, proto::EvpnRuntimeLifecycle::Active as i32);
        assert_eq!(
            resp.mutation_state,
            proto::EvpnRuntimeMutationState::EvpnRuntimeMutationDisabled as i32
        );
        assert_eq!(resp.evpn_instances_count, 2);
        assert_eq!(resp.evpn_ip_vrfs_count, 0);
        assert_eq!(resp.ethernet_segments_count, 0);
        assert_eq!(resp.ethernet_segment_member_vnis_count, 0);
        assert_eq!(
            resp.message,
            "startup snapshot active; runtime EVPN mutation disabled"
        );
    }

    #[tokio::test]
    async fn list_evpn_instances_reads_runtime_model_provider() {
        let mut live_table = EvpnInstanceTable::new();
        install(&mut live_table, 100, "65000:100", "10.0.0.1");
        let live_model = EvpnRuntimeModel::startup(live_table, IpVrfTable::new(), Vec::new());
        let svc = EvpnService::with_full_surface_runtime_and_duplicate_mac_control(
            Arc::new(|_| 0),
            Arc::new(Vec::new),
            Arc::new(|_| 0),
            Arc::new(|_| 0),
            Arc::new(FdbNexthopDataplaneStatus::default),
            Arc::new(move || live_model.clone()),
            None,
            crate::server::AccessMode::ReadWrite,
            None,
        );

        let resp = svc
            .list_evpn_instances(Request::new(proto::ListEvpnInstancesRequest {}))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(resp.instances.len(), 1);
        assert_eq!(resp.instances[0].vni, 100);
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

    #[tokio::test]
    async fn list_ethernet_segments_joins_runtime_state() {
        let esi = rustbgpd_evpn::EthernetSegmentIdentifier::new([3, 0, 0, 0, 0, 0, 0, 0, 0, 7]);
        let vni = EvpnInstanceId::new(100).unwrap();
        let mut instances = EvpnInstanceTable::new();
        instances
            .insert(
                EvpnInstance::new(
                    vni,
                    rd("65000:100"),
                    vec![rt("65000:100")],
                    ip("10.0.0.1"),
                    Some("br100".to_string()),
                    false,
                )
                .unwrap(),
            )
            .unwrap();
        let model = EvpnRuntimeModel::startup(
            instances,
            IpVrfTable::new(),
            vec![rustbgpd_evpn::EthernetSegment {
                esi,
                member_vnis: std::collections::BTreeSet::from([vni]),
                df_preference: 500,
                df_algorithm: rustbgpd_evpn::DfAlgorithm::HighestPreference,
                df_dont_preempt: true,
                redundancy_mode: rustbgpd_evpn::RedundancyMode::SingleActive,
                originator_ip: ip("10.0.0.1"),
            }],
        );
        let mut bum = BumEnforcementTable::new();
        bum.insert(esi, vni, rustbgpd_evpn::DfRole::NonDf, "br100".to_string());
        bum.set_ac_gate(esi, "eth1".to_string(), rustbgpd_evpn::AcGateState::Blocked);
        let mut bias = SameEsiBiasTable::new();
        bias.insert(esi, vni);
        let fdb = rustbgpd_evpn::FdbNexthopDataplaneStatus {
            groups: vec![rustbgpd_evpn::FdbNexthopGroupStatus {
                vni,
                esi,
                ethernet_tag: rustbgpd_evpn::EthernetTagId(0),
                group_id: 0x4000_0001,
                members: Vec::new(),
                ref_macs: vec![
                    MacAddress::new([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01]),
                    MacAddress::new([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x02]),
                ],
            }],
            orphan_nexthops_count: 0,
            pending_delete_count: 0,
            drift_recovery_disabled: false,
        };
        let bum_snapshot = bum.clone();
        let bias_snapshot = bias.clone();
        let svc = EvpnService::with_full_surface_runtime_and_duplicate_mac_control(
            Arc::new(|_| 0),
            Arc::new(Vec::new),
            Arc::new(|_| 0),
            Arc::new(|_| 0),
            Arc::new(move || fdb.clone()),
            Arc::new(move || model.clone()),
            None,
            crate::server::AccessMode::ReadWrite,
            None,
        )
        .with_ethernet_segment_state(
            Arc::new(move || Arc::new(bum_snapshot.clone())),
            Arc::new(move || Arc::new(bias_snapshot.clone())),
            Arc::new(move |target| {
                if target == esi {
                    vec!["operator".to_string(), "link".to_string()]
                } else {
                    Vec::new()
                }
            }),
        );

        let resp = svc
            .list_ethernet_segments(Request::new(proto::ListEthernetSegmentsRequest {
                esi: esi.to_string(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.segments.len(), 1);
        let segment = &resp.segments[0];
        assert_eq!(segment.esi, esi.to_string());
        assert_eq!(segment.member_vnis, vec![100]);
        assert_eq!(segment.redundancy_mode, "single-active");
        assert_eq!(segment.df_algorithm, "highest-preference");
        assert_eq!(segment.df_preference, 500);
        assert!(segment.df_dont_preempt);
        assert!(segment.drained);
        assert_eq!(segment.drain_reasons, vec!["link", "operator"]);
        assert_eq!(segment.ac_gate_state, "blocked");
        assert_eq!(segment.ac_gate_interface, "eth1");
        assert_eq!(segment.fdb_nexthop_groups_count, 1);
        assert_eq!(segment.fdb_nexthop_ref_macs_count, 2);
        assert_eq!(segment.members.len(), 1);
        assert_eq!(segment.members[0].df_role, "nondf");
        assert_eq!(segment.members[0].bum_forwarding_action, "suppress");
        assert_eq!(segment.members[0].bridge, "br100");
        assert!(segment.members[0].same_esi_bias_eligible);
    }

    #[tokio::test]
    async fn clear_duplicate_mac_quarantine_rejects_read_only_listener() {
        let svc = service_with_duplicate_mac_clear(
            crate::server::AccessMode::ReadOnly,
            Some(fixed_duplicate_mac_clear(Ok(DuplicateMacClearOutcome {
                cleared: true,
            }))),
        );
        let err = svc
            .clear_duplicate_mac_quarantine(Request::new(
                proto::ClearDuplicateMacQuarantineRequest {
                    vni: 100,
                    mac: "aa:bb:cc:dd:ee:ff".to_string(),
                },
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn clear_duplicate_mac_quarantine_requires_control_hook() {
        let svc = service_with_duplicate_mac_clear(crate::server::AccessMode::ReadWrite, None);
        let err = svc
            .clear_duplicate_mac_quarantine(Request::new(
                proto::ClearDuplicateMacQuarantineRequest {
                    vni: 100,
                    mac: "aa:bb:cc:dd:ee:ff".to_string(),
                },
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unavailable);
    }

    #[tokio::test]
    async fn clear_duplicate_mac_quarantine_maps_success_and_inactive() {
        let clear: DuplicateMacClearFn = Arc::new(|vni, mac| {
            assert_eq!(vni.as_u32(), 100);
            assert_eq!(mac.to_string(), "aa:bb:cc:dd:ee:ff");
            Box::pin(async move { Ok(DuplicateMacClearOutcome { cleared: true }) })
                as DuplicateMacClearFuture
        });
        let svc =
            service_with_duplicate_mac_clear(crate::server::AccessMode::ReadWrite, Some(clear));
        let resp = svc
            .clear_duplicate_mac_quarantine(Request::new(
                proto::ClearDuplicateMacQuarantineRequest {
                    vni: 100,
                    mac: "aa:bb:cc:dd:ee:ff".to_string(),
                },
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(resp.cleared);
        assert!(resp.message.contains("cleared"));

        let svc = service_with_duplicate_mac_clear(
            crate::server::AccessMode::ReadWrite,
            Some(fixed_duplicate_mac_clear(Ok(DuplicateMacClearOutcome {
                cleared: false,
            }))),
        );
        let resp = svc
            .clear_duplicate_mac_quarantine(Request::new(
                proto::ClearDuplicateMacQuarantineRequest {
                    vni: 100,
                    mac: "aa:bb:cc:dd:ee:ff".to_string(),
                },
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(!resp.cleared);
        assert!(resp.message.contains("no active"));
    }

    #[tokio::test]
    async fn clear_duplicate_mac_quarantine_validates_request() {
        let svc = service_with_duplicate_mac_clear(
            crate::server::AccessMode::ReadWrite,
            Some(fixed_duplicate_mac_clear(Ok(DuplicateMacClearOutcome {
                cleared: true,
            }))),
        );
        let bad_vni = svc
            .clear_duplicate_mac_quarantine(Request::new(
                proto::ClearDuplicateMacQuarantineRequest {
                    vni: 0,
                    mac: "aa:bb:cc:dd:ee:ff".to_string(),
                },
            ))
            .await
            .unwrap_err();
        assert_eq!(bad_vni.code(), tonic::Code::InvalidArgument);

        let bad_mac = svc
            .clear_duplicate_mac_quarantine(Request::new(
                proto::ClearDuplicateMacQuarantineRequest {
                    vni: 100,
                    mac: "aa:bb:cc".to_string(),
                },
            ))
            .await
            .unwrap_err();
        assert_eq!(bad_mac.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn clear_duplicate_mac_quarantine_maps_control_errors() {
        let svc = service_with_duplicate_mac_clear(
            crate::server::AccessMode::ReadWrite,
            Some(fixed_duplicate_mac_clear(Err(
                DuplicateMacClearError::NotFound("missing VNI".to_string()),
            ))),
        );
        let err = svc
            .clear_duplicate_mac_quarantine(Request::new(
                proto::ClearDuplicateMacQuarantineRequest {
                    vni: 100,
                    mac: "aa:bb:cc:dd:ee:ff".to_string(),
                },
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);

        let svc = service_with_duplicate_mac_clear(
            crate::server::AccessMode::ReadWrite,
            Some(fixed_duplicate_mac_clear(Err(
                DuplicateMacClearError::Unavailable("control unavailable".to_string()),
            ))),
        );
        let err = svc
            .clear_duplicate_mac_quarantine(Request::new(
                proto::ClearDuplicateMacQuarantineRequest {
                    vni: 100,
                    mac: "aa:bb:cc:dd:ee:ff".to_string(),
                },
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unavailable);
    }

    fn service_with_es_drain(
        access_mode: crate::server::AccessMode,
        ethernet_segment_drain: Option<EthernetSegmentDrainFn>,
    ) -> EvpnService {
        service_with_duplicate_mac_clear(access_mode, None)
            .with_ethernet_segment_drain(ethernet_segment_drain)
    }

    fn fixed_es_drain(
        result: Result<EthernetSegmentDrainOutcome, EthernetSegmentDrainError>,
    ) -> EthernetSegmentDrainFn {
        Arc::new(move |_, _| {
            let result = result.clone();
            Box::pin(async move { result }) as EthernetSegmentDrainFuture
        })
    }

    const TEST_ESI: &str = "00:11:22:33:44:55:66:77:88:99";

    #[tokio::test]
    async fn set_ethernet_segment_drain_rejects_read_only_listener() {
        let svc = service_with_es_drain(
            crate::server::AccessMode::ReadOnly,
            Some(fixed_es_drain(Ok(EthernetSegmentDrainOutcome {
                drained: true,
                changed: true,
                member_vni_count: 1,
                reasons: vec!["operator".to_string()],
            }))),
        );
        let err = svc
            .set_ethernet_segment_drain(Request::new(proto::SetEthernetSegmentDrainRequest {
                esi: TEST_ESI.to_string(),
                drained: true,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn set_ethernet_segment_drain_requires_control_hook() {
        let svc = service_with_es_drain(crate::server::AccessMode::ReadWrite, None);
        let err = svc
            .set_ethernet_segment_drain(Request::new(proto::SetEthernetSegmentDrainRequest {
                esi: TEST_ESI.to_string(),
                drained: true,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unavailable);
    }

    #[tokio::test]
    async fn set_ethernet_segment_drain_validates_esi() {
        let svc = service_with_es_drain(
            crate::server::AccessMode::ReadWrite,
            Some(fixed_es_drain(Ok(EthernetSegmentDrainOutcome {
                drained: true,
                changed: true,
                member_vni_count: 1,
                reasons: vec!["operator".to_string()],
            }))),
        );
        for bad in [
            "",
            "00:11:22",
            "zz:11:22:33:44:55:66:77:88:99",
            "0:1:2:3:4:5:6:7:8:9",
        ] {
            let err = svc
                .set_ethernet_segment_drain(Request::new(proto::SetEthernetSegmentDrainRequest {
                    esi: bad.to_string(),
                    drained: true,
                }))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument, "esi {bad:?}");
        }
    }

    #[tokio::test]
    async fn set_ethernet_segment_drain_maps_applied_and_idempotent_outcomes() {
        let drain: EthernetSegmentDrainFn = Arc::new(|esi, drained| {
            assert_eq!(esi.to_string(), TEST_ESI);
            assert!(drained);
            Box::pin(async move {
                Ok(EthernetSegmentDrainOutcome {
                    drained: true,
                    changed: true,
                    member_vni_count: 3,
                    reasons: vec!["operator".to_string()],
                })
            }) as EthernetSegmentDrainFuture
        });
        let svc = service_with_es_drain(crate::server::AccessMode::ReadWrite, Some(drain));
        let resp = svc
            .set_ethernet_segment_drain(Request::new(proto::SetEthernetSegmentDrainRequest {
                esi: TEST_ESI.to_string(),
                drained: true,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(resp.drained);
        assert!(resp.changed);
        assert_eq!(resp.member_vni_count, 3);
        assert!(resp.message.contains("drained"));
        assert!(resp.message.contains("Type 4"));
        assert_eq!(resp.reasons, vec!["operator".to_string()]);

        let svc = service_with_es_drain(
            crate::server::AccessMode::ReadWrite,
            Some(fixed_es_drain(Ok(EthernetSegmentDrainOutcome {
                drained: true,
                changed: false,
                member_vni_count: 3,
                reasons: vec!["operator".to_string()],
            }))),
        );
        let resp = svc
            .set_ethernet_segment_drain(Request::new(proto::SetEthernetSegmentDrainRequest {
                esi: TEST_ESI.to_string(),
                drained: true,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(resp.drained);
        assert!(!resp.changed, "idempotent repeat must report changed=false");
        assert!(resp.message.contains("already drained"));
    }

    /// ADR-0085 decision 2: the response reports the COMPOSED state
    /// and the reason set. An operator undrain that removes its
    /// reason while the link drain holds must say "remains drained";
    /// an operator drain on an already link-drained segment must not
    /// claim a fresh withdrawal.
    #[tokio::test]
    async fn set_ethernet_segment_drain_reports_composed_state_and_reasons() {
        // Operator undrain accepted, but the bound link is down.
        let svc = service_with_es_drain(
            crate::server::AccessMode::ReadWrite,
            Some(fixed_es_drain(Ok(EthernetSegmentDrainOutcome {
                drained: true,
                changed: true,
                member_vni_count: 2,
                reasons: vec!["link".to_string()],
            }))),
        );
        let resp = svc
            .set_ethernet_segment_drain(Request::new(proto::SetEthernetSegmentDrainRequest {
                esi: TEST_ESI.to_string(),
                drained: false,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(resp.drained, "composed state stays drained");
        assert!(resp.changed, "operator reason was removed");
        assert_eq!(resp.reasons, vec!["link".to_string()]);
        assert!(resp.message.contains("remains drained"));
        assert!(resp.message.contains("link"));

        // Operator drain stacked on an existing link drain: no fresh
        // withdrawal happened.
        let svc = service_with_es_drain(
            crate::server::AccessMode::ReadWrite,
            Some(fixed_es_drain(Ok(EthernetSegmentDrainOutcome {
                drained: true,
                changed: true,
                member_vni_count: 2,
                reasons: vec!["operator".to_string(), "link".to_string()],
            }))),
        );
        let resp = svc
            .set_ethernet_segment_drain(Request::new(proto::SetEthernetSegmentDrainRequest {
                esi: TEST_ESI.to_string(),
                drained: true,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(resp.drained);
        assert!(resp.changed);
        assert_eq!(
            resp.reasons,
            vec!["operator".to_string(), "link".to_string()]
        );
        assert!(resp.message.contains("already withdrawn"));
    }

    #[tokio::test]
    async fn set_ethernet_segment_drain_maps_control_errors() {
        let svc = service_with_es_drain(
            crate::server::AccessMode::ReadWrite,
            Some(fixed_es_drain(Err(EthernetSegmentDrainError::NotFound(
                "not configured".to_string(),
            )))),
        );
        let err = svc
            .set_ethernet_segment_drain(Request::new(proto::SetEthernetSegmentDrainRequest {
                esi: TEST_ESI.to_string(),
                drained: true,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);

        let svc = service_with_es_drain(
            crate::server::AccessMode::ReadWrite,
            Some(fixed_es_drain(Err(EthernetSegmentDrainError::Unavailable(
                "control closed".to_string(),
            )))),
        );
        let err = svc
            .set_ethernet_segment_drain(Request::new(proto::SetEthernetSegmentDrainRequest {
                esi: TEST_ESI.to_string(),
                drained: false,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unavailable);
    }

    #[test]
    fn parse_esi_round_trips_display_form() {
        let esi = super::parse_esi(TEST_ESI).unwrap();
        assert_eq!(esi.to_string(), TEST_ESI);
        assert!(super::parse_esi("not-an-esi").is_err());
    }

    #[tokio::test]
    async fn apply_evpn_runtime_rejects_read_only_listener() {
        let apply: EvpnRuntimeApplyFn = Arc::new(|_| {
            Box::pin(async {
                Ok(proto::ApplyEvpnRuntimeResponse {
                    outcome: proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyValidated as i32,
                    runtime: None,
                    plan: None,
                    message: "unexpected".to_string(),
                })
            }) as EvpnRuntimeApplyFuture
        });
        let svc = service_with_runtime_apply(crate::server::AccessMode::ReadOnly, Some(apply));

        let err = svc
            .apply_evpn_runtime(Request::new(proto::ApplyEvpnRuntimeRequest {
                candidate_toml: "candidate".to_string(),
                validate_only: true,
            }))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn apply_evpn_runtime_requires_control_hook() {
        let svc = service_with_runtime_apply(crate::server::AccessMode::ReadWrite, None);

        let err = svc
            .apply_evpn_runtime(Request::new(proto::ApplyEvpnRuntimeRequest {
                candidate_toml: "candidate".to_string(),
                validate_only: true,
            }))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::Unavailable);
    }

    #[tokio::test]
    async fn apply_evpn_runtime_forwards_to_control_hook() {
        let apply: EvpnRuntimeApplyFn = Arc::new(|request| {
            assert_eq!(request.candidate_toml, "candidate");
            assert!(request.validate_only);
            Box::pin(async {
                Ok(proto::ApplyEvpnRuntimeResponse {
                    outcome: proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyValidated as i32,
                    runtime: None,
                    plan: None,
                    message: "validated".to_string(),
                })
            }) as EvpnRuntimeApplyFuture
        });
        let svc = service_with_runtime_apply(crate::server::AccessMode::ReadWrite, Some(apply));

        let resp = svc
            .apply_evpn_runtime(Request::new(proto::ApplyEvpnRuntimeRequest {
                candidate_toml: "candidate".to_string(),
                validate_only: true,
            }))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(
            resp.outcome,
            proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyValidated as i32
        );
        assert_eq!(resp.message, "validated");
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
    async fn list_ip_vrfs_reads_runtime_model_provider() {
        let mut live_vrfs = IpVrfTable::new();
        install_vrf(
            &mut live_vrfs,
            "blue",
            5000,
            "65000:5000",
            "10.0.0.1",
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        );
        let live_model = EvpnRuntimeModel::startup(EvpnInstanceTable::new(), live_vrfs, Vec::new());
        let svc = EvpnService::with_full_surface_runtime_and_duplicate_mac_control(
            Arc::new(|_| 0),
            Arc::new(Vec::new),
            Arc::new(|_| 0),
            Arc::new(|_| 0),
            Arc::new(FdbNexthopDataplaneStatus::default),
            Arc::new(move || live_model.clone()),
            None,
            crate::server::AccessMode::ReadWrite,
            None,
        );

        let resp = svc
            .list_ip_vrfs(Request::new(proto::ListIpVrfsRequest {}))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(resp.ip_vrfs.len(), 1);
        assert_eq!(resp.ip_vrfs[0].name, "blue");
        assert_eq!(resp.ip_vrfs[0].vni, 5000);
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
    async fn list_ip_vrfs_surfaces_scoped_remote_prefix_drop_counts() {
        let mut table = IpVrfTable::new();
        install_vrf(
            &mut table,
            "blue",
            5000,
            "65000:5000",
            "10.0.0.1",
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        );
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
            Arc::new(Vec::new),
            Arc::new(|_| 0),
            Arc::new(|_| 0),
            Arc::new(rustbgpd_evpn::FdbNexthopDataplaneStatus::default),
        )
        .with_remote_ip_prefix_drop_counts(Arc::new(|| {
            vec![
                RemoteIpPrefixDropCount {
                    vrf: "blue".to_string(),
                    reason: "unresolved_overlay_index_gateway".to_string(),
                    count: 2,
                },
                RemoteIpPrefixDropCount {
                    vrf: "red".to_string(),
                    reason: "l3vni_mismatch".to_string(),
                    count: 1,
                },
            ]
        }));

        let resp = svc
            .list_ip_vrfs(Request::new(proto::ListIpVrfsRequest {}))
            .await
            .unwrap()
            .into_inner();
        let blue = resp
            .ip_vrfs
            .iter()
            .find(|row| row.name == "blue")
            .expect("blue row should exist");
        assert_eq!(blue.remote_prefix_drop_counts.len(), 1);
        assert_eq!(
            blue.remote_prefix_drop_counts[0].reason,
            "unresolved_overlay_index_gateway"
        );
        assert_eq!(blue.remote_prefix_drop_counts[0].count, 2);
        let red = resp
            .ip_vrfs
            .iter()
            .find(|row| row.name == "red")
            .expect("red row should exist");
        assert_eq!(red.remote_prefix_drop_counts.len(), 1);
        assert_eq!(red.remote_prefix_drop_counts[0].reason, "l3vni_mismatch");
        assert_eq!(red.remote_prefix_drop_counts[0].count, 1);
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

    #[tokio::test]
    async fn get_ip_vrf_surfaces_remote_prefix_drop_counts() {
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
        )
        .with_remote_ip_prefix_drop_counts(Arc::new(|| {
            vec![RemoteIpPrefixDropCount {
                vrf: "blue".to_string(),
                reason: "ambiguous_overlay_index_gateway".to_string(),
                count: 3,
            }]
        }));

        let resp = svc
            .get_ip_vrf(Request::new(proto::GetIpVrfRequest {
                name: "blue".into(),
            }))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(resp.remote_prefix_drop_counts.len(), 1);
        assert_eq!(
            resp.remote_prefix_drop_counts[0].reason,
            "ambiguous_overlay_index_gateway"
        );
        assert_eq!(resp.remote_prefix_drop_counts[0].count, 3);
    }
}
