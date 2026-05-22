//! rustbgpd — API-first BGP daemon
//!
//! Binary entry point. Loads config, wires components, starts runtime.

#![cfg_attr(
    not(any(feature = "jemalloc", feature = "dhat-heap")),
    deny(unsafe_code)
)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

mod blackhole;
mod config;
mod config_persister;
mod evpn_dataplane;
mod evpn_imet;
mod evpn_l3_originator;
mod evpn_originator;
mod evpn_segment;
mod evpn_svi;
mod fib;
mod fib_common;
mod fib_runtime;
mod looking_glass;
mod metrics_server;
mod peer_manager;
mod policy_admin;
mod reload;

use std::collections::BTreeMap;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::process;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant as StdInstant, SystemTime, UNIX_EPOCH};

use rustbgpd_rib::{RibManager, RibUpdate};
use rustbgpd_telemetry::{BgpMetrics, init_logging};
use rustbgpd_transport::{BgpListener, ListenerSocketOptions, TcpAoListenerKey};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::config::{
    Config, GrpcAccessMode, GrpcEnforcementConfig, GrpcListener, GrpcMaxTier, GrpcRoleConfig,
};
use crate::config_persister::{ConfigMutation, ConfigPersister};
use crate::peer_manager::PeerManager;
use crate::reload::{ReloadedConfig, apply_reload_outcome, reload_config, run_config_bridge};
use rustbgpd_api::evpn_service::{
    EvpnRuntimeApplyError as GrpcEvpnRuntimeApplyError, runtime_apply_outcome_to_proto,
    runtime_plan_to_proto, runtime_snapshot_to_proto,
};
use rustbgpd_api::peer_types::{PeerManagerCommand, PeerManagerNeighborConfig};
use rustbgpd_api::proto;
use rustbgpd_api::server::{
    AccessMode as GrpcServerAccessMode, ListenerConfig as GrpcListenerConfig, ListenerEndpoint,
    ServeConfig,
};

const GR_RESTART_MARKER_VERSION: u8 = 1;

#[derive(Debug, Serialize, Deserialize)]
struct GrRestartMarker {
    version: u8,
    expires_at_unix: u64,
}

struct BmpRuntime {
    control_tx: mpsc::Sender<rustbgpd_bmp::BmpControlEvent>,
    manager_handle: JoinHandle<()>,
    client_handles: Vec<JoinHandle<()>>,
}

impl From<GrpcAccessMode> for GrpcServerAccessMode {
    fn from(value: GrpcAccessMode) -> Self {
        match value {
            GrpcAccessMode::ReadOnly => Self::ReadOnly,
            GrpcAccessMode::ReadWrite => Self::ReadWrite,
        }
    }
}

const fn grpc_max_tier_to_auth_tier(value: GrpcMaxTier) -> rustbgpd_api::authz::AuthTier {
    match value {
        GrpcMaxTier::Read => rustbgpd_api::authz::AuthTier::Read,
        GrpcMaxTier::SensitiveRead => rustbgpd_api::authz::AuthTier::SensitiveRead,
        GrpcMaxTier::Mutating => rustbgpd_api::authz::AuthTier::Mutating,
        GrpcMaxTier::OperatorOnly => rustbgpd_api::authz::AuthTier::OperatorOnly,
    }
}

fn evpn_vni_to_esi_map(
    ethernet_segments: &[rustbgpd_evpn::EthernetSegment],
) -> Arc<BTreeMap<rustbgpd_evpn::EvpnInstanceId, rustbgpd_wire::EthernetSegmentIdentifier>> {
    let mut map = BTreeMap::new();
    for seg in ethernet_segments {
        for &vni in &seg.member_vnis {
            // `Config::resolve_ethernet_segments` rejects duplicate
            // member-VNI across segments, so this is a logic bug if it
            // ever trips on a resolved model.
            debug_assert!(!map.contains_key(&vni));
            map.insert(vni, seg.esi);
        }
    }
    Arc::new(map)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DaemonEvpnRuntimeConvergeError {
    Unsupported(String),
    Failed(rustbgpd_evpn::EvpnRuntimeConvergeError),
}

impl DaemonEvpnRuntimeConvergeError {
    fn unsupported(message: impl Into<String>) -> Self {
        Self::Unsupported(message.into())
    }

    fn failed(message: impl Into<String>) -> Self {
        Self::Failed(rustbgpd_evpn::EvpnRuntimeConvergeError::new(message))
    }

    fn message(&self) -> &str {
        match self {
            Self::Unsupported(message) => message,
            Self::Failed(source) => source.message(),
        }
    }
}

type DaemonEvpnRuntimeConvergeFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), DaemonEvpnRuntimeConvergeError>> + Send + 'a>>;

trait DaemonEvpnRuntimeConverger: Send + Sync {
    fn converge<'a>(
        &'a self,
        current: &'a rustbgpd_evpn::EvpnRuntimeModel,
        candidate: &'a rustbgpd_evpn::EvpnRuntimeCandidate,
        plan: &'a rustbgpd_evpn::EvpnRuntimePlan,
    ) -> DaemonEvpnRuntimeConvergeFuture<'a>;
}

struct PreconvergedRuntimeConverger;

impl rustbgpd_evpn::EvpnRuntimeConverger for PreconvergedRuntimeConverger {
    fn converge(
        &mut self,
        _current: &rustbgpd_evpn::EvpnRuntimeModel,
        _candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
        _plan: &rustbgpd_evpn::EvpnRuntimePlan,
    ) -> Result<(), rustbgpd_evpn::EvpnRuntimeConvergeError> {
        Ok(())
    }
}

struct FailedRuntimeConverger {
    source: rustbgpd_evpn::EvpnRuntimeConvergeError,
}

impl rustbgpd_evpn::EvpnRuntimeConverger for FailedRuntimeConverger {
    fn converge(
        &mut self,
        _current: &rustbgpd_evpn::EvpnRuntimeModel,
        _candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
        _plan: &rustbgpd_evpn::EvpnRuntimePlan,
    ) -> Result<(), rustbgpd_evpn::EvpnRuntimeConvergeError> {
        Err(self.source.clone())
    }
}

#[derive(Clone)]
struct EvpnRuntimeActorConverger {
    rib_tx: mpsc::Sender<RibUpdate>,
    imet_controller: Arc<tokio::sync::Mutex<evpn_imet::EvpnImetController>>,
    dataplane: Option<evpn_dataplane::EvpnDataplaneRuntimeControl>,
    originator: Option<evpn_originator::EvpnOriginatorRuntimeControl>,
    svi: Option<evpn_svi::EvpnSviRuntimeControl>,
    l3_originator: Option<evpn_l3_originator::EvpnL3OriginatorRuntimeControl>,
    segment: Option<evpn_segment::EvpnSegmentRuntimeControl>,
}

impl EvpnRuntimeActorConverger {
    async fn converge_l2vni_add(
        &self,
        current: &rustbgpd_evpn::EvpnRuntimeModel,
        candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
        plan: &rustbgpd_evpn::EvpnRuntimePlan,
    ) -> Result<(), DaemonEvpnRuntimeConvergeError> {
        let added_vni = validate_single_l2vni_add(current, candidate, plan)?;
        let Some(instance) = candidate.instances().get(added_vni).cloned() else {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "candidate did not contain added L2VNI {added_vni}"
            )));
        };
        let candidate_instances = Arc::new(candidate.instances().clone());
        let candidate_vni_to_esi = evpn_vni_to_esi_map(candidate.ethernet_segments());
        let candidate_ip_vrfs = Arc::new(candidate.ip_vrfs().clone());
        let ip_vrf_metadata_changed = current.ip_vrfs() != candidate.ip_vrfs();

        let dataplane = self.require_l2vni_dataplane("add")?;
        let originator = self.require_l2vni_originator("add")?;
        let svi_required = instance.advertise_svi_mac;
        let svi = self.svi.as_ref();
        if svi_required && svi.is_none() {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(
                "L2VNI runtime add with advertise_svi_mac=true requires an active SVI actor; \
                 live SVI actor-spawn is not supported yet",
            ));
        }
        if let Some(svi) = svi
            && !svi.is_open()
        {
            return Err(DaemonEvpnRuntimeConvergeError::failed(
                "EVPN SVI runtime control is closed",
            ));
        }
        let segment = self.open_segment_runtime_control()?;

        let imet_outcome = self
            .imet_controller
            .lock()
            .await
            .originate_instance(instance, &self.rib_tx)
            .await;
        if !matches!(
            imet_outcome,
            evpn_imet::ImetOriginateOutcome::Originated { .. }
                | evpn_imet::ImetOriginateOutcome::AlreadyOriginated { .. }
                | evpn_imet::ImetOriginateOutcome::ReplyDropped { .. }
        ) {
            return Err(DaemonEvpnRuntimeConvergeError::failed(format!(
                "EVPN IMET origination failed for L2VNI {added_vni}: {imet_outcome:?}"
            )));
        }

        if ip_vrf_metadata_changed && !dataplane.replace_ip_vrfs(candidate_ip_vrfs) {
            self.rollback_imet(added_vni).await;
            return Err(DaemonEvpnRuntimeConvergeError::failed(
                "EVPN dataplane IP-VRF runtime model publish failed",
            ));
        }
        if !dataplane.replace_evpn_instances(candidate_instances.clone()) {
            Self::rollback_l2vni_dataplane(dataplane, current, ip_vrf_metadata_changed);
            self.rollback_imet(added_vni).await;
            return Err(DaemonEvpnRuntimeConvergeError::failed(
                "EVPN dataplane runtime model publish failed",
            ));
        }
        if !originator.replace_runtime_model(candidate_instances.clone(), candidate_vni_to_esi) {
            Self::rollback_l2vni_dataplane(dataplane, current, ip_vrf_metadata_changed);
            self.rollback_imet(added_vni).await;
            return Err(DaemonEvpnRuntimeConvergeError::failed(
                "EVPN Type 2 originator runtime model publish failed",
            ));
        }
        if let Some(svi) = svi
            && !svi.replace_evpn_instances(candidate_instances.clone())
        {
            Self::rollback_l2vni_dataplane(dataplane, current, ip_vrf_metadata_changed);
            let current_instances = Arc::new(current.instances().clone());
            let _ = originator.replace_runtime_model(
                current_instances,
                evpn_vni_to_esi_map(current.ethernet_segments()),
            );
            self.rollback_imet(added_vni).await;
            return Err(DaemonEvpnRuntimeConvergeError::failed(
                "EVPN SVI runtime model publish failed",
            ));
        }
        if let Err(err) = Self::publish_segment_instances(segment, candidate_instances) {
            Self::rollback_l2vni_runtime_models(
                dataplane,
                Some(originator),
                svi,
                segment,
                current,
                ip_vrf_metadata_changed,
            );
            self.rollback_imet(added_vni).await;
            return Err(err);
        }

        Ok(())
    }

    fn rollback_l2vni_dataplane(
        dataplane: &evpn_dataplane::EvpnDataplaneRuntimeControl,
        current: &rustbgpd_evpn::EvpnRuntimeModel,
        rollback_ip_vrf_metadata: bool,
    ) {
        let _ = dataplane.replace_evpn_instances(Arc::new(current.instances().clone()));
        if rollback_ip_vrf_metadata {
            let _ = dataplane.replace_ip_vrfs(Arc::new(current.ip_vrfs().clone()));
        }
    }

    fn require_l2vni_dataplane(
        &self,
        operation: &str,
    ) -> Result<&evpn_dataplane::EvpnDataplaneRuntimeControl, DaemonEvpnRuntimeConvergeError> {
        let dataplane = self.dataplane.as_ref().ok_or_else(|| {
            DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "L2VNI runtime {operation} requires an active EVPN dataplane actor; \
                 empty/RR-only startup actor-spawn is not supported yet"
            ))
        })?;
        if !dataplane.is_open() {
            return Err(DaemonEvpnRuntimeConvergeError::failed(
                "EVPN dataplane runtime control is closed",
            ));
        }
        Ok(dataplane)
    }

    fn require_l2vni_originator(
        &self,
        operation: &str,
    ) -> Result<&evpn_originator::EvpnOriginatorRuntimeControl, DaemonEvpnRuntimeConvergeError>
    {
        let originator = self.originator.as_ref().ok_or_else(|| {
            DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "L2VNI runtime {operation} requires an active EVPN Type 2 originator; \
                 empty/RR-only startup actor-spawn is not supported yet"
            ))
        })?;
        if !originator.is_open() {
            return Err(DaemonEvpnRuntimeConvergeError::failed(
                "EVPN Type 2 originator runtime control is closed",
            ));
        }
        Ok(originator)
    }

    fn rollback_l2vni_runtime_models(
        dataplane: &evpn_dataplane::EvpnDataplaneRuntimeControl,
        originator: Option<&evpn_originator::EvpnOriginatorRuntimeControl>,
        svi: Option<&evpn_svi::EvpnSviRuntimeControl>,
        segment: Option<&evpn_segment::EvpnSegmentRuntimeControl>,
        current: &rustbgpd_evpn::EvpnRuntimeModel,
        rollback_ip_vrf_metadata: bool,
    ) {
        Self::rollback_l2vni_dataplane(dataplane, current, rollback_ip_vrf_metadata);
        let current_instances = Arc::new(current.instances().clone());
        if let Some(originator) = originator {
            let _ = originator.replace_runtime_model(
                current_instances.clone(),
                evpn_vni_to_esi_map(current.ethernet_segments()),
            );
        }
        if let Some(svi) = svi {
            let _ = svi.replace_evpn_instances(current_instances.clone());
        }
        if let Some(segment) = segment {
            let _ = segment.replace_instances(current_instances);
        }
    }

    fn open_segment_runtime_control(
        &self,
    ) -> Result<Option<&evpn_segment::EvpnSegmentRuntimeControl>, DaemonEvpnRuntimeConvergeError>
    {
        let segment = self.segment.as_ref();
        if let Some(segment) = segment
            && !segment.is_open()
        {
            return Err(DaemonEvpnRuntimeConvergeError::failed(
                "EVPN segment runtime control is closed",
            ));
        }
        Ok(segment)
    }

    fn publish_segment_instances(
        segment: Option<&evpn_segment::EvpnSegmentRuntimeControl>,
        instances: Arc<rustbgpd_evpn::EvpnInstanceTable>,
    ) -> Result<(), DaemonEvpnRuntimeConvergeError> {
        if let Some(segment) = segment
            && !segment.replace_instances(instances)
        {
            return Err(DaemonEvpnRuntimeConvergeError::failed(
                "EVPN segment instance runtime model publish failed",
            ));
        }
        Ok(())
    }

    async fn converge_l2vni_delete(
        &self,
        current: &rustbgpd_evpn::EvpnRuntimeModel,
        candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
        plan: &rustbgpd_evpn::EvpnRuntimePlan,
    ) -> Result<(), DaemonEvpnRuntimeConvergeError> {
        let deleted_instance = validate_single_l2vni_delete(current, candidate, plan)?;
        let deleted_vni = deleted_instance.id;
        let current_instances = Arc::new(current.instances().clone());
        let candidate_instances = Arc::new(candidate.instances().clone());
        let candidate_ip_vrfs = Arc::new(candidate.ip_vrfs().clone());
        let ip_vrf_metadata_changed = current.ip_vrfs() != candidate.ip_vrfs();

        let dataplane = self.require_l2vni_dataplane("delete")?;
        let originator = self.require_l2vni_originator("delete")?;
        let svi_required = deleted_instance.advertise_svi_mac;
        let svi = self.svi.as_ref();
        if svi_required && svi.is_none() {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(
                "L2VNI runtime delete with advertise_svi_mac=true requires an active SVI actor; \
                 live SVI actor-spawn is not supported yet",
            ));
        }
        if let Some(svi) = svi
            && !svi.is_open()
        {
            return Err(DaemonEvpnRuntimeConvergeError::failed(
                "EVPN SVI runtime control is closed",
            ));
        }
        let segment = self.open_segment_runtime_control()?;

        if ip_vrf_metadata_changed && !dataplane.replace_ip_vrfs(candidate_ip_vrfs) {
            return Err(DaemonEvpnRuntimeConvergeError::failed(
                "EVPN dataplane IP-VRF runtime model publish failed",
            ));
        }
        if !dataplane.replace_evpn_instances(candidate_instances.clone()) {
            Self::rollback_l2vni_dataplane(dataplane, current, ip_vrf_metadata_changed);
            return Err(DaemonEvpnRuntimeConvergeError::failed(
                "EVPN dataplane runtime model publish failed",
            ));
        }
        if let Some(svi) = svi
            && !svi.replace_evpn_instances(candidate_instances.clone())
        {
            Self::rollback_l2vni_dataplane(dataplane, current, ip_vrf_metadata_changed);
            return Err(DaemonEvpnRuntimeConvergeError::failed(
                "EVPN SVI runtime model publish failed",
            ));
        }

        let imet_outcome = self
            .imet_controller
            .lock()
            .await
            .withdraw_instance(deleted_vni, &self.rib_tx)
            .await;
        if !matches!(
            imet_outcome,
            evpn_imet::ImetWithdrawOutcome::Withdrawn { .. }
                | evpn_imet::ImetWithdrawOutcome::NotOriginated { .. }
        ) {
            Self::rollback_l2vni_dataplane(dataplane, current, ip_vrf_metadata_changed);
            if let Some(svi) = svi {
                let _ = svi.replace_evpn_instances(current_instances.clone());
            }
            return Err(DaemonEvpnRuntimeConvergeError::failed(format!(
                "EVPN IMET withdrawal failed for L2VNI {deleted_vni}: {imet_outcome:?}"
            )));
        }

        if !originator.replace_runtime_model(
            candidate_instances.clone(),
            evpn_vni_to_esi_map(candidate.ethernet_segments()),
        ) {
            Self::rollback_l2vni_dataplane(dataplane, current, ip_vrf_metadata_changed);
            if let Some(svi) = svi {
                let _ = svi.replace_evpn_instances(current_instances);
            }
            self.restore_imet(deleted_instance).await;
            return Err(DaemonEvpnRuntimeConvergeError::failed(
                "EVPN Type 2 originator runtime model publish failed",
            ));
        }
        if let Err(err) = Self::publish_segment_instances(segment, candidate_instances) {
            Self::rollback_l2vni_runtime_models(
                dataplane,
                Some(originator),
                svi,
                segment,
                current,
                ip_vrf_metadata_changed,
            );
            self.restore_imet(deleted_instance).await;
            return Err(err);
        }

        Ok(())
    }

    fn converge_ip_vrf_add(
        &self,
        current: &rustbgpd_evpn::EvpnRuntimeModel,
        candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
        plan: &rustbgpd_evpn::EvpnRuntimePlan,
    ) -> Result<(), DaemonEvpnRuntimeConvergeError> {
        let added_name = validate_single_ip_vrf_add(plan)?;
        let candidate_ip_vrfs = Arc::new(candidate.ip_vrfs().clone());
        if candidate.ip_vrfs().get(&added_name).is_none() {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "candidate is missing planned IP-VRF {added_name:?}"
            )));
        }

        let dataplane = self.dataplane.as_ref().ok_or_else(|| {
            DaemonEvpnRuntimeConvergeError::unsupported(
                "IP-VRF runtime add requires an active EVPN dataplane actor; \
                 no-EVPN startup actor-spawn is not supported yet",
            )
        })?;
        let l3_originator = self.l3_originator.as_ref().ok_or_else(|| {
            DaemonEvpnRuntimeConvergeError::unsupported(
                "IP-VRF runtime add requires an active EVPN Type 5 originator; \
                 live Type 5 actor-spawn is not supported yet",
            )
        })?;
        if !dataplane.is_open() {
            return Err(DaemonEvpnRuntimeConvergeError::failed(
                "EVPN dataplane runtime control is closed",
            ));
        }
        if !l3_originator.is_open() {
            return Err(DaemonEvpnRuntimeConvergeError::failed(
                "EVPN Type 5 originator runtime control is closed",
            ));
        }

        if !dataplane.replace_ip_vrfs(candidate_ip_vrfs.clone()) {
            return Err(DaemonEvpnRuntimeConvergeError::failed(
                "EVPN dataplane IP-VRF runtime model publish failed",
            ));
        }
        if !l3_originator.replace_ip_vrfs(candidate_ip_vrfs) {
            if !dataplane.replace_ip_vrfs(Arc::new(current.ip_vrfs().clone())) {
                return Err(DaemonEvpnRuntimeConvergeError::failed(
                    "EVPN Type 5 originator runtime model publish failed and EVPN dataplane IP-VRF rollback failed; live dataplane state may require daemon restart",
                ));
            }
            return Err(DaemonEvpnRuntimeConvergeError::failed(
                "EVPN Type 5 originator runtime model publish failed",
            ));
        }
        Ok(())
    }

    fn converge_ip_vrf_delete(
        &self,
        current: &rustbgpd_evpn::EvpnRuntimeModel,
        candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
        plan: &rustbgpd_evpn::EvpnRuntimePlan,
    ) -> Result<(), DaemonEvpnRuntimeConvergeError> {
        let _deleted_name = validate_single_ip_vrf_delete(current, candidate, plan)?;
        let candidate_ip_vrfs = Arc::new(candidate.ip_vrfs().clone());

        let dataplane = self.dataplane.as_ref().ok_or_else(|| {
            DaemonEvpnRuntimeConvergeError::unsupported(
                "IP-VRF runtime delete requires an active EVPN dataplane actor; \
                 no-EVPN startup actor-spawn is not supported yet",
            )
        })?;
        let l3_originator = self.l3_originator.as_ref().ok_or_else(|| {
            DaemonEvpnRuntimeConvergeError::unsupported(
                "IP-VRF runtime delete requires an active EVPN Type 5 originator; \
                 live Type 5 actor-spawn is not supported yet",
            )
        })?;
        if !dataplane.is_open() {
            return Err(DaemonEvpnRuntimeConvergeError::failed(
                "EVPN dataplane runtime control is closed",
            ));
        }
        if !l3_originator.is_open() {
            return Err(DaemonEvpnRuntimeConvergeError::failed(
                "EVPN Type 5 originator runtime control is closed",
            ));
        }

        if !dataplane.replace_ip_vrfs(candidate_ip_vrfs.clone()) {
            return Err(DaemonEvpnRuntimeConvergeError::failed(
                "EVPN dataplane IP-VRF runtime model publish failed",
            ));
        }
        if !l3_originator.replace_ip_vrfs(candidate_ip_vrfs) {
            if !dataplane.replace_ip_vrfs(Arc::new(current.ip_vrfs().clone())) {
                return Err(DaemonEvpnRuntimeConvergeError::failed(
                    "EVPN Type 5 originator runtime model publish failed and EVPN dataplane IP-VRF rollback failed; live dataplane state may require daemon restart",
                ));
            }
            return Err(DaemonEvpnRuntimeConvergeError::failed(
                "EVPN Type 5 originator runtime model publish failed",
            ));
        }
        Ok(())
    }

    fn converge_ethernet_segment_add(
        &self,
        current: &rustbgpd_evpn::EvpnRuntimeModel,
        candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
        plan: &rustbgpd_evpn::EvpnRuntimePlan,
    ) -> Result<(), DaemonEvpnRuntimeConvergeError> {
        validate_single_ethernet_segment_add(current, candidate, plan)?;
        self.publish_ethernet_segment_runtime_snapshot(current, candidate, "add")
    }

    fn converge_ethernet_segment_delete(
        &self,
        current: &rustbgpd_evpn::EvpnRuntimeModel,
        candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
        plan: &rustbgpd_evpn::EvpnRuntimePlan,
    ) -> Result<(), DaemonEvpnRuntimeConvergeError> {
        validate_single_ethernet_segment_delete(current, candidate, plan)?;
        self.publish_ethernet_segment_runtime_snapshot(current, candidate, "delete")
    }

    fn converge_ethernet_segment_redefine(
        &self,
        current: &rustbgpd_evpn::EvpnRuntimeModel,
        candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
        plan: &rustbgpd_evpn::EvpnRuntimePlan,
    ) -> Result<(), DaemonEvpnRuntimeConvergeError> {
        validate_single_ethernet_segment_redefine(current, candidate, plan)?;
        self.publish_ethernet_segment_runtime_snapshot(current, candidate, "redefine")
    }

    fn publish_ethernet_segment_runtime_snapshot(
        &self,
        current: &rustbgpd_evpn::EvpnRuntimeModel,
        candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
        operation: &str,
    ) -> Result<(), DaemonEvpnRuntimeConvergeError> {
        let segment = self.segment.as_ref().ok_or_else(|| {
            DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "Ethernet Segment runtime {operation} requires an active EVPN segment actor; \
                 live segment actor-spawn is not supported yet"
            ))
        })?;
        if !segment.is_open() {
            return Err(DaemonEvpnRuntimeConvergeError::failed(
                "EVPN segment runtime control is closed",
            ));
        }
        // ES add/delete/redefine leaves the instance table unchanged
        // (`plan.evpn_instances.has_changes() == false`), so clone it once
        // and share the Arc across the segment + originator publishes.
        let candidate_instances = Arc::new(candidate.instances().clone());
        Self::publish_segment_instances(Some(segment), candidate_instances.clone())?;

        // ES add/delete/redefine changes member VNI -> ESI bindings, which the
        // Type 2 originator stamps onto local MAC / MAC+IP routes.
        // Republish the originator's runtime model (unchanged instances,
        // new vni->esi map) so it drains stale local routes and
        // re-originates them under the candidate ESI map.
        // RR / no-local-MAC deployments have no originator and are left
        // untouched (the segment publish below still runs).
        let republished_originator = if let Some(originator) = self.originator.as_ref() {
            if !originator.is_open() {
                return Err(DaemonEvpnRuntimeConvergeError::failed(
                    "EVPN Type 2 originator runtime control is closed",
                ));
            }
            if !originator.replace_runtime_model(
                candidate_instances.clone(),
                evpn_vni_to_esi_map(candidate.ethernet_segments()),
            ) {
                return Err(DaemonEvpnRuntimeConvergeError::failed(
                    "EVPN Type 2 originator runtime model publish failed",
                ));
            }
            true
        } else {
            false
        };

        // Publish the complete candidate ES set: the segment actor's
        // change-detection and ESI-label-allocator release logic operate
        // on the full desired snapshot, mirroring the L2VNI/IP-VRF paths.
        let candidate_segments = Arc::new(candidate.ethernet_segments().to_vec());
        if !segment.replace_segments(candidate_segments) {
            if republished_originator && let Some(originator) = self.originator.as_ref() {
                // Roll the originator back to the committed vni->esi map.
                let _ = originator.replace_runtime_model(
                    Arc::new(current.instances().clone()),
                    evpn_vni_to_esi_map(current.ethernet_segments()),
                );
            }
            return Err(DaemonEvpnRuntimeConvergeError::failed(
                "EVPN segment runtime model publish failed",
            ));
        }
        Ok(())
    }

    async fn rollback_imet(&self, vni: rustbgpd_evpn::EvpnInstanceId) {
        let _ = self
            .imet_controller
            .lock()
            .await
            .withdraw_instance(vni, &self.rib_tx)
            .await;
    }

    async fn restore_imet(&self, instance: rustbgpd_evpn::EvpnInstance) {
        let _ = self
            .imet_controller
            .lock()
            .await
            .originate_instance(instance, &self.rib_tx)
            .await;
    }
}

impl DaemonEvpnRuntimeConverger for EvpnRuntimeActorConverger {
    fn converge<'a>(
        &'a self,
        current: &'a rustbgpd_evpn::EvpnRuntimeModel,
        candidate: &'a rustbgpd_evpn::EvpnRuntimeCandidate,
        plan: &'a rustbgpd_evpn::EvpnRuntimePlan,
    ) -> DaemonEvpnRuntimeConvergeFuture<'a> {
        Box::pin(async move {
            if plan.evpn_instances.has_changes() {
                if plan.evpn_instances.added.is_empty()
                    && !plan.evpn_instances.deleted.is_empty()
                    && plan.evpn_instances.redefined.is_empty()
                {
                    return self.converge_l2vni_delete(current, candidate, plan).await;
                }
                return self.converge_l2vni_add(current, candidate, plan).await;
            }
            if plan.ip_vrfs.has_changes() {
                if plan.ip_vrfs.added.is_empty()
                    && !plan.ip_vrfs.deleted.is_empty()
                    && plan.ip_vrfs.redefined.is_empty()
                {
                    return self.converge_ip_vrf_delete(current, candidate, plan);
                }
                return self.converge_ip_vrf_add(current, candidate, plan);
            }
            if plan.ethernet_segments.has_changes() {
                if plan.ethernet_segments.added.is_empty()
                    && !plan.ethernet_segments.deleted.is_empty()
                    && plan.ethernet_segments.redefined.is_empty()
                {
                    return self.converge_ethernet_segment_delete(current, candidate, plan);
                }
                if plan.ethernet_segments.added.is_empty()
                    && plan.ethernet_segments.deleted.is_empty()
                    && !plan.ethernet_segments.redefined.is_empty()
                {
                    return self.converge_ethernet_segment_redefine(current, candidate, plan);
                }
                return self.converge_ethernet_segment_add(current, candidate, plan);
            }
            Err(DaemonEvpnRuntimeConvergeError::unsupported(
                "ApplyEvpnRuntime has no supported changes in this candidate",
            ))
        })
    }
}

fn validate_single_l2vni_add(
    current: &rustbgpd_evpn::EvpnRuntimeModel,
    candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
    plan: &rustbgpd_evpn::EvpnRuntimePlan,
) -> Result<rustbgpd_evpn::EvpnInstanceId, DaemonEvpnRuntimeConvergeError> {
    if plan.ip_vrfs.has_changes() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently does not support mixed L2VNI and IP-VRF changes in one request",
        ));
    }
    if plan.ethernet_segments.has_changes() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports only L2VNI add; Ethernet Segment changes are not supported yet",
        ));
    }
    if !plan.evpn_instances.deleted.is_empty() || !plan.evpn_instances.redefined.is_empty() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports only add-only L2VNI changes; delete/redefine is not supported yet",
        ));
    }
    if plan.evpn_instances.added.len() != 1 {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports exactly one added L2VNI per request",
        ));
    }

    let raw_vni = plan.evpn_instances.added[0];
    let added_vni = rustbgpd_evpn::EvpnInstanceId::new(raw_vni).map_err(|err| {
        DaemonEvpnRuntimeConvergeError::unsupported(format!(
            "invalid planned L2VNI {raw_vni}: {err}"
        ))
    })?;
    if current.instances().get(added_vni).is_some() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
            "planned L2VNI {added_vni} is already committed"
        )));
    }
    if candidate.instances().get(added_vni).is_none() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
            "candidate is missing planned L2VNI {added_vni}"
        )));
    }
    Ok(added_vni)
}

fn validate_single_l2vni_delete(
    current: &rustbgpd_evpn::EvpnRuntimeModel,
    candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
    plan: &rustbgpd_evpn::EvpnRuntimePlan,
) -> Result<rustbgpd_evpn::EvpnInstance, DaemonEvpnRuntimeConvergeError> {
    if plan.ip_vrfs.has_changes() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports L2VNI delete only when IP-VRF changes are absent",
        ));
    }
    if plan.ethernet_segments.has_changes() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports L2VNI delete only when Ethernet Segment changes are absent",
        ));
    }
    if !plan.evpn_instances.added.is_empty() || !plan.evpn_instances.redefined.is_empty() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports only delete-only L2VNI changes; add/redefine is not supported in the same request",
        ));
    }
    if plan.evpn_instances.deleted.len() != 1 {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports exactly one deleted L2VNI per request",
        ));
    }
    let raw_vni = plan.evpn_instances.deleted[0];
    let deleted_vni = rustbgpd_evpn::EvpnInstanceId::new(raw_vni).map_err(|err| {
        DaemonEvpnRuntimeConvergeError::unsupported(format!(
            "invalid planned L2VNI {raw_vni}: {err}"
        ))
    })?;
    let Some(instance) = current.instances().get(deleted_vni).cloned() else {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
            "planned L2VNI {deleted_vni} is not committed"
        )));
    };
    if candidate.instances().get(deleted_vni).is_some() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
            "candidate still contains planned deleted L2VNI {deleted_vni}"
        )));
    }
    validate_l2vni_delete_ip_vrf_metadata(current, candidate, deleted_vni)?;
    if current
        .ethernet_segments()
        .iter()
        .any(|segment| segment.member_vnis.contains(&deleted_vni))
    {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
            "L2VNI {deleted_vni} is a member of an Ethernet Segment; ES-aware delete is not supported yet"
        )));
    }

    Ok(instance)
}

fn validate_l2vni_delete_ip_vrf_metadata(
    current: &rustbgpd_evpn::EvpnRuntimeModel,
    candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
    deleted_vni: rustbgpd_evpn::EvpnInstanceId,
) -> Result<(), DaemonEvpnRuntimeConvergeError> {
    for vrf in current.ip_vrfs().iter() {
        let mut expected = current
            .ip_vrfs()
            .referenced_l2vnis(&vrf.name)
            .cloned()
            .unwrap_or_default();
        expected.remove(&deleted_vni);

        let actual = candidate
            .ip_vrfs()
            .referenced_l2vnis(&vrf.name)
            .cloned()
            .unwrap_or_default();
        let candidate_reference_present = candidate.ip_vrfs().is_referenced(&vrf.name);
        let expected_reference_present = !expected.is_empty();
        if actual != expected || candidate_reference_present != expected_reference_present {
            let name = &vrf.name;
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "ApplyEvpnRuntime currently supports L2VNI delete only when candidate IP-VRF link metadata for {name:?} matches the committed metadata except for removing deleted L2VNI {deleted_vni}"
            )));
        }
    }
    Ok(())
}

fn validate_single_ip_vrf_add(
    plan: &rustbgpd_evpn::EvpnRuntimePlan,
) -> Result<String, DaemonEvpnRuntimeConvergeError> {
    if plan.evpn_instances.has_changes() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports IP-VRF add only when L2VNI changes are absent",
        ));
    }
    if plan.ethernet_segments.has_changes() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports IP-VRF add only when Ethernet Segment changes are absent",
        ));
    }
    if !plan.ip_vrfs.deleted.is_empty() || !plan.ip_vrfs.redefined.is_empty() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports only add-only IP-VRF changes; delete/redefine is not supported yet",
        ));
    }
    if plan.ip_vrfs.added.len() != 1 {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports exactly one added IP-VRF per request",
        ));
    }
    Ok(plan.ip_vrfs.added[0].clone())
}

fn validate_single_ip_vrf_delete(
    current: &rustbgpd_evpn::EvpnRuntimeModel,
    candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
    plan: &rustbgpd_evpn::EvpnRuntimePlan,
) -> Result<String, DaemonEvpnRuntimeConvergeError> {
    if plan.evpn_instances.has_changes() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports IP-VRF delete only when L2VNI changes are absent",
        ));
    }
    if plan.ethernet_segments.has_changes() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports IP-VRF delete only when Ethernet Segment changes are absent",
        ));
    }
    if !plan.ip_vrfs.added.is_empty() || !plan.ip_vrfs.redefined.is_empty() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports only delete-only IP-VRF changes; add/redefine is not supported in the same request",
        ));
    }
    if plan.ip_vrfs.deleted.len() != 1 {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports exactly one deleted IP-VRF per request",
        ));
    }

    let deleted_name = plan.ip_vrfs.deleted[0].clone();
    if current.ip_vrfs().get(&deleted_name).is_none() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
            "planned IP-VRF {deleted_name:?} is not committed"
        )));
    }
    if candidate.ip_vrfs().get(&deleted_name).is_some() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
            "candidate still contains planned deleted IP-VRF {deleted_name:?}"
        )));
    }
    if current.ip_vrfs().is_referenced(&deleted_name) {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
            "IP-VRF {deleted_name:?} is referenced by an L2VNI; linked IP-VRF delete is not supported yet"
        )));
    }

    Ok(deleted_name)
}

fn validate_single_ethernet_segment_add(
    current: &rustbgpd_evpn::EvpnRuntimeModel,
    candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
    plan: &rustbgpd_evpn::EvpnRuntimePlan,
) -> Result<rustbgpd_wire::EthernetSegmentIdentifier, DaemonEvpnRuntimeConvergeError> {
    if plan.evpn_instances.has_changes() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports Ethernet Segment add only when L2VNI changes are absent",
        ));
    }
    if plan.ip_vrfs.has_changes() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports Ethernet Segment add only when IP-VRF changes are absent",
        ));
    }
    if !plan.ethernet_segments.deleted.is_empty() || !plan.ethernet_segments.redefined.is_empty() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports only add-only Ethernet Segment changes; delete/redefine is not supported yet",
        ));
    }
    if plan.ethernet_segments.added.len() != 1 {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports exactly one added Ethernet Segment per request",
        ));
    }

    let added_esi = plan.ethernet_segments.added[0];
    if current
        .ethernet_segments()
        .iter()
        .any(|seg| seg.esi == added_esi)
    {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
            "planned Ethernet Segment {added_esi} is already committed"
        )));
    }
    let Some(seg) = candidate
        .ethernet_segments()
        .iter()
        .find(|seg| seg.esi == added_esi)
    else {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
            "candidate is missing planned Ethernet Segment {added_esi}"
        )));
    };

    validate_ethernet_segment_member_vnis_present(
        added_esi,
        &seg.member_vnis,
        candidate.instances(),
    )?;

    Ok(added_esi)
}

fn validate_single_ethernet_segment_delete(
    current: &rustbgpd_evpn::EvpnRuntimeModel,
    candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
    plan: &rustbgpd_evpn::EvpnRuntimePlan,
) -> Result<rustbgpd_wire::EthernetSegmentIdentifier, DaemonEvpnRuntimeConvergeError> {
    if plan.evpn_instances.has_changes() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports Ethernet Segment delete only when L2VNI changes are absent",
        ));
    }
    if plan.ip_vrfs.has_changes() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports Ethernet Segment delete only when IP-VRF changes are absent",
        ));
    }
    if !plan.ethernet_segments.added.is_empty() || !plan.ethernet_segments.redefined.is_empty() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports only delete-only Ethernet Segment changes; add/redefine is not supported in the same request",
        ));
    }
    if plan.ethernet_segments.deleted.len() != 1 {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports exactly one deleted Ethernet Segment per request",
        ));
    }

    let deleted_esi = plan.ethernet_segments.deleted[0];
    if !current
        .ethernet_segments()
        .iter()
        .any(|seg| seg.esi == deleted_esi)
    {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
            "planned Ethernet Segment {deleted_esi} is not committed"
        )));
    }
    if candidate
        .ethernet_segments()
        .iter()
        .any(|seg| seg.esi == deleted_esi)
    {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
            "candidate still contains planned deleted Ethernet Segment {deleted_esi}"
        )));
    }

    Ok(deleted_esi)
}

fn validate_single_ethernet_segment_redefine(
    current: &rustbgpd_evpn::EvpnRuntimeModel,
    candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
    plan: &rustbgpd_evpn::EvpnRuntimePlan,
) -> Result<rustbgpd_wire::EthernetSegmentIdentifier, DaemonEvpnRuntimeConvergeError> {
    if plan.evpn_instances.has_changes() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports Ethernet Segment redefine only when L2VNI changes are absent",
        ));
    }
    if plan.ip_vrfs.has_changes() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports Ethernet Segment redefine only when IP-VRF changes are absent",
        ));
    }
    if !plan.ethernet_segments.added.is_empty() || !plan.ethernet_segments.deleted.is_empty() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports only redefine-only Ethernet Segment changes; add/delete is not supported in the same request",
        ));
    }
    if plan.ethernet_segments.redefined.len() != 1 {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports exactly one redefined Ethernet Segment per request",
        ));
    }

    let redefined_esi = plan.ethernet_segments.redefined[0];
    if !current
        .ethernet_segments()
        .iter()
        .any(|seg| seg.esi == redefined_esi)
    {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
            "planned Ethernet Segment {redefined_esi} is not committed"
        )));
    }
    let Some(seg) = candidate
        .ethernet_segments()
        .iter()
        .find(|seg| seg.esi == redefined_esi)
    else {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
            "candidate is missing planned Ethernet Segment {redefined_esi}"
        )));
    };

    validate_ethernet_segment_member_vnis_present(
        redefined_esi,
        &seg.member_vnis,
        candidate.instances(),
    )?;

    Ok(redefined_esi)
}

fn validate_ethernet_segment_member_vnis_present(
    esi: rustbgpd_wire::EthernetSegmentIdentifier,
    member_vnis: &std::collections::BTreeSet<rustbgpd_evpn::EvpnInstanceId>,
    instances: &rustbgpd_evpn::EvpnInstanceTable,
) -> Result<(), DaemonEvpnRuntimeConvergeError> {
    if member_vnis.is_empty() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
            "Ethernet Segment {esi} has no member VNIs"
        )));
    }
    for vni in member_vnis {
        if instances.get(*vni).is_none() {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "Ethernet Segment {esi} references unknown member VNI {}",
                vni.as_u32()
            )));
        }
    }
    Ok(())
}

fn evpn_runtime_candidate_from_toml(
    candidate_toml: &str,
) -> Result<rustbgpd_evpn::EvpnRuntimeCandidate, GrpcEvpnRuntimeApplyError> {
    if candidate_toml.trim().is_empty() {
        return Err(GrpcEvpnRuntimeApplyError::InvalidArgument(
            "candidate_toml must contain a full rustbgpd config".to_string(),
        ));
    }
    let candidate =
        Config::load_toml_with_diagnostics(candidate_toml, "candidate EVPN runtime config")
            .map_err(GrpcEvpnRuntimeApplyError::InvalidArgument)?;
    let instances = candidate
        .resolve_evpn_instances()
        .map_err(|err| GrpcEvpnRuntimeApplyError::InvalidArgument(err.to_string()))?;
    let ip_vrfs = candidate
        .resolve_evpn_ip_vrfs()
        .map_err(|err| GrpcEvpnRuntimeApplyError::InvalidArgument(err.to_string()))?;
    let ethernet_segments = candidate
        .resolve_ethernet_segments()
        .map_err(|err| GrpcEvpnRuntimeApplyError::InvalidArgument(err.to_string()))?;
    Ok(rustbgpd_evpn::EvpnRuntimeCandidate::new(
        instances,
        ip_vrfs,
        ethernet_segments,
    ))
}

async fn apply_evpn_runtime_request<C>(
    request: &proto::ApplyEvpnRuntimeRequest,
    coordinator: &Mutex<rustbgpd_evpn::EvpnRuntimeCoordinator>,
    apply_lock: &tokio::sync::Mutex<()>,
    converger: &C,
) -> Result<proto::ApplyEvpnRuntimeResponse, GrpcEvpnRuntimeApplyError>
where
    C: DaemonEvpnRuntimeConverger + ?Sized,
{
    let candidate = evpn_runtime_candidate_from_toml(&request.candidate_toml)?;
    let _apply_guard = apply_lock.lock().await;

    let (current, plan, snapshot) = {
        let coordinator = coordinator.lock().map_err(|_| {
            GrpcEvpnRuntimeApplyError::Internal(
                "EVPN runtime coordinator lock poisoned".to_string(),
            )
        })?;
        // Planning is pure: it previews the next generation without
        // mutating the committed model or the coordinator's
        // lifecycle/mutation state.
        let current = coordinator.model().clone();
        let plan = coordinator.plan_candidate(&candidate);
        let snapshot = coordinator.snapshot();
        (current, plan, snapshot)
    };

    if request.validate_only {
        return Ok(proto::ApplyEvpnRuntimeResponse {
            outcome: proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyValidated as i32,
            runtime: Some(runtime_snapshot_to_proto(&snapshot)),
            plan: Some(runtime_plan_to_proto(&plan)),
            message: "candidate EVPN runtime model validated; generation not advanced".to_string(),
        });
    }

    if plan.is_noop() {
        return Ok(proto::ApplyEvpnRuntimeResponse {
            outcome: runtime_apply_outcome_to_proto(rustbgpd_evpn::EvpnRuntimeApplyOutcome::Noop),
            runtime: Some(runtime_snapshot_to_proto(&snapshot)),
            plan: Some(runtime_plan_to_proto(&plan)),
            message:
                "candidate EVPN runtime model matches the committed generation; no changes applied"
                    .to_string(),
        });
    }

    if let Err(error) = converger.converge(&current, &candidate, &plan).await {
        if let DaemonEvpnRuntimeConvergeError::Failed(source) = error.clone() {
            let mut coordinator = coordinator.lock().map_err(|_| {
                GrpcEvpnRuntimeApplyError::Internal(
                    "EVPN runtime coordinator lock poisoned".to_string(),
                )
            })?;
            let mut failed = FailedRuntimeConverger { source };
            let _ = coordinator.apply_candidate(candidate, &mut failed);
        }
        return Err(GrpcEvpnRuntimeApplyError::FailedPrecondition(format!(
            "EVPN runtime mutation failed: {}; generation {} remains committed",
            error.message(),
            snapshot.generation.as_u64()
        )));
    }

    let mut coordinator = coordinator.lock().map_err(|_| {
        GrpcEvpnRuntimeApplyError::Internal("EVPN runtime coordinator lock poisoned".to_string())
    })?;
    let mut preconverged = PreconvergedRuntimeConverger;
    let report = coordinator
        .apply_candidate(candidate, &mut preconverged)
        .map_err(|err| GrpcEvpnRuntimeApplyError::FailedPrecondition(err.to_string()))?;
    let snapshot = coordinator.snapshot();
    Ok(proto::ApplyEvpnRuntimeResponse {
        outcome: runtime_apply_outcome_to_proto(report.outcome),
        runtime: Some(runtime_snapshot_to_proto(&snapshot)),
        plan: Some(runtime_plan_to_proto(&report.plan)),
        message: format!(
            "candidate EVPN runtime model committed as generation {}",
            report.committed_generation.as_u64()
        ),
    })
}

fn fib_runtime_event_to_bgp_event(
    event: fib_runtime::FibRuntimeEvent,
) -> rustbgpd_api::proto::BgpEvent {
    let (event_type, action, severity) = match event.kind {
        fib_runtime::FibRuntimeEventKind::Installed => (
            rustbgpd_api::proto::BgpEventType::DataplaneRouteInstalled,
            "installed",
            rustbgpd_api::proto::EventSeverity::Info,
        ),
        fib_runtime::FibRuntimeEventKind::Withdrawn => (
            rustbgpd_api::proto::BgpEventType::DataplaneRouteWithdrawn,
            "withdrawn",
            rustbgpd_api::proto::EventSeverity::Info,
        ),
        fib_runtime::FibRuntimeEventKind::Failed => (
            rustbgpd_api::proto::BgpEventType::DataplaneRouteFailed,
            "failed",
            rustbgpd_api::proto::EventSeverity::Warning,
        ),
    };
    let prefix = event.prefix.addr_string();
    let prefix_length = u32::from(event.prefix.prefix_len());
    let next_hop = event.next_hop.map_or_else(String::new, |ip| ip.to_string());
    let peer_address = event.peer.map_or_else(String::new, |ip| ip.to_string());
    let afi_safi = match event.prefix {
        rustbgpd_wire::Prefix::V4(_) => rustbgpd_api::proto::AddressFamily::Ipv4Unicast,
        rustbgpd_wire::Prefix::V6(_) => rustbgpd_api::proto::AddressFamily::Ipv6Unicast,
    } as i32;
    let route = rustbgpd_api::proto::DataplaneRouteEvent {
        source: "fib".to_string(),
        action: action.to_string(),
        table_name: event.table_name.clone(),
        table_id: event.table_id,
        metric: event.metric,
        prefix: prefix.clone(),
        prefix_length,
        next_hop,
        peer_address: peer_address.clone(),
        timestamp: event.timestamp.clone(),
        reason: event.reason.clone(),
    };

    rustbgpd_api::proto::BgpEvent {
        timestamp: event.timestamp,
        category: rustbgpd_api::proto::EventCategory::Dataplane as i32,
        event_type: event_type as i32,
        severity: severity as i32,
        peer_address,
        previous_peer_address: String::new(),
        prefix: prefix.clone(),
        prefix_length,
        afi_safi,
        summary: format!(
            "dataplane fib route {action} {prefix}/{prefix_length}: {}",
            event.reason
        ),
        target_peer_address: String::new(),
        payload: Some(rustbgpd_api::proto::bgp_event::Payload::DataplaneRoute(
            route,
        )),
    }
}

fn spawn_fib_dataplane_event_bridge(
    mut fib_events: broadcast::Receiver<fib_runtime::FibRuntimeEvent>,
    bgp_events: broadcast::Sender<rustbgpd_api::proto::BgpEvent>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match fib_events.recv().await {
                Ok(event) => {
                    let _ = bgp_events.send(fib_runtime_event_to_bgp_event(event));
                }
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    warn!(
                        missed,
                        "FIB dataplane event bridge lagged; dropping stale route events"
                    );
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    })
}

const fn grpc_enforcement_to_auth_enforcement(
    value: GrpcEnforcementConfig,
) -> rustbgpd_api::authz::AuthEnforcement {
    match value {
        GrpcEnforcementConfig::Legacy => rustbgpd_api::authz::AuthEnforcement::Legacy,
        GrpcEnforcementConfig::Tier => rustbgpd_api::authz::AuthEnforcement::Tier,
    }
}

const fn grpc_role_to_principal_role(value: GrpcRoleConfig) -> rustbgpd_api::authz::PrincipalRole {
    match value {
        GrpcRoleConfig::Observer => rustbgpd_api::authz::PrincipalRole::Observer,
        GrpcRoleConfig::Automation => rustbgpd_api::authz::PrincipalRole::Automation,
        GrpcRoleConfig::Operator => rustbgpd_api::authz::PrincipalRole::Operator,
    }
}

fn grpc_principal_roles(config: &Config) -> BTreeMap<String, rustbgpd_api::authz::PrincipalRole> {
    config
        .security
        .grpc
        .roles
        .iter()
        .map(|(principal, role)| (principal.clone(), grpc_role_to_principal_role(*role)))
        .collect()
}

fn max_gr_restart_time_secs(config: &Config) -> Option<u64> {
    config
        .neighbors
        .iter()
        .filter(|neighbor| neighbor.graceful_restart.unwrap_or(true))
        .map(|neighbor| u64::from(neighbor.gr_restart_time.unwrap_or(120)))
        .max()
}

fn marker_expires_at(marker: &GrRestartMarker) -> Result<SystemTime, String> {
    if marker.version != GR_RESTART_MARKER_VERSION {
        return Err(format!(
            "unsupported marker version {} (expected {})",
            marker.version, GR_RESTART_MARKER_VERSION
        ));
    }
    UNIX_EPOCH
        .checked_add(Duration::from_secs(marker.expires_at_unix))
        .ok_or_else(|| "marker expiry overflows system clock".to_string())
}

fn read_gr_restart_marker(path: &Path) -> Result<Option<SystemTime>, String> {
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let marker: GrRestartMarker = toml::from_str(&content).map_err(|e| e.to_string())?;
    marker_expires_at(&marker).map(Some)
}

fn write_gr_restart_marker(path: &Path, expires_at: SystemTime) -> std::io::Result<()> {
    let expires_at_unix = expires_at
        .duration_since(UNIX_EPOCH)
        .map_err(|e| std::io::Error::other(e.to_string()))?
        .as_secs();
    let marker = GrRestartMarker {
        version: GR_RESTART_MARKER_VERSION,
        expires_at_unix,
    };
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "restart marker path has no parent directory",
        )
    })?;
    std::fs::create_dir_all(parent)?;
    let encoded = toml::to_string(&marker).map_err(|e| std::io::Error::other(e.to_string()))?;
    std::fs::write(path, encoded)
}

fn load_grpc_token(path: &Path) -> Result<String, String> {
    let token = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read gRPC token file {}: {e}", path.display()))?;
    let token = token.trim_end().to_string();
    if token.is_empty() {
        return Err(format!(
            "gRPC token file {} must contain a non-empty token",
            path.display()
        ));
    }
    Ok(token)
}

fn load_grpc_pem(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    let bytes = std::fs::read(path)
        .map_err(|e| format!("failed to read gRPC {label} file {}: {e}", path.display()))?;
    if bytes.is_empty() {
        return Err(format!("gRPC {label} file {} is empty", path.display()));
    }
    Ok(bytes)
}

fn resolve_grpc_listeners(config: &Config) -> Result<Vec<GrpcListenerConfig>, String> {
    let enforcement = grpc_enforcement_to_auth_enforcement(config.security.grpc.enforcement);
    let roles = Arc::new(grpc_principal_roles(config));
    config
        .grpc_listeners()
        .into_iter()
        .map(|listener| match listener {
            GrpcListener::Tcp {
                addr,
                access_mode,
                max_tier,
                token_file,
                principal,
                tls,
            } => {
                let tls_params = tls
                    .map(|paths| {
                        Ok::<_, String>(rustbgpd_api::server::TlsParams {
                            cert_pem: load_grpc_pem(&paths.cert_file, "tls_cert_file")?,
                            key_pem: load_grpc_pem(&paths.key_file, "tls_key_file")?,
                            client_ca_pem: load_grpc_pem(
                                &paths.client_ca_file,
                                "tls_client_ca_file",
                            )?,
                        })
                    })
                    .transpose()?;
                Ok(GrpcListenerConfig {
                    endpoint: ListenerEndpoint::Tcp(addr),
                    access_mode: access_mode.into(),
                    max_tier: grpc_max_tier_to_auth_tier(max_tier),
                    enforcement,
                    roles: Arc::clone(&roles),
                    auth_token: token_file.as_deref().map(load_grpc_token).transpose()?,
                    principal,
                    tls: tls_params,
                })
            }
            GrpcListener::Uds {
                path,
                mode,
                access_mode,
                max_tier,
                token_file,
                principal,
            } => Ok(GrpcListenerConfig {
                endpoint: ListenerEndpoint::Uds { path, mode },
                access_mode: access_mode.into(),
                max_tier: grpc_max_tier_to_auth_tier(max_tier),
                enforcement,
                roles: Arc::clone(&roles),
                auth_token: token_file.as_deref().map(load_grpc_token).transpose()?,
                principal,
                tls: None,
            }),
        })
        .collect()
}

fn remove_gr_restart_marker(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn tcp_ao_listener_key_for_neighbor(
    listen_addr: SocketAddr,
    neighbor: &config::ResolvedNeighbor,
) -> Option<TcpAoListenerKey> {
    let tcp_ao = neighbor.transport_config.tcp_ao.as_ref()?;
    let peer = neighbor.transport_config.remote_addr.ip();
    if listen_addr.is_ipv4() != peer.is_ipv4() {
        return None;
    }
    Some(TcpAoListenerKey {
        peer,
        config: tcp_ao.clone(),
    })
}

fn print_config_diff(diff: &config::ConfigDiff) {
    use owo_colors::OwoColorize;

    let reload_header = "Reload-applied changes:".green().to_string();
    let restart_header = "Restart-required changes:".yellow().to_string();
    let add_marker = "+".green().to_string();
    let remove_marker = "-".red().to_string();
    let change_marker = "~".yellow().to_string();
    let restart_marker = "!".yellow().to_string();
    let inline_policy_hint =
        "(migrate inline policy to named definitions + import_chain/export_chain for hot reload)"
            .dimmed()
            .to_string();
    let style = config::ConfigDiffTextStyle {
        reload_header: reload_header.into(),
        restart_header: restart_header.into(),
        add_marker: add_marker.into(),
        remove_marker: remove_marker.into(),
        change_marker: change_marker.into(),
        restart_marker: restart_marker.into(),
        inline_policy_hint: inline_policy_hint.into(),
        no_changes: "No changes.".into(),
    };
    print!("{}", config::format_config_diff_with_style(diff, &style));
}

fn print_startup_banner(config: &Config, grpc_listeners: &[GrpcListenerConfig]) {
    let ebgp = config
        .neighbors
        .iter()
        .filter(|n| n.remote_asn != config.global.asn)
        .count();
    let ibgp = config.neighbors.len() - ebgp;
    let peer_groups = config.peer_groups.len();
    let policies = config.policy.definitions.len();
    let neighbor_sets = config.policy.neighbor_sets.len();

    eprintln!();
    eprintln!(
        "  rustbgpd {} | AS {} | router-id {}",
        env!("CARGO_PKG_VERSION"),
        config.global.asn,
        config.global.router_id,
    );

    // Peers
    let mut peer_parts = Vec::new();
    if ebgp > 0 {
        peer_parts.push(format!("{ebgp} eBGP"));
    }
    if ibgp > 0 {
        peer_parts.push(format!("{ibgp} iBGP"));
    }
    let peer_summary = if peer_parts.is_empty() {
        "0 peers (dynamic-only)".to_string()
    } else {
        format!(
            "{} peers ({})",
            config.neighbors.len(),
            peer_parts.join(", ")
        )
    };
    let pg_suffix = if peer_groups > 0 {
        format!(
            " in {peer_groups} peer group{}",
            if peer_groups == 1 { "" } else { "s" }
        )
    } else {
        String::new()
    };
    eprintln!("  |- {peer_summary}{pg_suffix}");

    // Policy
    if policies > 0 || neighbor_sets > 0 {
        let mut parts = Vec::new();
        if policies > 0 {
            parts.push(format!(
                "{policies} named polic{}",
                if policies == 1 { "y" } else { "ies" }
            ));
        }
        if neighbor_sets > 0 {
            parts.push(format!(
                "{neighbor_sets} neighbor set{}",
                if neighbor_sets == 1 { "" } else { "s" }
            ));
        }
        eprintln!("  |- {}", parts.join(", "));
    }

    // Listeners
    for listener in grpc_listeners {
        let label = match &listener.endpoint {
            ListenerEndpoint::Tcp(addr) => format!("grpc: tcp://{addr}"),
            ListenerEndpoint::Uds { path, .. } => format!("grpc: unix://{}", path.display()),
        };
        let auth = if listener.auth_token.is_some() {
            " (token auth)"
        } else {
            ""
        };
        let access = match listener.access_mode {
            GrpcServerAccessMode::ReadOnly => " (read-only)",
            GrpcServerAccessMode::ReadWrite => "",
        };
        eprintln!("  |- {label}{access}{auth}");
    }

    // Metrics
    if let Some(addr) = config.prometheus_addr() {
        eprintln!("  |- metrics: http://{addr}/metrics");
    }

    // Looking glass
    if let Some(addr) = config.looking_glass_addr() {
        eprintln!("  |- looking glass: http://{addr}/status");
    }

    // Optional subsystems
    if let Some(ref rpki) = config.rpki {
        let n = rpki.cache_servers.len();
        if n > 0 {
            eprintln!("  |- rpki: {n} cache{}", if n == 1 { "" } else { "s" });
        }
    }
    if let Some(ref bmp) = config.bmp {
        let n = bmp.collectors.len();
        if n > 0 {
            eprintln!("  |- bmp: {n} collector{}", if n == 1 { "" } else { "s" });
        }
    }
    if let Some(ref mrt) = config.mrt {
        eprintln!("  |- mrt: {}", mrt.output_dir);
    }

    eprintln!();
}

fn fatal_startup_error(message: &'static str, error: impl std::fmt::Display) -> ! {
    error!(error = %error, "{message}");
    process::exit(1);
}

#[expect(clippy::too_many_lines)]
fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Handle --version / -V before anything else.
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("rustbgpd {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    // Handle --help / -h.
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "rustbgpd {} — API-first BGP daemon\n\n\
             Usage: rustbgpd [OPTIONS] [CONFIG_PATH]\n\n\
             Arguments:\n  \
               CONFIG_PATH  Path to TOML config file [default: /etc/rustbgpd/config.toml]\n\n\
             Options:\n  \
               --check      Validate config and exit without starting the daemon\n  \
               --diff PATH  Compare config against PATH and show what SIGHUP would change\n  \
               --json       Output diff as JSON (only with --diff)\n  \
               --version    Print version and exit\n  \
               --help       Print this help message",
            env!("CARGO_PKG_VERSION")
        );
        return;
    }

    // Parse flags and config path from remaining args.
    let mut check_only = false;
    let mut diff_path: Option<String> = None;
    let mut json_output = false;
    let mut config_path = "/etc/rustbgpd/config.toml".to_string();
    let mut expect_diff_path = false;
    for arg in &args[1..] {
        if expect_diff_path {
            diff_path = Some(arg.clone());
            expect_diff_path = false;
        } else if arg == "--check" {
            check_only = true;
        } else if arg == "--diff" {
            expect_diff_path = true;
        } else if arg == "--json" {
            json_output = true;
        } else if !arg.starts_with('-') {
            config_path.clone_from(arg);
        } else {
            eprintln!("error: unknown option: {arg}");
            eprintln!("usage: rustbgpd [--check] [--diff PATH] [--json] [--version] [CONFIG_PATH]");
            process::exit(1);
        }
    }
    if expect_diff_path {
        eprintln!("error: --diff requires a path argument");
        process::exit(2);
    }
    if json_output && diff_path.is_none() {
        eprintln!("error: --json can only be used with --diff");
        process::exit(2);
    }

    let config = match Config::load_with_diagnostics(&config_path) {
        Ok(c) => c,
        Err(diagnostic) => {
            eprintln!("{diagnostic}");
            process::exit(1);
        }
    };

    if check_only {
        println!("config OK: {config_path}");
        return;
    }

    if let Some(ref diff_target) = diff_path {
        let new_config = match Config::load_with_diagnostics(diff_target) {
            Ok(c) => c,
            Err(diagnostic) => {
                eprintln!("{diagnostic}");
                process::exit(2);
            }
        };
        let diff = config::diff_config(&config, &new_config);
        if json_output {
            let output = config::config_diff_json_value(&diff);
            match serde_json::to_string_pretty(&output) {
                Ok(json) => println!("{json}"),
                Err(e) => {
                    eprintln!("error: failed to serialize diff: {e}");
                    process::exit(2);
                }
            }
        } else {
            print_config_diff(&diff);
        }
        process::exit(i32::from(diff.has_actionable_changes()));
    }

    let log_directives = config.per_peer_log_directives();
    if let Err(e) = init_logging(&log_directives) {
        eprintln!("error: failed to initialize logging: {e}");
        process::exit(1);
    }

    #[cfg(feature = "dhat-heap")]
    let profiler = Some(
        dhat::Profiler::builder()
            .file_name("dhat-heap.json")
            .build(),
    );
    #[cfg(not(feature = "dhat-heap"))]
    let profiler: Option<()> = None;

    let rt = tokio::runtime::Runtime::new()
        .unwrap_or_else(|e| fatal_startup_error("failed to create tokio runtime", e));
    rt.block_on(run(config, profiler));
}

#[expect(clippy::too_many_lines)]
async fn run<T>(mut config: Config, profiler: Option<T>) {
    // Snapshot the gRPC listener config as it was at process start.
    // The live TCP/UDS listeners bind once and are not rebuilt on
    // SIGHUP; this snapshot is what they're actually serving. Reload
    // compares the new declared config against THIS snapshot (not
    // against the in-memory mutable `config`) so drift between
    // declared listener config and live state stays visible across
    // every reload, not just the first one. The runtime config is
    // patched on reload to keep these two listener fields equal to
    // the live state — no other reload semantics change.
    let live_grpc_tcp = config.global.telemetry.grpc_tcp.clone();
    let live_grpc_uds = config.global.telemetry.grpc_uds.clone();

    let start_time = tokio::time::Instant::now();
    let gr_restart_marker_path = config.gr_restart_marker_path();
    let local_gr_restart_until = match read_gr_restart_marker(&gr_restart_marker_path) {
        Ok(Some(expires_at)) => {
            if let Ok(remaining) = expires_at.duration_since(SystemTime::now()) {
                let deadline = StdInstant::now() + remaining;
                info!(
                    marker = %gr_restart_marker_path.display(),
                    restart_time_secs = remaining.as_secs(),
                    "detected GR restart marker — static peers will advertise R=1 until the restart window expires"
                );
                Some(deadline)
            } else {
                info!(
                    marker = %gr_restart_marker_path.display(),
                    "ignoring expired GR restart marker"
                );
                if let Err(e) = remove_gr_restart_marker(&gr_restart_marker_path) {
                    warn!(
                        marker = %gr_restart_marker_path.display(),
                        error = %e,
                        "failed to remove expired GR restart marker"
                    );
                }
                None
            }
        }
        Ok(None) => None,
        Err(e) => {
            warn!(
                marker = %gr_restart_marker_path.display(),
                error = %e,
                "ignoring invalid GR restart marker — starting without restarting-speaker mode"
            );
            if let Err(remove_err) = remove_gr_restart_marker(&gr_restart_marker_path) {
                warn!(
                    marker = %gr_restart_marker_path.display(),
                    error = %remove_err,
                    "failed to remove malformed GR restart marker"
                );
            }
            None
        }
    };

    if let Some(deadline) = local_gr_restart_until {
        let marker_path = gr_restart_marker_path.clone();
        let sleep_for = deadline.saturating_duration_since(StdInstant::now());
        tokio::spawn(async move {
            tokio::time::sleep(sleep_for).await;
            if let Err(e) = remove_gr_restart_marker(&marker_path) {
                warn!(
                    marker = %marker_path.display(),
                    error = %e,
                    "failed to remove expired GR restart marker"
                );
            }
        });
    }

    info!(
        version = env!("CARGO_PKG_VERSION"),
        asn = config.global.asn,
        router_id = %config.global.router_id,
        neighbors = config.neighbors.len(),
        "starting rustbgpd"
    );

    let metrics = BgpMetrics::new();
    let grpc_listeners = resolve_grpc_listeners(&config).unwrap_or_else(|e| {
        error!(error = %e, "invalid gRPC listener configuration");
        process::exit(1);
    });

    // Startup banner — human-friendly topology summary on stderr.
    print_startup_banner(&config, &grpc_listeners);
    let router_id: Ipv4Addr = config.global.router_id.parse().unwrap_or_else(|e| {
        error!(
            router_id = %config.global.router_id,
            error = %e,
            "invalid router-id after configuration validation"
        );
        process::exit(1);
    });

    // Spawn metrics HTTP server (if configured)
    if let Some(prometheus_addr) = config.prometheus_addr() {
        let metrics_clone = metrics.clone();
        tokio::spawn(async move {
            metrics_server::serve_metrics(prometheus_addr, metrics_clone).await;
        });
    }

    // Build global export policy chain for RIB manager fallback
    let export_policy = config.export_chain().unwrap_or_else(|e| {
        error!("invalid global export policy: {e}");
        process::exit(1);
    });

    // Spawn RIB manager
    let cluster_id = config.cluster_id();
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(4096);
    let (rib_query_tx, rib_query_rx) = mpsc::channel::<RibUpdate>(256);
    tokio::spawn(
        RibManager::new(
            rib_rx,
            rib_query_rx,
            export_policy,
            cluster_id,
            metrics.clone(),
        )
        .run(),
    );

    // Validation snapshot channel: broadcast VRP + ASPA tables to transport
    // sessions for import-time route validation.  Starts empty — sessions fall
    // back to NotFound/Unknown until the first cache update arrives.
    let (validation_watch_tx, validation_watch_rx) =
        tokio::sync::watch::channel(rustbgpd_rpki::ValidationSnapshot::default());

    // Spawn RPKI subsystem (VRP manager + per-cache RTR clients)
    if let Some(ref rpki_config) = config.rpki
        && !rpki_config.cache_servers.is_empty()
    {
        let (vrp_update_tx, vrp_update_rx) = mpsc::channel(256);
        let (rpki_table_tx, mut rpki_table_rx) = mpsc::channel(16);

        // ASPA table channel (VrpManager → RIB)
        let (aspa_table_tx, mut aspa_table_rx) = mpsc::channel(16);

        // Spawn VRP + ASPA manager
        let vrp_mgr = rustbgpd_rpki::VrpManager::new(vrp_update_rx, rpki_table_tx)
            .with_aspa_tx(aspa_table_tx);
        tokio::spawn(vrp_mgr.run());

        // Forward VRP table updates to RIB manager + validation watch
        let rpki_rib_tx = rib_tx.clone();
        let validation_tx_vrp = validation_watch_tx.clone();
        tokio::spawn(async move {
            while let Some(update) = rpki_table_rx.recv().await {
                validation_tx_vrp.send_modify(|snapshot| {
                    snapshot.vrp_table = Some(std::sync::Arc::clone(&update.table));
                });
                let _ = rpki_rib_tx
                    .send(RibUpdate::RpkiCacheUpdate {
                        table: update.table,
                    })
                    .await;
            }
        });

        // Forward ASPA table updates to RIB manager + validation watch
        let aspa_rib_tx = rib_tx.clone();
        let validation_tx_aspa = validation_watch_tx.clone();
        tokio::spawn(async move {
            while let Some(update) = aspa_table_rx.recv().await {
                validation_tx_aspa.send_modify(|snapshot| {
                    snapshot.aspa_table = Some(std::sync::Arc::clone(&update.table));
                });
                let _ = aspa_rib_tx
                    .send(RibUpdate::AspaTableUpdate {
                        table: update.table,
                    })
                    .await;
            }
        });

        // Spawn one RTR client per configured cache server
        for server in &rpki_config.cache_servers {
            let addr: std::net::SocketAddr = match server.address.parse() {
                Ok(a) => a,
                Err(e) => {
                    error!(
                        address = %server.address,
                        error = %e,
                        "invalid RPKI cache server address — skipping"
                    );
                    continue;
                }
            };
            let client_config = rustbgpd_rpki::RtrClientConfig {
                server_addr: addr,
                refresh_interval: server.refresh_interval,
                retry_interval: server.retry_interval,
                expire_interval: server.expire_interval,
            };
            let client = rustbgpd_rpki::RtrClient::new(client_config, vrp_update_tx.clone());
            info!(server = %addr, "spawning RTR client for RPKI cache");
            tokio::spawn(client.run());
        }
    }

    // Spawn BMP subsystem (manager + per-collector clients)
    let mut bmp_runtime: Option<BmpRuntime> = None;
    let bmp_tx = if let Some(ref bmp_config) = config.bmp
        && !bmp_config.collectors.is_empty()
    {
        let (bmp_event_tx, bmp_event_rx) = mpsc::channel(4096);
        let (bmp_control_tx, bmp_control_rx) = mpsc::channel(256);
        let sys_name = bmp_config.sys_name.clone();
        let sys_descr = if bmp_config.sys_descr.is_empty() {
            format!("rustbgpd {}", env!("CARGO_PKG_VERSION"))
        } else {
            bmp_config.sys_descr.clone()
        };

        let mut collectors: Vec<(std::net::SocketAddr, mpsc::Sender<bytes::Bytes>)> = Vec::new();
        let mut client_handles = Vec::new();
        for collector in &bmp_config.collectors {
            let addr: std::net::SocketAddr = match collector.address.parse() {
                Ok(a) => a,
                Err(e) => {
                    error!(
                        address = %collector.address,
                        error = %e,
                        "invalid BMP collector address — skipping"
                    );
                    continue;
                }
            };
            let (msg_tx, msg_rx) = mpsc::channel(4096);
            let collector_id = collectors.len();
            collectors.push((addr, msg_tx));
            let client = rustbgpd_bmp::BmpClient::new(
                rustbgpd_bmp::BmpClientConfig {
                    collector_id,
                    collector_addr: addr,
                    reconnect_interval: collector.reconnect_interval,
                },
                msg_rx,
                sys_name.clone(),
                sys_descr.clone(),
                Some(bmp_control_tx.clone()),
                metrics.clone(),
            );
            info!(collector = %addr, "spawning BMP client");
            client_handles.push(tokio::spawn(client.run()));
        }

        let mgr = rustbgpd_bmp::BmpManager::new(
            bmp_event_rx,
            bmp_control_rx,
            collectors,
            metrics.clone(),
        );
        let manager_handle = tokio::spawn(mgr.run());
        bmp_runtime = Some(BmpRuntime {
            control_tx: bmp_control_tx,
            manager_handle,
            client_handles,
        });

        Some(bmp_event_tx)
    } else {
        None
    };

    // Spawn MRT manager (periodic TABLE_DUMP_V2 snapshots)
    let mrt_trigger_tx: Option<mpsc::Sender<oneshot::Sender<Result<std::path::PathBuf, String>>>> =
        if let Some(ref mrt_config) = config.mrt {
            let writer_config = rustbgpd_mrt::MrtWriterConfig {
                output_dir: std::path::PathBuf::from(&mrt_config.output_dir),
                dump_interval: mrt_config.dump_interval,
                compress: mrt_config.compress,
                file_prefix: mrt_config.file_prefix.clone(),
            };
            let (trigger_tx, trigger_rx) = mpsc::channel(16);
            let mgr =
                rustbgpd_mrt::MrtManager::new(writer_config, rib_tx.clone(), trigger_rx, router_id);
            info!(
                output_dir = %mrt_config.output_dir,
                interval = mrt_config.dump_interval,
                "spawning MRT dump manager"
            );
            tokio::spawn(mgr.run());
            Some(trigger_tx)
        } else {
            None
        };

    // Spawn PeerManager (keep JoinHandle for coordinated shutdown)
    let (peer_mgr_tx, peer_mgr_rx) = mpsc::channel::<PeerManagerCommand>(64);
    let (peer_mgr_internal_tx, peer_mgr_internal_rx) = mpsc::unbounded_channel();
    let peer_mgr = PeerManager::new_with_config(
        peer_mgr_rx,
        peer_mgr_internal_rx,
        config.global.asn,
        router_id,
        cluster_id,
        local_gr_restart_until,
        metrics.clone(),
        rib_tx.clone(),
        bmp_tx,
        Some(validation_watch_rx),
        config.clone(),
    );
    let peer_mgr_handle = tokio::spawn(peer_mgr.run());

    // Spawn config persister (converts gRPC config events → disk writes).
    //
    // Two inputs feed the persister:
    //   * `event_tx` — gRPC layer pushes per-mutation `ConfigEvent`s;
    //     the bridge applies each onto its locally held snapshot and
    //     then forwards a full `ReplaceConfig` to the persister.
    //   * `bridge_replace_tx` — the SIGHUP path pushes the desired
    //     reloaded TOML snapshot. The bridge swaps it into its
    //     locally held snapshot and refreshes the persister base
    //     without writing it back to disk. Runtime may stay pinned for
    //     restart-required fields; disk must preserve the operator's
    //     edit-then-restart intent.
    //
    // The replace path MUST go through the bridge (not directly to
    // the persister) so the bridge's snapshot stays consistent with
    // what's on disk. Otherwise the next gRPC mutation would apply
    // to a stale pre-reload snapshot and overwrite the persisted
    // file with `stale_pre_reload + one_mutation`.
    let (config_event_tx, bridge_replace_tx) = if let Some(ref path) = config.file_path {
        let (event_tx, event_rx) = mpsc::channel::<rustbgpd_api::peer_types::ConfigEvent>(64);
        let (mutation_tx, mutation_rx) = mpsc::channel::<ConfigMutation>(64);
        let (bridge_replace_tx, bridge_replace_rx) = mpsc::unbounded_channel::<Box<Config>>();
        let persister = ConfigPersister::new(mutation_rx, path.clone(), config.clone());
        tokio::spawn(persister.run());
        tokio::spawn(run_config_bridge(
            event_rx,
            bridge_replace_rx,
            mutation_tx,
            config.clone(),
        ));
        (Some(event_tx), Some(bridge_replace_tx))
    } else {
        (None, None)
    };

    // Shutdown channels:
    // - grpc_shutdown: signals all tonic listeners to stop
    // - rpc_shutdown: given to ControlService so Shutdown RPC can trigger exit
    let (grpc_shutdown_tx, grpc_shutdown_rx) = oneshot::channel::<()>();
    let (rpc_shutdown_tx, mut rpc_shutdown_rx) = watch::channel(false);

    for listener in &grpc_listeners {
        match &listener.endpoint {
            ListenerEndpoint::Tcp(addr) => {
                info!(
                    %addr,
                    auth_enabled = listener.auth_token.is_some(),
                    "configured gRPC TCP listener"
                );
                if !addr.ip().is_loopback() && listener.auth_token.is_none() {
                    warn!(
                        %addr,
                        "gRPC TCP listener bound to a non-loopback address without authentication; prefer UDS for local administration or a proxy with mTLS for remote access"
                    );
                } else if !addr.ip().is_loopback() {
                    warn!(
                        %addr,
                        "gRPC TCP listener bound to a non-loopback address with bearer authentication but no transport encryption; prefer a proxy with mTLS for remote access"
                    );
                }
            }
            ListenerEndpoint::Uds { path, mode } => {
                info!(
                    path = %path.display(),
                    mode = format_args!("{mode:o}"),
                    auth_enabled = listener.auth_token.is_some(),
                    "configured gRPC UDS listener"
                );
            }
        }
    }

    // Spawn birdwatcher-compatible looking glass HTTP server (if configured)
    if let Some(lg_addr) = config.looking_glass_addr() {
        let lg_state = std::sync::Arc::new(looking_glass::LookingGlassState::new(
            rib_query_tx.clone(),
            peer_mgr_tx.clone(),
            config.global.asn,
            config.global.router_id.clone(),
        ));
        tokio::spawn(looking_glass::serve(lg_addr, lg_state));
    }

    // Resolve declared EVPN instances once at startup and hand the
    // gRPC layer a shared `Arc`. The validation pass at config load
    // already proved this resolution succeeds, so a second failure
    // here would be a programming error rather than operator input,
    // but we still surface it as a daemon-fatal diagnostic to avoid
    // silently dropping instances if a future code path skips validation.
    let evpn_instances = std::sync::Arc::new(config.resolve_evpn_instances().unwrap_or_else(|e| {
        fatal_startup_error(
            "EVPN instances failed to re-resolve after configuration validation",
            e,
        );
    }));

    // Gate 9 IP-VRFs (`[[evpn_ip_vrfs]]`). Same fatal-after-validate
    // pattern as `evpn_instances`. Empty for any deployment without
    // Gate 9 config; the dataplane short-circuits `probe_ip_vrfs` when
    // empty so L2-only and RR-only deployments incur zero added cost.
    let evpn_ip_vrfs = std::sync::Arc::new(config.resolve_evpn_ip_vrfs().unwrap_or_else(|e| {
        fatal_startup_error(
            "EVPN IP-VRFs failed to re-resolve after configuration validation",
            e,
        );
    }));

    let (evpn_duplicate_mac_quarantine_tx, evpn_duplicate_mac_quarantine_rx) =
        tokio::sync::watch::channel(std::sync::Arc::new(std::collections::BTreeSet::<
            rustbgpd_evpn::DuplicateMacKey,
        >::new()));

    // EVPN Linux dataplane reconciler (Gate 7b). Returns None when
    // [[evpn_instances]] is empty — RR-only deployments don't open a
    // netlink socket and don't spawn the actor. The handle is moved
    // into the coordinated shutdown block at the bottom of main where
    // we await its bounded drain.
    let evpn_dataplane_shutdown = tokio_util::sync::CancellationToken::new();
    let supervisor_config = {
        let mut cfg = evpn_dataplane::SupervisorConfig::default();
        cfg.actor_config.apply_bum_enforcement = config.apply_bum_enforcement;
        cfg
    };
    let mut evpn_dataplane_handle = evpn_dataplane::spawn_with_quarantine(
        supervisor_config,
        &evpn_instances,
        &evpn_ip_vrfs,
        rib_tx.clone(),
        metrics.clone(),
        evpn_dataplane_shutdown.clone(),
        evpn_duplicate_mac_quarantine_rx,
    )
    .await;
    let evpn_dataplane_runtime_control = evpn_dataplane_handle
        .as_ref()
        .map(evpn_dataplane::EvpnDataplaneHandle::runtime_control);

    // EVPN local-MAC originator (Gate 7b+1). Spawned alongside the
    // dataplane supervisor under the same `[[evpn_instances]]` gate.
    // Consumes the upward `LocalMacObservation` channel surfaced by
    // the dataplane (Phase D); kernel-learned MACs become BGP EVPN
    // Type 2 originations per RFC 7432 §15.1. RR-only deployments
    // skip this entirely — `evpn_dataplane::spawn` returned `None`
    // and `local_mac_rx` is therefore `None`.
    let evpn_originator_shutdown = tokio_util::sync::CancellationToken::new();
    let evpn_originated_local_mac_counts = evpn_originator::OriginatedLocalMacCounts::default();
    // Resolve `[[ethernet_segments]]` early so the originator can
    // attach the right ESI to Type 2 routes for MACs learned on
    // multi-homed VNIs (Gate 8b ESI-aware MAC origination). The
    // same resolved table is consumed by `evpn_segment::spawn`
    // below.
    let ethernet_segments = config.resolve_ethernet_segments().unwrap_or_else(|e| {
        fatal_startup_error(
            "Ethernet segments failed to re-resolve after configuration validation",
            e,
        );
    });
    let vni_to_esi = evpn_vni_to_esi_map(&ethernet_segments);
    // ADR-0063 EVPN runtime coordinator. The public API validates full
    // candidates through this handle and commits only after daemon
    // actor convergence accepts the planned mutation. SIGHUP remains
    // restart-required for EVPN edits.
    let evpn_runtime_coordinator =
        Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
            evpn_instances.clone(),
            evpn_ip_vrfs.clone(),
            ethernet_segments.clone(),
        )));
    let evpn_originator_handle = if let Some(handle) = evpn_dataplane_handle.as_mut() {
        evpn_originator::spawn_with_quarantine(
            evpn_originator::OriginatorConfig::default(),
            &evpn_instances,
            rib_tx.clone(),
            handle.local_mac_rx.take(),
            metrics.clone(),
            evpn_originated_local_mac_counts.clone(),
            evpn_originator_shutdown.clone(),
            vni_to_esi.clone(),
            evpn_duplicate_mac_quarantine_tx.clone(),
        )
    } else {
        None
    };
    let evpn_originator_runtime_control = evpn_originator_handle
        .as_ref()
        .map(evpn_originator::EvpnOriginatorHandle::runtime_control);

    // EVPN Type 3 IMET origination (Gate 7b+1 phase F). One Type 3
    // per L2VNI announcing this VTEP's BGP-level VNI membership; not
    // conditioned on kernel readiness. Originated at startup, with
    // controller-owned keys retained for shutdown-time withdraw.
    // RR-only paths (empty `evpn_instances`) skip origination entirely
    // — IMET requires a VTEP IP, which an RR doesn't have.
    let evpn_imet_controller =
        Arc::new(tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new()));
    if !evpn_instances.is_empty() {
        evpn_imet_controller
            .lock()
            .await
            .originate_all(evpn_instances.iter().cloned().collect::<Vec<_>>(), &rib_tx)
            .await;
    }

    // EVPN SVI-MAC origination (RFC 9135 §6.1) — gated on any
    // instance setting `advertise_svi_mac = true`. Subscribes to the
    // dataplane handle's report broadcast and originates a Type 2
    // for each Ready bridge's own MAC. `evpn_svi::spawn` returns
    // `None` when no instance opts in, so RR-only and SVI-MAC-off
    // deployments incur zero cost.
    let evpn_svi_shutdown = tokio_util::sync::CancellationToken::new();
    let evpn_svi_handle = if let Some(handle) = evpn_dataplane_handle.as_ref() {
        evpn_svi::spawn(
            &evpn_instances,
            rib_tx.clone(),
            handle.subscribe_reports(),
            metrics.clone(),
            evpn_originated_local_mac_counts.clone(),
            evpn_svi_shutdown.clone(),
        )
    } else {
        None
    };
    let evpn_svi_runtime_control = evpn_svi_handle
        .as_ref()
        .map(evpn_svi::EvpnSviHandle::runtime_control);

    // EVPN Ethernet Segment orchestrator (Gate 8 multihoming
    // foundation — observable DF election, no enforcement). Spawned
    // when `[[ethernet_segments]]` has at least one entry and at
    // least one configured `[[evpn_instances]]` exists for the
    // member-VNI table to resolve against. Returns `None` for
    // single-homed deployments and route reflectors.
    let evpn_segment_shutdown = tokio_util::sync::CancellationToken::new();
    // `ethernet_segments` was resolved upstream so the originator
    // could build its `vni_to_esi` lookup before we got here.
    let evpn_segment_handle = if ethernet_segments.is_empty() {
        None
    } else {
        let bum_enforcement_tx = evpn_dataplane_handle
            .as_ref()
            .map(evpn_dataplane::EvpnDataplaneHandle::bum_enforcement_sender);
        evpn_segment::spawn(
            &evpn_instances,
            ethernet_segments,
            rib_tx.clone(),
            bum_enforcement_tx,
            metrics.clone(),
            evpn_segment_shutdown.clone(),
        )
    };
    let evpn_segment_runtime_control = evpn_segment_handle
        .as_ref()
        .map(evpn_segment::EvpnSegmentHandle::runtime_control);

    // Latest snapshot of `DataplaneReport.ip_vrf_status` rows for the
    // gRPC `ListIpVrfs` / `GetIpVrf` surface (Gate 9 slice 5). Backed
    // by a `tokio::sync::watch` so gRPC handlers can read the latest
    // value lock-free (`.borrow().clone()`) without blocking a tokio
    // worker; the subscriber task replaces the value on every
    // dataplane report. RR-only deployments
    // (`evpn_dataplane_handle.is_none()`) leave the initial empty Vec
    // in place — `probe_ip_vrfs` would short-circuit to empty even if
    // the actor ran, so the gRPC surface stays consistent without any
    // wiring.
    let (evpn_ip_vrf_status_tx, evpn_ip_vrf_status_rx) =
        tokio::sync::watch::channel(Vec::<rustbgpd_evpn::IpVrfDataplaneStatus>::new());

    // Latest snapshot of `DataplaneReport.ip_vrf_routes.observations`
    // for the Gate 9 slice 6b L3 originator subscriber and for
    // Prometheus gauge updates. Stays empty on RR-only deployments and
    // when `[[evpn_ip_vrfs]]` is unset — `dump_ip_vrf_routes`
    // short-circuits in both cases.
    let (evpn_ip_vrf_routes_tx, evpn_ip_vrf_routes_rx) =
        tokio::sync::watch::channel(std::sync::Arc::new(std::collections::HashMap::<
            rustbgpd_evpn::IpVrfId,
            Vec<rustbgpd_evpn::LocalIpRouteObservation>,
        >::new()));

    // Latest per-VRF installed-route counts (Gate 9 slice 6c). The
    // reconcile actor's L3 install pipeline emits these on every
    // report; the daemon mirrors them onto a watch channel that the
    // gRPC `IpVrfState.installed_routes_count` field reads
    // lock-free.
    let (evpn_ip_vrf_installed_routes_tx, evpn_ip_vrf_installed_routes_rx) =
        tokio::sync::watch::channel(std::sync::Arc::new(std::collections::HashMap::<
            rustbgpd_evpn::IpVrfId,
            u32,
        >::new()));
    // Latest owned FDB nexthop-group state (ADR-0059). The reconciler
    // publishes the actor-owned group/refcount snapshot on every
    // report; gRPC reads this watch channel lock-free for
    // `EvpnService.ListEvpnNexthops`.
    let (evpn_fdb_nexthops_tx, evpn_fdb_nexthops_rx) =
        tokio::sync::watch::channel(rustbgpd_evpn::FdbNexthopDataplaneStatus::default());
    let evpn_remote_ip_prefix_drop_counts_rx = evpn_dataplane_handle.as_ref().map_or_else(
        || {
            let (_, rx) = tokio::sync::watch::channel(std::sync::Arc::new(
                evpn_dataplane::RemoteIpPrefixDropCounts::new(),
            ));
            rx
        },
        evpn_dataplane::EvpnDataplaneHandle::remote_prefix_drop_counts_receiver,
    );
    if let Some(handle) = evpn_dataplane_handle.as_ref() {
        let mut reports = handle.subscribe_reports();
        // Resolve IpVrfId → operator-facing name for the metric labels
        // — same labelling the gRPC surface uses.
        let vrf_id_to_name: std::collections::HashMap<rustbgpd_evpn::IpVrfId, String> =
            evpn_ip_vrfs
                .iter()
                .map(|v| (v.id, v.name.clone()))
                .collect();
        let metrics_for_routes = metrics.clone();
        tokio::spawn(async move {
            loop {
                match reports.recv().await {
                    Ok(report) => {
                        // `send_replace` is the no-await write —
                        // updates the value in place and wakes any
                        // pending watchers. Safe to call from inside
                        // a tokio task without blocking the worker.
                        evpn_fdb_nexthops_tx.send_replace(report.fdb_nexthops);
                        evpn_ip_vrf_status_tx.send_replace(report.ip_vrf_status);
                        // Slice 6a: publish per-VRF observed-routes
                        // gauge values and bump filtered-routes
                        // counters by the per-pass deltas. The
                        // observations themselves are forwarded onto
                        // a watch channel for the L3 originator
                        // (slice 6b) to subscribe to.
                        //
                        // `ip_vrf_routes = None` signals a transient
                        // kernel-dump failure (ADR-0054 §6). Preserve
                        // the watch's last-good value and do not
                        // increment Prometheus counters — the next
                        // successful reconcile pass will re-publish
                        // and bump filter counts from a fresh dump.
                        if let Some(dump) = report.ip_vrf_routes {
                            for (vrf_id, observations) in &dump.observations {
                                let label = vrf_id_to_name
                                    .get(vrf_id)
                                    .cloned()
                                    .unwrap_or_else(|| vrf_id.as_u32().to_string());
                                metrics_for_routes.set_evpn_ip_vrf_observed_routes(
                                    &label,
                                    i64::try_from(observations.len()).unwrap_or(i64::MAX),
                                );
                            }
                            for ((vrf_id, reason), delta) in &dump.filter_counts {
                                let label = vrf_id_to_name
                                    .get(vrf_id)
                                    .cloned()
                                    .unwrap_or_else(|| vrf_id.as_u32().to_string());
                                metrics_for_routes.add_evpn_ip_vrf_observed_routes_filtered(
                                    &label,
                                    reason.label(),
                                    *delta,
                                );
                            }
                            evpn_ip_vrf_routes_tx
                                .send_replace(std::sync::Arc::new(dump.observations));
                        } else {
                            tracing::debug!(
                                "ip-vrf route dump failed this reconcile pass; preserving \
                                 last-good observation snapshot"
                            );
                        }
                        // Slice 6c: publish installed-route counts to
                        // the watch channel + Prometheus gauge. The
                        // reconcile actor populates
                        // `report.ip_vrf_installed_routes` from its
                        // L3 owned set on every pass; this is
                        // authoritative (no `Option` wrap needed
                        // because a kernel dump failure during L3
                        // install just leaves the count at its prior
                        // value — the owned set itself doesn't
                        // change on failure).
                        for (vrf_id, count) in &report.ip_vrf_installed_routes {
                            let label = vrf_id_to_name
                                .get(vrf_id)
                                .cloned()
                                .unwrap_or_else(|| vrf_id.as_u32().to_string());
                            metrics_for_routes
                                .set_evpn_ip_vrf_installed_routes(&label, i64::from(*count));
                        }
                        evpn_ip_vrf_installed_routes_tx
                            .send_replace(std::sync::Arc::new(report.ip_vrf_installed_routes));
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        // The reconcile actor emits at most one report
                        // per pass (5 s default); if this subscriber
                        // fell behind that bound, the broadcast buffer
                        // already replaced the missed entries with
                        // newer ones. Keep going — the next received
                        // report supersedes whatever we missed.
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                }
            }
        });
    }

    // EVPN Type 5 originator (Gate 9 slice 6b). Subscribes to the
    // route-observation watch channel populated above and the slice-5
    // IP-VRF status watch. Returns `None` when no `[[evpn_ip_vrfs]]`
    // are configured, so L2-only and RR-only deployments incur zero
    // cost. The shared `OriginatedIpVrfRouteCounts` is read-only on
    // the gRPC side (below) so handlers can surface
    // `originated_routes_count` without coordinating with the actor.
    let evpn_l3_originator_shutdown = tokio_util::sync::CancellationToken::new();
    let evpn_originated_ip_vrf_route_counts =
        evpn_l3_originator::OriginatedIpVrfRouteCounts::default();
    let evpn_l3_originator_handle = evpn_l3_originator::spawn(evpn_l3_originator::SpawnConfig {
        ip_vrfs: evpn_ip_vrfs.clone(),
        rib_tx: rib_tx.clone(),
        route_observations_rx: evpn_ip_vrf_routes_rx.clone(),
        ip_vrf_status_rx: evpn_ip_vrf_status_rx.clone(),
        metrics: metrics.clone(),
        originated_counts: evpn_originated_ip_vrf_route_counts.clone(),
        shutdown: evpn_l3_originator_shutdown.clone(),
    });
    let evpn_l3_originator_runtime_control = evpn_l3_originator_handle
        .as_ref()
        .map(evpn_l3_originator::EvpnL3OriginatorHandle::runtime_control);
    let evpn_runtime_apply_lock = Arc::new(tokio::sync::Mutex::new(()));
    let evpn_runtime_converger = Arc::new(EvpnRuntimeActorConverger {
        rib_tx: rib_tx.clone(),
        imet_controller: evpn_imet_controller.clone(),
        dataplane: evpn_dataplane_runtime_control,
        originator: evpn_originator_runtime_control,
        svi: evpn_svi_runtime_control,
        l3_originator: evpn_l3_originator_runtime_control,
        segment: evpn_segment_runtime_control,
    });

    // RFC 7999 BLACKHOLE kernel-discard reconciler (ADR-0060 FIB
    // slice). Completely opt-in: `install_blackhole_discard = true`
    // is effective only alongside `honor_blackhole = true`, and the
    // actor itself still enforces host-prefix-only by default.
    let (blackhole_status_tx, blackhole_status_rx) =
        tokio::sync::watch::channel(Vec::<blackhole::BlackholeStatus>::new());
    let blackhole_shutdown = tokio_util::sync::CancellationToken::new();
    let blackhole_handle = blackhole::spawn(
        blackhole::BlackholeConfig {
            enabled: config.global.honor_blackhole && config.global.install_blackhole_discard,
            allow_broad_prefixes: config.global.allow_blackhole_broad_prefixes,
        },
        rib_tx.clone(),
        metrics.clone(),
        blackhole_status_tx,
        blackhole_shutdown.clone(),
    );

    // ADR-0061 general unicast FIB reconciler. Completely opt-in:
    // an empty `[[fib_tables]]` list returns `None` and leaves
    // route-server / route-reflector deployments control-plane-only.
    let (fib_status_tx, fib_status_rx) =
        tokio::sync::watch::channel(Vec::<fib_runtime::FibRuntimeStatus>::new());
    let (fib_event_tx, fib_event_rx) =
        tokio::sync::broadcast::channel::<fib_runtime::FibRuntimeEvent>(4096);
    let (fib_bgp_event_tx, _) =
        tokio::sync::broadcast::channel::<rustbgpd_api::proto::BgpEvent>(4096);
    let _fib_event_bridge_handle =
        spawn_fib_dataplane_event_bridge(fib_event_rx, fib_bgp_event_tx.clone());
    let fib_runtime_shutdown = tokio_util::sync::CancellationToken::new();
    let fib_runtime_handle = fib_runtime::spawn(
        fib_runtime::FibRuntimeConfig {
            tables: config.fib_tables.clone(),
            owned_state_path: Some(config.runtime_state_dir().join("fib-owned.json")),
        },
        rib_tx.clone(),
        rib_query_tx.clone(),
        metrics.clone(),
        fib_status_tx,
        fib_event_tx,
        fib_runtime_shutdown.clone(),
    );

    // Spawn gRPC API server (keep JoinHandle for supervision)
    let grpc_rib_tx = rib_tx.clone();
    let grpc_rib_query_tx = rib_query_tx;
    let grpc_peer_mgr_tx = peer_mgr_tx.clone();
    let evpn_duplicate_mac_clear = evpn_originator_handle.as_ref().map(|handle| {
        let control = handle.control();
        Arc::new(move |vni, mac| {
            let control = control.clone();
            Box::pin(async move {
                match control
                    .clear_duplicate_mac_quarantine(rustbgpd_evpn::DuplicateMacKey::new(vni, mac))
                    .await
                {
                    Ok(evpn_originator::ClearDuplicateMacQuarantineResult::Cleared) => {
                        Ok(rustbgpd_api::evpn_service::DuplicateMacClearOutcome { cleared: true })
                    }
                    Ok(evpn_originator::ClearDuplicateMacQuarantineResult::NotActive) => {
                        Ok(rustbgpd_api::evpn_service::DuplicateMacClearOutcome { cleared: false })
                    }
                    Ok(evpn_originator::ClearDuplicateMacQuarantineResult::UnknownVni) => Err(
                        rustbgpd_api::evpn_service::DuplicateMacClearError::NotFound(format!(
                            "no EVPN instance configured for VNI {vni}"
                        )),
                    ),
                    Err(evpn_originator::EvpnOriginatorControlError::Closed) => Err(
                        rustbgpd_api::evpn_service::DuplicateMacClearError::Unavailable(
                            "EVPN originator control channel is closed".to_string(),
                        ),
                    ),
                    Err(evpn_originator::EvpnOriginatorControlError::ReplyDropped) => Err(
                        rustbgpd_api::evpn_service::DuplicateMacClearError::Unavailable(
                            "EVPN originator control response channel dropped".to_string(),
                        ),
                    ),
                }
            }) as rustbgpd_api::evpn_service::DuplicateMacClearFuture
        }) as rustbgpd_api::evpn_service::DuplicateMacClearFn
    });
    let serve_config = ServeConfig {
        asn: config.global.asn,
        router_id: config.global.router_id.clone(),
        listen_port: u32::from(config.global.listen_port),
        metrics: metrics.clone(),
        start_time,
        mrt_trigger_tx,
        evpn_originated_local_mac_count: {
            let counts = evpn_originated_local_mac_counts.clone();
            Arc::new(move |vni| {
                rustbgpd_evpn::EvpnInstanceId::new(vni).map_or(0, |id| counts.count(id))
            })
        },
        evpn_ip_vrf_status_snapshot: {
            // `borrow()` on a watch receiver is lock-free (internal
            // seqlock); cloning the Vec releases the borrow before
            // the gRPC handler returns.
            let rx = evpn_ip_vrf_status_rx.clone();
            Arc::new(move || rx.borrow().clone())
        },
        evpn_originated_ip_vrf_route_count: {
            let counts = evpn_originated_ip_vrf_route_counts.clone();
            Arc::new(move |vni| rustbgpd_evpn::IpVrfId::new(vni).map_or(0, |id| counts.count(id)))
        },
        evpn_installed_ip_vrf_route_count: {
            let rx = evpn_ip_vrf_installed_routes_rx.clone();
            Arc::new(move |vni| {
                rustbgpd_evpn::IpVrfId::new(vni).map_or(0, |id| {
                    u64::from(rx.borrow().get(&id).copied().unwrap_or(0))
                })
            })
        },
        evpn_remote_ip_prefix_drop_counts: {
            let rx = evpn_remote_ip_prefix_drop_counts_rx.clone();
            Arc::new(move || {
                rx.borrow()
                    .iter()
                    .map(|((vrf, reason), count)| {
                        rustbgpd_api::evpn_service::RemoteIpPrefixDropCount {
                            vrf: vrf.clone(),
                            reason: reason.clone(),
                            count: *count,
                        }
                    })
                    .collect()
            })
        },
        evpn_fdb_nexthop_snapshot: {
            let rx = evpn_fdb_nexthops_rx.clone();
            Arc::new(move || rx.borrow().clone())
        },
        evpn_runtime_model: {
            let coordinator = evpn_runtime_coordinator.clone();
            Arc::new(move || match coordinator.lock() {
                Ok(guard) => guard.model().clone(),
                Err(poisoned) => poisoned.into_inner().model().clone(),
            })
        },
        evpn_runtime_apply: {
            let coordinator = evpn_runtime_coordinator.clone();
            let apply_lock = evpn_runtime_apply_lock.clone();
            let converger = evpn_runtime_converger.clone();
            Some(Arc::new(move |request| {
                let coordinator = coordinator.clone();
                let apply_lock = apply_lock.clone();
                let converger = converger.clone();
                Box::pin(async move {
                    apply_evpn_runtime_request(
                        &request,
                        coordinator.as_ref(),
                        apply_lock.as_ref(),
                        converger.as_ref(),
                    )
                    .await
                }) as rustbgpd_api::evpn_service::EvpnRuntimeApplyFuture
            })
                as rustbgpd_api::evpn_service::EvpnRuntimeApplyFn)
        },
        evpn_duplicate_mac_clear,
        blackhole_discard_snapshot: {
            let rx = blackhole_status_rx.clone();
            Arc::new(move || {
                rx.borrow()
                    .iter()
                    .map(|status| rustbgpd_api::proto::BlackholeDiscard {
                        prefix: status.prefix.addr_string(),
                        prefix_length: u32::from(status.prefix.prefix_len()),
                        peer_address: status.peer.to_string(),
                        state: match status.state {
                            blackhole::BlackholeState::Installed => {
                                rustbgpd_api::proto::BlackholeDiscardState::Installed as i32
                            }
                            blackhole::BlackholeState::Rejected => {
                                rustbgpd_api::proto::BlackholeDiscardState::Rejected as i32
                            }
                            blackhole::BlackholeState::Failed => {
                                rustbgpd_api::proto::BlackholeDiscardState::Failed as i32
                            }
                        },
                        reason: status.reason.clone(),
                    })
                    .collect()
            })
        },
        fib_route_snapshot: {
            let rx = fib_status_rx.clone();
            Arc::new(move || {
                rx.borrow()
                    .iter()
                    .map(|status| {
                        let sampling = status.sampling.as_ref();
                        rustbgpd_api::proto::FibRouteStatus {
                            table_name: status.table_name.clone(),
                            table_id: status.table_id,
                            metric: status.metric,
                            prefix: status.prefix.addr_string(),
                            prefix_length: u32::from(status.prefix.prefix_len()),
                            next_hop: status
                                .next_hop
                                .map_or_else(String::new, |ip| ip.to_string()),
                            peer_address: status.peer.map_or_else(String::new, |ip| ip.to_string()),
                            state: match status.state {
                                fib_runtime::FibRuntimeState::Installed => {
                                    rustbgpd_api::proto::FibRouteState::Installed as i32
                                }
                                fib_runtime::FibRuntimeState::Rejected => {
                                    rustbgpd_api::proto::FibRouteState::Rejected as i32
                                }
                                fib_runtime::FibRuntimeState::Failed => {
                                    rustbgpd_api::proto::FibRouteState::Failed as i32
                                }
                            },
                            reason: status.reason.clone(),
                            sampling_sampled_rows: sampling.map_or(0, |s| s.sampled_rows),
                            sampling_suppressed_rows: sampling.map_or(0, |s| s.suppressed_rows),
                            sampling_total_rows: sampling.map_or(0, |s| s.total_rows),
                            sampling_max_routes: sampling.map_or(0, |s| s.max_routes),
                            sampling_sample_limit: sampling.map_or(0, |s| s.sample_limit),
                            sampling_complete: sampling.is_some_and(|s| s.suppressed_rows == 0),
                        }
                    })
                    .collect()
            })
        },
        dataplane_route_events: Some(fib_bgp_event_tx),
    };
    let mut grpc_handle = tokio::spawn(async move {
        rustbgpd_api::server::serve(
            grpc_listeners,
            grpc_rib_tx,
            grpc_rib_query_tx,
            grpc_peer_mgr_tx,
            serve_config,
            grpc_shutdown_rx,
            rpc_shutdown_tx,
            config_event_tx,
        )
        .await;
    });

    let peer_configs = config.resolved_neighbors().unwrap_or_else(|e| {
        error!("invalid policy configuration: {e}");
        process::exit(1);
    });
    // Spawn BGP inbound TCP listener. The current daemon opens one
    // listener socket from `Config::listen_addr()`; only install TCP-AO
    // MKTs whose peer family can match that socket. Outbound active-open
    // sockets still install their per-neighbor key independently below.
    let listen_addr = config.listen_addr();
    let listener_options = ListenerSocketOptions {
        tcp_ao_keys: peer_configs
            .iter()
            .filter_map(|neighbor| tcp_ao_listener_key_for_neighbor(listen_addr, neighbor))
            .collect(),
    };

    let tcp_ao_listener_required = !listener_options.tcp_ao_keys.is_empty();
    let (accept_tx, mut accept_rx) = mpsc::channel::<rustbgpd_transport::AcceptedConnection>(64);
    match BgpListener::bind_with_options(listen_addr, accept_tx, listener_options).await {
        Ok(listener) => {
            let listener_peer_mgr_tx = peer_mgr_tx.clone();
            tokio::spawn(async move {
                while let Some(conn) = accept_rx.recv().await {
                    if let Err(e) = listener_peer_mgr_tx
                        .send(PeerManagerCommand::AcceptInbound {
                            stream: conn.stream,
                            peer_addr: conn.peer_addr,
                        })
                        .await
                    {
                        warn!(error = %e, "failed to forward inbound connection to peer manager");
                    }
                }
            });
            tokio::spawn(listener.run());
        }
        Err(e) => {
            if tcp_ao_listener_required {
                error!(
                    %listen_addr,
                    error = %e,
                    "failed to start BGP listener with TCP-AO-protected peers configured; refusing to run partially protected"
                );
                process::exit(1);
            }
            warn!(%listen_addr, error = %e, "failed to bind BGP listener");
        }
    }

    // Add initial peers from config via PeerManager
    for neighbor in peer_configs {
        let transport_config = neighbor.transport_config;
        let label = neighbor.label;
        let import_policy = neighbor.import_policy;
        let export_policy = neighbor.export_policy;
        let peer_group = neighbor.peer_group;
        info!(
            peer = %transport_config.remote_addr,
            label = %label,
            remote_asn = transport_config.peer.remote_asn,
            "adding peer from config"
        );
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let _ = peer_mgr_tx
            .send(PeerManagerCommand::AddPeer {
                config: PeerManagerNeighborConfig {
                    address: transport_config.remote_addr.ip(),
                    remote_asn: transport_config.peer.remote_asn,
                    description: label.clone(),
                    peer_group,
                    hold_time: Some(transport_config.peer.hold_time),
                    max_prefixes: transport_config.max_prefixes,
                    md5_password: transport_config.md5_password.clone(),
                    tcp_ao: transport_config.tcp_ao.clone(),
                    ttl_security: transport_config.ttl_security,
                    families: transport_config.peer.families.clone(),
                    graceful_restart: transport_config.peer.graceful_restart,
                    gr_restart_time: transport_config.peer.gr_restart_time,
                    gr_stale_routes_time: transport_config.gr_stale_routes_time,
                    llgr_stale_time: transport_config.llgr_stale_time,
                    gr_restart_eligible: true,
                    local_ipv6_nexthop: transport_config.local_ipv6_nexthop,
                    route_reflector_client: transport_config.route_reflector_client,
                    route_server_client: transport_config.route_server_client,
                    remove_private_as: transport_config.remove_private_as,
                    add_path_receive: transport_config.peer.add_path_receive,
                    add_path_send: transport_config.peer.add_path_send,
                    add_path_send_max: transport_config.peer.add_path_send_max,
                    import_policy,
                    export_policy,
                },
                sync_config_snapshot: false,
                reply: reply_tx,
            })
            .await;
        match reply_rx.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => error!(label = %label, error = %e, "failed to add peer"),
            Err(e) => error!(label = %label, error = %e, "peer manager reply dropped"),
        }
    }

    // Signal handlers (unix-only, which is our target)
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .unwrap_or_else(|e| fatal_startup_error("failed to register SIGTERM handler", e));
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .unwrap_or_else(|e| fatal_startup_error("failed to register SIGHUP handler", e));

    // Wait for shutdown signal: SIGINT, SIGTERM, Shutdown RPC, unexpected gRPC exit, or SIGHUP
    //
    // SIGHUP runs `reload_config` on a dedicated tokio task so the
    // signal-arm dispatch returns immediately. Without this, the SIGHUP
    // arm's inline `.await` would block the same `select!` from
    // observing SIGINT/SIGTERM for the duration of the reload (up to
    // ~7 round-trip commands × 500 ms `PEER_POLICY_UPDATE_TIMEOUT` plus
    // reconcile round-trip). Operators hitting Ctrl-C mid-reload should
    // see the daemon respond.
    //
    // Concurrency invariant: at most one reload in flight. Concurrent
    // reloads would race on `peer_mgr_tx` ordering (interleaved
    // SetPolicy / ReconcilePeers commands) and double-fire the
    // post-reload sync. A SIGHUP that arrives while a reload is still
    // running is logged and dropped — the operator-facing back-pressure
    // surface.
    let mut reload_in_flight: Option<tokio::task::JoinHandle<Option<ReloadedConfig>>> = None;
    loop {
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                match result {
                    Ok(()) => info!("received SIGINT"),
                    Err(e) => error!(error = %e, "failed to listen for SIGINT"),
                }
                break;
            }
            _ = sigterm.recv() => {
                info!("received SIGTERM");
                break;
            }
            changed = rpc_shutdown_rx.changed() => {
                if changed.is_err() || !*rpc_shutdown_rx.borrow() {
                    continue;
                }
                info!("shutdown initiated via gRPC");
                break;
            }
            result = &mut grpc_handle => {
                error!(?result, "gRPC server exited unexpectedly");
                info!("initiating shutdown due to gRPC server failure");
                break;
            }
            _ = sighup.recv() => {
                if reload_in_flight.is_some() {
                    warn!("SIGHUP received while previous reload still in flight; ignoring");
                    continue;
                }
                info!("SIGHUP received, reloading configuration");
                let path = config.file_path.as_ref().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
                let snapshot = config.clone();
                let live_tcp = live_grpc_tcp.clone();
                let live_uds = live_grpc_uds.clone();
                let pm_tx = peer_mgr_tx.clone();
                reload_in_flight = Some(tokio::spawn(async move {
                    reload_config(
                        &path,
                        &snapshot,
                        live_tcp.as_ref(),
                        live_uds.as_ref(),
                        &pm_tx,
                    )
                    .await
                }));
            }
            // Only polled when a reload is in flight. Standard tokio
            // idiom: `std::future::pending().await` parks the arm
            // forever in the no-handle case so `select!` ignores it.
            // The `take()` drops the borrow before we touch
            // `reload_in_flight` again in the body, sidestepping the
            // borrow-across-await complaint.
            outcome = async {
                match reload_in_flight.as_mut() {
                    Some(handle) => handle.await,
                    None => std::future::pending().await,
                }
            } => {
                reload_in_flight = None;
                match outcome {
                    Ok(Some(new_config)) => {
                        match apply_reload_outcome(
                            new_config,
                            &peer_mgr_internal_tx,
                            bridge_replace_tx.as_ref(),
                        )
                        .await
                        {
                            Ok(advanced) => config = advanced,
                            Err(stage) => error!(
                                stage,
                                "post-reload sync failed mid-flight; in-memory config not advanced — next SIGHUP will retry"
                            ),
                        }
                    }
                    Ok(None) => {
                        // reload_config already logged the failure.
                    }
                    Err(e) => error!(error = %e, "reload task panicked"),
                }
            }
        }
    }

    // If a reload is still in flight at shutdown, abort it before
    // tearing down the peer manager. Letting it run would race the
    // peer manager's Shutdown command and potentially queue commands
    // against an already-draining manager.
    if let Some(handle) = reload_in_flight.take() {
        handle.abort();
        let _ = handle.await;
    }

    // Drop the profiler now while all data structures are still alive,
    // so the heap snapshot captures the live working set.
    drop(profiler);

    // Coordinated shutdown:
    // 1. Tell PeerManager to shut down (sends NOTIFICATIONs to all peers)
    info!("initiating coordinated shutdown");
    if let Some(restart_time_secs) = max_gr_restart_time_secs(&config) {
        let expires_at = SystemTime::now() + Duration::from_secs(restart_time_secs);
        if let Err(e) = write_gr_restart_marker(&gr_restart_marker_path, expires_at) {
            warn!(
                marker = %gr_restart_marker_path.display(),
                error = %e,
                "failed to write GR restart marker — restarting-speaker mode will be unavailable on the next start (check runtime_state_dir permissions)"
            );
        } else {
            info!(
                marker = %gr_restart_marker_path.display(),
                restart_time_secs,
                "wrote GR restart marker for coordinated shutdown"
            );
        }
    } else if let Err(e) = remove_gr_restart_marker(&gr_restart_marker_path) {
        warn!(
            marker = %gr_restart_marker_path.display(),
            error = %e,
            "failed to clear GR restart marker"
        );
    }
    // 1.9a Drain the EVPN local-MAC originator first — BEFORE the
    // peer manager shutdown — so its Type 2 Withdraws ride the still-
    // open BGP sessions to peers. `RibUpdate::WithdrawEvpn` recomputes
    // and stages outbound updates before replying, so the transport
    // path picks them up if (and only if) the peer sessions are still
    // alive. Doing this after `PeerManagerCommand::Shutdown` would
    // leave peers with stale Type 2 routes on their LocRib until our
    // hold-timer expired on their side.
    //
    // Bounded 5 s drain — the originator's `drain_to_withdraws`
    // emits one Withdraw per still-advertised MAC.
    if let Some(handle) = evpn_originator_handle {
        info!("draining EVPN originator");
        handle.shutdown().await;
    }

    // 1.9a' Drain the SVI-MAC originator first — same ordering
    // rationale as the local-MAC originator: SVI Type 2 withdraws
    // must land while peer sessions are still up.
    if let Some(handle) = evpn_svi_handle {
        info!("draining EVPN SVI-MAC originator");
        handle.shutdown().await;
    }

    // 1.9a''' Drain the EVPN L3 (Type 5) originator. Same ordering
    // rationale: Type 5 withdraws must reach peers before BGP
    // sessions tear down so remote VTEPs flush their kernel FIBs
    // cleanly. The originator's diff loop emits one
    // `RibUpdate::WithdrawEvpn` per currently-originated prefix.
    if let Some(handle) = evpn_l3_originator_handle {
        info!("draining EVPN L3 originator");
        handle.shutdown().await;
    }

    // 1.9a'' Drain the EVPN segment orchestrator — withdraws all
    // Type 4 ES + Type 1 EAD-per-ES + Type 1 EAD-per-EVI routes
    // before peer sessions tear down. Same ordering rationale as
    // the originator + SVI tasks.
    if let Some(handle) = evpn_segment_handle {
        info!("draining EVPN segment orchestrator");
        handle.shutdown().await;
    }

    // 1.9b Withdraw the Type 3 IMET routes we originated at startup
    // so peers cleanly remove us from their ingress-replication
    // lists. Same ordering rationale as the Type 2 drain — must land
    // before peer sessions tear down.
    let mut imet_controller = evpn_imet_controller.lock().await;
    if !imet_controller.is_empty() {
        info!(
            count = imet_controller.len(),
            "withdrawing EVPN Type 3 IMET routes"
        );
        imet_controller.withdraw_all(&rib_tx).await;
    }
    drop(imet_controller);

    let _ = peer_mgr_tx.send(PeerManagerCommand::Shutdown).await;

    // 2. Wait for PeerManager to finish draining all peers
    if let Err(e) = peer_mgr_handle.await {
        error!(error = %e, "peer manager task panicked");
    }

    // 2.4 Drain daemon-owned BLACKHOLE discard routes. This is local
    // kernel state only, so it does not need live BGP sessions. The
    // actor removes only prefixes it successfully installed during
    // this daemon lifetime.
    if let Some(handle) = blackhole_handle {
        info!("draining BLACKHOLE discard routes");
        handle.shutdown().await;
    }

    // 2.45 Drain daemon-owned ADR-0061 general FIB routes. This is
    // local kernel state only, so it does not need live BGP sessions.
    if let Some(handle) = fib_runtime_handle {
        info!("draining general FIB routes");
        handle.shutdown().await;
    }

    // 2.5 Drain the EVPN Linux dataplane reconciler. The actor
    // withdraws every owned remote-MAC FDB entry under a bounded
    // 5 s drain (ADR-0054 §7) and exits; foreign entries
    // (kernel-learned local MACs, operator-static FDB entries) are
    // structurally untouched by the diff loop and survive the drain.
    // This runs after the peer manager because the kernel-side FDB
    // teardown does not need an active BGP session.
    if let Some(handle) = evpn_dataplane_handle {
        info!("draining EVPN dataplane");
        handle.shutdown().await;
    }

    // 3. Shut down BMP subsystem (send explicit shutdown and await bounded drain)
    if let Some(mut bmp_runtime) = bmp_runtime {
        if let Err(e) = bmp_runtime
            .control_tx
            .send(rustbgpd_bmp::BmpControlEvent::Shutdown)
            .await
        {
            warn!(error = %e, "failed to send BMP shutdown control event");
        }

        match tokio::time::timeout(Duration::from_secs(2), &mut bmp_runtime.manager_handle).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => warn!(error = %e, "BMP manager task panicked during shutdown"),
            Err(_) => {
                warn!("BMP manager did not exit within 2s; aborting task");
                bmp_runtime.manager_handle.abort();
            }
        }

        for mut handle in bmp_runtime.client_handles {
            match tokio::time::timeout(Duration::from_secs(2), &mut handle).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!(error = %e, "BMP client task panicked during shutdown"),
                Err(_) => {
                    warn!("BMP client did not exit within 2s; aborting task");
                    handle.abort();
                }
            }
        }
    }

    // 4. Stop the gRPC server
    let _ = grpc_shutdown_tx.send(());

    info!("rustbgpd exiting");
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[derive(Clone)]
    struct TestRuntimeConverger {
        result: Result<(), DaemonEvpnRuntimeConvergeError>,
    }

    impl TestRuntimeConverger {
        const fn ok() -> Self {
            Self { result: Ok(()) }
        }

        fn unsupported(message: &str) -> Self {
            Self {
                result: Err(DaemonEvpnRuntimeConvergeError::unsupported(message)),
            }
        }

        fn failed(message: &str) -> Self {
            Self {
                result: Err(DaemonEvpnRuntimeConvergeError::failed(message)),
            }
        }
    }

    impl DaemonEvpnRuntimeConverger for TestRuntimeConverger {
        fn converge<'a>(
            &'a self,
            _current: &'a rustbgpd_evpn::EvpnRuntimeModel,
            _candidate: &'a rustbgpd_evpn::EvpnRuntimeCandidate,
            _plan: &'a rustbgpd_evpn::EvpnRuntimePlan,
        ) -> DaemonEvpnRuntimeConvergeFuture<'a> {
            Box::pin(async move { self.result.clone() })
        }
    }

    fn unique_temp_path(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("rustbgpd-{name}-{suffix}.toml"))
    }

    fn load_config_from_toml(name: &str, toml: &str) -> Config {
        let path = unique_temp_path(name);
        std::fs::write(&path, toml).unwrap();
        let config = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&path).ok();
        config
    }

    fn tcp_ao_neighbor_toml(address: &str) -> String {
        format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "{address}"
remote_asn = 65002
tcp_ao = {{ key = "secret", send_id = 1, recv_id = 1, algorithm = "hmac(sha256)" }}
"#
        )
    }

    fn minimal_runtime_candidate_toml() -> &'static str {
        r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[security.grpc]
enforcement = "legacy"
"#
    }

    fn l2vni_runtime_candidate_toml() -> &'static str {
        r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[security.grpc]
enforcement = "legacy"

[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"
"#
    }

    fn l2vni_one_es_runtime_candidate_toml() -> &'static str {
        r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[security.grpc]
enforcement = "legacy"

[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.1"
"#
    }

    // Two committed L2VNIs + one ES over VNI 100. Config requires one
    // local ES per VNI, so a second ES must target VNI 200. This is the
    // pre-add baseline for the single-ES-add tests.
    fn two_l2vni_one_es_runtime_candidate_toml() -> &'static str {
        r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[security.grpc]
enforcement = "legacy"

[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"

[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.1"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.1"
"#
    }

    // Adds a second ES over VNI 200 on top of the one-ES baseline (one
    // local ES per VNI). Used as the single-ES-add candidate.
    fn two_l2vni_two_es_runtime_candidate_toml() -> &'static str {
        r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[security.grpc]
enforcement = "legacy"

[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"

[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.1"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.1"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:02"
member_vnis = [200]
originator_ip = "10.0.0.1"
"#
    }

    // Redefines the existing ES so it also covers VNI 200. Used by the
    // single-ES-redefine tests.
    fn two_l2vni_redefined_es_runtime_candidate_toml() -> &'static str {
        r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[security.grpc]
enforcement = "legacy"

[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"

[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.1"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100, 200]
originator_ip = "10.0.0.1"
"#
    }

    fn l2vni_linked_ip_vrf_runtime_candidate_toml() -> &'static str {
        r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[security.grpc]
enforcement = "legacy"

[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"
ip_vrf = "tenant-blue"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#
    }

    fn two_l2vni_linked_ip_vrf_runtime_candidate_toml() -> &'static str {
        r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[security.grpc]
enforcement = "legacy"

[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"
ip_vrf = "tenant-blue"

[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.1"
ip_vrf = "tenant-blue"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#
    }

    fn l2vni_one_ip_vrf_runtime_candidate_toml() -> &'static str {
        r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[security.grpc]
enforcement = "legacy"

[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#
    }

    fn two_l2vni_runtime_candidate_toml() -> &'static str {
        r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[security.grpc]
enforcement = "legacy"

[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"

[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.1"
"#
    }

    fn two_l2vni_one_ip_vrf_runtime_candidate_toml() -> &'static str {
        r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[security.grpc]
enforcement = "legacy"

[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"

[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.1"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#
    }

    fn ip_vrf_runtime_candidate_toml() -> &'static str {
        r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[security.grpc]
enforcement = "legacy"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#
    }

    fn two_ip_vrf_runtime_candidate_toml() -> &'static str {
        r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[security.grpc]
enforcement = "legacy"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000

[[evpn_ip_vrfs]]
name = "tenant-green"
vni = 6000
rd = "65000:6000"
route_targets = ["65000:6000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:02"
vrf_device = "vrf-green"
l3vxlan_device = "vni6000"
table_id = 6000
"#
    }

    fn empty_evpn_runtime_coordinator() -> Arc<Mutex<rustbgpd_evpn::EvpnRuntimeCoordinator>> {
        Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
            rustbgpd_evpn::EvpnInstanceTable::new(),
            rustbgpd_evpn::IpVrfTable::new(),
            Vec::new(),
        )))
    }

    fn ip_vrf_runtime_coordinator() -> Arc<Mutex<rustbgpd_evpn::EvpnRuntimeCoordinator>> {
        let current = runtime_candidate_from_toml(ip_vrf_runtime_candidate_toml());
        Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
            rustbgpd_evpn::EvpnInstanceTable::new(),
            current.ip_vrfs().clone(),
            Vec::new(),
        )))
    }

    fn two_ip_vrf_runtime_coordinator() -> Arc<Mutex<rustbgpd_evpn::EvpnRuntimeCoordinator>> {
        let current = runtime_candidate_from_toml(two_ip_vrf_runtime_candidate_toml());
        Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
            rustbgpd_evpn::EvpnInstanceTable::new(),
            current.ip_vrfs().clone(),
            Vec::new(),
        )))
    }

    fn two_l2vni_runtime_coordinator() -> Arc<Mutex<rustbgpd_evpn::EvpnRuntimeCoordinator>> {
        let current = runtime_candidate_from_toml(two_l2vni_runtime_candidate_toml());
        Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
            current.instances().clone(),
            rustbgpd_evpn::IpVrfTable::new(),
            Vec::new(),
        )))
    }

    fn runtime_model_from_candidate_toml(toml: &str) -> rustbgpd_evpn::EvpnRuntimeModel {
        let candidate = evpn_runtime_candidate_from_toml(toml).unwrap();
        rustbgpd_evpn::EvpnRuntimeModel::coordinator_startup(
            candidate.instances().clone(),
            candidate.ip_vrfs().clone(),
            candidate.ethernet_segments().to_vec(),
        )
    }

    fn runtime_candidate_from_toml(toml: &str) -> rustbgpd_evpn::EvpnRuntimeCandidate {
        evpn_runtime_candidate_from_toml(toml).unwrap()
    }

    fn runtime_converger_rib_responder(
        mut rib_rx: mpsc::Receiver<RibUpdate>,
        injects: Arc<tokio::sync::Mutex<Vec<rustbgpd_wire::EvpnRouteKey>>>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let (events_tx, _) = broadcast::channel(16);
            while let Some(msg) = rib_rx.recv().await {
                match msg {
                    RibUpdate::SubscribeEvpnRouteEvents { reply } => {
                        let _ = reply.send(events_tx.subscribe());
                    }
                    RibUpdate::QueryEvpnRoutes { reply } => {
                        let _ = reply.send(vec![]);
                    }
                    RibUpdate::InjectEvpn { route, reply } => {
                        injects.lock().await.push(route.key());
                        let _ = reply.send(Ok(()));
                    }
                    RibUpdate::WithdrawEvpn { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    _ => {}
                }
            }
        })
    }

    // Like `runtime_converger_rib_responder` but also records withdraws,
    // for tests that need to observe drains (e.g. ES-add re-stamping a
    // member VNI's local MAC origination).
    fn runtime_converger_rib_recorder(
        mut rib_rx: mpsc::Receiver<RibUpdate>,
        injects: Arc<tokio::sync::Mutex<Vec<rustbgpd_wire::EvpnRouteKey>>>,
        withdraws: Arc<tokio::sync::Mutex<Vec<rustbgpd_wire::EvpnRouteKey>>>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let (events_tx, _) = broadcast::channel(16);
            while let Some(msg) = rib_rx.recv().await {
                match msg {
                    RibUpdate::SubscribeEvpnRouteEvents { reply } => {
                        let _ = reply.send(events_tx.subscribe());
                    }
                    RibUpdate::QueryEvpnRoutes { reply } => {
                        let _ = reply.send(vec![]);
                    }
                    RibUpdate::InjectEvpn { route, reply } => {
                        injects.lock().await.push(route.key());
                        let _ = reply.send(Ok(()));
                    }
                    RibUpdate::WithdrawEvpn { key, reply } => {
                        withdraws.lock().await.push(key);
                        let _ = reply.send(Ok(()));
                    }
                    _ => {}
                }
            }
        })
    }

    fn runtime_ip_vrf_ready_status(
        id: rustbgpd_evpn::IpVrfId,
        name: &str,
    ) -> rustbgpd_evpn::IpVrfDataplaneStatus {
        rustbgpd_evpn::IpVrfDataplaneStatus {
            vrf_id: id,
            vrf_name: name.to_string(),
            status: rustbgpd_evpn::ip_vrf::IpVrfStatus::Ready {
                vrf_ifindex: 60,
                l3vxlan_ifindex: 61,
                table_id: id.as_u32(),
                router_mac: rustbgpd_evpn::MacAddress::new([0x02, 0, 0, 0, 0, 0x60]),
            },
        }
    }

    fn runtime_local_ip_observation(
        id: rustbgpd_evpn::IpVrfId,
    ) -> rustbgpd_evpn::ip_vrf::LocalIpRouteObservation {
        rustbgpd_evpn::ip_vrf::LocalIpRouteObservation {
            vrf_id: id,
            prefix: rustbgpd_wire::EvpnIpPrefixValue::V4(rustbgpd_wire::Ipv4Prefix::new(
                std::net::Ipv4Addr::new(10, 6, 0, 0),
                24,
            )),
            source: rustbgpd_evpn::RouteSource::Static,
        }
    }

    async fn wait_for_recorded_evpn_key(
        records: &Arc<tokio::sync::Mutex<Vec<rustbgpd_wire::EvpnRouteKey>>>,
        message: &'static str,
    ) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if !records.lock().await.is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect(message);
    }

    #[tokio::test]
    async fn apply_evpn_runtime_validate_only_plans_without_advancing() {
        let coordinator = empty_evpn_runtime_coordinator();
        let apply_lock = tokio::sync::Mutex::new(());
        let converger = TestRuntimeConverger::ok();

        let response = apply_evpn_runtime_request(
            &proto::ApplyEvpnRuntimeRequest {
                candidate_toml: l2vni_runtime_candidate_toml().to_string(),
                validate_only: true,
            },
            coordinator.as_ref(),
            &apply_lock,
            &converger,
        )
        .await
        .unwrap();

        assert_eq!(
            response.outcome,
            proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyValidated as i32
        );
        let plan = response.plan.unwrap();
        assert_eq!(plan.current_generation, 1);
        assert_eq!(plan.proposed_generation, 2);
        assert_eq!(plan.evpn_instances.unwrap().added, vec!["100"]);
        assert_eq!(response.runtime.unwrap().generation, 1);
        assert_eq!(coordinator.lock().unwrap().model().generation().as_u64(), 1);
    }

    #[tokio::test]
    async fn apply_evpn_runtime_noop_succeeds_without_generation_advance() {
        let coordinator = empty_evpn_runtime_coordinator();
        let apply_lock = tokio::sync::Mutex::new(());
        let converger = TestRuntimeConverger::failed("noop should not converge");

        let response = apply_evpn_runtime_request(
            &proto::ApplyEvpnRuntimeRequest {
                candidate_toml: minimal_runtime_candidate_toml().to_string(),
                validate_only: false,
            },
            coordinator.as_ref(),
            &apply_lock,
            &converger,
        )
        .await
        .unwrap();

        assert_eq!(
            response.outcome,
            proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyNoop as i32
        );
        assert_eq!(response.runtime.unwrap().generation, 1);
        assert_eq!(coordinator.lock().unwrap().model().generation().as_u64(), 1);
    }

    #[tokio::test]
    async fn apply_evpn_runtime_l2vni_add_commits_after_convergence() {
        let coordinator = empty_evpn_runtime_coordinator();
        let apply_lock = tokio::sync::Mutex::new(());
        let converger = TestRuntimeConverger::ok();

        let response = apply_evpn_runtime_request(
            &proto::ApplyEvpnRuntimeRequest {
                candidate_toml: l2vni_runtime_candidate_toml().to_string(),
                validate_only: false,
            },
            coordinator.as_ref(),
            &apply_lock,
            &converger,
        )
        .await
        .unwrap();

        assert_eq!(
            response.outcome,
            proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyCommitted as i32
        );
        let runtime = response.runtime.unwrap();
        assert_eq!(runtime.generation, 2);
        assert_eq!(
            runtime.mutation_state,
            proto::EvpnRuntimeMutationState::EvpnRuntimeMutationIdle as i32
        );
        let plan = response.plan.unwrap();
        assert_eq!(plan.evpn_instances.unwrap().added, vec!["100"]);
        let guard = coordinator.lock().unwrap();
        assert_eq!(guard.model().generation().as_u64(), 2);
        assert!(
            guard
                .model()
                .instances()
                .get(rustbgpd_evpn::EvpnInstanceId::new(100).unwrap())
                .is_some()
        );
    }

    #[tokio::test]
    async fn apply_evpn_runtime_l2vni_delete_commits_after_convergence() {
        let coordinator = two_l2vni_runtime_coordinator();
        let apply_lock = tokio::sync::Mutex::new(());
        let converger = TestRuntimeConverger::ok();

        let response = apply_evpn_runtime_request(
            &proto::ApplyEvpnRuntimeRequest {
                candidate_toml: l2vni_runtime_candidate_toml().to_string(),
                validate_only: false,
            },
            coordinator.as_ref(),
            &apply_lock,
            &converger,
        )
        .await
        .unwrap();

        assert_eq!(
            response.outcome,
            proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyCommitted as i32
        );
        let runtime = response.runtime.unwrap();
        assert_eq!(runtime.generation, 2);
        let plan = response.plan.unwrap();
        assert_eq!(plan.evpn_instances.unwrap().deleted, vec!["200"]);
        let guard = coordinator.lock().unwrap();
        assert_eq!(guard.model().generation().as_u64(), 2);
        assert!(
            guard
                .model()
                .instances()
                .get(rustbgpd_evpn::EvpnInstanceId::new(200).unwrap())
                .is_none()
        );
    }

    #[tokio::test]
    async fn apply_evpn_runtime_l2vni_delete_commits_in_ip_vrf_deployment() {
        let current = runtime_candidate_from_toml(l2vni_linked_ip_vrf_runtime_candidate_toml());
        let coordinator = Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
            current.instances().clone(),
            current.ip_vrfs().clone(),
            Vec::new(),
        )));
        let apply_lock = tokio::sync::Mutex::new(());
        let converger = TestRuntimeConverger::ok();

        let response = apply_evpn_runtime_request(
            &proto::ApplyEvpnRuntimeRequest {
                candidate_toml: ip_vrf_runtime_candidate_toml().to_string(),
                validate_only: false,
            },
            coordinator.as_ref(),
            &apply_lock,
            &converger,
        )
        .await
        .unwrap();

        assert_eq!(
            response.outcome,
            proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyCommitted as i32
        );
        assert_eq!(response.runtime.unwrap().generation, 2);
        let plan = response.plan.unwrap();
        assert_eq!(plan.evpn_instances.unwrap().deleted, vec!["100"]);
        let guard = coordinator.lock().unwrap();
        assert_eq!(guard.model().generation().as_u64(), 2);
        assert!(
            guard
                .model()
                .instances()
                .get(rustbgpd_evpn::EvpnInstanceId::new(100).unwrap())
                .is_none()
        );
        assert!(guard.model().ip_vrfs().get("tenant-blue").is_some());
        assert!(!guard.model().ip_vrfs().is_referenced("tenant-blue"));
    }

    #[tokio::test]
    async fn apply_evpn_runtime_ip_vrf_add_commits_after_convergence() {
        let coordinator = ip_vrf_runtime_coordinator();
        let apply_lock = tokio::sync::Mutex::new(());
        let converger = TestRuntimeConverger::ok();

        let response = apply_evpn_runtime_request(
            &proto::ApplyEvpnRuntimeRequest {
                candidate_toml: two_ip_vrf_runtime_candidate_toml().to_string(),
                validate_only: false,
            },
            coordinator.as_ref(),
            &apply_lock,
            &converger,
        )
        .await
        .unwrap();

        assert_eq!(
            response.outcome,
            proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyCommitted as i32
        );
        let runtime = response.runtime.unwrap();
        assert_eq!(runtime.generation, 2);
        let plan = response.plan.unwrap();
        assert_eq!(plan.evpn_ip_vrfs.unwrap().added, vec!["tenant-green"]);
        let guard = coordinator.lock().unwrap();
        assert!(guard.model().ip_vrfs().get("tenant-green").is_some());
    }

    #[tokio::test]
    async fn apply_evpn_runtime_ip_vrf_delete_commits_after_convergence() {
        let coordinator = two_ip_vrf_runtime_coordinator();
        let apply_lock = tokio::sync::Mutex::new(());
        let converger = TestRuntimeConverger::ok();

        let response = apply_evpn_runtime_request(
            &proto::ApplyEvpnRuntimeRequest {
                candidate_toml: ip_vrf_runtime_candidate_toml().to_string(),
                validate_only: false,
            },
            coordinator.as_ref(),
            &apply_lock,
            &converger,
        )
        .await
        .unwrap();

        assert_eq!(
            response.outcome,
            proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyCommitted as i32
        );
        let runtime = response.runtime.unwrap();
        assert_eq!(runtime.generation, 2);
        let plan = response.plan.unwrap();
        assert_eq!(plan.evpn_ip_vrfs.unwrap().deleted, vec!["tenant-green"]);
        let guard = coordinator.lock().unwrap();
        assert!(guard.model().ip_vrfs().get("tenant-green").is_none());
        assert!(guard.model().ip_vrfs().get("tenant-blue").is_some());
    }

    #[test]
    fn validate_single_ip_vrf_delete_rejects_linked_l2vni() {
        let current =
            runtime_model_from_candidate_toml(l2vni_linked_ip_vrf_runtime_candidate_toml());
        let candidate = rustbgpd_evpn::EvpnRuntimeCandidate::new(
            current.instances().clone(),
            rustbgpd_evpn::IpVrfTable::new(),
            Vec::new(),
        );
        let plan = current.plan_candidate(&candidate);

        let error = validate_single_ip_vrf_delete(&current, &candidate, &plan).unwrap_err();
        let DaemonEvpnRuntimeConvergeError::Unsupported(message) = error else {
            panic!("expected unsupported error, got {error:?}");
        };
        assert!(
            message.contains("referenced by an L2VNI"),
            "unexpected error message: {message}"
        );
    }

    #[tokio::test]
    async fn apply_evpn_runtime_unsupported_non_noop_does_not_degrade_runtime() {
        let coordinator = empty_evpn_runtime_coordinator();
        let apply_lock = tokio::sync::Mutex::new(());
        let converger = TestRuntimeConverger::unsupported("unsupported test shape");

        let error = apply_evpn_runtime_request(
            &proto::ApplyEvpnRuntimeRequest {
                candidate_toml: l2vni_runtime_candidate_toml().to_string(),
                validate_only: false,
            },
            coordinator.as_ref(),
            &apply_lock,
            &converger,
        )
        .await
        .unwrap_err();

        assert!(matches!(
            error,
            GrpcEvpnRuntimeApplyError::FailedPrecondition(_)
        ));
        // A non-noop apply with no convergence backend is a capability gap,
        // not an operational failure: the committed generation stays healthy
        // (Active/Idle) so `GetEvpnRuntime` never reports a misleading
        // degraded state from a fail-closed probe.
        let snapshot = coordinator.lock().unwrap().snapshot();
        assert_eq!(snapshot.generation.as_u64(), 1);
        assert_eq!(
            snapshot.lifecycle,
            rustbgpd_evpn::EvpnRuntimeLifecycle::Active
        );
        assert_eq!(
            snapshot.mutation_state,
            rustbgpd_evpn::EvpnRuntimeMutationState::Idle
        );
    }

    #[tokio::test]
    async fn apply_evpn_runtime_ethernet_segment_add_commits_after_convergence() {
        // Start with one committed ES over VNI 100 (so the segment actor
        // spawns), then add a second ES over VNI 200 — the single
        // supported ES mutation shape (one local ES per VNI).
        let current = runtime_candidate_from_toml(two_l2vni_one_es_runtime_candidate_toml());
        let coordinator = Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
            current.instances().clone(),
            current.ip_vrfs().clone(),
            current.ethernet_segments().to_vec(),
        )));
        let apply_lock = tokio::sync::Mutex::new(());
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _rib = runtime_converger_rib_responder(rib_rx, injects);

        let instances = Arc::new(current.instances().clone());
        let segment_handle = evpn_segment::spawn(
            &instances,
            current.ethernet_segments().to_vec(),
            rib_tx.clone(),
            None,
            BgpMetrics::new(),
            tokio_util::sync::CancellationToken::new(),
        )
        .expect("segment actor should spawn for non-empty ES config");

        let converger = EvpnRuntimeActorConverger {
            rib_tx,
            imet_controller: Arc::new(
                tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new()),
            ),
            dataplane: None,
            originator: None,
            svi: None,
            l3_originator: None,
            segment: Some(segment_handle.runtime_control()),
        };

        let response = apply_evpn_runtime_request(
            &proto::ApplyEvpnRuntimeRequest {
                candidate_toml: two_l2vni_two_es_runtime_candidate_toml().to_string(),
                validate_only: false,
            },
            coordinator.as_ref(),
            &apply_lock,
            &converger,
        )
        .await
        .unwrap();

        assert_eq!(
            response.outcome,
            proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyCommitted as i32
        );
        assert_eq!(response.runtime.unwrap().generation, 2);
        {
            let guard = coordinator.lock().unwrap();
            assert_eq!(guard.model().generation().as_u64(), 2);
            assert_eq!(guard.model().ethernet_segments().len(), 2);
        }
        segment_handle.shutdown().await;
    }

    #[tokio::test]
    async fn apply_evpn_runtime_ethernet_segment_delete_commits_after_convergence() {
        // Committed model has two ES; the candidate drops one → delete,
        // the segment actor owns the Type 1/4 drain for the removed ES.
        let current = runtime_candidate_from_toml(two_l2vni_two_es_runtime_candidate_toml());
        let coordinator = Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
            current.instances().clone(),
            current.ip_vrfs().clone(),
            current.ethernet_segments().to_vec(),
        )));
        let apply_lock = tokio::sync::Mutex::new(());
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _rib = runtime_converger_rib_responder(rib_rx, injects);

        let instances = Arc::new(current.instances().clone());
        let segment_handle = evpn_segment::spawn(
            &instances,
            current.ethernet_segments().to_vec(),
            rib_tx.clone(),
            None,
            BgpMetrics::new(),
            tokio_util::sync::CancellationToken::new(),
        )
        .expect("segment actor should spawn for non-empty ES config");

        let converger = EvpnRuntimeActorConverger {
            rib_tx,
            imet_controller: Arc::new(
                tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new()),
            ),
            dataplane: None,
            originator: None,
            svi: None,
            l3_originator: None,
            segment: Some(segment_handle.runtime_control()),
        };

        let response = apply_evpn_runtime_request(
            &proto::ApplyEvpnRuntimeRequest {
                candidate_toml: two_l2vni_one_es_runtime_candidate_toml().to_string(),
                validate_only: false,
            },
            coordinator.as_ref(),
            &apply_lock,
            &converger,
        )
        .await
        .unwrap();

        assert_eq!(
            response.outcome,
            proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyCommitted as i32
        );
        assert_eq!(response.runtime.unwrap().generation, 2);
        {
            let guard = coordinator.lock().unwrap();
            assert_eq!(guard.model().generation().as_u64(), 2);
            assert_eq!(guard.model().ethernet_segments().len(), 1);
        }
        segment_handle.shutdown().await;
    }

    #[tokio::test]
    async fn apply_evpn_runtime_ethernet_segment_redefine_commits_after_convergence() {
        // Committed model has one ES over VNI 100; the candidate redefines
        // that same ESI so it also covers VNI 200.
        let current = runtime_candidate_from_toml(two_l2vni_one_es_runtime_candidate_toml());
        let coordinator = Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
            current.instances().clone(),
            current.ip_vrfs().clone(),
            current.ethernet_segments().to_vec(),
        )));
        let apply_lock = tokio::sync::Mutex::new(());
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _rib = runtime_converger_rib_responder(rib_rx, injects);

        let instances = Arc::new(current.instances().clone());
        let segment_handle = evpn_segment::spawn(
            &instances,
            current.ethernet_segments().to_vec(),
            rib_tx.clone(),
            None,
            BgpMetrics::new(),
            tokio_util::sync::CancellationToken::new(),
        )
        .expect("segment actor should spawn for non-empty ES config");

        let converger = EvpnRuntimeActorConverger {
            rib_tx,
            imet_controller: Arc::new(
                tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new()),
            ),
            dataplane: None,
            originator: None,
            svi: None,
            l3_originator: None,
            segment: Some(segment_handle.runtime_control()),
        };

        let response = apply_evpn_runtime_request(
            &proto::ApplyEvpnRuntimeRequest {
                candidate_toml: two_l2vni_redefined_es_runtime_candidate_toml().to_string(),
                validate_only: false,
            },
            coordinator.as_ref(),
            &apply_lock,
            &converger,
        )
        .await
        .unwrap();

        assert_eq!(
            response.outcome,
            proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyCommitted as i32
        );
        assert_eq!(response.runtime.unwrap().generation, 2);
        {
            let guard = coordinator.lock().unwrap();
            assert_eq!(guard.model().generation().as_u64(), 2);
            assert_eq!(guard.model().ethernet_segments().len(), 1);
            assert_eq!(guard.model().ethernet_segments()[0].member_vnis.len(), 2);
        }
        segment_handle.shutdown().await;
    }

    #[test]
    fn validate_single_ethernet_segment_add_accepts_committed_runtime_added_member_vni() {
        let current = runtime_model_from_candidate_toml(two_l2vni_one_es_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(two_l2vni_two_es_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);

        let added_esi = validate_single_ethernet_segment_add(&current, &candidate, &plan).unwrap();
        assert_eq!(
            added_esi,
            rustbgpd_wire::EthernetSegmentIdentifier::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 2])
        );
    }

    #[test]
    fn validate_single_ethernet_segment_add_rejects_unknown_member_vni() {
        let current = runtime_model_from_candidate_toml(two_l2vni_one_es_runtime_candidate_toml());
        let esi = rustbgpd_wire::EthernetSegmentIdentifier::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let member_vnis =
            std::collections::BTreeSet::from([rustbgpd_evpn::EvpnInstanceId::new(300).unwrap()]);

        let error =
            validate_ethernet_segment_member_vnis_present(esi, &member_vnis, current.instances())
                .unwrap_err();
        let DaemonEvpnRuntimeConvergeError::Unsupported(message) = error else {
            panic!("expected unsupported error, got {error:?}");
        };
        assert!(
            message.contains("unknown member VNI 300"),
            "unexpected error message: {message}"
        );
    }

    #[test]
    fn validate_single_ethernet_segment_redefine_accepts_one_redefined_segment() {
        let current = runtime_model_from_candidate_toml(two_l2vni_one_es_runtime_candidate_toml());
        let candidate =
            runtime_candidate_from_toml(two_l2vni_redefined_es_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);

        let redefined_esi =
            validate_single_ethernet_segment_redefine(&current, &candidate, &plan).unwrap();
        assert_eq!(
            redefined_esi,
            rustbgpd_wire::EthernetSegmentIdentifier::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        );
    }

    #[test]
    fn validate_single_ethernet_segment_redefine_accepts_committed_runtime_added_member_vni() {
        let current = runtime_model_from_candidate_toml(two_l2vni_one_es_runtime_candidate_toml());
        let candidate =
            runtime_candidate_from_toml(two_l2vni_redefined_es_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);

        let redefined_esi =
            validate_single_ethernet_segment_redefine(&current, &candidate, &plan).unwrap();
        assert_eq!(
            redefined_esi,
            rustbgpd_wire::EthernetSegmentIdentifier::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        );
    }

    #[test]
    fn validate_single_ethernet_segment_delete_accepts_one_removed_segment() {
        let current = runtime_model_from_candidate_toml(two_l2vni_two_es_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(two_l2vni_one_es_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);

        let deleted_esi =
            validate_single_ethernet_segment_delete(&current, &candidate, &plan).unwrap();
        assert_eq!(
            deleted_esi,
            rustbgpd_wire::EthernetSegmentIdentifier::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 2])
        );
    }

    #[tokio::test]
    async fn apply_evpn_runtime_convergence_failure_marks_runtime_failed() {
        let coordinator = empty_evpn_runtime_coordinator();
        let apply_lock = tokio::sync::Mutex::new(());
        let converger = TestRuntimeConverger::failed("RIB unavailable");

        let error = apply_evpn_runtime_request(
            &proto::ApplyEvpnRuntimeRequest {
                candidate_toml: l2vni_runtime_candidate_toml().to_string(),
                validate_only: false,
            },
            coordinator.as_ref(),
            &apply_lock,
            &converger,
        )
        .await
        .unwrap_err();

        assert!(matches!(
            error,
            GrpcEvpnRuntimeApplyError::FailedPrecondition(_)
        ));
        let snapshot = coordinator.lock().unwrap().snapshot();
        assert_eq!(snapshot.generation.as_u64(), 1);
        assert_eq!(
            snapshot.lifecycle,
            rustbgpd_evpn::EvpnRuntimeLifecycle::Degraded
        );
        assert_eq!(
            snapshot.mutation_state,
            rustbgpd_evpn::EvpnRuntimeMutationState::Failed
        );
    }

    #[tokio::test]
    async fn runtime_actor_converger_l2vni_add_publishes_imet_and_actor_models() {
        let current =
            runtime_model_from_candidate_toml(l2vni_linked_ip_vrf_runtime_candidate_toml());
        let candidate =
            runtime_candidate_from_toml(two_l2vni_linked_ip_vrf_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);
        let current_instances = Arc::new(current.instances().clone());
        let current_ip_vrfs = Arc::new(current.ip_vrfs().clone());
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(32);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _rib = runtime_converger_rib_responder(rib_rx, injects.clone());

        let (evpn_instances_tx, evpn_instances_rx) = watch::channel(current_instances.clone());
        let (ip_vrfs_tx, ip_vrfs_rx) = watch::channel(current_ip_vrfs);
        let (bum_enforcement_tx, _bum_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
        let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
            watch::channel(Arc::new(evpn_dataplane::RemoteIpPrefixDropCounts::new()));
        let (report_tx, _) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(1);
        let dataplane_handle = evpn_dataplane::EvpnDataplaneHandle {
            shutdown: tokio_util::sync::CancellationToken::new(),
            supervisor_join: tokio::spawn(async {}),
            actor_join: tokio::spawn(async {}),
            local_mac_rx: None,
            report_tx,
            bum_enforcement_tx,
            evpn_instances_tx,
            ip_vrfs_tx,
            remote_prefix_drop_counts_rx,
        };
        let (_local_tx, local_rx) = mpsc::channel(1);
        let originator_handle = evpn_originator::spawn(
            evpn_originator::OriginatorConfig::default(),
            &current_instances,
            rib_tx.clone(),
            Some(local_rx),
            BgpMetrics::new(),
            evpn_originator::OriginatedLocalMacCounts::default(),
            tokio_util::sync::CancellationToken::new(),
            evpn_vni_to_esi_map(current.ethernet_segments()),
        )
        .expect("originator should spawn for non-empty current model");
        let converger = EvpnRuntimeActorConverger {
            rib_tx,
            imet_controller: Arc::new(
                tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new()),
            ),
            dataplane: Some(dataplane_handle.runtime_control()),
            originator: Some(originator_handle.runtime_control()),
            svi: None,
            l3_originator: None,
            segment: None,
        };

        converger
            .converge(&current, &candidate, &plan)
            .await
            .unwrap();

        let added_vni = rustbgpd_evpn::EvpnInstanceId::new(200).unwrap();
        assert!(evpn_instances_rx.borrow().get(added_vni).is_some());
        assert!(
            ip_vrfs_rx
                .borrow()
                .referenced_l2vnis("tenant-blue")
                .is_some_and(|vnis| vnis.contains(&added_vni)),
            "dataplane IP-VRF model should learn that the runtime-added L2VNI is linked to tenant-blue"
        );
        assert!(
            injects
                .lock()
                .await
                .iter()
                .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::Imet { .. })),
            "L2VNI add should originate an IMET route before generation commit"
        );
        originator_handle.shutdown().await;
        dataplane_handle.shutdown().await;
    }

    #[tokio::test]
    async fn runtime_actor_converger_l2vni_add_updates_segment_instance_view() {
        let current = runtime_model_from_candidate_toml(l2vni_one_es_runtime_candidate_toml());
        let l2_candidate = runtime_candidate_from_toml(two_l2vni_one_es_runtime_candidate_toml());
        let l2_plan = current.plan_candidate(&l2_candidate);
        let current_after_l2 =
            runtime_model_from_candidate_toml(two_l2vni_one_es_runtime_candidate_toml());
        let es_candidate = runtime_candidate_from_toml(two_l2vni_two_es_runtime_candidate_toml());
        let es_plan = current_after_l2.plan_candidate(&es_candidate);
        let current_instances = Arc::new(current.instances().clone());

        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(128);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws);

        let (evpn_instances_tx, _evpn_instances_rx) = watch::channel(current_instances.clone());
        let (ip_vrfs_tx, _ip_vrfs_rx) = watch::channel(Arc::new(rustbgpd_evpn::IpVrfTable::new()));
        let (bum_enforcement_tx, _bum_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
        let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
            watch::channel(Arc::new(evpn_dataplane::RemoteIpPrefixDropCounts::new()));
        let (report_tx, _) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(1);
        let dataplane_handle = evpn_dataplane::EvpnDataplaneHandle {
            shutdown: tokio_util::sync::CancellationToken::new(),
            supervisor_join: tokio::spawn(async {}),
            actor_join: tokio::spawn(async {}),
            local_mac_rx: None,
            report_tx,
            bum_enforcement_tx,
            evpn_instances_tx,
            ip_vrfs_tx,
            remote_prefix_drop_counts_rx,
        };
        let (_local_tx, local_rx) = mpsc::channel(1);
        let originator_handle = evpn_originator::spawn(
            evpn_originator::OriginatorConfig::default(),
            &current_instances,
            rib_tx.clone(),
            Some(local_rx),
            BgpMetrics::new(),
            evpn_originator::OriginatedLocalMacCounts::default(),
            tokio_util::sync::CancellationToken::new(),
            evpn_vni_to_esi_map(current.ethernet_segments()),
        )
        .expect("originator should spawn for non-empty current model");
        let segment_handle = evpn_segment::spawn(
            &current_instances,
            current.ethernet_segments().to_vec(),
            rib_tx.clone(),
            None,
            BgpMetrics::new(),
            tokio_util::sync::CancellationToken::new(),
        )
        .expect("segment actor should spawn for non-empty ES config");

        let converger = EvpnRuntimeActorConverger {
            rib_tx,
            imet_controller: Arc::new(
                tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new()),
            ),
            dataplane: Some(dataplane_handle.runtime_control()),
            originator: Some(originator_handle.runtime_control()),
            svi: None,
            l3_originator: None,
            segment: Some(segment_handle.runtime_control()),
        };

        converger
            .converge(&current, &l2_candidate, &l2_plan)
            .await
            .unwrap();
        converger
            .converge(&current_after_l2, &es_candidate, &es_plan)
            .await
            .unwrap();

        let deadline = StdInstant::now() + Duration::from_secs(2);
        loop {
            let observed = injects.lock().await.clone();
            if observed.iter().any(|key| {
                matches!(
                    key,
                    rustbgpd_wire::EvpnRouteKey::EadPerEvi {
                        ethernet_tag,
                        ..
                    } if ethernet_tag.0 == 200
                )
            }) {
                break;
            }
            assert!(
                StdInstant::now() < deadline,
                "timed out waiting for EAD-per-EVI over runtime-added VNI; observed {observed:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        segment_handle.shutdown().await;
        originator_handle.shutdown().await;
        dataplane_handle.shutdown().await;
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "actor convergence regression sets up dataplane, IMET, and Type 2 controls end to end"
    )]
    async fn runtime_actor_converger_l2vni_delete_drains_imet_and_actor_models() {
        let current = runtime_model_from_candidate_toml(two_l2vni_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(l2vni_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);
        let current_instances = Arc::new(current.instances().clone());
        let deleted_vni = rustbgpd_evpn::EvpnInstanceId::new(200).unwrap();

        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

        let (evpn_instances_tx, evpn_instances_rx) = watch::channel(current_instances.clone());
        let (ip_vrfs_tx, _ip_vrfs_rx) = watch::channel(Arc::new(rustbgpd_evpn::IpVrfTable::new()));
        let (bum_enforcement_tx, _bum_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
        let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
            watch::channel(Arc::new(evpn_dataplane::RemoteIpPrefixDropCounts::new()));
        let (report_tx, _) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(1);
        let dataplane_handle = evpn_dataplane::EvpnDataplaneHandle {
            shutdown: tokio_util::sync::CancellationToken::new(),
            supervisor_join: tokio::spawn(async {}),
            actor_join: tokio::spawn(async {}),
            local_mac_rx: None,
            report_tx,
            bum_enforcement_tx,
            evpn_instances_tx,
            ip_vrfs_tx,
            remote_prefix_drop_counts_rx,
        };
        let (local_tx, local_rx) = mpsc::channel(8);
        let originator_handle = evpn_originator::spawn(
            evpn_originator::OriginatorConfig::default(),
            &current_instances,
            rib_tx.clone(),
            Some(local_rx),
            BgpMetrics::new(),
            evpn_originator::OriginatedLocalMacCounts::default(),
            tokio_util::sync::CancellationToken::new(),
            evpn_vni_to_esi_map(current.ethernet_segments()),
        )
        .expect("originator should spawn for non-empty current model");
        let mut imet_controller = evpn_imet::EvpnImetController::new();
        let imet_keys = imet_controller
            .originate_all(current.instances().iter().cloned(), &rib_tx)
            .await;
        assert_eq!(imet_keys.len(), 2);

        // Prove the originator has live local state on the deleted VNI,
        // so the delete convergence has a Type 2 drain to perform.
        local_tx
            .send(rustbgpd_evpn::LocalMacObservation::Learned {
                vni: deleted_vni,
                mac: rustbgpd_evpn::MacAddress::new([0x02, 0, 0, 0, 0, 0xcc]),
                ifindex: 20,
            })
            .await
            .unwrap();
        let mac_inject_deadline = StdInstant::now() + Duration::from_secs(2);
        loop {
            if injects
                .lock()
                .await
                .iter()
                .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::MacIp { .. }))
            {
                break;
            }
            assert!(
                StdInstant::now() < mac_inject_deadline,
                "originator did not originate the VNI 200 local MAC"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let converger = EvpnRuntimeActorConverger {
            rib_tx,
            imet_controller: Arc::new(tokio::sync::Mutex::new(imet_controller)),
            dataplane: Some(dataplane_handle.runtime_control()),
            originator: Some(originator_handle.runtime_control()),
            svi: None,
            l3_originator: None,
            segment: None,
        };

        converger
            .converge(&current, &candidate, &plan)
            .await
            .unwrap();

        assert!(evpn_instances_rx.borrow().get(deleted_vni).is_none());
        assert!(
            withdraws
                .lock()
                .await
                .iter()
                .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::Imet { .. })),
            "L2VNI delete should withdraw the removed VNI's IMET route before generation commit"
        );

        let mac_withdraw_deadline = StdInstant::now() + Duration::from_secs(2);
        loop {
            if withdraws
                .lock()
                .await
                .iter()
                .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::MacIp { .. }))
            {
                break;
            }
            assert!(
                StdInstant::now() < mac_withdraw_deadline,
                "L2VNI delete did not drain the removed VNI's local MAC"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        originator_handle.shutdown().await;
        dataplane_handle.shutdown().await;
    }

    #[tokio::test]
    async fn runtime_actor_converger_l2vni_delete_publishes_ip_vrf_metadata() {
        let current =
            runtime_model_from_candidate_toml(l2vni_linked_ip_vrf_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(ip_vrf_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);
        let current_instances = Arc::new(current.instances().clone());
        let current_ip_vrfs = Arc::new(current.ip_vrfs().clone());
        let deleted_vni = rustbgpd_evpn::EvpnInstanceId::new(100).unwrap();

        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

        let (evpn_instances_tx, evpn_instances_rx) = watch::channel(current_instances.clone());
        let (ip_vrfs_tx, ip_vrfs_rx) = watch::channel(current_ip_vrfs);
        let (bum_enforcement_tx, _bum_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
        let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
            watch::channel(Arc::new(evpn_dataplane::RemoteIpPrefixDropCounts::new()));
        let (report_tx, _) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(1);
        let dataplane_handle = evpn_dataplane::EvpnDataplaneHandle {
            shutdown: tokio_util::sync::CancellationToken::new(),
            supervisor_join: tokio::spawn(async {}),
            actor_join: tokio::spawn(async {}),
            local_mac_rx: None,
            report_tx,
            bum_enforcement_tx,
            evpn_instances_tx,
            ip_vrfs_tx,
            remote_prefix_drop_counts_rx,
        };
        let (_local_tx, local_rx) = mpsc::channel(1);
        let originator_handle = evpn_originator::spawn(
            evpn_originator::OriginatorConfig::default(),
            &current_instances,
            rib_tx.clone(),
            Some(local_rx),
            BgpMetrics::new(),
            evpn_originator::OriginatedLocalMacCounts::default(),
            tokio_util::sync::CancellationToken::new(),
            evpn_vni_to_esi_map(current.ethernet_segments()),
        )
        .expect("originator should spawn for non-empty current model");
        let mut imet_controller = evpn_imet::EvpnImetController::new();
        let imet_keys = imet_controller
            .originate_all(current.instances().iter().cloned(), &rib_tx)
            .await;
        assert_eq!(imet_keys.len(), 1);

        let converger = EvpnRuntimeActorConverger {
            rib_tx,
            imet_controller: Arc::new(tokio::sync::Mutex::new(imet_controller)),
            dataplane: Some(dataplane_handle.runtime_control()),
            originator: Some(originator_handle.runtime_control()),
            svi: None,
            l3_originator: None,
            segment: None,
        };

        converger
            .converge(&current, &candidate, &plan)
            .await
            .unwrap();

        assert!(evpn_instances_rx.borrow().get(deleted_vni).is_none());
        assert!(
            !ip_vrfs_rx.borrow().is_referenced("tenant-blue"),
            "dataplane IP-VRF model should drop the deleted L2VNI's tenant binding"
        );
        assert!(
            withdraws
                .lock()
                .await
                .iter()
                .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::Imet { .. })),
            "IP-VRF-linked L2VNI delete should still withdraw the removed VNI's IMET route"
        );

        originator_handle.shutdown().await;
        dataplane_handle.shutdown().await;
    }

    #[test]
    fn validate_single_l2vni_delete_allows_unlinked_ip_vrf_table() {
        let current =
            runtime_model_from_candidate_toml(two_l2vni_one_ip_vrf_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(l2vni_one_ip_vrf_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);

        let deleted = validate_single_l2vni_delete(&current, &candidate, &plan).unwrap();
        assert_eq!(deleted.id, rustbgpd_evpn::EvpnInstanceId::new(200).unwrap());
    }

    #[test]
    fn validate_single_l2vni_delete_allows_ip_vrf_link_metadata_update() {
        let current =
            runtime_model_from_candidate_toml(l2vni_linked_ip_vrf_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(ip_vrf_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);

        assert!(
            !plan.ip_vrfs.has_changes(),
            "IP-VRF row changes should stay fail-closed; this case only changes link metadata"
        );
        assert_ne!(current.ip_vrfs(), candidate.ip_vrfs());
        let deleted = validate_single_l2vni_delete(&current, &candidate, &plan).unwrap();
        assert_eq!(deleted.id, rustbgpd_evpn::EvpnInstanceId::new(100).unwrap());
    }

    #[test]
    fn validate_single_l2vni_delete_allows_remaining_ip_vrf_link_metadata() {
        let current =
            runtime_model_from_candidate_toml(two_l2vni_linked_ip_vrf_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(l2vni_linked_ip_vrf_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);

        let deleted = validate_single_l2vni_delete(&current, &candidate, &plan).unwrap();
        assert_eq!(deleted.id, rustbgpd_evpn::EvpnInstanceId::new(200).unwrap());
        assert!(
            candidate
                .ip_vrfs()
                .referenced_l2vnis("tenant-blue")
                .is_some_and(|vnis| {
                    vnis == &std::collections::BTreeSet::from([rustbgpd_evpn::EvpnInstanceId::new(
                        100,
                    )
                    .unwrap()])
                })
        );
    }

    #[test]
    fn validate_single_l2vni_delete_rejects_mixed_ip_vrf_link_metadata_update() {
        let current =
            runtime_model_from_candidate_toml(two_l2vni_linked_ip_vrf_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(l2vni_one_ip_vrf_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);

        assert_eq!(plan.evpn_instances.deleted, vec![200]);
        assert!(
            !plan.ip_vrfs.has_changes(),
            "IP-VRF row diffing intentionally ignores link metadata"
        );
        let error = validate_single_l2vni_delete(&current, &candidate, &plan).unwrap_err();
        let DaemonEvpnRuntimeConvergeError::Unsupported(message) = error else {
            panic!("expected unsupported error, got {error:?}");
        };
        assert!(
            message.contains("candidate IP-VRF link metadata for \"tenant-blue\""),
            "unexpected error message: {message}"
        );
    }

    #[tokio::test]
    async fn runtime_actor_converger_ip_vrf_add_publishes_dataplane_model() {
        let current = runtime_model_from_candidate_toml(ip_vrf_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(two_ip_vrf_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);
        let current_instances = Arc::new(current.instances().clone());
        let current_ip_vrfs = Arc::new(current.ip_vrfs().clone());
        let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(32);

        let (evpn_instances_tx, _evpn_instances_rx) = watch::channel(current_instances);
        let (ip_vrfs_tx, ip_vrfs_rx) = watch::channel(current_ip_vrfs.clone());
        let (bum_enforcement_tx, _bum_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
        let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
            watch::channel(Arc::new(evpn_dataplane::RemoteIpPrefixDropCounts::new()));
        let (report_tx, _) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(1);
        let dataplane_handle = evpn_dataplane::EvpnDataplaneHandle {
            shutdown: tokio_util::sync::CancellationToken::new(),
            supervisor_join: tokio::spawn(async {}),
            actor_join: tokio::spawn(async {}),
            local_mac_rx: None,
            report_tx,
            bum_enforcement_tx,
            evpn_instances_tx,
            ip_vrfs_tx,
            remote_prefix_drop_counts_rx,
        };
        let (_obs_tx, obs_rx) = watch::channel(Arc::new(std::collections::HashMap::<
            rustbgpd_evpn::IpVrfId,
            Vec<rustbgpd_evpn::ip_vrf::LocalIpRouteObservation>,
        >::new()));
        let (_status_tx, status_rx) =
            watch::channel(Vec::<rustbgpd_evpn::IpVrfDataplaneStatus>::new());
        let l3_handle = evpn_l3_originator::spawn(evpn_l3_originator::SpawnConfig {
            ip_vrfs: current_ip_vrfs,
            rib_tx: rib_tx.clone(),
            route_observations_rx: obs_rx,
            ip_vrf_status_rx: status_rx,
            metrics: BgpMetrics::new(),
            originated_counts: evpn_l3_originator::OriginatedIpVrfRouteCounts::default(),
            shutdown: tokio_util::sync::CancellationToken::new(),
        })
        .expect("L3 originator should spawn for non-empty current model");
        let converger = EvpnRuntimeActorConverger {
            rib_tx,
            imet_controller: Arc::new(
                tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new()),
            ),
            dataplane: Some(dataplane_handle.runtime_control()),
            originator: None,
            svi: None,
            l3_originator: Some(l3_handle.runtime_control()),
            segment: None,
        };

        converger
            .converge(&current, &candidate, &plan)
            .await
            .unwrap();

        assert!(ip_vrfs_rx.borrow().get("tenant-green").is_some());
        l3_handle.shutdown().await;
        dataplane_handle.shutdown().await;
    }

    #[tokio::test]
    async fn runtime_actor_converger_ip_vrf_delete_publishes_dataplane_and_l3_model() {
        let current = runtime_model_from_candidate_toml(two_ip_vrf_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(ip_vrf_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);
        let current_instances = Arc::new(current.instances().clone());
        let current_ip_vrfs = Arc::new(current.ip_vrfs().clone());
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

        let (evpn_instances_tx, _evpn_instances_rx) = watch::channel(current_instances);
        let (ip_vrfs_tx, ip_vrfs_rx) = watch::channel(current_ip_vrfs.clone());
        let (bum_enforcement_tx, _bum_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
        let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
            watch::channel(Arc::new(evpn_dataplane::RemoteIpPrefixDropCounts::new()));
        let (report_tx, _) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(1);
        let dataplane_handle = evpn_dataplane::EvpnDataplaneHandle {
            shutdown: tokio_util::sync::CancellationToken::new(),
            supervisor_join: tokio::spawn(async {}),
            actor_join: tokio::spawn(async {}),
            local_mac_rx: None,
            report_tx,
            bum_enforcement_tx,
            evpn_instances_tx,
            ip_vrfs_tx,
            remote_prefix_drop_counts_rx,
        };
        let (obs_tx, obs_rx) = watch::channel(Arc::new(std::collections::HashMap::<
            rustbgpd_evpn::IpVrfId,
            Vec<rustbgpd_evpn::ip_vrf::LocalIpRouteObservation>,
        >::new()));
        let (status_tx, status_rx) =
            watch::channel(Vec::<rustbgpd_evpn::IpVrfDataplaneStatus>::new());
        let l3_handle = evpn_l3_originator::spawn(evpn_l3_originator::SpawnConfig {
            ip_vrfs: current_ip_vrfs,
            rib_tx: rib_tx.clone(),
            route_observations_rx: obs_rx,
            ip_vrf_status_rx: status_rx,
            metrics: BgpMetrics::new(),
            originated_counts: evpn_l3_originator::OriginatedIpVrfRouteCounts::default(),
            shutdown: tokio_util::sync::CancellationToken::new(),
        })
        .expect("L3 originator should spawn for non-empty current model");
        let green_id = rustbgpd_evpn::IpVrfId::new(6000).unwrap();
        status_tx.send_replace(vec![runtime_ip_vrf_ready_status(green_id, "tenant-green")]);
        let mut observations = std::collections::HashMap::new();
        observations.insert(green_id, vec![runtime_local_ip_observation(green_id)]);
        obs_tx.send_replace(Arc::new(observations));
        wait_for_recorded_evpn_key(
            &injects,
            "Type 5 originator should inject tenant-green before delete",
        )
        .await;

        let converger = EvpnRuntimeActorConverger {
            rib_tx,
            imet_controller: Arc::new(
                tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new()),
            ),
            dataplane: Some(dataplane_handle.runtime_control()),
            originator: None,
            svi: None,
            l3_originator: Some(l3_handle.runtime_control()),
            segment: None,
        };

        converger
            .converge(&current, &candidate, &plan)
            .await
            .unwrap();

        assert!(ip_vrfs_rx.borrow().get("tenant-green").is_none());
        assert!(ip_vrfs_rx.borrow().get("tenant-blue").is_some());
        wait_for_recorded_evpn_key(
            &withdraws,
            "Type 5 originator should withdraw tenant-green after delete",
        )
        .await;
        l3_handle.shutdown().await;
        dataplane_handle.shutdown().await;
    }

    #[tokio::test]
    async fn runtime_actor_converger_ethernet_segment_add_publishes_es_routes() {
        // current = one ES over VNI 100 (actor spawned); candidate adds a
        // second ES over VNI 200 (one local ES per VNI).
        let current = runtime_model_from_candidate_toml(two_l2vni_one_es_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(two_l2vni_two_es_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);
        let instances = Arc::new(current.instances().clone());
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _rib = runtime_converger_rib_responder(rib_rx, injects.clone());

        let segment_handle = evpn_segment::spawn(
            &instances,
            current.ethernet_segments().to_vec(),
            rib_tx.clone(),
            None,
            BgpMetrics::new(),
            tokio_util::sync::CancellationToken::new(),
        )
        .expect("segment actor should spawn for non-empty ES config");

        let converger = EvpnRuntimeActorConverger {
            rib_tx,
            imet_controller: Arc::new(
                tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new()),
            ),
            dataplane: None,
            originator: None,
            svi: None,
            l3_originator: None,
            segment: Some(segment_handle.runtime_control()),
        };

        converger
            .converge(&current, &candidate, &plan)
            .await
            .unwrap();

        // The segment actor consumes the new ES snapshot asynchronously and
        // re-originates Type 4 ES + Type 1 EAD-per-ES + EAD-per-EVI for the
        // full set. Poll until at least two ES (Type 4) routes are seen,
        // proving the added ES drove origination past the single startup ES.
        let deadline = StdInstant::now() + Duration::from_secs(2);
        loop {
            let observed = injects.lock().await.clone();
            let es = observed
                .iter()
                .filter(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::Es { .. }))
                .count();
            let has_ead_es = observed
                .iter()
                .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::EadPerEs { .. }));
            let has_ead_evi = observed
                .iter()
                .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::EadPerEvi { .. }));
            if es >= 2 && has_ead_es && has_ead_evi {
                break;
            }
            assert!(
                StdInstant::now() < deadline,
                "timed out waiting for ES routes; observed {observed:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        segment_handle.shutdown().await;
    }

    #[tokio::test]
    async fn runtime_actor_converger_ethernet_segment_add_restamps_member_vni_local_macs() {
        // Adding an ES over VNI 200 must republish the Type 2 originator's
        // vni->esi map so its local MACs stop carrying ESI=0. The
        // originator drains the member VNI's stale local routes on the map
        // change — observe that drain (a MacIp withdraw) as proof the
        // originator model was republished by the ES-add converger.
        let current = runtime_model_from_candidate_toml(two_l2vni_one_es_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(two_l2vni_two_es_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);
        let current_instances = Arc::new(current.instances().clone());

        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

        let (local_tx, local_rx) = mpsc::channel(8);
        let originator_handle = evpn_originator::spawn(
            evpn_originator::OriginatorConfig::default(),
            &current_instances,
            rib_tx.clone(),
            Some(local_rx),
            BgpMetrics::new(),
            evpn_originator::OriginatedLocalMacCounts::default(),
            tokio_util::sync::CancellationToken::new(),
            evpn_vni_to_esi_map(current.ethernet_segments()),
        )
        .expect("originator should spawn for non-empty current model");
        let segment_handle = evpn_segment::spawn(
            &current_instances,
            current.ethernet_segments().to_vec(),
            rib_tx.clone(),
            None,
            BgpMetrics::new(),
            tokio_util::sync::CancellationToken::new(),
        )
        .expect("segment actor should spawn for non-empty ES config");

        // Learn a local MAC on the to-be-segment-bound VNI 200; the
        // originator originates a MAC-only Type 2 (ESI 0 — VNI 200 has no
        // segment yet).
        local_tx
            .send(rustbgpd_evpn::LocalMacObservation::Learned {
                vni: rustbgpd_evpn::EvpnInstanceId::new(200).unwrap(),
                mac: rustbgpd_evpn::MacAddress::new([0x02, 0, 0, 0, 0, 0xbb]),
                ifindex: 20,
            })
            .await
            .unwrap();
        let mac_inject_deadline = StdInstant::now() + Duration::from_secs(2);
        loop {
            if injects
                .lock()
                .await
                .iter()
                .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::MacIp { .. }))
            {
                break;
            }
            assert!(
                StdInstant::now() < mac_inject_deadline,
                "originator did not originate the VNI 200 local MAC"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let converger = EvpnRuntimeActorConverger {
            rib_tx,
            imet_controller: Arc::new(
                tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new()),
            ),
            dataplane: None,
            originator: Some(originator_handle.runtime_control()),
            svi: None,
            l3_originator: None,
            segment: Some(segment_handle.runtime_control()),
        };

        converger
            .converge(&current, &candidate, &plan)
            .await
            .unwrap();

        // The originator must drain VNI 200's now-stale ESI=0 local MAC
        // (then re-originate under the segment's ESI). Seeing the MacIp
        // withdraw proves the ES-add converger republished the originator
        // runtime model — without that, the originator would keep
        // advertising the member VNI with ESI 0.
        let drain_deadline = StdInstant::now() + Duration::from_secs(2);
        loop {
            if withdraws
                .lock()
                .await
                .iter()
                .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::MacIp { .. }))
            {
                break;
            }
            assert!(
                StdInstant::now() < drain_deadline,
                "ES add did not republish the originator model (no local MAC drain observed)"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        originator_handle.shutdown().await;
        segment_handle.shutdown().await;
    }

    #[tokio::test]
    async fn runtime_actor_converger_ethernet_segment_redefine_rebuilds_es_routes() {
        let current = runtime_model_from_candidate_toml(two_l2vni_one_es_runtime_candidate_toml());
        let candidate =
            runtime_candidate_from_toml(two_l2vni_redefined_es_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);
        let current_instances = Arc::new(current.instances().clone());
        let redefined_esi =
            rustbgpd_wire::EthernetSegmentIdentifier::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

        let segment_handle = evpn_segment::spawn(
            &current_instances,
            current.ethernet_segments().to_vec(),
            rib_tx.clone(),
            None,
            BgpMetrics::new(),
            tokio_util::sync::CancellationToken::new(),
        )
        .expect("segment actor should spawn for non-empty ES config");

        let initial_deadline = StdInstant::now() + Duration::from_secs(2);
        loop {
            if injects.lock().await.iter().any(|key| {
                matches!(
                    key,
                    rustbgpd_wire::EvpnRouteKey::EadPerEvi {
                        esi,
                        ethernet_tag,
                        ..
                    } if *esi == redefined_esi && ethernet_tag.0 == 100
                )
            }) {
                break;
            }
            assert!(
                StdInstant::now() < initial_deadline,
                "timed out waiting for initial ES EAD-per-EVI route"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let converger = EvpnRuntimeActorConverger {
            rib_tx,
            imet_controller: Arc::new(
                tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new()),
            ),
            dataplane: None,
            originator: None,
            svi: None,
            l3_originator: None,
            segment: Some(segment_handle.runtime_control()),
        };

        converger
            .converge(&current, &candidate, &plan)
            .await
            .unwrap();

        let redefine_deadline = StdInstant::now() + Duration::from_secs(2);
        loop {
            let drained = withdraws.lock().await.clone();
            let injected = injects.lock().await.clone();
            let drained_old_evi = drained.iter().any(|key| {
                matches!(
                    key,
                    rustbgpd_wire::EvpnRouteKey::EadPerEvi {
                        esi,
                        ethernet_tag,
                        ..
                    } if *esi == redefined_esi && ethernet_tag.0 == 100
                )
            });
            let injected_new_evi = injected.iter().any(|key| {
                matches!(
                    key,
                    rustbgpd_wire::EvpnRouteKey::EadPerEvi {
                        esi,
                        ethernet_tag,
                        ..
                    } if *esi == redefined_esi && ethernet_tag.0 == 200
                )
            });
            if drained_old_evi && injected_new_evi {
                break;
            }
            assert!(
                StdInstant::now() < redefine_deadline,
                "ES redefine did not drain/rebuild EAD-per-EVI routes; drained {drained:?}, injected {injected:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        segment_handle.shutdown().await;
    }

    #[tokio::test]
    async fn runtime_actor_converger_ethernet_segment_redefine_restamps_member_vni_local_macs() {
        let current = runtime_model_from_candidate_toml(two_l2vni_one_es_runtime_candidate_toml());
        let candidate =
            runtime_candidate_from_toml(two_l2vni_redefined_es_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);
        let current_instances = Arc::new(current.instances().clone());

        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

        let (local_tx, local_rx) = mpsc::channel(8);
        let originator_handle = evpn_originator::spawn(
            evpn_originator::OriginatorConfig::default(),
            &current_instances,
            rib_tx.clone(),
            Some(local_rx),
            BgpMetrics::new(),
            evpn_originator::OriginatedLocalMacCounts::default(),
            tokio_util::sync::CancellationToken::new(),
            evpn_vni_to_esi_map(current.ethernet_segments()),
        )
        .expect("originator should spawn for non-empty current model");
        let segment_handle = evpn_segment::spawn(
            &current_instances,
            current.ethernet_segments().to_vec(),
            rib_tx.clone(),
            None,
            BgpMetrics::new(),
            tokio_util::sync::CancellationToken::new(),
        )
        .expect("segment actor should spawn for non-empty ES config");

        local_tx
            .send(rustbgpd_evpn::LocalMacObservation::Learned {
                vni: rustbgpd_evpn::EvpnInstanceId::new(200).unwrap(),
                mac: rustbgpd_evpn::MacAddress::new([0x02, 0, 0, 0, 0, 0xee]),
                ifindex: 20,
            })
            .await
            .unwrap();
        let mac_inject_deadline = StdInstant::now() + Duration::from_secs(2);
        loop {
            if injects
                .lock()
                .await
                .iter()
                .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::MacIp { .. }))
            {
                break;
            }
            assert!(
                StdInstant::now() < mac_inject_deadline,
                "originator did not originate the VNI 200 local MAC"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let converger = EvpnRuntimeActorConverger {
            rib_tx,
            imet_controller: Arc::new(
                tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new()),
            ),
            dataplane: None,
            originator: Some(originator_handle.runtime_control()),
            svi: None,
            l3_originator: None,
            segment: Some(segment_handle.runtime_control()),
        };

        converger
            .converge(&current, &candidate, &plan)
            .await
            .unwrap();

        let drain_deadline = StdInstant::now() + Duration::from_secs(2);
        loop {
            if withdraws
                .lock()
                .await
                .iter()
                .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::MacIp { .. }))
            {
                break;
            }
            assert!(
                StdInstant::now() < drain_deadline,
                "ES redefine did not republish the originator model (no local MAC drain observed)"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        originator_handle.shutdown().await;
        segment_handle.shutdown().await;
    }

    #[tokio::test]
    async fn runtime_actor_converger_ethernet_segment_delete_drains_es_routes() {
        let current = runtime_model_from_candidate_toml(two_l2vni_two_es_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(two_l2vni_one_es_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);
        let current_instances = Arc::new(current.instances().clone());
        let removed_esi =
            rustbgpd_wire::EthernetSegmentIdentifier::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

        let segment_handle = evpn_segment::spawn(
            &current_instances,
            current.ethernet_segments().to_vec(),
            rib_tx.clone(),
            None,
            BgpMetrics::new(),
            tokio_util::sync::CancellationToken::new(),
        )
        .expect("segment actor should spawn for non-empty ES config");

        let initial_deadline = StdInstant::now() + Duration::from_secs(2);
        loop {
            let observed = injects.lock().await.clone();
            let has_es = observed
                .iter()
                .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::Es { esi, .. } if *esi == removed_esi));
            let has_ead_es = observed.iter().any(|key| {
                matches!(key, rustbgpd_wire::EvpnRouteKey::EadPerEs { esi, .. } if *esi == removed_esi)
            });
            let has_ead_evi = observed.iter().any(|key| {
                matches!(key, rustbgpd_wire::EvpnRouteKey::EadPerEvi { esi, .. } if *esi == removed_esi)
            });
            if has_es && has_ead_es && has_ead_evi {
                break;
            }
            assert!(
                StdInstant::now() < initial_deadline,
                "timed out waiting for initial removed-ES routes; observed {observed:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let converger = EvpnRuntimeActorConverger {
            rib_tx,
            imet_controller: Arc::new(
                tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new()),
            ),
            dataplane: None,
            originator: None,
            svi: None,
            l3_originator: None,
            segment: Some(segment_handle.runtime_control()),
        };

        converger
            .converge(&current, &candidate, &plan)
            .await
            .unwrap();

        let drain_deadline = StdInstant::now() + Duration::from_secs(2);
        loop {
            let drained = withdraws.lock().await.clone();
            let has_es = drained
                .iter()
                .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::Es { esi, .. } if *esi == removed_esi));
            let has_ead_es = drained.iter().any(|key| {
                matches!(key, rustbgpd_wire::EvpnRouteKey::EadPerEs { esi, .. } if *esi == removed_esi)
            });
            let has_ead_evi = drained.iter().any(|key| {
                matches!(key, rustbgpd_wire::EvpnRouteKey::EadPerEvi { esi, .. } if *esi == removed_esi)
            });
            if has_es && has_ead_es && has_ead_evi {
                break;
            }
            assert!(
                StdInstant::now() < drain_deadline,
                "ES delete did not drain removed segment routes; drained {drained:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        segment_handle.shutdown().await;
    }

    #[tokio::test]
    async fn runtime_actor_converger_ethernet_segment_delete_restamps_member_vni_local_macs() {
        let current = runtime_model_from_candidate_toml(two_l2vni_two_es_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(two_l2vni_one_es_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);
        let current_instances = Arc::new(current.instances().clone());

        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

        let (local_tx, local_rx) = mpsc::channel(8);
        let originator_handle = evpn_originator::spawn(
            evpn_originator::OriginatorConfig::default(),
            &current_instances,
            rib_tx.clone(),
            Some(local_rx),
            BgpMetrics::new(),
            evpn_originator::OriginatedLocalMacCounts::default(),
            tokio_util::sync::CancellationToken::new(),
            evpn_vni_to_esi_map(current.ethernet_segments()),
        )
        .expect("originator should spawn for non-empty current model");
        let segment_handle = evpn_segment::spawn(
            &current_instances,
            current.ethernet_segments().to_vec(),
            rib_tx.clone(),
            None,
            BgpMetrics::new(),
            tokio_util::sync::CancellationToken::new(),
        )
        .expect("segment actor should spawn for non-empty ES config");

        local_tx
            .send(rustbgpd_evpn::LocalMacObservation::Learned {
                vni: rustbgpd_evpn::EvpnInstanceId::new(200).unwrap(),
                mac: rustbgpd_evpn::MacAddress::new([0x02, 0, 0, 0, 0, 0xdd]),
                ifindex: 20,
            })
            .await
            .unwrap();
        let mac_inject_deadline = StdInstant::now() + Duration::from_secs(2);
        loop {
            if injects
                .lock()
                .await
                .iter()
                .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::MacIp { .. }))
            {
                break;
            }
            assert!(
                StdInstant::now() < mac_inject_deadline,
                "originator did not originate the VNI 200 segmented local MAC"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let converger = EvpnRuntimeActorConverger {
            rib_tx,
            imet_controller: Arc::new(
                tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new()),
            ),
            dataplane: None,
            originator: Some(originator_handle.runtime_control()),
            svi: None,
            l3_originator: None,
            segment: Some(segment_handle.runtime_control()),
        };

        converger
            .converge(&current, &candidate, &plan)
            .await
            .unwrap();

        let drain_deadline = StdInstant::now() + Duration::from_secs(2);
        loop {
            if withdraws
                .lock()
                .await
                .iter()
                .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::MacIp { .. }))
            {
                break;
            }
            assert!(
                StdInstant::now() < drain_deadline,
                "ES delete did not republish the originator model (no local MAC drain observed)"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        originator_handle.shutdown().await;
        segment_handle.shutdown().await;
    }

    #[test]
    fn gr_restart_marker_round_trip() {
        let path = unique_temp_path("gr-restart-marker");
        let expires_at = SystemTime::now() + Duration::from_mins(2);
        write_gr_restart_marker(&path, expires_at).unwrap();
        let read_back = read_gr_restart_marker(&path).unwrap().unwrap();
        let diff = read_back
            .duration_since(expires_at)
            .unwrap_or_else(|e| e.duration());
        assert!(diff < Duration::from_secs(1));
        remove_gr_restart_marker(&path).unwrap();
    }

    #[test]
    fn gr_restart_marker_invalid_version_rejected() {
        let path = unique_temp_path("gr-restart-bad-version");
        std::fs::write(&path, "version = 2\nexpires_at_unix = 1\n").unwrap();
        let err = read_gr_restart_marker(&path).unwrap_err();
        assert!(err.contains("unsupported marker version"));
        remove_gr_restart_marker(&path).unwrap();
    }

    #[test]
    fn tcp_ao_listener_key_includes_peer_matching_listener_family() {
        let config = load_config_from_toml("listener-tcp-ao-v4", &tcp_ao_neighbor_toml("10.0.0.2"));
        let peer = config.resolved_neighbors().unwrap().pop().unwrap();

        let key = tcp_ao_listener_key_for_neighbor(config.listen_addr(), &peer).unwrap();

        assert_eq!(key.peer.to_string(), "10.0.0.2");
    }

    #[test]
    fn tcp_ao_listener_key_skips_peer_outside_listener_family() {
        let config =
            load_config_from_toml("listener-tcp-ao-v6", &tcp_ao_neighbor_toml("2001:db8::2"));
        let peer = config.resolved_neighbors().unwrap().pop().unwrap();

        assert!(tcp_ao_listener_key_for_neighbor(config.listen_addr(), &peer).is_none());
    }

    #[test]
    #[expect(clippy::too_many_lines)]
    fn max_gr_restart_time_uses_largest_enabled_peer() {
        let config = crate::config::Config {
            global: crate::config::Global {
                asn: 65001,
                router_id: "10.0.0.1".to_string(),
                listen_port: 179,
                cluster_id: None,
                runtime_state_dir: "/tmp".to_string(),
                telemetry: crate::config::TelemetryConfig {
                    prometheus_addr: Some("127.0.0.1:9179".to_string()),
                    log_format: "json".to_string(),
                    grpc_tcp: None,
                    grpc_uds: None,
                    looking_glass: None,
                },
                dynamic_neighbor_limit: None,
                honor_graceful_shutdown: false,
                honor_blackhole: false,
                install_blackhole_discard: false,
                allow_blackhole_broad_prefixes: false,
            },
            security: crate::config::SecurityConfig::default(),
            neighbors: vec![
                crate::config::Neighbor {
                    address: "10.0.0.2".to_string(),
                    remote_asn: 65002,
                    description: None,
                    peer_group: None,
                    hold_time: None,
                    max_prefixes: None,
                    md5_password: None,
                    tcp_ao: None,
                    ttl_security: Some(false),
                    families: Vec::new(),
                    graceful_restart: Some(true),
                    gr_restart_time: Some(90),
                    gr_stale_routes_time: None,
                    llgr_stale_time: None,
                    local_ipv6_nexthop: None,
                    route_reflector_client: Some(false),
                    route_server_client: Some(false),
                    remove_private_as: None,
                    add_path: None,
                    import_policy: Vec::new(),
                    export_policy: Vec::new(),
                    import_policy_chain: Vec::new(),
                    export_policy_chain: Vec::new(),
                    log_level: None,
                },
                crate::config::Neighbor {
                    address: "10.0.0.3".to_string(),
                    remote_asn: 65003,
                    description: None,
                    peer_group: None,
                    hold_time: None,
                    max_prefixes: None,
                    md5_password: None,
                    tcp_ao: None,
                    ttl_security: Some(false),
                    families: Vec::new(),
                    graceful_restart: Some(true),
                    gr_restart_time: Some(180),
                    gr_stale_routes_time: None,
                    llgr_stale_time: None,
                    local_ipv6_nexthop: None,
                    route_reflector_client: Some(false),
                    route_server_client: Some(false),
                    remove_private_as: None,
                    add_path: None,
                    import_policy: Vec::new(),
                    export_policy: Vec::new(),
                    import_policy_chain: Vec::new(),
                    export_policy_chain: Vec::new(),
                    log_level: None,
                },
                crate::config::Neighbor {
                    address: "10.0.0.4".to_string(),
                    remote_asn: 65004,
                    description: None,
                    peer_group: None,
                    hold_time: None,
                    max_prefixes: None,
                    md5_password: None,
                    tcp_ao: None,
                    ttl_security: Some(false),
                    families: Vec::new(),
                    graceful_restart: Some(false),
                    gr_restart_time: Some(300),
                    gr_stale_routes_time: None,
                    llgr_stale_time: None,
                    local_ipv6_nexthop: None,
                    route_reflector_client: Some(false),
                    route_server_client: Some(false),
                    remove_private_as: None,
                    add_path: None,
                    import_policy: Vec::new(),
                    export_policy: Vec::new(),
                    import_policy_chain: Vec::new(),
                    export_policy_chain: Vec::new(),
                    log_level: None,
                },
            ],
            peer_groups: std::collections::HashMap::new(),
            policy: crate::config::PolicyConfig::default(),
            rpki: None,
            bmp: None,
            mrt: None,
            file_path: None,
            dynamic_neighbors: Vec::new(),
            evpn_instances: Vec::new(),
            ethernet_segments: Vec::new(),
            evpn_ip_vrfs: Vec::new(),
            fib_tables: Vec::new(),
            apply_bum_enforcement: false,
        };

        assert_eq!(max_gr_restart_time_secs(&config), Some(180));
    }
}
