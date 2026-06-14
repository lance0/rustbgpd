//! EVPN runtime mutation converger (ADR-0063 / `EvpnService.ApplyEvpnRuntime`).
//!
//! Owns the command-driven convergence of the live daemon to a validated
//! candidate EVPN runtime model: the per-shape `converge_*` functions, the
//! shape detectors and validators, the rollback ladder, and the gRPC apply
//! entry point. Extracted from `src/main.rs`; see ADR-0063.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;
use tokio::task::JoinError;

use rustbgpd_api::evpn_service::{
    EvpnRuntimeApplyError as GrpcEvpnRuntimeApplyError, runtime_apply_outcome_to_proto,
    runtime_plan_to_proto, runtime_snapshot_to_proto,
};
use rustbgpd_api::proto;
use rustbgpd_rib::RibUpdate;

use crate::config::Config;
use crate::{
    evpn_dataplane, evpn_imet, evpn_l3_originator, evpn_originator, evpn_segment, evpn_svi,
};

pub(crate) fn evpn_vni_to_esi_map(
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
pub(crate) enum DaemonEvpnRuntimeConvergeError {
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

pub(crate) type DaemonEvpnRuntimeConvergeFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), DaemonEvpnRuntimeConvergeError>> + Send + 'a>>;

pub(crate) trait DaemonEvpnRuntimeConverger: Send + Sync {
    fn converge<'a>(
        &'a self,
        current: &'a rustbgpd_evpn::EvpnRuntimeModel,
        candidate: &'a rustbgpd_evpn::EvpnRuntimeCandidate,
        plan: &'a rustbgpd_evpn::EvpnRuntimePlan,
    ) -> DaemonEvpnRuntimeConvergeFuture<'a>;
}

fn apply_task_join_error(context: &str, error: &JoinError) -> GrpcEvpnRuntimeApplyError {
    let reason = if error.is_panic() {
        "panicked"
    } else if error.is_cancelled() {
        "was cancelled"
    } else {
        "failed"
    };
    GrpcEvpnRuntimeApplyError::Internal(format!("EVPN runtime {context} task {reason}: {error}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EvpnRuntimeReloadOutcome {
    Noop,
    Committed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EvpnRuntimeReloadApplyResult {
    pub(crate) outcome: EvpnRuntimeReloadOutcome,
    pub(crate) message: String,
}

pub(crate) struct EvpnRuntimeReloadAttempt {
    pub(crate) baseline: Config,
    pub(crate) result: Result<Option<EvpnRuntimeReloadApplyResult>, GrpcEvpnRuntimeApplyError>,
}

#[derive(Clone)]
pub(crate) struct EvpnRuntimeReloadApply {
    coordinator: Arc<Mutex<rustbgpd_evpn::EvpnRuntimeCoordinator>>,
    apply_lock: Arc<tokio::sync::Mutex<()>>,
    converger: Arc<dyn DaemonEvpnRuntimeConverger>,
    committed_config: Arc<Mutex<Config>>,
    /// ADR-0085: where the resolved `[[ethernet_segments]]` interface
    /// bindings are republished whenever the committed config
    /// advances (SIGHUP and `ApplyEvpnRuntime` both commit through
    /// `set_committed_config`, so this is the single chokepoint). The
    /// link-drain coordinator consumes the receiver.
    es_link_bindings_tx:
        Option<Arc<tokio::sync::watch::Sender<crate::evpn_es_link_drain::EsLinkBindings>>>,
}

impl EvpnRuntimeReloadApply {
    pub(crate) fn new<C>(
        coordinator: Arc<Mutex<rustbgpd_evpn::EvpnRuntimeCoordinator>>,
        apply_lock: Arc<tokio::sync::Mutex<()>>,
        converger: Arc<C>,
        committed_config: Config,
    ) -> Self
    where
        C: DaemonEvpnRuntimeConverger + 'static,
    {
        Self {
            coordinator,
            apply_lock,
            converger,
            committed_config: Arc::new(Mutex::new(committed_config)),
            es_link_bindings_tx: None,
        }
    }

    /// Attach the ADR-0085 binding publisher. Every committed config
    /// advance re-resolves and republishes the binding map (publish
    /// is `send_if_modified`, so unchanged bindings stay silent).
    pub(crate) fn with_es_link_bindings_publisher(
        mut self,
        tx: Arc<tokio::sync::watch::Sender<crate::evpn_es_link_drain::EsLinkBindings>>,
    ) -> Self {
        self.es_link_bindings_tx = Some(tx);
        self
    }

    fn committed_config_locked(&self) -> Config {
        match self.committed_config.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn set_committed_config(&self, config: &Config) {
        match self.committed_config.lock() {
            Ok(mut guard) => *guard = config.clone(),
            Err(poisoned) => *poisoned.into_inner() = config.clone(),
        }
        self.publish_es_link_bindings(config);
    }

    /// Re-resolve and republish the ADR-0085 interface bindings for a
    /// newly committed config. A binding-only edit plans as an EVPN
    /// runtime no-op (the bindings deliberately live outside the
    /// domain type the planner diffs), but still commits the config —
    /// and lands here, where the link-drain coordinator picks it up
    /// and re-evaluates immediately.
    fn publish_es_link_bindings(&self, config: &Config) {
        let Some(tx) = self.es_link_bindings_tx.as_ref() else {
            return;
        };
        match config.resolve_es_link_bindings() {
            Ok(bindings) => {
                tx.send_if_modified(|current| {
                    if **current == bindings {
                        return false;
                    }
                    *current = Arc::new(bindings);
                    true
                });
            }
            // Unreachable for a config that passed validation; warn
            // rather than poison the commit.
            Err(error) => tracing::warn!(
                %error,
                "failed to resolve Ethernet Segment interface bindings from committed config"
            ),
        }
    }

    pub(crate) async fn apply_request(
        &self,
        request: &proto::ApplyEvpnRuntimeRequest,
    ) -> Result<proto::ApplyEvpnRuntimeResponse, GrpcEvpnRuntimeApplyError> {
        let candidate = Config::load_toml_with_diagnostics(
            &request.candidate_toml,
            "candidate EVPN runtime config",
        )
        .map_err(|err| GrpcEvpnRuntimeApplyError::InvalidArgument(err.clone()))?;
        self.apply_candidate_config(&candidate, request.validate_only)
            .await
    }

    #[cfg(test)]
    pub(crate) async fn apply_config(
        &self,
        config: &Config,
    ) -> Result<EvpnRuntimeReloadApplyResult, GrpcEvpnRuntimeApplyError> {
        let response = self.apply_candidate_config(config, false).await?;
        let outcome = response_to_reload_outcome(response.outcome)?;
        Ok(EvpnRuntimeReloadApplyResult {
            outcome,
            message: response.message,
        })
    }

    // ADR-0080: the converge + commit critical section runs on a detached
    // task so a dropped caller — a disconnected gRPC client or an aborted
    // SIGHUP reload — cannot cancel the apply between its actor/RIB side
    // effects and the rollback/baseline bookkeeping. The caller only awaits
    // the result; losing the caller loses the response, never the
    // mutation's atomicity. Coordinated shutdown serializes with these
    // detached tasks by taking the same apply lock before EVPN teardown.
    async fn apply_candidate_config(
        &self,
        config: &Config,
        validate_only: bool,
    ) -> Result<proto::ApplyEvpnRuntimeResponse, GrpcEvpnRuntimeApplyError> {
        let this = self.clone();
        let config = config.clone();
        let join = tokio::spawn(async move {
            let _apply_guard = this.apply_lock.lock().await;
            let response = this
                .apply_candidate_config_locked(&config, validate_only)
                .await?;
            if !validate_only
                && matches!(
                    response.outcome,
                    value if value == proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyNoop as i32
                        || value == proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyCommitted as i32
                )
            {
                this.set_committed_config(&config);
            }
            Ok(response)
        });
        join.await
            .map_err(|error| apply_task_join_error("apply", &error))?
    }

    pub(crate) async fn apply_config_if_changed<F>(
        &self,
        config: &Config,
        changed: F,
    ) -> EvpnRuntimeReloadAttempt
    where
        F: FnOnce(&Config, &Config) -> bool + Send + 'static,
    {
        let this = self.clone();
        let config = config.clone();
        // Same ADR-0080 shield as `apply_candidate_config`: shutdown aborts
        // an in-flight reload task, and that abort must not cancel a
        // converge mid-flight.
        let join = tokio::spawn(async move {
            let _apply_guard = this.apply_lock.lock().await;
            let baseline = this.committed_config_locked();
            if !changed(&config, &baseline) {
                return EvpnRuntimeReloadAttempt {
                    baseline,
                    result: Ok(None),
                };
            }

            let result = match this.apply_candidate_config_locked(&config, false).await {
                Ok(response) => response_to_reload_outcome(response.outcome).map(|outcome| {
                    Some(EvpnRuntimeReloadApplyResult {
                        outcome,
                        message: response.message,
                    })
                }),
                Err(error) => Err(error),
            };
            if matches!(result, Ok(Some(_))) {
                this.set_committed_config(&config);
            }

            EvpnRuntimeReloadAttempt { baseline, result }
        });
        match join.await {
            Ok(attempt) => attempt,
            Err(error) => EvpnRuntimeReloadAttempt {
                baseline: self.committed_config_locked(),
                result: Err(apply_task_join_error("reload apply", &error)),
            },
        }
    }

    async fn apply_candidate_config_locked(
        &self,
        config: &Config,
        validate_only: bool,
    ) -> Result<proto::ApplyEvpnRuntimeResponse, GrpcEvpnRuntimeApplyError> {
        let candidate = evpn_runtime_candidate_from_config(config)?;
        apply_evpn_runtime_candidate_locked(
            candidate,
            validate_only,
            &self.coordinator,
            self.converger.as_ref(),
        )
        .await
    }
}

fn response_to_reload_outcome(
    outcome: i32,
) -> Result<EvpnRuntimeReloadOutcome, GrpcEvpnRuntimeApplyError> {
    match outcome {
        value if value == proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyNoop as i32 => {
            Ok(EvpnRuntimeReloadOutcome::Noop)
        }
        value if value == proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyCommitted as i32 => {
            Ok(EvpnRuntimeReloadOutcome::Committed)
        }
        value => Err(GrpcEvpnRuntimeApplyError::Internal(format!(
            "EVPN runtime reload returned unexpected outcome value {value}"
        ))),
    }
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
pub(crate) struct EvpnRuntimeActorConverger {
    rib_tx: mpsc::Sender<RibUpdate>,
    imet_controller: Arc<tokio::sync::Mutex<evpn_imet::EvpnImetController>>,
    dataplane: Option<evpn_dataplane::EvpnDataplaneRuntimeControl>,
    originator: Option<evpn_originator::EvpnOriginatorRuntimeControl>,
    svi: Option<evpn_svi::EvpnSviRuntimeControl>,
    l3_originator: Option<evpn_l3_originator::EvpnL3OriginatorRuntimeControl>,
    segment: Option<evpn_segment::EvpnSegmentRuntimeControl>,
    /// ADR-0084 operator drained-ESI set. Every originator runtime-model
    /// publish carries the current snapshot; a converge whose segment-set
    /// publish succeeded GCs drain entries for ESIs that left the config
    /// (after the last fallible publish — see `gc_drained_esis`).
    es_drain: crate::evpn_es_drain::EvpnEsDrainState,
}

impl EvpnRuntimeActorConverger {
    #[allow(clippy::too_many_arguments)] // one optional control per EVPN actor plus the shared drain state
    pub(crate) fn new(
        rib_tx: mpsc::Sender<RibUpdate>,
        imet_controller: Arc<tokio::sync::Mutex<evpn_imet::EvpnImetController>>,
        dataplane: Option<evpn_dataplane::EvpnDataplaneRuntimeControl>,
        originator: Option<evpn_originator::EvpnOriginatorRuntimeControl>,
        svi: Option<evpn_svi::EvpnSviRuntimeControl>,
        l3_originator: Option<evpn_l3_originator::EvpnL3OriginatorRuntimeControl>,
        segment: Option<evpn_segment::EvpnSegmentRuntimeControl>,
        es_drain: crate::evpn_es_drain::EvpnEsDrainState,
    ) -> Self {
        Self {
            rib_tx,
            imet_controller,
            dataplane,
            originator,
            svi,
            l3_originator,
            segment,
            es_drain,
        }
    }

    /// GC the ADR-0084 drained-ESI set against a segment snapshot the
    /// converge just published (drop entries for ESIs that left the
    /// config) and return the new set when it changed so the caller can
    /// republish it to the segment actor. Must run only AFTER every
    /// fallible actor publish of the converge succeeded: GC'ing before a
    /// publish that then fails would split the drain state — the
    /// coordinator (gauge, RPC drain reasons) would report the ES
    /// undrained while the segment actor's drained-set mirror keeps it
    /// withdrawn, and a bare operator undrain would be an idempotent
    /// no-op that fans nothing out (the cross-actor seam audit's
    /// split-state finding). With this ordering a failed converge leaves
    /// the entry in place on BOTH sides, so the rollback has nothing to
    /// restore (preserving ADR-0084's no-restore stance) and a
    /// subsequent undrain is a real transition.
    fn gc_drained_esis(
        &self,
        segments: &[rustbgpd_evpn::EthernetSegment],
    ) -> Option<Arc<std::collections::BTreeSet<rustbgpd_wire::EthernetSegmentIdentifier>>> {
        self.es_drain.retain_configured(segments)
    }

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
        if !originator.replace_runtime_model(
            candidate_instances.clone(),
            candidate_vni_to_esi,
            self.es_drain.snapshot(),
        ) {
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
                self.es_drain.snapshot(),
            );
            self.rollback_imet(added_vni).await;
            return Err(DaemonEvpnRuntimeConvergeError::failed(
                "EVPN SVI runtime model publish failed",
            ));
        }
        if let Err(err) = Self::publish_segment_instances(segment, candidate_instances) {
            self.rollback_l2vni_runtime_models(
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
        &self,
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
                self.es_drain.snapshot(),
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

    fn require_segment_runtime_control(
        &self,
        operation: &str,
    ) -> Result<&evpn_segment::EvpnSegmentRuntimeControl, DaemonEvpnRuntimeConvergeError> {
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

    /// Converge a pure additive build-up that spans multiple EVPN runtime
    /// domains or multiple rows. This is the positive mirror of tenant
    /// teardown: publish full candidate snapshots to every level-triggered
    /// actor, originate IMET for newly added L2VNIs, and roll all touched
    /// consumers back to the committed snapshots if any publish fails.
    #[expect(
        clippy::too_many_lines,
        reason = "ordered multi-consumer build-up with rollback is clearer as one sequence"
    )]
    async fn converge_additive_build_up(
        &self,
        current: &rustbgpd_evpn::EvpnRuntimeModel,
        candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
        plan: &rustbgpd_evpn::EvpnRuntimePlan,
    ) -> Result<(), DaemonEvpnRuntimeConvergeError> {
        let added_instances = validate_additive_build_up(current, candidate, plan)?;
        let candidate_instances = Arc::new(candidate.instances().clone());
        let candidate_ip_vrfs = Arc::new(candidate.ip_vrfs().clone());
        let candidate_segments = Arc::new(candidate.ethernet_segments().to_vec());
        let candidate_vni_to_esi = evpn_vni_to_esi_map(candidate.ethernet_segments());

        let l2_changed = !plan.evpn_instances.added.is_empty();
        let ip_vrf_rows_changed = !plan.ip_vrfs.added.is_empty();
        let ip_vrf_metadata_changed = current.ip_vrfs() != candidate.ip_vrfs();
        let es_changed = !plan.ethernet_segments.added.is_empty();

        let dataplane = if l2_changed || ip_vrf_metadata_changed || ip_vrf_rows_changed {
            Some(self.require_l2vni_dataplane("additive build-up")?)
        } else {
            None
        };
        let originator = if l2_changed {
            Some(self.require_l2vni_originator("additive build-up")?)
        } else if es_changed {
            if let Some(originator) = self.originator.as_ref()
                && !originator.is_open()
            {
                return Err(DaemonEvpnRuntimeConvergeError::failed(
                    "EVPN Type 2 originator runtime control is closed",
                ));
            }
            self.originator.as_ref()
        } else {
            None
        };
        let svi_required = added_instances.iter().any(|inst| inst.advertise_svi_mac);
        let svi = self.svi.as_ref();
        if svi_required && svi.is_none() {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(
                "additive L2VNI build-up with advertise_svi_mac=true requires an active SVI actor; \
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
        let segment = if es_changed {
            Some(self.require_segment_runtime_control("additive build-up")?)
        } else if l2_changed {
            self.open_segment_runtime_control()?
        } else {
            None
        };
        let l3_originator = if ip_vrf_rows_changed {
            let l3 = self.l3_originator.as_ref().ok_or_else(|| {
                DaemonEvpnRuntimeConvergeError::unsupported(
                    "additive IP-VRF build-up requires an active EVPN Type 5 originator; \
                     live Type 5 actor-spawn is not supported yet",
                )
            })?;
            if !l3.is_open() {
                return Err(DaemonEvpnRuntimeConvergeError::failed(
                    "EVPN Type 5 originator runtime control is closed",
                ));
            }
            Some(l3)
        } else {
            None
        };

        let mut originated_instances = Vec::with_capacity(added_instances.len());
        for instance in &added_instances {
            let outcome = self
                .imet_controller
                .lock()
                .await
                .originate_instance(instance.clone(), &self.rib_tx)
                .await;
            if !matches!(
                outcome,
                evpn_imet::ImetOriginateOutcome::Originated { .. }
                    | evpn_imet::ImetOriginateOutcome::AlreadyOriginated { .. }
                    | evpn_imet::ImetOriginateOutcome::ReplyDropped { .. }
            ) {
                let restored = self
                    .rollback_additive_build_up(current, &originated_instances)
                    .await;
                return Err(additive_build_failure(
                    restored,
                    &format!(
                        "EVPN IMET origination failed for L2VNI {}: {outcome:?}",
                        instance.id
                    ),
                ));
            }
            originated_instances.push(instance.clone());
        }

        if let Some(dataplane) = dataplane {
            if ip_vrf_metadata_changed && !dataplane.replace_ip_vrfs(candidate_ip_vrfs.clone()) {
                let restored = self
                    .rollback_additive_build_up(current, &originated_instances)
                    .await;
                return Err(additive_build_failure(
                    restored,
                    "EVPN dataplane IP-VRF runtime model publish failed",
                ));
            }
            if l2_changed && !dataplane.replace_evpn_instances(candidate_instances.clone()) {
                let restored = self
                    .rollback_additive_build_up(current, &originated_instances)
                    .await;
                return Err(additive_build_failure(
                    restored,
                    "EVPN dataplane runtime model publish failed",
                ));
            }
        }
        if let Some(originator) = originator
            && !originator.replace_runtime_model(
                candidate_instances.clone(),
                candidate_vni_to_esi,
                self.es_drain.snapshot(),
            )
        {
            let restored = self
                .rollback_additive_build_up(current, &originated_instances)
                .await;
            return Err(additive_build_failure(
                restored,
                "EVPN Type 2 originator runtime model publish failed",
            ));
        }
        if let Some(svi) = svi
            && l2_changed
            && !svi.replace_evpn_instances(candidate_instances.clone())
        {
            let restored = self
                .rollback_additive_build_up(current, &originated_instances)
                .await;
            return Err(additive_build_failure(
                restored,
                "EVPN SVI runtime model publish failed",
            ));
        }
        if let Some(segment) = segment {
            if l2_changed && !segment.replace_instances(candidate_instances.clone()) {
                let restored = self
                    .rollback_additive_build_up(current, &originated_instances)
                    .await;
                return Err(additive_build_failure(
                    restored,
                    "EVPN segment instance runtime model publish failed",
                ));
            }
            if es_changed && !segment.replace_segments(candidate_segments) {
                let restored = self
                    .rollback_additive_build_up(current, &originated_instances)
                    .await;
                return Err(additive_build_failure(
                    restored,
                    "EVPN segment runtime model publish failed",
                ));
            }
        }
        if let Some(l3) = l3_originator
            && !l3.replace_ip_vrfs(candidate_ip_vrfs)
        {
            let restored = self
                .rollback_additive_build_up(current, &originated_instances)
                .await;
            return Err(additive_build_failure(
                restored,
                "EVPN Type 5 originator runtime model publish failed",
            ));
        }

        Ok(())
    }

    /// Best-effort rollback for additive build-up: republish committed
    /// snapshots and withdraw any newly originated IMET routes.
    async fn rollback_additive_build_up(
        &self,
        current: &rustbgpd_evpn::EvpnRuntimeModel,
        added_instances: &[rustbgpd_evpn::EvpnInstance],
    ) -> bool {
        let current_instances = Arc::new(current.instances().clone());
        let current_ip_vrfs = Arc::new(current.ip_vrfs().clone());
        let current_segments = Arc::new(current.ethernet_segments().to_vec());
        let current_vni_to_esi = evpn_vni_to_esi_map(current.ethernet_segments());

        let mut restored = true;
        if let Some(dataplane) = self.dataplane.as_ref() {
            restored &= dataplane.replace_ip_vrfs(current_ip_vrfs.clone());
            restored &= dataplane.replace_evpn_instances(current_instances.clone());
        }
        if let Some(originator) = self.originator.as_ref() {
            restored &= originator.replace_runtime_model(
                current_instances.clone(),
                current_vni_to_esi,
                self.es_drain.snapshot(),
            );
        }
        if let Some(svi) = self.svi.as_ref() {
            restored &= svi.replace_evpn_instances(current_instances.clone());
        }
        if let Some(segment) = self.segment.as_ref() {
            restored &= segment.replace_instances(current_instances);
            restored &= segment.replace_segments(current_segments);
        }
        if let Some(l3) = self.l3_originator.as_ref() {
            restored &= l3.replace_ip_vrfs(current_ip_vrfs);
        }
        for instance in added_instances {
            restored &= matches!(
                self.imet_controller
                    .lock()
                    .await
                    .withdraw_instance(instance.id, &self.rib_tx)
                    .await,
                evpn_imet::ImetWithdrawOutcome::Withdrawn { .. }
                    | evpn_imet::ImetWithdrawOutcome::NotOriginated { .. }
            );
        }
        restored
    }

    /// Converge a standalone L2VNI swap: one-or-more clean L2VNI adds plus
    /// one-or-more clean L2VNI deletes in a single candidate. This deliberately
    /// excludes IP-VRF link changes and Ethernet Segment membership so the
    /// operation is just the composition of already-supported add/delete
    /// semantics over the level-triggered L2VNI consumers.
    #[expect(
        clippy::too_many_lines,
        reason = "ordered multi-consumer swap with rollback reads clearest as one sequence"
    )]
    async fn converge_l2vni_swap(
        &self,
        current: &rustbgpd_evpn::EvpnRuntimeModel,
        candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
        plan: &rustbgpd_evpn::EvpnRuntimePlan,
    ) -> Result<(), DaemonEvpnRuntimeConvergeError> {
        let (added_instances, deleted_instances) = validate_l2vni_swap(current, candidate, plan)?;
        let candidate_instances = Arc::new(candidate.instances().clone());

        let dataplane = self.require_l2vni_dataplane("swap")?;
        let originator = self.require_l2vni_originator("swap")?;
        let svi_required = added_instances
            .iter()
            .chain(deleted_instances.iter())
            .any(|instance| instance.advertise_svi_mac);
        let svi = self.svi.as_ref();
        if svi_required && svi.is_none() {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(
                "L2VNI runtime swap with advertise_svi_mac=true requires an active SVI actor; \
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

        let mut originated_added = Vec::with_capacity(added_instances.len());
        for instance in &added_instances {
            let outcome = self
                .imet_controller
                .lock()
                .await
                .originate_instance(instance.clone(), &self.rib_tx)
                .await;
            if !matches!(
                outcome,
                evpn_imet::ImetOriginateOutcome::Originated { .. }
                    | evpn_imet::ImetOriginateOutcome::AlreadyOriginated { .. }
                    | evpn_imet::ImetOriginateOutcome::ReplyDropped { .. }
            ) {
                let restored = self
                    .rollback_l2vni_swap(current, &originated_added, &[])
                    .await;
                return Err(l2vni_swap_failure(
                    restored,
                    &format!(
                        "EVPN IMET origination failed for added L2VNI {}: {outcome:?}",
                        instance.id
                    ),
                ));
            }
            originated_added.push(instance.clone());
        }

        if !dataplane.replace_evpn_instances(candidate_instances.clone()) {
            let restored = self
                .rollback_l2vni_swap(current, &originated_added, &[])
                .await;
            return Err(l2vni_swap_failure(
                restored,
                "EVPN dataplane runtime model publish failed",
            ));
        }
        if let Some(svi) = svi
            && !svi.replace_evpn_instances(candidate_instances.clone())
        {
            let restored = self
                .rollback_l2vni_swap(current, &originated_added, &[])
                .await;
            return Err(l2vni_swap_failure(
                restored,
                "EVPN SVI runtime model publish failed",
            ));
        }

        let mut withdrawn_deleted = Vec::with_capacity(deleted_instances.len());
        for instance in &deleted_instances {
            let outcome = self
                .imet_controller
                .lock()
                .await
                .withdraw_instance(instance.id, &self.rib_tx)
                .await;
            if !matches!(
                outcome,
                evpn_imet::ImetWithdrawOutcome::Withdrawn { .. }
                    | evpn_imet::ImetWithdrawOutcome::NotOriginated { .. }
            ) {
                let restored = self
                    .rollback_l2vni_swap(current, &originated_added, &withdrawn_deleted)
                    .await;
                return Err(l2vni_swap_failure(
                    restored,
                    &format!(
                        "EVPN IMET withdrawal failed for deleted L2VNI {}: {outcome:?}",
                        instance.id
                    ),
                ));
            }
            withdrawn_deleted.push(instance.clone());
        }

        if !originator.replace_runtime_model(
            candidate_instances.clone(),
            evpn_vni_to_esi_map(candidate.ethernet_segments()),
            self.es_drain.snapshot(),
        ) {
            let restored = self
                .rollback_l2vni_swap(current, &originated_added, &withdrawn_deleted)
                .await;
            return Err(l2vni_swap_failure(
                restored,
                "EVPN Type 2 originator runtime model publish failed",
            ));
        }
        if let Err(err) = Self::publish_segment_instances(segment, candidate_instances) {
            let restored = self
                .rollback_l2vni_swap(current, &originated_added, &withdrawn_deleted)
                .await;
            return Err(l2vni_swap_failure(restored, err.message()));
        }

        Ok(())
    }

    async fn rollback_l2vni_swap(
        &self,
        current: &rustbgpd_evpn::EvpnRuntimeModel,
        added_instances: &[rustbgpd_evpn::EvpnInstance],
        withdrawn_deleted_instances: &[rustbgpd_evpn::EvpnInstance],
    ) -> bool {
        let current_instances = Arc::new(current.instances().clone());
        let mut restored = true;
        if let Some(dataplane) = self.dataplane.as_ref() {
            restored &= dataplane.replace_evpn_instances(current_instances.clone());
        }
        if let Some(originator) = self.originator.as_ref() {
            restored &= originator.replace_runtime_model(
                current_instances.clone(),
                evpn_vni_to_esi_map(current.ethernet_segments()),
                self.es_drain.snapshot(),
            );
        }
        if let Some(svi) = self.svi.as_ref() {
            restored &= svi.replace_evpn_instances(current_instances.clone());
        }
        if let Some(segment) = self.segment.as_ref() {
            restored &= segment.replace_instances(current_instances);
        }
        for instance in added_instances {
            restored &= matches!(
                self.imet_controller
                    .lock()
                    .await
                    .withdraw_instance(instance.id, &self.rib_tx)
                    .await,
                evpn_imet::ImetWithdrawOutcome::Withdrawn { .. }
                    | evpn_imet::ImetWithdrawOutcome::NotOriginated { .. }
            );
        }
        for instance in withdrawn_deleted_instances {
            restored &= self.restore_imet(instance.clone()).await;
        }
        restored
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
            self.es_drain.snapshot(),
        ) {
            Self::rollback_l2vni_dataplane(dataplane, current, ip_vrf_metadata_changed);
            if let Some(svi) = svi {
                let _ = svi.replace_evpn_instances(current_instances);
            }
            let _ = self.restore_imet(deleted_instance).await;
            return Err(DaemonEvpnRuntimeConvergeError::failed(
                "EVPN Type 2 originator runtime model publish failed",
            ));
        }
        if let Err(err) = Self::publish_segment_instances(segment, candidate_instances) {
            self.rollback_l2vni_runtime_models(
                dataplane,
                Some(originator),
                svi,
                segment,
                current,
                ip_vrf_metadata_changed,
            );
            let _ = self.restore_imet(deleted_instance).await;
            return Err(err);
        }

        Ok(())
    }

    /// Converge an atomic tenant teardown — a delete-only multi-element /
    /// cross-resource mutation (ES-aware L2VNI delete + linked IP-VRF delete +
    /// ES delete/member-shrink) that the single-shape converters can't route.
    ///
    /// All derived state drains through the level-triggered consumers when the
    /// candidate snapshots are published: the Type 5 originator
    /// (`drain_changed_ip_vrfs`) and dataplane re-projection drop removed
    /// IP-VRFs' Type 5 + L3 FIB; the segment actor drops removed members'
    /// Type 1/4 (it skips segments whose member VNI has no instance); the Type 2
    /// originator and SVI drop removed VNIs' routes. The only explicit consumer
    /// is the per-VNI Type 3 IMET, withdrawn here. On any publish failure the
    /// rollback republishes the committed snapshots and re-originates IMET.
    #[expect(
        clippy::too_many_lines,
        reason = "ordered multi-consumer teardown with a per-step rollback ladder reads clearest as one sequence"
    )]
    async fn converge_tenant_teardown(
        &self,
        current: &rustbgpd_evpn::EvpnRuntimeModel,
        candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
        plan: &rustbgpd_evpn::EvpnRuntimePlan,
    ) -> Result<(), DaemonEvpnRuntimeConvergeError> {
        let deleted_instances = validate_tenant_teardown(current, candidate, plan)?;
        let candidate_instances = Arc::new(candidate.instances().clone());
        let candidate_ip_vrfs = Arc::new(candidate.ip_vrfs().clone());
        let candidate_segments = Arc::new(candidate.ethernet_segments().to_vec());
        let candidate_vni_to_esi = evpn_vni_to_esi_map(candidate.ethernet_segments());
        let ip_vrf_changed = current.ip_vrfs() != candidate.ip_vrfs();

        let dataplane = self.require_l2vni_dataplane("tenant teardown")?;
        let originator = self.require_l2vni_originator("tenant teardown")?;
        let svi_required = deleted_instances.iter().any(|inst| inst.advertise_svi_mac);
        let svi = self.svi.as_ref();
        if svi_required && svi.is_none() {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(
                "tenant teardown of an advertise_svi_mac L2VNI requires an active SVI actor; \
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
        let l3_originator = if ip_vrf_changed {
            let l3 = self.l3_originator.as_ref().ok_or_else(|| {
                DaemonEvpnRuntimeConvergeError::unsupported(
                    "tenant teardown with IP-VRF changes requires an active EVPN Type 5 \
                     originator; live Type 5 actor-spawn is not supported yet",
                )
            })?;
            if !l3.is_open() {
                return Err(DaemonEvpnRuntimeConvergeError::failed(
                    "EVPN Type 5 originator runtime control is closed",
                ));
            }
            Some(l3)
        } else {
            None
        };

        // Each step publishes a candidate snapshot to a level-triggered actor;
        // on failure, `rollback_tenant_teardown` republishes the committed
        // snapshots + re-originates IMET, and `teardown_failure` escalates if
        // that IMET restore itself fails.
        if ip_vrf_changed && !dataplane.replace_ip_vrfs(candidate_ip_vrfs.clone()) {
            let restored = self
                .rollback_tenant_teardown(current, &deleted_instances)
                .await;
            return Err(teardown_failure(
                restored,
                "EVPN dataplane IP-VRF runtime model publish failed",
            ));
        }
        if !dataplane.replace_evpn_instances(candidate_instances.clone()) {
            let restored = self
                .rollback_tenant_teardown(current, &deleted_instances)
                .await;
            return Err(teardown_failure(
                restored,
                "EVPN dataplane runtime model publish failed",
            ));
        }
        if let Some(svi) = svi
            && !svi.replace_evpn_instances(candidate_instances.clone())
        {
            let restored = self
                .rollback_tenant_teardown(current, &deleted_instances)
                .await;
            return Err(teardown_failure(
                restored,
                "EVPN SVI runtime model publish failed",
            ));
        }

        for inst in &deleted_instances {
            let outcome = self
                .imet_controller
                .lock()
                .await
                .withdraw_instance(inst.id, &self.rib_tx)
                .await;
            if !matches!(
                outcome,
                evpn_imet::ImetWithdrawOutcome::Withdrawn { .. }
                    | evpn_imet::ImetWithdrawOutcome::NotOriginated { .. }
            ) {
                let vni = inst.id;
                let restored = self
                    .rollback_tenant_teardown(current, &deleted_instances)
                    .await;
                return Err(teardown_failure(
                    restored,
                    &format!("EVPN IMET withdrawal failed for L2VNI {vni}: {outcome:?}"),
                ));
            }
        }

        // The drained-set snapshot may still carry a to-be-deleted ESI's
        // entry (the ADR-0084 GC at the end runs only after every publish
        // succeeded); it is inert here — the originator keys drain through
        // the published vni->esi map, which no longer maps it.
        if !originator.replace_runtime_model(
            candidate_instances.clone(),
            candidate_vni_to_esi,
            self.es_drain.snapshot(),
        ) {
            let restored = self
                .rollback_tenant_teardown(current, &deleted_instances)
                .await;
            return Err(teardown_failure(
                restored,
                "EVPN Type 2 originator runtime model publish failed",
            ));
        }
        if let Some(segment) = segment {
            if !segment.replace_instances(candidate_instances.clone()) {
                let restored = self
                    .rollback_tenant_teardown(current, &deleted_instances)
                    .await;
                return Err(teardown_failure(
                    restored,
                    "EVPN segment instance runtime model publish failed",
                ));
            }
            if !segment.replace_segments(candidate_segments) {
                let restored = self
                    .rollback_tenant_teardown(current, &deleted_instances)
                    .await;
                return Err(teardown_failure(
                    restored,
                    "EVPN segment runtime model publish failed",
                ));
            }
        }
        if let Some(l3) = l3_originator
            && !l3.replace_ip_vrfs(candidate_ip_vrfs)
        {
            let restored = self
                .rollback_tenant_teardown(current, &deleted_instances)
                .await;
            return Err(teardown_failure(
                restored,
                "EVPN Type 5 originator runtime model publish failed",
            ));
        }

        // ADR-0084 GC, only now that every fallible publish above
        // succeeded: a teardown can delete a drained ES; drop its drain
        // entry and push the GC'd set so a re-added ESI cannot pick up
        // a stale drain inside the segment actor. GC-after-success keeps
        // the coordinator and the actors agreeing (all still drained)
        // when a publish fails mid-converge — see `gc_drained_esis`.
        // The push is best-effort: a closed control here means daemon
        // teardown.
        if let Some(gc_drained) = self.gc_drained_esis(candidate.ethernet_segments())
            && let Some(segment) = segment
        {
            let _ = segment.replace_drained_esis(gc_drained);
        }

        Ok(())
    }

    /// Converge an `ip_vrf` relink — an L2VNI re-homed to a different IP-VRF (or
    /// its link added/removed). This mutates only the IP-VRF reference metadata,
    /// not any row, and only the dataplane reads the link (for RFC 9135 §9.2
    /// overlay-index recursion gateway resolution). RD is unchanged, so there is
    /// no IMET re-origination; the Type 2 originator / SVI / segment do not read
    /// the link, so there is nothing to republish to them. Dataplane-only.
    fn converge_ip_vrf_relink(
        &self,
        current: &rustbgpd_evpn::EvpnRuntimeModel,
        candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
        plan: &rustbgpd_evpn::EvpnRuntimePlan,
    ) -> Result<(), DaemonEvpnRuntimeConvergeError> {
        validate_ip_vrf_relink(current, candidate, plan)?;
        let dataplane = self.require_l2vni_dataplane("ip_vrf relink")?;
        if !dataplane.replace_ip_vrfs(Arc::new(candidate.ip_vrfs().clone())) {
            // The control is open (checked above); a failed publish means the
            // actor exited in between and nothing was applied, so there is no
            // partial state to roll back.
            return Err(DaemonEvpnRuntimeConvergeError::failed(
                "EVPN dataplane IP-VRF reference republish failed during ip_vrf relink",
            ));
        }
        Ok(())
    }

    /// Best-effort rollback of a tenant teardown: republish every committed
    /// snapshot to its actor (all idempotent, level-triggered) and re-originate
    /// the Type 3 IMET for each deleted L2VNI. Returns whether every IMET route
    /// was restored, so the caller can escalate when live Type 3 state is left
    /// withdrawn.
    async fn rollback_tenant_teardown(
        &self,
        current: &rustbgpd_evpn::EvpnRuntimeModel,
        deleted_instances: &[rustbgpd_evpn::EvpnInstance],
    ) -> bool {
        let current_instances = Arc::new(current.instances().clone());
        let current_ip_vrfs = Arc::new(current.ip_vrfs().clone());
        let current_segments = Arc::new(current.ethernet_segments().to_vec());
        let current_vni_to_esi = evpn_vni_to_esi_map(current.ethernet_segments());

        if let Some(dataplane) = self.dataplane.as_ref() {
            let _ = dataplane.replace_ip_vrfs(current_ip_vrfs.clone());
            let _ = dataplane.replace_evpn_instances(current_instances.clone());
        }
        if let Some(svi) = self.svi.as_ref() {
            let _ = svi.replace_evpn_instances(current_instances.clone());
        }
        if let Some(originator) = self.originator.as_ref() {
            let _ = originator.replace_runtime_model(
                current_instances.clone(),
                current_vni_to_esi,
                self.es_drain.snapshot(),
            );
        }
        if let Some(segment) = self.segment.as_ref() {
            let _ = segment.replace_instances(current_instances);
            let _ = segment.replace_segments(current_segments);
        }
        if let Some(l3) = self.l3_originator.as_ref() {
            let _ = l3.replace_ip_vrfs(current_ip_vrfs);
        }

        let mut all_restored = true;
        for inst in deleted_instances {
            all_restored &= self.restore_imet(inst.clone()).await;
        }
        all_restored
    }

    #[expect(
        clippy::too_many_lines,
        reason = "ordered IMET re-originate + watch-channel republish with a per-step rollback ladder reads clearest as one sequence"
    )]
    async fn converge_l2vni_redefine(
        &self,
        current: &rustbgpd_evpn::EvpnRuntimeModel,
        candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
        plan: &rustbgpd_evpn::EvpnRuntimePlan,
    ) -> Result<(), DaemonEvpnRuntimeConvergeError> {
        let redefined_vni = validate_single_l2vni_redefine(current, candidate, plan)?;
        let Some(new_instance) = candidate.instances().get(redefined_vni).cloned() else {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "candidate did not contain redefined L2VNI {redefined_vni}"
            )));
        };
        let Some(old_instance) = current.instances().get(redefined_vni).cloned() else {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "committed model did not contain redefined L2VNI {redefined_vni}"
            )));
        };
        let candidate_instances = Arc::new(candidate.instances().clone());
        let candidate_vni_to_esi = evpn_vni_to_esi_map(candidate.ethernet_segments());

        let dataplane = self.require_l2vni_dataplane("redefine")?;
        let originator = self.require_l2vni_originator("redefine")?;
        // Either the committed or candidate side may carry advertise_svi_mac,
        // so the SVI actor is required if either does (turning it off still
        // needs the actor to withdraw the stale SVI MAC).
        let svi_required = new_instance.advertise_svi_mac || old_instance.advertise_svi_mac;
        let svi = self.svi.as_ref();
        if svi_required && svi.is_none() {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(
                "L2VNI runtime redefine with advertise_svi_mac=true requires an active SVI actor; \
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

        // IMET (Type 3) is the only explicit, non-watch consumer. The
        // controller tracks one key per VNI, so a redefine must withdraw the
        // old-RD route before originating the new one — a bare re-originate
        // would no-op with `AlreadyOriginated` and keep the stale key. Hold the
        // controller lock across both so the re-origination is atomic against
        // concurrent IMET mutators (notably the shutdown-time `withdraw_all`),
        // which must not interleave between the withdraw and the originate.
        let originate_outcome = {
            let mut imet = self.imet_controller.lock().await;
            let withdraw_outcome = imet.withdraw_instance(redefined_vni, &self.rib_tx).await;
            if !matches!(
                withdraw_outcome,
                evpn_imet::ImetWithdrawOutcome::Withdrawn { .. }
                    | evpn_imet::ImetWithdrawOutcome::NotOriginated { .. }
            ) {
                // Nothing new is tracked yet; the committed route stands or has
                // already been removed by the failed withdraw. Surface the error
                // (the guard drops as we return, releasing the lock).
                return Err(DaemonEvpnRuntimeConvergeError::failed(format!(
                    "EVPN IMET withdrawal failed for redefined L2VNI {redefined_vni}: {withdraw_outcome:?}"
                )));
            }
            imet.originate_instance(new_instance, &self.rib_tx).await
        };
        if !matches!(
            originate_outcome,
            evpn_imet::ImetOriginateOutcome::Originated { .. }
                | evpn_imet::ImetOriginateOutcome::AlreadyOriginated { .. }
                | evpn_imet::ImetOriginateOutcome::ReplyDropped { .. }
        ) {
            // The new route was not originated, so the old key is no longer
            // tracked (we withdrew it above): a plain re-originate of the old
            // instance restores the committed route. Escalate if even that
            // fails — the committed Type 3 is then withdrawn with no fallback.
            let restored = self.restore_imet(old_instance).await;
            return Err(redefine_imet_failure(
                restored,
                redefined_vni,
                &format!(
                    "EVPN IMET origination failed for redefined L2VNI {redefined_vni}: {originate_outcome:?}"
                ),
            ));
        }

        // The remaining consumers are watch-channel level-triggered: each
        // diffs the full candidate instance table against its last-seen table
        // and drains/re-originates the content-changed VNI itself. IP-VRF link
        // metadata is guaranteed unchanged (validated above), so there is no
        // dataplane IP-VRF republish on the redefine path.
        if !dataplane.replace_evpn_instances(candidate_instances.clone()) {
            Self::rollback_l2vni_dataplane(dataplane, current, false);
            let restored = self
                .rollback_imet_redefine(redefined_vni, old_instance)
                .await;
            return Err(redefine_imet_failure(
                restored,
                redefined_vni,
                "EVPN dataplane runtime model publish failed",
            ));
        }
        if !originator.replace_runtime_model(
            candidate_instances.clone(),
            candidate_vni_to_esi,
            self.es_drain.snapshot(),
        ) {
            Self::rollback_l2vni_dataplane(dataplane, current, false);
            let restored = self
                .rollback_imet_redefine(redefined_vni, old_instance)
                .await;
            return Err(redefine_imet_failure(
                restored,
                redefined_vni,
                "EVPN Type 2 originator runtime model publish failed",
            ));
        }
        if let Some(svi) = svi
            && !svi.replace_evpn_instances(candidate_instances.clone())
        {
            Self::rollback_l2vni_dataplane(dataplane, current, false);
            let current_instances = Arc::new(current.instances().clone());
            let _ = originator.replace_runtime_model(
                current_instances,
                evpn_vni_to_esi_map(current.ethernet_segments()),
                self.es_drain.snapshot(),
            );
            let restored = self
                .rollback_imet_redefine(redefined_vni, old_instance)
                .await;
            return Err(redefine_imet_failure(
                restored,
                redefined_vni,
                "EVPN SVI runtime model publish failed",
            ));
        }
        if let Err(err) = Self::publish_segment_instances(segment, candidate_instances) {
            self.rollback_l2vni_runtime_models(
                dataplane,
                Some(originator),
                svi,
                segment,
                current,
                false,
            );
            let restored = self
                .rollback_imet_redefine(redefined_vni, old_instance)
                .await;
            return Err(redefine_imet_failure(
                restored,
                redefined_vni,
                err.message(),
            ));
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

    fn converge_ip_vrf_redefine(
        &self,
        current: &rustbgpd_evpn::EvpnRuntimeModel,
        candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
        plan: &rustbgpd_evpn::EvpnRuntimePlan,
    ) -> Result<(), DaemonEvpnRuntimeConvergeError> {
        let redefined_name = validate_single_ip_vrf_redefine(current, candidate, plan)?;
        let candidate_ip_vrfs = Arc::new(candidate.ip_vrfs().clone());
        if candidate.ip_vrfs().get(&redefined_name).is_none() {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "candidate is missing planned redefined IP-VRF {redefined_name:?}"
            )));
        }

        let dataplane = self.dataplane.as_ref().ok_or_else(|| {
            DaemonEvpnRuntimeConvergeError::unsupported(
                "IP-VRF runtime redefine requires an active EVPN dataplane actor; \
                 no-EVPN startup actor-spawn is not supported yet",
            )
        })?;
        let l3_originator = self.l3_originator.as_ref().ok_or_else(|| {
            DaemonEvpnRuntimeConvergeError::unsupported(
                "IP-VRF runtime redefine requires an active EVPN Type 5 originator; \
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
        let segment = self.require_segment_runtime_control(operation)?;
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
        // The drained-set snapshot may still carry a to-be-deleted ESI's
        // entry (the ADR-0084 GC below runs only after every publish
        // succeeded); it is inert here — the originator keys drain
        // through the published vni->esi map, which no longer maps it.
        let republished_originator = if let Some(originator) = self.originator.as_ref() {
            if !originator.is_open() {
                return Err(DaemonEvpnRuntimeConvergeError::failed(
                    "EVPN Type 2 originator runtime control is closed",
                ));
            }
            if !originator.replace_runtime_model(
                candidate_instances.clone(),
                evpn_vni_to_esi_map(candidate.ethernet_segments()),
                self.es_drain.snapshot(),
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
                    self.es_drain.snapshot(),
                );
            }
            return Err(DaemonEvpnRuntimeConvergeError::failed(
                "EVPN segment runtime model publish failed",
            ));
        }
        // ADR-0084 GC, only now that every fallible publish above
        // succeeded: an ES delete drops its drain entry (a redefine keeps
        // the ESI, so its drain survives), and the GC'd set is pushed so
        // a re-added ESI cannot pick up a stale drain inside the segment
        // actor. GC-after-success keeps the coordinator and the actors
        // agreeing (all still drained) when a publish fails mid-converge
        // — see `gc_drained_esis`. The push is best-effort: a closed
        // control here means daemon teardown.
        if let Some(gc_drained) = self.gc_drained_esis(candidate.ethernet_segments()) {
            let _ = segment.replace_drained_esis(gc_drained);
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

    /// Re-originate a committed instance's Type 3 IMET after a failed
    /// convergence step withdrew it. Returns `false` if the route could not be
    /// restored, so callers on the redefine path can escalate (the committed
    /// Type 3 is then withdrawn with no fallback). Best-effort callers may
    /// ignore the result.
    async fn restore_imet(&self, instance: rustbgpd_evpn::EvpnInstance) -> bool {
        matches!(
            self.imet_controller
                .lock()
                .await
                .originate_instance(instance, &self.rib_tx)
                .await,
            evpn_imet::ImetOriginateOutcome::Originated { .. }
                | evpn_imet::ImetOriginateOutcome::AlreadyOriginated { .. }
                | evpn_imet::ImetOriginateOutcome::ReplyDropped { .. }
        )
    }

    /// Roll a redefine's IMET (Type 3) state back to the committed instance
    /// *after the new route has already been originated*. The controller
    /// tracks one key per VNI, so [`Self::restore_imet`] (a bare re-originate)
    /// is insufficient here — it would no-op with `AlreadyOriginated` against
    /// the new key. Withdraw the currently-tracked (new) route first, then
    /// re-originate the old one. Returns `false` if the committed route could
    /// not be restored, so the caller can surface a stronger failure (live
    /// Type 3 state may then require repair/restart).
    #[must_use]
    async fn rollback_imet_redefine(
        &self,
        vni: rustbgpd_evpn::EvpnInstanceId,
        old_instance: rustbgpd_evpn::EvpnInstance,
    ) -> bool {
        let mut imet = self.imet_controller.lock().await;
        // The withdraw outcome is load-bearing: if it fails (Rejected /
        // RibUnavailable / ReplyDropped) the controller keeps tracking the
        // *new* key, so the re-originate below would no-op with
        // `AlreadyOriginated` and leave the wrong route installed. Only
        // proceed once the new key is provably cleared.
        if !matches!(
            imet.withdraw_instance(vni, &self.rib_tx).await,
            evpn_imet::ImetWithdrawOutcome::Withdrawn { .. }
                | evpn_imet::ImetWithdrawOutcome::NotOriginated { .. }
        ) {
            return false;
        }
        // With the new key cleared, a genuine re-origination yields
        // `Originated` (or `ReplyDropped`, accepted optimistically as the
        // main path does); `AlreadyOriginated` here would mean the key was
        // never cleared and is treated as failure.
        matches!(
            imet.originate_instance(old_instance, &self.rib_tx).await,
            evpn_imet::ImetOriginateOutcome::Originated { .. }
                | evpn_imet::ImetOriginateOutcome::ReplyDropped { .. }
        )
    }
}

/// Build the failure returned from a redefine convergence step that ran after
/// the new IMET route was originated. When the IMET rollback restored the
/// committed Type 3 route the original step message stands; otherwise the
/// message is escalated because live Type 3 state may need operator repair.
fn redefine_imet_failure(
    imet_restored: bool,
    vni: rustbgpd_evpn::EvpnInstanceId,
    step_message: &str,
) -> DaemonEvpnRuntimeConvergeError {
    if imet_restored {
        DaemonEvpnRuntimeConvergeError::failed(step_message.to_string())
    } else {
        DaemonEvpnRuntimeConvergeError::failed(format!(
            "{step_message}; EVPN IMET redefine rollback also failed for L2VNI {vni} — \
             live Type 3 state may require repair/restart"
        ))
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
            // Atomic tenant teardown (delete-only multi-element / cross-resource)
            // is routed first; single-element deletes fall through to the
            // single-shape converters below.
            if is_tenant_teardown_plan(plan, current) {
                return self
                    .converge_tenant_teardown(current, candidate, plan)
                    .await;
            }
            // An `ip_vrf` relink mutates only the L2VNI->IP-VRF reference
            // metadata (no row changeset), so it is routed on the dedicated
            // reference-delta signal before the row-changeset blocks below.
            if is_ip_vrf_relink_plan(plan) {
                return self.converge_ip_vrf_relink(current, candidate, plan);
            }
            // Pure add-only build-up across multiple rows/domains is safe to
            // converge with full candidate snapshots. Generic mixed edits
            // (adds with deletes/redefines) stay fail-closed below.
            if is_additive_build_up_plan(plan) {
                return self
                    .converge_additive_build_up(current, candidate, plan)
                    .await;
            }
            // A standalone L2VNI swap is the conservative mixed-edit slice:
            // add and delete L2VNIs in one candidate while leaving IP-VRFs,
            // Ethernet Segments, redefines, and relinks untouched.
            if is_l2vni_swap_plan(plan) {
                return self.converge_l2vni_swap(current, candidate, plan).await;
            }
            // Teardown + pure relink (both routed above) own reference changes.
            // For every other route, reject a relink mixed into the request so it
            // can't diverge the dataplane (ES path) or apply unvalidated.
            validate_no_unexpected_relink(current, candidate, plan)?;
            if plan.evpn_instances.has_changes() {
                if plan.evpn_instances.added.is_empty()
                    && !plan.evpn_instances.deleted.is_empty()
                    && plan.evpn_instances.redefined.is_empty()
                {
                    return self.converge_l2vni_delete(current, candidate, plan).await;
                }
                if plan.evpn_instances.added.is_empty()
                    && plan.evpn_instances.deleted.is_empty()
                    && !plan.evpn_instances.redefined.is_empty()
                {
                    return self.converge_l2vni_redefine(current, candidate, plan).await;
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
                if plan.ip_vrfs.added.is_empty()
                    && plan.ip_vrfs.deleted.is_empty()
                    && !plan.ip_vrfs.redefined.is_empty()
                {
                    return self.converge_ip_vrf_redefine(current, candidate, plan);
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
            "L2VNI add cannot be combined with Ethernet Segment changes in one request; apply each as a separate ApplyEvpnRuntime request",
        ));
    }
    if !plan.evpn_instances.deleted.is_empty() || !plan.evpn_instances.redefined.is_empty() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports only add-only L2VNI changes; combining add/delete/redefine in one request is not supported — apply each change as a separate ApplyEvpnRuntime request (tracked in #210)",
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
            "ApplyEvpnRuntime currently supports only delete-only L2VNI changes; combining add/delete/redefine in one request is not supported — apply each change as a separate ApplyEvpnRuntime request (tracked in #210)",
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
            "L2VNI {deleted_vni} is an Ethernet Segment member; delete it together with its Ethernet Segment (atomic tenant teardown) or after removing it from the segment"
        )));
    }

    Ok(instance)
}

fn is_l2vni_swap_plan(plan: &rustbgpd_evpn::EvpnRuntimePlan) -> bool {
    !plan.evpn_instances.added.is_empty()
        && !plan.evpn_instances.deleted.is_empty()
        && plan.evpn_instances.redefined.is_empty()
        && !plan.ip_vrfs.has_changes()
        && !plan.ethernet_segments.has_changes()
}

fn validate_l2vni_swap(
    current: &rustbgpd_evpn::EvpnRuntimeModel,
    candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
    plan: &rustbgpd_evpn::EvpnRuntimePlan,
) -> Result<
    (
        Vec<rustbgpd_evpn::EvpnInstance>,
        Vec<rustbgpd_evpn::EvpnInstance>,
    ),
    DaemonEvpnRuntimeConvergeError,
> {
    if !is_l2vni_swap_plan(plan) {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime L2VNI swap requires only L2VNI add/delete changes with no redefines, IP-VRF changes, or Ethernet Segment changes",
        ));
    }
    if plan.ip_vrf_references_changed || current.ip_vrfs() != candidate.ip_vrfs() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime L2VNI swap requires standalone L2VNIs; ip_vrf link changes must be applied separately",
        ));
    }

    let mut added_instances = Vec::with_capacity(plan.evpn_instances.added.len());
    for &raw_vni in &plan.evpn_instances.added {
        let vni = rustbgpd_evpn::EvpnInstanceId::new(raw_vni).map_err(|err| {
            DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "invalid planned added L2VNI {raw_vni}: {err}"
            ))
        })?;
        if current.instances().get(vni).is_some() {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "planned added L2VNI {vni} is already committed"
            )));
        }
        let Some(instance) = candidate.instances().get(vni).cloned() else {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "candidate is missing planned added L2VNI {vni}"
            )));
        };
        added_instances.push(instance);
    }

    let mut deleted_instances = Vec::with_capacity(plan.evpn_instances.deleted.len());
    for &raw_vni in &plan.evpn_instances.deleted {
        let vni = rustbgpd_evpn::EvpnInstanceId::new(raw_vni).map_err(|err| {
            DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "invalid planned deleted L2VNI {raw_vni}: {err}"
            ))
        })?;
        let Some(instance) = current.instances().get(vni).cloned() else {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "planned deleted L2VNI {vni} is not committed"
            )));
        };
        if candidate.instances().get(vni).is_some() {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "candidate still contains planned deleted L2VNI {vni}"
            )));
        }
        if current
            .ethernet_segments()
            .iter()
            .any(|segment| segment.member_vnis.contains(&vni))
        {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "L2VNI swap cannot delete Ethernet Segment member L2VNI {vni}; use atomic tenant teardown or remove the segment membership first"
            )));
        }
        deleted_instances.push(instance);
    }

    Ok((added_instances, deleted_instances))
}

fn validate_single_l2vni_redefine(
    current: &rustbgpd_evpn::EvpnRuntimeModel,
    candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
    plan: &rustbgpd_evpn::EvpnRuntimePlan,
) -> Result<rustbgpd_evpn::EvpnInstanceId, DaemonEvpnRuntimeConvergeError> {
    if plan.ip_vrfs.has_changes() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports L2VNI redefine only when IP-VRF changes are absent",
        ));
    }
    if plan.ethernet_segments.has_changes() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports L2VNI redefine only when Ethernet Segment changes are absent",
        ));
    }
    if !plan.evpn_instances.added.is_empty() || !plan.evpn_instances.deleted.is_empty() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports only redefine-only L2VNI changes; combining add/delete/redefine in one request is not supported — apply each change as a separate ApplyEvpnRuntime request (tracked in #210)",
        ));
    }
    if plan.evpn_instances.redefined.len() != 1 {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports exactly one redefined L2VNI per request",
        ));
    }

    let raw_vni = plan.evpn_instances.redefined[0];
    let redefined_vni = rustbgpd_evpn::EvpnInstanceId::new(raw_vni).map_err(|err| {
        DaemonEvpnRuntimeConvergeError::unsupported(format!(
            "invalid planned L2VNI {raw_vni}: {err}"
        ))
    })?;
    if current.instances().get(redefined_vni).is_none() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
            "planned L2VNI {redefined_vni} is not committed"
        )));
    }
    if candidate.instances().get(redefined_vni).is_none() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
            "candidate is missing planned L2VNI {redefined_vni}"
        )));
    }

    // A *pure* `ip_vrf` relink (link change with no row edits) is routed to
    // `converge_ip_vrf_relink` upstream on `plan.ip_vrf_references_changed`. This
    // check therefore only fires for a redefine *combined* with a relink (the
    // L2VNI row is redefined AND its link moved) — keep that fail-closed; a
    // redefine and a relink must be applied as separate requests.
    if current.ip_vrfs() != candidate.ip_vrfs() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime does not support an L2VNI redefine combined with an ip_vrf relink in one request; apply the relink separately",
        ));
    }

    Ok(redefined_vni)
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

/// True when the plan is a pure `ip_vrf` relink: the L2VNI->IP-VRF reference
/// metadata changed but no IP-VRF / L2VNI / Ethernet Segment row did. Routed
/// before the row-changeset blocks; teardown is classified first so a delete
/// (which also shifts references) never lands here.
fn is_ip_vrf_relink_plan(plan: &rustbgpd_evpn::EvpnRuntimePlan) -> bool {
    plan.ip_vrf_references_changed
        && !plan.evpn_instances.has_changes()
        && !plan.ip_vrfs.has_changes()
        && !plan.ethernet_segments.has_changes()
}

/// Validate an `ip_vrf` relink: no row changesets, and the divergence is purely
/// in the IP-VRF reference metadata.
fn validate_ip_vrf_relink(
    current: &rustbgpd_evpn::EvpnRuntimeModel,
    candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
    plan: &rustbgpd_evpn::EvpnRuntimePlan,
) -> Result<(), DaemonEvpnRuntimeConvergeError> {
    if plan.evpn_instances.has_changes()
        || plan.ip_vrfs.has_changes()
        || plan.ethernet_segments.has_changes()
    {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime ip_vrf relink converge requires no L2VNI / IP-VRF / Ethernet Segment row changes",
        ));
    }
    if !plan.ip_vrf_references_changed || !current.ip_vrfs().references_differ(candidate.ip_vrfs())
    {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime ip_vrf relink converge requires an IP-VRF link reference change",
        ));
    }
    Ok(())
}

/// Central guard for the fourth change signal. `ip_vrf_references_changed` (an
/// L2VNI's `ip_vrf` link moving) is not one of the three row changesets the
/// single-shape validators gate on, so without this a relink could be silently
/// composed with any row shape — e.g. an ES change would commit the candidate
/// but never republish `ip_vrfs`, diverging the dataplane from the committed
/// model. The invariant: a pure relink and atomic tenant teardown own reference
/// changes on their own paths (both routed before this); a row-shape change may
/// only carry the link delta intrinsic to its own added/deleted L2VNIs. Any
/// other relinked VNI is a mixed-in relink and is rejected.
fn validate_no_unexpected_relink(
    current: &rustbgpd_evpn::EvpnRuntimeModel,
    candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
    plan: &rustbgpd_evpn::EvpnRuntimePlan,
) -> Result<(), DaemonEvpnRuntimeConvergeError> {
    if !plan.ip_vrf_references_changed {
        return Ok(());
    }
    let touched: std::collections::BTreeSet<rustbgpd_evpn::EvpnInstanceId> = plan
        .evpn_instances
        .added
        .iter()
        .chain(plan.evpn_instances.deleted.iter())
        .filter_map(|raw| rustbgpd_evpn::EvpnInstanceId::new(*raw).ok())
        .collect();
    let current_links = current.ip_vrfs().l2vni_link_map();
    let candidate_links = candidate.ip_vrfs().l2vni_link_map();
    let mut vnis: std::collections::BTreeSet<rustbgpd_evpn::EvpnInstanceId> =
        current_links.keys().copied().collect();
    vnis.extend(candidate_links.keys().copied());
    for vni in vnis {
        if current_links.get(&vni) != candidate_links.get(&vni) && !touched.contains(&vni) {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "ApplyEvpnRuntime: L2VNI {vni} `ip_vrf` link change (relink) is mixed into another \
                 runtime change; apply the relink as a separate request"
            )));
        }
    }
    Ok(())
}

/// True when the plan is a pure add-only build-up that the single-row add paths
/// cannot express: multiple domains change together, or one domain adds more
/// than one row. Single-row adds keep routing through their narrower legacy
/// validators.
fn is_additive_build_up_plan(plan: &rustbgpd_evpn::EvpnRuntimePlan) -> bool {
    let no_deletes_or_redefines = plan.evpn_instances.deleted.is_empty()
        && plan.evpn_instances.redefined.is_empty()
        && plan.ip_vrfs.deleted.is_empty()
        && plan.ip_vrfs.redefined.is_empty()
        && plan.ethernet_segments.deleted.is_empty()
        && plan.ethernet_segments.redefined.is_empty();
    let has_add = !plan.evpn_instances.added.is_empty()
        || !plan.ip_vrfs.added.is_empty()
        || !plan.ethernet_segments.added.is_empty();
    if !(no_deletes_or_redefines && has_add) {
        return false;
    }
    let resource_types_added = [
        !plan.evpn_instances.added.is_empty(),
        !plan.ip_vrfs.added.is_empty(),
        !plan.ethernet_segments.added.is_empty(),
    ]
    .into_iter()
    .filter(|changed| *changed)
    .count();
    resource_types_added > 1
        || plan.evpn_instances.added.len() > 1
        || plan.ip_vrfs.added.len() > 1
        || plan.ethernet_segments.added.len() > 1
}

fn validate_additive_build_up(
    current: &rustbgpd_evpn::EvpnRuntimeModel,
    candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
    plan: &rustbgpd_evpn::EvpnRuntimePlan,
) -> Result<Vec<rustbgpd_evpn::EvpnInstance>, DaemonEvpnRuntimeConvergeError> {
    if !is_additive_build_up_plan(plan) {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime additive build-up requires pure add-only changes across multiple rows or EVPN runtime domains",
        ));
    }
    validate_no_unexpected_relink(current, candidate, plan)?;

    let mut added_instances = Vec::with_capacity(plan.evpn_instances.added.len());
    for &raw_vni in &plan.evpn_instances.added {
        let vni = rustbgpd_evpn::EvpnInstanceId::new(raw_vni).map_err(|err| {
            DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "invalid planned L2VNI {raw_vni}: {err}"
            ))
        })?;
        if current.instances().get(vni).is_some() {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "planned L2VNI {vni} is already committed"
            )));
        }
        let Some(instance) = candidate.instances().get(vni).cloned() else {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "candidate is missing planned L2VNI {vni}"
            )));
        };
        added_instances.push(instance);
    }

    for name in &plan.ip_vrfs.added {
        if current.ip_vrfs().get(name).is_some() {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "planned IP-VRF {name:?} is already committed"
            )));
        }
        if candidate.ip_vrfs().get(name).is_none() {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "candidate is missing planned IP-VRF {name:?}"
            )));
        }
    }

    for esi in &plan.ethernet_segments.added {
        if current
            .ethernet_segments()
            .iter()
            .any(|segment| segment.esi == *esi)
        {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "planned Ethernet Segment {esi} is already committed"
            )));
        }
        let Some(segment) = candidate
            .ethernet_segments()
            .iter()
            .find(|segment| segment.esi == *esi)
        else {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "candidate is missing planned Ethernet Segment {esi}"
            )));
        };
        validate_ethernet_segment_member_vnis_present(
            *esi,
            &segment.member_vnis,
            candidate.instances(),
        )?;
    }

    Ok(added_instances)
}

/// Build the failure returned from an additive build-up step. Escalates when
/// the rollback could not republish committed snapshots or withdraw newly
/// originated Type 3 routes.
fn additive_build_failure(restored: bool, step_message: &str) -> DaemonEvpnRuntimeConvergeError {
    if restored {
        DaemonEvpnRuntimeConvergeError::failed(step_message.to_string())
    } else {
        DaemonEvpnRuntimeConvergeError::failed(format!(
            "{step_message}; EVPN additive build-up rollback also failed — \
             live runtime state may require repair/restart"
        ))
    }
}

fn l2vni_swap_failure(restored: bool, step_message: &str) -> DaemonEvpnRuntimeConvergeError {
    if restored {
        DaemonEvpnRuntimeConvergeError::failed(step_message.to_string())
    } else {
        DaemonEvpnRuntimeConvergeError::failed(format!(
            "{step_message}; EVPN L2VNI swap rollback also failed — \
             live runtime state may require repair/restart"
        ))
    }
}

/// Whether `plan` is an atomic tenant teardown — a delete-only mutation that
/// the single-shape converters cannot handle (multi-element, cross-resource,
/// an ES-member L2VNI delete, or a still-referenced IP-VRF delete). Clean
/// single-element non-ES, non-referenced deletes return `false` so they keep
/// routing to the existing single-shape delete converters.
fn is_tenant_teardown_plan(
    plan: &rustbgpd_evpn::EvpnRuntimePlan,
    current: &rustbgpd_evpn::EvpnRuntimeModel,
) -> bool {
    let no_adds = plan.evpn_instances.added.is_empty()
        && plan.ip_vrfs.added.is_empty()
        && plan.ethernet_segments.added.is_empty();
    // L2VNI / IP-VRF redefines stay on their dedicated single-redefine paths;
    // teardown allows ES redefines (member-shrink) only.
    let no_l2_ipvrf_redefine =
        plan.evpn_instances.redefined.is_empty() && plan.ip_vrfs.redefined.is_empty();
    let has_deletion = !plan.evpn_instances.deleted.is_empty()
        || !plan.ip_vrfs.deleted.is_empty()
        || !plan.ethernet_segments.deleted.is_empty();
    if !(no_adds && no_l2_ipvrf_redefine && has_deletion) {
        return false;
    }

    let resource_types_changed = [
        plan.evpn_instances.has_changes(),
        plan.ip_vrfs.has_changes(),
        plan.ethernet_segments.has_changes(),
    ]
    .into_iter()
    .filter(|changed| *changed)
    .count();
    let multi_resource = resource_types_changed > 1;
    let multi_element = plan.evpn_instances.deleted.len() > 1
        || plan.ip_vrfs.deleted.len() > 1
        || plan.ethernet_segments.deleted.len() > 1;
    let es_member_l2vni_deleted = plan.evpn_instances.deleted.iter().any(|&raw| {
        rustbgpd_evpn::EvpnInstanceId::new(raw).is_ok_and(|vni| {
            current
                .ethernet_segments()
                .iter()
                .any(|segment| segment.member_vnis.contains(&vni))
        })
    });
    let referenced_ip_vrf_deleted = plan
        .ip_vrfs
        .deleted
        .iter()
        .any(|name| current.ip_vrfs().is_referenced(name));

    multi_resource || multi_element || es_member_l2vni_deleted || referenced_ip_vrf_deleted
}

/// Validate an atomic tenant teardown and return the deleted L2VNI instances
/// (needed for IMET withdraw + SVI gating + rollback restore). Accepts a
/// delete-only plan: ≥1 deletion, no adds, no L2VNI/IP-VRF redefines, ES
/// redefines limited to member-shrink, and the candidate internally consistent
/// (no IP-VRF deleted while an L2VNI still references it; no ES still listing a
/// deleted member VNI).
#[expect(
    clippy::too_many_lines,
    reason = "sequential teardown guards read clearer inline than split across helpers"
)]
fn validate_tenant_teardown(
    current: &rustbgpd_evpn::EvpnRuntimeModel,
    candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
    plan: &rustbgpd_evpn::EvpnRuntimePlan,
) -> Result<Vec<rustbgpd_evpn::EvpnInstance>, DaemonEvpnRuntimeConvergeError> {
    if !plan.evpn_instances.added.is_empty()
        || !plan.ip_vrfs.added.is_empty()
        || !plan.ethernet_segments.added.is_empty()
    {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime tenant teardown does not support adds in the same request",
        ));
    }
    if !plan.evpn_instances.redefined.is_empty() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime tenant teardown does not support L2VNI redefine in the same request",
        ));
    }
    if !plan.ip_vrfs.redefined.is_empty() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime tenant teardown does not support IP-VRF redefine in the same request",
        ));
    }
    if plan.evpn_instances.deleted.is_empty()
        && plan.ip_vrfs.deleted.is_empty()
        && plan.ethernet_segments.deleted.is_empty()
    {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime tenant teardown requires at least one deletion",
        ));
    }

    // ES redefines in a teardown may only shrink member_vnis (drop the VNIs
    // being deleted); every other ES field must be unchanged.
    for esi in &plan.ethernet_segments.redefined {
        let Some(cur) = current
            .ethernet_segments()
            .iter()
            .find(|seg| seg.esi == *esi)
        else {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "planned redefined Ethernet Segment {esi} is not committed"
            )));
        };
        let Some(cand) = candidate
            .ethernet_segments()
            .iter()
            .find(|seg| seg.esi == *esi)
        else {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "candidate is missing planned redefined Ethernet Segment {esi}"
            )));
        };
        let member_shrink_only = cand.member_vnis.len() < cur.member_vnis.len()
            && cand.member_vnis.iter().all(|v| cur.member_vnis.contains(v))
            && {
                let mut probe = cur.clone();
                probe.member_vnis.clone_from(&cand.member_vnis);
                &probe == cand
            };
        if !member_shrink_only {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "ApplyEvpnRuntime tenant teardown supports Ethernet Segment {esi} redefine only as a member_vnis shrink; other field changes are not supported"
            )));
        }
    }

    // Resolve + validate each deleted L2VNI.
    let mut deleted_instances = Vec::with_capacity(plan.evpn_instances.deleted.len());
    for &raw_vni in &plan.evpn_instances.deleted {
        let vni = rustbgpd_evpn::EvpnInstanceId::new(raw_vni).map_err(|err| {
            DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "invalid planned L2VNI {raw_vni}: {err}"
            ))
        })?;
        let Some(instance) = current.instances().get(vni).cloned() else {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "planned L2VNI {vni} is not committed"
            )));
        };
        if candidate.instances().get(vni).is_some() {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "candidate still contains planned deleted L2VNI {vni}"
            )));
        }
        deleted_instances.push(instance);
    }
    let deleted_vnis: std::collections::BTreeSet<rustbgpd_evpn::EvpnInstanceId> =
        deleted_instances.iter().map(|inst| inst.id).collect();

    // Consistency A — a deleted IP-VRF must have all its referencing L2VNIs
    // deleted in the same request (no surviving L2VNI may dangle on it).
    // Defense-in-depth: config validation (`config/mod.rs` L2VNI->IP-VRF
    // cross-ref) already rejects a candidate that leaves a dangling reference,
    // so the dangling-ref branch below is unreachable from the gRPC entry
    // point — kept in case a future caller constructs a candidate directly.
    for name in &plan.ip_vrfs.deleted {
        if current.ip_vrfs().get(name).is_none() {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "planned IP-VRF {name:?} is not committed"
            )));
        }
        if candidate.ip_vrfs().get(name).is_some() {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "candidate still contains planned deleted IP-VRF {name:?}"
            )));
        }
        let refs = current
            .ip_vrfs()
            .referenced_l2vnis(name)
            .cloned()
            .unwrap_or_default();
        for vni in refs {
            if !deleted_vnis.contains(&vni) {
                return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                    "tenant teardown: IP-VRF {name:?} is referenced by L2VNI {vni}, which must be deleted in the same request"
                )));
            }
        }
    }

    // Consistency B — no candidate Ethernet Segment may still list a deleted
    // VNI as a member (delete or member-shrink the segment in the same request).
    // Like Consistency A, config validation (`config/mod.rs` ES member_vnis
    // existence check) rejects a candidate ES that references an absent VNI, so
    // this branch is unreachable from the gRPC entry point and stands as
    // defense-in-depth for direct candidate construction.
    for seg in candidate.ethernet_segments() {
        for vni in &seg.member_vnis {
            if deleted_vnis.contains(vni) {
                return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                    "tenant teardown: candidate Ethernet Segment {} still references deleted L2VNI {vni}; delete or member-shrink the segment in the same request",
                    seg.esi
                )));
            }
        }
    }

    // Validate each deleted Ethernet Segment.
    for esi in &plan.ethernet_segments.deleted {
        if !current
            .ethernet_segments()
            .iter()
            .any(|seg| seg.esi == *esi)
        {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "planned deleted Ethernet Segment {esi} is not committed"
            )));
        }
        if candidate
            .ethernet_segments()
            .iter()
            .any(|seg| seg.esi == *esi)
        {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "candidate still contains planned deleted Ethernet Segment {esi}"
            )));
        }
    }

    Ok(deleted_instances)
}

/// Build the failure returned from a tenant-teardown step. Escalates when the
/// IMET rollback could not restore the committed Type 3 routes.
fn teardown_failure(imet_restored: bool, step_message: &str) -> DaemonEvpnRuntimeConvergeError {
    if imet_restored {
        DaemonEvpnRuntimeConvergeError::failed(step_message.to_string())
    } else {
        DaemonEvpnRuntimeConvergeError::failed(format!(
            "{step_message}; EVPN IMET teardown rollback also failed — \
             live Type 3 state may require repair/restart"
        ))
    }
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
            "ApplyEvpnRuntime currently supports only add-only IP-VRF changes — apply a delete/redefine as a separate ApplyEvpnRuntime request (tracked in #210)",
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
            "ApplyEvpnRuntime currently supports only delete-only IP-VRF changes — apply an add/redefine as a separate ApplyEvpnRuntime request (tracked in #210)",
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
            "IP-VRF {deleted_name:?} is referenced by an L2VNI; delete it together with the referencing L2VNI(s) (atomic tenant teardown) or after removing the reference"
        )));
    }

    Ok(deleted_name)
}

fn validate_single_ip_vrf_redefine(
    current: &rustbgpd_evpn::EvpnRuntimeModel,
    candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
    plan: &rustbgpd_evpn::EvpnRuntimePlan,
) -> Result<String, DaemonEvpnRuntimeConvergeError> {
    if plan.evpn_instances.has_changes() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports IP-VRF redefine only when L2VNI changes are absent",
        ));
    }
    if plan.ethernet_segments.has_changes() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports IP-VRF redefine only when Ethernet Segment changes are absent",
        ));
    }
    if !plan.ip_vrfs.added.is_empty() || !plan.ip_vrfs.deleted.is_empty() {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports only redefine-only IP-VRF changes — apply an add/delete as a separate ApplyEvpnRuntime request (tracked in #210)",
        ));
    }
    if plan.ip_vrfs.redefined.len() != 1 {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(
            "ApplyEvpnRuntime currently supports exactly one redefined IP-VRF per request",
        ));
    }

    let name = plan.ip_vrfs.redefined[0].clone();
    let Some(old) = current.ip_vrfs().get(&name) else {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
            "planned redefined IP-VRF {name:?} is not committed"
        )));
    };
    let Some(new) = candidate.ip_vrfs().get(&name) else {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
            "candidate is missing planned redefined IP-VRF {name:?}"
        )));
    };

    // The L3VNI, VRF device, L3VXLAN device, and table id are the IP-VRF's
    // kernel-object identity; changing one is a VRF lifecycle operation (destroy
    // + recreate the kernel VRF), which is restart-required by design — a runtime
    // drain/recreate would risk a dual-state window (kernel on the old identity
    // while the originator publishes the new). `router_mac` is NOT identity: it
    // is an accepted live route/policy-field redefine (the Type 5 originator +
    // dataplane self-diff it cleanly), so it is intentionally absent from this
    // guard.
    if old.id != new.id
        || old.vrf_device != new.vrf_device
        || old.l3vxlan_device != new.l3vxlan_device
        || old.table_id != new.table_id
    {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
            "ApplyEvpnRuntime IP-VRF redefine supports live route/policy/egress field changes (rd, route_targets, local_vtep_ip, router_mac) for {name:?}; changing the L3VNI, vrf_device, l3vxlan_device, or table_id is restart-required by design (kernel VRF identity lifecycle)"
        )));
    }

    let current_refs = current
        .ip_vrfs()
        .referenced_l2vnis(&name)
        .cloned()
        .unwrap_or_default();
    let candidate_refs = candidate
        .ip_vrfs()
        .referenced_l2vnis(&name)
        .cloned()
        .unwrap_or_default();
    if current_refs != candidate_refs
        || current.ip_vrfs().is_referenced(&name) != candidate.ip_vrfs().is_referenced(&name)
    {
        return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
            "ApplyEvpnRuntime does not support an IP-VRF redefine combined with an ip_vrf relink for {name:?} in one request; apply the relink as a separate request"
        )));
    }

    Ok(name)
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
            "Ethernet Segment add cannot be combined with ES delete/redefine in one request; apply each as a separate ApplyEvpnRuntime request",
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
            "ApplyEvpnRuntime currently supports only delete-only Ethernet Segment changes — apply an add/redefine as a separate ApplyEvpnRuntime request (tracked in #210)",
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
            "ApplyEvpnRuntime currently supports only redefine-only Ethernet Segment changes — apply an add/delete as a separate ApplyEvpnRuntime request (tracked in #210)",
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

#[cfg(test)]
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
    evpn_runtime_candidate_from_config(&candidate)
}

fn evpn_runtime_candidate_from_config(
    candidate: &Config,
) -> Result<rustbgpd_evpn::EvpnRuntimeCandidate, GrpcEvpnRuntimeApplyError> {
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

#[cfg(test)]
pub(crate) async fn apply_evpn_runtime_request<C>(
    request: &proto::ApplyEvpnRuntimeRequest,
    coordinator: &Mutex<rustbgpd_evpn::EvpnRuntimeCoordinator>,
    apply_lock: &tokio::sync::Mutex<()>,
    converger: &C,
) -> Result<proto::ApplyEvpnRuntimeResponse, GrpcEvpnRuntimeApplyError>
where
    C: DaemonEvpnRuntimeConverger + ?Sized,
{
    let candidate = evpn_runtime_candidate_from_toml(&request.candidate_toml)?;
    apply_evpn_runtime_candidate(
        candidate,
        request.validate_only,
        coordinator,
        apply_lock,
        converger,
    )
    .await
}

#[cfg(test)]
async fn apply_evpn_runtime_candidate<C>(
    candidate: rustbgpd_evpn::EvpnRuntimeCandidate,
    validate_only: bool,
    coordinator: &Mutex<rustbgpd_evpn::EvpnRuntimeCoordinator>,
    apply_lock: &tokio::sync::Mutex<()>,
    converger: &C,
) -> Result<proto::ApplyEvpnRuntimeResponse, GrpcEvpnRuntimeApplyError>
where
    C: DaemonEvpnRuntimeConverger + ?Sized,
{
    let _apply_guard = apply_lock.lock().await;
    apply_evpn_runtime_candidate_locked(candidate, validate_only, coordinator, converger).await
}

async fn apply_evpn_runtime_candidate_locked<C>(
    candidate: rustbgpd_evpn::EvpnRuntimeCandidate,
    validate_only: bool,
    coordinator: &Mutex<rustbgpd_evpn::EvpnRuntimeCoordinator>,
    converger: &C,
) -> Result<proto::ApplyEvpnRuntimeResponse, GrpcEvpnRuntimeApplyError>
where
    C: DaemonEvpnRuntimeConverger + ?Sized,
{
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

    if validate_only {
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

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant as StdInstant};

    use rustbgpd_rib::RibCommandError;
    use rustbgpd_telemetry::BgpMetrics;
    use tokio::sync::{broadcast, watch};

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

    /// Signals entry into `converge` and then blocks until the test grants
    /// a permit — lets a test drop the caller's future mid-converge.
    struct GatedRuntimeConverger {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Semaphore>,
    }

    impl DaemonEvpnRuntimeConverger for GatedRuntimeConverger {
        fn converge<'a>(
            &'a self,
            _current: &'a rustbgpd_evpn::EvpnRuntimeModel,
            _candidate: &'a rustbgpd_evpn::EvpnRuntimeCandidate,
            _plan: &'a rustbgpd_evpn::EvpnRuntimePlan,
        ) -> DaemonEvpnRuntimeConvergeFuture<'a> {
            Box::pin(async move {
                self.entered.notify_one();
                // A closed semaphore must fail the test loudly — silently
                // proceeding would let the cancellation-shield tests pass
                // without ever blocking mid-converge.
                let _permit = self
                    .release
                    .acquire()
                    .await
                    .expect("gate semaphore closed while converge was blocked");
                Ok(())
            })
        }
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

    // A full tenant: L2VNI 100 that is both an Ethernet Segment member and
    // linked to IP-VRF tenant-blue. Tearing this down to the minimal candidate
    // exercises ES-aware L2VNI delete + ES delete + linked IP-VRF delete at
    // once.
    fn es_member_l2vni_linked_ip_vrf_runtime_candidate_toml() -> &'static str {
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

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.1"
"#
    }

    fn es_member_l2vni_linked_ip_vrf_svi_runtime_candidate_toml() -> &'static str {
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
advertise_svi_mac = true

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

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.1"
"#
    }

    fn two_tenant_additive_runtime_candidate_toml() -> &'static str {
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
advertise_svi_mac = true

[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.1"
ip_vrf = "tenant-green"
advertise_svi_mac = true

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
local_vtep_ip = "10.0.0.101"
router_mac = "02:00:00:00:00:02"
vrf_device = "vrf-green"
l3vxlan_device = "vni6000"
table_id = 6000

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

    fn relink_green_plus_l2vni_runtime_candidate_toml() -> &'static str {
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
ip_vrf = "tenant-green"

[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.1"
ip_vrf = "tenant-green"

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
vni = 5001
rd = "65000:5001"
route_targets = ["65000:5001"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:02"
vrf_device = "vrf-green"
l3vxlan_device = "vni5001"
table_id = 5001

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:02"
member_vnis = [200]
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

    fn l2vni_swap_linked_ip_vrf_runtime_candidate_toml() -> &'static str {
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
vni = 300
rd = "65000:300"
route_targets = ["65000:300"]
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

    fn l2vni_swap_runtime_candidate_toml() -> &'static str {
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
vni = 300
rd = "65000:300"
route_targets = ["65000:300"]
local_vtep_ip = "10.0.0.1"
"#
    }

    fn l2vni_swap_delete_vni100_runtime_candidate_toml() -> &'static str {
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
vni = 200
rd = "65000:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.1"

[[evpn_instances]]
vni = 300
rd = "65000:300"
route_targets = ["65000:300"]
local_vtep_ip = "10.0.0.1"
"#
    }

    // Two L2VNIs where VNI 100 advertises its SVI MAC. Tearing both down is a
    // multi-element teardown that exercises the SVI drain leg of
    // converge_tenant_teardown.
    fn two_l2vni_one_svi_runtime_candidate_toml() -> &'static str {
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
advertise_svi_mac = true

[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.1"
"#
    }

    // Redefines VNI 100's route identity (new RD + RT) on top of the
    // `two_l2vni` baseline; VNI 200 is untouched. The single-L2VNI-redefine
    // candidate.
    fn two_l2vni_one_redefined_l2vni_runtime_candidate_toml() -> &'static str {
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
rd = "65000:111"
route_targets = ["65000:111"]
local_vtep_ip = "10.0.0.1"

[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.1"
"#
    }

    // Redefines VNI 100 by flipping its dataplane aliasing-ECMP gate off; all
    // other fields (including RD/RT) are unchanged. Exercises the
    // dataplane-only `FdbNhg -> SingleDst` redefine transition.
    fn two_l2vni_aliasing_toggle_runtime_candidate_toml() -> &'static str {
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
apply_aliasing_ecmp = false

[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.1"
"#
    }

    // Redefines BOTH VNIs at once — used to assert the validator rejects a
    // multi-element redefine.
    fn two_l2vni_both_redefined_runtime_candidate_toml() -> &'static str {
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
rd = "65000:111"
route_targets = ["65000:111"]
local_vtep_ip = "10.0.0.1"

[[evpn_instances]]
vni = 200
rd = "65000:222"
route_targets = ["65000:222"]
local_vtep_ip = "10.0.0.1"
"#
    }

    // Redefines VNI 100 (new RD) AND adds a standalone IP-VRF — used to assert
    // the validator rejects a redefine mixed with an IP-VRF change.
    fn two_l2vni_one_redefined_plus_ip_vrf_runtime_candidate_toml() -> &'static str {
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
rd = "65000:111"
route_targets = ["65000:111"]
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

    // Redefines VNI 100 (new RD) while it remains an Ethernet Segment member.
    fn two_l2vni_one_es_redefined_member_runtime_candidate_toml() -> &'static str {
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
rd = "65000:111"
route_targets = ["65000:111"]
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

    // Two declared IP-VRFs (tenant-blue, tenant-green) with L2VNI 100 linked to
    // tenant-blue. The `_relinked` variant moves only the L2VNI's `ip_vrf` to
    // tenant-green — every IP-VRF and L2VNI row is byte-identical, so the diff
    // is a pure reference-metadata (relink) change.
    fn relink_blue_runtime_candidate_toml() -> &'static str {
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

[[evpn_ip_vrfs]]
name = "tenant-green"
vni = 5001
rd = "65000:5001"
route_targets = ["65000:5001"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:02"
vrf_device = "vrf-green"
l3vxlan_device = "vni5001"
table_id = 5001
"#
    }

    fn relink_green_runtime_candidate_toml() -> &'static str {
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
ip_vrf = "tenant-green"

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
vni = 5001
rd = "65000:5001"
route_targets = ["65000:5001"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:02"
vrf_device = "vrf-green"
l3vxlan_device = "vni5001"
table_id = 5001
"#
    }

    // The relink fixtures' two IP-VRFs with no L2VNI — a baseline for adding a
    // linked L2VNI (the reference delta the central relink guard must allow).
    fn ip_vrfs_blue_green_runtime_candidate_toml() -> &'static str {
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
vni = 5001
rd = "65000:5001"
route_targets = ["65000:5001"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:02"
vrf_device = "vrf-green"
l3vxlan_device = "vni5001"
table_id = 5001
"#
    }

    fn ip_vrf_redefined_runtime_candidate_toml() -> &'static str {
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
rd = "65000:5555"
route_targets = ["65000:5555"]
local_vtep_ip = "10.0.0.101"
router_mac = "02:00:00:00:00:11"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#
    }

    fn ip_vrf_redefined_l3vni_runtime_candidate_toml() -> &'static str {
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
vni = 5001
rd = "65000:5555"
route_targets = ["65000:5555"]
local_vtep_ip = "10.0.0.101"
router_mac = "02:00:00:00:00:11"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5001"
table_id = 5001
"#
    }

    fn ip_vrf_redefined_plus_l2vni_runtime_candidate_toml() -> &'static str {
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
rd = "65000:5555"
route_targets = ["65000:5555"]
local_vtep_ip = "10.0.0.101"
router_mac = "02:00:00:00:00:11"
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

    fn two_ip_vrf_both_redefined_runtime_candidate_toml() -> &'static str {
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
rd = "65000:5555"
route_targets = ["65000:5555"]
local_vtep_ip = "10.0.0.101"
router_mac = "02:00:00:00:00:11"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000

[[evpn_ip_vrfs]]
name = "tenant-green"
vni = 6000
rd = "65000:6666"
route_targets = ["65000:6666"]
local_vtep_ip = "10.0.0.101"
router_mac = "02:00:00:00:00:12"
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

    fn two_l2vni_one_es_runtime_coordinator() -> Arc<Mutex<rustbgpd_evpn::EvpnRuntimeCoordinator>> {
        let current = runtime_candidate_from_toml(two_l2vni_one_es_runtime_candidate_toml());
        Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
            current.instances().clone(),
            rustbgpd_evpn::IpVrfTable::new(),
            current.ethernet_segments().to_vec(),
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
            via: None,
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

    async fn wait_for_recorded_evpn_key_matching<F>(
        records: &Arc<tokio::sync::Mutex<Vec<rustbgpd_wire::EvpnRouteKey>>>,
        message: &'static str,
        matches_key: F,
    ) where
        F: Fn(&rustbgpd_wire::EvpnRouteKey) -> bool,
    {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if records.lock().await.iter().any(&matches_key) {
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
    async fn apply_evpn_runtime_l2vni_swap_commits_after_convergence() {
        let coordinator = two_l2vni_runtime_coordinator();
        let apply_lock = tokio::sync::Mutex::new(());
        let converger = TestRuntimeConverger::ok();

        let response = apply_evpn_runtime_request(
            &proto::ApplyEvpnRuntimeRequest {
                candidate_toml: l2vni_swap_runtime_candidate_toml().to_string(),
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
        let instances = plan.evpn_instances.unwrap();
        assert_eq!(instances.added, vec!["300"]);
        assert_eq!(instances.deleted, vec!["200"]);
        let guard = coordinator.lock().unwrap();
        assert!(
            guard
                .model()
                .instances()
                .get(rustbgpd_evpn::EvpnInstanceId::new(300).unwrap())
                .is_some()
        );
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

    #[tokio::test]
    async fn apply_evpn_runtime_ip_vrf_redefine_commits_after_convergence() {
        let coordinator = ip_vrf_runtime_coordinator();
        let apply_lock = tokio::sync::Mutex::new(());
        let converger = TestRuntimeConverger::ok();

        let response = apply_evpn_runtime_request(
            &proto::ApplyEvpnRuntimeRequest {
                candidate_toml: ip_vrf_redefined_runtime_candidate_toml().to_string(),
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
        assert_eq!(plan.evpn_ip_vrfs.unwrap().redefined, vec!["tenant-blue"]);
        let guard = coordinator.lock().unwrap();
        let vrf = guard
            .model()
            .ip_vrfs()
            .get("tenant-blue")
            .expect("tenant-blue should still be committed");
        assert_eq!(guard.model().generation().as_u64(), 2);
        assert_eq!(vrf.id.as_u32(), 5000);
        assert_eq!(vrf.rd.to_string(), "65000:5555");
        assert_eq!(vrf.local_vtep_ip.to_string(), "10.0.0.101");
        assert_eq!(vrf.router_mac.to_string(), "02:00:00:00:00:11");
        assert_eq!(vrf.table_id, 5000);
        assert_eq!(vrf.vrf_device, "vrf-blue");
        assert_eq!(vrf.l3vxlan_device, "vni5000");
    }

    /// ADR-0080: dropping the request future mid-converge (a disconnected
    /// gRPC client) must not cancel the apply — the detached task finishes
    /// the commit and advances the reload baseline on its own.
    #[tokio::test]
    async fn apply_request_dropped_mid_converge_still_commits_and_advances_baseline() {
        let baseline =
            Config::load_toml_with_diagnostics(minimal_runtime_candidate_toml(), "test baseline")
                .unwrap();
        let coordinator = empty_evpn_runtime_coordinator();
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let converger = Arc::new(GatedRuntimeConverger {
            entered: entered.clone(),
            release: release.clone(),
        });
        let reload_apply = EvpnRuntimeReloadApply::new(
            coordinator.clone(),
            Arc::new(tokio::sync::Mutex::new(())),
            converger,
            baseline,
        );

        let request = proto::ApplyEvpnRuntimeRequest {
            candidate_toml: l2vni_runtime_candidate_toml().to_string(),
            validate_only: false,
        };
        let mut caller = Box::pin(reload_apply.apply_request(&request));
        tokio::select! {
            _ = &mut caller => panic!("apply must still be blocked in converge"),
            () = entered.notified() => {}
        }
        // Simulate the client disconnect: tonic drops the request future.
        drop(caller);
        release.add_permits(1);

        let deadline = StdInstant::now() + Duration::from_secs(5);
        loop {
            if coordinator.lock().unwrap().model().generation().as_u64() == 2
                && reload_apply.committed_config_locked().evpn_instances.len() == 1
            {
                break;
            }
            assert!(
                StdInstant::now() < deadline,
                "dropped caller cancelled the apply: generation/baseline never advanced"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// ADR-0080, SIGHUP flavor: shutdown aborts an in-flight reload task;
    /// the abort must not cancel an EVPN converge already past planning.
    #[tokio::test]
    async fn reload_apply_dropped_mid_converge_still_commits_and_advances_baseline() {
        let baseline =
            Config::load_toml_with_diagnostics(minimal_runtime_candidate_toml(), "test baseline")
                .unwrap();
        let candidate =
            Config::load_toml_with_diagnostics(l2vni_runtime_candidate_toml(), "test candidate")
                .unwrap();
        let coordinator = empty_evpn_runtime_coordinator();
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let converger = Arc::new(GatedRuntimeConverger {
            entered: entered.clone(),
            release: release.clone(),
        });
        let reload_apply = EvpnRuntimeReloadApply::new(
            coordinator.clone(),
            Arc::new(tokio::sync::Mutex::new(())),
            converger,
            baseline,
        );

        let apply = reload_apply.clone();
        let mut caller =
            Box::pin(async move { apply.apply_config_if_changed(&candidate, |_, _| true).await });
        tokio::select! {
            _ = &mut caller => panic!("reload apply must still be blocked in converge"),
            () = entered.notified() => {}
        }
        // Simulate the shutdown-time `JoinHandle::abort` of the reload task.
        drop(caller);
        release.add_permits(1);

        let deadline = StdInstant::now() + Duration::from_secs(5);
        loop {
            if coordinator.lock().unwrap().model().generation().as_u64() == 2
                && reload_apply.committed_config_locked().evpn_instances.len() == 1
            {
                break;
            }
            assert!(
                StdInstant::now() < deadline,
                "aborted reload cancelled the apply: generation/baseline never advanced"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// ADR-0085: a binding-only `[[ethernet_segments]]` edit plans as
    /// an EVPN runtime no-op (the binding lives outside the domain
    /// type the planner diffs) but must still advance the committed
    /// config AND republish the resolved bindings to the link-drain
    /// coordinator's watch — both directions: bind and unbind.
    #[tokio::test]
    async fn committed_config_advance_republishes_es_link_bindings() {
        let baseline = Config::load_toml_with_diagnostics(
            l2vni_one_es_runtime_candidate_toml(),
            "test baseline",
        )
        .unwrap();
        let bound_toml = format!(
            "{}interface = \"bond0\"\nrecovery_delay_secs = 5\n",
            l2vni_one_es_runtime_candidate_toml()
        );
        let bound = Config::load_toml_with_diagnostics(&bound_toml, "test candidate").unwrap();

        // Coordinator already holds the baseline model, so the
        // binding-only candidate is a planner no-op.
        let coordinator = Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
            baseline.resolve_evpn_instances().unwrap(),
            baseline.resolve_evpn_ip_vrfs().unwrap(),
            baseline.resolve_ethernet_segments().unwrap(),
        )));
        let (bindings_tx, mut bindings_rx) =
            tokio::sync::watch::channel(Arc::new(baseline.resolve_es_link_bindings().unwrap())
                as crate::evpn_es_link_drain::EsLinkBindings);
        let reload_apply = EvpnRuntimeReloadApply::new(
            coordinator,
            Arc::new(tokio::sync::Mutex::new(())),
            Arc::new(TestRuntimeConverger::ok()),
            baseline,
        )
        .with_es_link_bindings_publisher(Arc::new(bindings_tx));

        assert!(bindings_rx.borrow_and_update().is_empty());

        // Bind: SIGHUP-shaped apply commits (Noop) and republishes.
        let attempt = reload_apply
            .apply_config_if_changed(&bound, evpn_runtime_changed_for_test)
            .await;
        assert!(matches!(
            attempt.result,
            Ok(Some(EvpnRuntimeReloadApplyResult {
                outcome: EvpnRuntimeReloadOutcome::Noop,
                ..
            }))
        ));
        assert!(bindings_rx.has_changed().unwrap(), "binding add published");
        let published = bindings_rx.borrow_and_update().clone();
        let binding = published.values().next().expect("one binding");
        assert_eq!(binding.interface, "bond0");
        assert_eq!(binding.recovery_delay, Duration::from_secs(5));

        // Unbind: removing the keys republishes the empty map.
        let unbound = Config::load_toml_with_diagnostics(
            l2vni_one_es_runtime_candidate_toml(),
            "test candidate",
        )
        .unwrap();
        let attempt = reload_apply
            .apply_config_if_changed(&unbound, evpn_runtime_changed_for_test)
            .await;
        assert!(matches!(attempt.result, Ok(Some(_))));
        assert!(
            bindings_rx.has_changed().unwrap(),
            "binding removal published"
        );
        assert!(bindings_rx.borrow_and_update().is_empty());
    }

    fn evpn_runtime_changed_for_test(new_config: &Config, current: &Config) -> bool {
        new_config.evpn_instances != current.evpn_instances
            || new_config.evpn_ip_vrfs != current.evpn_ip_vrfs
            || new_config.ethernet_segments != current.ethernet_segments
    }

    #[test]
    fn validate_single_ip_vrf_redefine_accepts_one_redefined_vrf() {
        let current = runtime_model_from_candidate_toml(ip_vrf_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(ip_vrf_redefined_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);

        let redefined = validate_single_ip_vrf_redefine(&current, &candidate, &plan).unwrap();
        assert_eq!(redefined, "tenant-blue");
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

    #[test]
    fn validate_single_ip_vrf_redefine_rejects_mixed_l2vni_change() {
        let current = runtime_model_from_candidate_toml(ip_vrf_runtime_candidate_toml());
        let candidate =
            runtime_candidate_from_toml(ip_vrf_redefined_plus_l2vni_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);

        let error = validate_single_ip_vrf_redefine(&current, &candidate, &plan).unwrap_err();
        let DaemonEvpnRuntimeConvergeError::Unsupported(message) = error else {
            panic!("expected unsupported error, got {error:?}");
        };
        assert!(
            message.contains("L2VNI changes are absent"),
            "unexpected error message: {message}"
        );
    }

    #[test]
    fn validate_single_ip_vrf_redefine_rejects_multiple_redefined_vrfs() {
        let current = runtime_model_from_candidate_toml(two_ip_vrf_runtime_candidate_toml());
        let candidate =
            runtime_candidate_from_toml(two_ip_vrf_both_redefined_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);

        let error = validate_single_ip_vrf_redefine(&current, &candidate, &plan).unwrap_err();
        let DaemonEvpnRuntimeConvergeError::Unsupported(message) = error else {
            panic!("expected unsupported error, got {error:?}");
        };
        assert!(
            message.contains("exactly one redefined IP-VRF"),
            "unexpected error message: {message}"
        );
    }

    #[test]
    fn validate_single_ip_vrf_redefine_rejects_l3vni_device_or_table_change() {
        let current = runtime_model_from_candidate_toml(ip_vrf_runtime_candidate_toml());
        let candidate =
            runtime_candidate_from_toml(ip_vrf_redefined_l3vni_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);

        let error = validate_single_ip_vrf_redefine(&current, &candidate, &plan).unwrap_err();
        let DaemonEvpnRuntimeConvergeError::Unsupported(message) = error else {
            panic!("expected unsupported error, got {error:?}");
        };
        assert!(
            message.contains("L3VNI"),
            "unexpected error message: {message}"
        );
    }

    #[test]
    fn ip_vrf_relink_is_not_a_noop_and_classifies() {
        // A pure relink edits no IP-VRF / L2VNI / ES row, so without the
        // reference-delta signal the plan would read as a no-op and never
        // converge. Pin that the signal is set, the plan is non-noop, and the
        // relink classifier routes it.
        let current = runtime_model_from_candidate_toml(relink_blue_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(relink_green_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);

        assert!(
            !plan.evpn_instances.has_changes(),
            "L2VNI rows are identical"
        );
        assert!(!plan.ip_vrfs.has_changes(), "IP-VRF rows are identical");
        assert!(!plan.ethernet_segments.has_changes());
        assert!(plan.ip_vrf_references_changed, "the link reference moved");
        assert!(!plan.is_noop(), "a relink must not read as a no-op");
        assert!(is_ip_vrf_relink_plan(&plan));
        assert!(!is_tenant_teardown_plan(&plan, &current));
    }

    #[test]
    fn validate_ip_vrf_relink_accepts_pure_relink() {
        let current = runtime_model_from_candidate_toml(relink_blue_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(relink_green_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);

        validate_ip_vrf_relink(&current, &candidate, &plan).unwrap();
    }

    #[test]
    fn validate_ip_vrf_relink_rejects_row_changes() {
        // Dropping the L2VNI shifts references too, but it is a row delete — not
        // a pure relink — so the relink validator must fail closed.
        let current = runtime_model_from_candidate_toml(relink_blue_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(ip_vrf_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);

        assert!(plan.evpn_instances.has_changes() || plan.ip_vrfs.has_changes());
        let error = validate_ip_vrf_relink(&current, &candidate, &plan).unwrap_err();
        let DaemonEvpnRuntimeConvergeError::Unsupported(message) = error else {
            panic!("expected unsupported error, got {error:?}");
        };
        assert!(
            message.contains("no L2VNI / IP-VRF / Ethernet Segment row changes"),
            "unexpected error message: {message}"
        );
    }

    #[test]
    fn validate_no_unexpected_relink_rejects_relink_outside_add_delete() {
        // A relinked VNI that is neither added nor deleted (the dispatcher only
        // reaches this guard for non-pure-relink, non-teardown plans) is a relink
        // mixed into another change — e.g. ES change + relink, which would
        // otherwise commit but never republish ip_vrfs and diverge the dataplane.
        let current = runtime_model_from_candidate_toml(relink_blue_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(relink_green_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);
        assert!(plan.ip_vrf_references_changed);
        assert!(plan.evpn_instances.added.is_empty() && plan.evpn_instances.deleted.is_empty());

        let error = validate_no_unexpected_relink(&current, &candidate, &plan).unwrap_err();
        let DaemonEvpnRuntimeConvergeError::Unsupported(message) = error else {
            panic!("expected unsupported error, got {error:?}");
        };
        assert!(
            message.contains("relink") && message.contains("separate request"),
            "unexpected error message: {message}"
        );
    }

    #[test]
    fn validate_no_unexpected_relink_allows_linked_l2vni_add() {
        // Adding an L2VNI that links an IP-VRF is the reference delta intrinsic to
        // that add (the VNI is in evpn_instances.added), so the guard must allow
        // it — otherwise building up a linked tenant would fail closed.
        let current =
            runtime_model_from_candidate_toml(ip_vrfs_blue_green_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(relink_blue_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);
        assert_eq!(plan.evpn_instances.added, vec![100]);
        assert!(plan.ip_vrf_references_changed);

        validate_no_unexpected_relink(&current, &candidate, &plan).unwrap();
    }

    #[test]
    fn validate_no_unexpected_relink_noop_when_references_unchanged() {
        let current = runtime_model_from_candidate_toml(relink_blue_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(relink_blue_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);
        assert!(!plan.ip_vrf_references_changed);
        validate_no_unexpected_relink(&current, &candidate, &plan).unwrap();
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
            es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
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
            es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
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
            es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
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

    #[tokio::test]
    async fn apply_evpn_runtime_l2vni_redefine_commits_after_convergence() {
        let coordinator = two_l2vni_runtime_coordinator();
        let apply_lock = tokio::sync::Mutex::new(());
        let converger = TestRuntimeConverger::ok();

        let response = apply_evpn_runtime_request(
            &proto::ApplyEvpnRuntimeRequest {
                candidate_toml: two_l2vni_one_redefined_l2vni_runtime_candidate_toml().to_string(),
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
        assert_eq!(plan.evpn_instances.unwrap().redefined, vec!["100"]);

        let expected_rd =
            runtime_candidate_from_toml(two_l2vni_one_redefined_l2vni_runtime_candidate_toml())
                .instances()
                .get(rustbgpd_evpn::EvpnInstanceId::new(100).unwrap())
                .unwrap()
                .rd;
        let guard = coordinator.lock().unwrap();
        assert_eq!(guard.model().generation().as_u64(), 2);
        assert_eq!(
            guard
                .model()
                .instances()
                .get(rustbgpd_evpn::EvpnInstanceId::new(100).unwrap())
                .unwrap()
                .rd,
            expected_rd,
            "committed model should carry the redefined RD for VNI 100"
        );
    }

    #[tokio::test]
    async fn apply_evpn_runtime_l2vni_redefine_es_member_commits_after_convergence() {
        let coordinator = two_l2vni_one_es_runtime_coordinator();
        let apply_lock = tokio::sync::Mutex::new(());
        let converger = TestRuntimeConverger::ok();

        let response = apply_evpn_runtime_request(
            &proto::ApplyEvpnRuntimeRequest {
                candidate_toml: two_l2vni_one_es_redefined_member_runtime_candidate_toml()
                    .to_string(),
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
        assert_eq!(plan.evpn_instances.unwrap().redefined, vec!["100"]);

        let expected_rd =
            runtime_candidate_from_toml(two_l2vni_one_es_redefined_member_runtime_candidate_toml())
                .instances()
                .get(rustbgpd_evpn::EvpnInstanceId::new(100).unwrap())
                .unwrap()
                .rd;
        let guard = coordinator.lock().unwrap();
        assert_eq!(
            guard
                .model()
                .instances()
                .get(rustbgpd_evpn::EvpnInstanceId::new(100).unwrap())
                .unwrap()
                .rd,
            expected_rd,
            "committed model should carry the redefined RD for ES-member VNI 100"
        );
        assert_eq!(guard.model().ethernet_segments().len(), 1);
        assert!(
            guard.model().ethernet_segments()[0]
                .member_vnis
                .contains(&rustbgpd_evpn::EvpnInstanceId::new(100).unwrap()),
            "ES membership should remain unchanged"
        );
    }

    #[test]
    fn validate_single_l2vni_redefine_accepts_one_redefined_instance() {
        let current = runtime_model_from_candidate_toml(two_l2vni_runtime_candidate_toml());
        let candidate =
            runtime_candidate_from_toml(two_l2vni_one_redefined_l2vni_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);

        let redefined = validate_single_l2vni_redefine(&current, &candidate, &plan).unwrap();
        assert_eq!(redefined, rustbgpd_evpn::EvpnInstanceId::new(100).unwrap());
    }

    #[test]
    fn validate_single_l2vni_redefine_accepts_es_member() {
        let current = runtime_model_from_candidate_toml(two_l2vni_one_es_runtime_candidate_toml());
        let candidate =
            runtime_candidate_from_toml(two_l2vni_one_es_redefined_member_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);

        let redefined = validate_single_l2vni_redefine(&current, &candidate, &plan).unwrap();
        assert_eq!(redefined, rustbgpd_evpn::EvpnInstanceId::new(100).unwrap());
    }

    #[test]
    fn validate_single_l2vni_redefine_rejects_mixed_ip_vrf_change() {
        let current = runtime_model_from_candidate_toml(two_l2vni_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(
            two_l2vni_one_redefined_plus_ip_vrf_runtime_candidate_toml(),
        );
        let plan = current.plan_candidate(&candidate);

        let error = validate_single_l2vni_redefine(&current, &candidate, &plan).unwrap_err();
        let DaemonEvpnRuntimeConvergeError::Unsupported(message) = error else {
            panic!("expected unsupported error, got {error:?}");
        };
        assert!(
            message.contains("IP-VRF changes are absent"),
            "unexpected error message: {message}"
        );
    }

    #[test]
    fn validate_single_l2vni_redefine_rejects_multiple_redefined() {
        let current = runtime_model_from_candidate_toml(two_l2vni_runtime_candidate_toml());
        let candidate =
            runtime_candidate_from_toml(two_l2vni_both_redefined_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);

        let error = validate_single_l2vni_redefine(&current, &candidate, &plan).unwrap_err();
        let DaemonEvpnRuntimeConvergeError::Unsupported(message) = error else {
            panic!("expected unsupported error, got {error:?}");
        };
        assert!(
            message.contains("exactly one redefined L2VNI"),
            "unexpected error message: {message}"
        );
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
        let (same_esi_bias_tx, _bias_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
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
            same_esi_bias_tx,
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
            es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
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
    #[expect(
        clippy::too_many_lines,
        reason = "full dataplane-handle + segment-actor wiring per the sibling converger proofs"
    )]
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
        let (same_esi_bias_tx, _bias_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
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
            same_esi_bias_tx,
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
            es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
        };

        converger
            .converge(&current, &l2_candidate, &l2_plan)
            .await
            .unwrap();
        converger
            .converge(&current_after_l2, &es_candidate, &es_plan)
            .await
            .unwrap();

        // The Ethernet Tag is pinned to 0 (RFC 7432 §6.1); the
        // runtime-added VNI's EAD-per-EVI is identified by its RD.
        let added_rd = current_after_l2
            .instances()
            .get(rustbgpd_evpn::EvpnInstanceId::new(200).unwrap())
            .expect("VNI 200 present after the L2 add")
            .rd;
        let deadline = StdInstant::now() + Duration::from_secs(2);
        loop {
            let observed = injects.lock().await.clone();
            if observed.iter().any(|key| {
                matches!(
                    key,
                    rustbgpd_wire::EvpnRouteKey::EadPerEvi {
                        rd,
                        ..
                    } if *rd == added_rd
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
    async fn runtime_actor_converger_additive_build_up_rejects_missing_originator() {
        let current = runtime_model_from_candidate_toml(
            es_member_l2vni_linked_ip_vrf_svi_runtime_candidate_toml(),
        );
        let candidate = runtime_candidate_from_toml(two_tenant_additive_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);
        let current_instances = Arc::new(current.instances().clone());
        let current_ip_vrfs = Arc::new(current.ip_vrfs().clone());
        let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(8);
        let (evpn_instances_tx, _evpn_instances_rx) = watch::channel(current_instances);
        let (ip_vrfs_tx, _ip_vrfs_rx) = watch::channel(current_ip_vrfs);
        let (bum_enforcement_tx, _bum_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
        let (same_esi_bias_tx, _bias_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
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
            same_esi_bias_tx,
            evpn_instances_tx,
            ip_vrfs_tx,
            remote_prefix_drop_counts_rx,
        };
        let converger = EvpnRuntimeActorConverger {
            rib_tx,
            imet_controller: Arc::new(
                tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new()),
            ),
            dataplane: Some(dataplane_handle.runtime_control()),
            originator: None,
            svi: None,
            l3_originator: None,
            segment: None,
            es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
        };

        let error = converger
            .converge(&current, &candidate, &plan)
            .await
            .unwrap_err();
        let DaemonEvpnRuntimeConvergeError::Unsupported(message) = error else {
            panic!("expected unsupported error, got {error:?}");
        };
        assert!(
            message.contains("Type 2 originator"),
            "unexpected error message: {message}"
        );
        dataplane_handle.shutdown().await;
    }

    #[tokio::test]
    async fn runtime_actor_converger_additive_build_up_rejects_missing_segment_actor() {
        let current = runtime_model_from_candidate_toml(l2vni_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(two_l2vni_two_es_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);
        assert!(is_additive_build_up_plan(&plan));

        let current_instances = Arc::new(current.instances().clone());
        let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(8);
        let (evpn_instances_tx, _evpn_instances_rx) = watch::channel(current_instances.clone());
        let (ip_vrfs_tx, _ip_vrfs_rx) = watch::channel(Arc::new(rustbgpd_evpn::IpVrfTable::new()));
        let (bum_enforcement_tx, _bum_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
        let (same_esi_bias_tx, _bias_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
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
            same_esi_bias_tx,
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
            es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
        };

        let error = converger
            .converge(&current, &candidate, &plan)
            .await
            .unwrap_err();
        let DaemonEvpnRuntimeConvergeError::Unsupported(message) = error else {
            panic!("expected unsupported error, got {error:?}");
        };
        assert!(
            message.contains("segment actor"),
            "unexpected error message: {message}"
        );
        originator_handle.shutdown().await;
        dataplane_handle.shutdown().await;
    }

    #[test]
    fn additive_build_failure_escalates_when_rollback_fails() {
        let restored = additive_build_failure(true, "EVPN segment publish failed");
        assert_eq!(restored.message(), "EVPN segment publish failed");

        let stranded = additive_build_failure(false, "EVPN segment publish failed");
        assert!(stranded.message().contains("EVPN segment publish failed"));
        assert!(
            stranded
                .message()
                .contains("additive build-up rollback also failed"),
            "unexpected message: {}",
            stranded.message()
        );
        assert!(stranded.message().contains("repair/restart"));
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "rollback proof wires dataplane, IMET, Type 5, and segment actors"
    )]
    async fn runtime_actor_converger_additive_build_up_rollback_restores_imet_and_models() {
        let current = runtime_model_from_candidate_toml(
            es_member_l2vni_linked_ip_vrf_svi_runtime_candidate_toml(),
        );
        let candidate = runtime_candidate_from_toml(two_tenant_additive_runtime_candidate_toml());
        let current_instances = Arc::new(current.instances().clone());
        let current_ip_vrfs = Arc::new(current.ip_vrfs().clone());
        let candidate_instances = Arc::new(candidate.instances().clone());
        let candidate_ip_vrfs = Arc::new(candidate.ip_vrfs().clone());
        let candidate_segments = Arc::new(candidate.ethernet_segments().to_vec());
        let added_vni = rustbgpd_evpn::EvpnInstanceId::new(200).unwrap();
        let added_instance = candidate.instances().get(added_vni).unwrap().clone();
        let added_rd = added_instance.rd;
        let added_esi =
            rustbgpd_wire::EthernetSegmentIdentifier::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let type5_id = rustbgpd_evpn::IpVrfId::new(6000).unwrap();
        let expected_overlay_rd = candidate.ip_vrfs().get("tenant-green").unwrap().rd;

        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(128);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

        let (evpn_instances_tx, evpn_instances_rx) = watch::channel(current_instances.clone());
        let (ip_vrfs_tx, ip_vrfs_rx) = watch::channel(current_ip_vrfs.clone());
        let (bum_enforcement_tx, _bum_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
        let (same_esi_bias_tx, _bias_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
        let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
            watch::channel(Arc::new(evpn_dataplane::RemoteIpPrefixDropCounts::new()));
        let (report_tx, _) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(8);
        let dataplane_handle = evpn_dataplane::EvpnDataplaneHandle {
            shutdown: tokio_util::sync::CancellationToken::new(),
            supervisor_join: tokio::spawn(async {}),
            actor_join: tokio::spawn(async {}),
            local_mac_rx: None,
            report_tx,
            bum_enforcement_tx,
            same_esi_bias_tx,
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
        .expect("Type 5 originator should spawn for a non-empty current IP-VRF table");
        status_tx.send_replace(vec![runtime_ip_vrf_ready_status(type5_id, "tenant-green")]);
        let mut observations = std::collections::HashMap::new();
        observations.insert(type5_id, vec![runtime_local_ip_observation(type5_id)]);
        obs_tx.send_replace(Arc::new(observations));

        let mut imet_controller = evpn_imet::EvpnImetController::new();
        let _ = imet_controller
            .originate_instance(added_instance.clone(), &rib_tx)
            .await;
        let imet_controller = Arc::new(tokio::sync::Mutex::new(imet_controller));
        let dataplane = dataplane_handle.runtime_control();
        let segment = segment_handle.runtime_control();
        let originator = originator_handle.runtime_control();
        let l3 = l3_handle.runtime_control();
        assert!(dataplane.replace_ip_vrfs(candidate_ip_vrfs.clone()));
        assert!(dataplane.replace_evpn_instances(candidate_instances.clone()));
        assert!(originator.replace_runtime_model(
            candidate_instances.clone(),
            evpn_vni_to_esi_map(candidate.ethernet_segments()),
            Arc::new(std::collections::BTreeSet::new()),
        ));
        assert!(segment.replace_instances(candidate_instances));
        assert!(segment.replace_segments(candidate_segments));
        assert!(l3.replace_ip_vrfs(candidate_ip_vrfs));

        wait_for_recorded_evpn_key_matching(
            &injects,
            "mid-build state should have originated added IMET",
            |key| matches!(key, rustbgpd_wire::EvpnRouteKey::Imet { rd, .. } if *rd == added_rd),
        )
        .await;
        wait_for_recorded_evpn_key_matching(
            &injects,
            "mid-build state should have originated added ES",
            |key| matches!(key, rustbgpd_wire::EvpnRouteKey::Es { esi, .. } if *esi == added_esi),
        )
        .await;
        wait_for_recorded_evpn_key_matching(
            &injects,
            "mid-build state should have originated tenant-green Type 5",
            |key| matches!(key, rustbgpd_wire::EvpnRouteKey::IpPrefix { rd, .. } if *rd == expected_overlay_rd),
        )
        .await;

        let converger = EvpnRuntimeActorConverger {
            rib_tx,
            imet_controller,
            dataplane: Some(dataplane_handle.runtime_control()),
            originator: Some(originator_handle.runtime_control()),
            svi: None,
            l3_originator: Some(l3_handle.runtime_control()),
            segment: Some(segment_handle.runtime_control()),
            es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
        };

        let restored = converger
            .rollback_additive_build_up(&current, &[added_instance])
            .await;
        assert!(restored, "rollback should restore all touched state");
        assert!(evpn_instances_rx.borrow().get(added_vni).is_none());
        assert!(
            !ip_vrfs_rx.borrow().is_referenced("tenant-green"),
            "rollback should restore the committed IP-VRF reference map"
        );
        wait_for_recorded_evpn_key_matching(
            &withdraws,
            "rollback should withdraw added IMET",
            |key| matches!(key, rustbgpd_wire::EvpnRouteKey::Imet { rd, .. } if *rd == added_rd),
        )
        .await;
        wait_for_recorded_evpn_key_matching(
            &withdraws,
            "rollback should withdraw added ES state",
            |key| matches!(key, rustbgpd_wire::EvpnRouteKey::Es { esi, .. } if *esi == added_esi),
        )
        .await;
        wait_for_recorded_evpn_key_matching(
            &withdraws,
            "rollback should withdraw tenant-green Type 5 state",
            |key| matches!(key, rustbgpd_wire::EvpnRouteKey::IpPrefix { rd, .. } if *rd == expected_overlay_rd),
        )
        .await;

        l3_handle.shutdown().await;
        segment_handle.shutdown().await;
        originator_handle.shutdown().await;
        dataplane_handle.shutdown().await;
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "wires every EVPN runtime actor to prove cross-domain additive convergence"
    )]
    async fn runtime_actor_converger_additive_build_up_publishes_all_actor_models() {
        let current = runtime_model_from_candidate_toml(
            es_member_l2vni_linked_ip_vrf_svi_runtime_candidate_toml(),
        );
        let candidate = runtime_candidate_from_toml(two_tenant_additive_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);
        assert!(is_additive_build_up_plan(&plan));

        let current_instances = Arc::new(current.instances().clone());
        let current_ip_vrfs = Arc::new(current.ip_vrfs().clone());
        let added_vni = rustbgpd_evpn::EvpnInstanceId::new(200).unwrap();
        let added_esi =
            rustbgpd_wire::EthernetSegmentIdentifier::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let added_rd = candidate.instances().get(added_vni).unwrap().rd;
        let expected_overlay_rd = candidate.ip_vrfs().get("tenant-green").unwrap().rd;

        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(128);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws);

        let (evpn_instances_tx, evpn_instances_rx) = watch::channel(current_instances.clone());
        let (ip_vrfs_tx, ip_vrfs_rx) = watch::channel(current_ip_vrfs.clone());
        let (bum_enforcement_tx, _bum_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
        let (same_esi_bias_tx, _bias_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
        let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
            watch::channel(Arc::new(evpn_dataplane::RemoteIpPrefixDropCounts::new()));
        let (report_tx, _) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(8);
        let dataplane_handle = evpn_dataplane::EvpnDataplaneHandle {
            shutdown: tokio_util::sync::CancellationToken::new(),
            supervisor_join: tokio::spawn(async {}),
            actor_join: tokio::spawn(async {}),
            local_mac_rx: None,
            report_tx,
            bum_enforcement_tx,
            same_esi_bias_tx,
            evpn_instances_tx,
            ip_vrfs_tx,
            remote_prefix_drop_counts_rx,
        };

        let (local_tx, local_rx) = mpsc::channel(16);
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

        let (svi_report_tx, svi_report_rx) =
            broadcast::channel::<rustbgpd_evpn::DataplaneReport>(8);
        let svi_handle = evpn_svi::spawn(
            &current_instances,
            rib_tx.clone(),
            svi_report_rx,
            BgpMetrics::new(),
            evpn_originator::OriginatedLocalMacCounts::default(),
            tokio_util::sync::CancellationToken::new(),
        )
        .expect("SVI actor should spawn when a committed instance advertises its SVI MAC");

        let segment_handle = evpn_segment::spawn(
            &current_instances,
            current.ethernet_segments().to_vec(),
            rib_tx.clone(),
            None,
            BgpMetrics::new(),
            tokio_util::sync::CancellationToken::new(),
        )
        .expect("segment actor should spawn for non-empty ES config");

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
        .expect("Type 5 originator should spawn for a non-empty current IP-VRF table");
        let type5_id = rustbgpd_evpn::IpVrfId::new(6000).unwrap();
        status_tx.send_replace(vec![runtime_ip_vrf_ready_status(type5_id, "tenant-green")]);
        let mut observations = std::collections::HashMap::new();
        observations.insert(type5_id, vec![runtime_local_ip_observation(type5_id)]);
        obs_tx.send_replace(Arc::new(observations));

        let converger = EvpnRuntimeActorConverger {
            rib_tx,
            imet_controller: Arc::new(
                tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new()),
            ),
            dataplane: Some(dataplane_handle.runtime_control()),
            originator: Some(originator_handle.runtime_control()),
            svi: Some(svi_handle.runtime_control()),
            l3_originator: Some(l3_handle.runtime_control()),
            segment: Some(segment_handle.runtime_control()),
            es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
        };

        converger
            .converge(&current, &candidate, &plan)
            .await
            .unwrap();

        assert!(evpn_instances_rx.borrow().get(added_vni).is_some());
        assert!(
            ip_vrfs_rx
                .borrow()
                .referenced_l2vnis("tenant-green")
                .is_some_and(|vnis| vnis.contains(&added_vni)),
            "dataplane IP-VRF model should learn the new tenant-green link"
        );

        wait_for_recorded_evpn_key_matching(
            &injects,
            "additive build-up should originate IMET for the added L2VNI",
            |key| {
                matches!(
                    key,
                    rustbgpd_wire::EvpnRouteKey::Imet {
                        rd,
                        ..
                    } if *rd == added_rd
                )
            },
        )
        .await;
        wait_for_recorded_evpn_key_matching(
            &injects,
            "additive build-up should publish tenant-green Type 5 state",
            |key| matches!(key, rustbgpd_wire::EvpnRouteKey::IpPrefix { rd, .. } if *rd == expected_overlay_rd),
        )
        .await;
        wait_for_recorded_evpn_key_matching(
            &injects,
            "additive build-up should publish the added Ethernet Segment",
            |key| matches!(key, rustbgpd_wire::EvpnRouteKey::Es { esi, .. } if *esi == added_esi),
        )
        .await;
        wait_for_recorded_evpn_key_matching(
            &injects,
            "additive build-up should publish EAD-per-EVI for the added member VNI",
            // Ethernet Tag is pinned to 0 (RFC 7432 §6.1); the added
            // member VNI's EAD-per-EVI is identified by its RD.
            |key| {
                matches!(
                    key,
                    rustbgpd_wire::EvpnRouteKey::EadPerEvi {
                        esi,
                        rd,
                        ..
                    } if *esi == added_esi && *rd == added_rd
                )
            },
        )
        .await;

        let local_mac = rustbgpd_evpn::MacAddress::new([0x02, 0, 0, 0, 0, 0xab]);
        let local_mac_deadline = StdInstant::now() + Duration::from_secs(2);
        loop {
            local_tx
                .send(rustbgpd_evpn::LocalMacObservation::Learned {
                    vni: added_vni,
                    mac: local_mac,
                    ifindex: 20,
                })
                .await
                .unwrap();
            if injects.lock().await.iter().any(|key| {
                matches!(
                    key,
                    rustbgpd_wire::EvpnRouteKey::MacIp {
                        rd,
                        mac,
                        ..
                    } if *rd == added_rd && *mac == local_mac
                )
            }) {
                break;
            }
            assert!(
                StdInstant::now() < local_mac_deadline,
                "Type 2 originator did not accept the added L2VNI"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let svi_mac = rustbgpd_evpn::MacAddress::new([0x02, 0, 0, 0, 0, 0xcd]);
        let svi_deadline = StdInstant::now() + Duration::from_secs(2);
        loop {
            let _ = svi_report_tx.send(svi_dataplane_report(200, svi_mac));
            if injects.lock().await.iter().any(|key| {
                matches!(
                    key,
                    rustbgpd_wire::EvpnRouteKey::MacIp {
                        rd,
                        mac,
                        ..
                    } if *rd == added_rd && *mac == svi_mac
                )
            }) {
                break;
            }
            assert!(
                StdInstant::now() < svi_deadline,
                "SVI actor did not accept the added L2VNI"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        l3_handle.shutdown().await;
        svi_handle.shutdown().await;
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
        let (same_esi_bias_tx, _bias_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
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
            same_esi_bias_tx,
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
            es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
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
    async fn runtime_actor_converger_l2vni_swap_updates_models_and_imet() {
        let current = runtime_model_from_candidate_toml(two_l2vni_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(l2vni_swap_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);
        let current_instances = Arc::new(current.instances().clone());
        let added_vni = rustbgpd_evpn::EvpnInstanceId::new(300).unwrap();
        let deleted_vni = rustbgpd_evpn::EvpnInstanceId::new(200).unwrap();
        let added_rd = candidate.instances().get(added_vni).unwrap().rd;
        let deleted_rd = current.instances().get(deleted_vni).unwrap().rd;

        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

        let (evpn_instances_tx, evpn_instances_rx) = watch::channel(current_instances.clone());
        let (ip_vrfs_tx, _ip_vrfs_rx) = watch::channel(Arc::new(rustbgpd_evpn::IpVrfTable::new()));
        let (bum_enforcement_tx, _bum_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
        let (same_esi_bias_tx, _bias_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
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
            same_esi_bias_tx,
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
        assert_eq!(imet_keys.len(), 2);

        let converger = EvpnRuntimeActorConverger {
            rib_tx,
            imet_controller: Arc::new(tokio::sync::Mutex::new(imet_controller)),
            dataplane: Some(dataplane_handle.runtime_control()),
            originator: Some(originator_handle.runtime_control()),
            svi: None,
            l3_originator: None,
            segment: None,
            es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
        };

        converger
            .converge(&current, &candidate, &plan)
            .await
            .unwrap();

        assert!(evpn_instances_rx.borrow().get(added_vni).is_some());
        assert!(evpn_instances_rx.borrow().get(deleted_vni).is_none());

        let drained = withdraws.lock().await.clone();
        let injected = injects.lock().await.clone();
        assert!(
            drained.iter().any(|key| matches!(
                key,
                rustbgpd_wire::EvpnRouteKey::Imet { rd, .. } if *rd == deleted_rd
            )),
            "swap should withdraw the deleted L2VNI's IMET route; drained {drained:?}"
        );
        assert!(
            injected.iter().any(|key| matches!(
                key,
                rustbgpd_wire::EvpnRouteKey::Imet { rd, .. } if *rd == added_rd
            )),
            "swap should originate the added L2VNI's IMET route; injected {injected:?}"
        );

        originator_handle.shutdown().await;
        dataplane_handle.shutdown().await;
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "wires the dataplane/originator/IMET actors to prove swap rollback restoration"
    )]
    async fn runtime_actor_converger_l2vni_swap_rollback_restores_imet_and_models() {
        // Drive the swap forward legs up to the rollback point (added IMET
        // originated, candidate models published, deleted IMET withdrawn),
        // then call rollback_l2vni_swap directly and prove it restores the
        // committed model and unwinds the speculative IMET state. This covers
        // the highest-risk swap path — the IMET withdraw-added / restore-
        // deleted ordering — which the happy-path test does not exercise.
        let current = runtime_model_from_candidate_toml(two_l2vni_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(l2vni_swap_runtime_candidate_toml());
        let current_instances = Arc::new(current.instances().clone());
        let candidate_instances = Arc::new(candidate.instances().clone());
        let added_vni = rustbgpd_evpn::EvpnInstanceId::new(300).unwrap();
        let deleted_vni = rustbgpd_evpn::EvpnInstanceId::new(200).unwrap();
        let added_instance = candidate.instances().get(added_vni).unwrap().clone();
        let deleted_instance = current.instances().get(deleted_vni).unwrap().clone();
        let added_rd = added_instance.rd;
        let deleted_rd = deleted_instance.rd;

        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

        let (evpn_instances_tx, evpn_instances_rx) = watch::channel(current_instances.clone());
        let (ip_vrfs_tx, _ip_vrfs_rx) = watch::channel(Arc::new(rustbgpd_evpn::IpVrfTable::new()));
        let (bum_enforcement_tx, _bum_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
        let (same_esi_bias_tx, _bias_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
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
            same_esi_bias_tx,
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
        assert_eq!(imet_keys.len(), 2);
        // Forward leg 1: originate the added L2VNI's IMET.
        let _ = imet_controller
            .originate_instance(added_instance.clone(), &rib_tx)
            .await;
        let imet_controller = Arc::new(tokio::sync::Mutex::new(imet_controller));

        // Forward leg 2: publish the candidate models to dataplane + originator.
        let dataplane = dataplane_handle.runtime_control();
        let originator = originator_handle.runtime_control();
        assert!(dataplane.replace_evpn_instances(candidate_instances.clone()));
        assert!(originator.replace_runtime_model(
            candidate_instances.clone(),
            evpn_vni_to_esi_map(candidate.ethernet_segments()),
            Arc::new(std::collections::BTreeSet::new()),
        ));
        // Forward leg 3: withdraw the deleted L2VNI's IMET.
        let _ = imet_controller
            .lock()
            .await
            .withdraw_instance(deleted_vni, &rib_tx)
            .await;

        // The forward legs above are all awaited (the recorder pushes before
        // replying), so the mid-swap RIB effects are fully recorded. Clear so
        // the rollback's effects are unambiguous.
        injects.lock().await.clear();
        withdraws.lock().await.clear();

        let converger = EvpnRuntimeActorConverger {
            rib_tx,
            imet_controller,
            dataplane: Some(dataplane_handle.runtime_control()),
            originator: Some(originator_handle.runtime_control()),
            svi: None,
            l3_originator: None,
            segment: None,
            es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
        };

        let restored = converger
            .rollback_l2vni_swap(&current, &[added_instance], &[deleted_instance])
            .await;
        assert!(restored, "swap rollback should restore all touched state");

        // Committed model restored: the deleted VNI is back, the added VNI gone.
        assert!(
            evpn_instances_rx.borrow().get(deleted_vni).is_some(),
            "rollback should restore the deleted L2VNI to the committed model"
        );
        assert!(
            evpn_instances_rx.borrow().get(added_vni).is_none(),
            "rollback should drop the speculatively-added L2VNI"
        );

        // Speculative added IMET withdrawn; deleted IMET re-originated.
        wait_for_recorded_evpn_key_matching(
            &withdraws,
            "rollback should withdraw the speculatively-added L2VNI IMET",
            |key| matches!(key, rustbgpd_wire::EvpnRouteKey::Imet { rd, .. } if *rd == added_rd),
        )
        .await;
        wait_for_recorded_evpn_key_matching(
            &injects,
            "rollback should restore the deleted L2VNI IMET",
            |key| matches!(key, rustbgpd_wire::EvpnRouteKey::Imet { rd, .. } if *rd == deleted_rd),
        )
        .await;

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
        let (same_esi_bias_tx, _bias_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
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
            same_esi_bias_tx,
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
            es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
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
    fn validate_l2vni_swap_accepts_standalone_add_delete() {
        let current = runtime_model_from_candidate_toml(two_l2vni_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(l2vni_swap_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);

        assert!(is_l2vni_swap_plan(&plan));
        let (added, deleted) = validate_l2vni_swap(&current, &candidate, &plan).unwrap();
        assert_eq!(
            added
                .iter()
                .map(|instance| instance.id.as_u32())
                .collect::<Vec<_>>(),
            vec![300]
        );
        assert_eq!(
            deleted
                .iter()
                .map(|instance| instance.id.as_u32())
                .collect::<Vec<_>>(),
            vec![200]
        );
    }

    #[test]
    fn validate_l2vni_swap_rejects_ip_vrf_link_metadata_change() {
        let current =
            runtime_model_from_candidate_toml(two_l2vni_linked_ip_vrf_runtime_candidate_toml());
        let candidate =
            runtime_candidate_from_toml(l2vni_swap_linked_ip_vrf_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);

        assert!(is_l2vni_swap_plan(&plan));
        assert!(
            !plan.ip_vrfs.has_changes(),
            "IP-VRF row diffing intentionally ignores link metadata"
        );
        assert_ne!(current.ip_vrfs(), candidate.ip_vrfs());
        let error = validate_l2vni_swap(&current, &candidate, &plan).unwrap_err();
        let DaemonEvpnRuntimeConvergeError::Unsupported(message) = error else {
            panic!("expected unsupported error, got {error:?}");
        };
        assert!(
            message.contains("standalone L2VNIs"),
            "unexpected error message: {message}"
        );
    }

    #[test]
    fn validate_l2vni_swap_rejects_es_member_delete() {
        let current = runtime_model_from_candidate_toml(two_l2vni_one_es_runtime_candidate_toml());
        let base_candidate =
            runtime_candidate_from_toml(l2vni_swap_delete_vni100_runtime_candidate_toml());
        let candidate = rustbgpd_evpn::EvpnRuntimeCandidate::new(
            base_candidate.instances().clone(),
            current.ip_vrfs().clone(),
            current.ethernet_segments().to_vec(),
        );
        let plan = current.plan_candidate(&candidate);

        assert!(is_l2vni_swap_plan(&plan));
        let error = validate_l2vni_swap(&current, &candidate, &plan).unwrap_err();
        let DaemonEvpnRuntimeConvergeError::Unsupported(message) = error else {
            panic!("expected unsupported error, got {error:?}");
        };
        assert!(
            message.contains("Ethernet Segment member"),
            "unexpected error message: {message}"
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

    #[test]
    fn validate_tenant_teardown_accepts_full_tenant() {
        let current = runtime_model_from_candidate_toml(
            es_member_l2vni_linked_ip_vrf_runtime_candidate_toml(),
        );
        let candidate = runtime_candidate_from_toml(minimal_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);

        // A tenant teardown spans all three resource types in one delete-only plan.
        assert_eq!(plan.evpn_instances.deleted, vec![100]);
        assert_eq!(plan.ip_vrfs.deleted, vec!["tenant-blue".to_string()]);
        assert_eq!(plan.ethernet_segments.deleted.len(), 1);
        assert!(plan.evpn_instances.added.is_empty());
        assert!(is_tenant_teardown_plan(&plan, &current));

        let deleted = validate_tenant_teardown(&current, &candidate, &plan).unwrap();
        assert_eq!(deleted.len(), 1);
        assert_eq!(
            deleted[0].id,
            rustbgpd_evpn::EvpnInstanceId::new(100).unwrap()
        );
    }

    #[test]
    fn validate_tenant_teardown_accepts_es_member_shrink() {
        // VNI 200 leaves; the ES it shared with VNI 100 shrinks its member set
        // to [100] in the same request (a member-shrink redefine, not a delete).
        let current =
            runtime_model_from_candidate_toml(two_l2vni_redefined_es_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(l2vni_one_es_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);

        assert_eq!(plan.evpn_instances.deleted, vec![200]);
        assert_eq!(plan.ethernet_segments.redefined.len(), 1);
        assert!(plan.ethernet_segments.deleted.is_empty());
        assert!(is_tenant_teardown_plan(&plan, &current));

        let deleted = validate_tenant_teardown(&current, &candidate, &plan).unwrap();
        assert_eq!(deleted.len(), 1);
        assert_eq!(
            deleted[0].id,
            rustbgpd_evpn::EvpnInstanceId::new(200).unwrap()
        );
    }

    #[test]
    fn validate_tenant_teardown_rejects_add() {
        let current = runtime_model_from_candidate_toml(l2vni_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(two_l2vni_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);

        assert_eq!(plan.evpn_instances.added, vec![200]);
        let error = validate_tenant_teardown(&current, &candidate, &plan).unwrap_err();
        let DaemonEvpnRuntimeConvergeError::Unsupported(message) = error else {
            panic!("expected unsupported error, got {error:?}");
        };
        assert!(
            message.contains("does not support adds"),
            "unexpected error message: {message}"
        );
    }

    #[test]
    fn validate_tenant_teardown_rejects_l2vni_redefine() {
        let current = runtime_model_from_candidate_toml(two_l2vni_runtime_candidate_toml());
        let candidate =
            runtime_candidate_from_toml(two_l2vni_one_redefined_l2vni_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);

        assert_eq!(plan.evpn_instances.redefined, vec![100]);
        let error = validate_tenant_teardown(&current, &candidate, &plan).unwrap_err();
        let DaemonEvpnRuntimeConvergeError::Unsupported(message) = error else {
            panic!("expected unsupported error, got {error:?}");
        };
        assert!(
            message.contains("does not support L2VNI redefine"),
            "unexpected error message: {message}"
        );
    }

    #[test]
    fn m47_interop_configs_describe_a_tenant_teardown() {
        // Pin the M47 interop fixtures: the booted PE config and the gRPC
        // teardown candidate must parse through the real config loader and
        // diff to an atomic tenant teardown (L2VNI 100 + its Ethernet
        // Segment). Guards the smoke against drift in either the configs or
        // the teardown classifier.
        let current = runtime_model_from_candidate_toml(include_str!(
            "../tests/interop/configs/rustbgpd-m47-pe1.toml"
        ));
        let candidate = runtime_candidate_from_toml(include_str!(
            "../tests/interop/configs/rustbgpd-m47-teardown.toml"
        ));
        let plan = current.plan_candidate(&candidate);

        assert_eq!(plan.evpn_instances.deleted, vec![100]);
        assert_eq!(plan.ethernet_segments.deleted.len(), 1);
        assert!(is_tenant_teardown_plan(&plan, &current));

        let deleted = validate_tenant_teardown(&current, &candidate, &plan).unwrap();
        assert_eq!(deleted.len(), 1);
        assert_eq!(
            deleted[0].id,
            rustbgpd_evpn::EvpnInstanceId::new(100).unwrap()
        );
    }

    #[test]
    fn m48_interop_configs_describe_a_linked_ip_vrf_teardown() {
        // Pin the M48 datapath interop fixtures: the booted PE config and the
        // gRPC teardown candidate must parse through the real config loader and
        // diff to an atomic tenant teardown of a linked L2VNI + IP-VRF (vrf1 is
        // referenced by L2VNI 10, so dropping both routes through the teardown
        // path rather than a standalone IP-VRF delete). Guards the smoke
        // against drift in either the configs or the teardown classifier.
        let current = runtime_model_from_candidate_toml(include_str!(
            "../tests/interop/configs/rustbgpd-m48-pe1.toml"
        ));
        let candidate = runtime_candidate_from_toml(include_str!(
            "../tests/interop/configs/rustbgpd-m48-teardown.toml"
        ));
        let plan = current.plan_candidate(&candidate);

        assert_eq!(plan.evpn_instances.deleted, vec![10]);
        assert_eq!(plan.ip_vrfs.deleted, vec!["vrf1".to_string()]);
        assert!(is_tenant_teardown_plan(&plan, &current));

        let deleted = validate_tenant_teardown(&current, &candidate, &plan).unwrap();
        assert_eq!(deleted.len(), 1);
        assert_eq!(
            deleted[0].id,
            rustbgpd_evpn::EvpnInstanceId::new(10).unwrap()
        );
    }

    #[test]
    fn validate_additive_build_up_accepts_l2vni_ip_vrf_and_es() {
        let current = runtime_model_from_candidate_toml(
            es_member_l2vni_linked_ip_vrf_svi_runtime_candidate_toml(),
        );
        let candidate = runtime_candidate_from_toml(two_tenant_additive_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);

        assert!(is_additive_build_up_plan(&plan));
        let added = validate_additive_build_up(&current, &candidate, &plan).unwrap();
        assert_eq!(added.len(), 1);
        assert_eq!(
            added[0].id,
            rustbgpd_evpn::EvpnInstanceId::new(200).unwrap()
        );
    }

    #[test]
    fn validate_additive_build_up_rejects_add_with_redefine() {
        let current = runtime_model_from_candidate_toml(two_l2vni_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(
            two_l2vni_one_redefined_plus_ip_vrf_runtime_candidate_toml(),
        );
        let plan = current.plan_candidate(&candidate);

        assert!(!plan.ip_vrfs.added.is_empty());
        assert!(!plan.evpn_instances.redefined.is_empty());
        assert!(!is_additive_build_up_plan(&plan));
        let error = validate_additive_build_up(&current, &candidate, &plan).unwrap_err();
        let DaemonEvpnRuntimeConvergeError::Unsupported(message) = error else {
            panic!("expected unsupported error, got {error:?}");
        };
        assert!(
            message.contains("pure add-only"),
            "unexpected error message: {message}"
        );
    }

    #[test]
    fn validate_additive_build_up_rejects_existing_l2vni_relink() {
        let current = runtime_model_from_candidate_toml(relink_blue_runtime_candidate_toml());
        let candidate =
            runtime_candidate_from_toml(relink_green_plus_l2vni_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);

        assert!(is_additive_build_up_plan(&plan));
        assert!(plan.ip_vrf_references_changed);
        let error = validate_additive_build_up(&current, &candidate, &plan).unwrap_err();
        let DaemonEvpnRuntimeConvergeError::Unsupported(message) = error else {
            panic!("expected unsupported error, got {error:?}");
        };
        assert!(
            message.contains("L2VNI 100") && message.contains("relink"),
            "unexpected error message: {message}"
        );
    }

    #[test]
    fn validate_additive_build_up_rejects_unknown_es_member() {
        let current = runtime_model_from_candidate_toml(minimal_runtime_candidate_toml());
        let valid = runtime_candidate_from_toml(l2vni_one_es_runtime_candidate_toml());
        let mut bad_segment = valid.ethernet_segments()[0].clone();
        bad_segment.member_vnis =
            std::collections::BTreeSet::from([rustbgpd_evpn::EvpnInstanceId::new(300).unwrap()]);
        let bad_candidate = rustbgpd_evpn::EvpnRuntimeCandidate::new(
            valid.instances().clone(),
            rustbgpd_evpn::IpVrfTable::new(),
            vec![bad_segment],
        );
        let plan = current.plan_candidate(&bad_candidate);

        assert!(is_additive_build_up_plan(&plan));
        let error = validate_additive_build_up(&current, &bad_candidate, &plan).unwrap_err();
        let DaemonEvpnRuntimeConvergeError::Unsupported(message) = error else {
            panic!("expected unsupported error, got {error:?}");
        };
        assert!(
            message.contains("unknown member VNI 300"),
            "unexpected error message: {message}"
        );
    }

    #[tokio::test]
    async fn apply_evpn_runtime_tenant_teardown_commits() {
        let current =
            runtime_candidate_from_toml(es_member_l2vni_linked_ip_vrf_runtime_candidate_toml());
        let coordinator = Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
            current.instances().clone(),
            current.ip_vrfs().clone(),
            current.ethernet_segments().to_vec(),
        )));
        let apply_lock = tokio::sync::Mutex::new(());
        let converger = TestRuntimeConverger::ok();

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
            proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyCommitted as i32
        );
        assert_eq!(response.runtime.unwrap().generation, 2);
        let plan = response.plan.unwrap();
        assert_eq!(plan.evpn_instances.unwrap().deleted, vec!["100"]);
        assert_eq!(plan.evpn_ip_vrfs.unwrap().deleted, vec!["tenant-blue"]);
        let guard = coordinator.lock().unwrap();
        assert_eq!(guard.model().generation().as_u64(), 2);
        assert!(guard.model().instances().is_empty());
        assert!(guard.model().ip_vrfs().get("tenant-blue").is_none());
        assert!(guard.model().ethernet_segments().is_empty());
    }

    #[tokio::test]
    async fn apply_evpn_runtime_additive_build_up_commits() {
        let current =
            runtime_candidate_from_toml(es_member_l2vni_linked_ip_vrf_svi_runtime_candidate_toml());
        let coordinator = Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
            current.instances().clone(),
            current.ip_vrfs().clone(),
            current.ethernet_segments().to_vec(),
        )));
        let apply_lock = tokio::sync::Mutex::new(());
        let converger = TestRuntimeConverger::ok();

        let response = apply_evpn_runtime_request(
            &proto::ApplyEvpnRuntimeRequest {
                candidate_toml: two_tenant_additive_runtime_candidate_toml().to_string(),
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
        assert_eq!(plan.evpn_instances.unwrap().added, vec!["200"]);
        assert_eq!(plan.evpn_ip_vrfs.unwrap().added, vec!["tenant-green"]);
        assert_eq!(plan.ethernet_segments.unwrap().added.len(), 1);
        assert!(
            plan.ip_vrf_references_changed,
            "the added L2VNI links to the added IP-VRF"
        );

        let guard = coordinator.lock().unwrap();
        assert_eq!(guard.model().generation().as_u64(), 2);
        assert!(
            guard
                .model()
                .instances()
                .get(rustbgpd_evpn::EvpnInstanceId::new(200).unwrap())
                .is_some()
        );
        assert!(guard.model().ip_vrfs().get("tenant-green").is_some());
        assert_eq!(guard.model().ethernet_segments().len(), 2);
    }

    #[tokio::test]
    async fn apply_evpn_runtime_ip_vrf_relink_commits() {
        // The coordinator must commit a pure relink (not short-circuit to Noop):
        // the candidate edits no row, so this only works because the plan's
        // ip_vrf_references_changed signal makes is_noop() false.
        let current = runtime_candidate_from_toml(relink_blue_runtime_candidate_toml());
        let coordinator = Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
            current.instances().clone(),
            current.ip_vrfs().clone(),
            current.ethernet_segments().to_vec(),
        )));
        let apply_lock = tokio::sync::Mutex::new(());
        let converger = TestRuntimeConverger::ok();

        let response = apply_evpn_runtime_request(
            &proto::ApplyEvpnRuntimeRequest {
                candidate_toml: relink_green_runtime_candidate_toml().to_string(),
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
        assert!(
            plan.ip_vrf_references_changed,
            "the plan summary must surface the relink so it doesn't read as empty/COMMITTED"
        );
        assert!(plan.evpn_instances.unwrap().redefined.is_empty());
        assert!(plan.evpn_ip_vrfs.unwrap().redefined.is_empty());
        let guard = coordinator.lock().unwrap();
        assert_eq!(guard.model().generation().as_u64(), 2);
        let vni100 = rustbgpd_evpn::EvpnInstanceId::new(100).unwrap();
        assert!(
            guard
                .model()
                .ip_vrfs()
                .referenced_l2vnis("tenant-green")
                .is_some_and(|v| v.contains(&vni100))
        );
        assert!(!guard.model().ip_vrfs().is_referenced("tenant-blue"));
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
        let (same_esi_bias_tx, _bias_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
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
            same_esi_bias_tx,
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
            es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
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
    async fn runtime_actor_converger_ip_vrf_relink_republishes_ip_vrfs() {
        // A relink is dataplane-only: republish the candidate IP-VRF table (now
        // carrying the moved link reference) to the dataplane watch. No IMET /
        // originator / SVI / segment / l3 work.
        let current = runtime_model_from_candidate_toml(relink_blue_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(relink_green_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);
        let current_instances = Arc::new(current.instances().clone());
        let current_ip_vrfs = Arc::new(current.ip_vrfs().clone());
        let vni100 = rustbgpd_evpn::EvpnInstanceId::new(100).unwrap();
        assert!(
            current_ip_vrfs
                .referenced_l2vnis("tenant-blue")
                .is_some_and(|v| v.contains(&vni100)),
            "baseline links L2VNI 100 to tenant-blue"
        );

        let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(8);
        let (evpn_instances_tx, _evpn_instances_rx) = watch::channel(current_instances);
        let (ip_vrfs_tx, ip_vrfs_rx) = watch::channel(current_ip_vrfs);
        let (bum_enforcement_tx, _bum_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
        let (same_esi_bias_tx, _bias_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
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
            same_esi_bias_tx,
            evpn_instances_tx,
            ip_vrfs_tx,
            remote_prefix_drop_counts_rx,
        };
        let converger = EvpnRuntimeActorConverger {
            rib_tx,
            imet_controller: Arc::new(
                tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new()),
            ),
            dataplane: Some(dataplane_handle.runtime_control()),
            originator: None,
            svi: None,
            l3_originator: None,
            segment: None,
            es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
        };

        converger
            .converge(&current, &candidate, &plan)
            .await
            .unwrap();

        let published = ip_vrfs_rx.borrow();
        assert!(
            published
                .referenced_l2vnis("tenant-green")
                .is_some_and(|v| v.contains(&vni100)),
            "relink republishes ip_vrfs with L2VNI 100 now referencing tenant-green"
        );
        assert!(
            !published.is_referenced("tenant-blue"),
            "tenant-blue should no longer be referenced after the relink"
        );
        drop(published);
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
        let (same_esi_bias_tx, _bias_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
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
            same_esi_bias_tx,
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
            es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
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
    async fn runtime_actor_converger_ip_vrf_redefine_reoriginates_type5() {
        let current = runtime_model_from_candidate_toml(ip_vrf_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(ip_vrf_redefined_runtime_candidate_toml());
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
        let (same_esi_bias_tx, _bias_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
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
            same_esi_bias_tx,
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
        let blue_id = rustbgpd_evpn::IpVrfId::new(5000).unwrap();
        status_tx.send_replace(vec![runtime_ip_vrf_ready_status(blue_id, "tenant-blue")]);
        let mut observations = std::collections::HashMap::new();
        observations.insert(blue_id, vec![runtime_local_ip_observation(blue_id)]);
        obs_tx.send_replace(Arc::new(observations));
        wait_for_recorded_evpn_key(
            &injects,
            "Type 5 originator should inject tenant-blue before redefine",
        )
        .await;
        let old_key = injects.lock().await[0];

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
            es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
        };

        converger
            .converge(&current, &candidate, &plan)
            .await
            .unwrap();

        assert_eq!(
            ip_vrfs_rx
                .borrow()
                .get("tenant-blue")
                .expect("redefined VRF should be published to dataplane")
                .rd
                .to_string(),
            "65000:5555"
        );
        let deadline = StdInstant::now() + Duration::from_secs(2);
        loop {
            let observed_withdraws = withdraws.lock().await.clone();
            let observed_injects = injects.lock().await.clone();
            if observed_withdraws.contains(&old_key)
                && observed_injects.iter().any(|key| *key != old_key)
            {
                break;
            }
            assert!(
                StdInstant::now() < deadline,
                "timed out waiting for Type 5 withdraw/re-inject after IP-VRF redefine; injects={observed_injects:?} withdraws={observed_withdraws:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

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
            es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
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
            es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
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
        // Ethernet Tag is pinned to 0 (RFC 7432 §6.1); member VNIs'
        // EAD-per-EVI routes are told apart by their per-VNI RDs.
        let member_rd = |raw_vni: u32| {
            current
                .instances()
                .get(rustbgpd_evpn::EvpnInstanceId::new(raw_vni).unwrap())
                .unwrap_or_else(|| panic!("VNI {raw_vni} present in the current model"))
                .rd
        };
        let old_member_rd = member_rd(100);
        let new_member_rd = member_rd(200);

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
                        rd,
                        ..
                    } if *esi == redefined_esi && *rd == old_member_rd
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
            es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
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
                        rd,
                        ..
                    } if *esi == redefined_esi && *rd == old_member_rd
                )
            });
            let injected_new_evi = injected.iter().any(|key| {
                matches!(
                    key,
                    rustbgpd_wire::EvpnRouteKey::EadPerEvi {
                        esi,
                        rd,
                        ..
                    } if *esi == redefined_esi && *rd == new_member_rd
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
            es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
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
    async fn runtime_actor_converger_l2vni_redefine_reoriginates_imet() {
        // Committed VNI 100 (RD 65000:100); candidate redefines it to RD
        // 65000:111. The redefine path must withdraw the committed Type 3 IMET
        // route and originate the new-RD one through the real converger.
        let current = runtime_model_from_candidate_toml(two_l2vni_runtime_candidate_toml());
        let candidate =
            runtime_candidate_from_toml(two_l2vni_one_redefined_l2vni_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);
        let current_instances = Arc::new(current.instances().clone());
        let vni100 = rustbgpd_evpn::EvpnInstanceId::new(100).unwrap();
        let old_rd = current.instances().get(vni100).unwrap().rd;
        let new_rd = candidate.instances().get(vni100).unwrap().rd;

        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

        // Pre-originate the committed (old-RD) IMET so the redefine has a
        // Type 3 route to withdraw.
        let imet_controller =
            Arc::new(tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new()));
        {
            let old_inst = current.instances().get(vni100).unwrap().clone();
            let _ = imet_controller
                .lock()
                .await
                .originate_instance(old_inst, &rib_tx)
                .await;
        }

        // Dataplane + originator are required by the redefine converge path.
        let (evpn_instances_tx, _evpn_instances_rx) = watch::channel(current_instances.clone());
        let (ip_vrfs_tx, _ip_vrfs_rx) = watch::channel(Arc::new(rustbgpd_evpn::IpVrfTable::new()));
        let (bum_enforcement_tx, _bum_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
        let (same_esi_bias_tx, _bias_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
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
            same_esi_bias_tx,
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
            imet_controller,
            dataplane: Some(dataplane_handle.runtime_control()),
            originator: Some(originator_handle.runtime_control()),
            svi: None,
            l3_originator: None,
            segment: None,
            es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
        };

        converger
            .converge(&current, &candidate, &plan)
            .await
            .unwrap();

        // IMET withdraw/originate are awaited round-trips through the RIB
        // recorder, so both are recorded by the time `converge` returns.
        let drained = withdraws.lock().await.clone();
        let injected = injects.lock().await.clone();
        assert!(
            drained.iter().any(|key| matches!(
                key,
                rustbgpd_wire::EvpnRouteKey::Imet { rd, .. } if *rd == old_rd
            )),
            "redefine should withdraw the committed (old-RD) IMET route; drained {drained:?}"
        );
        assert!(
            injected.iter().any(|key| matches!(
                key,
                rustbgpd_wire::EvpnRouteKey::Imet { rd, .. } if *rd == new_rd
            )),
            "redefine should originate the new-RD IMET route; injected {injected:?}"
        );

        originator_handle.shutdown().await;
        dataplane_handle.shutdown().await;
    }

    #[tokio::test]
    async fn rollback_imet_redefine_reports_failure_when_withdraw_rejected() {
        // If the IMET withdraw of the new key fails, the controller keeps
        // tracking it, so a bare re-originate of the old instance would no-op
        // with AlreadyOriginated. rollback_imet_redefine must report failure
        // (false) rather than claiming the committed route was restored.
        let current = runtime_model_from_candidate_toml(two_l2vni_runtime_candidate_toml());
        let candidate =
            runtime_candidate_from_toml(two_l2vni_one_redefined_l2vni_runtime_candidate_toml());
        let vni100 = rustbgpd_evpn::EvpnInstanceId::new(100).unwrap();
        let old_instance = current.instances().get(vni100).unwrap().clone();
        let new_instance = candidate.instances().get(vni100).unwrap().clone();

        // RIB responder that accepts injects but rejects every withdraw.
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(32);
        let _rib = tokio::spawn(async move {
            while let Some(msg) = rib_rx.recv().await {
                match msg {
                    RibUpdate::InjectEvpn { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    RibUpdate::WithdrawEvpn { reply, .. } => {
                        let _ = reply.send(Err(RibCommandError::internal("withdraw rejected")));
                    }
                    _ => {}
                }
            }
        });

        // Pre-originate the new key so the controller tracks it (the state
        // after a successful redefine main path).
        let imet_controller =
            Arc::new(tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new()));
        {
            let _ = imet_controller
                .lock()
                .await
                .originate_instance(new_instance, &rib_tx)
                .await;
        }

        let converger = EvpnRuntimeActorConverger {
            rib_tx,
            imet_controller,
            dataplane: None,
            originator: None,
            svi: None,
            l3_originator: None,
            segment: None,
            es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
        };

        let restored = converger.rollback_imet_redefine(vni100, old_instance).await;
        assert!(
            !restored,
            "rollback must report failure when the new IMET key could not be withdrawn"
        );
    }

    #[test]
    fn l2vni_swap_failure_escalates_when_rollback_fails() {
        let error = l2vni_swap_failure(false, "EVPN dataplane runtime model publish failed");
        let DaemonEvpnRuntimeConvergeError::Failed(source) = error else {
            panic!("expected failed error, got {error:?}");
        };
        assert!(
            source.message().contains("rollback also failed"),
            "unexpected error message: {}",
            source.message()
        );
    }

    #[tokio::test]
    async fn restore_imet_reports_failure_when_origination_rejected() {
        // restore_imet must report whether the committed Type 3 was actually
        // re-originated, so the redefine originate-failure path can escalate
        // when even the restore fails.
        let current = runtime_model_from_candidate_toml(two_l2vni_runtime_candidate_toml());
        let old_instance = current
            .instances()
            .get(rustbgpd_evpn::EvpnInstanceId::new(100).unwrap())
            .unwrap()
            .clone();

        // RIB responder that rejects every inject (origination).
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(32);
        let _rib = tokio::spawn(async move {
            while let Some(msg) = rib_rx.recv().await {
                if let RibUpdate::InjectEvpn { reply, .. } = msg {
                    let _ = reply.send(Err(RibCommandError::internal("inject rejected")));
                }
            }
        });

        let converger = EvpnRuntimeActorConverger {
            rib_tx,
            imet_controller: Arc::new(
                tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new()),
            ),
            dataplane: None,
            originator: None,
            svi: None,
            l3_originator: None,
            segment: None,
            es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
        };

        assert!(
            !converger.restore_imet(old_instance).await,
            "restore_imet must report failure when the RIB rejects the re-origination"
        );
    }

    #[tokio::test]
    async fn apply_evpn_runtime_l2vni_redefine_aliasing_toggle_commits() {
        // Toggling apply_aliasing_ecmp off is a redefine; it is now
        // runtime-drivable (the dataplane diff converges it via the
        // FdbNhg -> SingleDst transition). Confirm the committed model carries
        // the flag flip for VNI 100.
        let coordinator = two_l2vni_runtime_coordinator();
        let apply_lock = tokio::sync::Mutex::new(());
        let converger = TestRuntimeConverger::ok();

        let response = apply_evpn_runtime_request(
            &proto::ApplyEvpnRuntimeRequest {
                candidate_toml: two_l2vni_aliasing_toggle_runtime_candidate_toml().to_string(),
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
        let plan = response.plan.unwrap();
        assert_eq!(plan.evpn_instances.unwrap().redefined, vec!["100"]);
        let guard = coordinator.lock().unwrap();
        assert!(
            !guard
                .model()
                .instances()
                .get(rustbgpd_evpn::EvpnInstanceId::new(100).unwrap())
                .unwrap()
                .apply_aliasing_ecmp,
            "committed model should carry apply_aliasing_ecmp=false for VNI 100"
        );
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
            es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
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
    #[expect(
        clippy::too_many_lines,
        reason = "tenant teardown exercises every actor at once"
    )]
    async fn runtime_actor_converger_tenant_teardown_drains_imet_and_es_routes() {
        // Tear down an ES-member L2VNI + its Ethernet Segment in one pass and
        // assert the multi-actor drain: Type 3 IMET withdraw, Type 1/4 segment
        // withdraws, and the dataplane instance model emptied.
        let current = runtime_model_from_candidate_toml(l2vni_one_es_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(minimal_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);
        let current_instances = Arc::new(current.instances().clone());
        let current_ip_vrfs = Arc::new(current.ip_vrfs().clone());
        let deleted_vni = rustbgpd_evpn::EvpnInstanceId::new(100).unwrap();
        let removed_esi =
            rustbgpd_wire::EthernetSegmentIdentifier::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

        let (evpn_instances_tx, evpn_instances_rx) = watch::channel(current_instances.clone());
        let (ip_vrfs_tx, _ip_vrfs_rx) = watch::channel(current_ip_vrfs);
        let (bum_enforcement_tx, _bum_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
        let (same_esi_bias_tx, _bias_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
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
            same_esi_bias_tx,
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
        let mut imet_controller = evpn_imet::EvpnImetController::new();
        let imet_keys = imet_controller
            .originate_all(current.instances().iter().cloned(), &rib_tx)
            .await;
        assert_eq!(imet_keys.len(), 1);

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
                "timed out waiting for initial ES routes; observed {observed:?}"
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
            segment: Some(segment_handle.runtime_control()),
            es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
        };

        converger
            .converge(&current, &candidate, &plan)
            .await
            .unwrap();

        assert!(
            evpn_instances_rx.borrow().get(deleted_vni).is_none(),
            "dataplane instance model should drop the torn-down L2VNI"
        );

        let drain_deadline = StdInstant::now() + Duration::from_secs(2);
        loop {
            let drained = withdraws.lock().await.clone();
            let has_imet = drained
                .iter()
                .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::Imet { .. }));
            let has_es = drained
                .iter()
                .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::Es { esi, .. } if *esi == removed_esi));
            let has_ead_es = drained.iter().any(|key| {
                matches!(key, rustbgpd_wire::EvpnRouteKey::EadPerEs { esi, .. } if *esi == removed_esi)
            });
            let has_ead_evi = drained.iter().any(|key| {
                matches!(key, rustbgpd_wire::EvpnRouteKey::EadPerEvi { esi, .. } if *esi == removed_esi)
            });
            if has_imet && has_es && has_ead_es && has_ead_evi {
                break;
            }
            assert!(
                StdInstant::now() < drain_deadline,
                "tenant teardown did not drain IMET + segment routes; drained {drained:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        originator_handle.shutdown().await;
        segment_handle.shutdown().await;
        dataplane_handle.shutdown().await;
    }

    fn svi_dataplane_report(
        vni: u32,
        bridge_mac: rustbgpd_evpn::MacAddress,
    ) -> rustbgpd_evpn::DataplaneReport {
        rustbgpd_evpn::DataplaneReport {
            intent_generation: 0,
            reconcile_generation: 0,
            instance_status: vec![rustbgpd_evpn::InstanceDataplaneStatus {
                vni: rustbgpd_evpn::EvpnInstanceId::new(vni).unwrap(),
                state: rustbgpd_evpn::InstanceState::Ready,
                message: None,
                bridge_mac: Some(bridge_mac),
            }],
            applied: vec![],
            failed: vec![],
            bum_enforcement: vec![],
            ip_vrf_status: vec![],
            ip_vrf_routes: Some(rustbgpd_evpn::ip_vrf::IpVrfRouteDump::default()),
            ip_vrf_installed_routes: std::collections::HashMap::new(),
            fdb_nexthops: rustbgpd_evpn::FdbNexthopDataplaneStatus::default(),
            fdb_nhg_drift_counters: rustbgpd_evpn::FdbNhgDriftCounters::default(),
            l3_adoption_counters: rustbgpd_evpn::L3AdoptionCounters::default(),
            single_active_counters: rustbgpd_evpn::SingleActiveCounters::default(),
        }
    }

    #[test]
    fn teardown_failure_escalates_when_imet_not_restored() {
        // When the rollback restored IMET, the error is the bare step message.
        let restored = teardown_failure(true, "EVPN segment publish failed");
        assert_eq!(restored.message(), "EVPN segment publish failed");

        // When IMET could NOT be restored, the message escalates so an operator
        // knows live Type 3 state may need repair/restart.
        let stranded = teardown_failure(false, "EVPN segment publish failed");
        assert!(stranded.message().contains("EVPN segment publish failed"));
        assert!(
            stranded
                .message()
                .contains("IMET teardown rollback also failed"),
            "unexpected message: {}",
            stranded.message()
        );
        assert!(stranded.message().contains("repair/restart"));
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "rollback test wires every actor + simulates a mid-teardown state"
    )]
    async fn runtime_actor_converger_tenant_teardown_rollback_restores_imet_and_models() {
        // Drive the rollback ladder directly: seed a live tenant, simulate a
        // mid-teardown state (IMET withdrawn + segment routes drained), then
        // call rollback_tenant_teardown and assert it re-originates the Type 3
        // IMET and the Type 1/4 segment routes and reports full restoration.
        let current = runtime_model_from_candidate_toml(l2vni_one_es_runtime_candidate_toml());
        let current_instances = Arc::new(current.instances().clone());
        let current_ip_vrfs = Arc::new(current.ip_vrfs().clone());
        let deleted_vni = rustbgpd_evpn::EvpnInstanceId::new(100).unwrap();
        let deleted_instances = vec![current.instances().get(deleted_vni).cloned().unwrap()];
        let removed_esi =
            rustbgpd_wire::EthernetSegmentIdentifier::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

        let (evpn_instances_tx, _evpn_instances_rx) = watch::channel(current_instances.clone());
        let (ip_vrfs_tx, _ip_vrfs_rx) = watch::channel(current_ip_vrfs);
        let (bum_enforcement_tx, _bum_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
        let (same_esi_bias_tx, _bias_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
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
            same_esi_bias_tx,
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
        let mut imet_controller = evpn_imet::EvpnImetController::new();
        imet_controller
            .originate_all(current.instances().iter().cloned(), &rib_tx)
            .await;

        // Wait for the live tenant's initial origination (IMET + Type 1/4).
        let initial_deadline = StdInstant::now() + Duration::from_secs(2);
        loop {
            let observed = injects.lock().await.clone();
            let imet = observed
                .iter()
                .filter(|k| matches!(k, rustbgpd_wire::EvpnRouteKey::Imet { .. }))
                .count();
            let es = observed.iter().any(
                |k| matches!(k, rustbgpd_wire::EvpnRouteKey::Es { esi, .. } if *esi == removed_esi),
            );
            if imet >= 1 && es {
                break;
            }
            assert!(
                StdInstant::now() < initial_deadline,
                "no initial origination"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Simulate the mid-teardown state: IMET withdrawn + segment drained.
        imet_controller
            .withdraw_instance(deleted_vni, &rib_tx)
            .await;
        let empty_instances = Arc::new(rustbgpd_evpn::EvpnInstanceTable::new());
        let segment_control = segment_handle.runtime_control();
        assert!(segment_control.replace_instances(empty_instances.clone()));
        assert!(segment_control.replace_segments(Arc::new(Vec::new())));
        let drain_deadline = StdInstant::now() + Duration::from_secs(2);
        loop {
            let drained = withdraws.lock().await.clone();
            let imet = drained
                .iter()
                .any(|k| matches!(k, rustbgpd_wire::EvpnRouteKey::Imet { .. }));
            let es = drained.iter().any(
                |k| matches!(k, rustbgpd_wire::EvpnRouteKey::Es { esi, .. } if *esi == removed_esi),
            );
            if imet && es {
                break;
            }
            assert!(
                StdInstant::now() < drain_deadline,
                "mid-teardown drain stalled"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let imet_before = injects
            .lock()
            .await
            .iter()
            .filter(|k| matches!(k, rustbgpd_wire::EvpnRouteKey::Imet { .. }))
            .count();
        let es_before = injects
            .lock()
            .await
            .iter()
            .filter(
                |k| matches!(k, rustbgpd_wire::EvpnRouteKey::Es { esi, .. } if *esi == removed_esi),
            )
            .count();

        let converger = EvpnRuntimeActorConverger {
            rib_tx,
            imet_controller: Arc::new(tokio::sync::Mutex::new(imet_controller)),
            dataplane: Some(dataplane_handle.runtime_control()),
            originator: Some(originator_handle.runtime_control()),
            svi: None,
            l3_originator: None,
            segment: Some(segment_handle.runtime_control()),
            es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
        };

        let restored = converger
            .rollback_tenant_teardown(&current, &deleted_instances)
            .await;
        assert!(restored, "rollback should report full IMET restoration");

        // Rollback re-originates the IMET (synchronously) and republishes the
        // committed segment snapshot (which re-originates the Type 4 ES route).
        let restore_deadline = StdInstant::now() + Duration::from_secs(2);
        loop {
            let observed = injects.lock().await.clone();
            let imet_now = observed
                .iter()
                .filter(|k| matches!(k, rustbgpd_wire::EvpnRouteKey::Imet { .. }))
                .count();
            let es_now = observed
                .iter()
                .filter(|k| matches!(k, rustbgpd_wire::EvpnRouteKey::Es { esi, .. } if *esi == removed_esi))
                .count();
            if imet_now > imet_before && es_now > es_before {
                break;
            }
            assert!(
                StdInstant::now() < restore_deadline,
                "rollback did not re-originate IMET + ES (imet {imet_before}->{imet_now}, es {es_before}->{es_now})"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        originator_handle.shutdown().await;
        segment_handle.shutdown().await;
        dataplane_handle.shutdown().await;
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "wires dataplane + originator + SVI actors and drives a report"
    )]
    async fn runtime_actor_converger_tenant_teardown_drains_svi_mac() {
        // A multi-element teardown that deletes an advertise_svi_mac L2VNI must
        // drain its SVI MAC (Type 2) through the SVI actor's instance-watch path.
        let current = runtime_model_from_candidate_toml(two_l2vni_one_svi_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(minimal_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);
        let current_instances = Arc::new(current.instances().clone());
        let current_ip_vrfs = Arc::new(current.ip_vrfs().clone());
        let svi_mac = rustbgpd_evpn::MacAddress::new([0x02, 0, 0, 0, 0, 0x5b]);

        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

        let (evpn_instances_tx, _evpn_instances_rx) = watch::channel(current_instances.clone());
        let (ip_vrfs_tx, _ip_vrfs_rx) = watch::channel(current_ip_vrfs);
        let (bum_enforcement_tx, _bum_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
        let (same_esi_bias_tx, _bias_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
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
            same_esi_bias_tx,
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
        let (svi_report_tx, svi_report_rx) =
            broadcast::channel::<rustbgpd_evpn::DataplaneReport>(8);
        let svi_handle = evpn_svi::spawn(
            &current_instances,
            rib_tx.clone(),
            svi_report_rx,
            BgpMetrics::new(),
            evpn_originator::OriginatedLocalMacCounts::default(),
            tokio_util::sync::CancellationToken::new(),
        )
        .expect("SVI actor should spawn when an instance advertises its SVI MAC");
        let mut imet_controller = evpn_imet::EvpnImetController::new();
        imet_controller
            .originate_all(current.instances().iter().cloned(), &rib_tx)
            .await;

        // Drive the SVI MAC origination via a Ready dataplane report, then
        // capture the originated Type 2 key.
        svi_report_tx
            .send(svi_dataplane_report(100, svi_mac))
            .unwrap();
        let svi_deadline = StdInstant::now() + Duration::from_secs(2);
        let svi_key = loop {
            let observed = injects.lock().await.clone();
            if let Some(key) = observed
                .iter()
                .find(|k| matches!(k, rustbgpd_wire::EvpnRouteKey::MacIp { .. }))
                .copied()
            {
                break key;
            }
            assert!(
                StdInstant::now() < svi_deadline,
                "SVI actor never originated the SVI MAC; observed {observed:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        };

        let converger = EvpnRuntimeActorConverger {
            rib_tx,
            imet_controller: Arc::new(tokio::sync::Mutex::new(imet_controller)),
            dataplane: Some(dataplane_handle.runtime_control()),
            originator: Some(originator_handle.runtime_control()),
            svi: Some(svi_handle.runtime_control()),
            l3_originator: None,
            segment: None,
            es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
        };

        converger
            .converge(&current, &candidate, &plan)
            .await
            .unwrap();

        let drain_deadline = StdInstant::now() + Duration::from_secs(2);
        loop {
            if withdraws.lock().await.contains(&svi_key) {
                break;
            }
            assert!(
                StdInstant::now() < drain_deadline,
                "tenant teardown did not withdraw the SVI MAC"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        svi_handle.shutdown().await;
        originator_handle.shutdown().await;
        dataplane_handle.shutdown().await;
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
            es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
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

    /// ADR-0084 decision 3 on the originator side, pinned at the
    /// converger: every runtime-model publish carries the LIVE
    /// coordinator drained set, so an unrelated runtime apply (here an
    /// L2VNI add) committed while an Ethernet Segment is
    /// operator-drained must not undrain it — neither the member
    /// VNI's local Type 2 nor the segment's Type 1/4 routes may
    /// re-originate from the apply.
    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "full two-actor + drain-primitive wiring per the sibling converger proofs"
    )]
    async fn runtime_apply_preserves_operator_drain_across_unrelated_l2vni_add() {
        let current = runtime_model_from_candidate_toml(l2vni_one_es_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(two_l2vni_one_es_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);
        let current_instances = Arc::new(current.instances().clone());
        let drained_esi =
            rustbgpd_wire::EthernetSegmentIdentifier::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

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

        // A local MAC on the ES member VNI 100 originates a Type 2.
        local_tx
            .send(rustbgpd_evpn::LocalMacObservation::Learned {
                vni: rustbgpd_evpn::EvpnInstanceId::new(100).unwrap(),
                mac: rustbgpd_evpn::MacAddress::new([0x02, 0, 0, 0, 0, 0xab]),
                ifindex: 10,
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
                "originator did not originate the VNI 100 local MAC"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Operator-drain the ES through the shared primitive against
        // the same drain state the converger will read.
        let es_drain = crate::evpn_es_drain::EvpnEsDrainState::default();
        let apply_lock = tokio::sync::Mutex::new(());
        let coordinator = Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::from_model(&current));
        let segment_control = segment_handle.runtime_control();
        let originator_control = originator_handle.runtime_control();
        let outcome = crate::evpn_es_drain::apply_ethernet_segment_drain(
            drained_esi,
            crate::evpn_es_drain::EsDrainReason::Operator,
            true,
            &apply_lock,
            &coordinator,
            &es_drain,
            Some(&segment_control),
            Some(&originator_control),
        )
        .await
        .expect("drain applies against the committed model");
        assert!(outcome.drained && outcome.changed);
        let drain_deadline = StdInstant::now() + Duration::from_secs(2);
        loop {
            let drained = withdraws.lock().await.clone();
            let macip_withdrawn = drained
                .iter()
                .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::MacIp { .. }));
            let es_withdrawn = drained
                .iter()
                .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::Es { .. }));
            if macip_withdrawn && es_withdrawn {
                break;
            }
            assert!(
                StdInstant::now() < drain_deadline,
                "drain did not withdraw across both actors; withdrew {drained:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let inject_floor = injects.lock().await.len();

        // Unrelated runtime apply: add L2VNI 200. The converger
        // publishes the originator model with `es_drain.snapshot()`.
        let (evpn_instances_tx, _evpn_instances_rx) = watch::channel(current_instances.clone());
        let (ip_vrfs_tx, _ip_vrfs_rx) = watch::channel(Arc::new(rustbgpd_evpn::IpVrfTable::new()));
        let (bum_enforcement_tx, _bum_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
        let (same_esi_bias_tx, _bias_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
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
            same_esi_bias_tx,
            evpn_instances_tx,
            ip_vrfs_tx,
            remote_prefix_drop_counts_rx,
        };
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
            es_drain: es_drain.clone(),
        };
        converger
            .converge(&current, &candidate, &plan)
            .await
            .unwrap();

        // The add's IMET origination round-trips the publish.
        let imet_deadline = StdInstant::now() + Duration::from_secs(2);
        loop {
            if injects
                .lock()
                .await
                .iter()
                .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::Imet { .. }))
            {
                break;
            }
            assert!(
                StdInstant::now() < imet_deadline,
                "L2VNI add did not originate the new VNI's IMET"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(
            es_drain.snapshot().contains(&drained_esi),
            "the apply must not GC a still-configured drained ES"
        );
        let post = injects.lock().await.clone();
        assert!(
            !post[inject_floor..].iter().any(|key| matches!(
                key,
                rustbgpd_wire::EvpnRouteKey::MacIp { .. }
                    | rustbgpd_wire::EvpnRouteKey::Es { .. }
                    | rustbgpd_wire::EvpnRouteKey::EadPerEs { .. }
                    | rustbgpd_wire::EvpnRouteKey::EadPerEvi { .. }
            )),
            "an unrelated L2VNI add must not undrain the ES (no Type 2 replay, \
             no Type 1/4 re-origination); injected {post:?}"
        );

        originator_handle.shutdown().await;
        segment_handle.shutdown().await;
        dataplane_handle.shutdown().await;
    }

    /// The drain-GC split-state fix (cross-actor seam audit follow-up to
    /// ADR-0084): an ES-delete apply whose Type 2 originator publish
    /// fails mid-converge must leave the coordinator's drain state
    /// (the gauge / RPC drain-reason source) and the segment actor's
    /// drained-set mirror AGREEING — both still drained — and a
    /// subsequent bare operator undrain must be a real transition that
    /// fans the undrained set out to the actor, not an idempotent no-op
    /// against an entry the converge already GC'd.
    #[tokio::test]
    async fn failed_es_delete_publish_keeps_coordinator_and_actor_drain_agreeing() {
        let current = runtime_model_from_candidate_toml(two_l2vni_two_es_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(two_l2vni_one_es_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);
        let removed_esi =
            rustbgpd_wire::EthernetSegmentIdentifier::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

        let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(8);
        let es_drain = crate::evpn_es_drain::EvpnEsDrainState::default();
        let apply_lock = tokio::sync::Mutex::new(());
        let coordinator = Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::from_model(&current));
        let mut probe = evpn_segment::EvpnSegmentControlProbe::new();

        // Operator-drain the ES the apply will delete, through the shared
        // primitive: coordinator state + the segment actor's mirror.
        let outcome = crate::evpn_es_drain::apply_ethernet_segment_drain(
            removed_esi,
            crate::evpn_es_drain::EsDrainReason::Operator,
            true,
            &apply_lock,
            &coordinator,
            &es_drain,
            Some(&probe.control),
            None,
        )
        .await
        .expect("drain applies against the committed model");
        assert!(outcome.drained && outcome.changed);
        assert!(probe.drained_rx.borrow_and_update().contains(&removed_esi));

        // ES delete whose originator publish fails mid-converge (the
        // actor exited) — after the segment actor already received the
        // candidate instance snapshot.
        let converger = EvpnRuntimeActorConverger {
            rib_tx,
            imet_controller: Arc::new(
                tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new()),
            ),
            dataplane: None,
            originator: Some(evpn_originator::EvpnOriginatorRuntimeControl::closed_for_test()),
            svi: None,
            l3_originator: None,
            segment: Some(probe.control.clone()),
            es_drain: es_drain.clone(),
        };
        let err = converger
            .converge(&current, &candidate, &plan)
            .await
            .unwrap_err();
        assert!(
            err.message()
                .contains("originator runtime control is closed"),
            "expected the originator publish failure; got {err:?}"
        );

        // The invariant: both sides still report the ES drained.
        assert!(
            es_drain.snapshot().contains(&removed_esi),
            "a failed converge must not GC the coordinator's drain entry"
        );
        assert_eq!(
            es_drain.reasons_for(removed_esi),
            std::collections::BTreeSet::from([crate::evpn_es_drain::EsDrainReason::Operator]),
            "the RPC drain-reason source must still report the operator drain"
        );
        assert!(
            probe.drained_rx.borrow_and_update().contains(&removed_esi),
            "the segment actor's drained mirror must still hold the ES"
        );

        // And a bare operator undrain is a real transition that fans out.
        let outcome = crate::evpn_es_drain::apply_ethernet_segment_drain(
            removed_esi,
            crate::evpn_es_drain::EsDrainReason::Operator,
            false,
            &apply_lock,
            &coordinator,
            &es_drain,
            Some(&probe.control),
            None,
        )
        .await
        .expect("undrain applies against the committed model");
        assert!(
            outcome.changed,
            "the undrain after the failed apply must not be an idempotent no-op"
        );
        assert!(!outcome.drained);
        assert!(
            !probe.drained_rx.borrow_and_update().contains(&removed_esi),
            "the undrain must fan the undrained set out to the segment actor"
        );
    }

    /// The same invariant on the tenant-teardown path: a teardown that
    /// would delete a drained ES but fails before completing (here: the
    /// Type 2 originator is gone) must leave the coordinator drain state
    /// and the segment actor's mirror agreeing (both drained), with a
    /// subsequent operator undrain fanning out.
    #[tokio::test]
    async fn failed_tenant_teardown_keeps_coordinator_and_actor_drain_agreeing() {
        let current = runtime_model_from_candidate_toml(l2vni_one_es_runtime_candidate_toml());
        let candidate = runtime_candidate_from_toml(minimal_runtime_candidate_toml());
        let plan = current.plan_candidate(&candidate);
        let drained_esi =
            rustbgpd_wire::EthernetSegmentIdentifier::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

        let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(8);
        let es_drain = crate::evpn_es_drain::EvpnEsDrainState::default();
        let apply_lock = tokio::sync::Mutex::new(());
        let coordinator = Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::from_model(&current));
        let mut probe = evpn_segment::EvpnSegmentControlProbe::new();

        let outcome = crate::evpn_es_drain::apply_ethernet_segment_drain(
            drained_esi,
            crate::evpn_es_drain::EsDrainReason::Operator,
            true,
            &apply_lock,
            &coordinator,
            &es_drain,
            Some(&probe.control),
            None,
        )
        .await
        .expect("drain applies against the committed model");
        assert!(outcome.drained && outcome.changed);

        // Open dataplane control so the teardown reaches the originator
        // requirement, which fails (the actor exited).
        let (evpn_instances_tx, _evpn_instances_rx) =
            watch::channel(Arc::new(current.instances().clone()));
        let (ip_vrfs_tx, _ip_vrfs_rx) = watch::channel(Arc::new(rustbgpd_evpn::IpVrfTable::new()));
        let (bum_enforcement_tx, _bum_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
        let (same_esi_bias_tx, _bias_rx) =
            watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
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
            same_esi_bias_tx,
            evpn_instances_tx,
            ip_vrfs_tx,
            remote_prefix_drop_counts_rx,
        };
        let converger = EvpnRuntimeActorConverger {
            rib_tx,
            imet_controller: Arc::new(
                tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new()),
            ),
            dataplane: Some(dataplane_handle.runtime_control()),
            originator: Some(evpn_originator::EvpnOriginatorRuntimeControl::closed_for_test()),
            svi: None,
            l3_originator: None,
            segment: Some(probe.control.clone()),
            es_drain: es_drain.clone(),
        };
        let err = converger
            .converge(&current, &candidate, &plan)
            .await
            .unwrap_err();
        assert!(
            err.message()
                .contains("originator runtime control is closed"),
            "expected the originator failure; got {err:?}"
        );

        assert!(
            es_drain.snapshot().contains(&drained_esi),
            "a failed teardown must not GC the coordinator's drain entry"
        );
        assert!(
            probe.drained_rx.borrow_and_update().contains(&drained_esi),
            "the segment actor's drained mirror must still hold the ES"
        );

        let outcome = crate::evpn_es_drain::apply_ethernet_segment_drain(
            drained_esi,
            crate::evpn_es_drain::EsDrainReason::Operator,
            false,
            &apply_lock,
            &coordinator,
            &es_drain,
            Some(&probe.control),
            None,
        )
        .await
        .expect("undrain applies against the committed model");
        assert!(
            outcome.changed,
            "the undrain after the failed teardown must not be an idempotent no-op"
        );
        assert!(
            !probe.drained_rx.borrow_and_update().contains(&drained_esi),
            "the undrain must fan the undrained set out to the segment actor"
        );

        dataplane_handle.shutdown().await;
    }
}
