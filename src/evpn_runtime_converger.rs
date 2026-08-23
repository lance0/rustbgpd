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
use rustbgpd_evpn::runtime_plan_shape::{
    L2VniMixedChanges, SupportedPlanRoute, SupportedPlanShapeError, route_supported_plan_shape,
    validate_supported_plan_shape,
};
use rustbgpd_rib::RibUpdate;
use rustbgpd_telemetry::BgpMetrics;

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

    pub(crate) fn message(&self) -> &str {
        match self {
            Self::Unsupported(message) => message,
            Self::Failed(source) => source.message(),
        }
    }
}

impl From<SupportedPlanShapeError> for DaemonEvpnRuntimeConvergeError {
    fn from(error: SupportedPlanShapeError) -> Self {
        Self::Unsupported(error.message().to_string())
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

    /// The availability preconditions [`Self::converge`] would enforce for
    /// this plan's route — actor presence and openness — with no side
    /// effects. The `validate_only` dry-run runs this after the shape gate
    /// so a "validated" verdict is not contradicted by a commit of the
    /// identical candidate failing its actor precondition (LAN-897, e.g.
    /// an L2VNI add on an RR-only daemon that spawned no dataplane
    /// actors). The default has no preconditions: test convergers
    /// converge unconditionally.
    ///
    /// # Errors
    /// The routed converge method's precondition error.
    fn validate_availability(
        &self,
        current: &rustbgpd_evpn::EvpnRuntimeModel,
        candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
        plan: &rustbgpd_evpn::EvpnRuntimePlan,
    ) -> Result<(), DaemonEvpnRuntimeConvergeError> {
        let _ = (current, candidate, plan);
        Ok(())
    }
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
    pub(crate) terminal: EvpnRuntimeReloadTerminal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EvpnRuntimeReloadTerminal {
    Unchanged,
    Applied(EvpnRuntimeReloadApplyResult),
    RejectedNoEffect(GrpcEvpnRuntimeApplyError),
    KnownPartial(GrpcEvpnRuntimeApplyError),
    KnownDivergence(GrpcEvpnRuntimeApplyError),
    PublicationAmbiguous(GrpcEvpnRuntimeApplyError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EvpnRuntimeReloadState {
    generation: rustbgpd_evpn::EvpnRuntimeGeneration,
    lifecycle: rustbgpd_evpn::EvpnRuntimeLifecycle,
    mutation_state: rustbgpd_evpn::EvpnRuntimeMutationState,
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
    /// Daemon metrics handle, so a #268 decomposed-apply fail-stop can
    /// bump `evpn_runtime_decomposed_fail_stops_total`. Defaults to a
    /// throwaway registry (`with_metrics` wires the real one in `main`).
    metrics: BgpMetrics,
}

impl EvpnRuntimeReloadApply {
    pub(crate) fn new(
        coordinator: Arc<Mutex<rustbgpd_evpn::EvpnRuntimeCoordinator>>,
        apply_lock: Arc<tokio::sync::Mutex<()>>,
        converger: Arc<dyn DaemonEvpnRuntimeConverger>,
        committed_config: Config,
    ) -> Self {
        Self {
            coordinator,
            apply_lock,
            converger,
            committed_config: Arc::new(Mutex::new(committed_config)),
            es_link_bindings_tx: None,
            metrics: BgpMetrics::new(),
        }
    }

    /// Wire the daemon metrics handle so a #268 decomposed-apply
    /// fail-stop increments `evpn_runtime_decomposed_fail_stops_total`.
    pub(crate) fn with_metrics(mut self, metrics: BgpMetrics) -> Self {
        self.metrics = metrics;
        self
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
                .apply_candidate_config_locked(&config, validate_only, || {})
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

    pub(crate) async fn apply_config_if_changed<F, M>(
        &self,
        config: &Config,
        changed: F,
        begin_mutation: M,
    ) -> EvpnRuntimeReloadAttempt
    where
        F: FnOnce(&Config, &Config) -> bool + Send + 'static,
        M: FnOnce() + Send + 'static,
    {
        let this = self.clone();
        let config = config.clone();
        // Same ADR-0080 shield as `apply_candidate_config`: losing an outer
        // reload waiter must not cancel a converge mid-flight.
        let join = tokio::spawn(async move {
            let _apply_guard = this.apply_lock.lock().await;
            let baseline = this.committed_config_locked();
            if !changed(&config, &baseline) {
                return EvpnRuntimeReloadAttempt {
                    baseline,
                    terminal: EvpnRuntimeReloadTerminal::Unchanged,
                };
            }

            let before = match this.reload_state() {
                Ok(state) => state,
                Err(error) => {
                    return EvpnRuntimeReloadAttempt {
                        baseline,
                        terminal: EvpnRuntimeReloadTerminal::PublicationAmbiguous(error),
                    };
                }
            };
            let result = this
                .apply_candidate_config_locked(&config, false, begin_mutation)
                .await;
            let terminal = match this.reload_state() {
                Ok(after) => classify_reload_terminal(before, after, result),
                Err(error) => EvpnRuntimeReloadTerminal::PublicationAmbiguous(error),
            };
            if matches!(terminal, EvpnRuntimeReloadTerminal::Applied(_)) {
                this.set_committed_config(&config);
            }

            EvpnRuntimeReloadAttempt { baseline, terminal }
        });
        match join.await {
            Ok(attempt) => attempt,
            Err(error) => EvpnRuntimeReloadAttempt {
                baseline: self.committed_config_locked(),
                terminal: EvpnRuntimeReloadTerminal::PublicationAmbiguous(apply_task_join_error(
                    "reload apply",
                    &error,
                )),
            },
        }
    }

    fn reload_state(&self) -> Result<EvpnRuntimeReloadState, GrpcEvpnRuntimeApplyError> {
        let coordinator = self.coordinator.lock().map_err(|_| {
            GrpcEvpnRuntimeApplyError::Internal(
                "EVPN runtime coordinator lock poisoned while classifying reload settlement"
                    .to_string(),
            )
        })?;
        let model = coordinator.model();
        Ok(EvpnRuntimeReloadState {
            generation: model.generation(),
            lifecycle: model.lifecycle(),
            mutation_state: model.mutation_state(),
        })
    }

    async fn apply_candidate_config_locked<M>(
        &self,
        config: &Config,
        validate_only: bool,
        begin_mutation: M,
    ) -> Result<proto::ApplyEvpnRuntimeResponse, GrpcEvpnRuntimeApplyError>
    where
        M: FnOnce(),
    {
        let candidate = evpn_runtime_candidate_from_config(config)?;
        apply_evpn_runtime_candidate_locked(
            candidate,
            validate_only,
            &self.coordinator,
            self.converger.as_ref(),
            &self.metrics,
            begin_mutation,
        )
        .await
    }
}

fn classify_reload_terminal(
    before: EvpnRuntimeReloadState,
    after: EvpnRuntimeReloadState,
    result: Result<proto::ApplyEvpnRuntimeResponse, GrpcEvpnRuntimeApplyError>,
) -> EvpnRuntimeReloadTerminal {
    match result {
        Ok(_)
            if after.mutation_state == rustbgpd_evpn::EvpnRuntimeMutationState::Failed
                || after.lifecycle == rustbgpd_evpn::EvpnRuntimeLifecycle::Degraded
                || (before.mutation_state != rustbgpd_evpn::EvpnRuntimeMutationState::Idle
                    && after.mutation_state != rustbgpd_evpn::EvpnRuntimeMutationState::Idle) =>
        {
            EvpnRuntimeReloadTerminal::KnownDivergence(GrpcEvpnRuntimeApplyError::Internal(
                "EVPN runtime returned success while coordinator authority remained degraded"
                    .to_string(),
            ))
        }
        Ok(response) => match response_to_reload_outcome(response.outcome) {
            Ok(outcome) => EvpnRuntimeReloadTerminal::Applied(EvpnRuntimeReloadApplyResult {
                outcome,
                message: response.message,
            }),
            Err(error) => EvpnRuntimeReloadTerminal::PublicationAmbiguous(error),
        },
        Err(error) if after.generation != before.generation => {
            EvpnRuntimeReloadTerminal::KnownPartial(error)
        }
        Err(error)
            if after.mutation_state == rustbgpd_evpn::EvpnRuntimeMutationState::Failed
                || after.lifecycle == rustbgpd_evpn::EvpnRuntimeLifecycle::Degraded
                || (before.mutation_state != rustbgpd_evpn::EvpnRuntimeMutationState::Idle
                    && after.mutation_state != rustbgpd_evpn::EvpnRuntimeMutationState::Idle) =>
        {
            EvpnRuntimeReloadTerminal::KnownDivergence(error)
        }
        Err(error)
            if after.generation == before.generation
                && after.mutation_state == rustbgpd_evpn::EvpnRuntimeMutationState::Idle
                && matches!(
                    error,
                    GrpcEvpnRuntimeApplyError::InvalidArgument(_)
                        | GrpcEvpnRuntimeApplyError::FailedPrecondition(_)
                ) =>
        {
            EvpnRuntimeReloadTerminal::RejectedNoEffect(error)
        }
        Err(
            error @ (GrpcEvpnRuntimeApplyError::Internal(_)
            | GrpcEvpnRuntimeApplyError::Unavailable(_)),
        ) => EvpnRuntimeReloadTerminal::PublicationAmbiguous(error),
        Err(error) => EvpnRuntimeReloadTerminal::KnownDivergence(error),
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

/// The actor controls an L2VNI-family converge route (add, delete,
/// redefine, mixed update, tenant teardown) publishes to, acquired
/// (present + open) up front so a missing/closed actor fails before any
/// side effect. The LAN-897 dry-run availability gate acquires the same
/// set and drops it, so validate and commit agree on preconditions.
struct L2vniFamilyActors<'a> {
    dataplane: &'a evpn_dataplane::EvpnDataplaneRuntimeControl,
    originator: &'a evpn_originator::EvpnOriginatorRuntimeControl,
    svi: Option<&'a evpn_svi::EvpnSviRuntimeControl>,
    segment: Option<&'a evpn_segment::EvpnSegmentRuntimeControl>,
}

/// Same contract as [`L2vniFamilyActors`] for the additive build-up
/// route, where every actor is conditional on which domains the
/// candidate adds rows in.
struct AdditiveBuildUpActors<'a> {
    dataplane: Option<&'a evpn_dataplane::EvpnDataplaneRuntimeControl>,
    originator: Option<&'a evpn_originator::EvpnOriginatorRuntimeControl>,
    svi: Option<&'a evpn_svi::EvpnSviRuntimeControl>,
    segment: Option<&'a evpn_segment::EvpnSegmentRuntimeControl>,
    l3_originator: Option<&'a evpn_l3_originator::EvpnL3OriginatorRuntimeControl>,
}

impl EvpnRuntimeActorConverger {
    #[expect(
        clippy::too_many_arguments,
        reason = "one optional control per EVPN actor plus shared drain state is explicit wiring"
    )]
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
        added_vni: rustbgpd_evpn::EvpnInstanceId,
    ) -> Result<(), DaemonEvpnRuntimeConvergeError> {
        let Some(instance) = candidate.instances().get(added_vni).cloned() else {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "candidate did not contain added L2VNI {added_vni}"
            )));
        };
        let candidate_instances = Arc::new(candidate.instances().clone());
        let candidate_vni_to_esi = evpn_vni_to_esi_map(candidate.ethernet_segments());
        let candidate_ip_vrfs = Arc::new(candidate.ip_vrfs().clone());
        let ip_vrf_metadata_changed = current.ip_vrfs() != candidate.ip_vrfs();

        let L2vniFamilyActors {
            dataplane,
            originator,
            svi,
            segment,
        } = self.l2vni_add_actors(&instance)?;

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

    /// Availability preconditions shared by every L2VNI-family converge
    /// route: required dataplane + Type 2 originator, an SVI actor when
    /// the touched instances demand one (open when merely present), and
    /// an open segment control when one exists. `svi_requirement` names
    /// the operation in the missing-SVI-actor rejection.
    fn require_l2vni_family_actors(
        &self,
        operation: &str,
        svi_required: bool,
        svi_requirement: &str,
    ) -> Result<L2vniFamilyActors<'_>, DaemonEvpnRuntimeConvergeError> {
        let dataplane = self.require_l2vni_dataplane(operation)?;
        let originator = self.require_l2vni_originator(operation)?;
        let svi = self.svi.as_ref();
        if svi_required && svi.is_none() {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "{svi_requirement} requires an active SVI actor; \
                 live SVI actor-spawn is not supported yet"
            )));
        }
        if let Some(svi) = svi
            && !svi.is_open()
        {
            return Err(DaemonEvpnRuntimeConvergeError::failed(
                "EVPN SVI runtime control is closed",
            ));
        }
        let segment = self.open_segment_runtime_control()?;
        Ok(L2vniFamilyActors {
            dataplane,
            originator,
            svi,
            segment,
        })
    }

    fn l2vni_add_actors(
        &self,
        added: &rustbgpd_evpn::EvpnInstance,
    ) -> Result<L2vniFamilyActors<'_>, DaemonEvpnRuntimeConvergeError> {
        self.require_l2vni_family_actors(
            "add",
            added.advertise_svi_mac,
            "L2VNI runtime add with advertise_svi_mac=true",
        )
    }

    fn l2vni_delete_actors(
        &self,
        deleted: &rustbgpd_evpn::EvpnInstance,
    ) -> Result<L2vniFamilyActors<'_>, DaemonEvpnRuntimeConvergeError> {
        self.require_l2vni_family_actors(
            "delete",
            deleted.advertise_svi_mac,
            "L2VNI runtime delete with advertise_svi_mac=true",
        )
    }

    fn l2vni_redefine_actors(
        &self,
        old: &rustbgpd_evpn::EvpnInstance,
        new: &rustbgpd_evpn::EvpnInstance,
    ) -> Result<L2vniFamilyActors<'_>, DaemonEvpnRuntimeConvergeError> {
        // Either the committed or candidate side may carry advertise_svi_mac,
        // so the SVI actor is required if either does (turning it off still
        // needs the actor to withdraw the stale SVI MAC).
        self.require_l2vni_family_actors(
            "redefine",
            new.advertise_svi_mac || old.advertise_svi_mac,
            "L2VNI runtime redefine with advertise_svi_mac=true",
        )
    }

    fn l2vni_swap_actors(
        &self,
        changes: &L2VniMixedChanges,
    ) -> Result<L2vniFamilyActors<'_>, DaemonEvpnRuntimeConvergeError> {
        let svi_required = changes
            .added
            .iter()
            .chain(changes.deleted.iter())
            .chain(changes.redefined.iter().flat_map(|(old, new)| [old, new]))
            .any(|instance| instance.advertise_svi_mac);
        self.require_l2vni_family_actors(
            "mixed L2VNI update",
            svi_required,
            "mixed L2VNI runtime update with advertise_svi_mac=true",
        )
    }

    fn tenant_teardown_actors(
        &self,
        deleted: &[rustbgpd_evpn::EvpnInstance],
        ip_vrf_changed: bool,
    ) -> Result<
        (
            L2vniFamilyActors<'_>,
            Option<&evpn_l3_originator::EvpnL3OriginatorRuntimeControl>,
        ),
        DaemonEvpnRuntimeConvergeError,
    > {
        let actors = self.require_l2vni_family_actors(
            "tenant teardown",
            deleted.iter().any(|inst| inst.advertise_svi_mac),
            "tenant teardown of an advertise_svi_mac L2VNI",
        )?;
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
        Ok((actors, l3_originator))
    }

    /// Availability preconditions shared by the single IP-VRF converge
    /// routes (add, delete, redefine): required dataplane + open, and
    /// required Type 5 originator + open.
    fn require_ip_vrf_actors(
        &self,
        operation: &str,
    ) -> Result<
        (
            &evpn_dataplane::EvpnDataplaneRuntimeControl,
            &evpn_l3_originator::EvpnL3OriginatorRuntimeControl,
        ),
        DaemonEvpnRuntimeConvergeError,
    > {
        let dataplane = self.dataplane.as_ref().ok_or_else(|| {
            DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "IP-VRF runtime {operation} requires an active EVPN dataplane actor; \
                 no-EVPN startup actor-spawn is not supported yet"
            ))
        })?;
        let l3_originator = self.l3_originator.as_ref().ok_or_else(|| {
            DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "IP-VRF runtime {operation} requires an active EVPN Type 5 originator; \
                 live Type 5 actor-spawn is not supported yet"
            ))
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
        Ok((dataplane, l3_originator))
    }

    /// Availability preconditions shared by the single Ethernet Segment
    /// converge routes: required segment actor + open, plus an open
    /// Type 2 originator when one exists (RR / no-local-MAC deployments
    /// have none and are left untouched).
    fn require_ethernet_segment_actors(
        &self,
        operation: &str,
    ) -> Result<
        (
            &evpn_segment::EvpnSegmentRuntimeControl,
            Option<&evpn_originator::EvpnOriginatorRuntimeControl>,
        ),
        DaemonEvpnRuntimeConvergeError,
    > {
        let segment = self.require_segment_runtime_control(operation)?;
        let originator = self.originator.as_ref();
        if let Some(originator) = originator
            && !originator.is_open()
        {
            return Err(DaemonEvpnRuntimeConvergeError::failed(
                "EVPN Type 2 originator runtime control is closed",
            ));
        }
        Ok((segment, originator))
    }

    /// Availability preconditions of the additive build-up route: each
    /// actor is required only for the domains the candidate adds rows
    /// in, mirroring the publishes `converge_additive_build_up` makes.
    fn require_additive_build_up_actors(
        &self,
        current: &rustbgpd_evpn::EvpnRuntimeModel,
        candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
        plan: &rustbgpd_evpn::EvpnRuntimePlan,
        added_instances: &[rustbgpd_evpn::EvpnInstance],
    ) -> Result<AdditiveBuildUpActors<'_>, DaemonEvpnRuntimeConvergeError> {
        let l2_changed = !plan.evpn_instances.added.is_empty();
        let ip_vrf_rows_changed = !plan.ip_vrfs.added.is_empty();
        let ip_vrf_metadata_changed = current.ip_vrfs() != candidate.ip_vrfs();
        let es_changed = !plan.ethernet_segments.added.is_empty()
            || !plan.ethernet_segments.redefined.is_empty();

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
        Ok(AdditiveBuildUpActors {
            dataplane,
            originator,
            svi,
            segment,
            l3_originator,
        })
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
        added_instances: Vec<rustbgpd_evpn::EvpnInstance>,
    ) -> Result<(), DaemonEvpnRuntimeConvergeError> {
        let candidate_instances = Arc::new(candidate.instances().clone());
        let candidate_ip_vrfs = Arc::new(candidate.ip_vrfs().clone());
        let candidate_segments = Arc::new(candidate.ethernet_segments().to_vec());
        let candidate_vni_to_esi = evpn_vni_to_esi_map(candidate.ethernet_segments());

        let l2_changed = !plan.evpn_instances.added.is_empty();
        let ip_vrf_metadata_changed = current.ip_vrfs() != candidate.ip_vrfs();
        let es_changed = !plan.ethernet_segments.added.is_empty()
            || !plan.ethernet_segments.redefined.is_empty();

        let AdditiveBuildUpActors {
            dataplane,
            originator,
            svi,
            segment,
            l3_originator,
        } = self.require_additive_build_up_actors(current, candidate, plan, &added_instances)?;

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

    /// Converge a mixed L2VNI-only candidate: one-or-more L2VNI change
    /// classes (add/delete/redefine) in one request. The only cross-domain
    /// metadata this path accepts is the IP-VRF link delta intrinsic to
    /// added/deleted VNIs; broader relinks, IP-VRF row changes, and Ethernet
    /// Segment row changes still fail closed.
    #[expect(
        clippy::too_many_lines,
        reason = "ordered multi-consumer swap with rollback reads clearest as one sequence"
    )]
    async fn converge_l2vni_swap(
        &self,
        current: &rustbgpd_evpn::EvpnRuntimeModel,
        candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
        changes: L2VniMixedChanges,
    ) -> Result<(), DaemonEvpnRuntimeConvergeError> {
        let candidate_instances = Arc::new(candidate.instances().clone());
        let candidate_ip_vrfs = Arc::new(candidate.ip_vrfs().clone());
        let ip_vrf_metadata_changed = current.ip_vrfs() != candidate.ip_vrfs();

        let L2vniFamilyActors {
            dataplane,
            originator,
            svi,
            segment,
        } = self.l2vni_swap_actors(&changes)?;

        let mut originated_added = Vec::with_capacity(changes.added.len());
        for instance in &changes.added {
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
                    .rollback_l2vni_mixed(
                        current,
                        &originated_added,
                        &[],
                        &[],
                        ip_vrf_metadata_changed,
                    )
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

        let mut redefined_old_instances = Vec::with_capacity(changes.redefined.len());
        for (old_instance, new_instance) in &changes.redefined {
            let redefined_vni = old_instance.id;
            // Re-key the redefined VNI's IMET under one guard (withdraw old,
            // originate new), but never call rollback while the guard is held:
            // rollback_l2vni_mixed re-locks imet_controller, and tokio's Mutex
            // is not reentrant, so an in-guard rollback would deadlock the
            // converge task. Capture the outcome, drop the guard, then handle.
            let rekey = {
                let mut imet = self.imet_controller.lock().await;
                let withdraw_outcome = imet.withdraw_instance(redefined_vni, &self.rib_tx).await;
                if matches!(
                    withdraw_outcome,
                    evpn_imet::ImetWithdrawOutcome::Withdrawn { .. }
                        | evpn_imet::ImetWithdrawOutcome::NotOriginated { .. }
                ) {
                    Ok(imet
                        .originate_instance(new_instance.clone(), &self.rib_tx)
                        .await)
                } else {
                    Err(withdraw_outcome)
                }
            };
            // Track the in-flight old instance before any rollback so a partial
            // withdraw (e.g. ReplyDropped) is force-restored rather than left
            // withdrawn while the rollback reports success.
            redefined_old_instances.push(old_instance.clone());
            match rekey {
                Err(withdraw_outcome) => {
                    let restored = self
                        .rollback_l2vni_mixed(
                            current,
                            &originated_added,
                            &[],
                            &redefined_old_instances,
                            ip_vrf_metadata_changed,
                        )
                        .await;
                    return Err(l2vni_swap_failure(
                        restored,
                        &format!(
                            "EVPN IMET withdrawal failed for redefined L2VNI {redefined_vni}: {withdraw_outcome:?}"
                        ),
                    ));
                }
                Ok(originate_outcome) => {
                    if !matches!(
                        originate_outcome,
                        evpn_imet::ImetOriginateOutcome::Originated { .. }
                            | evpn_imet::ImetOriginateOutcome::AlreadyOriginated { .. }
                            | evpn_imet::ImetOriginateOutcome::ReplyDropped { .. }
                    ) {
                        let restored = self
                            .rollback_l2vni_mixed(
                                current,
                                &originated_added,
                                &[],
                                &redefined_old_instances,
                                ip_vrf_metadata_changed,
                            )
                            .await;
                        return Err(l2vni_swap_failure(
                            restored,
                            &format!(
                                "EVPN IMET origination failed for redefined L2VNI {redefined_vni}: {originate_outcome:?}"
                            ),
                        ));
                    }
                }
            }
        }

        if ip_vrf_metadata_changed && !dataplane.replace_ip_vrfs(candidate_ip_vrfs) {
            let restored = self
                .rollback_l2vni_mixed(
                    current,
                    &originated_added,
                    &[],
                    &redefined_old_instances,
                    ip_vrf_metadata_changed,
                )
                .await;
            return Err(l2vni_swap_failure(
                restored,
                "EVPN dataplane IP-VRF runtime model publish failed",
            ));
        }
        if !dataplane.replace_evpn_instances(candidate_instances.clone()) {
            let restored = self
                .rollback_l2vni_mixed(
                    current,
                    &originated_added,
                    &[],
                    &redefined_old_instances,
                    ip_vrf_metadata_changed,
                )
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
                .rollback_l2vni_mixed(
                    current,
                    &originated_added,
                    &[],
                    &redefined_old_instances,
                    ip_vrf_metadata_changed,
                )
                .await;
            return Err(l2vni_swap_failure(
                restored,
                "EVPN SVI runtime model publish failed",
            ));
        }

        let mut withdrawn_deleted = Vec::with_capacity(changes.deleted.len());
        for instance in &changes.deleted {
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
                    .rollback_l2vni_mixed(
                        current,
                        &originated_added,
                        &withdrawn_deleted,
                        &redefined_old_instances,
                        ip_vrf_metadata_changed,
                    )
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
                .rollback_l2vni_mixed(
                    current,
                    &originated_added,
                    &withdrawn_deleted,
                    &redefined_old_instances,
                    ip_vrf_metadata_changed,
                )
                .await;
            return Err(l2vni_swap_failure(
                restored,
                "EVPN Type 2 originator runtime model publish failed",
            ));
        }
        if let Err(err) = Self::publish_segment_instances(segment, candidate_instances) {
            let restored = self
                .rollback_l2vni_mixed(
                    current,
                    &originated_added,
                    &withdrawn_deleted,
                    &redefined_old_instances,
                    ip_vrf_metadata_changed,
                )
                .await;
            return Err(l2vni_swap_failure(restored, err.message()));
        }

        Ok(())
    }

    async fn rollback_l2vni_mixed(
        &self,
        current: &rustbgpd_evpn::EvpnRuntimeModel,
        added_instances: &[rustbgpd_evpn::EvpnInstance],
        withdrawn_deleted_instances: &[rustbgpd_evpn::EvpnInstance],
        redefined_old_instances: &[rustbgpd_evpn::EvpnInstance],
        ip_vrf_metadata_changed: bool,
    ) -> bool {
        let current_instances = Arc::new(current.instances().clone());
        let current_ip_vrfs = Arc::new(current.ip_vrfs().clone());
        let mut restored = true;
        if let Some(dataplane) = self.dataplane.as_ref() {
            if ip_vrf_metadata_changed {
                restored &= dataplane.replace_ip_vrfs(current_ip_vrfs);
            }
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
        for instance in redefined_old_instances {
            restored &= self
                .rollback_imet_redefine(instance.id, instance.clone())
                .await;
        }
        restored
    }

    async fn converge_l2vni_delete(
        &self,
        current: &rustbgpd_evpn::EvpnRuntimeModel,
        candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
        deleted_instance: rustbgpd_evpn::EvpnInstance,
    ) -> Result<(), DaemonEvpnRuntimeConvergeError> {
        let deleted_vni = deleted_instance.id;
        let current_instances = Arc::new(current.instances().clone());
        let candidate_instances = Arc::new(candidate.instances().clone());
        let candidate_ip_vrfs = Arc::new(candidate.ip_vrfs().clone());
        let ip_vrf_metadata_changed = current.ip_vrfs() != candidate.ip_vrfs();

        let L2vniFamilyActors {
            dataplane,
            originator,
            svi,
            segment,
        } = self.l2vni_delete_actors(&deleted_instance)?;

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
        deleted_instances: Vec<rustbgpd_evpn::EvpnInstance>,
    ) -> Result<(), DaemonEvpnRuntimeConvergeError> {
        let candidate_instances = Arc::new(candidate.instances().clone());
        let candidate_ip_vrfs = Arc::new(candidate.ip_vrfs().clone());
        let candidate_segments = Arc::new(candidate.ethernet_segments().to_vec());
        let candidate_vni_to_esi = evpn_vni_to_esi_map(candidate.ethernet_segments());
        let ip_vrf_changed = current.ip_vrfs() != candidate.ip_vrfs();

        let (
            L2vniFamilyActors {
                dataplane,
                originator,
                svi,
                segment,
            },
            l3_originator,
        ) = self.tenant_teardown_actors(&deleted_instances, ip_vrf_changed)?;

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
        candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
    ) -> Result<(), DaemonEvpnRuntimeConvergeError> {
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
        redefined_vni: rustbgpd_evpn::EvpnInstanceId,
    ) -> Result<(), DaemonEvpnRuntimeConvergeError> {
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

        let L2vniFamilyActors {
            dataplane,
            originator,
            svi,
            segment,
        } = self.l2vni_redefine_actors(&old_instance, &new_instance)?;

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
        added_name: &str,
    ) -> Result<(), DaemonEvpnRuntimeConvergeError> {
        let candidate_ip_vrfs = Arc::new(candidate.ip_vrfs().clone());
        if candidate.ip_vrfs().get(added_name).is_none() {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "candidate is missing planned IP-VRF {added_name:?}"
            )));
        }

        let (dataplane, l3_originator) = self.require_ip_vrf_actors("add")?;

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
        _deleted_name: String,
    ) -> Result<(), DaemonEvpnRuntimeConvergeError> {
        let candidate_ip_vrfs = Arc::new(candidate.ip_vrfs().clone());

        let (dataplane, l3_originator) = self.require_ip_vrf_actors("delete")?;

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
        redefined_name: &str,
    ) -> Result<(), DaemonEvpnRuntimeConvergeError> {
        let candidate_ip_vrfs = Arc::new(candidate.ip_vrfs().clone());
        if candidate.ip_vrfs().get(redefined_name).is_none() {
            return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                "candidate is missing planned redefined IP-VRF {redefined_name:?}"
            )));
        }

        let (dataplane, l3_originator) = self.require_ip_vrf_actors("redefine")?;

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
        _added_esi: rustbgpd_wire::EthernetSegmentIdentifier,
    ) -> Result<(), DaemonEvpnRuntimeConvergeError> {
        self.publish_ethernet_segment_runtime_snapshot(current, candidate, "add")
    }

    fn converge_ethernet_segment_delete(
        &self,
        current: &rustbgpd_evpn::EvpnRuntimeModel,
        candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
        _deleted_esi: rustbgpd_wire::EthernetSegmentIdentifier,
    ) -> Result<(), DaemonEvpnRuntimeConvergeError> {
        self.publish_ethernet_segment_runtime_snapshot(current, candidate, "delete")
    }

    fn converge_ethernet_segment_redefine(
        &self,
        current: &rustbgpd_evpn::EvpnRuntimeModel,
        candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
        _redefined_esi: rustbgpd_wire::EthernetSegmentIdentifier,
    ) -> Result<(), DaemonEvpnRuntimeConvergeError> {
        self.publish_ethernet_segment_runtime_snapshot(current, candidate, "redefine")
    }

    fn publish_ethernet_segment_runtime_snapshot(
        &self,
        current: &rustbgpd_evpn::EvpnRuntimeModel,
        candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
        operation: &str,
    ) -> Result<(), DaemonEvpnRuntimeConvergeError> {
        let (segment, originator) = self.require_ethernet_segment_actors(operation)?;
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
        let republished_originator = if let Some(originator) = originator {
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
            if republished_originator && let Some(originator) = originator {
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

impl DaemonEvpnRuntimeConverger for EvpnRuntimeActorConverger {
    fn converge<'a>(
        &'a self,
        current: &'a rustbgpd_evpn::EvpnRuntimeModel,
        candidate: &'a rustbgpd_evpn::EvpnRuntimeCandidate,
        plan: &'a rustbgpd_evpn::EvpnRuntimePlan,
    ) -> DaemonEvpnRuntimeConvergeFuture<'a> {
        Box::pin(async move {
            match route_supported_plan_shape(current, candidate, plan)? {
                SupportedPlanRoute::TenantTeardown(deleted) => {
                    self.converge_tenant_teardown(current, candidate, deleted)
                        .await
                }
                SupportedPlanRoute::IpVrfRelink => self.converge_ip_vrf_relink(candidate),
                SupportedPlanRoute::AdditiveBuildUp(added) => {
                    self.converge_additive_build_up(current, candidate, plan, added)
                        .await
                }
                SupportedPlanRoute::L2vniMixed(changes) => {
                    self.converge_l2vni_swap(current, candidate, changes).await
                }
                SupportedPlanRoute::SingleL2vniDelete(deleted) => {
                    self.converge_l2vni_delete(current, candidate, *deleted)
                        .await
                }
                SupportedPlanRoute::SingleL2vniRedefine(vni) => {
                    self.converge_l2vni_redefine(current, candidate, vni).await
                }
                SupportedPlanRoute::SingleL2vniAdd(vni) => {
                    self.converge_l2vni_add(current, candidate, vni).await
                }
                SupportedPlanRoute::SingleIpVrfDelete(name) => {
                    self.converge_ip_vrf_delete(current, candidate, name)
                }
                SupportedPlanRoute::SingleIpVrfRedefine(name) => {
                    self.converge_ip_vrf_redefine(current, candidate, &name)
                }
                SupportedPlanRoute::SingleIpVrfAdd(name) => {
                    self.converge_ip_vrf_add(current, candidate, &name)
                }
                SupportedPlanRoute::SingleEthernetSegmentDelete(esi) => {
                    self.converge_ethernet_segment_delete(current, candidate, esi)
                }
                SupportedPlanRoute::SingleEthernetSegmentRedefine(esi) => {
                    self.converge_ethernet_segment_redefine(current, candidate, esi)
                }
                SupportedPlanRoute::SingleEthernetSegmentAdd(esi) => {
                    self.converge_ethernet_segment_add(current, candidate, esi)
                }
            }
        })
    }

    fn validate_availability(
        &self,
        current: &rustbgpd_evpn::EvpnRuntimeModel,
        candidate: &rustbgpd_evpn::EvpnRuntimeCandidate,
        plan: &rustbgpd_evpn::EvpnRuntimePlan,
    ) -> Result<(), DaemonEvpnRuntimeConvergeError> {
        // Route exactly as `converge` would (via the shared classifier),
        // then acquire — and drop — the same actor set the routed
        // `converge_*` method acquires through the same `require_*`
        // helpers. No publish, no IMET mutation: availability only.
        match route_supported_plan_shape(current, candidate, plan)? {
            SupportedPlanRoute::TenantTeardown(deleted) => {
                let ip_vrf_changed = current.ip_vrfs() != candidate.ip_vrfs();
                self.tenant_teardown_actors(&deleted, ip_vrf_changed)
                    .map(drop)
            }
            SupportedPlanRoute::IpVrfRelink => {
                self.require_l2vni_dataplane("ip_vrf relink").map(drop)
            }
            SupportedPlanRoute::AdditiveBuildUp(added) => self
                .require_additive_build_up_actors(current, candidate, plan, &added)
                .map(drop),
            SupportedPlanRoute::L2vniMixed(changes) => self.l2vni_swap_actors(&changes).map(drop),
            SupportedPlanRoute::SingleL2vniDelete(deleted) => {
                self.l2vni_delete_actors(&deleted).map(drop)
            }
            SupportedPlanRoute::SingleL2vniRedefine(vni) => {
                let Some(new_instance) = candidate.instances().get(vni) else {
                    return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                        "candidate did not contain redefined L2VNI {vni}"
                    )));
                };
                let Some(old_instance) = current.instances().get(vni) else {
                    return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                        "committed model did not contain redefined L2VNI {vni}"
                    )));
                };
                self.l2vni_redefine_actors(old_instance, new_instance)
                    .map(drop)
            }
            SupportedPlanRoute::SingleL2vniAdd(vni) => {
                let Some(added) = candidate.instances().get(vni) else {
                    return Err(DaemonEvpnRuntimeConvergeError::unsupported(format!(
                        "candidate did not contain added L2VNI {vni}"
                    )));
                };
                self.l2vni_add_actors(added).map(drop)
            }
            SupportedPlanRoute::SingleIpVrfDelete(_) => {
                self.require_ip_vrf_actors("delete").map(drop)
            }
            SupportedPlanRoute::SingleIpVrfRedefine(_) => {
                self.require_ip_vrf_actors("redefine").map(drop)
            }
            SupportedPlanRoute::SingleIpVrfAdd(_) => self.require_ip_vrf_actors("add").map(drop),
            SupportedPlanRoute::SingleEthernetSegmentDelete(_) => {
                self.require_ethernet_segment_actors("delete").map(drop)
            }
            SupportedPlanRoute::SingleEthernetSegmentRedefine(_) => {
                self.require_ethernet_segment_actors("redefine").map(drop)
            }
            SupportedPlanRoute::SingleEthernetSegmentAdd(_) => {
                self.require_ethernet_segment_actors("add").map(drop)
            }
        }
    }
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

#[expect(
    clippy::too_many_lines,
    reason = "the plan/validate-only/converge/decompose/commit sequence reads clearest as one flow"
)]
async fn apply_evpn_runtime_candidate_locked<M>(
    candidate: rustbgpd_evpn::EvpnRuntimeCandidate,
    validate_only: bool,
    coordinator: &Mutex<rustbgpd_evpn::EvpnRuntimeCoordinator>,
    converger: &dyn DaemonEvpnRuntimeConverger,
    metrics: &BgpMetrics,
    begin_mutation: M,
) -> Result<proto::ApplyEvpnRuntimeResponse, GrpcEvpnRuntimeApplyError>
where
    M: FnOnce(),
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
        // LAN-214 #9: a dry-run must reject exactly what a real apply would
        // reject. Re-run the same shape acceptance the commit path uses —
        // supported primitive shape, or a #268 decomposition into supported
        // steps — WITHOUT committing or touching any actor. (`converge` is
        // skipped on purpose: it has actor side effects; its shape routing
        // mirrors `validate_supported_plan_shape` and its actor
        // preconditions are re-run side-effect-free through
        // `validate_availability` — LAN-897.)
        let message = if plan.is_noop() {
            "candidate EVPN runtime model validated (no-op: matches the committed generation); \
             generation not advanced"
                .to_string()
        } else {
            match validate_supported_plan_shape(&current, &candidate, &plan) {
                Ok(()) => {
                    if let Err(availability_error) =
                        converger.validate_availability(&current, &candidate, &plan)
                    {
                        return Err(GrpcEvpnRuntimeApplyError::FailedPrecondition(format!(
                            "EVPN runtime candidate rejected: {}; generation {} remains committed",
                            availability_error.message(),
                            snapshot.generation.as_u64()
                        )));
                    }
                    "candidate EVPN runtime model validated as a supported primitive shape; \
                     generation not advanced"
                        .to_string()
                }
                Err(shape_error) => {
                    match crate::evpn_plan_decomposer::decompose_evpn_runtime_candidate(
                        &current, &candidate, &plan,
                    ) {
                        Ok(steps) => {
                            // A real apply converges each decomposed step
                            // through the same actor preconditions; simulate
                            // the sequence (as the decomposer does for shape)
                            // and check availability per step.
                            let total = steps.len();
                            let mut model = current.clone();
                            for (index, step) in steps.iter().enumerate() {
                                let step_plan = model.plan_candidate(&step.candidate);
                                if !step_plan.is_noop()
                                    && let Err(availability_error) = converger
                                        .validate_availability(&model, &step.candidate, &step_plan)
                                {
                                    return Err(GrpcEvpnRuntimeApplyError::FailedPrecondition(
                                        format!(
                                            "EVPN runtime candidate rejected: decomposed step \
                                             {}/{total} ({}) would fail: {}; generation {} \
                                             remains committed",
                                            index + 1,
                                            step.description,
                                            availability_error.message(),
                                            snapshot.generation.as_u64()
                                        ),
                                    ));
                                }
                                model = rustbgpd_evpn::EvpnRuntimeModel::startup(
                                    step.candidate.instances().clone(),
                                    step.candidate.ip_vrfs().clone(),
                                    step.candidate.ethernet_segments().to_vec(),
                                );
                            }
                            format!(
                                "candidate EVPN runtime model validated; a real apply would \
                                 decompose it into {} supported steps ({}); generation not \
                                 advanced",
                                steps.len(),
                                steps
                                    .iter()
                                    .map(|step| step.description.clone())
                                    .collect::<Vec<_>>()
                                    .join("; ")
                            )
                        }
                        // Primitive but unsupported: surface the same shape
                        // rejection the commit path would return.
                        Err(crate::evpn_plan_decomposer::EvpnDecomposeError::AlreadyPrimitive) => {
                            return Err(GrpcEvpnRuntimeApplyError::FailedPrecondition(format!(
                                "EVPN runtime candidate rejected: {}; generation {} remains committed",
                                shape_error.message(),
                                snapshot.generation.as_u64()
                            )));
                        }
                        Err(crate::evpn_plan_decomposer::EvpnDecomposeError::Unsupported(
                            reason,
                        )) => {
                            return Err(GrpcEvpnRuntimeApplyError::FailedPrecondition(format!(
                                "EVPN runtime candidate rejected: {reason}; generation {} remains committed",
                                snapshot.generation.as_u64()
                            )));
                        }
                    }
                }
            }
        };
        return Ok(proto::ApplyEvpnRuntimeResponse {
            outcome: proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyValidated as i32,
            runtime: Some(runtime_snapshot_to_proto(&snapshot)),
            plan: Some(runtime_plan_to_proto(&plan)),
            message,
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

    // Reject unsupported shapes and unavailable actor routes while this is
    // still a pure plan. Once the phase callback fires, the next awaited work
    // is a mutation-capable converge (direct or decomposed).
    match validate_supported_plan_shape(&current, &candidate, &plan) {
        Ok(()) => {
            if let Err(error) = converger.validate_availability(&current, &candidate, &plan) {
                return Err(GrpcEvpnRuntimeApplyError::FailedPrecondition(format!(
                    "EVPN runtime mutation failed: {}; generation {} remains committed",
                    error.message(),
                    snapshot.generation.as_u64()
                )));
            }
        }
        Err(shape_error) => {
            match crate::evpn_plan_decomposer::decompose_evpn_runtime_candidate(
                &current, &candidate, &plan,
            ) {
                Ok(steps) => {
                    let total = steps.len();
                    let mut model = current.clone();
                    for (index, step) in steps.iter().enumerate() {
                        let step_plan = model.plan_candidate(&step.candidate);
                        if !step_plan.is_noop()
                            && let Err(error) =
                                converger.validate_availability(&model, &step.candidate, &step_plan)
                        {
                            return Err(GrpcEvpnRuntimeApplyError::FailedPrecondition(format!(
                                "EVPN runtime mutation failed: decomposed step {}/{total} ({}) \
                                 would fail: {}; generation {} remains committed",
                                index + 1,
                                step.description,
                                error.message(),
                                snapshot.generation.as_u64()
                            )));
                        }
                        model = rustbgpd_evpn::EvpnRuntimeModel::startup(
                            step.candidate.instances().clone(),
                            step.candidate.ip_vrfs().clone(),
                            step.candidate.ethernet_segments().to_vec(),
                        );
                    }
                    begin_mutation();
                    return apply_decomposed_evpn_runtime_steps(
                        steps,
                        &plan,
                        coordinator,
                        converger,
                        metrics,
                    )
                    .await;
                }
                Err(crate::evpn_plan_decomposer::EvpnDecomposeError::AlreadyPrimitive) => {
                    return Err(GrpcEvpnRuntimeApplyError::FailedPrecondition(format!(
                        "EVPN runtime mutation failed: {}; generation {} remains committed",
                        shape_error.message(),
                        snapshot.generation.as_u64()
                    )));
                }
                Err(crate::evpn_plan_decomposer::EvpnDecomposeError::Unsupported(reason)) => {
                    return Err(GrpcEvpnRuntimeApplyError::FailedPrecondition(format!(
                        "EVPN runtime mutation failed: {reason}; generation {} remains committed",
                        snapshot.generation.as_u64()
                    )));
                }
            }
        }
    }

    begin_mutation();
    if let Err(error) = converger.converge(&current, &candidate, &plan).await {
        // #268: a candidate the dispatch rejects as an unsupported *mixed*
        // composition may still converge as an ordered sequence of
        // already-supported primitive steps, each committing its own
        // generation. Only `Unsupported` triggers the attempt — a `Failed`
        // converge had side effects and must pin, exactly as before.
        if matches!(error, DaemonEvpnRuntimeConvergeError::Unsupported(_)) {
            match crate::evpn_plan_decomposer::decompose_evpn_runtime_candidate(
                &current, &candidate, &plan,
            ) {
                Ok(steps) => {
                    return apply_decomposed_evpn_runtime_steps(
                        steps,
                        &plan,
                        coordinator,
                        converger,
                        metrics,
                    )
                    .await;
                }
                // The plan is already primitive (e.g. a supported shape that
                // failed on a missing actor): today's error stands verbatim.
                Err(crate::evpn_plan_decomposer::EvpnDecomposeError::AlreadyPrimitive) => {}
                // Fail the whole candidate closed, naming the offending
                // step, before any step commits.
                Err(crate::evpn_plan_decomposer::EvpnDecomposeError::Unsupported(message)) => {
                    return Err(GrpcEvpnRuntimeApplyError::FailedPrecondition(format!(
                        "EVPN runtime mutation failed: {message}; generation {} remains committed",
                        snapshot.generation.as_u64()
                    )));
                }
            }
        }
        if let DaemonEvpnRuntimeConvergeError::Failed(source) = error.clone() {
            // #268 decomposition is only attempted for `Unsupported` mixes;
            // a `Failed` converge had side effects and pins here instead.
            tracing::error!(
                error = %error.message(),
                generation = snapshot.generation.as_u64(),
                "decomposition skipped: prior converge failed; pinning the coordinator \
                 and leaving generation committed"
            );
            let mut coordinator = coordinator.lock().map_err(|_| {
                GrpcEvpnRuntimeApplyError::Internal(
                    "EVPN runtime coordinator lock poisoned".to_string(),
                )
            })?;
            let _ = coordinator.apply_candidate(candidate, Err(source));
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
    let report = coordinator
        .apply_candidate(candidate, Ok(()))
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

/// Apply the #268-decomposed primitive steps of a mixed candidate in
/// order, each through the unchanged converge path and each committing
/// its own runtime generation (operators see N generations for one
/// SIGHUP / apply). A mid-sequence failure is **fail-stop**: earlier
/// generations stay committed (no cross-step rollback), a `Failed`
/// converge pins the coordinator exactly like the single-shot path, and
/// the error + `ERROR` log name the completed generations, the failed
/// step, and the re-SIGHUP recovery. The caller holds the apply lock.
async fn apply_decomposed_evpn_runtime_steps(
    steps: Vec<crate::evpn_plan_decomposer::DecomposedStep>,
    overall_plan: &rustbgpd_evpn::EvpnRuntimePlan,
    coordinator: &Mutex<rustbgpd_evpn::EvpnRuntimeCoordinator>,
    converger: &dyn DaemonEvpnRuntimeConverger,
    metrics: &BgpMetrics,
) -> Result<proto::ApplyEvpnRuntimeResponse, GrpcEvpnRuntimeApplyError> {
    let lock_coordinator = || {
        coordinator.lock().map_err(|_| {
            GrpcEvpnRuntimeApplyError::Internal(
                "EVPN runtime coordinator lock poisoned".to_string(),
            )
        })
    };
    let total = steps.len();
    tracing::info!(
        total_steps = total,
        "mixed EVPN runtime candidate decomposed into {total} primitive steps; \
         each step commits its own runtime generation ({total} generations for one apply/SIGHUP)"
    );
    let mut committed_generations: Vec<u64> = Vec::new();
    for (index, step) in steps.into_iter().enumerate() {
        let step_number = index + 1;
        let (step_current, step_plan) = {
            let coordinator = lock_coordinator()?;
            (
                coordinator.model().clone(),
                coordinator.plan_candidate(&step.candidate),
            )
        };
        if step_plan.is_noop() {
            continue;
        }
        if let Err(error) = converger
            .converge(&step_current, &step.candidate, &step_plan)
            .await
        {
            if let DaemonEvpnRuntimeConvergeError::Failed(source) = error.clone() {
                let mut coordinator = lock_coordinator()?;
                let _ = coordinator.apply_candidate(step.candidate.clone(), Err(source));
                // Fail-stop pinned the coordinator (mutation_state=Failed);
                // the ERROR log below carries the human detail.
                metrics.add_evpn_runtime_decomposed_fail_stops(1);
            }
            let committed_summary = if committed_generations.is_empty() {
                "no earlier step committed".to_string()
            } else {
                format!(
                    "earlier steps committed generations {committed_generations:?}, which remain \
                     committed (fail-stop: no cross-step rollback)"
                )
            };
            tracing::error!(
                step = step_number,
                total_steps = total,
                description = %step.description,
                error = %error.message(),
                "decomposed EVPN runtime apply failed mid-sequence; {committed_summary}; fix the \
                 candidate config and re-SIGHUP / re-apply — the next attempt replans from the \
                 committed model and converges only the remainder"
            );
            return Err(GrpcEvpnRuntimeApplyError::FailedPrecondition(format!(
                "EVPN runtime mutation failed at decomposed step {step_number}/{total} ({}): {}; \
                 {committed_summary}; fix the config and re-SIGHUP / re-apply to converge the \
                 remainder",
                step.description,
                error.message(),
            )));
        }
        let report = {
            let mut coordinator = lock_coordinator()?;
            coordinator
                .apply_candidate(step.candidate, Ok(()))
                .map_err(|err| GrpcEvpnRuntimeApplyError::FailedPrecondition(err.to_string()))?
        };
        tracing::info!(
            step = step_number,
            total_steps = total,
            generation = report.committed_generation.as_u64(),
            description = %step.description,
            "decomposed EVPN runtime step committed"
        );
        committed_generations.push(report.committed_generation.as_u64());
    }
    let snapshot = lock_coordinator()?.snapshot();
    // Report what actually committed, not `total` (`steps.len()`): no-op
    // steps `continue` without a generation, so `committed` can be < total.
    let committed = committed_generations.len();
    // #25: no-op steps `continue` without a generation, so committed may be < total.
    let planned_note = if committed == total {
        String::new()
    } else {
        format!(" ({committed} of {total} planned steps committed)")
    };
    let generations_summary = match (committed_generations.first(), committed_generations.last()) {
        (Some(first), Some(last)) => format!(" as generations {first}..={last}"),
        _ => String::new(),
    };
    Ok(proto::ApplyEvpnRuntimeResponse {
        outcome: runtime_apply_outcome_to_proto(rustbgpd_evpn::EvpnRuntimeApplyOutcome::Committed),
        runtime: Some(runtime_snapshot_to_proto(&snapshot)),
        // #23: the response echoes the operator's REQUESTED mixed plan, not
        // the primitive committed steps. Per-step committed detail lives in
        // the INFO logs above and in `generations_summary`.
        plan: Some(runtime_plan_to_proto(overall_plan)),
        message: format!(
            "candidate EVPN runtime model committed via {committed} decomposed steps{planned_note}{generations_summary}"
        ),
    })
}

#[cfg(test)]
mod tests;
