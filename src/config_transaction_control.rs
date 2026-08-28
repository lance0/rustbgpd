//! Binary-owned config transaction apply hook.
//!
//! `ConfigService` lives in the API crate, but committing a transaction needs
//! binary-only state: the FIB reconciler command channel, config persistence,
//! peer-manager validation, and the runtime-config lock shared with SIGHUP.

mod live_policy_impact;

use live_policy_impact::commit_live_policy_impact_locked;
#[cfg(test)]
use live_policy_impact::resolve_live_policy_targets;

use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{Mutex, mpsc, oneshot, watch};

use rustbgpd_api::health_probe::DaemonGate;
use rustbgpd_api::peer_types::ConfigPersistCommitOutcome;
#[cfg(test)]
use rustbgpd_api::peer_types::ResolvedPeerPolicy;
use rustbgpd_api::peer_types::{
    ConfigEvent, ConfigPersistAck, DynamicPeerBounceOutcome, DynamicRangeTarget, PeerKey,
    PeerLifecycleError, PeerManagerCommand, PeerManagerNeighborConfig,
    RuntimeConfigTransactionPlanError, RuntimeConfigTransactionStatus,
};
use rustbgpd_api::proto;
use rustbgpd_api::runtime_config_settlement::RuntimeConfigFenceReason;
use rustbgpd_api::runtime_config_settlement::{
    OwnedRuntimeConfigOperation, OwnedRuntimeConfigRequestContext, RuntimeConfigOperationKind,
    RuntimeConfigSettlementPhase, RuntimeConfigSettlementWatchdog,
};
use rustbgpd_api::server::{
    ConfigHistoryListFn, ConfigMutationGateFn, ConfigRollbackFn, ConfigTransactionAbortFn,
    ConfigTransactionApplyContext, ConfigTransactionApplyError, ConfigTransactionApplyFn,
    ConfigTransactionConfirmFn, ConfigTransactionStatusFn, GnmiSetCommitAction, GnmiSetError,
    GnmiSetFn, GnmiSetOutcome, RuntimeConfigCoordinatorClosed,
};
use rustbgpd_telemetry::BgpMetrics;
use tracing::{error, info, warn};

use crate::config::{
    AcceptedConfigSnapshot, Config, EffectiveNeighborImpactKind, Neighbor, diff_config,
    diff_neighbors, normalized_discard_path_attributes,
};
use crate::fib_table_control::{
    FibTableControlDeps, FibTransactionReplaceOutcome, read_current_tables,
    replace_tables_for_transaction, runtime_unavailable_error,
};
use crate::gnmi_set_bridge;
use crate::peer_manager::{
    InternalCommand, PlannedTransactionConfig, TransactionConfigRollbackToken,
    TransactionConfigScope,
};
use crate::reload::transaction_config_snapshot_accepted;

const PERSIST_RESERVE_TIMEOUT: Duration = Duration::from_secs(2);
const CONFIG_TRANSACTION_COORDINATOR_ACQUIRE_TIMEOUT: Duration = Duration::from_mins(10);
const DEFAULT_CONFIRM_TIMEOUT_SECONDS: u32 = 600;
const MAX_CONFIRM_TIMEOUT_SECONDS: u32 = 86_400;
const MAX_CONFIRM_ID_CHARS: usize = 128;
const FIB_SECTION: &str = "[[fib_tables]]";
const DYNAMIC_SECTION: &str = "[[dynamic_neighbors]]";
const NEIGHBOR_ADD_SECTION: &str = "[[neighbors]] add";
const NEIGHBOR_DELETE_SECTION: &str = "[[neighbors]] delete";
const NEIGHBOR_MODIFY_SECTION: &str = "[[neighbors]] modify";
const PEER_GROUP_CATALOG_SECTION: &str = "[peer_groups] catalog";
const POLICY_DEFINITIONS_SECTION: &str = "[policy] definitions";
const POLICY_NEIGHBOR_SETS_SECTION: &str = "[policy] neighbor_sets";
const POLICY_GLOBAL_CHAINS_SECTION: &str = "[policy] global chains";
const POLICY_LIVE_IMPACT_SECTION: &str = "[policy] live impact";
const SESSION_RESHAPE_SECTION: &str = "effective neighbor session reshape";

#[derive(Clone)]
pub struct ConfigTransactionController {
    deps: Arc<FibTableControlDeps>,
    metrics: BgpMetrics,
    state: Arc<Mutex<ConfirmedState>>,
    accepted_rx: Option<watch::Receiver<Arc<AcceptedConfigSnapshot>>>,
    peer_mgr_internal_tx: Option<mpsc::Sender<InternalCommand>>,
    confirm_v3_launch: Option<crate::confirm_journal::v3::LaunchIdentity>,
    v3_residue_cleanup_active: Arc<AtomicBool>,
    settlement: Option<(RuntimeConfigSettlementWatchdog, DaemonGate)>,
    #[cfg(test)]
    v3_residue_cleanup_spawn_fail: Arc<AtomicBool>,
}

#[derive(Default)]
struct ConfirmedState {
    applying_confirm_id: Option<String>,
    pending: Option<PendingConfirmedTransaction>,
    timer: Option<tokio::task::JoinHandle<()>>,
    last: Option<ConfirmedTransactionRecord>,
    /// LAN-277: confirm id of a confirmed apply that failed in an
    /// ambiguous-completion window (see [`ApplyFailure`]). The revert journal
    /// is retained — it is the only proven path back — and every further
    /// config mutation is fenced off: the daemon cannot prove what the failed
    /// transaction left on disk, and a later-accepted mutation would be
    /// silently clobbered by the retained journal's boot revert. Only a
    /// restart resolves this state (boot revert consumes the journal, or the
    /// operator removes it by hand).
    ambiguous_failure_confirm_id: Option<String>,
}

#[derive(Clone)]
struct PendingConfirmedTransaction {
    confirm_id: String,
    rollback_expected_runtime_snapshot_token: String,
    timeout_seconds: u32,
    deadline: tokio::time::Instant,
    deadline_unix_seconds: u64,
    committed_sections: Vec<String>,
    runtime_snapshot_token: String,
    /// LAN-277: set when an abort or timeout auto-revert rollback FAILED. The
    /// transaction stays pending (fence closed, journal retained) because the
    /// runtime/disk/journal are in a three-way inconsistency the daemon could
    /// not repair; the operator resolves it by retrying abort, confirming the
    /// candidate, or restarting (boot revert from the retained journal).
    rollback_failed: Option<proto::ConfigTransactionConfirmationStatus>,
    /// The exact immutable pre-transaction object retained by disk-backed
    /// authority and reused by live abort/timeout planning.
    prior_snapshot: Arc<AcceptedConfigSnapshot>,
    /// Disk-backed v3 authority. The raw object owns the prior bytes; live
    /// rollback reuses `prior_snapshot` and retains no duplicate full String.
    v3_files: Option<Arc<crate::confirm_journal::v3::PendingFiles>>,
}

#[derive(Clone, Debug)]
struct ConfirmedTransactionRecord {
    confirm_id: String,
    status: proto::ConfigTransactionConfirmationStatus,
    timeout_seconds: u32,
    deadline_unix_seconds: u64,
    committed_sections: Vec<String>,
    runtime_snapshot_token: String,
    human_text: String,
}

#[derive(Clone, Debug)]
struct ConfirmedApplyMode {
    confirm_id: String,
    timeout_seconds: u32,
}

trait OwnedOperationError: From<RuntimeConfigCoordinatorClosed> + Send + 'static {
    fn unavailable(message: &'static str) -> Self;
    fn task_lost(message: &'static str) -> Self;
    fn fence_reason(&self) -> Option<RuntimeConfigFenceReason>;
}

impl OwnedOperationError for ConfigTransactionApplyError {
    fn unavailable(message: &'static str) -> Self {
        Self::Unavailable(message.to_string())
    }

    fn task_lost(message: &'static str) -> Self {
        Self::Internal(message.to_string())
    }

    fn fence_reason(&self) -> Option<RuntimeConfigFenceReason> {
        match self {
            Self::RecoveryRequired { reason, .. } => Some(*reason),
            _ => None,
        }
    }
}

enum OwnedGnmiSetError {
    Clean(GnmiSetError),
    Fenced {
        message: String,
        reason: RuntimeConfigFenceReason,
    },
}

impl From<RuntimeConfigCoordinatorClosed> for OwnedGnmiSetError {
    fn from(error: RuntimeConfigCoordinatorClosed) -> Self {
        Self::Clean(error.into())
    }
}

impl OwnedOperationError for OwnedGnmiSetError {
    fn unavailable(message: &'static str) -> Self {
        Self::Clean(GnmiSetError::Unavailable(message.to_string()))
    }

    fn task_lost(message: &'static str) -> Self {
        Self::Clean(GnmiSetError::Internal(message.to_string()))
    }

    fn fence_reason(&self) -> Option<RuntimeConfigFenceReason> {
        match self {
            Self::Fenced { reason, .. } => Some(*reason),
            Self::Clean(_) => None,
        }
    }
}

impl From<GnmiSetError> for OwnedGnmiSetError {
    fn from(error: GnmiSetError) -> Self {
        Self::Clean(error)
    }
}

#[derive(Clone, Default)]
struct RuntimeConfigMutationProgress(Option<OwnedRuntimeConfigOperation>);

impl RuntimeConfigMutationProgress {
    fn owned(operation: &OwnedRuntimeConfigOperation) -> Self {
        Self(Some(operation.clone()))
    }

    fn begin_mutation(&self) {
        if let Some(operation) = &self.0 {
            operation.advance_phase(RuntimeConfigSettlementPhase::Mutating);
        }
    }

    fn begin_settling(&self) {
        if let Some(operation) = &self.0 {
            operation.advance_phase(RuntimeConfigSettlementPhase::SettlingRollback);
        }
    }
}

impl ConfigTransactionController {
    async fn execute_owned_operation<T, E, F, Fut>(
        self,
        kind: RuntimeConfigOperationKind,
        context: OwnedRuntimeConfigRequestContext,
        shutdown_message: &'static str,
        task_lost_message: &'static str,
        body: F,
    ) -> Result<T, E>
    where
        T: Send + 'static,
        E: OwnedOperationError,
        F: FnOnce(Self, Option<OwnedRuntimeConfigOperation>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<T, E>> + Send + 'static,
    {
        let watched = self.settlement.is_some();
        let join = tokio::spawn(async move {
            let coordinator_permit = self.deps.lock.acquire().await?;
            let Some((watchdog, daemon_gate)) = self.settlement.clone() else {
                return body(self, None).await;
            };
            let (operation, executor_guard) = watchdog.register_owned(
                kind,
                self.deps.lock.clone(),
                coordinator_permit,
                daemon_gate,
                None,
                None,
                context.response_attached(),
            );
            if self
                .settlement
                .as_ref()
                .is_some_and(|(_, gate)| gate.is_shutting_down())
            {
                if !operation.try_settle() {
                    std::future::pending::<()>().await;
                }
                drop(executor_guard);
                return Err(E::unavailable(shutdown_message));
            }
            let result = body(self, Some(operation.clone())).await;
            if let Err(error) = &result
                && let Some(reason) = error.fence_reason()
            {
                let _ = operation.fence_recovery(reason);
                std::future::pending::<()>().await;
            }
            if !operation.try_settle() {
                std::future::pending::<()>().await;
            }
            drop(executor_guard);
            result
        });
        match join.await {
            Ok(result) => result,
            Err(_) if watched => std::future::pending().await,
            Err(_) => Err(E::task_lost(task_lost_message)),
        }
    }

    #[cfg(test)]
    #[must_use]
    pub fn new(deps: FibTableControlDeps, metrics: BgpMetrics) -> Self {
        Self {
            deps: Arc::new(deps),
            metrics,
            state: Arc::new(Mutex::new(ConfirmedState::default())),
            accepted_rx: None,
            peer_mgr_internal_tx: None,
            confirm_v3_launch: None,
            v3_residue_cleanup_active: Arc::new(AtomicBool::new(false)),
            settlement: None,
            v3_residue_cleanup_spawn_fail: Arc::new(AtomicBool::new(false)),
        }
    }

    #[must_use]
    pub(crate) fn new_accepted(
        deps: FibTableControlDeps,
        metrics: BgpMetrics,
        accepted_rx: watch::Receiver<Arc<AcceptedConfigSnapshot>>,
    ) -> Self {
        Self {
            deps: Arc::new(deps),
            metrics,
            state: Arc::new(Mutex::new(ConfirmedState::default())),
            accepted_rx: Some(accepted_rx),
            peer_mgr_internal_tx: None,
            confirm_v3_launch: None,
            v3_residue_cleanup_active: Arc::new(AtomicBool::new(false)),
            settlement: None,
            #[cfg(test)]
            v3_residue_cleanup_spawn_fail: Arc::new(AtomicBool::new(false)),
        }
    }

    #[must_use]
    pub(crate) fn with_runtime_config_settlement(
        mut self,
        watchdog: RuntimeConfigSettlementWatchdog,
        daemon_gate: DaemonGate,
    ) -> Self {
        self.settlement = Some((watchdog, daemon_gate));
        self
    }

    #[must_use]
    pub(crate) fn with_preloaded_planner(mut self, tx: mpsc::Sender<InternalCommand>) -> Self {
        self.peer_mgr_internal_tx = Some(tx);
        self
    }

    #[must_use]
    pub(crate) fn with_confirm_v3_launch(
        mut self,
        launch: crate::confirm_journal::v3::LaunchIdentity,
    ) -> Self {
        self.confirm_v3_launch = Some(launch);
        self
    }

    async fn plan_preloaded_snapshot(
        &self,
        snapshot: Arc<AcceptedConfigSnapshot>,
        expected_runtime_snapshot_token: String,
    ) -> Result<PlannedTransactionConfig, ConfigTransactionApplyError> {
        let (barrier_tx, barrier_rx) = oneshot::channel();
        self.deps
            .peer_mgr_tx
            .send(PeerManagerCommand::RuntimeConfigSnapshot { reply: barrier_tx })
            .await
            .map_err(|_| {
                ConfigTransactionApplyError::Unavailable("peer manager is unavailable".to_string())
            })?;
        barrier_rx
            .await
            .map_err(|_| {
                ConfigTransactionApplyError::Unavailable(
                    "peer manager dropped runtime snapshot barrier".to_string(),
                )
            })?
            .map_err(ConfigTransactionApplyError::Unavailable)?;
        let tx = self.peer_mgr_internal_tx.as_ref().ok_or_else(|| {
            ConfigTransactionApplyError::Unavailable(
                "preloaded config transaction planner is unavailable".to_string(),
            )
        })?;
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(InternalCommand::PlanAcceptedTransactionConfig {
            snapshot,
            expected_runtime_snapshot_token: Some(expected_runtime_snapshot_token),
            reply: reply_tx,
        })
        .await
        .map_err(|_| {
            ConfigTransactionApplyError::Unavailable("peer manager is unavailable".to_string())
        })?;
        reply_rx
            .await
            .map_err(|_| {
                ConfigTransactionApplyError::Unavailable(
                    "peer manager dropped preloaded plan reply".to_string(),
                )
            })?
            .map_err(plan_error_to_status)
    }

    async fn prepare_rollback_payload(
        &self,
        payload: crate::config_history::RollbackPayload,
        request: &proto::RollbackConfigTransactionRequest,
    ) -> Result<(String, Option<PlannedTransactionConfig>), ConfigTransactionApplyError> {
        match payload {
            crate::config_history::RollbackPayload::V2 {
                normalized_toml,
                manifest,
                source_sha256,
            } => {
                if !request.confirm_id.is_empty() {
                    validate_confirm_id(&request.confirm_id)?;
                    if request.confirm_timeout_seconds > 0 {
                        validate_confirm_timeout_seconds(request.confirm_timeout_seconds)?;
                    }
                }
                let accepted = self.accepted_rx.as_ref().ok_or_else(|| {
                    ConfigTransactionApplyError::Unavailable(
                        "accepted-config authority unavailable".to_string(),
                    )
                })?;
                let config_path = accepted
                    .borrow()
                    .config_ref()
                    .file_path
                    .clone()
                    .ok_or_else(|| {
                        ConfigTransactionApplyError::FailedPrecondition(
                            "cannot restore external provenance without a daemon config path"
                                .to_string(),
                        )
                    })?;
                let snapshot = AcceptedConfigSnapshot::load_retained(&normalized_toml, &config_path)
                    .map_err(|_| {
                        ConfigTransactionApplyError::FailedPrecondition(
                            "cannot restore retained external-source snapshot: a declared external source is missing, unreadable, or changed"
                                .to_string(),
                        )
                    })?;
                crate::config_history::verify_retained_snapshot(
                    &snapshot,
                    &normalized_toml,
                    &manifest,
                    source_sha256,
                )
                .map_err(|_| {
                    ConfigTransactionApplyError::FailedPrecondition(
                        "cannot restore retained external-source snapshot: a declared external source is missing, unreadable, or changed"
                            .to_string(),
                    )
                })?;
                let plan = self
                    .plan_preloaded_snapshot(
                        snapshot.clone(),
                        request.expected_runtime_snapshot_token.clone(),
                    )
                    .await?;
                Ok((normalized_toml, Some(plan)))
            }
        }
    }

    async fn apply_prepared_rollback(
        &self,
        request: proto::ApplyConfigTransactionRequest,
        preloaded: Option<PlannedTransactionConfig>,
        progress: &RuntimeConfigMutationProgress,
    ) -> Result<proto::ConfigTransactionApplyResponse, ConfigTransactionApplyError> {
        let confirmed = parse_confirmed_apply_mode(&request)?;
        if let Some(confirmed) = confirmed {
            self.begin_confirmed_apply(&confirmed.confirm_id).await?;
            let result = self
                .apply_confirmed_locked(request, confirmed.clone(), preloaded, progress)
                .await;
            if !matches!(
                result,
                Ok(proto::ConfigTransactionApplyResponse {
                    confirmation: Some(_),
                    ..
                })
            ) {
                self.clear_applying_confirm_id(&confirmed.confirm_id).await;
            }
            result
        } else if let Some(preloaded) = preloaded {
            self.reject_if_pending("ConfigService.RollbackConfigTransaction")
                .await?;
            let peer_mgr_internal_tx = self.peer_mgr_internal_tx.as_ref().ok_or_else(|| {
                ConfigTransactionApplyError::Unavailable(
                    "typed config transaction staging is unavailable".to_string(),
                )
            })?;
            apply_config_transaction_locked_with_preloaded(
                &self.deps,
                request,
                Some(preloaded),
                Some(peer_mgr_internal_tx),
                progress,
            )
            .await
            .map_err(ApplyFailure::into_apply_error)
        } else {
            self.apply_locked(request, None, progress).await
        }
    }

    async fn accepted_runtime_snapshot(&self) -> Result<Config, String> {
        let Some(accepted_rx) = &self.accepted_rx else {
            #[cfg(test)]
            return crate::reload::runtime_config_snapshot(&self.deps.peer_mgr_tx).await;
            #[cfg(not(test))]
            return Err("accepted-config authority unavailable".to_string());
        };
        let accepted = accepted_rx.borrow().clone();
        transaction_config_snapshot_accepted(&self.deps.peer_mgr_tx, &accepted).await
    }

    async fn accepted_prior_snapshot(&self) -> Result<Arc<AcceptedConfigSnapshot>, String> {
        if let Some(accepted_rx) = &self.accepted_rx {
            // Bind provenance before awaiting the peer-manager snapshot.  A
            // concurrent SIGHUP may advance the watch channel while that reply
            // is in flight; re-borrowing afterwards could otherwise relabel an
            // older runtime config with a newer external-source manifest.
            let accepted = accepted_rx.borrow().clone();
            let runtime =
                transaction_config_snapshot_accepted(&self.deps.peer_mgr_tx, &accepted).await?;
            return accepted.derive_config(runtime);
        }
        #[cfg(test)]
        return Ok(AcceptedConfigSnapshot::from_config_for_test(
            self.accepted_runtime_snapshot().await?,
        ));
        #[cfg(not(test))]
        Err("accepted-config authority unavailable".to_string())
    }

    #[must_use]
    pub fn apply_fn(&self) -> ConfigTransactionApplyFn {
        let controller = self.clone();
        Arc::new(move |request, context| {
            let controller = controller.clone();
            Box::pin(async move { controller.apply_with_context(request, context).await })
        })
    }

    #[must_use]
    pub fn gnmi_set_fn(&self) -> GnmiSetFn {
        let controller = self.clone();
        Arc::new(move |transaction, context| {
            let controller = controller.clone();
            Box::pin(async move {
                controller
                    .apply_gnmi_set_with_context(transaction, context)
                    .await
            })
        })
    }

    #[must_use]
    pub fn confirm_fn(&self) -> ConfigTransactionConfirmFn {
        let controller = self.clone();
        Arc::new(move |request, context| {
            let controller = controller.clone();
            Box::pin(async move { controller.confirm_with_context(request, context).await })
        })
    }

    #[must_use]
    pub fn abort_fn(&self) -> ConfigTransactionAbortFn {
        let controller = self.clone();
        Arc::new(move |request, context| {
            let controller = controller.clone();
            Box::pin(async move { controller.abort_with_context(request, context).await })
        })
    }

    #[must_use]
    pub fn status_fn(&self) -> ConfigTransactionStatusFn {
        let controller = self.clone();
        Arc::new(move |_request| {
            let controller = controller.clone();
            Box::pin(async move { controller.status().await })
        })
    }

    #[must_use]
    pub fn history_fn(&self) -> ConfigHistoryListFn {
        let controller = self.clone();
        Arc::new(move |_request| {
            let controller = controller.clone();
            Box::pin(async move { controller.history() })
        })
    }

    #[must_use]
    pub fn rollback_fn(&self) -> ConfigRollbackFn {
        let controller = self.clone();
        Arc::new(move |request, context| {
            let controller = controller.clone();
            Box::pin(async move { controller.rollback_with_context(request, context).await })
        })
    }

    #[must_use]
    pub fn mutation_gate_fn(&self) -> ConfigMutationGateFn {
        let controller = self.clone();
        Arc::new(move |operation| {
            let controller = controller.clone();
            Box::pin(async move {
                controller
                    .reject_if_pending(operation)
                    .await
                    .map_err(|error| error.to_string())
            })
        })
    }

    pub async fn reject_if_pending(
        &self,
        operation: &'static str,
    ) -> Result<(), ConfigTransactionApplyError> {
        let state = self.state.lock().await;
        if let Some(confirm_id) = &state.ambiguous_failure_confirm_id {
            return Err(ambiguous_failure_fence_error(operation, confirm_id));
        }
        if let Some(pending) = &state.pending {
            return Err(ConfigTransactionApplyError::FailedPrecondition(format!(
                "{operation} is blocked while confirmed config transaction {:?} is awaiting confirmation",
                pending.confirm_id
            )));
        }
        if let Some(confirm_id) = &state.applying_confirm_id {
            return Err(ConfigTransactionApplyError::FailedPrecondition(format!(
                "{operation} is blocked while confirmed config transaction {confirm_id:?} is applying"
            )));
        }
        Ok(())
    }

    #[cfg(test)]
    async fn apply(
        self,
        request: proto::ApplyConfigTransactionRequest,
    ) -> Result<proto::ConfigTransactionApplyResponse, ConfigTransactionApplyError> {
        let (context, _attachment) = ConfigTransactionApplyContext::unary();
        self.apply_with_context(request, context).await
    }

    async fn apply_with_context(
        self,
        request: proto::ApplyConfigTransactionRequest,
        mut context: ConfigTransactionApplyContext,
    ) -> Result<proto::ConfigTransactionApplyResponse, ConfigTransactionApplyError> {
        validate_apply_request(&request)?;
        let confirmed = parse_confirmed_apply_mode(&request)?;
        let watched = self.settlement.is_some();
        let join = tokio::spawn(async move {
            let coordinator_permit = tokio::time::timeout(
                CONFIG_TRANSACTION_COORDINATOR_ACQUIRE_TIMEOUT,
                self.deps.lock.acquire(),
            )
            .await
            .map_err(|_| {
                ConfigTransactionApplyError::DeadlineExceeded(
                    "config transaction timed out waiting for the runtime config coordinator; \
                     coordinator ownership was not acquired and apply did not begin"
                        .to_string(),
                )
            })??;
            let Some((watchdog, daemon_gate)) = self.settlement.clone() else {
                let result = self
                    .apply_locked(
                        request,
                        confirmed,
                        &RuntimeConfigMutationProgress::default(),
                    )
                    .await;
                drop(context);
                return result;
            };
            let response_attached = context.request_context().response_attached();
            let stream = context.take_stream_ownership();
            let (stream_permit, stream_admission) = stream
                .map_or((None, None), |(permit, admission)| {
                    (Some(permit), Some(admission))
                });
            let (operation, executor_guard) = watchdog.register_owned(
                RuntimeConfigOperationKind::Apply,
                self.deps.lock.clone(),
                coordinator_permit,
                daemon_gate,
                stream_permit,
                stream_admission,
                response_attached,
            );
            drop(context);
            if self
                .settlement
                .as_ref()
                .is_some_and(|(_, gate)| gate.is_shutting_down())
            {
                if !operation.try_settle() {
                    std::future::pending::<()>().await;
                }
                drop(executor_guard);
                return Err(ConfigTransactionApplyError::Unavailable(
                    "config transaction rejected: daemon is shutting down".to_string(),
                ));
            }
            let progress = RuntimeConfigMutationProgress::owned(&operation);
            let result = self.apply_locked(request, confirmed, &progress).await;
            if let Err(ConfigTransactionApplyError::RecoveryRequired { reason, .. }) = &result {
                let _ = operation.fence_recovery(*reason);
                std::future::pending::<()>().await;
            }
            if !operation.try_settle() {
                std::future::pending::<()>().await;
            }
            drop(executor_guard);
            result
        });

        match join.await {
            Ok(result) => result,
            Err(_) if watched => std::future::pending().await,
            Err(_) => Err(ConfigTransactionApplyError::Internal(
                "config transaction apply task did not complete".to_string(),
            )),
        }
    }

    #[cfg(test)]
    async fn apply_gnmi_set(
        self,
        transaction: rustbgpd_api::server::GnmiSetTransaction,
    ) -> Result<GnmiSetOutcome, GnmiSetError> {
        let (context, _attachment) = OwnedRuntimeConfigRequestContext::unary();
        self.apply_gnmi_set_with_context(transaction, context).await
    }

    #[expect(
        clippy::too_many_lines,
        reason = "gNMI Set keeps its closed commit-action dispatch inside one owned settlement executor"
    )]
    async fn apply_gnmi_set_with_context(
        self,
        transaction: rustbgpd_api::server::GnmiSetTransaction,
        context: OwnedRuntimeConfigRequestContext,
    ) -> Result<GnmiSetOutcome, GnmiSetError> {
        let result = self
            .execute_owned_operation(
                RuntimeConfigOperationKind::GnmiSet,
                context,
                "gNMI Set rejected: daemon is shutting down",
                "gNMI Set transaction task did not complete",
                move |controller, operation| async move {
                    let self_ = controller;
                    let progress = RuntimeConfigMutationProgress(operation);
                    match transaction.commit_action.clone() {
                        Some(GnmiSetCommitAction::Confirm { confirm_id }) => {
                            let confirm_id = validate_confirm_id(&confirm_id)
                                .map_err(apply_error_to_owned_gnmi_set_error)?;
                            self_
                                .confirm_locked(confirm_id, &progress)
                                .await
                                .map_err(apply_error_to_owned_gnmi_set_error)?;
                            return Ok(GnmiSetOutcome::default());
                        }
                        Some(GnmiSetCommitAction::Cancel { confirm_id }) => {
                            let confirm_id = validate_confirm_id(&confirm_id)
                                .map_err(apply_error_to_owned_gnmi_set_error)?;
                            self_
                                .abort_locked(confirm_id, &progress)
                                .await
                                .map_err(apply_error_to_owned_gnmi_set_error)?;
                            return Ok(GnmiSetOutcome::default());
                        }
                        Some(GnmiSetCommitAction::SetRollbackDuration {
                            confirm_id,
                            confirm_timeout_seconds,
                        }) => {
                            let confirm_id = validate_confirm_id(&confirm_id)
                                .map_err(apply_error_to_owned_gnmi_set_error)?;
                            let confirm_timeout_seconds =
                                validate_confirm_timeout_seconds(confirm_timeout_seconds)
                                    .map_err(apply_error_to_owned_gnmi_set_error)?;
                            self_
                                .reset_rollback_duration_locked(
                                    confirm_id,
                                    confirm_timeout_seconds,
                                    &progress,
                                )
                                .await
                                .map_err(apply_error_to_owned_gnmi_set_error)?;
                            return Ok(GnmiSetOutcome::default());
                        }
                        Some(GnmiSetCommitAction::Commit { .. }) => {
                            self_
                                .reject_if_pending("gnmi.gNMI/Set")
                                .await
                                .map_err(apply_error_to_owned_gnmi_set_error)?;
                            // A confirmed gNMI candidate is derived from the live
                            // config. The ordinary planner must still fence external
                            // declarations after constructing the full snapshot.
                        }
                        None => {
                            self_
                                .reject_if_pending("gnmi.gNMI/Set")
                                .await
                                .map_err(apply_error_to_owned_gnmi_set_error)?;
                        }
                    }
                    let current = self_.accepted_runtime_snapshot().await.map_err(|error| {
                        OwnedGnmiSetError::Clean(GnmiSetError::Unavailable(error))
                    })?;
                    let mut candidate =
                        gnmi_set_bridge::apply_transaction_to_config(current, &transaction)
                            .map_err(OwnedGnmiSetError::Clean)?;
                    let candidate_toml = crate::config::raw_config_document_bounded(&mut candidate)
                        .map_err(|error| {
                            GnmiSetError::Internal(format!(
                                "failed to serialize gNMI Set candidate config: {error}"
                            ))
                        })?;
                    let (confirm_id, confirm_timeout_seconds) = match transaction.commit_action {
                        Some(GnmiSetCommitAction::Commit {
                            confirm_id,
                            confirm_timeout_seconds,
                        }) => (confirm_id, confirm_timeout_seconds),
                        Some(
                            GnmiSetCommitAction::Confirm { .. }
                            | GnmiSetCommitAction::Cancel { .. }
                            | GnmiSetCommitAction::SetRollbackDuration { .. },
                        ) => unreachable!(
                            "commit-control actions handled before candidate generation"
                        ),
                        None => (String::new(), 0),
                    };
                    let request = proto::ApplyConfigTransactionRequest {
                        candidate_toml,
                        expected_runtime_snapshot_token: String::new(),
                        client_request_id: "gnmi-set".to_string(),
                        comment: String::new(),
                        confirm_id,
                        confirm_timeout_seconds,
                    };
                    let confirmed = parse_confirmed_apply_mode(&request)
                        .map_err(apply_error_to_owned_gnmi_set_error)?;
                    let response = if confirmed.is_some() {
                        self_
                            .apply_locked(request, confirmed, &progress)
                            .await
                            .map_err(apply_error_to_owned_gnmi_set_error)?
                    } else {
                        // The coordinator lock serializes this internal gNMI Set path,
                        // and the candidate was just built from the live runtime
                        // snapshot. Let the shared apply executor do the single
                        // authoritative plan.
                        let peer_mgr_internal_tx =
                            self_.peer_mgr_internal_tx.as_ref().ok_or_else(|| {
                                OwnedGnmiSetError::Clean(GnmiSetError::Unavailable(
                                    "typed config transaction staging is unavailable".to_string(),
                                ))
                            })?;
                        apply_config_transaction_locked(
                            &self_.deps,
                            request,
                            Some(peer_mgr_internal_tx),
                            &progress,
                        )
                        .await
                        .map_err(|failure| match failure.fence_reason {
                            Some(reason) => OwnedGnmiSetError::Fenced {
                                message: failure.error.to_string(),
                                reason,
                            },
                            None => OwnedGnmiSetError::Clean(apply_error_to_gnmi_set_error(
                                failure.error,
                            )),
                        })?
                    };
                    gnmi_set_outcome_from_apply_response(response).map_err(OwnedGnmiSetError::Clean)
                },
            )
            .await;
        match result {
            Ok(outcome) => Ok(outcome),
            Err(OwnedGnmiSetError::Clean(error)) => Err(error),
            Err(OwnedGnmiSetError::Fenced { message, .. }) => {
                let _ = message;
                std::future::pending().await
            }
        }
    }

    async fn apply_locked(
        &self,
        request: proto::ApplyConfigTransactionRequest,
        confirmed: Option<ConfirmedApplyMode>,
        progress: &RuntimeConfigMutationProgress,
    ) -> Result<proto::ConfigTransactionApplyResponse, ConfigTransactionApplyError> {
        if let Some(confirmed) = confirmed {
            self.begin_confirmed_apply(&confirmed.confirm_id).await?;
            let result = self
                .apply_confirmed_locked(request, confirmed.clone(), None, progress)
                .await;
            if !matches!(
                result,
                Ok(proto::ConfigTransactionApplyResponse {
                    confirmation: Some(_),
                    ..
                })
            ) {
                self.clear_applying_confirm_id(&confirmed.confirm_id).await;
            }
            result
        } else {
            self.reject_if_pending("ConfigService.ApplyConfigTransaction")
                .await?;
            apply_config_transaction_locked(
                &self.deps,
                request,
                self.peer_mgr_internal_tx.as_ref(),
                progress,
            )
            .await
            .map_err(ApplyFailure::into_apply_error)
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "confirmed apply keeps one auditable publication-to-pending-state sequence"
    )]
    async fn apply_confirmed_locked(
        &self,
        request: proto::ApplyConfigTransactionRequest,
        confirmed: ConfirmedApplyMode,
        preloaded: Option<PlannedTransactionConfig>,
        progress: &RuntimeConfigMutationProgress,
    ) -> Result<proto::ConfigTransactionApplyResponse, ConfigTransactionApplyError> {
        let prior_snapshot = self
            .accepted_prior_snapshot()
            .await
            .map_err(ConfigTransactionApplyError::Unavailable)?;
        if let Some(launch) = &self.confirm_v3_launch {
            let prior_bytes = prior_snapshot.normalized_toml().len();
            if !launch.accepts_normalized_prior_length(prior_bytes) {
                return Err(ConfigTransactionApplyError::FailedPrecondition(format!(
                    "refusing confirmed apply: current accepted normalized config is {prior_bytes} bytes, exceeding the v3 commit-confirm prior limit of {} bytes; apply the candidate without confirmation or reduce the canonical config size",
                    launch.normalized_prior_limit_bytes()
                )));
            }
        }
        let rollback_config = prior_snapshot.config();

        // ADR-0113: a confirmed transaction may TIGHTEN an outbound prefix
        // maximum, because its automatic undo only loosens and a loosening is
        // always valid. A raise or removal is refused here — its undo is a
        // lowering that the capacity it just opened may already have
        // invalidated, and an undo that cannot apply is not an undo. Nothing
        // has committed yet, and the same edit is available as an ordinary
        // committed transaction.
        if confirmed_apply_loosens_outbound_limits(&rollback_config, &request.candidate_toml) {
            return Err(ConfigTransactionApplyError::FailedPrecondition(
                "confirmed transactions may only tighten max_prefixes_out_ipv4 / \
                 max_prefixes_out_ipv6: raising or removing one leaves an automatic undo \
                 that could become an invalid lowering. Apply the loosening change as an \
                 ordinary committed transaction instead"
                    .to_string(),
            ));
        }

        let timeout = Duration::from_secs(u64::from(confirmed.timeout_seconds));
        let authority_deadline_unix_seconds = SystemTime::now()
            .checked_add(timeout)
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |duration| duration.as_secs());

        // Durable commit-confirm (ADR-0076 Decision 6): journal the revert
        // state BEFORE the candidate commits, so a crash at any later point
        // inside the confirm window is repaired by the boot-time revert. If
        // the journal cannot be written, refuse the confirmed apply up front
        // (nothing has committed yet) rather than run an unprotected window.
        let v3_files = if let Some(launch) = &self.confirm_v3_launch {
            let pending_dir = self
                .deps
                .confirm_journal_path
                .as_ref()
                .and_then(|path| path.parent())
                .ok_or_else(|| {
                    ConfigTransactionApplyError::Internal(
                        "refusing confirmed apply: v3 pending storage is unavailable".to_string(),
                    )
                })?;
            progress.begin_settling();
            match launch.publish(
                pending_dir,
                &confirmed.confirm_id,
                authority_deadline_unix_seconds,
                &prior_snapshot,
            ) {
                Ok(files) => Some(Arc::new(files)),
                Err(error) => {
                    if error.authority_retained() {
                        self.state.lock().await.ambiguous_failure_confirm_id =
                            Some(confirmed.confirm_id.clone());
                    }
                    let message = format!(
                        "refusing confirmed apply: v3 pending authority publication failed ({:?}); {}",
                        error.kind(),
                        if error.authority_retained() {
                            "locator authority may be durable and config mutations are blocked until restart"
                        } else {
                            "the candidate and runtime remain untouched"
                        }
                    );
                    return Err(if error.authority_retained() {
                        ConfigTransactionApplyError::RecoveryRequired {
                            reason: RuntimeConfigFenceReason::PublicationAmbiguous,
                            message,
                        }
                    } else {
                        // ADR-0127: a publication failure before the locator
                        // rename retains no authority and precedes every
                        // runtime mutation — a determinate clean no-effect
                        // refusal, same as the NotPublished persistence
                        // mapping in persist_candidate_config, not an
                        // internal invariant breach.
                        ConfigTransactionApplyError::FailedPrecondition(message)
                    });
                }
            }
        } else {
            #[cfg(not(test))]
            return Err(ConfigTransactionApplyError::Unavailable(
                "v3 commit-confirm authority is unavailable".to_string(),
            ));
            #[cfg(test)]
            None
        };

        let mut response = match apply_config_transaction_locked_with_preloaded(
            &self.deps,
            request,
            preloaded,
            self.peer_mgr_internal_tx.as_ref(),
            progress,
        )
        .await
        {
            Ok(response) => response,
            Err(failure) => {
                if let Some(reason) = failure.fence_reason {
                    // LAN-277: the apply failed somewhere the daemon cannot
                    // prove the candidate left no trace (lost persistence
                    // acknowledgement, failed post-persist finalization, or
                    // failed compound rollback). Retain the pre-transaction
                    // journal — it is the only proven path back — and fence
                    // off every further config mutation so a later-accepted
                    // config cannot be clobbered by the retained journal's
                    // boot revert.
                    let mut state = self.state.lock().await;
                    state.ambiguous_failure_confirm_id = Some(confirmed.confirm_id.clone());
                    drop(state);
                    error!(
                        confirm_id = %confirmed.confirm_id,
                        error = %failure.error,
                        "confirmed config transaction failed with an ambiguous outcome; retaining the revert journal and blocking config mutations until restart"
                    );
                    return Err(ConfigTransactionApplyError::RecoveryRequired {
                        reason,
                        message: format!(
                            "{}; the transaction outcome is ambiguous; the commit-confirm revert journal is retained and config mutations are blocked; restart rustbgpd to boot-revert to the pre-transaction config",
                            failure.error
                        ),
                    });
                }
                // Provably nothing committed — a stale journal would only
                // trigger a harmless same-content boot revert, but clean it
                // up anyway.
                progress.begin_settling();
                self.cleanup_uncommitted_authority(
                    &confirmed.confirm_id,
                    v3_files.as_deref(),
                    "confirmed apply failed",
                )
                .await?;
                return Err(failure.error);
            }
        };
        if response.status != proto::ConfigTransactionPlanStatus::Committable as i32 {
            progress.begin_settling();
            self.cleanup_uncommitted_authority(
                &confirmed.confirm_id,
                v3_files.as_deref(),
                "confirmed apply did not commit",
            )
            .await?;
            return Ok(response);
        }

        // The durable authority must predate mutation, but its timestamp is
        // informational: boot recovery is unconditional. Start the live and
        // public confirmation window only after the candidate has committed.
        let deadline = tokio::time::Instant::now() + timeout;
        let deadline_unix_seconds = SystemTime::now()
            .checked_add(timeout)
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |duration| duration.as_secs());
        let pending = PendingConfirmedTransaction {
            confirm_id: confirmed.confirm_id.clone(),
            rollback_expected_runtime_snapshot_token: response.runtime_snapshot_token.clone(),
            timeout_seconds: confirmed.timeout_seconds,
            deadline,
            deadline_unix_seconds,
            committed_sections: response.committed_sections.clone(),
            runtime_snapshot_token: response.runtime_snapshot_token.clone(),
            rollback_failed: None,
            prior_snapshot,
            v3_files,
        };
        let confirmation = pending_confirmation_proto(
            &pending,
            "Confirmed config transaction is pending confirmation.",
        );
        progress.begin_settling();
        self.install_pending_confirmed_transaction(pending).await;
        self.spawn_confirm_timeout(confirmed.confirm_id).await;
        response.confirmation = Some(confirmation);
        response.human_text.push_str(
            "Confirmed transaction pending; call ConfirmConfigTransaction before the timeout or it will be rolled back.\n",
        );
        Ok(response)
    }

    #[cfg(test)]
    async fn confirm(
        self,
        request: proto::ConfirmConfigTransactionRequest,
    ) -> Result<proto::ConfirmConfigTransactionResponse, ConfigTransactionApplyError> {
        let (context, _attachment) = OwnedRuntimeConfigRequestContext::unary();
        self.confirm_with_context(request, context).await
    }

    async fn confirm_with_context(
        self,
        request: proto::ConfirmConfigTransactionRequest,
        context: OwnedRuntimeConfigRequestContext,
    ) -> Result<proto::ConfirmConfigTransactionResponse, ConfigTransactionApplyError> {
        let confirm_id = validate_confirm_id(&request.confirm_id)?;
        self.execute_owned_operation(
            RuntimeConfigOperationKind::Confirm,
            context,
            "config transaction confirm rejected: daemon is shutting down",
            "config transaction confirm task did not complete",
            move |controller, operation| async move {
                let progress = RuntimeConfigMutationProgress(operation);
                controller.confirm_locked(confirm_id, &progress).await
            },
        )
        .await
    }

    async fn confirm_locked(
        &self,
        confirm_id: String,
        progress: &RuntimeConfigMutationProgress,
    ) -> Result<proto::ConfirmConfigTransactionResponse, ConfigTransactionApplyError> {
        // Validate the handle against the pending transaction before touching
        // the journal, then delete the journal BEFORE clearing the pending
        // state: if deletion fails the confirm must fail while the fence and
        // timer stay armed — a leftover journal would boot-revert a config
        // the operator explicitly confirmed.
        let matched = self.matching_pending(&confirm_id).await?;
        progress.begin_settling();
        let residue_cleanup = if let Some(files) = &matched.v3_files {
            files.remove_locator_authority().map_err(|error| {
                ConfigTransactionApplyError::RecoveryRequired {
                    reason: RuntimeConfigFenceReason::PublicationAmbiguous,
                    message: format!(
                        "confirm not recorded: durable v3 locator removal failed ({:?}); the transaction is still pending and will roll back on timeout",
                        error.kind()
                    ),
                }
            })?;
            self.claim_v3(files, "confirmed transaction")
        } else {
            None
        };
        let pending = self.take_matching_pending(&confirm_id).await?;
        let record = ConfirmedTransactionRecord {
            confirm_id: pending.confirm_id,
            status: proto::ConfigTransactionConfirmationStatus::Confirmed,
            timeout_seconds: pending.timeout_seconds,
            deadline_unix_seconds: pending.deadline_unix_seconds,
            committed_sections: pending.committed_sections,
            runtime_snapshot_token: pending.runtime_snapshot_token,
            human_text: "Confirmed config transaction committed permanently.".to_string(),
        };
        let confirmation = record_confirmation_proto(&record);
        self.set_last_record(record).await;
        self.hand_off_v3(residue_cleanup, "confirmed transaction");
        self.metrics
            .record_config_transaction_lifecycle("confirm", "success");
        Ok(proto::ConfirmConfigTransactionResponse {
            confirmation: Some(confirmation),
            human_text: "Confirmed config transaction committed permanently.\n".to_string(),
        })
    }

    #[cfg(test)]
    async fn abort(
        self,
        request: proto::AbortConfigTransactionRequest,
    ) -> Result<proto::AbortConfigTransactionResponse, ConfigTransactionApplyError> {
        let (context, _attachment) = OwnedRuntimeConfigRequestContext::unary();
        self.abort_with_context(request, context).await
    }

    async fn abort_with_context(
        self,
        request: proto::AbortConfigTransactionRequest,
        context: OwnedRuntimeConfigRequestContext,
    ) -> Result<proto::AbortConfigTransactionResponse, ConfigTransactionApplyError> {
        let confirm_id = validate_confirm_id(&request.confirm_id)?;
        self.execute_owned_operation(
            RuntimeConfigOperationKind::Abort,
            context,
            "config transaction abort rejected: daemon is shutting down",
            "config transaction abort task did not complete",
            move |controller, operation| async move {
                let progress = RuntimeConfigMutationProgress(operation);
                controller.abort_locked(confirm_id, &progress).await
            },
        )
        .await
    }

    async fn abort_locked(
        &self,
        confirm_id: String,
        progress: &RuntimeConfigMutationProgress,
    ) -> Result<proto::AbortConfigTransactionResponse, ConfigTransactionApplyError> {
        let pending = self.matching_pending(&confirm_id).await?;
        progress.begin_settling();
        match self.rollback_pending_locked(&pending, progress).await {
            Ok(response) => {
                self.remove_pending_after_rollback(
                        &confirm_id,
                        proto::ConfigTransactionConfirmationStatus::Aborted,
                        response.runtime_snapshot_token.clone(),
                        "Aborted confirmed config transaction and restored the previous runtime config.",
                        true,
                    )
                    .await?;
                self.metrics
                    .record_config_transaction_lifecycle("abort", "success");
                Ok(proto::AbortConfigTransactionResponse {
                    confirmation: self.last_confirmation().await,
                    runtime_snapshot_token: response.runtime_snapshot_token,
                    human_text:
                        "Aborted confirmed config transaction and restored the previous runtime config.\n"
                            .to_string(),
                })
            }
            Err(error) => {
                // LAN-277: a failed rollback is NOT a terminal outcome — the
                // unconfirmed candidate is still running and the journal still
                // holds the only proven way back. Keep the transaction
                // pending: the mutation fence stays closed, the confirm timer
                // stays armed (the timeout auto-revert retries the rollback),
                // and the operator can retry abort, confirm to accept the
                // candidate, or restart to boot-revert from the journal.
                self.mark_pending_rollback_failed(
                    &confirm_id,
                    proto::ConfigTransactionConfirmationStatus::AbortFailed,
                )
                .await;
                self.metrics
                    .record_config_transaction_lifecycle("abort", "failure");
                Err(confirm_abort_rollback_error(&confirm_id, &error))
            }
        }
    }

    async fn reset_rollback_duration_locked(
        &self,
        confirm_id: String,
        timeout_seconds: u32,
        progress: &RuntimeConfigMutationProgress,
    ) -> Result<(), ConfigTransactionApplyError> {
        // The revert journal is NOT rewritten here: its deadline field is
        // informational only — boot revert fires on any unconfirmed journal
        // regardless of remaining time (see `confirm_journal` module docs).
        let timeout = Duration::from_secs(u64::from(timeout_seconds));
        let deadline = tokio::time::Instant::now() + timeout;
        let deadline_unix_seconds = SystemTime::now()
            .checked_add(timeout)
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |duration| duration.as_secs());
        {
            let mut state = self.state.lock().await;
            let Some(pending) = state.pending.as_mut() else {
                return Err(ConfigTransactionApplyError::FailedPrecondition(
                    "no confirmed config transaction is pending".to_string(),
                ));
            };
            if pending.confirm_id != confirm_id {
                return Err(ConfigTransactionApplyError::FailedPrecondition(format!(
                    "confirmed config transaction id mismatch: pending {:?}",
                    pending.confirm_id
                )));
            }
            progress.begin_settling();
            pending.timeout_seconds = timeout_seconds;
            pending.deadline = deadline;
            pending.deadline_unix_seconds = deadline_unix_seconds;
        }
        self.spawn_confirm_timeout(confirm_id).await;
        Ok(())
    }

    async fn status(
        &self,
    ) -> Result<proto::ConfigTransactionStatusResponse, ConfigTransactionApplyError> {
        let state = self.state.lock().await;
        if let Some(pending) = &state.pending {
            if let Some(status) = pending.rollback_failed {
                let human_text = if status
                    == proto::ConfigTransactionConfirmationStatus::AbortFailed
                {
                    "Abort rollback failed; the transaction is still pending: retry abort, confirm, or restart to boot-revert from the retained journal."
                } else {
                    "Automatic rollback failed; the transaction is still pending: retry abort, confirm, or restart to boot-revert from the retained journal."
                };
                let mut confirmation = pending_confirmation_proto(pending, human_text);
                confirmation.status = status.into();
                return Ok(proto::ConfigTransactionStatusResponse {
                    confirmation: Some(confirmation),
                    human_text: format!("{human_text}\n"),
                });
            }
            return Ok(proto::ConfigTransactionStatusResponse {
                confirmation: Some(pending_confirmation_proto(
                    pending,
                    "Confirmed config transaction is awaiting confirmation.",
                )),
                human_text: "Confirmed config transaction is awaiting confirmation.\n".to_string(),
            });
        }
        if let Some(confirm_id) = &state.ambiguous_failure_confirm_id {
            let human_text = format!(
                "Confirmed config transaction {confirm_id:?} failed with an ambiguous outcome; \
                 config mutations are blocked and the revert journal is retained. Restart \
                 rustbgpd to boot-revert to the pre-transaction config."
            );
            return Ok(proto::ConfigTransactionStatusResponse {
                confirmation: Some(proto::ConfigTransactionConfirmation {
                    status: proto::ConfigTransactionConfirmationStatus::None.into(),
                    confirm_id: confirm_id.clone(),
                    timeout_seconds: 0,
                    deadline_unix_seconds: 0,
                    committed_sections: Vec::new(),
                    runtime_snapshot_token: String::new(),
                    human_text: human_text.clone(),
                }),
                human_text: format!("{human_text}\n"),
            });
        }
        if let Some(confirm_id) = &state.applying_confirm_id {
            return Ok(proto::ConfigTransactionStatusResponse {
                confirmation: Some(proto::ConfigTransactionConfirmation {
                    status: proto::ConfigTransactionConfirmationStatus::Pending.into(),
                    confirm_id: confirm_id.clone(),
                    timeout_seconds: 0,
                    deadline_unix_seconds: 0,
                    committed_sections: Vec::new(),
                    runtime_snapshot_token: String::new(),
                    human_text: "Confirmed config transaction is applying.".to_string(),
                }),
                human_text: "Confirmed config transaction is applying.\n".to_string(),
            });
        }
        if let Some(record) = &state.last {
            return Ok(proto::ConfigTransactionStatusResponse {
                confirmation: Some(record_confirmation_proto(record)),
                human_text: format!("{}\n", record.human_text),
            });
        }
        Ok(proto::ConfigTransactionStatusResponse {
            confirmation: Some(proto::ConfigTransactionConfirmation {
                status: proto::ConfigTransactionConfirmationStatus::None.into(),
                confirm_id: String::new(),
                timeout_seconds: 0,
                deadline_unix_seconds: 0,
                committed_sections: Vec::new(),
                runtime_snapshot_token: String::new(),
                human_text: "No confirmed config transaction is pending.".to_string(),
            }),
            human_text: "No confirmed config transaction is pending.\n".to_string(),
        })
    }

    fn history(&self) -> Result<proto::ListConfigHistoryResponse, ConfigTransactionApplyError> {
        let dir = self.history_dir()?;
        let entries = crate::config_history::list_mixed(dir).map_err(|error| {
            warn!(
                error_kind = ?error.kind(),
                "failed to list config history"
            );
            ConfigTransactionApplyError::Internal(
                "config history storage is unavailable or unsafe; inspect daemon logs".to_string(),
            )
        })?;
        let mut proto_entries = Vec::with_capacity(entries.len());
        for entry in &entries {
            // The pinned v2 scan derives each redacted summary from the
            // same decoded object as its status and digests.
            let provenance_status = match entry.status {
                crate::config_history::HistoryStatus::Recorded => {
                    proto::ConfigHistoryProvenanceStatus::Recorded
                }
                crate::config_history::HistoryStatus::Unreadable => {
                    proto::ConfigHistoryProvenanceStatus::Unreadable
                }
            };
            proto_entries.push(proto::ConfigHistoryEntry {
                index: u32::try_from(entry.index).unwrap_or(u32::MAX),
                timestamp_unix_seconds: entry.timestamp_unix_seconds,
                sha256: entry.sha256.clone().unwrap_or_default(),
                summary: entry.summary.clone(),
                source_sha256: entry.source_sha256.clone().unwrap_or_default(),
                provenance_status: provenance_status.into(),
            });
        }
        let human_text = if proto_entries.is_empty() {
            "No config snapshots recorded yet.\n".to_string()
        } else {
            format!(
                "{} v2 config history row(s) retained; index 0 is newest. Provenance-verified rows can be restored with RollbackConfigTransaction (rbgp config rollback N); unreadable rows are refused.\n",
                proto_entries.len()
            )
        };
        Ok(proto::ListConfigHistoryResponse {
            entries: proto_entries,
            human_text,
        })
    }

    /// Junos-style `rollback N`: resolve history entry N and push it through
    /// the SAME apply path as `ApplyConfigTransaction` — `apply_locked` does
    /// the plan/impact classification, commit, receipts, and (when a confirm
    /// handle is given) the whole confirmed-commit lifecycle. There is
    /// deliberately no second apply route here.
    #[cfg(test)]
    async fn rollback(
        self,
        request: proto::RollbackConfigTransactionRequest,
    ) -> Result<proto::ConfigTransactionApplyResponse, ConfigTransactionApplyError> {
        let (context, _attachment) = OwnedRuntimeConfigRequestContext::unary();
        self.rollback_with_context(request, context).await
    }

    async fn rollback_with_context(
        self,
        request: proto::RollbackConfigTransactionRequest,
        context: OwnedRuntimeConfigRequestContext,
    ) -> Result<proto::ConfigTransactionApplyResponse, ConfigTransactionApplyError> {
        self.history_dir()?;
        if request.index == 0 {
            return Err(ConfigTransactionApplyError::InvalidArgument(
                "rollback index must be >= 1: index 0 is the newest config-history row".to_string(),
            ));
        }
        if request.confirm_id.is_empty() && request.confirm_timeout_seconds > 0 {
            return Err(ConfigTransactionApplyError::InvalidArgument(
                "confirm_id is required when confirm_timeout_seconds is set".to_string(),
            ));
        }
        self.execute_owned_operation(
            RuntimeConfigOperationKind::Rollback,
            context,
            "config rollback rejected: daemon is shutting down",
            "config rollback task did not complete",
            move |controller, operation| async move {
            let self_ = controller;
            let progress = RuntimeConfigMutationProgress(operation);
            // Resolve the entry under the coordinator lock so a concurrent
            // commit cannot shift indexes between resolution and apply.
            let dir = self_.history_dir()?;
            let index = usize::try_from(request.index).unwrap_or(usize::MAX);
            let entries = crate::config_history::list_mixed(dir).map_err(|_| {
                ConfigTransactionApplyError::FailedPrecondition(
                    "cannot roll back: config history storage is unavailable or unsafe".to_string(),
                )
            })?;
            let Some(entry) = entries.get(index) else {
                let noun = if entries.len() == 1 {
                    "entry"
                } else {
                    "entries"
                };
                return Err(ConfigTransactionApplyError::FailedPrecondition(format!(
                    "cannot roll back: config history has {} retained {noun}; index {index} is out of range",
                    entries.len(),
                )));
            };
            if entry.status == crate::config_history::HistoryStatus::Unreadable {
                return Err(ConfigTransactionApplyError::FailedPrecondition(
                    "cannot roll back an unreadable config history entry".to_string(),
                ));
            }
            let payload = crate::config_history::read_mixed_rollback(dir, entry).map_err(|_| {
                ConfigTransactionApplyError::FailedPrecondition(
                    "cannot roll back: config history entry became unavailable or unsafe"
                        .to_string(),
                )
            })?;
            let (candidate_toml, preloaded) =
                self_.prepare_rollback_payload(payload, &request).await?;
            let client_request_id = if request.client_request_id.is_empty() {
                format!("config-rollback:{index}")
            } else {
                request.client_request_id
            };
            let apply_request = proto::ApplyConfigTransactionRequest {
                candidate_toml,
                expected_runtime_snapshot_token: request.expected_runtime_snapshot_token,
                client_request_id,
                comment: request.comment,
                confirm_id: request.confirm_id,
                confirm_timeout_seconds: request.confirm_timeout_seconds,
            };
            let mut response = self_
                .apply_prepared_rollback(apply_request, preloaded, &progress)
                .await?;
            // Name the restored entry only when something actually committed;
            // a noop ("already running that config") or rejected plan keeps
            // the executor's own receipt text.
            if response.status == proto::ConfigTransactionPlanStatus::Committable as i32 {
                let _ = writeln!(
                    response.human_text,
                    "Rolled back to applied config {index} (recorded {}, sha256 {}).",
                    entry.timestamp_unix_seconds,
                    entry.sha256.as_deref().unwrap_or("unavailable")
                );
            }
            Ok(response)
            },
        )
        .await
    }

    fn history_dir(&self) -> Result<&std::path::Path, ConfigTransactionApplyError> {
        self.deps.config_history_dir.as_deref().ok_or_else(|| {
            ConfigTransactionApplyError::FailedPrecondition(
                "config history is unavailable: this daemon is running without an \
                 config-history directory"
                    .to_string(),
            )
        })
    }

    async fn begin_confirmed_apply(
        &self,
        confirm_id: &str,
    ) -> Result<(), ConfigTransactionApplyError> {
        let mut state = self.state.lock().await;
        if let Some(failed) = &state.ambiguous_failure_confirm_id {
            return Err(ambiguous_failure_fence_error(
                "ConfigService.ApplyConfigTransaction",
                failed,
            ));
        }
        if let Some(pending) = &state.pending {
            return Err(ConfigTransactionApplyError::FailedPrecondition(format!(
                "confirmed config transaction {:?} is already awaiting confirmation",
                pending.confirm_id
            )));
        }
        if let Some(active) = &state.applying_confirm_id {
            return Err(ConfigTransactionApplyError::FailedPrecondition(format!(
                "confirmed config transaction {active:?} is already applying"
            )));
        }
        state.applying_confirm_id = Some(confirm_id.to_string());
        Ok(())
    }

    async fn clear_applying_confirm_id(&self, confirm_id: &str) {
        let mut state = self.state.lock().await;
        if state.applying_confirm_id.as_deref() == Some(confirm_id) {
            state.applying_confirm_id = None;
        }
    }

    async fn install_pending_confirmed_transaction(&self, pending: PendingConfirmedTransaction) {
        let mut state = self.state.lock().await;
        if let Some(timer) = state.timer.take() {
            timer.abort();
        }
        if let Some(existing) = &state.pending {
            error!(
                existing_confirm_id = %existing.confirm_id,
                new_confirm_id = %pending.confirm_id,
                "replacing unexpected pending confirmed config transaction state"
            );
        }
        debug_assert!(
            state.pending.is_none(),
            "begin_confirmed_apply must prevent overlapping confirmed transactions"
        );
        state.applying_confirm_id = None;
        state.last = None;
        state.pending = Some(pending);
    }

    async fn spawn_confirm_timeout(&self, confirm_id: String) {
        let controller = self.clone();
        let task_confirm_id = confirm_id.clone();
        let handle = tokio::spawn(async move {
            let deadline = {
                let state = controller.state.lock().await;
                state
                    .pending
                    .as_ref()
                    .filter(|pending| pending.confirm_id == task_confirm_id)
                    .map(|pending| pending.deadline)
            };
            let Some(deadline) = deadline else {
                return;
            };
            tokio::time::sleep_until(deadline).await;
            if let Err(error) = controller.auto_revert(task_confirm_id.clone()).await {
                error!(
                    confirm_id = %task_confirm_id,
                    error = %error,
                    "confirmed config transaction auto-revert failed"
                );
            }
        });
        let mut state = self.state.lock().await;
        if state
            .pending
            .as_ref()
            .is_some_and(|pending| pending.confirm_id == confirm_id)
        {
            if let Some(previous) = state.timer.replace(handle) {
                previous.abort();
            }
        } else {
            handle.abort();
        }
    }

    async fn auto_revert(self, confirm_id: String) -> Result<(), ConfigTransactionApplyError> {
        self.execute_owned_operation(
            RuntimeConfigOperationKind::AutoRevert,
            OwnedRuntimeConfigRequestContext::detached(),
            "config transaction auto-revert rejected: daemon is shutting down",
            "config transaction auto-revert task did not complete",
            move |controller, operation| async move {
                let progress = RuntimeConfigMutationProgress(operation);
                let Some(pending) = controller.pending_for_timeout(&confirm_id).await else {
                    return Ok(());
                };
                if tokio::time::Instant::now() < pending.deadline {
                    return Ok(());
                }
                progress.begin_settling();
                match controller
                    .rollback_pending_locked(&pending, &progress)
                    .await
                {
                    Ok(response) => {
                        controller.remove_pending_after_rollback(
                        &confirm_id,
                        proto::ConfigTransactionConfirmationStatus::AutoReverted,
                        response.runtime_snapshot_token,
                        "Confirmed config transaction timed out and was automatically rolled back.",
                        false,
                    )
                    .await?;
                        controller
                            .metrics
                            .record_config_transaction_lifecycle("auto_revert", "success");
                        info!(confirm_id, "confirmed config transaction auto-reverted");
                        Ok(())
                    }
                    Err(error) => {
                        // LAN-277: keep the transaction pending on a failed
                        // auto-revert (fence closed, journal retained). The
                        // one-shot timer has already fired and is NOT re-armed —
                        // retrying in a loop against a persistently failing
                        // rollback would spin; the operator resolves it by
                        // retrying abort, confirming, resetting the rollback
                        // duration (which re-arms the timer), or restarting.
                        controller
                            .mark_pending_rollback_failed(
                                &confirm_id,
                                proto::ConfigTransactionConfirmationStatus::AutoRevertFailed,
                            )
                            .await;
                        controller
                            .metrics
                            .record_config_transaction_lifecycle("auto_revert", "failure");
                        Err(error)
                    }
                }
            },
        )
        .await
    }

    async fn matching_pending(
        &self,
        confirm_id: &str,
    ) -> Result<PendingConfirmedTransaction, ConfigTransactionApplyError> {
        let state = self.state.lock().await;
        let Some(pending) = &state.pending else {
            return Err(ConfigTransactionApplyError::FailedPrecondition(
                "no confirmed config transaction is pending".to_string(),
            ));
        };
        if pending.confirm_id != confirm_id {
            return Err(ConfigTransactionApplyError::FailedPrecondition(format!(
                "confirmed config transaction id mismatch: pending {:?}",
                pending.confirm_id
            )));
        }
        Ok(pending.clone())
    }

    async fn pending_for_timeout(&self, confirm_id: &str) -> Option<PendingConfirmedTransaction> {
        let state = self.state.lock().await;
        state
            .pending
            .as_ref()
            .filter(|pending| pending.confirm_id == confirm_id)
            .cloned()
    }

    async fn take_matching_pending(
        &self,
        confirm_id: &str,
    ) -> Result<PendingConfirmedTransaction, ConfigTransactionApplyError> {
        let mut state = self.state.lock().await;
        let Some(pending) = state.pending.take() else {
            return Err(ConfigTransactionApplyError::FailedPrecondition(
                "no confirmed config transaction is pending".to_string(),
            ));
        };
        if pending.confirm_id != confirm_id {
            let pending_id = pending.confirm_id.clone();
            state.pending = Some(pending);
            return Err(ConfigTransactionApplyError::FailedPrecondition(format!(
                "confirmed config transaction id mismatch: pending {pending_id:?}"
            )));
        }
        if let Some(timer) = state.timer.take() {
            timer.abort();
        }
        Ok(pending)
    }

    async fn rollback_pending_locked(
        &self,
        pending: &PendingConfirmedTransaction,
        progress: &RuntimeConfigMutationProgress,
    ) -> Result<proto::ConfigTransactionApplyResponse, ConfigTransactionApplyError> {
        let request = proto::ApplyConfigTransactionRequest {
            candidate_toml: pending.prior_snapshot.normalized_toml().to_string(),
            expected_runtime_snapshot_token: pending
                .rollback_expected_runtime_snapshot_token
                .clone(),
            client_request_id: format!("confirmed-rollback:{}", pending.confirm_id),
            comment: "confirmed transaction rollback".to_string(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        };
        let prior = &pending.prior_snapshot;
        let plan = self
            .plan_preloaded_snapshot(
                Arc::clone(prior),
                pending.rollback_expected_runtime_snapshot_token.clone(),
            )
            .await?;
        let peer_mgr_internal_tx = self.peer_mgr_internal_tx.as_ref().ok_or_else(|| {
            ConfigTransactionApplyError::Unavailable(
                "typed config transaction staging is unavailable".to_string(),
            )
        })?;
        let result = apply_config_transaction_locked_with_preloaded(
            &self.deps,
            request,
            Some(plan),
            Some(peer_mgr_internal_tx),
            progress,
        )
        .await;
        let response = result.map_err(ApplyFailure::into_apply_error)?;
        // A rollback whose re-apply plan did not commit leaves the
        // aborted/expired candidate running — that is a rollback failure,
        // not a success, and the caller must record AbortFailed /
        // AutoRevertFailed. Noop is genuine success (the runtime already
        // matches the rollback snapshot).
        match proto::ConfigTransactionPlanStatus::try_from(response.status) {
            Ok(
                proto::ConfigTransactionPlanStatus::Noop
                | proto::ConfigTransactionPlanStatus::Committable,
            ) => Ok(response),
            Ok(proto::ConfigTransactionPlanStatus::Rejected) => {
                Err(ConfigTransactionApplyError::FailedPrecondition(format!(
                    "confirmed-transaction rollback was rejected; the unconfirmed candidate is still running: {}",
                    response.human_text.trim()
                )))
            }
            Ok(proto::ConfigTransactionPlanStatus::Unspecified) | Err(_) => {
                Err(ConfigTransactionApplyError::Internal(format!(
                    "confirmed-transaction rollback returned unexpected plan status {}",
                    response.status
                )))
            }
        }
    }

    async fn cleanup_uncommitted_authority(
        &self,
        confirm_id: &str,
        files: Option<&crate::confirm_journal::v3::PendingFiles>,
        context: &'static str,
    ) -> Result<(), ConfigTransactionApplyError> {
        let Some(files) = files else {
            return Ok(());
        };
        match files.remove_locator_authority() {
            Ok(()) => {
                let cleanup = self.claim_v3(files, context);
                let mut state = self.state.lock().await;
                if state.applying_confirm_id.as_deref() == Some(confirm_id) {
                    state.applying_confirm_id = None;
                }
                drop(state);
                self.hand_off_v3(cleanup, context);
                Ok(())
            }
            Err(error) => {
                let mut state = self.state.lock().await;
                state.ambiguous_failure_confirm_id = Some(confirm_id.to_string());
                Err(ConfigTransactionApplyError::RecoveryRequired {
                    reason: RuntimeConfigFenceReason::PublicationAmbiguous,
                    message: format!(
                        "confirm outcome is ambiguous because durable v3 locator removal could not be proven ({:?}); config mutation admission is being fenced and the daemon will exit for supervised recovery",
                        error.kind()
                    ),
                })
            }
        }
    }

    /// Consume the pending transaction after a SUCCESSFUL abort/auto-revert
    /// rollback. The rollback re-persisted the pre-transaction config, so the
    /// journal is consumed. A FAILED rollback never reaches here — it keeps
    /// the transaction pending with the journal retained (see
    /// `mark_pending_rollback_failed`).
    async fn remove_pending_after_rollback(
        &self,
        confirm_id: &str,
        status: proto::ConfigTransactionConfirmationStatus,
        runtime_snapshot_token: String,
        human_text: &'static str,
        abort_timer: bool,
    ) -> Result<(), ConfigTransactionApplyError> {
        let matched = self.matching_pending(confirm_id).await?;
        let residue_cleanup = if let Some(files) = &matched.v3_files {
            files.remove_locator_authority().map_err(|error| {
                ConfigTransactionApplyError::RecoveryRequired {
                    reason: RuntimeConfigFenceReason::PublicationAmbiguous,
                    message: format!(
                        "rollback restored the prior config but remains nonterminal because durable v3 locator removal failed ({:?})",
                        error.kind()
                    ),
                }
            })?;
            self.claim_v3(files, "confirmed rollback")
        } else {
            None
        };
        let mut state = self.state.lock().await;
        let Some(pending) = state.pending.take() else {
            return Ok(());
        };
        if pending.confirm_id != confirm_id {
            state.pending = Some(pending);
            return Ok(());
        }
        let timer = state.timer.take();
        if abort_timer && let Some(timer) = timer {
            timer.abort();
        }
        state.last = Some(ConfirmedTransactionRecord {
            confirm_id: pending.confirm_id,
            status,
            timeout_seconds: pending.timeout_seconds,
            deadline_unix_seconds: pending.deadline_unix_seconds,
            committed_sections: pending.committed_sections,
            runtime_snapshot_token,
            human_text: human_text.to_string(),
        });
        drop(state);
        self.hand_off_v3(residue_cleanup, "confirmed rollback");
        Ok(())
    }

    fn claim_v3(
        &self,
        files: &crate::confirm_journal::v3::PendingFiles,
        context: &'static str,
    ) -> Option<V3Handoff> {
        let active = Arc::clone(&self.v3_residue_cleanup_active);
        if active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            warn!(context, "v3 terminal residue cleanup is already active");
            return None;
        }
        let reservation = V3Reservation(active);
        let (cleanup, failed) = files.claim_terminal_residue();
        failed.then(|| warn!(context, "v3 terminal residue claim was incomplete"));
        cleanup.map(|cleanup| (cleanup, reservation))
    }

    fn hand_off_v3(&self, handoff: Option<V3Handoff>, context: &'static str) {
        let Some((cleanup, reservation)) = handoff else {
            return;
        };
        debug_assert!(self.v3_residue_cleanup_active.load(Ordering::Acquire));
        #[cfg(test)]
        if self
            .v3_residue_cleanup_spawn_fail
            .swap(false, Ordering::AcqRel)
        {
            warn!(context, "v3 residue cleanup could not start");
            return;
        }
        if let Err(error) = std::thread::Builder::new()
            .name("rustbgpd-v3-cleanup".to_string())
            .spawn(move || {
                let _reservation = reservation;
                if cleanup.cleanup() {
                    warn!(context, "v3 residue cleanup failed");
                }
            })
        {
            warn!(
                context,
                error_kind = ?error.kind(),
                "v3 locator is durably absent, but residue cleanup could not start"
            );
        }
    }

    /// LAN-277: record a FAILED abort/auto-revert rollback on the still-pending
    /// transaction. The pending entry (and with it the mutation fence and the
    /// on-disk revert journal) is deliberately NOT consumed — the daemon could
    /// not restore the pre-transaction state, so the transaction has not
    /// reached a terminal outcome.
    async fn mark_pending_rollback_failed(
        &self,
        confirm_id: &str,
        status: proto::ConfigTransactionConfirmationStatus,
    ) {
        let mut state = self.state.lock().await;
        if let Some(pending) = state.pending.as_mut()
            && pending.confirm_id == confirm_id
        {
            pending.rollback_failed = Some(status);
            // Persist the failure into the retained on-disk journal so a
            // later boot's revert diagnostics can say "a rollback already
            // failed; the pre-restart state was uncertain" instead of the
            // generic never-confirmed message. Best-effort: the journal
            // (with the proven rollback snapshot) is already on disk, and
            // failing to annotate it must not mask the rollback failure.
            if let Some(files) = &pending.v3_files
                && let Err(error) = files.record_rollback_failed()
            {
                warn!(
                    error_kind = ?error.kind(),
                    "failed to record rollback failure in the v3 commit-confirm metadata"
                );
            }
        }
    }

    async fn set_last_record(&self, record: ConfirmedTransactionRecord) {
        let mut state = self.state.lock().await;
        state.last = Some(record);
    }

    async fn last_confirmation(&self) -> Option<proto::ConfigTransactionConfirmation> {
        self.state
            .lock()
            .await
            .last
            .as_ref()
            .map(record_confirmation_proto)
    }
}

type V3Handoff = (
    crate::confirm_journal::v3::TerminalResidueCleanup,
    V3Reservation,
);

struct V3Reservation(Arc<AtomicBool>);

impl Drop for V3Reservation {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Internal apply-pipeline failure carrying an exact recovery classification.
///
/// `fence_reason == None` means the daemon can prove nothing of the candidate
/// survives: the config file was never replaced and every live mutation was
/// rolled back, so the pre-transaction revert journal is redundant and may be
/// removed. A reason marks a window that must retain ownership:
///
/// - **(a) post-persist finalization failure** — the candidate is already
///   durable on disk when a later step (`commit_config_snapshot_stage`) fails;
/// - **(b) persistence-acknowledgement loss** — the persister's reply channel
///   dropped, so the config file may or may not now hold the candidate;
/// - **(c) compound rollback failure** — the rollback of live/staged state
///   itself failed, leaving the runtime part-candidate.
///
/// Public API surfaces strip this to the inner error; only the confirmed-apply
/// path inspects the flag (journal retention + mutation fence).
#[derive(Debug)]
struct ApplyFailure {
    error: ConfigTransactionApplyError,
    fence_reason: Option<RuntimeConfigFenceReason>,
}

impl ApplyFailure {
    fn fenced(error: ConfigTransactionApplyError, fence_reason: RuntimeConfigFenceReason) -> Self {
        Self {
            error,
            fence_reason: Some(fence_reason),
        }
    }

    fn into_apply_error(self) -> ConfigTransactionApplyError {
        match self.fence_reason {
            Some(reason) => ConfigTransactionApplyError::RecoveryRequired {
                reason,
                message: self.error.to_string(),
            },
            None => self.error,
        }
    }
}

impl From<ConfigTransactionApplyError> for ApplyFailure {
    fn from(error: ConfigTransactionApplyError) -> Self {
        let fence_reason = match &error {
            ConfigTransactionApplyError::RecoveryRequired { reason, .. } => Some(*reason),
            _ => None,
        };
        Self {
            error,
            fence_reason,
        }
    }
}

/// The LAN-277 mutation-fence rejection for the wedged (ambiguous confirmed
/// apply failure) state.
fn ambiguous_failure_fence_error(operation: &str, confirm_id: &str) -> ConfigTransactionApplyError {
    ConfigTransactionApplyError::FailedPrecondition(format!(
        "{operation} is blocked: confirmed config transaction {confirm_id:?} failed with an \
         ambiguous outcome and its revert journal is retained; restart rustbgpd to boot-revert \
         to the pre-transaction config before further config mutations"
    ))
}

fn validate_apply_request(
    request: &proto::ApplyConfigTransactionRequest,
) -> Result<(), ConfigTransactionApplyError> {
    rustbgpd_api::server::validate_config_transaction_apply_metadata(request)
}

fn parse_confirmed_apply_mode(
    request: &proto::ApplyConfigTransactionRequest,
) -> Result<Option<ConfirmedApplyMode>, ConfigTransactionApplyError> {
    if request.confirm_id.is_empty() {
        return Ok(None);
    }
    let confirm_id = validate_confirm_id(&request.confirm_id)?;
    let timeout_seconds = if request.confirm_timeout_seconds == 0 {
        DEFAULT_CONFIRM_TIMEOUT_SECONDS
    } else {
        request.confirm_timeout_seconds
    };
    let timeout_seconds = validate_confirm_timeout_seconds(timeout_seconds)?;
    Ok(Some(ConfirmedApplyMode {
        confirm_id,
        timeout_seconds,
    }))
}

fn validate_confirm_timeout_seconds(
    timeout_seconds: u32,
) -> Result<u32, ConfigTransactionApplyError> {
    if timeout_seconds == 0 {
        return Err(ConfigTransactionApplyError::InvalidArgument(
            "confirm_timeout_seconds must be positive".to_string(),
        ));
    }
    if timeout_seconds > MAX_CONFIRM_TIMEOUT_SECONDS {
        return Err(ConfigTransactionApplyError::InvalidArgument(format!(
            "confirm_timeout_seconds must be <= {MAX_CONFIRM_TIMEOUT_SECONDS}"
        )));
    }
    Ok(timeout_seconds)
}

fn validate_confirm_id(confirm_id: &str) -> Result<String, ConfigTransactionApplyError> {
    if confirm_id.trim().is_empty() {
        return Err(ConfigTransactionApplyError::InvalidArgument(
            "confirm_id is required".to_string(),
        ));
    }
    if confirm_id.chars().count() > MAX_CONFIRM_ID_CHARS {
        return Err(ConfigTransactionApplyError::InvalidArgument(format!(
            "confirm_id must be at most {MAX_CONFIRM_ID_CHARS} characters"
        )));
    }
    if confirm_id.chars().any(char::is_control) {
        return Err(ConfigTransactionApplyError::InvalidArgument(
            "confirm_id must not contain control characters".to_string(),
        ));
    }
    Ok(confirm_id.to_string())
}

fn pending_confirmation_proto(
    pending: &PendingConfirmedTransaction,
    human_text: &str,
) -> proto::ConfigTransactionConfirmation {
    proto::ConfigTransactionConfirmation {
        status: proto::ConfigTransactionConfirmationStatus::Pending.into(),
        confirm_id: pending.confirm_id.clone(),
        timeout_seconds: pending.timeout_seconds,
        deadline_unix_seconds: pending.deadline_unix_seconds,
        committed_sections: pending.committed_sections.clone(),
        runtime_snapshot_token: pending.runtime_snapshot_token.clone(),
        human_text: human_text.to_string(),
    }
}

fn record_confirmation_proto(
    record: &ConfirmedTransactionRecord,
) -> proto::ConfigTransactionConfirmation {
    proto::ConfigTransactionConfirmation {
        status: record.status.into(),
        confirm_id: record.confirm_id.clone(),
        timeout_seconds: record.timeout_seconds,
        deadline_unix_seconds: record.deadline_unix_seconds,
        committed_sections: record.committed_sections.clone(),
        runtime_snapshot_token: record.runtime_snapshot_token.clone(),
        human_text: record.human_text.clone(),
    }
}

#[cfg(test)]
async fn apply_config_transaction(
    deps: Arc<FibTableControlDeps>,
    request: proto::ApplyConfigTransactionRequest,
) -> Result<proto::ConfigTransactionApplyResponse, ConfigTransactionApplyError> {
    validate_apply_request(&request)?;

    let join = tokio::spawn(async move {
        let _guard = deps.lock.acquire().await?;
        apply_config_transaction_locked(
            &deps,
            request,
            None,
            &RuntimeConfigMutationProgress::default(),
        )
        .await
        .map_err(ApplyFailure::into_apply_error)
    });

    join.await.map_err(|_| {
        ConfigTransactionApplyError::Internal(
            "config transaction apply task did not complete".to_string(),
        )
    })?
}

#[cfg(test)]
async fn apply_config_transaction_with_internal(
    deps: Arc<FibTableControlDeps>,
    request: proto::ApplyConfigTransactionRequest,
    peer_mgr_internal_tx: mpsc::Sender<InternalCommand>,
) -> Result<proto::ConfigTransactionApplyResponse, ConfigTransactionApplyError> {
    validate_apply_request(&request)?;
    let join = tokio::spawn(async move {
        let _guard = deps.lock.acquire().await?;
        apply_config_transaction_locked(
            &deps,
            request,
            Some(&peer_mgr_internal_tx),
            &RuntimeConfigMutationProgress::default(),
        )
        .await
        .map_err(ApplyFailure::into_apply_error)
    });
    join.await.map_err(|_| {
        ConfigTransactionApplyError::Internal(
            "config transaction apply task did not complete".to_string(),
        )
    })?
}

async fn apply_config_transaction_locked(
    deps: &FibTableControlDeps,
    request: proto::ApplyConfigTransactionRequest,
    peer_mgr_internal_tx: Option<&mpsc::Sender<InternalCommand>>,
    progress: &RuntimeConfigMutationProgress,
) -> Result<proto::ConfigTransactionApplyResponse, ApplyFailure> {
    apply_config_transaction_locked_with_preloaded(
        deps,
        request,
        None,
        peer_mgr_internal_tx,
        progress,
    )
    .await
}

#[expect(
    clippy::too_many_lines,
    reason = "planning, typed-candidate verification, and family dispatch share one transaction boundary"
)]
async fn apply_config_transaction_locked_with_preloaded(
    deps: &FibTableControlDeps,
    request: proto::ApplyConfigTransactionRequest,
    preloaded: Option<PlannedTransactionConfig>,
    peer_mgr_internal_tx: Option<&mpsc::Sender<InternalCommand>>,
    progress: &RuntimeConfigMutationProgress,
) -> Result<proto::ConfigTransactionApplyResponse, ApplyFailure> {
    let (plan, candidate, typed_plan) = if let Some(planned) = preloaded {
        (planned.plan, planned.candidate, true)
    } else {
        let candidate = Config::load_toml_with_diagnostics(
            &request.candidate_toml,
            "candidate runtime config transaction",
        )
        .map_err(ConfigTransactionApplyError::InvalidArgument)?;
        let plan = plan_candidate(
            &deps.peer_mgr_tx,
            request.candidate_toml.clone(),
            request.expected_runtime_snapshot_token.clone(),
        )
        .await?;
        (plan, Box::new(candidate), false)
    };

    match plan.status {
        RuntimeConfigTransactionStatus::Noop => {
            return Ok(proto::ConfigTransactionApplyResponse {
                status: proto::ConfigTransactionPlanStatus::Noop.into(),
                runtime_snapshot_token: plan.runtime_snapshot_token,
                committed_sections: Vec::new(),
                human_text: "No changes.\n".to_string(),
                confirmation: None,
                update_group_impact: Some(rustbgpd_api::update_group_impact_to_proto(
                    plan.update_group_impact,
                )),
            });
        }
        RuntimeConfigTransactionStatus::Rejected => {
            return Ok(rejected_response(plan.runtime_snapshot_token));
        }
        RuntimeConfigTransactionStatus::Committable => {}
    }

    let Some(family) = apply_family(&plan.supported_sections) else {
        return Ok(rejected_response(plan.runtime_snapshot_token));
    };

    let peer_mgr_internal_tx = peer_mgr_internal_tx.ok_or_else(|| {
        ConfigTransactionApplyError::Unavailable(
            "typed config transaction staging is unavailable".to_string(),
        )
    })?;

    let committed_candidate_toml = plan
        .committed_candidate
        .clone()
        .ok_or_else(|| {
            ConfigTransactionApplyError::Internal(
                "committable config transaction plan omitted its candidate".to_string(),
            )
        })?
        .into_inner();
    let candidate = if typed_plan {
        *candidate
    } else {
        let typed = plan_loaded_candidate(
            peer_mgr_internal_tx,
            candidate,
            request.expected_runtime_snapshot_token.clone(),
        )
        .await?;
        let typed_candidate = typed
            .plan
            .committed_candidate
            .as_ref()
            .map(rustbgpd_api::peer_types::RuntimeConfigTransactionCandidate::as_str);
        if typed_candidate != Some(committed_candidate_toml.as_str()) {
            return Err(ConfigTransactionApplyError::FailedPrecondition(
                "typed transaction candidate changed while it was being planned; retry against a fresh runtime snapshot"
                    .to_string(),
            )
            .into());
        }
        *typed.candidate
    };
    let config_tx = deps.config_tx.clone().ok_or_else(|| {
        ConfigTransactionApplyError::FailedPrecondition(
            "config transactions are unavailable: this daemon is running without config \
             persistence"
                .to_string(),
        )
    })?;
    // Post-commit token comes from the plan (computed under the peer-manager's
    // key); the apply path can't recompute a key-consistent token itself.
    let post_commit_runtime_snapshot_token = plan.post_commit_runtime_snapshot_token;
    let update_group_impact = rustbgpd_api::update_group_impact_to_proto(plan.update_group_impact);
    let authoritative_candidate =
        (family == ApplyFamily::LivePolicyImpact).then(|| Box::new(candidate.clone()));
    let mut response = commit_apply_family(
        deps,
        peer_mgr_internal_tx,
        &config_tx,
        family,
        committed_candidate_toml,
        candidate,
        plan.supported_sections,
        post_commit_runtime_snapshot_token,
        update_group_impact,
        progress,
    )
    .await?;
    if family == ApplyFamily::LivePolicyImpact {
        let authoritative = plan_loaded_candidate(
            peer_mgr_internal_tx,
            authoritative_candidate.expect("live policy candidate retained"),
            String::new(),
        )
        .await?;
        response.runtime_snapshot_token = authoritative.plan.runtime_snapshot_token;
    }
    Ok(response)
}

#[expect(
    clippy::too_many_arguments,
    reason = "the transaction executor carries candidate, receipt, and commit-token state"
)]
async fn commit_apply_family(
    deps: &FibTableControlDeps,
    peer_mgr_internal_tx: &mpsc::Sender<InternalCommand>,
    config_tx: &mpsc::Sender<ConfigEvent>,
    family: ApplyFamily,
    candidate_toml: String,
    candidate: Config,
    supported_sections: Vec<String>,
    post_commit_runtime_snapshot_token: String,
    update_group_impact: proto::UpdateGroupImpactPlan,
    progress: &RuntimeConfigMutationProgress,
) -> Result<proto::ConfigTransactionApplyResponse, ApplyFailure> {
    // ADR-0113 deliberately INVERTS ADR-0076's apply-live-before-persist
    // order for outbound prefix maxima. Applying a raise or removal first
    // would admit routes above the old maximum, and a later persistence
    // failure could not roll that back: the undo is a lowering whose
    // precondition (usage at or below the maximum) the newly admitted routes
    // may already have invalidated. So the candidate is preflighted into an
    // inactive prepared transaction here, the family commit below persists,
    // and activation follows the acknowledgement.
    let prepared = prepare_outbound_prefix_limit_transaction(deps, &candidate).await?;
    // Boxed: the family commit owns the whole candidate `Config` across its
    // awaits, and inlining it here would widen every enclosing transaction
    // future by that snapshot.
    let committed = Box::pin(commit_apply_family_inner(
        deps,
        peer_mgr_internal_tx,
        config_tx,
        family,
        candidate_toml,
        candidate,
        supported_sections,
        post_commit_runtime_snapshot_token,
        update_group_impact,
        progress,
    ))
    .await;
    finish_outbound_prefix_limit_transaction(deps, prepared, &committed).await?;
    committed
}

/// Whether a confirmed transaction's candidate would raise or remove an
/// outbound prefix maximum (ADR-0113). Kept out of the async body so the
/// parsed candidate never sits in the transaction future.
fn confirmed_apply_loosens_outbound_limits(rollback: &Config, candidate_toml: &str) -> bool {
    toml::from_str::<Config>(candidate_toml)
        .is_ok_and(|candidate| crate::config::outbound_prefix_limits_loosen(rollback, &candidate))
}

/// Preflight the candidate's outbound prefix maxima and hold them inactive.
///
/// `Ok(None)` when the RIB channel is absent (unit-test deps) or nothing is
/// prepared; the returned identity is what activation and discard address.
async fn prepare_outbound_prefix_limit_transaction(
    deps: &FibTableControlDeps,
    candidate: &Config,
) -> Result<Option<u64>, ApplyFailure> {
    let Some(rib_tx) = deps.rib_tx.as_ref() else {
        return Ok(None);
    };
    let txn = crate::reload::next_outbound_prefix_limit_txn();
    crate::reload::prepare_outbound_prefix_limits(rib_tx, txn, candidate)
        .await
        .map_err(|error| {
            ApplyFailure::from(ConfigTransactionApplyError::FailedPrecondition(error))
        })?;
    Ok(Some(txn))
}

/// Activate a prepared outbound prefix-limit transaction after the candidate
/// is durable, or discard it when the commit failed.
///
/// A post-persist activation failure is an ambiguous outcome, not a clean
/// no-commit failure: the candidate is on disk, so the confirm journal and
/// the config-mutation fence must be retained and the existing restart
/// boot-repair path takes over. There is deliberately no best-effort live
/// rollback whose lowering precondition may no longer hold.
async fn finish_outbound_prefix_limit_transaction(
    deps: &FibTableControlDeps,
    prepared: Option<u64>,
    committed: &Result<proto::ConfigTransactionApplyResponse, ApplyFailure>,
) -> Result<(), ApplyFailure> {
    let (Some(rib_tx), Some(txn)) = (deps.rib_tx.as_ref(), prepared) else {
        return Ok(());
    };
    let activate = committed.as_ref().is_ok_and(|response| {
        response.status == i32::from(proto::ConfigTransactionPlanStatus::Committable)
    });
    let outcome = crate::reload::finish_outbound_prefix_limits(rib_tx, txn, activate).await;
    match outcome {
        Err(error) if activate => Err(ApplyFailure::fenced(
            ConfigTransactionApplyError::Internal(format!(
                "persisted configuration was committed but its outbound prefix maxima could not be activated: {error}"
            )),
            RuntimeConfigFenceReason::KnownDivergence,
        )),
        // A discard cannot fail meaningfully: nothing was applied.
        Ok(()) | Err(_) => Ok(()),
    }
}

#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "family dispatch mirrors commit_apply_family's parameters verbatim"
)]
async fn commit_apply_family_inner(
    deps: &FibTableControlDeps,
    peer_mgr_internal_tx: &mpsc::Sender<InternalCommand>,
    config_tx: &mpsc::Sender<ConfigEvent>,
    family: ApplyFamily,
    candidate_toml: String,
    candidate: Config,
    supported_sections: Vec<String>,
    post_commit_runtime_snapshot_token: String,
    update_group_impact: proto::UpdateGroupImpactPlan,
    progress: &RuntimeConfigMutationProgress,
) -> Result<proto::ConfigTransactionApplyResponse, ApplyFailure> {
    match family {
        ApplyFamily::FibTables => {
            commit_fib_transaction(
                deps,
                peer_mgr_internal_tx,
                config_tx,
                candidate_toml,
                candidate,
                post_commit_runtime_snapshot_token,
                update_group_impact,
                progress,
            )
            .await
        }
        ApplyFamily::DynamicNeighbors => {
            commit_dynamic_neighbors_locked(
                &deps.peer_mgr_tx,
                peer_mgr_internal_tx,
                config_tx,
                candidate_toml,
                &candidate,
                progress,
            )
            .await?;
            Ok(committable_response(
                post_commit_runtime_snapshot_token,
                vec![DYNAMIC_SECTION.to_string()],
                format!(
                    "Committed [[dynamic_neighbors]] transaction.\n{} range(s) active.\n",
                    candidate.dynamic_neighbors.len()
                ),
                Some(update_group_impact),
            ))
        }
        ApplyFamily::CatalogSnapshot => {
            commit_candidate_snapshot_locked(
                &deps.peer_mgr_tx,
                peer_mgr_internal_tx,
                config_tx,
                candidate_toml,
                &candidate,
                progress,
            )
            .await?;
            Ok(committable_response(
                post_commit_runtime_snapshot_token,
                supported_sections,
                format!(
                    "Committed catalog-only runtime config transaction.\n{} policy definition(s), {} neighbor set(s), {} peer group(s) active.\n",
                    candidate.policy.definitions.len(),
                    candidate.policy.neighbor_sets.len(),
                    candidate.peer_groups.len(),
                ),
                Some(update_group_impact),
            ))
        }
        ApplyFamily::LivePolicyImpact => {
            let refreshed = commit_live_policy_impact_locked(
                &deps.peer_mgr_tx,
                peer_mgr_internal_tx,
                config_tx,
                candidate_toml,
                &candidate,
                progress,
            )
            .await?;
            Ok(committable_response(
                post_commit_runtime_snapshot_token,
                supported_sections,
                format!(
                    "Committed live policy-impact runtime config transaction.\n{refreshed} live session(s) re-evaluated under the new resolved policy.\n"
                ),
                Some(update_group_impact),
            ))
        }
        ApplyFamily::PeerSessionReshape => {
            let commit = commit_peer_session_reshape_locked(
                &deps.peer_mgr_tx,
                peer_mgr_internal_tx,
                config_tx,
                candidate_toml,
                &candidate,
                progress,
            )
            .await?;
            Ok(committable_response(
                post_commit_runtime_snapshot_token,
                supported_sections,
                peer_session_reshape_commit_message(&commit),
                Some(update_group_impact),
            ))
        }
        ApplyFamily::StaticNeighbors => {
            commit_static_neighbors_locked(
                &deps.peer_mgr_tx,
                peer_mgr_internal_tx,
                config_tx,
                candidate_toml,
                &candidate,
                &supported_sections,
                progress,
            )
            .await?;
            Ok(committable_response(
                post_commit_runtime_snapshot_token,
                supported_sections,
                "Committed [[neighbors]] add/delete/modify transaction.\n".to_string(),
                Some(update_group_impact),
            ))
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "FIB commit carries the typed settlement progress with its existing closed transaction inputs"
)]
async fn commit_fib_transaction(
    deps: &FibTableControlDeps,
    peer_mgr_internal_tx: &mpsc::Sender<InternalCommand>,
    config_tx: &mpsc::Sender<ConfigEvent>,
    candidate_toml: String,
    candidate: Config,
    post_commit_runtime_snapshot_token: String,
    update_group_impact: proto::UpdateGroupImpactPlan,
    progress: &RuntimeConfigMutationProgress,
) -> Result<proto::ConfigTransactionApplyResponse, ApplyFailure> {
    let fib_cmd_tx = deps.fib_cmd_tx.clone().ok_or_else(|| {
        fib_error_to_apply_error(runtime_unavailable_error(!deps.startup_tables.is_empty()))
    })?;
    let permit = reserve_persist_permit(config_tx).await?;
    let previous_tables = read_current_tables(
        Some(&fib_cmd_tx),
        rustbgpd_api::rib_service::FibTableControlError::Internal,
    )
    .await
    .map_err(fib_error_to_apply_error)?
    .unwrap_or_default();
    let staged_tables = candidate.fib_tables.clone();
    progress.begin_mutation();
    let rollback = stage_preloaded_config_snapshot(
        peer_mgr_internal_tx,
        Box::new(candidate.clone()),
        TransactionConfigScope::FibTablesOnly,
    )
    .await?;
    match replace_tables_for_transaction(&fib_cmd_tx, staged_tables.clone()).await {
        FibTransactionReplaceOutcome::Applied => {}
        FibTransactionReplaceOutcome::NotAccepted(error)
        | FibTransactionReplaceOutcome::RejectedNoEffect(error) => {
            progress.begin_settling();
            return Err(restore_preloaded_snapshot_after_error(
                peer_mgr_internal_tx,
                rollback,
                fib_error_to_apply_error(error).into(),
            )
            .await);
        }
        FibTransactionReplaceOutcome::KnownDivergence(error) => {
            return Err(ApplyFailure::fenced(
                fib_error_to_apply_error(error),
                RuntimeConfigFenceReason::KnownDivergence,
            ));
        }
        FibTransactionReplaceOutcome::AcknowledgementLost(error) => {
            return Err(ApplyFailure::fenced(
                fib_error_to_apply_error(error),
                RuntimeConfigFenceReason::AcknowledgementLost,
            ));
        }
    }
    progress.begin_settling();
    if let Err(failure) = persist_candidate_config(permit, candidate_toml).await {
        if failure.fence_reason.is_some() {
            return Err(failure);
        }
        return Err(rollback_fib_transaction_after_error(
            &fib_cmd_tx,
            peer_mgr_internal_tx,
            previous_tables,
            rollback,
            failure,
        )
        .await);
    }
    commit_config_snapshot_stage(&deps.peer_mgr_tx).await?;
    Ok(committable_response(
        post_commit_runtime_snapshot_token,
        vec![FIB_SECTION.to_string()],
        format!(
            "Committed [[fib_tables]] transaction.\n{} table(s) active.\n",
            staged_tables.len()
        ),
        Some(update_group_impact),
    ))
}

async fn stage_preloaded_config_snapshot(
    peer_mgr_internal_tx: &mpsc::Sender<InternalCommand>,
    candidate: Box<Config>,
    scope: TransactionConfigScope,
) -> Result<TransactionConfigRollbackToken, ApplyFailure> {
    let (reply_tx, reply_rx) = oneshot::channel();
    peer_mgr_internal_tx
        .send(InternalCommand::StageTransactionConfig {
            candidate,
            scope,
            reply: reply_tx,
        })
        .await
        .map_err(|_| {
            ConfigTransactionApplyError::Unavailable("peer manager is unavailable".to_string())
        })?;
    reply_rx
        .await
        .map_err(|_| {
            ApplyFailure::fenced(
                ConfigTransactionApplyError::Internal(
                    "peer manager accepted config transaction snapshot stage but dropped its reply"
                        .to_string(),
                ),
                RuntimeConfigFenceReason::AcknowledgementLost,
            )
        })?
        .map_err(|error| ConfigTransactionApplyError::InvalidArgument(error).into())
}

async fn restore_preloaded_config_snapshot(
    peer_mgr_internal_tx: &mpsc::Sender<InternalCommand>,
    rollback: TransactionConfigRollbackToken,
) -> Result<(), ConfigTransactionApplyError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    peer_mgr_internal_tx
        .send(InternalCommand::RestoreTransactionConfig {
            rollback,
            reply: reply_tx,
        })
        .await
        .map_err(|_| {
            ConfigTransactionApplyError::Unavailable(
                "peer manager is unavailable during config transaction rollback".to_string(),
            )
        })?;
    reply_rx
        .await
        .map_err(|_| ConfigTransactionApplyError::RecoveryRequired {
            reason: RuntimeConfigFenceReason::AcknowledgementLost,
            message: "peer manager accepted config snapshot rollback but dropped its reply"
                .to_string(),
        })
}

async fn restore_preloaded_snapshot_after_error(
    peer_mgr_internal_tx: &mpsc::Sender<InternalCommand>,
    rollback: TransactionConfigRollbackToken,
    original: ApplyFailure,
) -> ApplyFailure {
    if original.fence_reason.is_some() {
        return original;
    }
    match restore_preloaded_config_snapshot(peer_mgr_internal_tx, rollback).await {
        Ok(()) => original,
        Err(rollback) => ApplyFailure::fenced(
            ConfigTransactionApplyError::Internal(format!(
                "{}; config snapshot rollback failed: {rollback}",
                original.error
            )),
            recovery_reason(&rollback),
        ),
    }
}

async fn rollback_fib_transaction_after_error(
    fib_cmd_tx: &mpsc::Sender<crate::fib_runtime::FibRuntimeCommand>,
    peer_mgr_internal_tx: &mpsc::Sender<InternalCommand>,
    previous_tables: Vec<crate::config::FibTableConfig>,
    rollback: TransactionConfigRollbackToken,
    original: ApplyFailure,
) -> ApplyFailure {
    if original.fence_reason.is_some() {
        return original;
    }
    match replace_tables_for_transaction(fib_cmd_tx, previous_tables).await {
        FibTransactionReplaceOutcome::Applied => {
            match restore_preloaded_config_snapshot(peer_mgr_internal_tx, rollback).await {
                Ok(()) => original,
                Err(rollback) => ApplyFailure::fenced(
                    ConfigTransactionApplyError::Internal(format!(
                        "{}; config snapshot rollback failed: {rollback}",
                        original.error
                    )),
                    recovery_reason(&rollback),
                ),
            }
        }
        FibTransactionReplaceOutcome::AcknowledgementLost(error) => ApplyFailure::fenced(
            fib_error_to_apply_error(error),
            RuntimeConfigFenceReason::AcknowledgementLost,
        ),
        FibTransactionReplaceOutcome::NotAccepted(error)
        | FibTransactionReplaceOutcome::RejectedNoEffect(error)
        | FibTransactionReplaceOutcome::KnownDivergence(error) => ApplyFailure::fenced(
            fib_error_to_apply_error(error),
            RuntimeConfigFenceReason::KnownDivergence,
        ),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApplyFamily {
    FibTables,
    DynamicNeighbors,
    CatalogSnapshot,
    LivePolicyImpact,
    PeerSessionReshape,
    StaticNeighbors,
}

fn apply_family(sections: &[String]) -> Option<ApplyFamily> {
    match sections {
        [section] if section == FIB_SECTION => Some(ApplyFamily::FibTables),
        [section] if section == DYNAMIC_SECTION => Some(ApplyFamily::DynamicNeighbors),
        // A live-impact transaction carries the `[policy] live impact` marker
        // alongside the catalog record section(s) it stems from. It supersedes
        // the catalog executor: catalog-only stages a snapshot, but a live
        // impact must also re-apply resolved chains to the affected sessions.
        sections
            if sections.iter().any(|s| s == POLICY_LIVE_IMPACT_SECTION)
                && sections.iter().all(|s| {
                    s == POLICY_LIVE_IMPACT_SECTION
                        || s == PEER_GROUP_CATALOG_SECTION
                        || s == POLICY_DEFINITIONS_SECTION
                        || s == POLICY_NEIGHBOR_SETS_SECTION
                        || s == POLICY_GLOBAL_CHAINS_SECTION
                }) =>
        {
            Some(ApplyFamily::LivePolicyImpact)
        }
        sections
            if sections.iter().any(|s| s == SESSION_RESHAPE_SECTION)
                && sections.iter().all(|s| {
                    s == SESSION_RESHAPE_SECTION
                        || s == PEER_GROUP_CATALOG_SECTION
                        || s == POLICY_DEFINITIONS_SECTION
                        || s == POLICY_NEIGHBOR_SETS_SECTION
                        || s == POLICY_GLOBAL_CHAINS_SECTION
                        || s == NEIGHBOR_MODIFY_SECTION
                }) =>
        {
            Some(ApplyFamily::PeerSessionReshape)
        }
        sections
            if !sections.is_empty()
                && sections.iter().all(|s| {
                    s == PEER_GROUP_CATALOG_SECTION
                        || s == POLICY_DEFINITIONS_SECTION
                        || s == POLICY_NEIGHBOR_SETS_SECTION
                        || s == POLICY_GLOBAL_CHAINS_SECTION
                }) =>
        {
            Some(ApplyFamily::CatalogSnapshot)
        }
        sections
            if !sections.is_empty()
                && sections.iter().all(|s| {
                    s == NEIGHBOR_ADD_SECTION
                        || s == NEIGHBOR_DELETE_SECTION
                        || s == NEIGHBOR_MODIFY_SECTION
                }) =>
        {
            Some(ApplyFamily::StaticNeighbors)
        }
        _ => None,
    }
}

async fn plan_loaded_candidate(
    peer_mgr_internal_tx: &mpsc::Sender<InternalCommand>,
    candidate: Box<Config>,
    expected_runtime_snapshot_token: String,
) -> Result<PlannedTransactionConfig, ConfigTransactionApplyError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    peer_mgr_internal_tx
        .send(InternalCommand::PlanTransactionConfig {
            candidate,
            expected_runtime_snapshot_token: Some(expected_runtime_snapshot_token),
            reply: reply_tx,
        })
        .await
        .map_err(|_| {
            ConfigTransactionApplyError::Unavailable("peer manager is unavailable".to_string())
        })?;
    reply_rx
        .await
        .map_err(|_| {
            ConfigTransactionApplyError::Unavailable(
                "peer manager dropped typed config transaction plan reply".to_string(),
            )
        })?
        .map_err(plan_error_to_status)
}

async fn plan_candidate(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    candidate_toml: String,
    expected_runtime_snapshot_token: String,
) -> Result<rustbgpd_api::peer_types::RuntimeConfigTransactionPlan, ConfigTransactionApplyError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    peer_mgr_tx
        .send(PeerManagerCommand::PlanConfigTransaction {
            candidate_toml,
            expected_runtime_snapshot_token: Some(expected_runtime_snapshot_token),
            reply: reply_tx,
        })
        .await
        .map_err(|_| {
            ConfigTransactionApplyError::Unavailable("peer manager is unavailable".to_string())
        })?;
    reply_rx
        .await
        .map_err(|_| {
            ConfigTransactionApplyError::Unavailable(
                "peer manager dropped config transaction plan reply".to_string(),
            )
        })?
        .map_err(plan_error_to_status)
}

async fn commit_candidate_snapshot_locked(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    peer_mgr_internal_tx: &mpsc::Sender<InternalCommand>,
    config_tx: &mpsc::Sender<ConfigEvent>,
    candidate_toml: String,
    candidate: &Config,
    progress: &RuntimeConfigMutationProgress,
) -> Result<(), ApplyFailure> {
    let permit = reserve_persist_permit(config_tx).await?;
    progress.begin_mutation();
    #[cfg(debug_assertions)]
    rustbgpd_api::runtime_config_settlement::settlement_test_control::hold(
        rustbgpd_api::runtime_config_settlement::settlement_test_control::Checkpoint::TransactionAfterBeginMutation,
    )
    .await;
    let rollback = stage_preloaded_config_snapshot(
        peer_mgr_internal_tx,
        Box::new(candidate.clone()),
        TransactionConfigScope::Full,
    )
    .await?;
    progress.begin_settling();
    if let Err(failure) = persist_candidate_config(permit, candidate_toml).await {
        if failure.fence_reason.is_some() {
            return Err(failure);
        }
        return Err(rollback_snapshot_after_error(peer_mgr_internal_tx, rollback, failure).await);
    }
    // LAN-277 window (a): the candidate is durable on disk from here on — a
    // finalization failure must not be reported as a clean no-commit failure.
    commit_config_snapshot_stage(peer_mgr_tx).await?;
    Ok(())
}

/// `[[dynamic_neighbors]]` commits replace the range set through the staged
/// config snapshot without going through the peer manager's per-range
/// add/delete surface, so the listener fences in `add_dynamic_range` /
/// `delete_dynamic_range` never run for them. Refuse here instead when the
/// transaction would change the startup/SIGHUP-pinned listener MD5/GTSM
/// range inventory (remove or add a protected range, or reassign one across
/// a protection boundary).
async fn commit_dynamic_neighbors_locked(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    peer_mgr_internal_tx: &mpsc::Sender<InternalCommand>,
    config_tx: &mpsc::Sender<ConfigEvent>,
    candidate_toml: String,
    candidate: &Config,
    progress: &RuntimeConfigMutationProgress,
) -> Result<(), ApplyFailure> {
    let permit = reserve_persist_permit(config_tx).await?;
    progress.begin_mutation();
    let rollback = stage_preloaded_config_snapshot(
        peer_mgr_internal_tx,
        Box::new(candidate.clone()),
        TransactionConfigScope::Full,
    )
    .await?;
    if dynamic_range_listener_auth_inventory(rollback.previous())
        != dynamic_range_listener_auth_inventory(candidate)
    {
        let error = peer_lifecycle_error_to_apply_error(PeerLifecycleError::RestartRequired(
            "[[dynamic_neighbors]] transaction changes a range protected by md5_password or \
             ttl_security; inbound listener enforcement is updated only by startup or SIGHUP \
             reload — apply this change through the config file and SIGHUP"
                .to_string(),
        ));
        progress.begin_settling();
        return Err(
            rollback_snapshot_after_error(peer_mgr_internal_tx, rollback, error.into()).await,
        );
    }
    progress.begin_settling();
    if let Err(failure) = persist_candidate_config(permit, candidate_toml).await {
        if failure.fence_reason.is_some() {
            return Err(failure);
        }
        return Err(rollback_snapshot_after_error(peer_mgr_internal_tx, rollback, failure).await);
    }
    // LAN-277 window (a): the candidate is durable on disk from here on — a
    // finalization failure must not be reported as a clean no-commit failure.
    commit_config_snapshot_stage(peer_mgr_tx).await?;
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "one linear add/change/remove apply pass whose every failure arm threads the same rollback pair"
)]
async fn commit_static_neighbors_locked(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    peer_mgr_internal_tx: &mpsc::Sender<InternalCommand>,
    config_tx: &mpsc::Sender<ConfigEvent>,
    candidate_toml: String,
    candidate: &Config,
    committed_sections: &[String],
    progress: &RuntimeConfigMutationProgress,
) -> Result<(), ApplyFailure> {
    let permit = reserve_persist_permit(config_tx).await?;
    progress.begin_mutation();
    let rollback = stage_preloaded_config_snapshot(
        peer_mgr_internal_tx,
        Box::new(candidate.clone()),
        TransactionConfigScope::Full,
    )
    .await?;
    let neighbor_diff = diff_neighbors(&rollback.previous().neighbors, &candidate.neighbors);
    if committed_sections.iter().any(|s| {
        s != NEIGHBOR_ADD_SECTION && s != NEIGHBOR_DELETE_SECTION && s != NEIGHBOR_MODIFY_SECTION
    }) {
        let error = ConfigTransactionApplyError::Internal(
            "static-neighbor transaction executor received a non-static-neighbor diff".to_string(),
        );
        progress.begin_settling();
        return Err(
            rollback_snapshot_after_error(peer_mgr_internal_tx, rollback, error.into()).await,
        );
    }

    let mut applied = Vec::new();
    let added = match resolve_static_neighbors(candidate, &neighbor_diff.added) {
        Ok(added) => added,
        Err(error) => {
            progress.begin_settling();
            return Err(rollback_snapshot_after_error(
                peer_mgr_internal_tx,
                rollback,
                error.into(),
            )
            .await);
        }
    };
    let changed = match resolve_static_neighbors(candidate, &neighbor_diff.changed) {
        Ok(changed) => changed,
        Err(error) => {
            progress.begin_settling();
            return Err(rollback_static_and_snapshot(
                peer_mgr_tx,
                peer_mgr_internal_tx,
                applied,
                rollback,
                error.into(),
            )
            .await);
        }
    };
    for config in added {
        if let Some(error) = runtime_added_neighbor_inbound_auth_error(&config) {
            progress.begin_settling();
            return Err(rollback_static_and_snapshot(
                peer_mgr_tx,
                peer_mgr_internal_tx,
                applied,
                rollback,
                error.into(),
            )
            .await);
        }
        if let Err(error) = add_static_peer(peer_mgr_tx, config.clone()).await {
            progress.begin_settling();
            return Err(rollback_static_and_snapshot(
                peer_mgr_tx,
                peer_mgr_internal_tx,
                applied,
                rollback,
                error.into(),
            )
            .await);
        }
        applied.push(AppliedStaticOp::Added(PeerKey::new(
            config.address,
            config.interface.clone(),
        )));
    }
    for config in changed {
        match reconfigure_static_peer(peer_mgr_tx, config).await {
            Ok(previous) => applied.push(AppliedStaticOp::Modified(Box::new(previous))),
            Err(error) => {
                progress.begin_settling();
                return Err(rollback_static_and_snapshot(
                    peer_mgr_tx,
                    peer_mgr_internal_tx,
                    applied,
                    rollback,
                    error.into(),
                )
                .await);
            }
        }
    }
    for peer in neighbor_diff.removed {
        match delete_static_peer(peer_mgr_tx, peer.clone()).await {
            Ok(removed) => applied.push(AppliedStaticOp::Deleted(Box::new(removed))),
            Err(error) => {
                progress.begin_settling();
                return Err(rollback_static_and_snapshot(
                    peer_mgr_tx,
                    peer_mgr_internal_tx,
                    applied,
                    rollback,
                    error.into(),
                )
                .await);
            }
        }
    }

    progress.begin_settling();
    if let Err(failure) = persist_candidate_config(permit, candidate_toml).await {
        if failure.fence_reason.is_some() {
            return Err(failure);
        }
        return Err(rollback_static_and_snapshot(
            peer_mgr_tx,
            peer_mgr_internal_tx,
            applied,
            rollback,
            failure,
        )
        .await);
    }
    // LAN-277 window (a): candidate durable on disk from here on.
    commit_config_snapshot_stage(peer_mgr_tx).await?;
    Ok(())
}

/// Outcome of a committed peer-group/session reshape transaction.
struct PeerSessionReshapeCommit {
    /// Static members reconfigured in place with captured priors.
    reconfigured: usize,
    /// Live dynamic sessions gracefully reset after persist (plus any
    /// per-peer signaling failures, reported rather than swallowed).
    dynamic_bounce: DynamicPeerBounceOutcome,
}

/// Human text for a committed peer-group/session reshape: static reconfigure
/// count, dynamic reset count, and any per-peer signaling failures (which keep
/// their running config until reconnect — reported, never swallowed).
fn peer_session_reshape_commit_message(commit: &PeerSessionReshapeCommit) -> String {
    let mut message = format!(
        "Committed peer-group/session reshape runtime config transaction.\n{} live session(s) reconfigured.\n",
        commit.reconfigured
    );
    if commit.dynamic_bounce.signaled > 0 {
        let _ = writeln!(
            message,
            "{} live dynamic session(s) signaled to reset; they re-accept under the committed config on reconnect.",
            commit.dynamic_bounce.signaled
        );
    }
    if !commit.dynamic_bounce.failures.is_empty() {
        let _ = writeln!(
            message,
            "{} dynamic session(s)/range(s) could not be signaled and keep their running config until they reconnect: {}",
            commit.dynamic_bounce.failures.len(),
            commit.dynamic_bounce.failures.join("; ")
        );
    }
    message
}

/// Commit a peer-group/session reshape transaction: stage the candidate
/// snapshot, reconfigure the affected concrete static peers (capturing prior
/// configs), persist, and roll back live peers + snapshot on failure. After a
/// successful persist, gracefully reset the live dynamic sessions accepted by
/// the affected ranges — they re-accept under the committed (already staged)
/// config on reconnect. The dynamic reset is deliberately post-persist and
/// best-effort: a failed transaction never flaps a dynamic peer, and a
/// per-peer signaling failure degrades to the documented
/// keep-running-config-until-reconnect semantics instead of failing the
/// already-durable transaction.
async fn commit_peer_session_reshape_locked(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    peer_mgr_internal_tx: &mpsc::Sender<InternalCommand>,
    config_tx: &mpsc::Sender<ConfigEvent>,
    candidate_toml: String,
    candidate: &Config,
    progress: &RuntimeConfigMutationProgress,
) -> Result<PeerSessionReshapeCommit, ApplyFailure> {
    let permit = reserve_persist_permit(config_tx).await?;
    progress.begin_mutation();
    let rollback = stage_preloaded_config_snapshot(
        peer_mgr_internal_tx,
        Box::new(candidate.clone()),
        TransactionConfigScope::Full,
    )
    .await?;

    let targets = match resolve_peer_session_reshape_targets(rollback.previous(), candidate) {
        Ok(targets) => targets,
        Err(error) => {
            progress.begin_settling();
            return Err(rollback_snapshot_after_error(
                peer_mgr_internal_tx,
                rollback,
                error.into(),
            )
            .await);
        }
    };
    if let Some(error) = dynamic_bounce_listener_auth_error(
        rollback.previous(),
        candidate,
        &targets.dynamic_bounce_ranges,
    ) {
        progress.begin_settling();
        return Err(
            rollback_snapshot_after_error(peer_mgr_internal_tx, rollback, error.into()).await,
        );
    }
    let reconfigured = targets.static_targets.len();

    let priors = match send_apply_peer_reshape_snapshot(peer_mgr_tx, targets.static_targets).await {
        Ok(priors) => priors,
        Err(error) => {
            // The peer-manager command self-heals its live mutations on a
            // mid-fanout failure, so only the staged snapshot needs rollback.
            progress.begin_settling();
            return Err(rollback_snapshot_after_error(
                peer_mgr_internal_tx,
                rollback,
                error.into(),
            )
            .await);
        }
    };

    progress.begin_settling();
    if let Err(failure) = persist_candidate_config(permit, candidate_toml).await {
        if failure.fence_reason.is_some() {
            return Err(failure);
        }
        return Err(rollback_peer_reshape_and_snapshot(
            peer_mgr_tx,
            peer_mgr_internal_tx,
            priors,
            rollback,
            failure,
        )
        .await);
    }
    // LAN-277 window (a): candidate durable on disk from here on.
    commit_config_snapshot_stage(peer_mgr_tx).await?;

    let dynamic_bounce = send_bounce_dynamic_range_peers(
        peer_mgr_tx,
        targets.dynamic_bounce_ranges,
        targets.dynamic_purge_ranges,
    )
    .await;
    Ok(PeerSessionReshapeCommit {
        reconfigured,
        dynamic_bounce,
    })
}

/// Send `BounceDynamicRangePeers` after a successful persist. Best-effort by
/// contract: the transaction is already durable, so a command-channel failure
/// is folded into the outcome's failure list (the affected sessions keep
/// their running config until they reconnect) instead of failing the commit.
async fn send_bounce_dynamic_range_peers(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    ranges: Vec<DynamicRangeTarget>,
    purge_ranges: Vec<DynamicRangeTarget>,
) -> DynamicPeerBounceOutcome {
    if ranges.is_empty() {
        return DynamicPeerBounceOutcome::default();
    }
    let unavailable = |ranges: &[DynamicRangeTarget]| DynamicPeerBounceOutcome {
        signaled: 0,
        failures: ranges
            .iter()
            .map(|range| {
                format!(
                    "{}/{} ({}): peer manager unavailable; live dynamic sessions keep \
                     their running config until they reconnect",
                    range.addr, range.prefix_len, range.peer_group
                )
            })
            .collect(),
    };
    let (reply_tx, reply_rx) = oneshot::channel();
    if peer_mgr_tx
        .send(PeerManagerCommand::BounceDynamicRangePeers {
            ranges: ranges.clone(),
            purge_ranges,
            reply: reply_tx,
        })
        .await
        .is_err()
    {
        return unavailable(&ranges);
    }
    match reply_rx.await {
        Ok(outcome) => outcome,
        Err(_) => unavailable(&ranges),
    }
}

/// Resolved commit set for a peer-group/session reshape transaction: static
/// members reconfigured in place (rollback-capable) plus the dynamic ranges
/// whose live sessions are gracefully reset after persist.
struct PeerSessionReshapeTargets {
    static_targets: Vec<PeerManagerNeighborConfig>,
    dynamic_bounce_ranges: Vec<DynamicRangeTarget>,
    dynamic_purge_ranges: Vec<DynamicRangeTarget>,
}

#[expect(
    clippy::too_many_lines,
    reason = "the reshape target resolver keeps its closed-world validation and static/dynamic target construction in one auditable pass"
)]
fn resolve_peer_session_reshape_targets(
    previous: &Config,
    candidate: &Config,
) -> Result<PeerSessionReshapeTargets, ConfigTransactionApplyError> {
    let diff = diff_config(previous, candidate);
    let neighbor_diff = diff_neighbors(&previous.neighbors, &candidate.neighbors);
    if !neighbor_diff.added.is_empty() || !neighbor_diff.removed.is_empty() {
        return Err(ConfigTransactionApplyError::Internal(
            "peer-session reshape executor received add/delete neighbor changes".to_string(),
        ));
    }
    // Mirrors `session_reshape_transaction`: a `[[dynamic_neighbors]]` record
    // edit (range add/remove, peer-group reassignment) is the dynamic-neighbor
    // executor's family — a dynamic impact reaching this executor must be a
    // pure peer-group field reshape over unchanged range records.
    if previous.dynamic_neighbors != candidate.dynamic_neighbors {
        return Err(ConfigTransactionApplyError::Internal(
            "peer-session reshape executor received [[dynamic_neighbors]] record changes"
                .to_string(),
        ));
    }

    let impacted: std::collections::HashSet<&str> = diff
        .effective_neighbor_impact
        .iter()
        .map(|impact| impact.address.as_str())
        .collect();
    if neighbor_diff
        .changed
        .iter()
        .any(|neighbor| !impacted.contains(neighbor.address.as_str()))
    {
        return Err(ConfigTransactionApplyError::Internal(
            "peer-session reshape executor received non-reshape neighbor changes".to_string(),
        ));
    }

    let mut targets = PeerSessionReshapeTargets {
        static_targets: Vec::new(),
        dynamic_bounce_ranges: Vec::new(),
        dynamic_purge_ranges: Vec::new(),
    };
    for impact in &diff.effective_neighbor_impact {
        if impact.kind != EffectiveNeighborImpactKind::SessionReshape {
            return Err(ConfigTransactionApplyError::Internal(format!(
                "peer-session reshape executor received unsupported impact for {}",
                impact.address
            )));
        }
        if impact.is_dynamic_range {
            let Some((addr, prefix_len)) = crate::config::effective_prefix_str(&impact.address)
            else {
                return Err(ConfigTransactionApplyError::Internal(format!(
                    "peer-session reshape impact references invalid dynamic range {}",
                    impact.address
                )));
            };
            let Some(range) = candidate.dynamic_neighbors.iter().find(|range| {
                crate::config::effective_prefix_str(&range.prefix) == Some((addr, prefix_len))
            }) else {
                return Err(ConfigTransactionApplyError::Internal(format!(
                    "peer-session reshape impact references dynamic range {} absent from the candidate",
                    impact.address
                )));
            };
            let target = DynamicRangeTarget {
                addr,
                prefix_len,
                peer_group: range.peer_group.clone(),
            };
            let previous_discard = previous
                .peer_groups
                .get(&range.peer_group)
                .and_then(|group| {
                    normalized_discard_path_attributes(group.discard_path_attributes.as_ref())
                });
            let candidate_discard =
                candidate
                    .peer_groups
                    .get(&range.peer_group)
                    .and_then(|group| {
                        normalized_discard_path_attributes(group.discard_path_attributes.as_ref())
                    });
            let purge_routes = previous_discard != candidate_discard;
            targets.dynamic_bounce_ranges.push(target.clone());
            if purge_routes {
                targets.dynamic_purge_ranges.push(target);
            }
            continue;
        }
        let mut matches = candidate
            .neighbors
            .iter()
            .filter(|neighbor| neighbor.address == impact.address);
        let Some(neighbor) = matches.next() else {
            return Err(ConfigTransactionApplyError::Internal(format!(
                "peer-session reshape impact references neighbor {} absent from the candidate",
                impact.address
            )));
        };
        // Defense in depth: two neighbors sharing an address would make the
        // resolve target ambiguous. The config loader forbids this today —
        // `interface` is only valid for IPv6 link-local, and a link-local
        // address may not repeat across interfaces — so this branch is
        // unreachable via a loadable config, but we fail closed rather than
        // reshape an arbitrarily-chosen session if that ever changes.
        if matches.next().is_some() {
            return Err(ConfigTransactionApplyError::Internal(format!(
                "peer-session reshape impact for {} is ambiguous across multiple scoped neighbors",
                impact.address
            )));
        }
        let resolved = candidate
            .resolve_neighbor(neighbor)
            .map_err(|error| ConfigTransactionApplyError::InvalidArgument(error.to_string()))?;
        targets
            .static_targets
            .push(crate::reload::build_peer_mgr_config(
                &resolved.transport_config,
                resolved.max_prefix_restart_seconds,
                &resolved.label,
                resolved.import_policy.as_ref(),
                resolved.export_policy.as_ref(),
                resolved.peer_group.clone(),
            ));
    }
    Ok(targets)
}

async fn send_apply_peer_reshape_snapshot(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    targets: Vec<PeerManagerNeighborConfig>,
) -> Result<Vec<PeerManagerNeighborConfig>, ConfigTransactionApplyError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    peer_mgr_tx
        .send(PeerManagerCommand::ApplyPeerReshapeSnapshot {
            targets,
            reply: reply_tx,
        })
        .await
        .map_err(|_| {
            ConfigTransactionApplyError::Unavailable("peer manager is unavailable".to_string())
        })?;
    reply_rx
        .await
        .map_err(|_| ConfigTransactionApplyError::RecoveryRequired {
            reason: RuntimeConfigFenceReason::AcknowledgementLost,
            message: "peer manager accepted peer reshape but dropped its reply".to_string(),
        })?
        .map_err(peer_lifecycle_error_to_apply_error)
}

async fn rollback_peer_reshape_and_snapshot(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    peer_mgr_internal_tx: &mpsc::Sender<InternalCommand>,
    priors: Vec<PeerManagerNeighborConfig>,
    rollback: TransactionConfigRollbackToken,
    original: ApplyFailure,
) -> ApplyFailure {
    if original.fence_reason.is_some() {
        return original;
    }
    let live_rollback = send_apply_peer_reshape_snapshot(peer_mgr_tx, priors)
        .await
        .map(|_| ());
    let snapshot_rollback = restore_preloaded_config_snapshot(peer_mgr_internal_tx, rollback).await;
    match (live_rollback, snapshot_rollback) {
        (Ok(()), Ok(())) => original,
        (live_result, snapshot_result) => combine_rollback_errors(
            &original.error,
            "peer reshape rollback",
            live_result.err(),
            snapshot_result.err(),
        ),
    }
}

/// The listener's dynamic-range inbound-auth inventory derived from a
/// config: effective prefix → (MD5 password, GTSM) for every range whose
/// peer group carries either. The listener installs these at startup/SIGHUP
/// only, so runtime commits must leave this set unchanged.
type DynamicRangeListenerAuth = (
    (std::net::IpAddr, u8),
    Option<String>,
    Option<std::num::NonZeroU8>,
);

fn dynamic_range_listener_auth_inventory(
    config: &Config,
) -> std::collections::BTreeSet<DynamicRangeListenerAuth> {
    config
        .dynamic_neighbors
        .iter()
        .filter_map(|range| {
            let key = crate::config::effective_prefix_str(&range.prefix)?;
            let group = config.peer_groups.get(&range.peer_group)?;
            let gtsm_hops = (group.ttl_security == Some(true))
                .then(|| group.ttl_security_hops.unwrap_or(std::num::NonZeroU8::MIN));
            (group.md5_password.is_some() || gtsm_hops.is_some())
                .then(|| (key, group.md5_password.clone(), gtsm_hops))
        })
        .collect()
}

/// A peer-group field reshape reaches the listener fence in
/// `apply_peer_reshape_snapshot` only through its *static* members, so a group
/// whose members are all `[[dynamic_neighbors]]` ranges resolves zero static
/// targets and skips it entirely — the post-persist bounce would then reset
/// live sessions into a listener still pinned to the old MD5/GTSM inventory.
/// Compare the previous and candidate inventories over the bounced ranges and
/// refuse instead. Scoped to those ranges so an untouched protected range
/// elsewhere in the config cannot fence an unrelated reshape.
fn dynamic_bounce_listener_auth_error(
    previous: &Config,
    candidate: &Config,
    ranges: &[DynamicRangeTarget],
) -> Option<ConfigTransactionApplyError> {
    if ranges.is_empty() {
        return None;
    }
    let scope: std::collections::BTreeSet<_> = ranges
        .iter()
        .map(|range| (range.addr, range.prefix_len))
        .collect();
    let scoped = |config: &Config| {
        dynamic_range_listener_auth_inventory(config)
            .into_iter()
            .filter(|(key, _, _)| scope.contains(key))
            .collect::<std::collections::BTreeSet<_>>()
    };
    (scoped(previous) != scoped(candidate)).then(|| {
        peer_lifecycle_error_to_apply_error(PeerLifecycleError::RestartRequired(
            "peer-group reshape changes md5_password or ttl_security for a \
             [[dynamic_neighbors]] range; inbound listener enforcement is updated only by \
             startup or SIGHUP reload — apply this change through the config file and SIGHUP"
                .to_string(),
        ))
    })
}

/// A neighbor added at runtime cannot get its inbound MD5 key or GTSM
/// selector onto the BGP listener (startup/SIGHUP-pinned); admitting it
/// would leave its inbound half silently unauthenticated.
fn runtime_added_neighbor_inbound_auth_error(
    config: &PeerManagerNeighborConfig,
) -> Option<ConfigTransactionApplyError> {
    (config.md5_password.is_some() || config.ttl_security_hops.is_some()).then(|| {
        peer_lifecycle_error_to_apply_error(PeerLifecycleError::RestartRequired(format!(
            "added neighbor {} resolves md5_password or ttl_security; inbound listener \
             enforcement is updated only by startup or SIGHUP reload — add this \
             neighbor through the config file and SIGHUP",
            config.address
        )))
    })
}

fn resolve_static_neighbors(
    candidate: &Config,
    neighbors: &[Neighbor],
) -> Result<Vec<PeerManagerNeighborConfig>, ConfigTransactionApplyError> {
    // The candidate has already passed `Config::validate()` at plan/apply load
    // time, which catches every config-correctness error across the full
    // neighbor set (undefined peer groups, malformed families, policy chains).
    // Resolve only the touched static neighbors here instead of rebuilding every
    // candidate peer. `resolve_neighbor` can still surface a per-neighbor error
    // (e.g. an IPv6 link-local interface-index lookup), which we map to
    // `InvalidArgument`.
    neighbors
        .iter()
        .map(|neighbor| {
            let resolved = candidate
                .resolve_neighbor(neighbor)
                .map_err(|error| ConfigTransactionApplyError::InvalidArgument(error.to_string()))?;
            Ok(crate::reload::build_peer_mgr_config(
                &resolved.transport_config,
                resolved.max_prefix_restart_seconds,
                &resolved.label,
                resolved.import_policy.as_ref(),
                resolved.export_policy.as_ref(),
                resolved.peer_group.clone(),
            ))
        })
        .collect()
}

async fn commit_config_snapshot_stage(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
) -> Result<(), ApplyFailure> {
    let (reply_tx, reply_rx) = oneshot::channel();
    peer_mgr_tx
        .send(PeerManagerCommand::CommitConfigSnapshotStage { reply: reply_tx })
        .await
        .map_err(|_| {
            ApplyFailure::fenced(
                ConfigTransactionApplyError::Unavailable(
                    "peer manager rejected config snapshot finalization before delivery"
                        .to_string(),
                ),
                RuntimeConfigFenceReason::KnownDivergence,
            )
        })?;
    reply_rx.await.map_err(|_| {
        ApplyFailure::fenced(
            ConfigTransactionApplyError::Unavailable(
                "peer manager accepted config snapshot finalization but dropped its reply"
                    .to_string(),
            ),
            RuntimeConfigFenceReason::AcknowledgementLost,
        )
    })
}

async fn rollback_snapshot_after_error(
    peer_mgr_internal_tx: &mpsc::Sender<InternalCommand>,
    rollback: TransactionConfigRollbackToken,
    original: ApplyFailure,
) -> ApplyFailure {
    if original.fence_reason.is_some() {
        return original;
    }
    match restore_preloaded_config_snapshot(peer_mgr_internal_tx, rollback).await {
        Ok(()) => original,
        Err(rollback_error) => {
            combine_rollback_errors(&original.error, "rollback", None, Some(rollback_error))
        }
    }
}

async fn reserve_persist_permit(
    config_tx: &mpsc::Sender<ConfigEvent>,
) -> Result<mpsc::OwnedPermit<ConfigEvent>, ConfigTransactionApplyError> {
    tokio::time::timeout(PERSIST_RESERVE_TIMEOUT, config_tx.clone().reserve_owned())
        .await
        .map_err(|_| {
            ConfigTransactionApplyError::Unavailable(
                "config persistence queue busy — refusing mutation to avoid drift".to_string(),
            )
        })?
        .map_err(|_| {
            ConfigTransactionApplyError::Unavailable("config persistence unavailable".to_string())
        })
}

async fn persist_candidate_config(
    permit: mpsc::OwnedPermit<ConfigEvent>,
    candidate_toml: String,
) -> Result<(), ApplyFailure> {
    let (ack_tx, ack_rx) = oneshot::channel();
    // Single-phase on purpose: the ADR-0076 executor owns its own
    // apply/rollback and ambiguous-outcome reporting, and ADR-0113 already
    // inverted the one family whose apply is not undoable.
    permit.send(ConfigEvent::ConfigTransactionCommitted {
        candidate_toml,
        ack: Some(ConfigPersistAck::immediate(ack_tx)),
    });
    match ack_rx.await {
        Ok(ConfigPersistCommitOutcome::PublishedDurable) => Ok(()),
        // The persister reported failure: the atomic write did not replace the
        // config file, so disk provably still holds the previous config.
        Ok(ConfigPersistCommitOutcome::NotPublished(error)) => {
            Err(ConfigTransactionApplyError::FailedPrecondition(error).into())
        }
        Ok(ConfigPersistCommitOutcome::PublicationAmbiguous(error)) => Err(ApplyFailure::fenced(
            ConfigTransactionApplyError::Internal(format!(
                "config candidate is visible but publication durability is unproved: {error}"
            )),
            RuntimeConfigFenceReason::PublicationAmbiguous,
        )),
        // LAN-277 window (b): the acknowledgement was lost. The persister may
        // or may not have written the candidate — the on-disk outcome is
        // unknowable from here.
        Err(_) => Err(ApplyFailure::fenced(
            ConfigTransactionApplyError::Internal(
                "config bridge dropped transaction persistence acknowledgement".to_string(),
            ),
            RuntimeConfigFenceReason::AcknowledgementLost,
        )),
    }
}

async fn add_static_peer(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    config: PeerManagerNeighborConfig,
) -> Result<(), ConfigTransactionApplyError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    peer_mgr_tx
        .send(PeerManagerCommand::AddPeer {
            config,
            sync_config_snapshot: false,
            reply: reply_tx,
        })
        .await
        .map_err(|_| {
            ConfigTransactionApplyError::Unavailable("peer manager is unavailable".to_string())
        })?;
    reply_rx
        .await
        .map_err(|_| ConfigTransactionApplyError::RecoveryRequired {
            reason: RuntimeConfigFenceReason::AcknowledgementLost,
            message: "peer manager accepted static-neighbor add but dropped its reply".to_string(),
        })?
        .map_err(peer_lifecycle_error_to_apply_error)
}

async fn delete_static_peer(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    peer: PeerKey,
) -> Result<PeerManagerNeighborConfig, ConfigTransactionApplyError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    peer_mgr_tx
        .send(PeerManagerCommand::DeletePeer {
            peer,
            sync_config_snapshot: false,
            reply: reply_tx,
        })
        .await
        .map_err(|_| {
            ConfigTransactionApplyError::Unavailable("peer manager is unavailable".to_string())
        })?;
    reply_rx
        .await
        .map_err(|_| ConfigTransactionApplyError::RecoveryRequired {
            reason: RuntimeConfigFenceReason::AcknowledgementLost,
            message: "peer manager accepted static-neighbor delete but dropped its reply"
                .to_string(),
        })?
        .map_err(peer_lifecycle_error_to_apply_error)
}

async fn reconfigure_static_peer(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    config: PeerManagerNeighborConfig,
) -> Result<PeerManagerNeighborConfig, ConfigTransactionApplyError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    peer_mgr_tx
        .send(PeerManagerCommand::ReconfigurePeer {
            config,
            reply: reply_tx,
        })
        .await
        .map_err(|_| {
            ConfigTransactionApplyError::Unavailable("peer manager is unavailable".to_string())
        })?;
    reply_rx
        .await
        .map_err(|_| ConfigTransactionApplyError::RecoveryRequired {
            reason: RuntimeConfigFenceReason::AcknowledgementLost,
            message: "peer manager accepted static-neighbor reconfigure but dropped its reply"
                .to_string(),
        })?
        .map_err(peer_lifecycle_error_to_apply_error)
}

enum AppliedStaticOp {
    Added(PeerKey),
    Deleted(Box<PeerManagerNeighborConfig>),
    Modified(Box<PeerManagerNeighborConfig>),
}

async fn rollback_static_ops(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    applied: Vec<AppliedStaticOp>,
) -> Result<(), ConfigTransactionApplyError> {
    for op in applied.into_iter().rev() {
        match op {
            AppliedStaticOp::Added(peer) => {
                delete_static_peer(peer_mgr_tx, peer)
                    .await
                    .map_err(|error| {
                        ConfigTransactionApplyError::Internal(format!(
                            "static-neighbor rollback delete failed: {error:?}"
                        ))
                    })?;
            }
            AppliedStaticOp::Deleted(config) => {
                add_static_peer(peer_mgr_tx, *config)
                    .await
                    .map_err(|error| {
                        ConfigTransactionApplyError::Internal(format!(
                            "static-neighbor rollback add failed: {error:?}"
                        ))
                    })?;
            }
            AppliedStaticOp::Modified(config) => {
                reconfigure_static_peer(peer_mgr_tx, *config)
                    .await
                    .map_err(|error| {
                        ConfigTransactionApplyError::Internal(format!(
                            "static-neighbor rollback reconfigure failed: {error}"
                        ))
                    })?;
            }
        }
    }
    Ok(())
}

async fn rollback_static_and_snapshot(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    peer_mgr_internal_tx: &mpsc::Sender<InternalCommand>,
    applied: Vec<AppliedStaticOp>,
    rollback: TransactionConfigRollbackToken,
    original: ApplyFailure,
) -> ApplyFailure {
    if original.fence_reason.is_some() {
        return original;
    }
    let static_rollback = rollback_static_ops(peer_mgr_tx, applied).await;
    let snapshot_rollback = restore_preloaded_config_snapshot(peer_mgr_internal_tx, rollback).await;
    match (static_rollback, snapshot_rollback) {
        (Ok(()), Ok(())) => original,
        (static_result, snapshot_result) => combine_rollback_errors(
            &original.error,
            "static rollback",
            static_result.err(),
            snapshot_result.err(),
        ),
    }
}

/// LAN-277 window (c): only reached when a rollback component failed, so the
/// runtime is left part-candidate — always an ambiguous completion.
fn combine_rollback_errors(
    original: &ConfigTransactionApplyError,
    first_label: &str,
    first_rollback: Option<ConfigTransactionApplyError>,
    snapshot_rollback: Option<ConfigTransactionApplyError>,
) -> ApplyFailure {
    error!(
        %original,
        ?first_rollback,
        ?snapshot_rollback,
        "config transaction rollback failed"
    );
    let reason = first_rollback
        .as_ref()
        .or(snapshot_rollback.as_ref())
        .map_or(RuntimeConfigFenceReason::KnownDivergence, recovery_reason);
    let mut message = format!("{original}; rollback failed");
    if let Some(error) = first_rollback {
        let _ = write!(message, "; {first_label}: {error}");
    }
    if let Some(error) = snapshot_rollback {
        let _ = write!(message, "; snapshot rollback: {error}");
    }
    ApplyFailure::fenced(ConfigTransactionApplyError::Internal(message), reason)
}

fn recovery_reason(error: &ConfigTransactionApplyError) -> RuntimeConfigFenceReason {
    match error {
        ConfigTransactionApplyError::RecoveryRequired { reason, .. } => *reason,
        _ => RuntimeConfigFenceReason::KnownDivergence,
    }
}

fn committable_response(
    runtime_snapshot_token: String,
    committed_sections: Vec<String>,
    human_text: String,
    update_group_impact: Option<proto::UpdateGroupImpactPlan>,
) -> proto::ConfigTransactionApplyResponse {
    proto::ConfigTransactionApplyResponse {
        status: proto::ConfigTransactionPlanStatus::Committable.into(),
        runtime_snapshot_token,
        committed_sections,
        human_text,
        confirmation: None,
        update_group_impact,
    }
}

fn plan_error_to_status(error: RuntimeConfigTransactionPlanError) -> ConfigTransactionApplyError {
    match error {
        RuntimeConfigTransactionPlanError::StaleSnapshot { .. } => {
            ConfigTransactionApplyError::FailedPrecondition(error.message())
        }
        RuntimeConfigTransactionPlanError::InvalidCandidate(message) => {
            ConfigTransactionApplyError::InvalidArgument(message)
        }
        RuntimeConfigTransactionPlanError::Internal(message) => {
            ConfigTransactionApplyError::Internal(message)
        }
    }
}

fn apply_error_to_gnmi_set_error(error: ConfigTransactionApplyError) -> GnmiSetError {
    match error {
        ConfigTransactionApplyError::InvalidArgument(message) => {
            GnmiSetError::InvalidArgument(message)
        }
        ConfigTransactionApplyError::FailedPrecondition(message) => {
            GnmiSetError::FailedPrecondition(message)
        }
        ConfigTransactionApplyError::Unavailable(message) => GnmiSetError::Unavailable(message),
        // gNMI Set owns the coordinator before it calls the locked apply helpers, so Apply's
        // pre-ownership deadline is unreachable here. Keep the exhaustive mapping inside the
        // existing gNMI vocabulary unless gNMI coordinator acquisition gains its own deadline.
        ConfigTransactionApplyError::DeadlineExceeded(message) => {
            GnmiSetError::Unavailable(message)
        }
        ConfigTransactionApplyError::Internal(message) => GnmiSetError::Internal(message),
        ConfigTransactionApplyError::RecoveryRequired { message, .. } => {
            GnmiSetError::Internal(message)
        }
    }
}

fn apply_error_to_owned_gnmi_set_error(error: ConfigTransactionApplyError) -> OwnedGnmiSetError {
    match error {
        ConfigTransactionApplyError::RecoveryRequired { reason, message } => {
            OwnedGnmiSetError::Fenced { message, reason }
        }
        error => OwnedGnmiSetError::Clean(apply_error_to_gnmi_set_error(error)),
    }
}

fn gnmi_set_outcome_from_apply_response(
    response: proto::ConfigTransactionApplyResponse,
) -> Result<GnmiSetOutcome, GnmiSetError> {
    match proto::ConfigTransactionPlanStatus::try_from(response.status) {
        Ok(
            proto::ConfigTransactionPlanStatus::Noop
            | proto::ConfigTransactionPlanStatus::Committable,
        ) => Ok(GnmiSetOutcome::default()),
        Ok(proto::ConfigTransactionPlanStatus::Rejected) => {
            let message = if response.human_text.is_empty() {
                "gNMI Set transaction was rejected".to_string()
            } else {
                response.human_text
            };
            Err(GnmiSetError::FailedPrecondition(message))
        }
        Ok(proto::ConfigTransactionPlanStatus::Unspecified) | Err(_) => {
            Err(GnmiSetError::Internal(format!(
                "gNMI Set transaction returned unexpected status {}",
                response.status
            )))
        }
    }
}

fn peer_lifecycle_error_to_apply_error(error: PeerLifecycleError) -> ConfigTransactionApplyError {
    match error {
        PeerLifecycleError::AlreadyExists(peer) => {
            ConfigTransactionApplyError::FailedPrecondition(format!("peer {peer} already exists"))
        }
        PeerLifecycleError::NotFound(peer) => {
            ConfigTransactionApplyError::FailedPrecondition(format!("peer {peer} not found"))
        }
        PeerLifecycleError::Invalid(message) => {
            ConfigTransactionApplyError::InvalidArgument(message)
        }
        PeerLifecycleError::RestartRequired(message) => {
            ConfigTransactionApplyError::FailedPrecondition(message)
        }
        PeerLifecycleError::Internal(message) => ConfigTransactionApplyError::Internal(message),
    }
}

fn confirm_abort_rollback_error(
    confirm_id: &str,
    error: &ConfigTransactionApplyError,
) -> ConfigTransactionApplyError {
    let message = format!(
        "failed to abort confirmed config transaction {confirm_id:?}: rollback failed: {error}"
    );
    match error {
        // Abort carries no candidate input — the rollback re-applies the
        // captured pre-commit snapshot — so an `InvalidArgument` from that
        // re-apply means the captured snapshot itself failed validation (data
        // corruption / internal invariant violation), not a malformed abort
        // request. Surface it as `Internal` rather than implying client fault.
        ConfigTransactionApplyError::InvalidArgument(_) => {
            ConfigTransactionApplyError::Internal(message)
        }
        ConfigTransactionApplyError::FailedPrecondition(_) => {
            ConfigTransactionApplyError::FailedPrecondition(message)
        }
        ConfigTransactionApplyError::Unavailable(_) => {
            ConfigTransactionApplyError::Unavailable(message)
        }
        ConfigTransactionApplyError::DeadlineExceeded(_) => {
            ConfigTransactionApplyError::DeadlineExceeded(message)
        }
        ConfigTransactionApplyError::Internal(_) => ConfigTransactionApplyError::Internal(message),
        ConfigTransactionApplyError::RecoveryRequired { reason, .. } => {
            ConfigTransactionApplyError::RecoveryRequired {
                reason: *reason,
                message,
            }
        }
    }
}

fn rejected_response(runtime_snapshot_token: String) -> proto::ConfigTransactionApplyResponse {
    proto::ConfigTransactionApplyResponse {
        status: proto::ConfigTransactionPlanStatus::Rejected.into(),
        runtime_snapshot_token,
        committed_sections: Vec::new(),
        human_text: "Config transaction is not committable by the current apply executor.\nRun PlanConfigTransaction for section classification.\n".to_string(),
        confirmation: None,
        update_group_impact: None,
    }
}

fn fib_error_to_apply_error(
    error: rustbgpd_api::rib_service::FibTableControlError,
) -> ConfigTransactionApplyError {
    match error {
        rustbgpd_api::rib_service::FibTableControlError::InvalidArgument(message)
        | rustbgpd_api::rib_service::FibTableControlError::NotFound(message) => {
            ConfigTransactionApplyError::InvalidArgument(message)
        }
        rustbgpd_api::rib_service::FibTableControlError::FailedPrecondition(message) => {
            ConfigTransactionApplyError::FailedPrecondition(message)
        }
        rustbgpd_api::rib_service::FibTableControlError::Unavailable(message) => {
            ConfigTransactionApplyError::Unavailable(message)
        }
        rustbgpd_api::rib_service::FibTableControlError::Internal(message) => {
            ConfigTransactionApplyError::Internal(message)
        }
    }
}

#[cfg(test)]
mod tests;
