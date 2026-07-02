//! Binary-owned config transaction apply hook.
//!
//! `ConfigService` lives in the API crate, but committing a transaction needs
//! binary-only state: the FIB reconciler command channel, config persistence,
//! peer-manager validation, and the runtime-config lock shared with SIGHUP.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{Mutex, mpsc, oneshot};

use rustbgpd_api::peer_types::{
    ConfigEvent, DynamicPeerBounceOutcome, DynamicRangeTarget, PeerKey, PeerLifecycleError,
    PeerManagerCommand, PeerManagerNeighborConfig, ResolvedPeerPolicy,
    RuntimeConfigTransactionPlanError, RuntimeConfigTransactionStatus, StageConfigSnapshotError,
};
use rustbgpd_api::proto;
use rustbgpd_api::server::{
    ConfigMutationGateFn, ConfigTransactionAbortFn, ConfigTransactionApplyError,
    ConfigTransactionApplyFn, ConfigTransactionConfirmFn, ConfigTransactionStatusFn,
    GnmiSetCommitAction, GnmiSetError, GnmiSetFn, GnmiSetOutcome,
};
use rustbgpd_telemetry::BgpMetrics;
use tracing::{error, info};

use crate::config::{Config, EffectiveNeighborImpactKind, Neighbor, diff_config, diff_neighbors};
use crate::fib_table_control::{
    FibTableControlDeps, commit_fib_tables_locked, runtime_unavailable_error,
};
use crate::gnmi_set_bridge;
use crate::reload::runtime_config_snapshot;

const PERSIST_RESERVE_TIMEOUT: Duration = Duration::from_secs(2);
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
}

#[derive(Debug, Default)]
struct ConfirmedState {
    applying_confirm_id: Option<String>,
    pending: Option<PendingConfirmedTransaction>,
    timer: Option<tokio::task::JoinHandle<()>>,
    last: Option<ConfirmedTransactionRecord>,
}

#[derive(Clone, Debug)]
struct PendingConfirmedTransaction {
    confirm_id: String,
    rollback_toml: String,
    rollback_expected_runtime_snapshot_token: String,
    timeout_seconds: u32,
    deadline: tokio::time::Instant,
    deadline_unix_seconds: u64,
    committed_sections: Vec<String>,
    runtime_snapshot_token: String,
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

impl ConfigTransactionController {
    #[must_use]
    pub fn new(deps: FibTableControlDeps, metrics: BgpMetrics) -> Self {
        Self {
            deps: Arc::new(deps),
            metrics,
            state: Arc::new(Mutex::new(ConfirmedState::default())),
        }
    }

    #[must_use]
    pub fn apply_fn(&self) -> ConfigTransactionApplyFn {
        let controller = self.clone();
        Arc::new(move |request| {
            let controller = controller.clone();
            Box::pin(async move { controller.apply(request).await })
        })
    }

    #[must_use]
    pub fn gnmi_set_fn(&self) -> GnmiSetFn {
        let controller = self.clone();
        Arc::new(move |transaction| {
            let controller = controller.clone();
            Box::pin(async move { controller.apply_gnmi_set(transaction).await })
        })
    }

    #[must_use]
    pub fn confirm_fn(&self) -> ConfigTransactionConfirmFn {
        let controller = self.clone();
        Arc::new(move |request| {
            let controller = controller.clone();
            Box::pin(async move { controller.confirm(request).await })
        })
    }

    #[must_use]
    pub fn abort_fn(&self) -> ConfigTransactionAbortFn {
        let controller = self.clone();
        Arc::new(move |request| {
            let controller = controller.clone();
            Box::pin(async move { controller.abort(request).await })
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

    async fn apply(
        self,
        request: proto::ApplyConfigTransactionRequest,
    ) -> Result<proto::ConfigTransactionApplyResponse, ConfigTransactionApplyError> {
        validate_apply_request(&request)?;
        let confirmed = parse_confirmed_apply_mode(&request)?;
        let join = tokio::spawn(async move {
            let _guard = self.deps.lock.lock().await;
            self.apply_locked(request, confirmed).await
        });

        join.await.map_err(|_| {
            ConfigTransactionApplyError::Internal(
                "config transaction apply task did not complete".to_string(),
            )
        })?
    }

    async fn apply_gnmi_set(
        self,
        transaction: rustbgpd_api::server::GnmiSetTransaction,
    ) -> Result<GnmiSetOutcome, GnmiSetError> {
        let join = tokio::spawn(async move {
            let _guard = self.deps.lock.lock().await;
            match transaction.commit_action.clone() {
                Some(GnmiSetCommitAction::Confirm { confirm_id }) => {
                    let confirm_id =
                        validate_confirm_id(&confirm_id).map_err(apply_error_to_gnmi_set_error)?;
                    self.confirm_locked(confirm_id)
                        .await
                        .map_err(apply_error_to_gnmi_set_error)?;
                    return Ok(GnmiSetOutcome::default());
                }
                Some(GnmiSetCommitAction::Cancel { confirm_id }) => {
                    let confirm_id =
                        validate_confirm_id(&confirm_id).map_err(apply_error_to_gnmi_set_error)?;
                    self.abort_locked(confirm_id)
                        .await
                        .map_err(apply_error_to_gnmi_set_error)?;
                    return Ok(GnmiSetOutcome::default());
                }
                Some(GnmiSetCommitAction::SetRollbackDuration {
                    confirm_id,
                    confirm_timeout_seconds,
                }) => {
                    let confirm_id =
                        validate_confirm_id(&confirm_id).map_err(apply_error_to_gnmi_set_error)?;
                    let confirm_timeout_seconds =
                        validate_confirm_timeout_seconds(confirm_timeout_seconds)
                            .map_err(apply_error_to_gnmi_set_error)?;
                    self.reset_rollback_duration_locked(confirm_id, confirm_timeout_seconds)
                        .await
                        .map_err(apply_error_to_gnmi_set_error)?;
                    return Ok(GnmiSetOutcome::default());
                }
                Some(GnmiSetCommitAction::Commit { .. }) | None => {
                    self.reject_if_pending("gnmi.gNMI/Set")
                        .await
                        .map_err(apply_error_to_gnmi_set_error)?;
                }
            }
            let current = runtime_config_snapshot(&self.deps.peer_mgr_tx)
                .await
                .map_err(GnmiSetError::Unavailable)?;
            let candidate = gnmi_set_bridge::apply_transaction_to_config(current, &transaction)?;
            let candidate_toml = toml::to_string_pretty(&candidate).map_err(|error| {
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
                ) => unreachable!("commit-control actions handled before candidate generation"),
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
            let confirmed =
                parse_confirmed_apply_mode(&request).map_err(apply_error_to_gnmi_set_error)?;
            let response = if confirmed.is_some() {
                self.apply_locked(request, confirmed)
                    .await
                    .map_err(apply_error_to_gnmi_set_error)?
            } else {
                // The coordinator lock serializes this internal gNMI Set path,
                // and the candidate was just built from the live runtime
                // snapshot. Let the shared apply executor do the single
                // authoritative plan.
                apply_config_transaction_locked(&self.deps, request)
                    .await
                    .map_err(apply_error_to_gnmi_set_error)?
            };
            gnmi_set_outcome_from_apply_response(response)
        });

        join.await.map_err(|_| {
            GnmiSetError::Internal("gNMI Set transaction task did not complete".to_string())
        })?
    }

    async fn apply_locked(
        &self,
        request: proto::ApplyConfigTransactionRequest,
        confirmed: Option<ConfirmedApplyMode>,
    ) -> Result<proto::ConfigTransactionApplyResponse, ConfigTransactionApplyError> {
        if let Some(confirmed) = confirmed {
            self.begin_confirmed_apply(&confirmed.confirm_id).await?;
            let result = self
                .apply_confirmed_locked(request, confirmed.clone())
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
            apply_config_transaction_locked(&self.deps, request).await
        }
    }

    async fn apply_confirmed_locked(
        &self,
        request: proto::ApplyConfigTransactionRequest,
        confirmed: ConfirmedApplyMode,
    ) -> Result<proto::ConfigTransactionApplyResponse, ConfigTransactionApplyError> {
        let rollback_config = runtime_config_snapshot(&self.deps.peer_mgr_tx)
            .await
            .map_err(ConfigTransactionApplyError::Unavailable)?;
        let rollback_toml = toml::to_string_pretty(&rollback_config).map_err(|error| {
            ConfigTransactionApplyError::Internal(format!(
                "failed to serialize confirmed transaction rollback snapshot: {error}"
            ))
        })?;
        let mut response = apply_config_transaction_locked(&self.deps, request).await?;
        if response.status != proto::ConfigTransactionPlanStatus::Committable as i32 {
            return Ok(response);
        }

        let timeout = Duration::from_secs(u64::from(confirmed.timeout_seconds));
        let deadline = tokio::time::Instant::now() + timeout;
        let deadline_unix_seconds = SystemTime::now()
            .checked_add(timeout)
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |duration| duration.as_secs());
        let pending = PendingConfirmedTransaction {
            confirm_id: confirmed.confirm_id.clone(),
            rollback_toml,
            rollback_expected_runtime_snapshot_token: response.runtime_snapshot_token.clone(),
            timeout_seconds: confirmed.timeout_seconds,
            deadline,
            deadline_unix_seconds,
            committed_sections: response.committed_sections.clone(),
            runtime_snapshot_token: response.runtime_snapshot_token.clone(),
        };
        let confirmation = pending_confirmation_proto(
            &pending,
            "Confirmed config transaction is pending confirmation.",
        );
        self.install_pending_confirmed_transaction(pending).await;
        self.spawn_confirm_timeout(confirmed.confirm_id).await;
        response.confirmation = Some(confirmation);
        response.human_text.push_str(
            "Confirmed transaction pending; call ConfirmConfigTransaction before the timeout or it will be rolled back.\n",
        );
        Ok(response)
    }

    async fn confirm(
        self,
        request: proto::ConfirmConfigTransactionRequest,
    ) -> Result<proto::ConfirmConfigTransactionResponse, ConfigTransactionApplyError> {
        let confirm_id = validate_confirm_id(&request.confirm_id)?;
        let join = tokio::spawn(async move {
            let _guard = self.deps.lock.lock().await;
            self.confirm_locked(confirm_id).await
        });
        join.await.map_err(|_| {
            ConfigTransactionApplyError::Internal(
                "config transaction confirm task did not complete".to_string(),
            )
        })?
    }

    async fn confirm_locked(
        &self,
        confirm_id: String,
    ) -> Result<proto::ConfirmConfigTransactionResponse, ConfigTransactionApplyError> {
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
        self.metrics
            .record_config_transaction_lifecycle("confirm", "success");
        Ok(proto::ConfirmConfigTransactionResponse {
            confirmation: Some(confirmation),
            human_text: "Confirmed config transaction committed permanently.\n".to_string(),
        })
    }

    async fn abort(
        self,
        request: proto::AbortConfigTransactionRequest,
    ) -> Result<proto::AbortConfigTransactionResponse, ConfigTransactionApplyError> {
        let confirm_id = validate_confirm_id(&request.confirm_id)?;
        let join = tokio::spawn(async move {
            let _guard = self.deps.lock.lock().await;
            self.abort_locked(confirm_id).await
        });
        join.await.map_err(|_| {
            ConfigTransactionApplyError::Internal(
                "config transaction abort task did not complete".to_string(),
            )
        })?
    }

    async fn abort_locked(
        &self,
        confirm_id: String,
    ) -> Result<proto::AbortConfigTransactionResponse, ConfigTransactionApplyError> {
        let pending = self.matching_pending(&confirm_id).await?;
        match self.rollback_pending_locked(&pending).await {
            Ok(response) => {
                self.remove_pending_after_rollback(
                        &confirm_id,
                        proto::ConfigTransactionConfirmationStatus::Aborted,
                        response.runtime_snapshot_token.clone(),
                        "Aborted confirmed config transaction and restored the previous runtime config.",
                        true,
                    )
                    .await;
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
                self.remove_pending_after_rollback(
                    &confirm_id,
                    proto::ConfigTransactionConfirmationStatus::AbortFailed,
                    pending.runtime_snapshot_token.clone(),
                    "Abort requested, but rollback of the confirmed config transaction failed.",
                    true,
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
    ) -> Result<(), ConfigTransactionApplyError> {
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
            return Ok(proto::ConfigTransactionStatusResponse {
                confirmation: Some(pending_confirmation_proto(
                    pending,
                    "Confirmed config transaction is awaiting confirmation.",
                )),
                human_text: "Confirmed config transaction is awaiting confirmation.\n".to_string(),
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

    async fn begin_confirmed_apply(
        &self,
        confirm_id: &str,
    ) -> Result<(), ConfigTransactionApplyError> {
        let mut state = self.state.lock().await;
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
        let join = tokio::spawn(async move {
            let _guard = self.deps.lock.lock().await;
            let Some(pending) = self.pending_for_timeout(&confirm_id).await else {
                return Ok(());
            };
            if tokio::time::Instant::now() < pending.deadline {
                return Ok(());
            }
            match self.rollback_pending_locked(&pending).await {
                Ok(response) => {
                    self.remove_pending_after_rollback(
                        &confirm_id,
                        proto::ConfigTransactionConfirmationStatus::AutoReverted,
                        response.runtime_snapshot_token,
                        "Confirmed config transaction timed out and was automatically rolled back.",
                        false,
                    )
                    .await;
                    self.metrics
                        .record_config_transaction_lifecycle("auto_revert", "success");
                    info!(confirm_id, "confirmed config transaction auto-reverted");
                    Ok(())
                }
                Err(error) => {
                    self.remove_pending_after_rollback(
                        &confirm_id,
                        proto::ConfigTransactionConfirmationStatus::AutoRevertFailed,
                        pending.runtime_snapshot_token.clone(),
                        "Confirmed config transaction timed out, but automatic rollback failed.",
                        false,
                    )
                    .await;
                    self.metrics
                        .record_config_transaction_lifecycle("auto_revert", "failure");
                    Err(error)
                }
            }
        });
        join.await.map_err(|_| {
            ConfigTransactionApplyError::Internal(
                "config transaction auto-revert task did not complete".to_string(),
            )
        })?
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
    ) -> Result<proto::ConfigTransactionApplyResponse, ConfigTransactionApplyError> {
        let response = apply_config_transaction_locked(
            &self.deps,
            proto::ApplyConfigTransactionRequest {
                candidate_toml: pending.rollback_toml.clone(),
                expected_runtime_snapshot_token: pending
                    .rollback_expected_runtime_snapshot_token
                    .clone(),
                client_request_id: format!("confirmed-rollback:{}", pending.confirm_id),
                comment: "confirmed transaction rollback".to_string(),
                confirm_id: String::new(),
                confirm_timeout_seconds: 0,
            },
        )
        .await?;
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

    async fn remove_pending_after_rollback(
        &self,
        confirm_id: &str,
        status: proto::ConfigTransactionConfirmationStatus,
        runtime_snapshot_token: String,
        human_text: &'static str,
        abort_timer: bool,
    ) {
        let mut state = self.state.lock().await;
        let Some(pending) = state.pending.take() else {
            return;
        };
        if pending.confirm_id != confirm_id {
            state.pending = Some(pending);
            return;
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

fn validate_apply_request(
    request: &proto::ApplyConfigTransactionRequest,
) -> Result<(), ConfigTransactionApplyError> {
    if request.expected_runtime_snapshot_token.is_empty() {
        return Err(ConfigTransactionApplyError::InvalidArgument(
            "expected_runtime_snapshot_token is required for ApplyConfigTransaction".to_string(),
        ));
    }
    if request.confirm_id.is_empty() && request.confirm_timeout_seconds > 0 {
        return Err(ConfigTransactionApplyError::InvalidArgument(
            "confirm_id is required when confirm_timeout_seconds is set".to_string(),
        ));
    }
    Ok(())
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
        let _guard = deps.lock.lock().await;
        apply_config_transaction_locked(&deps, request).await
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
) -> Result<proto::ConfigTransactionApplyResponse, ConfigTransactionApplyError> {
    let plan = plan_candidate(
        &deps.peer_mgr_tx,
        request.candidate_toml.clone(),
        request.expected_runtime_snapshot_token.clone(),
    )
    .await?;

    match plan.status {
        RuntimeConfigTransactionStatus::Noop => {
            return Ok(proto::ConfigTransactionApplyResponse {
                status: proto::ConfigTransactionPlanStatus::Noop.into(),
                runtime_snapshot_token: plan.runtime_snapshot_token,
                committed_sections: Vec::new(),
                human_text: "No changes.\n".to_string(),
                confirmation: None,
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

    let candidate =
        Config::load_toml_with_diagnostics(&request.candidate_toml, "candidate config transaction")
            .map_err(ConfigTransactionApplyError::InvalidArgument)?;
    let config_tx = deps.config_tx.clone().ok_or_else(|| {
        ConfigTransactionApplyError::FailedPrecondition(
            "config transactions require a persisted config (start rustbgpd with --config)"
                .to_string(),
        )
    })?;
    // Post-commit token comes from the plan (computed under the peer-manager's
    // key); the apply path can't recompute a key-consistent token itself.
    let post_commit_runtime_snapshot_token = plan.post_commit_runtime_snapshot_token;
    commit_apply_family(
        deps,
        &config_tx,
        family,
        request.candidate_toml,
        candidate,
        plan.supported_sections,
        post_commit_runtime_snapshot_token,
    )
    .await
}

async fn commit_apply_family(
    deps: &FibTableControlDeps,
    config_tx: &mpsc::Sender<ConfigEvent>,
    family: ApplyFamily,
    candidate_toml: String,
    candidate: Config,
    supported_sections: Vec<String>,
    post_commit_runtime_snapshot_token: String,
) -> Result<proto::ConfigTransactionApplyResponse, ConfigTransactionApplyError> {
    match family {
        ApplyFamily::FibTables => {
            commit_fib_transaction(
                deps,
                config_tx,
                &candidate,
                post_commit_runtime_snapshot_token,
            )
            .await
        }
        ApplyFamily::DynamicNeighbors => {
            commit_candidate_snapshot_locked(&deps.peer_mgr_tx, config_tx, candidate_toml).await?;
            Ok(committable_response(
                post_commit_runtime_snapshot_token,
                vec![DYNAMIC_SECTION.to_string()],
                format!(
                    "Committed [[dynamic_neighbors]] transaction.\n{} range(s) active.\n",
                    candidate.dynamic_neighbors.len()
                ),
            ))
        }
        ApplyFamily::CatalogSnapshot => {
            commit_candidate_snapshot_locked(&deps.peer_mgr_tx, config_tx, candidate_toml).await?;
            Ok(committable_response(
                post_commit_runtime_snapshot_token,
                supported_sections,
                format!(
                    "Committed catalog-only runtime config transaction.\n{} policy definition(s), {} neighbor set(s), {} peer group(s) active.\n",
                    candidate.policy.definitions.len(),
                    candidate.policy.neighbor_sets.len(),
                    candidate.peer_groups.len(),
                ),
            ))
        }
        ApplyFamily::LivePolicyImpact => {
            let refreshed = commit_live_policy_impact_locked(
                &deps.peer_mgr_tx,
                config_tx,
                candidate_toml,
                &candidate,
            )
            .await?;
            Ok(committable_response(
                post_commit_runtime_snapshot_token,
                supported_sections,
                format!(
                    "Committed live policy-impact runtime config transaction.\n{refreshed} live session(s) re-evaluated under the new resolved policy.\n"
                ),
            ))
        }
        ApplyFamily::PeerSessionReshape => {
            let commit = commit_peer_session_reshape_locked(
                &deps.peer_mgr_tx,
                config_tx,
                candidate_toml,
                &candidate,
            )
            .await?;
            Ok(committable_response(
                post_commit_runtime_snapshot_token,
                supported_sections,
                peer_session_reshape_commit_message(&commit),
            ))
        }
        ApplyFamily::StaticNeighbors => {
            commit_static_neighbors_locked(
                &deps.peer_mgr_tx,
                config_tx,
                candidate_toml,
                &candidate,
                &supported_sections,
            )
            .await?;
            Ok(committable_response(
                post_commit_runtime_snapshot_token,
                supported_sections,
                "Committed [[neighbors]] add/delete/modify transaction.\n".to_string(),
            ))
        }
    }
}

async fn commit_fib_transaction(
    deps: &FibTableControlDeps,
    config_tx: &mpsc::Sender<ConfigEvent>,
    candidate: &Config,
    post_commit_runtime_snapshot_token: String,
) -> Result<proto::ConfigTransactionApplyResponse, ConfigTransactionApplyError> {
    let fib_cmd_tx = deps.fib_cmd_tx.clone().ok_or_else(|| {
        fib_error_to_apply_error(runtime_unavailable_error(!deps.startup_tables.is_empty()))
    })?;
    let response = commit_fib_tables_locked(
        &fib_cmd_tx,
        &deps.peer_mgr_tx,
        config_tx,
        candidate.fib_tables.clone(),
    )
    .await
    .map_err(fib_error_to_apply_error)?;
    Ok(committable_response(
        post_commit_runtime_snapshot_token,
        vec![FIB_SECTION.to_string()],
        format!(
            "Committed [[fib_tables]] transaction.\n{} table(s) active.\n",
            response.tables.len()
        ),
    ))
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
    config_tx: &mpsc::Sender<ConfigEvent>,
    candidate_toml: String,
) -> Result<(), ConfigTransactionApplyError> {
    let permit = reserve_persist_permit(config_tx).await?;
    let previous_toml = stage_config_snapshot(peer_mgr_tx, candidate_toml.clone()).await?;
    if let Err(error) = persist_candidate_config(permit, candidate_toml).await {
        return Err(rollback_snapshot_after_error(peer_mgr_tx, previous_toml, error).await);
    }
    commit_config_snapshot_stage(peer_mgr_tx).await?;
    Ok(())
}

async fn commit_static_neighbors_locked(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    config_tx: &mpsc::Sender<ConfigEvent>,
    candidate_toml: String,
    candidate: &Config,
    committed_sections: &[String],
) -> Result<(), ConfigTransactionApplyError> {
    let permit = reserve_persist_permit(config_tx).await?;
    let previous_toml = stage_config_snapshot(peer_mgr_tx, candidate_toml.clone()).await?;
    let previous = match Config::load_toml_with_diagnostics(
        &previous_toml,
        "previous runtime config transaction snapshot",
    ) {
        Ok(previous) => previous,
        Err(error) => {
            let error = ConfigTransactionApplyError::Internal(error);
            return Err(rollback_snapshot_after_error(peer_mgr_tx, previous_toml, error).await);
        }
    };
    let neighbor_diff = diff_neighbors(&previous.neighbors, &candidate.neighbors);
    if committed_sections.iter().any(|s| {
        s != NEIGHBOR_ADD_SECTION && s != NEIGHBOR_DELETE_SECTION && s != NEIGHBOR_MODIFY_SECTION
    }) {
        let error = ConfigTransactionApplyError::Internal(
            "static-neighbor transaction executor received a non-static-neighbor diff".to_string(),
        );
        return Err(rollback_snapshot_after_error(peer_mgr_tx, previous_toml, error).await);
    }

    let mut applied = Vec::new();
    let added = match resolve_static_neighbors(candidate, &neighbor_diff.added) {
        Ok(added) => added,
        Err(error) => {
            return Err(rollback_snapshot_after_error(peer_mgr_tx, previous_toml, error).await);
        }
    };
    let changed = match resolve_static_neighbors(candidate, &neighbor_diff.changed) {
        Ok(changed) => changed,
        Err(error) => {
            return Err(
                rollback_static_and_snapshot(peer_mgr_tx, applied, previous_toml, error).await,
            );
        }
    };
    for config in added {
        if let Err(error) = add_static_peer(peer_mgr_tx, config.clone()).await {
            return Err(
                rollback_static_and_snapshot(peer_mgr_tx, applied, previous_toml, error).await,
            );
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
                return Err(rollback_static_and_snapshot(
                    peer_mgr_tx,
                    applied,
                    previous_toml,
                    error,
                )
                .await);
            }
        }
    }
    for peer in neighbor_diff.removed {
        match delete_static_peer(peer_mgr_tx, peer.clone()).await {
            Ok(removed) => applied.push(AppliedStaticOp::Deleted(Box::new(removed))),
            Err(error) => {
                return Err(rollback_static_and_snapshot(
                    peer_mgr_tx,
                    applied,
                    previous_toml,
                    error,
                )
                .await);
            }
        }
    }

    if let Err(error) = persist_candidate_config(permit, candidate_toml).await {
        return Err(rollback_static_and_snapshot(peer_mgr_tx, applied, previous_toml, error).await);
    }
    commit_config_snapshot_stage(peer_mgr_tx).await?;
    Ok(())
}

/// Commit a live-impact policy/peer-group/global-chain transaction: stage the
/// candidate snapshot, re-apply the affected static neighbors' resolved chains
/// to their live sessions (capturing priors), persist, and roll back live +
/// snapshot on failure. Returns the number of live sessions re-evaluated.
async fn commit_live_policy_impact_locked(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    config_tx: &mpsc::Sender<ConfigEvent>,
    candidate_toml: String,
    candidate: &Config,
) -> Result<usize, ConfigTransactionApplyError> {
    let permit = reserve_persist_permit(config_tx).await?;
    let previous_toml = stage_config_snapshot(peer_mgr_tx, candidate_toml.clone()).await?;
    let previous = match Config::load_toml_with_diagnostics(
        &previous_toml,
        "previous runtime config transaction snapshot",
    ) {
        Ok(previous) => previous,
        Err(error) => {
            let error = ConfigTransactionApplyError::Internal(error);
            return Err(rollback_snapshot_after_error(peer_mgr_tx, previous_toml, error).await);
        }
    };

    let targets = match resolve_live_policy_targets(&previous, candidate) {
        Ok(targets) => targets,
        Err(error) => {
            return Err(rollback_snapshot_after_error(peer_mgr_tx, previous_toml, error).await);
        }
    };

    let priors = match send_apply_policy_impact_snapshot(peer_mgr_tx, targets).await {
        Ok(priors) => priors,
        Err(error) => {
            // The peer-manager command self-heals its live mutations on a
            // mid-fanout failure, so only the staged snapshot needs rollback.
            return Err(rollback_snapshot_after_error(peer_mgr_tx, previous_toml, error).await);
        }
    };

    if let Err(error) = persist_candidate_config(permit, candidate_toml).await {
        return Err(
            rollback_live_policy_and_snapshot(peer_mgr_tx, priors, previous_toml, error).await,
        );
    }
    commit_config_snapshot_stage(peer_mgr_tx).await?;
    Ok(priors.len())
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
    config_tx: &mpsc::Sender<ConfigEvent>,
    candidate_toml: String,
    candidate: &Config,
) -> Result<PeerSessionReshapeCommit, ConfigTransactionApplyError> {
    let permit = reserve_persist_permit(config_tx).await?;
    let previous_toml = stage_config_snapshot(peer_mgr_tx, candidate_toml.clone()).await?;
    let previous = match Config::load_toml_with_diagnostics(
        &previous_toml,
        "previous runtime config transaction snapshot",
    ) {
        Ok(previous) => previous,
        Err(error) => {
            let error = ConfigTransactionApplyError::Internal(error);
            return Err(rollback_snapshot_after_error(peer_mgr_tx, previous_toml, error).await);
        }
    };

    let targets = match resolve_peer_session_reshape_targets(&previous, candidate) {
        Ok(targets) => targets,
        Err(error) => {
            return Err(rollback_snapshot_after_error(peer_mgr_tx, previous_toml, error).await);
        }
    };
    let reconfigured = targets.static_targets.len();

    let priors = match send_apply_peer_reshape_snapshot(peer_mgr_tx, targets.static_targets).await {
        Ok(priors) => priors,
        Err(error) => {
            // The peer-manager command self-heals its live mutations on a
            // mid-fanout failure, so only the staged snapshot needs rollback.
            return Err(rollback_snapshot_after_error(peer_mgr_tx, previous_toml, error).await);
        }
    };

    if let Err(error) = persist_candidate_config(permit, candidate_toml).await {
        return Err(
            rollback_peer_reshape_and_snapshot(peer_mgr_tx, priors, previous_toml, error).await,
        );
    }
    commit_config_snapshot_stage(peer_mgr_tx).await?;

    let dynamic_bounce =
        send_bounce_dynamic_range_peers(peer_mgr_tx, targets.dynamic_bounce_ranges).await;
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

#[derive(Default)]
struct LivePolicyTargets {
    static_targets: Vec<ResolvedPeerPolicy>,
    dynamic_ranges: Vec<DynamicRangeTarget>,
}

/// Build the resolved-chain apply set from a live-impact diff:
/// every static neighbor whose resolved import/export policy moved and every
/// dynamic range whose accepted live peers need candidate policy resolution.
fn resolve_live_policy_targets(
    previous: &Config,
    candidate: &Config,
) -> Result<LivePolicyTargets, ConfigTransactionApplyError> {
    let diff = diff_config(previous, candidate);
    let candidate_by_addr: std::collections::HashMap<&str, &Neighbor> = candidate
        .neighbors
        .iter()
        .map(|neighbor| (neighbor.address.as_str(), neighbor))
        .collect();
    let dynamic_range_by_key: std::collections::HashMap<_, _> = candidate
        .dynamic_neighbors
        .iter()
        .filter_map(|range| {
            crate::config::effective_prefix_str(&range.prefix).map(|key| (key, range))
        })
        .collect();
    let mut targets = LivePolicyTargets::default();
    for impact in &diff.effective_neighbor_impact {
        if !impact.kind.is_policy_chain() {
            // A committable live-impact plan only carries policy-chain-only
            // impacts; anything else is an internal inconsistency — fail closed
            // rather than silently skip.
            return Err(ConfigTransactionApplyError::Internal(format!(
                "live-policy executor received an unsupported impact for {}",
                impact.address
            )));
        }
        if impact.is_dynamic_range {
            let Some((addr, prefix_len)) = crate::config::effective_prefix_str(&impact.address)
            else {
                return Err(ConfigTransactionApplyError::Internal(format!(
                    "live-policy impact references invalid dynamic range {}",
                    impact.address
                )));
            };
            let Some(range) = dynamic_range_by_key.get(&(addr, prefix_len)) else {
                return Err(ConfigTransactionApplyError::Internal(format!(
                    "live-policy impact references dynamic range {} absent from the candidate",
                    impact.address
                )));
            };
            targets.dynamic_ranges.push(DynamicRangeTarget {
                addr,
                prefix_len,
                peer_group: range.peer_group.clone(),
            });
            continue;
        }
        let Some(neighbor) = candidate_by_addr.get(impact.address.as_str()) else {
            return Err(ConfigTransactionApplyError::Internal(format!(
                "live-policy impact references neighbor {} absent from the candidate",
                impact.address
            )));
        };
        let address = neighbor.address.parse().map_err(|error| {
            ConfigTransactionApplyError::InvalidArgument(format!(
                "invalid neighbor address {:?}: {error}",
                neighbor.address
            ))
        })?;
        let resolved = candidate
            .resolve_neighbor(neighbor)
            .map_err(|error| ConfigTransactionApplyError::InvalidArgument(error.to_string()))?;
        targets.static_targets.push(ResolvedPeerPolicy {
            address,
            interface: neighbor.interface.clone(),
            import_policy: resolved.import_policy,
            export_policy: resolved.export_policy,
        });
    }
    Ok(targets)
}

/// Resolved commit set for a peer-group/session reshape transaction: static
/// members reconfigured in place (rollback-capable) plus the dynamic ranges
/// whose live sessions are gracefully reset after persist.
struct PeerSessionReshapeTargets {
    static_targets: Vec<PeerManagerNeighborConfig>,
    dynamic_bounce_ranges: Vec<DynamicRangeTarget>,
}

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
            targets.dynamic_bounce_ranges.push(DynamicRangeTarget {
                addr,
                prefix_len,
                peer_group: range.peer_group.clone(),
            });
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
                &resolved.label,
                resolved.import_policy.as_ref(),
                resolved.export_policy.as_ref(),
                resolved.peer_group.clone(),
            ));
    }
    Ok(targets)
}

/// Send `ApplyPolicyImpactSnapshot` and return the captured prior chains.
async fn send_apply_policy_impact_snapshot(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    targets: LivePolicyTargets,
) -> Result<Vec<ResolvedPeerPolicy>, ConfigTransactionApplyError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    peer_mgr_tx
        .send(PeerManagerCommand::ApplyPolicyImpactSnapshot {
            static_targets: targets.static_targets,
            dynamic_ranges: targets.dynamic_ranges,
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
                "peer manager dropped policy-impact reply".to_string(),
            )
        })?
        .map_err(ConfigTransactionApplyError::Internal)
}

/// Send `ApplyResolvedPolicySnapshot` and return the captured prior chains.
/// Used in reverse to restore captured priors during rollback.
async fn send_apply_resolved_policy_snapshot(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    targets: Vec<ResolvedPeerPolicy>,
) -> Result<Vec<ResolvedPeerPolicy>, ConfigTransactionApplyError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    peer_mgr_tx
        .send(PeerManagerCommand::ApplyResolvedPolicySnapshot {
            targets,
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
                "peer manager dropped resolved-policy reply".to_string(),
            )
        })?
        .map_err(ConfigTransactionApplyError::Internal)
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
        .map_err(|_| {
            ConfigTransactionApplyError::Unavailable(
                "peer manager dropped peer-reshape reply".to_string(),
            )
        })?
        .map_err(peer_lifecycle_error_to_apply_error)
}

async fn rollback_live_policy_and_snapshot(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    priors: Vec<ResolvedPeerPolicy>,
    previous_toml: String,
    original: ConfigTransactionApplyError,
) -> ConfigTransactionApplyError {
    let live_rollback = send_apply_resolved_policy_snapshot(peer_mgr_tx, priors)
        .await
        .map(|_| ());
    let snapshot_rollback = rollback_config_snapshot(peer_mgr_tx, previous_toml).await;
    match (live_rollback, snapshot_rollback) {
        (Ok(()), Ok(())) => original,
        (live_result, snapshot_result) => combine_rollback_errors(
            &original,
            "live policy rollback",
            live_result.err(),
            snapshot_result.err(),
        ),
    }
}

async fn rollback_peer_reshape_and_snapshot(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    priors: Vec<PeerManagerNeighborConfig>,
    previous_toml: String,
    original: ConfigTransactionApplyError,
) -> ConfigTransactionApplyError {
    let live_rollback = send_apply_peer_reshape_snapshot(peer_mgr_tx, priors)
        .await
        .map(|_| ());
    let snapshot_rollback = rollback_config_snapshot(peer_mgr_tx, previous_toml).await;
    match (live_rollback, snapshot_rollback) {
        (Ok(()), Ok(())) => original,
        (live_result, snapshot_result) => combine_rollback_errors(
            &original,
            "peer reshape rollback",
            live_result.err(),
            snapshot_result.err(),
        ),
    }
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
                &resolved.label,
                resolved.import_policy.as_ref(),
                resolved.export_policy.as_ref(),
                resolved.peer_group.clone(),
            ))
        })
        .collect()
}

async fn stage_config_snapshot(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    candidate_toml: String,
) -> Result<String, ConfigTransactionApplyError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    peer_mgr_tx
        .send(PeerManagerCommand::StageConfigSnapshot {
            candidate_toml,
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
                "peer manager dropped config snapshot stage reply".to_string(),
            )
        })?
        .map_err(stage_config_snapshot_error_to_apply_error)
}

async fn rollback_config_snapshot(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    previous: String,
) -> Result<(), ConfigTransactionApplyError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    peer_mgr_tx
        .send(PeerManagerCommand::RestoreConfigSnapshot {
            candidate_toml: previous,
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
                "peer manager dropped config snapshot rollback reply".to_string(),
            )
        })?
        .map_err(stage_config_snapshot_error_to_apply_error)
        .map_err(|error| {
            ConfigTransactionApplyError::Internal(format!(
                "config snapshot rollback failed: {error}"
            ))
        })
}

async fn commit_config_snapshot_stage(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
) -> Result<(), ConfigTransactionApplyError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    peer_mgr_tx
        .send(PeerManagerCommand::CommitConfigSnapshotStage { reply: reply_tx })
        .await
        .map_err(|_| {
            ConfigTransactionApplyError::Unavailable("peer manager is unavailable".to_string())
        })?;
    reply_rx.await.map_err(|_| {
        ConfigTransactionApplyError::Unavailable(
            "peer manager dropped config snapshot commit reply".to_string(),
        )
    })
}

async fn rollback_snapshot_after_error(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    previous_toml: String,
    original: ConfigTransactionApplyError,
) -> ConfigTransactionApplyError {
    match rollback_config_snapshot(peer_mgr_tx, previous_toml).await {
        Ok(()) => original,
        Err(rollback_error) => {
            combine_rollback_errors(&original, "rollback", None, Some(rollback_error))
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
) -> Result<(), ConfigTransactionApplyError> {
    let (ack_tx, ack_rx) = oneshot::channel();
    permit.send(ConfigEvent::ConfigTransactionCommitted {
        candidate_toml,
        ack: Some(ack_tx),
    });
    ack_rx
        .await
        .map_err(|_| {
            ConfigTransactionApplyError::Internal(
                "config bridge dropped transaction persistence acknowledgement".to_string(),
            )
        })?
        .map_err(ConfigTransactionApplyError::FailedPrecondition)
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
        .map_err(|_| {
            ConfigTransactionApplyError::Unavailable(
                "peer manager dropped static-neighbor add reply".to_string(),
            )
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
        .map_err(|_| {
            ConfigTransactionApplyError::Unavailable(
                "peer manager dropped static-neighbor delete reply".to_string(),
            )
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
        .map_err(|_| {
            ConfigTransactionApplyError::Unavailable(
                "peer manager dropped static-neighbor reconfigure reply".to_string(),
            )
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
    applied: Vec<AppliedStaticOp>,
    previous_toml: String,
    original: ConfigTransactionApplyError,
) -> ConfigTransactionApplyError {
    let static_rollback = rollback_static_ops(peer_mgr_tx, applied).await;
    let snapshot_rollback = rollback_config_snapshot(peer_mgr_tx, previous_toml).await;
    match (static_rollback, snapshot_rollback) {
        (Ok(()), Ok(())) => original,
        (static_result, snapshot_result) => combine_rollback_errors(
            &original,
            "static rollback",
            static_result.err(),
            snapshot_result.err(),
        ),
    }
}

fn combine_rollback_errors(
    original: &ConfigTransactionApplyError,
    first_label: &str,
    first_rollback: Option<ConfigTransactionApplyError>,
    snapshot_rollback: Option<ConfigTransactionApplyError>,
) -> ConfigTransactionApplyError {
    error!(
        %original,
        ?first_rollback,
        ?snapshot_rollback,
        "config transaction rollback failed"
    );
    let mut message = format!("{original}; rollback failed");
    if let Some(error) = first_rollback {
        let _ = write!(message, "; {first_label}: {error}");
    }
    if let Some(error) = snapshot_rollback {
        let _ = write!(message, "; snapshot rollback: {error}");
    }
    ConfigTransactionApplyError::Internal(message)
}

fn committable_response(
    runtime_snapshot_token: String,
    committed_sections: Vec<String>,
    human_text: String,
) -> proto::ConfigTransactionApplyResponse {
    proto::ConfigTransactionApplyResponse {
        status: proto::ConfigTransactionPlanStatus::Committable.into(),
        runtime_snapshot_token,
        committed_sections,
        human_text,
        confirmation: None,
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
        ConfigTransactionApplyError::Internal(message) => GnmiSetError::Internal(message),
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

fn stage_config_snapshot_error_to_apply_error(
    error: StageConfigSnapshotError,
) -> ConfigTransactionApplyError {
    match error {
        StageConfigSnapshotError::InvalidCandidate(message) => {
            ConfigTransactionApplyError::InvalidArgument(message)
        }
        error @ StageConfigSnapshotError::SerializePreviousSnapshot(_) => {
            ConfigTransactionApplyError::Internal(error.to_string())
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
        ConfigTransactionApplyError::Internal(_) => ConfigTransactionApplyError::Internal(message),
    }
}

fn rejected_response(runtime_snapshot_token: String) -> proto::ConfigTransactionApplyResponse {
    proto::ConfigTransactionApplyResponse {
        status: proto::ConfigTransactionPlanStatus::Rejected.into(),
        runtime_snapshot_token,
        committed_sections: Vec::new(),
        human_text: "Config transaction is not committable by the current apply executor.\nRun PlanConfigTransaction for section classification.\n".to_string(),
        confirmation: None,
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
mod tests {
    use super::*;
    use crate::config::FibTableConfig;
    use crate::fib_runtime::FibRuntimeCommand;
    use rustbgpd_api::peer_types::{
        FibTableSnapshot, RuntimeConfigDiff, RuntimeConfigTransactionPlan,
        RuntimeConfigTransactionPlanError,
    };
    use rustbgpd_api::rib_service::FibTableControlError;
    use rustbgpd_policy::PolicyAction;
    use std::collections::{BTreeSet, HashMap, VecDeque};
    use tokio::sync::Mutex;

    fn base_toml(extra: &str) -> String {
        format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[security.grpc]
enforcement = "legacy"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002

{extra}
"#
        )
    }

    fn config_transaction_lifecycle_metric(
        controller: &ConfigTransactionController,
        operation: &str,
        outcome: &str,
    ) -> f64 {
        controller
            .metrics
            .registry()
            .gather()
            .iter()
            .find(|family| family.name() == "bgp_config_transaction_lifecycle_total")
            .and_then(|family| {
                family.metric.iter().find(|metric| {
                    let label_value = |name| {
                        metric
                            .get_label()
                            .iter()
                            .find(|label| label.name() == name)
                            .map(prometheus::proto::LabelPair::value)
                    };
                    label_value("operation") == Some(operation)
                        && label_value("outcome") == Some(outcome)
                })
            })
            .map_or(0.0, |metric| metric.get_counter().value())
    }

    fn assert_config_transaction_lifecycle_metric(
        controller: &ConfigTransactionController,
        operation: &str,
        outcome: &str,
        expected: f64,
    ) {
        let actual = config_transaction_lifecycle_metric(controller, operation, outcome);
        assert!(
            (actual - expected).abs() < f64::EPSILON,
            "metric operation={operation} outcome={outcome}: got {actual}, expected {expected}"
        );
    }

    use crate::test_support::basic_fib_table as table;

    fn snapshot(table: &FibTableConfig) -> FibTableSnapshot {
        FibTableSnapshot {
            name: table.name.clone(),
            table_id: table.table_id,
            metric: table.metric,
            families: table.families.clone(),
            allowed_peer_groups: table.allowed_peer_groups.clone(),
            allowed_neighbors: table.allowed_neighbors.clone(),
            max_routes: table.max_routes,
            maximum_paths: table.maximum_paths,
            maximum_paths_ebgp: table.maximum_paths_ebgp,
            maximum_paths_ibgp: table.maximum_paths_ibgp,
        }
    }

    fn peer_config_from_toml(toml: &str, address: &str) -> PeerManagerNeighborConfig {
        let config = Config::load_toml_with_diagnostics(toml, "test config")
            .expect("test config must parse");
        let address: std::net::IpAddr = address.parse().expect("test address must parse");
        let resolved = config.resolved_neighbors().expect("neighbors must resolve");
        let neighbor = resolved
            .iter()
            .find(|neighbor| neighbor.transport_config.remote_addr.ip() == address)
            .expect("neighbor must exist");
        crate::reload::build_peer_mgr_config(
            &neighbor.transport_config,
            &neighbor.label,
            neighbor.import_policy.as_ref(),
            neighbor.export_policy.as_ref(),
            neighbor.peer_group.clone(),
        )
    }

    fn gnmi_set_add_neighbor(
        address: &str,
        remote_asn: u64,
    ) -> rustbgpd_api::server::GnmiSetTransaction {
        rustbgpd_api::server::GnmiSetTransaction {
            prefix: None,
            operations: vec![rustbgpd_api::server::GnmiSetOperation::Update(gnmi_update(
                gnmi_neighbor_config_path(address, "peer-as"),
                rustbgpd_api::gnmi::typed_value::Value::UintVal(remote_asn),
            ))],
            commit_action: None,
        }
    }

    fn gnmi_set_add_neighbor_confirmed(
        address: &str,
        remote_asn: u64,
        confirm_id: &str,
        timeout_seconds: u32,
    ) -> rustbgpd_api::server::GnmiSetTransaction {
        let mut transaction = gnmi_set_add_neighbor(address, remote_asn);
        transaction.commit_action = Some(rustbgpd_api::server::GnmiSetCommitAction::Commit {
            confirm_id: confirm_id.to_string(),
            confirm_timeout_seconds: timeout_seconds,
        });
        transaction
    }

    fn gnmi_set_commit_confirm(confirm_id: &str) -> rustbgpd_api::server::GnmiSetTransaction {
        rustbgpd_api::server::GnmiSetTransaction {
            prefix: None,
            operations: Vec::new(),
            commit_action: Some(rustbgpd_api::server::GnmiSetCommitAction::Confirm {
                confirm_id: confirm_id.to_string(),
            }),
        }
    }

    fn gnmi_set_commit_cancel(confirm_id: &str) -> rustbgpd_api::server::GnmiSetTransaction {
        rustbgpd_api::server::GnmiSetTransaction {
            prefix: None,
            operations: Vec::new(),
            commit_action: Some(rustbgpd_api::server::GnmiSetCommitAction::Cancel {
                confirm_id: confirm_id.to_string(),
            }),
        }
    }

    fn gnmi_set_peer_group_hold_time(
        name: &str,
        hold_time: u64,
    ) -> rustbgpd_api::server::GnmiSetTransaction {
        rustbgpd_api::server::GnmiSetTransaction {
            prefix: None,
            operations: vec![rustbgpd_api::server::GnmiSetOperation::Update(gnmi_update(
                gnmi_peer_group_path(name, &["timers", "config", "hold-time"]),
                rustbgpd_api::gnmi::typed_value::Value::UintVal(hold_time),
            ))],
            commit_action: None,
        }
    }

    fn gnmi_set_dynamic_neighbor(
        prefix: &str,
        peer_group: &str,
    ) -> rustbgpd_api::server::GnmiSetTransaction {
        rustbgpd_api::server::GnmiSetTransaction {
            prefix: None,
            operations: vec![
                rustbgpd_api::server::GnmiSetOperation::Update(gnmi_update(
                    gnmi_dynamic_neighbor_path(prefix, &["config", "prefix"]),
                    rustbgpd_api::gnmi::typed_value::Value::StringVal(prefix.to_string()),
                )),
                rustbgpd_api::server::GnmiSetOperation::Update(gnmi_update(
                    gnmi_dynamic_neighbor_path(prefix, &["config", "peer-group"]),
                    rustbgpd_api::gnmi::typed_value::Value::StringVal(peer_group.to_string()),
                )),
            ],
            commit_action: None,
        }
    }

    fn gnmi_set_rollback_duration(
        confirm_id: &str,
        timeout_seconds: u32,
    ) -> rustbgpd_api::server::GnmiSetTransaction {
        rustbgpd_api::server::GnmiSetTransaction {
            prefix: None,
            operations: Vec::new(),
            commit_action: Some(
                rustbgpd_api::server::GnmiSetCommitAction::SetRollbackDuration {
                    confirm_id: confirm_id.to_string(),
                    confirm_timeout_seconds: timeout_seconds,
                },
            ),
        }
    }

    fn gnmi_update(
        path: rustbgpd_api::gnmi::Path,
        value: rustbgpd_api::gnmi::typed_value::Value,
    ) -> rustbgpd_api::gnmi::Update {
        rustbgpd_api::gnmi::Update {
            path: Some(path),
            #[allow(deprecated)]
            value: None,
            val: Some(rustbgpd_api::gnmi::TypedValue { value: Some(value) }),
            duplicates: 0,
        }
    }

    fn gnmi_neighbor_config_path(address: &str, leaf: &str) -> rustbgpd_api::gnmi::Path {
        rustbgpd_api::gnmi::Path {
            #[allow(deprecated)]
            element: Vec::new(),
            origin: String::new(),
            elem: vec![
                gnmi_pe("network-instances"),
                gnmi_keyed_pe("network-instance", "name", "DEFAULT"),
                gnmi_pe("protocols"),
                gnmi_protocol_pe(),
                gnmi_pe("bgp"),
                gnmi_pe("neighbors"),
                gnmi_keyed_pe("neighbor", "neighbor-address", address),
                gnmi_pe("config"),
                gnmi_pe(leaf),
            ],
            target: String::new(),
        }
    }

    fn gnmi_peer_group_path(name: &str, tail: &[&str]) -> rustbgpd_api::gnmi::Path {
        let mut elem = vec![
            gnmi_pe("network-instances"),
            gnmi_keyed_pe("network-instance", "name", "DEFAULT"),
            gnmi_pe("protocols"),
            gnmi_protocol_pe(),
            gnmi_pe("bgp"),
            gnmi_pe("peer-groups"),
            gnmi_keyed_pe("peer-group", "peer-group-name", name),
        ];
        elem.extend(tail.iter().map(|name| gnmi_pe(name)));
        rustbgpd_api::gnmi::Path {
            #[allow(deprecated)]
            element: Vec::new(),
            origin: String::new(),
            elem,
            target: String::new(),
        }
    }

    fn gnmi_dynamic_neighbor_path(prefix: &str, tail: &[&str]) -> rustbgpd_api::gnmi::Path {
        let mut elem = vec![
            gnmi_pe("network-instances"),
            gnmi_keyed_pe("network-instance", "name", "DEFAULT"),
            gnmi_pe("protocols"),
            gnmi_protocol_pe(),
            gnmi_pe("bgp"),
            gnmi_pe("global"),
            gnmi_pe("dynamic-neighbor-prefixes"),
            gnmi_keyed_pe("dynamic-neighbor-prefix", "prefix", prefix),
        ];
        elem.extend(tail.iter().map(|name| gnmi_pe(name)));
        rustbgpd_api::gnmi::Path {
            #[allow(deprecated)]
            element: Vec::new(),
            origin: String::new(),
            elem,
            target: String::new(),
        }
    }

    fn gnmi_pe(name: &str) -> rustbgpd_api::gnmi::PathElem {
        rustbgpd_api::gnmi::PathElem {
            name: name.to_string(),
            key: HashMap::new(),
        }
    }

    fn gnmi_keyed_pe(name: &str, key: &str, value: &str) -> rustbgpd_api::gnmi::PathElem {
        rustbgpd_api::gnmi::PathElem {
            name: name.to_string(),
            key: HashMap::from([(key.to_string(), value.to_string())]),
        }
    }

    fn gnmi_protocol_pe() -> rustbgpd_api::gnmi::PathElem {
        rustbgpd_api::gnmi::PathElem {
            name: "protocol".to_string(),
            key: HashMap::from([
                ("identifier".to_string(), "BGP".to_string()),
                ("name".to_string(), "BGP".to_string()),
            ]),
        }
    }

    #[test]
    fn resolve_static_neighbors_resolves_only_touched_neighbors() {
        let candidate = Config::load_toml_with_diagnostics(
            &base_toml(
                r#"
[peer_groups.edge]
hold_time = 75
max_prefixes = 9000

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "edge"

[[neighbors]]
address = "10.0.0.4"
remote_asn = 65004
peer_group = "edge"
"#,
            ),
            "candidate config",
        )
        .expect("candidate must parse");
        let touched = candidate
            .neighbors
            .iter()
            .find(|neighbor| neighbor.address == "10.0.0.3")
            .expect("target neighbor must exist")
            .clone();

        let resolved =
            resolve_static_neighbors(&candidate, &[touched]).expect("target neighbor must resolve");

        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].address.to_string(), "10.0.0.3");
        assert_eq!(resolved[0].peer_group.as_deref(), Some("edge"));
        assert_eq!(resolved[0].hold_time, Some(75));
        assert_eq!(resolved[0].max_prefixes, Some(9000));
    }

    #[test]
    fn stage_snapshot_errors_map_by_variant() {
        let error = stage_config_snapshot_error_to_apply_error(
            StageConfigSnapshotError::SerializePreviousSnapshot("synthetic".to_string()),
        );
        assert!(
            matches!(error, ConfigTransactionApplyError::Internal(ref message)
                if message.contains("failed to serialize previous runtime config snapshot: synthetic"))
        );

        let error =
            stage_config_snapshot_error_to_apply_error(StageConfigSnapshotError::InvalidCandidate(
                "invalid candidate config transaction: synthetic".to_string(),
            ));
        assert!(matches!(
            error,
            ConfigTransactionApplyError::InvalidArgument(_)
        ));
    }

    #[test]
    fn peer_lifecycle_errors_map_to_transaction_apply_classes() {
        let peer = PeerKey::new("10.0.0.2".parse().unwrap(), None);
        let duplicate =
            peer_lifecycle_error_to_apply_error(PeerLifecycleError::AlreadyExists(peer.clone()));
        assert!(matches!(
            duplicate,
            ConfigTransactionApplyError::FailedPrecondition(ref message)
                if message.contains("already exists")
        ));

        let missing = peer_lifecycle_error_to_apply_error(PeerLifecycleError::NotFound(peer));
        assert!(matches!(
            missing,
            ConfigTransactionApplyError::FailedPrecondition(ref message)
                if message.contains("not found")
        ));

        let invalid =
            peer_lifecycle_error_to_apply_error(PeerLifecycleError::Invalid("bad".to_string()));
        assert!(matches!(
            invalid,
            ConfigTransactionApplyError::InvalidArgument(ref message) if message == "bad"
        ));

        let restart = peer_lifecycle_error_to_apply_error(PeerLifecycleError::RestartRequired(
            "restart".to_string(),
        ));
        assert!(matches!(
            restart,
            ConfigTransactionApplyError::FailedPrecondition(ref message) if message == "restart"
        ));

        let internal =
            peer_lifecycle_error_to_apply_error(PeerLifecycleError::Internal("boom".to_string()));
        assert!(matches!(
            internal,
            ConfigTransactionApplyError::Internal(ref message) if message == "boom"
        ));
    }

    #[test]
    fn transaction_plan_errors_map_without_string_matching() {
        let stale = plan_error_to_status(RuntimeConfigTransactionPlanError::StaleSnapshot {
            expected: "old".to_string(),
            current: "new".to_string(),
        });
        assert!(matches!(
            stale,
            ConfigTransactionApplyError::FailedPrecondition(ref message)
                if message.contains("expected old, current new")
        ));

        let invalid = plan_error_to_status(RuntimeConfigTransactionPlanError::InvalidCandidate(
            "bad toml".to_string(),
        ));
        assert!(matches!(
            invalid,
            ConfigTransactionApplyError::InvalidArgument(ref message) if message == "bad toml"
        ));
    }

    fn diff() -> RuntimeConfigDiff {
        RuntimeConfigDiff {
            has_actionable_changes: true,
            has_reload_applied_changes: true,
            has_restart_required_changes: false,
            has_informational_changes: false,
            has_any_changes: true,
            human_text: "Reload-applied changes:\n".to_string(),
            diff_json: "{}".to_string(),
        }
    }

    fn plan(
        status: RuntimeConfigTransactionStatus,
        supported_sections: Vec<String>,
    ) -> RuntimeConfigTransactionPlan {
        RuntimeConfigTransactionPlan {
            status,
            runtime_snapshot_token: "kv1:old:1".to_string(),
            post_commit_runtime_snapshot_token: "kv1:new:2".to_string(),
            diff: diff(),
            supported_sections,
            unsupported_sections: Vec::new(),
            restart_required_sections: Vec::new(),
            human_text: String::new(),
        }
    }

    async fn fake_peer_manager(
        mut rx: mpsc::Receiver<PeerManagerCommand>,
        plan: RuntimeConfigTransactionPlan,
        staged: Arc<Mutex<Vec<FibTableSnapshot>>>,
    ) {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                PeerManagerCommand::PlanConfigTransaction { reply, .. } => {
                    let _ = reply.send(Ok(plan.clone()));
                }
                PeerManagerCommand::StageFibTables { tables, reply } => {
                    *staged.lock().await = tables;
                    let _ = reply.send(Ok(()));
                }
                PeerManagerCommand::SetFibTablesSnapshot { tables, reply } => {
                    *staged.lock().await = tables;
                    let _ = reply.send(());
                }
                _ => panic!("unexpected peer-manager command in config transaction test"),
            }
        }
    }

    async fn fake_fib_actor(
        mut rx: mpsc::Receiver<FibRuntimeCommand>,
        state: Arc<Mutex<Vec<FibTableConfig>>>,
        replace_result: Option<Result<(), String>>,
    ) {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                FibRuntimeCommand::GetTables { reply } => {
                    let _ = reply.send(state.lock().await.clone());
                }
                FibRuntimeCommand::ReplaceTables { tables, reply } => {
                    let result = replace_result.clone().unwrap_or(Ok(()));
                    if result.is_ok() {
                        *state.lock().await = tables;
                    }
                    let _ = reply.send(result);
                }
            }
        }
    }

    async fn fake_snapshot_peer_manager(
        rx: mpsc::Receiver<PeerManagerCommand>,
        plan: RuntimeConfigTransactionPlan,
        snapshot_toml: Arc<Mutex<String>>,
        peers: Arc<Mutex<Vec<PeerManagerNeighborConfig>>>,
    ) {
        fake_snapshot_peer_manager_recording_bounces(
            rx,
            plan,
            snapshot_toml,
            peers,
            Arc::new(Mutex::new(Vec::new())),
        )
        .await;
    }

    /// `fake_snapshot_peer_manager` with a recorder for
    /// `BounceDynamicRangePeers` selectors. The fake reports one signaled
    /// session per targeted range and no failures.
    async fn fake_snapshot_peer_manager_recording_bounces(
        mut rx: mpsc::Receiver<PeerManagerCommand>,
        plan: RuntimeConfigTransactionPlan,
        snapshot_toml: Arc<Mutex<String>>,
        peers: Arc<Mutex<Vec<PeerManagerNeighborConfig>>>,
        bounce_calls: Arc<Mutex<Vec<Vec<DynamicRangeTarget>>>>,
    ) {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                PeerManagerCommand::PlanConfigTransaction { reply, .. } => {
                    let _ = reply.send(Ok(plan.clone()));
                }
                PeerManagerCommand::StageConfigSnapshot {
                    candidate_toml,
                    reply,
                } => {
                    let mut snapshot = snapshot_toml.lock().await;
                    let previous = snapshot.clone();
                    *snapshot = candidate_toml;
                    let _ = reply.send(Ok(previous));
                }
                PeerManagerCommand::CommitConfigSnapshotStage { reply } => {
                    let _ = reply.send(());
                }
                PeerManagerCommand::RestoreConfigSnapshot {
                    candidate_toml,
                    reply,
                } => {
                    *snapshot_toml.lock().await = candidate_toml;
                    let _ = reply.send(Ok(()));
                }
                PeerManagerCommand::RuntimeConfigSnapshot { reply } => {
                    let _ = reply.send(Ok(rustbgpd_api::peer_types::RuntimeConfigSnapshotReply {
                        toml: snapshot_toml.lock().await.clone(),
                        rpol_files: Vec::new(),
                        rpol: rustbgpd_policy::rpol::RpolPolicySet::default(),
                    }));
                }
                PeerManagerCommand::AddPeer { config, reply, .. } => {
                    let mut peers = peers.lock().await;
                    let key = PeerKey::new(config.address, config.interface.clone());
                    if peers
                        .iter()
                        .any(|peer| PeerKey::new(peer.address, peer.interface.clone()) == key)
                    {
                        let _ = reply.send(Err(PeerLifecycleError::AlreadyExists(key)));
                    } else {
                        peers.push(config);
                        let _ = reply.send(Ok(()));
                    }
                }
                PeerManagerCommand::DeletePeer { peer, reply, .. } => {
                    let mut peers = peers.lock().await;
                    if let Some(index) = peers.iter().position(|config| {
                        PeerKey::new(config.address, config.interface.clone()) == peer
                    }) {
                        let _ = reply.send(Ok(peers.remove(index)));
                    } else {
                        let _ = reply.send(Err(PeerLifecycleError::NotFound(peer)));
                    }
                }
                PeerManagerCommand::ReconfigurePeer { config, reply } => {
                    let mut peers = peers.lock().await;
                    let _ = reply.send(fake_replace_peer_config(&mut peers, config));
                }
                PeerManagerCommand::ApplyPeerReshapeSnapshot { targets, reply } => {
                    let mut peers = peers.lock().await;
                    let _ = reply.send(fake_apply_peer_reshape_snapshot(&mut peers, targets));
                }
                PeerManagerCommand::BounceDynamicRangePeers { ranges, reply } => {
                    let signaled = ranges.len();
                    bounce_calls.lock().await.push(ranges);
                    let _ = reply.send(DynamicPeerBounceOutcome {
                        signaled,
                        failures: Vec::new(),
                    });
                }
                _ => panic!("unexpected peer-manager command in snapshot transaction test"),
            }
        }
    }

    fn fake_replace_peer_config(
        peers: &mut [PeerManagerNeighborConfig],
        config: PeerManagerNeighborConfig,
    ) -> Result<PeerManagerNeighborConfig, PeerLifecycleError> {
        let key = PeerKey::new(config.address, config.interface.clone());
        if let Some(existing) = peers
            .iter_mut()
            .find(|existing| PeerKey::new(existing.address, existing.interface.clone()) == key)
        {
            Ok(std::mem::replace(existing, config))
        } else {
            Err(PeerLifecycleError::NotFound(key))
        }
    }

    fn fake_apply_peer_reshape_snapshot(
        peers: &mut [PeerManagerNeighborConfig],
        targets: Vec<PeerManagerNeighborConfig>,
    ) -> Result<Vec<PeerManagerNeighborConfig>, PeerLifecycleError> {
        let mut seen = BTreeSet::new();
        for target in &targets {
            let key = PeerKey::new(target.address, target.interface.clone());
            if !seen.insert(key.clone()) {
                return Err(PeerLifecycleError::Invalid(format!(
                    "peer reshape target {key} appears more than once"
                )));
            }
        }
        let mut priors = Vec::with_capacity(targets.len());
        for target in targets {
            match fake_replace_peer_config(peers, target) {
                Ok(prior) => priors.push(prior),
                Err(error) => {
                    for prior in priors.into_iter().rev() {
                        let _ = fake_replace_peer_config(peers, prior);
                    }
                    return Err(error);
                }
            }
        }
        Ok(priors)
    }

    /// Like `fake_snapshot_peer_manager`, but answers each successive
    /// `PlanConfigTransaction` with the next queued plan — lets a test give
    /// the initial apply a Committable plan and the rollback re-apply a
    /// Rejected one.
    async fn fake_snapshot_peer_manager_with_plans(
        mut rx: mpsc::Receiver<PeerManagerCommand>,
        plans: Arc<Mutex<VecDeque<RuntimeConfigTransactionPlan>>>,
        snapshot_toml: Arc<Mutex<String>>,
        peers: Arc<Mutex<Vec<PeerManagerNeighborConfig>>>,
    ) {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                PeerManagerCommand::PlanConfigTransaction { reply, .. } => {
                    let plan = plans
                        .lock()
                        .await
                        .pop_front()
                        .expect("test queued too few transaction plans");
                    let _ = reply.send(Ok(plan));
                }
                PeerManagerCommand::StageConfigSnapshot {
                    candidate_toml,
                    reply,
                } => {
                    let mut snapshot = snapshot_toml.lock().await;
                    let previous = snapshot.clone();
                    *snapshot = candidate_toml;
                    let _ = reply.send(Ok(previous));
                }
                PeerManagerCommand::CommitConfigSnapshotStage { reply } => {
                    let _ = reply.send(());
                }
                PeerManagerCommand::RestoreConfigSnapshot {
                    candidate_toml,
                    reply,
                } => {
                    *snapshot_toml.lock().await = candidate_toml;
                    let _ = reply.send(Ok(()));
                }
                PeerManagerCommand::RuntimeConfigSnapshot { reply } => {
                    let _ = reply.send(Ok(rustbgpd_api::peer_types::RuntimeConfigSnapshotReply {
                        toml: snapshot_toml.lock().await.clone(),
                        rpol_files: Vec::new(),
                        rpol: rustbgpd_policy::rpol::RpolPolicySet::default(),
                    }));
                }
                PeerManagerCommand::AddPeer { config, reply, .. } => {
                    peers.lock().await.push(config);
                    let _ = reply.send(Ok(()));
                }
                _ => panic!("unexpected peer-manager command in queued-plan transaction test"),
            }
        }
    }

    async fn fake_snapshot_peer_manager_with_stage_results(
        mut rx: mpsc::Receiver<PeerManagerCommand>,
        plan: RuntimeConfigTransactionPlan,
        snapshot_toml: Arc<Mutex<String>>,
        peers: Arc<Mutex<Vec<PeerManagerNeighborConfig>>>,
        stage_results: Arc<Mutex<VecDeque<Result<(), StageConfigSnapshotError>>>>,
    ) {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                PeerManagerCommand::PlanConfigTransaction { reply, .. } => {
                    let _ = reply.send(Ok(plan.clone()));
                }
                PeerManagerCommand::StageConfigSnapshot {
                    candidate_toml,
                    reply,
                } => {
                    if let Some(result) = stage_results.lock().await.pop_front()
                        && let Err(error) = result
                    {
                        let _ = reply.send(Err(error));
                        continue;
                    }
                    let mut snapshot = snapshot_toml.lock().await;
                    let previous = snapshot.clone();
                    *snapshot = candidate_toml;
                    let _ = reply.send(Ok(previous));
                }
                PeerManagerCommand::CommitConfigSnapshotStage { reply } => {
                    let _ = reply.send(());
                }
                PeerManagerCommand::RestoreConfigSnapshot {
                    candidate_toml,
                    reply,
                } => {
                    if let Some(result) = stage_results.lock().await.pop_front()
                        && let Err(error) = result
                    {
                        let _ = reply.send(Err(error));
                        continue;
                    }
                    *snapshot_toml.lock().await = candidate_toml;
                    let _ = reply.send(Ok(()));
                }
                PeerManagerCommand::RuntimeConfigSnapshot { reply } => {
                    let _ = reply.send(Ok(rustbgpd_api::peer_types::RuntimeConfigSnapshotReply {
                        toml: snapshot_toml.lock().await.clone(),
                        rpol_files: Vec::new(),
                        rpol: rustbgpd_policy::rpol::RpolPolicySet::default(),
                    }));
                }
                PeerManagerCommand::AddPeer { config, reply, .. } => {
                    let mut peers = peers.lock().await;
                    let key = PeerKey::new(config.address, config.interface.clone());
                    if peers
                        .iter()
                        .any(|peer| PeerKey::new(peer.address, peer.interface.clone()) == key)
                    {
                        let _ = reply.send(Err(PeerLifecycleError::AlreadyExists(key)));
                    } else {
                        peers.push(config);
                        let _ = reply.send(Ok(()));
                    }
                }
                PeerManagerCommand::DeletePeer { peer, reply, .. } => {
                    let mut peers = peers.lock().await;
                    if let Some(index) = peers.iter().position(|config| {
                        PeerKey::new(config.address, config.interface.clone()) == peer
                    }) {
                        let _ = reply.send(Ok(peers.remove(index)));
                    } else {
                        let _ = reply.send(Err(PeerLifecycleError::NotFound(peer)));
                    }
                }
                PeerManagerCommand::ReconfigurePeer { config, reply } => {
                    let mut peers = peers.lock().await;
                    let key = PeerKey::new(config.address, config.interface.clone());
                    if let Some(index) = peers.iter().position(|existing| {
                        PeerKey::new(existing.address, existing.interface.clone()) == key
                    }) {
                        let previous = std::mem::replace(&mut peers[index], config);
                        let _ = reply.send(Ok(previous));
                    } else {
                        let _ = reply.send(Err(PeerLifecycleError::NotFound(key)));
                    }
                }
                _ => panic!("unexpected peer-manager command in snapshot transaction test"),
            }
        }
    }

    /// A config with one static neighbor whose import chain resolves to a
    /// named policy whose `default_action` is `action`. Diffing permit vs deny
    /// produces a pure static-neighbor policy-chain impact.
    /// Dynamic-range transaction tests use `dynamic_live_policy_toml`.
    fn live_policy_toml(action: &str) -> String {
        format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[security.grpc]
enforcement = "legacy"

[policy.definitions.f]
default_action = "{action}"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
import_policy_chain = ["f"]
"#
        )
    }

    fn dynamic_live_policy_toml(action: &str) -> String {
        format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[security.grpc]
enforcement = "legacy"

[peer_groups.ix]
import_policy_chain = ["f"]

[policy.definitions.f]
default_action = "{action}"

[[dynamic_neighbors]]
prefix = "10.30.0.9/16"
peer_group = "ix"
remote_asn = 65030
"#
        )
    }

    fn peer_group_reshape_toml(hold_time: u32) -> String {
        format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[security.grpc]
enforcement = "legacy"

[peer_groups.edge]
hold_time = {hold_time}

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "edge"
"#
        )
    }

    /// Peer group referenced only by a `[[dynamic_neighbors]]` range: a
    /// hold-time edit is a dynamic-range session reshape with no static
    /// members.
    fn dynamic_peer_group_reshape_toml(hold_time: u32) -> String {
        format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[security.grpc]
enforcement = "legacy"

[peer_groups.ix]
hold_time = {hold_time}

[[dynamic_neighbors]]
prefix = "10.30.0.0/16"
peer_group = "ix"
remote_asn = 65030
"#
        )
    }

    /// Peer group with one static member and one `[[dynamic_neighbors]]`
    /// range: a hold-time edit reshapes the static member and resets the
    /// range's live dynamic sessions.
    fn mixed_peer_group_reshape_toml(hold_time: u32) -> String {
        format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[security.grpc]
enforcement = "legacy"

[peer_groups.edge]
hold_time = {hold_time}

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "edge"

[[dynamic_neighbors]]
prefix = "10.30.0.0/16"
peer_group = "edge"
remote_asn = 65030
"#
        )
    }

    fn peer_group_reassignment_toml(group: &str) -> String {
        format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[security.grpc]
enforcement = "legacy"

[peer_groups.edge]
hold_time = 90

[peer_groups.core]
hold_time = 45

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "{group}"
"#
        )
    }

    fn resolved_static_peer_configs(toml: &str) -> Vec<PeerManagerNeighborConfig> {
        let config = Config::load_toml_with_diagnostics(toml, "peer reshape test config")
            .expect("test config must load");
        resolve_static_neighbors(&config, &config.neighbors)
            .expect("test config peers must resolve")
    }

    fn peer_session_reshape_plan() -> RuntimeConfigTransactionPlan {
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec![
                "[peer_groups] catalog".to_string(),
                "effective neighbor session reshape".to_string(),
            ],
        )
    }

    /// Fake peer manager for live-impact executor tests: serves the plan, swaps
    /// the snapshot on `StageConfigSnapshot`, and drives each policy-impact or
    /// resolved-policy apply from `apply_results` (Ok returns the next
    /// `captured_priors` entry, falling back to echoing targets when the test
    /// does not care about the returned prior payload; Err simulates a mid-fanout
    /// failure). Records static targets in `apply_calls` and dynamic selectors
    /// in `dynamic_calls`.
    async fn fake_live_policy_peer_manager(
        mut rx: mpsc::Receiver<PeerManagerCommand>,
        plan: RuntimeConfigTransactionPlan,
        snapshot_toml: Arc<Mutex<String>>,
        apply_results: Arc<Mutex<VecDeque<Result<(), String>>>>,
        captured_priors: Arc<Mutex<VecDeque<Vec<ResolvedPeerPolicy>>>>,
        apply_calls: Arc<Mutex<Vec<Vec<ResolvedPeerPolicy>>>>,
        dynamic_calls: Arc<Mutex<Vec<Vec<DynamicRangeTarget>>>>,
    ) {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                PeerManagerCommand::PlanConfigTransaction { reply, .. } => {
                    let _ = reply.send(Ok(plan.clone()));
                }
                PeerManagerCommand::StageConfigSnapshot {
                    candidate_toml,
                    reply,
                } => {
                    let mut snapshot = snapshot_toml.lock().await;
                    let previous = snapshot.clone();
                    *snapshot = candidate_toml;
                    let _ = reply.send(Ok(previous));
                }
                PeerManagerCommand::CommitConfigSnapshotStage { reply } => {
                    let _ = reply.send(());
                }
                PeerManagerCommand::RestoreConfigSnapshot {
                    candidate_toml,
                    reply,
                } => {
                    *snapshot_toml.lock().await = candidate_toml;
                    let _ = reply.send(Ok(()));
                }
                PeerManagerCommand::ApplyPolicyImpactSnapshot {
                    static_targets,
                    dynamic_ranges,
                    reply,
                } => {
                    apply_calls.lock().await.push(static_targets.clone());
                    dynamic_calls.lock().await.push(dynamic_ranges);
                    match apply_results.lock().await.pop_front().unwrap_or(Ok(())) {
                        Ok(()) => {
                            let priors = captured_priors
                                .lock()
                                .await
                                .pop_front()
                                .unwrap_or_else(|| static_targets.clone());
                            let _ = reply.send(Ok(priors));
                        }
                        Err(error) => {
                            let _ = reply.send(Err(error));
                        }
                    }
                }
                PeerManagerCommand::ApplyResolvedPolicySnapshot { targets, reply } => {
                    apply_calls.lock().await.push(targets.clone());
                    dynamic_calls.lock().await.push(Vec::new());
                    match apply_results.lock().await.pop_front().unwrap_or(Ok(())) {
                        Ok(()) => {
                            let priors = captured_priors
                                .lock()
                                .await
                                .pop_front()
                                .unwrap_or_else(|| targets.clone());
                            let _ = reply.send(Ok(priors));
                        }
                        Err(error) => {
                            let _ = reply.send(Err(error));
                        }
                    }
                }
                _ => panic!("unexpected peer-manager command in live-policy transaction test"),
            }
        }
    }

    fn deps_value(
        fib_cmd_tx: Option<mpsc::Sender<FibRuntimeCommand>>,
        peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
        config_tx: Option<mpsc::Sender<rustbgpd_api::peer_types::ConfigEvent>>,
        startup_tables: Vec<FibTableConfig>,
    ) -> FibTableControlDeps {
        FibTableControlDeps {
            fib_cmd_tx,
            peer_mgr_tx,
            config_tx,
            lock: Arc::new(Mutex::new(())),
            config_mutation_gate: None,
            startup_tables,
        }
    }

    fn deps(
        fib_cmd_tx: Option<mpsc::Sender<FibRuntimeCommand>>,
        peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
        config_tx: Option<mpsc::Sender<rustbgpd_api::peer_types::ConfigEvent>>,
        startup_tables: Vec<FibTableConfig>,
    ) -> Arc<FibTableControlDeps> {
        Arc::new(deps_value(
            fib_cmd_tx,
            peer_mgr_tx,
            config_tx,
            startup_tables,
        ))
    }

    #[tokio::test]
    async fn apply_requires_snapshot_token() {
        let (peer_tx, _peer_rx) = mpsc::channel(1);
        let err = apply_config_transaction(
            deps(None, peer_tx, None, Vec::new()),
            proto::ApplyConfigTransactionRequest {
                candidate_toml: base_toml(""),
                expected_runtime_snapshot_token: String::new(),
                client_request_id: String::new(),
                comment: String::new(),
                confirm_id: String::new(),
                confirm_timeout_seconds: 0,
            },
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, ConfigTransactionApplyError::InvalidArgument(ref message) if message.contains("expected_runtime_snapshot_token")),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn apply_rejects_cross_family_candidate_without_mutation() {
        let (peer_tx, peer_rx) = mpsc::channel(8);
        let staged = Arc::new(Mutex::new(Vec::new()));
        tokio::spawn(fake_peer_manager(
            peer_rx,
            plan(
                RuntimeConfigTransactionStatus::Committable,
                vec![
                    "[[dynamic_neighbors]]".to_string(),
                    "[[fib_tables]]".to_string(),
                ],
            ),
            staged.clone(),
        ));

        let response = apply_config_transaction(
            deps(None, peer_tx, None, Vec::new()),
            proto::ApplyConfigTransactionRequest {
                candidate_toml: base_toml(
                    r#"
[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
"#,
                ),
                expected_runtime_snapshot_token: "kv1:old:1".to_string(),
                client_request_id: String::new(),
                comment: String::new(),
                confirm_id: String::new(),
                confirm_timeout_seconds: 0,
            },
        )
        .await
        .unwrap();

        assert_eq!(
            response.status,
            proto::ConfigTransactionPlanStatus::Rejected as i32
        );
        assert!(response.committed_sections.is_empty());
        assert!(staged.lock().await.is_empty());
    }

    #[tokio::test]
    async fn apply_commits_dynamic_neighbors_full_set_after_persist_ack() {
        let previous_toml = base_toml("");
        let candidate_toml = base_toml(
            r#"
[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
remote_asn = 65010
"#,
        );
        let snapshot_toml = Arc::new(Mutex::new(previous_toml));
        let peers = Arc::new(Mutex::new(Vec::new()));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_snapshot_peer_manager(
            peer_rx,
            plan(
                RuntimeConfigTransactionStatus::Committable,
                vec!["[[dynamic_neighbors]]".to_string()],
            ),
            snapshot_toml.clone(),
            peers,
        ));
        let (config_tx, mut config_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            if let Some(ConfigEvent::ConfigTransactionCommitted {
                candidate_toml,
                ack: Some(ack),
            }) = config_rx.recv().await
            {
                assert!(candidate_toml.contains("[[dynamic_neighbors]]"));
                let _ = ack.send(Ok(()));
            }
        });

        let response = apply_config_transaction(
            deps(None, peer_tx, Some(config_tx), Vec::new()),
            proto::ApplyConfigTransactionRequest {
                candidate_toml: candidate_toml.clone(),
                expected_runtime_snapshot_token: "kv1:old:1".to_string(),
                client_request_id: String::new(),
                comment: String::new(),
                confirm_id: String::new(),
                confirm_timeout_seconds: 0,
            },
        )
        .await
        .unwrap();

        assert_eq!(
            response.status,
            proto::ConfigTransactionPlanStatus::Committable as i32
        );
        assert_eq!(response.committed_sections, vec!["[[dynamic_neighbors]]"]);
        assert_eq!(*snapshot_toml.lock().await, candidate_toml);
    }

    async fn ack_config_transaction_commits(mut config_rx: mpsc::Receiver<ConfigEvent>) {
        while let Some(ConfigEvent::ConfigTransactionCommitted { ack, .. }) = config_rx.recv().await
        {
            if let Some(ack) = ack {
                let _ = ack.send(Ok(()));
            }
        }
    }

    fn confirmed_dynamic_request(
        candidate_toml: String,
        confirm_id: &str,
        confirm_timeout_seconds: u32,
    ) -> proto::ApplyConfigTransactionRequest {
        proto::ApplyConfigTransactionRequest {
            candidate_toml,
            expected_runtime_snapshot_token: "kv1:old:1".to_string(),
            client_request_id: "deploy-1".to_string(),
            comment: "confirmed deploy".to_string(),
            confirm_id: confirm_id.to_string(),
            confirm_timeout_seconds,
        }
    }

    async fn confirmed_dynamic_controller(
        previous_toml: String,
        candidate_toml: String,
    ) -> (
        ConfigTransactionController,
        Arc<Mutex<String>>,
        tokio::task::JoinHandle<()>,
    ) {
        let snapshot_toml = Arc::new(Mutex::new(previous_toml));
        let peers = Arc::new(Mutex::new(Vec::new()));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_snapshot_peer_manager(
            peer_rx,
            plan(
                RuntimeConfigTransactionStatus::Committable,
                vec!["[[dynamic_neighbors]]".to_string()],
            ),
            snapshot_toml.clone(),
            peers,
        ));
        let (config_tx, config_rx) = mpsc::channel(8);
        let ack_task = tokio::spawn(ack_config_transaction_commits(config_rx));
        let controller = ConfigTransactionController::new(
            deps_value(None, peer_tx, Some(config_tx), Vec::new()),
            BgpMetrics::new(),
        );

        let response = controller
            .clone()
            .apply(confirmed_dynamic_request(
                candidate_toml.clone(),
                "deploy-1",
                60,
            ))
            .await
            .expect("confirmed apply must succeed");
        assert_eq!(
            response.status,
            proto::ConfigTransactionPlanStatus::Committable as i32
        );
        let confirmation = response
            .confirmation
            .as_ref()
            .expect("confirmed apply must return pending metadata");
        assert_eq!(
            confirmation.status,
            proto::ConfigTransactionConfirmationStatus::Pending as i32
        );
        assert_eq!(confirmation.confirm_id, "deploy-1");
        assert_eq!(*snapshot_toml.lock().await, candidate_toml);
        (controller, snapshot_toml, ack_task)
    }

    fn assert_snapshot_matches_config(snapshot_toml: &str, expected_toml: &str) {
        let snapshot =
            Config::load_toml_with_diagnostics(snapshot_toml, "restored runtime snapshot")
                .expect("restored snapshot must parse");
        let expected =
            Config::load_toml_with_diagnostics(expected_toml, "expected runtime snapshot")
                .expect("expected snapshot must parse");
        assert_eq!(snapshot, expected);
    }

    #[tokio::test]
    async fn confirmed_apply_enters_pending_and_confirm_clears_gate() {
        let previous_toml = base_toml("");
        let candidate_toml = base_toml(
            r#"
[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
remote_asn = 65010
"#,
        );
        let (controller, _snapshot_toml, ack_task) =
            confirmed_dynamic_controller(previous_toml, candidate_toml).await;

        let status = controller
            .clone()
            .status()
            .await
            .expect("status must succeed");
        assert_eq!(
            status.confirmation.unwrap().status,
            proto::ConfigTransactionConfirmationStatus::Pending as i32
        );
        let gate_err = controller
            .reject_if_pending("test mutation")
            .await
            .expect_err("pending confirmed transaction must block mutations");
        assert!(matches!(
            gate_err,
            ConfigTransactionApplyError::FailedPrecondition(_)
        ));

        let confirmed = controller
            .clone()
            .confirm(proto::ConfirmConfigTransactionRequest {
                confirm_id: "deploy-1".to_string(),
            })
            .await
            .expect("confirm must succeed");
        assert_eq!(
            confirmed.confirmation.unwrap().status,
            proto::ConfigTransactionConfirmationStatus::Confirmed as i32
        );
        assert_config_transaction_lifecycle_metric(&controller, "confirm", "success", 1.0);
        assert_config_transaction_lifecycle_metric(&controller, "confirm", "failure", 0.0);
        controller
            .clone()
            .auto_revert("deploy-1".to_string())
            .await
            .expect("stale timeout after confirm must be a no-op");
        let status = controller
            .clone()
            .status()
            .await
            .expect("status must succeed");
        assert_eq!(
            status.confirmation.unwrap().status,
            proto::ConfigTransactionConfirmationStatus::Confirmed as i32
        );
        controller
            .reject_if_pending("test mutation")
            .await
            .expect("confirmed transaction should release mutation gate");
        drop(controller);
        ack_task.abort();
    }

    #[tokio::test]
    async fn confirmed_abort_rolls_back_previous_snapshot() {
        let previous_toml = base_toml("");
        let candidate_toml = base_toml(
            r#"
[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
remote_asn = 65010
"#,
        );
        let (controller, snapshot_toml, ack_task) =
            confirmed_dynamic_controller(previous_toml.clone(), candidate_toml).await;

        let aborted = controller
            .clone()
            .abort(proto::AbortConfigTransactionRequest {
                confirm_id: "deploy-1".to_string(),
            })
            .await
            .expect("abort must roll back");
        assert_eq!(
            aborted.confirmation.unwrap().status,
            proto::ConfigTransactionConfirmationStatus::Aborted as i32
        );
        assert_config_transaction_lifecycle_metric(&controller, "abort", "success", 1.0);
        assert_config_transaction_lifecycle_metric(&controller, "abort", "failure", 0.0);
        assert_snapshot_matches_config(&snapshot_toml.lock().await, &previous_toml);
        ack_task.abort();
    }

    #[tokio::test]
    async fn confirmed_confirm_wrong_id_keeps_pending() {
        let previous_toml = base_toml("");
        let candidate_toml = base_toml(
            r#"
[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
remote_asn = 65010
"#,
        );
        let (controller, _snapshot_toml, ack_task) =
            confirmed_dynamic_controller(previous_toml, candidate_toml).await;

        let err = controller
            .clone()
            .confirm(proto::ConfirmConfigTransactionRequest {
                confirm_id: "wrong-id".to_string(),
            })
            .await
            .expect_err("wrong confirm_id must fail");
        assert!(
            matches!(err, ConfigTransactionApplyError::FailedPrecondition(ref message)
                if message.contains("confirmed config transaction id mismatch")),
            "{err:?}"
        );

        let status = controller.status().await.expect("status must succeed");
        let confirmation = status.confirmation.unwrap();
        assert_eq!(
            confirmation.status,
            proto::ConfigTransactionConfirmationStatus::Pending as i32
        );
        assert_eq!(confirmation.confirm_id, "deploy-1");
        assert!(
            (config_transaction_lifecycle_metric(&controller, "confirm", "failure") - 0.0).abs()
                < f64::EPSILON,
            "precondition/id-mismatch errors are not lifecycle transitions"
        );
        let gate_err = controller
            .reject_if_pending("test mutation")
            .await
            .expect_err("pending transaction must still gate mutations");
        assert!(matches!(
            gate_err,
            ConfigTransactionApplyError::FailedPrecondition(_)
        ));
        ack_task.abort();
    }

    #[tokio::test]
    async fn confirmed_apply_rejects_overlap_while_pending() {
        let previous_toml = base_toml("");
        let candidate_toml = base_toml(
            r#"
[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
remote_asn = 65010
"#,
        );
        let (controller, _snapshot_toml, ack_task) =
            confirmed_dynamic_controller(previous_toml, candidate_toml.clone()).await;

        let err = controller
            .clone()
            .apply(confirmed_dynamic_request(candidate_toml, "deploy-2", 60))
            .await
            .expect_err("second confirmed apply must fail while pending");
        assert!(
            matches!(err, ConfigTransactionApplyError::FailedPrecondition(ref message)
                if message.contains("already awaiting confirmation")),
            "{err:?}"
        );

        let status = controller.status().await.expect("status must succeed");
        let confirmation = status.confirmation.unwrap();
        assert_eq!(
            confirmation.status,
            proto::ConfigTransactionConfirmationStatus::Pending as i32
        );
        assert_eq!(confirmation.confirm_id, "deploy-1");
        ack_task.abort();
    }

    #[tokio::test]
    async fn confirmed_abort_failure_clears_pending_with_failed_record() {
        let previous_toml = base_toml("");
        let candidate_toml = base_toml(
            r#"
[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
remote_asn = 65010
"#,
        );
        let snapshot_toml = Arc::new(Mutex::new(previous_toml));
        let peers = Arc::new(Mutex::new(Vec::new()));
        let stage_results = Arc::new(Mutex::new(VecDeque::from([
            Ok(()),
            Err(StageConfigSnapshotError::InvalidCandidate(
                "stage rollback failed".to_string(),
            )),
        ])));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_snapshot_peer_manager_with_stage_results(
            peer_rx,
            plan(
                RuntimeConfigTransactionStatus::Committable,
                vec!["[[dynamic_neighbors]]".to_string()],
            ),
            snapshot_toml.clone(),
            peers,
            stage_results,
        ));
        let (config_tx, config_rx) = mpsc::channel(8);
        let ack_task = tokio::spawn(ack_config_transaction_commits(config_rx));
        let controller = ConfigTransactionController::new(
            deps_value(None, peer_tx, Some(config_tx), Vec::new()),
            BgpMetrics::new(),
        );

        controller
            .clone()
            .apply(confirmed_dynamic_request(
                candidate_toml.clone(),
                "deploy-1",
                60,
            ))
            .await
            .expect("confirmed apply must succeed");

        let err = controller
            .clone()
            .abort(proto::AbortConfigTransactionRequest {
                confirm_id: "deploy-1".to_string(),
            })
            .await
            .expect_err("abort rollback failure must be reported");
        // A rollback re-apply that fails candidate validation is an internal
        // condition (the captured snapshot is bad), not a malformed abort
        // request, so the abort surfaces INTERNAL rather than INVALID_ARGUMENT.
        assert!(
            matches!(err, ConfigTransactionApplyError::Internal(ref message)
                if message.contains("failed to abort confirmed config transaction")
                    && message.contains("rollback failed")
                    && message.contains("stage rollback failed")),
            "{err:?}"
        );

        let status = controller.status().await.expect("status must succeed");
        let confirmation = status.confirmation.unwrap();
        assert_eq!(
            confirmation.status,
            proto::ConfigTransactionConfirmationStatus::AbortFailed as i32
        );
        assert_eq!(confirmation.confirm_id, "deploy-1");
        assert_config_transaction_lifecycle_metric(&controller, "abort", "failure", 1.0);
        assert_config_transaction_lifecycle_metric(&controller, "abort", "success", 0.0);
        controller
            .reject_if_pending("test mutation")
            .await
            .expect("failed abort must clear the pending mutation gate");
        assert_snapshot_matches_config(&snapshot_toml.lock().await, &candidate_toml);
        ack_task.abort();
    }

    /// A rollback re-apply whose plan comes back `Rejected` returns `Ok`
    /// at the RPC level but commits nothing — the aborted candidate is
    /// still running. The abort must report `AbortFailed`, not record a
    /// success while the runtime still holds the unconfirmed config.
    #[tokio::test]
    async fn confirmed_abort_with_rejected_rollback_records_abort_failed() {
        let previous_toml = base_toml("");
        let candidate_toml = base_toml(
            r#"
[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
remote_asn = 65010
"#,
        );
        let snapshot_toml = Arc::new(Mutex::new(previous_toml));
        let peers = Arc::new(Mutex::new(Vec::new()));
        let plans = Arc::new(Mutex::new(VecDeque::from([
            plan(
                RuntimeConfigTransactionStatus::Committable,
                vec!["[[dynamic_neighbors]]".to_string()],
            ),
            plan(RuntimeConfigTransactionStatus::Rejected, Vec::new()),
        ])));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_snapshot_peer_manager_with_plans(
            peer_rx,
            plans,
            snapshot_toml.clone(),
            peers,
        ));
        let (config_tx, config_rx) = mpsc::channel(8);
        let ack_task = tokio::spawn(ack_config_transaction_commits(config_rx));
        let controller = ConfigTransactionController::new(
            deps_value(None, peer_tx, Some(config_tx), Vec::new()),
            BgpMetrics::new(),
        );

        controller
            .clone()
            .apply(confirmed_dynamic_request(
                candidate_toml.clone(),
                "deploy-1",
                60,
            ))
            .await
            .expect("confirmed apply must succeed");

        let err = controller
            .clone()
            .abort(proto::AbortConfigTransactionRequest {
                confirm_id: "deploy-1".to_string(),
            })
            .await
            .expect_err("a rejected rollback re-apply must fail the abort");
        assert!(
            matches!(err, ConfigTransactionApplyError::FailedPrecondition(ref message)
                if message.contains("rollback failed")
                    && message.contains("rejected")
                    && message.contains("still running")),
            "{err:?}"
        );

        let status = controller.status().await.expect("status must succeed");
        let confirmation = status.confirmation.unwrap();
        assert_eq!(
            confirmation.status,
            proto::ConfigTransactionConfirmationStatus::AbortFailed as i32
        );
        assert_config_transaction_lifecycle_metric(&controller, "abort", "failure", 1.0);
        assert_config_transaction_lifecycle_metric(&controller, "abort", "success", 0.0);
        // The candidate snapshot is untouched — the rejected rollback
        // committed nothing.
        assert_snapshot_matches_config(&snapshot_toml.lock().await, &candidate_toml);
        ack_task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn confirmed_timeout_auto_reverts_previous_snapshot() {
        let previous_toml = base_toml("");
        let candidate_toml = base_toml(
            r#"
[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
remote_asn = 65010
"#,
        );
        let snapshot_toml = Arc::new(Mutex::new(previous_toml.clone()));
        let peers = Arc::new(Mutex::new(Vec::new()));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_snapshot_peer_manager(
            peer_rx,
            plan(
                RuntimeConfigTransactionStatus::Committable,
                vec!["[[dynamic_neighbors]]".to_string()],
            ),
            snapshot_toml.clone(),
            peers,
        ));
        let (config_tx, config_rx) = mpsc::channel(8);
        let ack_task = tokio::spawn(ack_config_transaction_commits(config_rx));
        let controller = ConfigTransactionController::new(
            deps_value(None, peer_tx, Some(config_tx), Vec::new()),
            BgpMetrics::new(),
        );

        controller
            .clone()
            .apply(confirmed_dynamic_request(candidate_toml, "deploy-1", 1))
            .await
            .expect("confirmed apply must succeed");
        // Virtual time (start_paused): auto-advances past the 1s confirm
        // timeout so the spawned timer fires and runs auto-revert to completion,
        // deterministically and with no real wall-clock cost.
        tokio::time::sleep(Duration::from_millis(1_100)).await;

        let status = controller.status().await.expect("status must succeed");
        assert_eq!(
            status.confirmation.unwrap().status,
            proto::ConfigTransactionConfirmationStatus::AutoReverted as i32
        );
        assert_config_transaction_lifecycle_metric(&controller, "auto_revert", "success", 1.0);
        assert_config_transaction_lifecycle_metric(&controller, "auto_revert", "failure", 0.0);
        assert_snapshot_matches_config(&snapshot_toml.lock().await, &previous_toml);
        ack_task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn gnmi_set_rollback_duration_reset_shortens_timer() {
        let previous_toml = base_toml("");
        let candidate_toml = base_toml(
            r#"
[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
remote_asn = 65010
"#,
        );
        let (controller, snapshot_toml, ack_task) =
            confirmed_dynamic_controller(previous_toml.clone(), candidate_toml).await;

        controller
            .clone()
            .apply_gnmi_set(gnmi_set_rollback_duration("deploy-1", 1))
            .await
            .expect("rollback-duration reset must succeed");

        let status = controller.status().await.expect("status must succeed");
        let confirmation = status.confirmation.unwrap();
        assert_eq!(
            confirmation.status,
            proto::ConfigTransactionConfirmationStatus::Pending as i32
        );
        assert_eq!(confirmation.timeout_seconds, 1);

        tokio::time::sleep(Duration::from_millis(1_100)).await;

        let status = controller.status().await.expect("status must succeed");
        assert_eq!(
            status.confirmation.unwrap().status,
            proto::ConfigTransactionConfirmationStatus::AutoReverted as i32
        );
        assert_snapshot_matches_config(&snapshot_toml.lock().await, &previous_toml);
        ack_task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn gnmi_set_rollback_duration_reset_extends_timer() {
        let previous_toml = base_toml("");
        let candidate_toml = base_toml(
            r#"
[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
remote_asn = 65010
"#,
        );
        let snapshot_toml = Arc::new(Mutex::new(previous_toml));
        let peers = Arc::new(Mutex::new(Vec::new()));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_snapshot_peer_manager(
            peer_rx,
            plan(
                RuntimeConfigTransactionStatus::Committable,
                vec!["[[dynamic_neighbors]]".to_string()],
            ),
            snapshot_toml,
            peers,
        ));
        let (config_tx, config_rx) = mpsc::channel(8);
        let ack_task = tokio::spawn(ack_config_transaction_commits(config_rx));
        let controller = ConfigTransactionController::new(
            deps_value(None, peer_tx, Some(config_tx), Vec::new()),
            BgpMetrics::new(),
        );
        controller
            .clone()
            .apply(confirmed_dynamic_request(candidate_toml, "deploy-1", 1))
            .await
            .expect("confirmed apply must succeed");

        controller
            .clone()
            .apply_gnmi_set(gnmi_set_rollback_duration("deploy-1", 10))
            .await
            .expect("rollback-duration reset must succeed");
        tokio::time::sleep(Duration::from_millis(1_100)).await;

        let status = controller.status().await.expect("status must succeed");
        let confirmation = status.confirmation.unwrap();
        assert_eq!(
            confirmation.status,
            proto::ConfigTransactionConfirmationStatus::Pending as i32
        );
        assert_eq!(confirmation.timeout_seconds, 10);

        controller
            .clone()
            .apply_gnmi_set(gnmi_set_commit_confirm("deploy-1"))
            .await
            .expect("confirm after timer extension must succeed");
        ack_task.abort();
    }

    #[tokio::test]
    async fn auto_revert_failure_records_lifecycle_metric() {
        let previous_toml = base_toml("");
        let candidate_toml = base_toml(
            r#"
[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
remote_asn = 65010
"#,
        );
        let snapshot_toml = Arc::new(Mutex::new(previous_toml));
        let peers = Arc::new(Mutex::new(Vec::new()));
        let stage_results = Arc::new(Mutex::new(VecDeque::from([
            Ok(()),
            Err(StageConfigSnapshotError::InvalidCandidate(
                "stage rollback failed".to_string(),
            )),
        ])));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_snapshot_peer_manager_with_stage_results(
            peer_rx,
            plan(
                RuntimeConfigTransactionStatus::Committable,
                vec!["[[dynamic_neighbors]]".to_string()],
            ),
            snapshot_toml.clone(),
            peers,
            stage_results,
        ));
        let (config_tx, config_rx) = mpsc::channel(8);
        let ack_task = tokio::spawn(ack_config_transaction_commits(config_rx));
        let controller = ConfigTransactionController::new(
            deps_value(None, peer_tx, Some(config_tx), Vec::new()),
            BgpMetrics::new(),
        );

        controller
            .clone()
            .apply(confirmed_dynamic_request(
                candidate_toml.clone(),
                "deploy-1",
                1,
            ))
            .await
            .expect("confirmed apply must succeed");
        {
            let mut state = controller.state.lock().await;
            state
                .pending
                .as_mut()
                .expect("confirmed apply should be pending")
                .deadline = tokio::time::Instant::now();
        }
        controller
            .clone()
            .auto_revert("deploy-1".to_string())
            .await
            .expect_err("auto-revert rollback should fail");

        let status = controller.status().await.expect("status must succeed");
        let confirmation = status.confirmation.unwrap();
        assert_eq!(
            confirmation.status,
            proto::ConfigTransactionConfirmationStatus::AutoRevertFailed as i32
        );
        assert_config_transaction_lifecycle_metric(&controller, "auto_revert", "failure", 1.0);
        assert_config_transaction_lifecycle_metric(&controller, "auto_revert", "success", 0.0);
        assert_snapshot_matches_config(&snapshot_toml.lock().await, &candidate_toml);
        ack_task.abort();
    }

    #[tokio::test]
    async fn apply_commits_catalog_snapshot_after_persist_ack() {
        let previous_toml = base_toml("");
        let candidate_toml = base_toml(
            r#"
[peer_groups.prep-only]
hold_time = 120

[policy.neighbor_sets.ixp]
addresses = ["10.0.0.2"]

[policy.definitions.prep-only]
default_action = "permit"
"#,
        );
        let snapshot_toml = Arc::new(Mutex::new(previous_toml));
        let peers = Arc::new(Mutex::new(Vec::new()));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_snapshot_peer_manager(
            peer_rx,
            plan(
                RuntimeConfigTransactionStatus::Committable,
                vec![
                    "[policy] definitions".to_string(),
                    "[policy] neighbor_sets".to_string(),
                    "[peer_groups] catalog".to_string(),
                ],
            ),
            snapshot_toml.clone(),
            peers,
        ));
        let (config_tx, mut config_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            if let Some(ConfigEvent::ConfigTransactionCommitted {
                candidate_toml,
                ack: Some(ack),
            }) = config_rx.recv().await
            {
                assert!(candidate_toml.contains("[policy.definitions.prep-only]"));
                assert!(candidate_toml.contains("[peer_groups.prep-only]"));
                let _ = ack.send(Ok(()));
            }
        });

        let response = apply_config_transaction(
            deps(None, peer_tx, Some(config_tx), Vec::new()),
            proto::ApplyConfigTransactionRequest {
                candidate_toml: candidate_toml.clone(),
                expected_runtime_snapshot_token: "kv1:old:1".to_string(),
                client_request_id: String::new(),
                comment: String::new(),
                confirm_id: String::new(),
                confirm_timeout_seconds: 0,
            },
        )
        .await
        .unwrap();

        assert_eq!(
            response.status,
            proto::ConfigTransactionPlanStatus::Committable as i32
        );
        assert_eq!(
            response.committed_sections,
            vec![
                "[policy] definitions",
                "[policy] neighbor_sets",
                "[peer_groups] catalog",
            ]
        );
        assert_eq!(*snapshot_toml.lock().await, candidate_toml);
        assert!(response.human_text.contains("catalog-only"));
    }

    fn live_impact_plan() -> RuntimeConfigTransactionPlan {
        plan(
            RuntimeConfigTransactionStatus::Committable,
            vec![
                "[policy] definitions".to_string(),
                "[policy] live impact".to_string(),
            ],
        )
    }

    fn resolved_policy_targets(
        previous_toml: &str,
        candidate_toml: &str,
    ) -> Vec<ResolvedPeerPolicy> {
        let previous = Config::load_toml_with_diagnostics(previous_toml, "previous config")
            .expect("previous config must parse");
        let candidate = Config::load_toml_with_diagnostics(candidate_toml, "candidate config")
            .expect("candidate config must parse");
        resolve_live_policy_targets(&previous, &candidate)
            .expect("live policy targets must resolve")
            .static_targets
    }

    fn import_default_action(target: &ResolvedPeerPolicy) -> PolicyAction {
        target
            .import_policy
            .as_ref()
            .and_then(|chain| chain.policies.first())
            .map(|policy| policy.default_action)
            .expect("test target must carry one import policy")
    }

    fn resolved_dynamic_policy_target(toml: &str, address: &str) -> ResolvedPeerPolicy {
        let config =
            Config::load_toml_with_diagnostics(toml, "dynamic policy config").expect("valid TOML");
        let range = config
            .dynamic_neighbors
            .first()
            .expect("test config must define a dynamic range");
        let group = config
            .peer_groups
            .get(&range.peer_group)
            .expect("test config must define the range peer group");
        let address = address.parse().expect("valid test address");
        let resolved = config
            .resolve_dynamic_neighbor(
                address,
                range.remote_asn,
                "dynamic:ix",
                group,
                &range.peer_group,
            )
            .expect("dynamic policy must resolve");
        ResolvedPeerPolicy {
            address,
            interface: None,
            import_policy: resolved.import_policy,
            export_policy: resolved.export_policy,
        }
    }

    #[tokio::test]
    async fn apply_commits_live_policy_impact_after_persist_ack() {
        let previous_toml = live_policy_toml("permit");
        let candidate_toml = live_policy_toml("deny");
        let captured_priors = Arc::new(Mutex::new(VecDeque::from([resolved_policy_targets(
            &candidate_toml,
            &previous_toml,
        )])));
        let snapshot_toml = Arc::new(Mutex::new(previous_toml));
        let apply_results = Arc::new(Mutex::new(VecDeque::from([Ok(())])));
        let apply_calls = Arc::new(Mutex::new(Vec::new()));
        let dynamic_calls = Arc::new(Mutex::new(Vec::new()));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_live_policy_peer_manager(
            peer_rx,
            live_impact_plan(),
            snapshot_toml.clone(),
            apply_results,
            captured_priors,
            apply_calls.clone(),
            dynamic_calls.clone(),
        ));
        let (config_tx, mut config_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            if let Some(ConfigEvent::ConfigTransactionCommitted { ack: Some(ack), .. }) =
                config_rx.recv().await
            {
                let _ = ack.send(Ok(()));
            }
        });

        let response = apply_config_transaction(
            deps(None, peer_tx, Some(config_tx), Vec::new()),
            proto::ApplyConfigTransactionRequest {
                candidate_toml: candidate_toml.clone(),
                expected_runtime_snapshot_token: "kv1:old:1".to_string(),
                client_request_id: String::new(),
                comment: String::new(),
                confirm_id: String::new(),
                confirm_timeout_seconds: 0,
            },
        )
        .await
        .unwrap();

        assert_eq!(
            response.status,
            proto::ConfigTransactionPlanStatus::Committable as i32
        );
        assert_eq!(
            response.committed_sections,
            vec!["[policy] definitions", "[policy] live impact"]
        );
        assert_eq!(*snapshot_toml.lock().await, candidate_toml);
        assert!(response.human_text.contains("live policy-impact"));
        let calls = apply_calls.lock().await;
        assert_eq!(calls.len(), 1, "exactly one apply call");
        assert_eq!(calls[0].len(), 1, "one impacted static neighbor");
        assert_eq!(calls[0][0].address.to_string(), "10.0.0.2");
        assert_eq!(import_default_action(&calls[0][0]), PolicyAction::Deny);
        assert_eq!(
            dynamic_calls.lock().await.as_slice(),
            &[Vec::<DynamicRangeTarget>::new()],
            "static live-policy impact must not send dynamic selectors"
        );
    }

    #[tokio::test]
    async fn apply_commits_dynamic_range_live_policy_impact_after_persist_ack() {
        let previous_toml = dynamic_live_policy_toml("permit");
        let candidate_toml = dynamic_live_policy_toml("deny");
        let captured_priors = Arc::new(Mutex::new(VecDeque::from([vec![
            resolved_dynamic_policy_target(&previous_toml, "10.30.0.7"),
        ]])));
        let snapshot_toml = Arc::new(Mutex::new(previous_toml));
        let apply_results = Arc::new(Mutex::new(VecDeque::from([Ok(())])));
        let apply_calls = Arc::new(Mutex::new(Vec::new()));
        let dynamic_calls = Arc::new(Mutex::new(Vec::new()));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_live_policy_peer_manager(
            peer_rx,
            live_impact_plan(),
            snapshot_toml.clone(),
            apply_results,
            captured_priors,
            apply_calls.clone(),
            dynamic_calls.clone(),
        ));
        let (config_tx, mut config_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            if let Some(ConfigEvent::ConfigTransactionCommitted { ack: Some(ack), .. }) =
                config_rx.recv().await
            {
                let _ = ack.send(Ok(()));
            }
        });

        let response = apply_config_transaction(
            deps(None, peer_tx, Some(config_tx), Vec::new()),
            proto::ApplyConfigTransactionRequest {
                candidate_toml: candidate_toml.clone(),
                expected_runtime_snapshot_token: "kv1:old:1".to_string(),
                client_request_id: String::new(),
                comment: String::new(),
                confirm_id: String::new(),
                confirm_timeout_seconds: 0,
            },
        )
        .await
        .unwrap();

        assert_eq!(
            response.status,
            proto::ConfigTransactionPlanStatus::Committable as i32
        );
        assert_eq!(
            response.committed_sections,
            vec!["[policy] definitions", "[policy] live impact"]
        );
        assert_eq!(*snapshot_toml.lock().await, candidate_toml);
        assert!(response.human_text.contains("1 live session"));
        let calls = apply_calls.lock().await;
        assert_eq!(calls.len(), 1);
        assert!(
            calls[0].is_empty(),
            "dynamic-only live-policy impact must not send static targets"
        );
        let dynamic_calls = dynamic_calls.lock().await;
        assert_eq!(dynamic_calls.len(), 1);
        assert_eq!(dynamic_calls[0].len(), 1);
        assert_eq!(dynamic_calls[0][0].addr.to_string(), "10.30.0.0");
        assert_eq!(dynamic_calls[0][0].prefix_len, 16);
        assert_eq!(dynamic_calls[0][0].peer_group, "ix");
    }

    #[tokio::test]
    async fn apply_commits_peer_session_reshape_after_persist_ack() {
        let previous_toml = peer_group_reshape_toml(90);
        let candidate_toml = peer_group_reshape_toml(45);
        let initial_peers = resolved_static_peer_configs(&previous_toml);
        let snapshot_toml = Arc::new(Mutex::new(previous_toml));
        let peers = Arc::new(Mutex::new(initial_peers));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_snapshot_peer_manager(
            peer_rx,
            peer_session_reshape_plan(),
            snapshot_toml.clone(),
            peers.clone(),
        ));
        let (config_tx, mut config_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            if let Some(ConfigEvent::ConfigTransactionCommitted {
                candidate_toml,
                ack: Some(ack),
            }) = config_rx.recv().await
            {
                assert!(candidate_toml.contains("hold_time = 45"));
                let _ = ack.send(Ok(()));
            }
        });

        let response = apply_config_transaction(
            deps(None, peer_tx, Some(config_tx), Vec::new()),
            proto::ApplyConfigTransactionRequest {
                candidate_toml: candidate_toml.clone(),
                expected_runtime_snapshot_token: "kv1:old:1".to_string(),
                client_request_id: String::new(),
                comment: String::new(),
                confirm_id: String::new(),
                confirm_timeout_seconds: 0,
            },
        )
        .await
        .unwrap();

        assert_eq!(
            response.status,
            proto::ConfigTransactionPlanStatus::Committable as i32
        );
        assert_eq!(
            response.committed_sections,
            vec![
                "[peer_groups] catalog",
                "effective neighbor session reshape",
            ]
        );
        assert_eq!(*snapshot_toml.lock().await, candidate_toml);
        assert!(response.human_text.contains("1 live session"));
        let peers = peers.lock().await;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].hold_time, Some(45));
    }

    #[tokio::test]
    async fn apply_commits_static_peer_group_reassignment_after_persist_ack() {
        let previous_toml = peer_group_reassignment_toml("edge");
        let candidate_toml = peer_group_reassignment_toml("core");
        let initial_peers = resolved_static_peer_configs(&previous_toml);
        let snapshot_toml = Arc::new(Mutex::new(previous_toml));
        let peers = Arc::new(Mutex::new(initial_peers));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_snapshot_peer_manager(
            peer_rx,
            plan(
                RuntimeConfigTransactionStatus::Committable,
                vec![
                    "[[neighbors]] modify".to_string(),
                    "effective neighbor session reshape".to_string(),
                ],
            ),
            snapshot_toml.clone(),
            peers.clone(),
        ));
        let (config_tx, mut config_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            if let Some(ConfigEvent::ConfigTransactionCommitted {
                candidate_toml,
                ack: Some(ack),
            }) = config_rx.recv().await
            {
                assert!(candidate_toml.contains("peer_group = \"core\""));
                let _ = ack.send(Ok(()));
            }
        });

        let response = apply_config_transaction(
            deps(None, peer_tx, Some(config_tx), Vec::new()),
            proto::ApplyConfigTransactionRequest {
                candidate_toml: candidate_toml.clone(),
                expected_runtime_snapshot_token: "kv1:old:1".to_string(),
                client_request_id: String::new(),
                comment: String::new(),
                confirm_id: String::new(),
                confirm_timeout_seconds: 0,
            },
        )
        .await
        .unwrap();

        assert_eq!(
            response.status,
            proto::ConfigTransactionPlanStatus::Committable as i32
        );
        assert_eq!(
            response.committed_sections,
            vec!["[[neighbors]] modify", "effective neighbor session reshape"]
        );
        assert_eq!(*snapshot_toml.lock().await, candidate_toml);
        let peers = peers.lock().await;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].peer_group.as_deref(), Some("core"));
        assert_eq!(peers[0].hold_time, Some(45));
    }

    #[tokio::test]
    async fn apply_commits_dynamic_range_peer_group_reshape_after_persist_ack() {
        let previous_toml = dynamic_peer_group_reshape_toml(90);
        let candidate_toml = dynamic_peer_group_reshape_toml(45);
        let snapshot_toml = Arc::new(Mutex::new(previous_toml));
        let peers = Arc::new(Mutex::new(Vec::new()));
        let bounce_calls = Arc::new(Mutex::new(Vec::new()));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_snapshot_peer_manager_recording_bounces(
            peer_rx,
            peer_session_reshape_plan(),
            snapshot_toml.clone(),
            peers.clone(),
            bounce_calls.clone(),
        ));
        let (config_tx, mut config_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            if let Some(ConfigEvent::ConfigTransactionCommitted {
                candidate_toml,
                ack: Some(ack),
            }) = config_rx.recv().await
            {
                assert!(candidate_toml.contains("hold_time = 45"));
                let _ = ack.send(Ok(()));
            }
        });

        let response = apply_config_transaction(
            deps(None, peer_tx, Some(config_tx), Vec::new()),
            proto::ApplyConfigTransactionRequest {
                candidate_toml: candidate_toml.clone(),
                expected_runtime_snapshot_token: "kv1:old:1".to_string(),
                client_request_id: String::new(),
                comment: String::new(),
                confirm_id: String::new(),
                confirm_timeout_seconds: 0,
            },
        )
        .await
        .unwrap();

        assert_eq!(
            response.status,
            proto::ConfigTransactionPlanStatus::Committable as i32
        );
        assert_eq!(*snapshot_toml.lock().await, candidate_toml);
        // No static members: the reshape fan-out reconfigures nothing.
        assert!(peers.lock().await.is_empty());
        let bounce_calls = bounce_calls.lock().await;
        assert_eq!(bounce_calls.len(), 1, "{bounce_calls:?}");
        assert_eq!(bounce_calls[0].len(), 1);
        assert_eq!(bounce_calls[0][0].addr.to_string(), "10.30.0.0");
        assert_eq!(bounce_calls[0][0].prefix_len, 16);
        assert_eq!(bounce_calls[0][0].peer_group, "ix");
        assert!(
            response
                .human_text
                .contains("1 live dynamic session(s) signaled to reset"),
            "{}",
            response.human_text
        );
    }

    #[tokio::test]
    async fn apply_commits_mixed_static_and_dynamic_peer_group_reshape_after_persist_ack() {
        let previous_toml = mixed_peer_group_reshape_toml(90);
        let candidate_toml = mixed_peer_group_reshape_toml(45);
        let initial_peers = resolved_static_peer_configs(&previous_toml);
        let snapshot_toml = Arc::new(Mutex::new(previous_toml));
        let peers = Arc::new(Mutex::new(initial_peers));
        let bounce_calls = Arc::new(Mutex::new(Vec::new()));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_snapshot_peer_manager_recording_bounces(
            peer_rx,
            peer_session_reshape_plan(),
            snapshot_toml.clone(),
            peers.clone(),
            bounce_calls.clone(),
        ));
        let (config_tx, mut config_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            if let Some(ConfigEvent::ConfigTransactionCommitted {
                candidate_toml,
                ack: Some(ack),
            }) = config_rx.recv().await
            {
                assert!(candidate_toml.contains("hold_time = 45"));
                let _ = ack.send(Ok(()));
            }
        });

        let response = apply_config_transaction(
            deps(None, peer_tx, Some(config_tx), Vec::new()),
            proto::ApplyConfigTransactionRequest {
                candidate_toml: candidate_toml.clone(),
                expected_runtime_snapshot_token: "kv1:old:1".to_string(),
                client_request_id: String::new(),
                comment: String::new(),
                confirm_id: String::new(),
                confirm_timeout_seconds: 0,
            },
        )
        .await
        .unwrap();

        assert_eq!(
            response.status,
            proto::ConfigTransactionPlanStatus::Committable as i32
        );
        assert_eq!(*snapshot_toml.lock().await, candidate_toml);
        {
            let peers = peers.lock().await;
            assert_eq!(peers.len(), 1);
            assert_eq!(peers[0].hold_time, Some(45));
        }
        let bounce_calls = bounce_calls.lock().await;
        assert_eq!(bounce_calls.len(), 1, "{bounce_calls:?}");
        assert_eq!(bounce_calls[0].len(), 1);
        assert_eq!(bounce_calls[0][0].peer_group, "edge");
        assert!(
            response
                .human_text
                .contains("1 live session(s) reconfigured")
        );
        assert!(
            response
                .human_text
                .contains("1 live dynamic session(s) signaled to reset"),
            "{}",
            response.human_text
        );
    }

    #[tokio::test]
    async fn dynamic_range_peer_group_reshape_persistence_failure_skips_bounce() {
        // The dynamic reset is post-persist by contract: a failed transaction
        // must never flap a live dynamic session.
        let previous_toml = dynamic_peer_group_reshape_toml(90);
        let candidate_toml = dynamic_peer_group_reshape_toml(45);
        let snapshot_toml = Arc::new(Mutex::new(previous_toml.clone()));
        let peers = Arc::new(Mutex::new(Vec::new()));
        let bounce_calls = Arc::new(Mutex::new(Vec::new()));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_snapshot_peer_manager_recording_bounces(
            peer_rx,
            peer_session_reshape_plan(),
            snapshot_toml.clone(),
            peers.clone(),
            bounce_calls.clone(),
        ));
        let (config_tx, mut config_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            if let Some(ConfigEvent::ConfigTransactionCommitted { ack: Some(ack), .. }) =
                config_rx.recv().await
            {
                let _ = ack.send(Err("persist failed".to_string()));
            }
        });

        let err = apply_config_transaction(
            deps(None, peer_tx, Some(config_tx), Vec::new()),
            proto::ApplyConfigTransactionRequest {
                candidate_toml,
                expected_runtime_snapshot_token: "kv1:old:1".to_string(),
                client_request_id: String::new(),
                comment: String::new(),
                confirm_id: String::new(),
                confirm_timeout_seconds: 0,
            },
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, ConfigTransactionApplyError::FailedPrecondition(ref m) if m == "persist failed"),
            "{err:?}"
        );
        assert_eq!(*snapshot_toml.lock().await, previous_toml);
        assert!(
            bounce_calls.lock().await.is_empty(),
            "a failed transaction must not signal dynamic session resets"
        );
    }

    #[tokio::test]
    async fn peer_session_reshape_persistence_failure_rolls_back_live_and_snapshot() {
        let previous_toml = peer_group_reshape_toml(90);
        let candidate_toml = peer_group_reshape_toml(45);
        let initial_peers = resolved_static_peer_configs(&previous_toml);
        let snapshot_toml = Arc::new(Mutex::new(previous_toml.clone()));
        let peers = Arc::new(Mutex::new(initial_peers));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_snapshot_peer_manager(
            peer_rx,
            peer_session_reshape_plan(),
            snapshot_toml.clone(),
            peers.clone(),
        ));
        let (config_tx, mut config_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            if let Some(ConfigEvent::ConfigTransactionCommitted { ack: Some(ack), .. }) =
                config_rx.recv().await
            {
                let _ = ack.send(Err("persist failed".to_string()));
            }
        });

        let err = apply_config_transaction(
            deps(None, peer_tx, Some(config_tx), Vec::new()),
            proto::ApplyConfigTransactionRequest {
                candidate_toml,
                expected_runtime_snapshot_token: "kv1:old:1".to_string(),
                client_request_id: String::new(),
                comment: String::new(),
                confirm_id: String::new(),
                confirm_timeout_seconds: 0,
            },
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, ConfigTransactionApplyError::FailedPrecondition(ref m) if m == "persist failed"),
            "{err:?}"
        );
        assert_eq!(*snapshot_toml.lock().await, previous_toml);
        let peers = peers.lock().await;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].hold_time, Some(90));
    }

    #[tokio::test]
    async fn live_policy_impact_persistence_failure_rolls_back_live_and_snapshot() {
        let previous_toml = live_policy_toml("permit");
        let candidate_toml = live_policy_toml("deny");
        let snapshot_toml = Arc::new(Mutex::new(previous_toml.clone()));
        let captured_priors = Arc::new(Mutex::new(VecDeque::from([resolved_policy_targets(
            &candidate_toml,
            &previous_toml,
        )])));
        // commit apply succeeds; the rollback restore apply also succeeds.
        let apply_results = Arc::new(Mutex::new(VecDeque::from([Ok(()), Ok(())])));
        let apply_calls = Arc::new(Mutex::new(Vec::new()));
        let dynamic_calls = Arc::new(Mutex::new(Vec::new()));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_live_policy_peer_manager(
            peer_rx,
            live_impact_plan(),
            snapshot_toml.clone(),
            apply_results,
            captured_priors,
            apply_calls.clone(),
            dynamic_calls,
        ));
        let (config_tx, mut config_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            if let Some(ConfigEvent::ConfigTransactionCommitted { ack: Some(ack), .. }) =
                config_rx.recv().await
            {
                let _ = ack.send(Err("persist failed".to_string()));
            }
        });

        let err = apply_config_transaction(
            deps(None, peer_tx, Some(config_tx), Vec::new()),
            proto::ApplyConfigTransactionRequest {
                candidate_toml,
                expected_runtime_snapshot_token: "kv1:old:1".to_string(),
                client_request_id: String::new(),
                comment: String::new(),
                confirm_id: String::new(),
                confirm_timeout_seconds: 0,
            },
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, ConfigTransactionApplyError::FailedPrecondition(ref m) if m == "persist failed"),
            "{err:?}"
        );
        assert_eq!(
            *snapshot_toml.lock().await,
            previous_toml,
            "snapshot must roll back to the previous config"
        );
        let calls = apply_calls.lock().await;
        assert_eq!(calls.len(), 2, "commit apply + rollback restore");
        assert_eq!(
            calls[1][0].address.to_string(),
            "10.0.0.2",
            "restore re-applies the captured priors"
        );
        assert_eq!(import_default_action(&calls[0][0]), PolicyAction::Deny);
        assert_eq!(import_default_action(&calls[1][0]), PolicyAction::Permit);
    }

    #[tokio::test]
    async fn live_policy_impact_mid_fanout_failure_rolls_back_snapshot() {
        let previous_toml = live_policy_toml("permit");
        let candidate_toml = live_policy_toml("deny");
        let snapshot_toml = Arc::new(Mutex::new(previous_toml.clone()));
        // The apply itself fails; the peer-manager command self-heals its live
        // mutations, so the executor only rolls back the snapshot.
        let apply_results = Arc::new(Mutex::new(VecDeque::from([Err(
            "peer apply failed".to_string()
        )])));
        let captured_priors = Arc::new(Mutex::new(VecDeque::new()));
        let apply_calls = Arc::new(Mutex::new(Vec::new()));
        let dynamic_calls = Arc::new(Mutex::new(Vec::new()));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_live_policy_peer_manager(
            peer_rx,
            live_impact_plan(),
            snapshot_toml.clone(),
            apply_results,
            captured_priors,
            apply_calls.clone(),
            dynamic_calls,
        ));
        let (config_tx, mut config_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            // Persist should never be reached; drain the channel if it closes.
            let _ = config_rx.recv().await;
        });

        let err = apply_config_transaction(
            deps(None, peer_tx, Some(config_tx), Vec::new()),
            proto::ApplyConfigTransactionRequest {
                candidate_toml,
                expected_runtime_snapshot_token: "kv1:old:1".to_string(),
                client_request_id: String::new(),
                comment: String::new(),
                confirm_id: String::new(),
                confirm_timeout_seconds: 0,
            },
        )
        .await
        .unwrap_err();

        assert!(format!("{err}").contains("peer apply failed"), "{err:?}");
        assert_eq!(
            *snapshot_toml.lock().await,
            previous_toml,
            "snapshot must roll back after the apply failure"
        );
        let calls = apply_calls.lock().await;
        assert_eq!(
            calls.len(),
            1,
            "only the failed apply; no restore (command self-heals)"
        );
    }

    #[tokio::test]
    async fn live_policy_impact_compound_rollback_failure_reports_internal() {
        let previous_toml = live_policy_toml("permit");
        let candidate_toml = live_policy_toml("deny");
        let captured_priors = Arc::new(Mutex::new(VecDeque::from([resolved_policy_targets(
            &candidate_toml,
            &previous_toml,
        )])));
        let snapshot_toml = Arc::new(Mutex::new(previous_toml));
        // commit apply succeeds; the rollback restore apply FAILS too.
        let apply_results = Arc::new(Mutex::new(VecDeque::from([
            Ok(()),
            Err("restore failed".to_string()),
        ])));
        let apply_calls = Arc::new(Mutex::new(Vec::new()));
        let dynamic_calls = Arc::new(Mutex::new(Vec::new()));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_live_policy_peer_manager(
            peer_rx,
            live_impact_plan(),
            snapshot_toml.clone(),
            apply_results,
            captured_priors,
            apply_calls,
            dynamic_calls,
        ));
        let (config_tx, mut config_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            if let Some(ConfigEvent::ConfigTransactionCommitted { ack: Some(ack), .. }) =
                config_rx.recv().await
            {
                let _ = ack.send(Err("persist failed".to_string()));
            }
        });

        let err = apply_config_transaction(
            deps(None, peer_tx, Some(config_tx), Vec::new()),
            proto::ApplyConfigTransactionRequest {
                candidate_toml,
                expected_runtime_snapshot_token: "kv1:old:1".to_string(),
                client_request_id: String::new(),
                comment: String::new(),
                confirm_id: String::new(),
                confirm_timeout_seconds: 0,
            },
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, ConfigTransactionApplyError::Internal(_)),
            "{err:?}"
        );
        let message = format!("{err}");
        assert!(message.contains("persist failed"), "{message}");
        assert!(message.contains("live policy rollback"), "{message}");
    }

    #[tokio::test]
    async fn catalog_snapshot_persistence_failure_rolls_back_snapshot() {
        let previous_toml = base_toml("");
        let candidate_toml = base_toml(
            r#"
[policy.definitions.prep-only]
default_action = "permit"
"#,
        );
        let snapshot_toml = Arc::new(Mutex::new(previous_toml.clone()));
        let peers = Arc::new(Mutex::new(Vec::new()));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_snapshot_peer_manager(
            peer_rx,
            plan(
                RuntimeConfigTransactionStatus::Committable,
                vec!["[policy] definitions".to_string()],
            ),
            snapshot_toml.clone(),
            peers,
        ));
        let (config_tx, mut config_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            if let Some(ConfigEvent::ConfigTransactionCommitted { ack: Some(ack), .. }) =
                config_rx.recv().await
            {
                let _ = ack.send(Err("persist failed".to_string()));
            }
        });

        let err = apply_config_transaction(
            deps(None, peer_tx, Some(config_tx), Vec::new()),
            proto::ApplyConfigTransactionRequest {
                candidate_toml,
                expected_runtime_snapshot_token: "kv1:old:1".to_string(),
                client_request_id: String::new(),
                comment: String::new(),
                confirm_id: String::new(),
                confirm_timeout_seconds: 0,
            },
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, ConfigTransactionApplyError::FailedPrecondition(ref message) if message == "persist failed"),
            "{err:?}"
        );
        assert_eq!(*snapshot_toml.lock().await, previous_toml);
    }

    #[tokio::test]
    async fn dynamic_neighbor_persistence_failure_rolls_back_snapshot() {
        let previous_toml = base_toml("");
        let candidate_toml = base_toml(
            r#"
[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
"#,
        );
        let snapshot_toml = Arc::new(Mutex::new(previous_toml.clone()));
        let peers = Arc::new(Mutex::new(Vec::new()));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_snapshot_peer_manager(
            peer_rx,
            plan(
                RuntimeConfigTransactionStatus::Committable,
                vec!["[[dynamic_neighbors]]".to_string()],
            ),
            snapshot_toml.clone(),
            peers,
        ));
        let (config_tx, mut config_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            if let Some(ConfigEvent::ConfigTransactionCommitted { ack: Some(ack), .. }) =
                config_rx.recv().await
            {
                let _ = ack.send(Err("persist failed".to_string()));
            }
        });

        let err = apply_config_transaction(
            deps(None, peer_tx, Some(config_tx), Vec::new()),
            proto::ApplyConfigTransactionRequest {
                candidate_toml,
                expected_runtime_snapshot_token: "kv1:old:1".to_string(),
                client_request_id: String::new(),
                comment: String::new(),
                confirm_id: String::new(),
                confirm_timeout_seconds: 0,
            },
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, ConfigTransactionApplyError::FailedPrecondition(ref message) if message == "persist failed"),
            "{err:?}"
        );
        assert_eq!(*snapshot_toml.lock().await, previous_toml);
    }

    #[tokio::test]
    async fn persistence_failure_reports_snapshot_rollback_failure() {
        let previous_toml = base_toml("");
        let candidate_toml = base_toml(
            r#"
[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
"#,
        );
        let snapshot_toml = Arc::new(Mutex::new(previous_toml));
        let peers = Arc::new(Mutex::new(Vec::new()));
        let stage_results = Arc::new(Mutex::new(VecDeque::from([
            Ok(()),
            Err(StageConfigSnapshotError::SerializePreviousSnapshot(
                "stage rollback failed".to_string(),
            )),
        ])));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_snapshot_peer_manager_with_stage_results(
            peer_rx,
            plan(
                RuntimeConfigTransactionStatus::Committable,
                vec!["[[dynamic_neighbors]]".to_string()],
            ),
            snapshot_toml,
            peers,
            stage_results,
        ));
        let (config_tx, mut config_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            if let Some(ConfigEvent::ConfigTransactionCommitted { ack: Some(ack), .. }) =
                config_rx.recv().await
            {
                let _ = ack.send(Err("persist failed".to_string()));
            }
        });

        let err = apply_config_transaction(
            deps(None, peer_tx, Some(config_tx), Vec::new()),
            proto::ApplyConfigTransactionRequest {
                candidate_toml,
                expected_runtime_snapshot_token: "kv1:old:1".to_string(),
                client_request_id: String::new(),
                comment: String::new(),
                confirm_id: String::new(),
                confirm_timeout_seconds: 0,
            },
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, ConfigTransactionApplyError::Internal(ref message)
                if message.contains("persist failed")
                    && message.contains("snapshot rollback")
                    && message.contains("stage rollback failed")),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn apply_commits_static_neighbor_add_after_persist_ack() {
        let previous_toml = base_toml("");
        let candidate_toml = base_toml(
            r#"
[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
"#,
        );
        let snapshot_toml = Arc::new(Mutex::new(previous_toml));
        let peers = Arc::new(Mutex::new(Vec::new()));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_snapshot_peer_manager(
            peer_rx,
            plan(
                RuntimeConfigTransactionStatus::Committable,
                vec!["[[neighbors]] add".to_string()],
            ),
            snapshot_toml,
            peers.clone(),
        ));
        let (config_tx, mut config_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            if let Some(ConfigEvent::ConfigTransactionCommitted {
                candidate_toml,
                ack: Some(ack),
            }) = config_rx.recv().await
            {
                assert!(candidate_toml.contains("10.0.0.3"));
                let _ = ack.send(Ok(()));
            }
        });

        let response = apply_config_transaction(
            deps(None, peer_tx, Some(config_tx), Vec::new()),
            proto::ApplyConfigTransactionRequest {
                candidate_toml,
                expected_runtime_snapshot_token: "kv1:old:1".to_string(),
                client_request_id: String::new(),
                comment: String::new(),
                confirm_id: String::new(),
                confirm_timeout_seconds: 0,
            },
        )
        .await
        .unwrap();

        assert_eq!(
            response.status,
            proto::ConfigTransactionPlanStatus::Committable as i32
        );
        assert_eq!(response.committed_sections, vec!["[[neighbors]] add"]);
        let peers = peers.lock().await;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].address.to_string(), "10.0.0.3");
    }

    #[tokio::test]
    async fn gnmi_set_hook_commits_static_neighbor_add_through_transactions() {
        let previous_toml = base_toml("");
        let snapshot_toml = Arc::new(Mutex::new(previous_toml));
        let peers = Arc::new(Mutex::new(Vec::new()));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_snapshot_peer_manager(
            peer_rx,
            plan(
                RuntimeConfigTransactionStatus::Committable,
                vec!["[[neighbors]] add".to_string()],
            ),
            snapshot_toml.clone(),
            peers.clone(),
        ));
        let persisted = Arc::new(Mutex::new(String::new()));
        let persisted_task = Arc::clone(&persisted);
        let (config_tx, mut config_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            if let Some(ConfigEvent::ConfigTransactionCommitted {
                candidate_toml,
                ack: Some(ack),
            }) = config_rx.recv().await
            {
                *persisted_task.lock().await = candidate_toml;
                let _ = ack.send(Ok(()));
            }
        });
        let controller = ConfigTransactionController::new(
            deps_value(None, peer_tx, Some(config_tx), Vec::new()),
            BgpMetrics::new(),
        );

        controller
            .apply_gnmi_set(gnmi_set_add_neighbor("10.0.0.3", 65003))
            .await
            .unwrap();

        let peers = peers.lock().await;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].address.to_string(), "10.0.0.3");
        assert_eq!(peers[0].remote_asn, 65003);
        let persisted = persisted.lock().await;
        assert!(persisted.contains("10.0.0.3"));
        assert_eq!(*snapshot_toml.lock().await, *persisted);
    }

    #[tokio::test]
    async fn gnmi_set_hook_commits_peer_group_catalog_through_transactions() {
        let previous_toml = base_toml("");
        let snapshot_toml = Arc::new(Mutex::new(previous_toml));
        let peers = Arc::new(Mutex::new(Vec::new()));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_snapshot_peer_manager(
            peer_rx,
            plan(
                RuntimeConfigTransactionStatus::Committable,
                vec!["[peer_groups] catalog".to_string()],
            ),
            snapshot_toml.clone(),
            peers,
        ));
        let persisted = Arc::new(Mutex::new(String::new()));
        let persisted_task = Arc::clone(&persisted);
        let (config_tx, mut config_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            if let Some(ConfigEvent::ConfigTransactionCommitted {
                candidate_toml,
                ack: Some(ack),
            }) = config_rx.recv().await
            {
                *persisted_task.lock().await = candidate_toml;
                let _ = ack.send(Ok(()));
            }
        });
        let controller = ConfigTransactionController::new(
            deps_value(None, peer_tx, Some(config_tx), Vec::new()),
            BgpMetrics::new(),
        );

        controller
            .apply_gnmi_set(gnmi_set_peer_group_hold_time("rs-clients", 45))
            .await
            .unwrap();

        let persisted = persisted.lock().await;
        assert!(persisted.contains("[peer_groups.rs-clients]"));
        assert!(persisted.contains("hold_time = 45"));
        assert_eq!(*snapshot_toml.lock().await, *persisted);
    }

    #[tokio::test]
    async fn gnmi_set_hook_commits_dynamic_neighbors_through_transactions() {
        let previous_toml = base_toml(
            r"
[peer_groups.ix-members]
",
        );
        let snapshot_toml = Arc::new(Mutex::new(previous_toml));
        let peers = Arc::new(Mutex::new(Vec::new()));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_snapshot_peer_manager(
            peer_rx,
            plan(
                RuntimeConfigTransactionStatus::Committable,
                vec!["[[dynamic_neighbors]]".to_string()],
            ),
            snapshot_toml.clone(),
            peers,
        ));
        let persisted = Arc::new(Mutex::new(String::new()));
        let persisted_task = Arc::clone(&persisted);
        let (config_tx, mut config_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            if let Some(ConfigEvent::ConfigTransactionCommitted {
                candidate_toml,
                ack: Some(ack),
            }) = config_rx.recv().await
            {
                *persisted_task.lock().await = candidate_toml;
                let _ = ack.send(Ok(()));
            }
        });
        let controller = ConfigTransactionController::new(
            deps_value(None, peer_tx, Some(config_tx), Vec::new()),
            BgpMetrics::new(),
        );

        controller
            .apply_gnmi_set(gnmi_set_dynamic_neighbor("10.0.0.0/24", "ix-members"))
            .await
            .unwrap();

        let persisted = persisted.lock().await;
        assert!(persisted.contains("[[dynamic_neighbors]]"));
        assert!(persisted.contains("prefix = \"10.0.0.0/24\""));
        assert!(persisted.contains("peer_group = \"ix-members\""));
        assert!(persisted.contains("remote_asn = 0"));
        assert_eq!(*snapshot_toml.lock().await, *persisted);
    }

    #[tokio::test]
    async fn gnmi_set_commit_request_enters_confirmed_pending() {
        let previous_toml = base_toml("");
        let snapshot_toml = Arc::new(Mutex::new(previous_toml));
        let peers = Arc::new(Mutex::new(Vec::new()));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_snapshot_peer_manager(
            peer_rx,
            plan(
                RuntimeConfigTransactionStatus::Committable,
                vec!["[[neighbors]] add".to_string()],
            ),
            snapshot_toml,
            peers.clone(),
        ));
        let (config_tx, mut config_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            while let Some(ConfigEvent::ConfigTransactionCommitted { ack: Some(ack), .. }) =
                config_rx.recv().await
            {
                let _ = ack.send(Ok(()));
            }
        });
        let controller = ConfigTransactionController::new(
            deps_value(None, peer_tx, Some(config_tx), Vec::new()),
            BgpMetrics::new(),
        );

        controller
            .clone()
            .apply_gnmi_set(gnmi_set_add_neighbor_confirmed(
                "10.0.0.3",
                65003,
                "deploy-42",
                120,
            ))
            .await
            .unwrap();

        let status = controller.status().await.unwrap();
        let confirmation = status.confirmation.unwrap();
        assert_eq!(
            confirmation.status,
            proto::ConfigTransactionConfirmationStatus::Pending as i32
        );
        assert_eq!(confirmation.confirm_id, "deploy-42");
        assert_eq!(confirmation.timeout_seconds, 120);
        assert_eq!(peers.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn gnmi_set_commit_confirm_finalizes_pending_transaction() {
        let previous_toml = base_toml("");
        let snapshot_toml = Arc::new(Mutex::new(previous_toml));
        let peers = Arc::new(Mutex::new(Vec::new()));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_snapshot_peer_manager(
            peer_rx,
            plan(
                RuntimeConfigTransactionStatus::Committable,
                vec!["[[neighbors]] add".to_string()],
            ),
            snapshot_toml,
            peers,
        ));
        let (config_tx, mut config_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            while let Some(ConfigEvent::ConfigTransactionCommitted { ack: Some(ack), .. }) =
                config_rx.recv().await
            {
                let _ = ack.send(Ok(()));
            }
        });
        let controller = ConfigTransactionController::new(
            deps_value(None, peer_tx, Some(config_tx), Vec::new()),
            BgpMetrics::new(),
        );
        controller
            .clone()
            .apply_gnmi_set(gnmi_set_add_neighbor_confirmed(
                "10.0.0.3",
                65003,
                "deploy-42",
                120,
            ))
            .await
            .unwrap();

        controller
            .clone()
            .apply_gnmi_set(gnmi_set_commit_confirm("deploy-42"))
            .await
            .unwrap();

        let status = controller.status().await.unwrap();
        let confirmation = status.confirmation.unwrap();
        assert_eq!(
            confirmation.status,
            proto::ConfigTransactionConfirmationStatus::Confirmed as i32
        );
        assert_eq!(confirmation.confirm_id, "deploy-42");
    }

    #[tokio::test]
    async fn gnmi_set_commit_cancel_rolls_back_pending_transaction() {
        let previous_toml = base_toml("");
        let snapshot_toml = Arc::new(Mutex::new(previous_toml));
        let peers = Arc::new(Mutex::new(Vec::new()));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_snapshot_peer_manager(
            peer_rx,
            plan(
                RuntimeConfigTransactionStatus::Committable,
                vec!["[[neighbors]] add".to_string()],
            ),
            snapshot_toml,
            peers,
        ));
        let (config_tx, mut config_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            while let Some(ConfigEvent::ConfigTransactionCommitted { ack: Some(ack), .. }) =
                config_rx.recv().await
            {
                let _ = ack.send(Ok(()));
            }
        });
        let controller = ConfigTransactionController::new(
            deps_value(None, peer_tx, Some(config_tx), Vec::new()),
            BgpMetrics::new(),
        );
        controller
            .clone()
            .apply_gnmi_set(gnmi_set_add_neighbor_confirmed(
                "10.0.0.3",
                65003,
                "deploy-42",
                120,
            ))
            .await
            .unwrap();

        controller
            .clone()
            .apply_gnmi_set(gnmi_set_commit_cancel("deploy-42"))
            .await
            .unwrap();

        let status = controller.status().await.unwrap();
        let confirmation = status.confirmation.unwrap();
        assert_eq!(
            confirmation.status,
            proto::ConfigTransactionConfirmationStatus::Aborted as i32
        );
        assert_eq!(confirmation.confirm_id, "deploy-42");
    }

    #[tokio::test]
    async fn gnmi_set_confirm_and_cancel_validate_confirm_id() {
        let previous_toml = base_toml("");
        let snapshot_toml = Arc::new(Mutex::new(previous_toml));
        let peers = Arc::new(Mutex::new(Vec::new()));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_snapshot_peer_manager(
            peer_rx,
            plan(
                RuntimeConfigTransactionStatus::Committable,
                vec!["[[neighbors]] add".to_string()],
            ),
            snapshot_toml,
            peers,
        ));
        let controller = ConfigTransactionController::new(
            deps_value(None, peer_tx, None, Vec::new()),
            BgpMetrics::new(),
        );

        let Err(err) = controller
            .clone()
            .apply_gnmi_set(gnmi_set_commit_confirm("bad\nid"))
            .await
        else {
            panic!("malformed gNMI confirm id must reject");
        };
        assert!(matches!(
            err,
            GnmiSetError::InvalidArgument(ref message)
                if message.contains("must not contain control characters")
        ));

        let Err(err) = controller
            .apply_gnmi_set(gnmi_set_commit_cancel("bad\nid"))
            .await
        else {
            panic!("malformed gNMI cancel id must reject");
        };
        assert!(matches!(
            err,
            GnmiSetError::InvalidArgument(ref message)
                if message.contains("must not contain control characters")
        ));
    }

    #[tokio::test]
    async fn gnmi_set_rollback_duration_rejects_missing_pending_wrong_id_and_zero_timeout() {
        let controller = ConfigTransactionController::new(
            deps_value(None, mpsc::channel(1).0, None, Vec::new()),
            BgpMetrics::new(),
        );
        let Err(err) = controller
            .clone()
            .apply_gnmi_set(gnmi_set_rollback_duration("deploy-1", 120))
            .await
        else {
            panic!("rollback-duration reset without pending transaction must reject");
        };
        assert!(matches!(
            err,
            GnmiSetError::FailedPrecondition(ref message)
                if message.contains("no confirmed config transaction is pending")
        ));

        let previous_toml = base_toml("");
        let candidate_toml = base_toml(
            r#"
[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
remote_asn = 65010
"#,
        );
        let (controller, _snapshot_toml, ack_task) =
            confirmed_dynamic_controller(previous_toml, candidate_toml).await;

        let Err(err) = controller
            .clone()
            .apply_gnmi_set(gnmi_set_rollback_duration("wrong-id", 120))
            .await
        else {
            panic!("rollback-duration reset with wrong id must reject");
        };
        assert!(matches!(
            err,
            GnmiSetError::FailedPrecondition(ref message)
                if message.contains("confirmed config transaction id mismatch")
        ));

        let Err(err) = controller
            .clone()
            .apply_gnmi_set(gnmi_set_rollback_duration("deploy-1", 0))
            .await
        else {
            panic!("rollback-duration reset with zero timeout must reject");
        };
        assert!(matches!(
            err,
            GnmiSetError::InvalidArgument(ref message)
                if message.contains("confirm_timeout_seconds must be positive")
        ));

        let status = controller.status().await.expect("status must succeed");
        let confirmation = status.confirmation.unwrap();
        assert_eq!(
            confirmation.status,
            proto::ConfigTransactionConfirmationStatus::Pending as i32
        );
        assert_eq!(confirmation.timeout_seconds, 60);
        ack_task.abort();
    }

    #[tokio::test]
    async fn gnmi_set_rejects_normal_set_while_confirmed_pending() {
        let previous_toml = base_toml("");
        let snapshot_toml = Arc::new(Mutex::new(previous_toml));
        let peers = Arc::new(Mutex::new(Vec::new()));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_snapshot_peer_manager(
            peer_rx,
            plan(
                RuntimeConfigTransactionStatus::Committable,
                vec!["[[neighbors]] add".to_string()],
            ),
            snapshot_toml,
            peers,
        ));
        let (config_tx, mut config_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            while let Some(ConfigEvent::ConfigTransactionCommitted { ack: Some(ack), .. }) =
                config_rx.recv().await
            {
                let _ = ack.send(Ok(()));
            }
        });
        let controller = ConfigTransactionController::new(
            deps_value(None, peer_tx, Some(config_tx), Vec::new()),
            BgpMetrics::new(),
        );
        controller
            .clone()
            .apply_gnmi_set(gnmi_set_add_neighbor_confirmed(
                "10.0.0.3",
                65003,
                "deploy-42",
                120,
            ))
            .await
            .unwrap();

        let Err(err) = controller
            .apply_gnmi_set(gnmi_set_add_neighbor("10.0.0.4", 65004))
            .await
        else {
            panic!("normal gNMI Set must reject while confirmed transaction is pending");
        };
        assert!(matches!(
            err,
            GnmiSetError::FailedPrecondition(ref message)
                if message.contains("gnmi.gNMI/Set")
        ));
    }

    #[tokio::test]
    async fn static_neighbor_add_resolves_canonical_ipv6_address() {
        let previous_toml = base_toml("");
        let candidate_toml = base_toml(
            r#"
[[neighbors]]
address = "2001:0db8:0000:0000:0000:0000:0000:0003"
remote_asn = 65003
"#,
        );
        let snapshot_toml = Arc::new(Mutex::new(previous_toml));
        let peers = Arc::new(Mutex::new(Vec::new()));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_snapshot_peer_manager(
            peer_rx,
            plan(
                RuntimeConfigTransactionStatus::Committable,
                vec!["[[neighbors]] add".to_string()],
            ),
            snapshot_toml,
            peers.clone(),
        ));
        let (config_tx, mut config_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            if let Some(ConfigEvent::ConfigTransactionCommitted { ack: Some(ack), .. }) =
                config_rx.recv().await
            {
                let _ = ack.send(Ok(()));
            }
        });

        let response = apply_config_transaction(
            deps(None, peer_tx, Some(config_tx), Vec::new()),
            proto::ApplyConfigTransactionRequest {
                candidate_toml,
                expected_runtime_snapshot_token: "kv1:old:1".to_string(),
                client_request_id: String::new(),
                comment: String::new(),
                confirm_id: String::new(),
                confirm_timeout_seconds: 0,
            },
        )
        .await
        .unwrap();

        assert_eq!(
            response.status,
            proto::ConfigTransactionPlanStatus::Committable as i32
        );
        let peers = peers.lock().await;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].address.to_string(), "2001:db8::3");
    }

    #[tokio::test]
    async fn apply_commits_static_neighbor_modify_after_persist_ack() {
        let previous_toml = base_toml("");
        let candidate_toml =
            previous_toml.replace("remote_asn = 65002", "remote_asn = 65002\nhold_time = 45");
        let snapshot_toml = Arc::new(Mutex::new(previous_toml.clone()));
        let previous_peer = peer_config_from_toml(&previous_toml, "10.0.0.2");
        let peers = Arc::new(Mutex::new(vec![previous_peer]));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_snapshot_peer_manager(
            peer_rx,
            plan(
                RuntimeConfigTransactionStatus::Committable,
                vec!["[[neighbors]] modify".to_string()],
            ),
            snapshot_toml.clone(),
            peers.clone(),
        ));
        let (config_tx, mut config_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            if let Some(ConfigEvent::ConfigTransactionCommitted {
                candidate_toml,
                ack: Some(ack),
            }) = config_rx.recv().await
            {
                assert!(candidate_toml.contains("hold_time = 45"));
                let _ = ack.send(Ok(()));
            }
        });

        let response = apply_config_transaction(
            deps(None, peer_tx, Some(config_tx), Vec::new()),
            proto::ApplyConfigTransactionRequest {
                candidate_toml: candidate_toml.clone(),
                expected_runtime_snapshot_token: "kv1:old:1".to_string(),
                client_request_id: String::new(),
                comment: String::new(),
                confirm_id: String::new(),
                confirm_timeout_seconds: 0,
            },
        )
        .await
        .unwrap();

        assert_eq!(
            response.status,
            proto::ConfigTransactionPlanStatus::Committable as i32
        );
        assert_eq!(response.committed_sections, vec!["[[neighbors]] modify"]);
        assert_eq!(*snapshot_toml.lock().await, candidate_toml);
        let peers = peers.lock().await;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].address.to_string(), "10.0.0.2");
        assert_eq!(peers[0].hold_time, Some(45));
    }

    #[tokio::test]
    async fn static_neighbor_modify_persistence_failure_rolls_back_peer_and_snapshot() {
        let previous_toml = base_toml("");
        let candidate_toml =
            previous_toml.replace("remote_asn = 65002", "remote_asn = 65002\nhold_time = 45");
        let snapshot_toml = Arc::new(Mutex::new(previous_toml.clone()));
        let previous_peer = peer_config_from_toml(&previous_toml, "10.0.0.2");
        let peers = Arc::new(Mutex::new(vec![previous_peer.clone()]));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_snapshot_peer_manager(
            peer_rx,
            plan(
                RuntimeConfigTransactionStatus::Committable,
                vec!["[[neighbors]] modify".to_string()],
            ),
            snapshot_toml.clone(),
            peers.clone(),
        ));
        let (config_tx, mut config_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            if let Some(ConfigEvent::ConfigTransactionCommitted { ack: Some(ack), .. }) =
                config_rx.recv().await
            {
                let _ = ack.send(Err("persist failed".to_string()));
            }
        });

        let err = apply_config_transaction(
            deps(None, peer_tx, Some(config_tx), Vec::new()),
            proto::ApplyConfigTransactionRequest {
                candidate_toml,
                expected_runtime_snapshot_token: "kv1:old:1".to_string(),
                client_request_id: String::new(),
                comment: String::new(),
                confirm_id: String::new(),
                confirm_timeout_seconds: 0,
            },
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, ConfigTransactionApplyError::FailedPrecondition(ref message) if message == "persist failed"),
            "{err:?}"
        );
        assert_eq!(*snapshot_toml.lock().await, previous_toml);
        let peers = peers.lock().await;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].address, previous_peer.address);
        assert_eq!(peers[0].hold_time, previous_peer.hold_time);
    }

    #[tokio::test]
    async fn static_neighbor_mid_batch_add_failure_rolls_back_prior_add_and_snapshot() {
        let previous_toml = base_toml("");
        let candidate_toml = base_toml(
            r#"
[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003

[[neighbors]]
address = "10.0.0.4"
remote_asn = 65004
"#,
        );
        let snapshot_toml = Arc::new(Mutex::new(previous_toml.clone()));
        let peers = Arc::new(Mutex::new(vec![peer_config_from_toml(
            &candidate_toml,
            "10.0.0.4",
        )]));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_snapshot_peer_manager(
            peer_rx,
            plan(
                RuntimeConfigTransactionStatus::Committable,
                vec!["[[neighbors]] add".to_string()],
            ),
            snapshot_toml.clone(),
            peers.clone(),
        ));
        let (config_tx, _config_rx) = mpsc::channel(8);

        let err = apply_config_transaction(
            deps(None, peer_tx, Some(config_tx), Vec::new()),
            proto::ApplyConfigTransactionRequest {
                candidate_toml,
                expected_runtime_snapshot_token: "kv1:old:1".to_string(),
                client_request_id: String::new(),
                comment: String::new(),
                confirm_id: String::new(),
                confirm_timeout_seconds: 0,
            },
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, ConfigTransactionApplyError::FailedPrecondition(ref message)
                if message.contains("10.0.0.4") && message.contains("already exists")),
            "{err:?}"
        );
        assert_eq!(*snapshot_toml.lock().await, previous_toml);
        let peers = peers.lock().await;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].address.to_string(), "10.0.0.4");
    }

    #[tokio::test]
    async fn apply_commits_fib_full_set_after_persist_ack() {
        let original = table("edge", 1000);
        let replacement = table("core", 1001);
        let fib_state = Arc::new(Mutex::new(vec![original.clone()]));
        let staged = Arc::new(Mutex::new(vec![snapshot(&original)]));

        let (fib_tx, fib_rx) = mpsc::channel(8);
        tokio::spawn(fake_fib_actor(fib_rx, fib_state.clone(), None));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_peer_manager(
            peer_rx,
            plan(
                RuntimeConfigTransactionStatus::Committable,
                vec!["[[fib_tables]]".to_string()],
            ),
            staged.clone(),
        ));
        let (config_tx, mut config_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            if let Some(rustbgpd_api::peer_types::ConfigEvent::FibTablesReplaced {
                tables,
                ack: Some(ack),
            }) = config_rx.recv().await
            {
                assert_eq!(tables.len(), 1);
                assert_eq!(tables[0].name, "core");
                let _ = ack.send(Ok(()));
            }
        });

        let response = apply_config_transaction(
            deps(Some(fib_tx), peer_tx, Some(config_tx), vec![original]),
            proto::ApplyConfigTransactionRequest {
                candidate_toml: base_toml(
                    r#"
[[fib_tables]]
name = "core"
table_id = 1001
metric = 200
families = ["ipv4_unicast"]
"#,
                ),
                expected_runtime_snapshot_token: "kv1:old:1".to_string(),
                client_request_id: "deploy-1".to_string(),
                comment: "commit FIB".to_string(),
                confirm_id: String::new(),
                confirm_timeout_seconds: 0,
            },
        )
        .await
        .unwrap();

        assert_eq!(
            response.status,
            proto::ConfigTransactionPlanStatus::Committable as i32
        );
        assert_eq!(response.committed_sections, vec!["[[fib_tables]]"]);
        assert!(response.runtime_snapshot_token.starts_with("kv1:"));
        assert_eq!(*fib_state.lock().await, vec![replacement.clone()]);
        assert_eq!(*staged.lock().await, vec![snapshot(&replacement)]);
    }

    #[tokio::test]
    async fn persistence_rejection_rolls_back_fib_transaction() {
        let original = table("edge", 1000);
        let fib_state = Arc::new(Mutex::new(vec![original.clone()]));
        let staged = Arc::new(Mutex::new(vec![snapshot(&original)]));

        let (fib_tx, fib_rx) = mpsc::channel(8);
        tokio::spawn(fake_fib_actor(fib_rx, fib_state.clone(), None));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_peer_manager(
            peer_rx,
            plan(
                RuntimeConfigTransactionStatus::Committable,
                vec!["[[fib_tables]]".to_string()],
            ),
            staged.clone(),
        ));
        let (config_tx, mut config_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            if let Some(rustbgpd_api::peer_types::ConfigEvent::FibTablesReplaced {
                ack: Some(ack),
                ..
            }) = config_rx.recv().await
            {
                let _ = ack.send(Err("persist failed".to_string()));
            }
        });

        let err = apply_config_transaction(
            deps(
                Some(fib_tx),
                peer_tx,
                Some(config_tx),
                vec![original.clone()],
            ),
            proto::ApplyConfigTransactionRequest {
                candidate_toml: base_toml(
                    r#"
[[fib_tables]]
name = "core"
table_id = 1001
metric = 200
families = ["ipv4_unicast"]
"#,
                ),
                expected_runtime_snapshot_token: "kv1:old:1".to_string(),
                client_request_id: String::new(),
                comment: String::new(),
                confirm_id: String::new(),
                confirm_timeout_seconds: 0,
            },
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, ConfigTransactionApplyError::FailedPrecondition(ref message) if message == "persist failed"),
            "{err:?}"
        );
        assert_eq!(*fib_state.lock().await, vec![original.clone()]);
        assert_eq!(*staged.lock().await, vec![snapshot(&original)]);
    }

    #[test]
    fn fib_errors_map_to_apply_errors() {
        assert_eq!(
            fib_error_to_apply_error(FibTableControlError::Unavailable("busy".to_string())),
            ConfigTransactionApplyError::Unavailable("busy".to_string())
        );
    }
}
