//! Runtime `[[fib_tables]]` CRUD control (gRPC `RibService.SetFibTable` /
//! `DeleteFibTable` / `ListFibTables`).
//!
//! This is the binary-owned hook behind `RibService`'s `FibTableControlFn`.
//! It lives here, not in the API crate, because it needs the binary config
//! types, the FIB reconciler command channel (`FibRuntimeCommand`), the
//! peer-manager validator, and the config-persistence channel — none of which
//! the API crate can see across the crate boundary.
//!
//! Safety properties (see ADR-0061):
//! - **Atomic read-modify-write.** A single coordinator `Mutex`, shared with
//!   the SIGHUP reload path, is held across read (`GetTables`) → validate →
//!   apply (typed `OwnedReplaceTables`) → persist. Concurrent CRUD calls and SIGHUP FIB
//!   reloads can't interleave and clobber each other.
//! - **Validate before dispatch.** The candidate set is validated against the
//!   live config (peer-group references, reserved/duplicate ids, families, ECMP
//!   caps) by the peer manager before it ever reaches the reconciler.
//! - **Stage persistence before runtime mutation.** The exact candidate is
//!   durably staged without publication, then peer-manager and FIB actors apply
//!   it. Only a proved apply commits the stage; rejected effects restore the
//!   peer-manager snapshot, while any uncertain handoff fences the daemon.
//! - **Durable after dispatch.** The mutation runs in a detached task whose
//!   join handle the request future awaits; a canceled gRPC call cannot split a
//!   successful apply from its persistence.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use crate::config::FibTableConfig;
use crate::fib_runtime::{FibRuntimeCommand, OwnedFibReplaceOutcome};
use rustbgpd_api::health_probe::DaemonGate;
use rustbgpd_api::peer_types::ConfigPersistCommitOutcome;
use rustbgpd_api::peer_types::{
    CatalogMutationError, ConfigEvent, ConfigPersistAck, ConfigPersistError, FibTableSnapshot,
    PeerManagerCommand,
};
use rustbgpd_api::proto;
use rustbgpd_api::rib_service::{
    FibTableControlError, FibTableControlFn, FibTableControlFuture, FibTableControlRequest,
};
use rustbgpd_api::runtime_config_settlement::RuntimeConfigFenceReason;
use rustbgpd_api::runtime_config_settlement::{
    OwnedRuntimeConfigOperation, OwnedRuntimeConfigOutcome, OwnedRuntimeConfigRequestContext,
    RuntimeConfigOperationKind, RuntimeConfigSettlementPhase, RuntimeConfigSettlementWatchdog,
};
use rustbgpd_api::server::{
    ConfigMutationGateFn, RuntimeConfigCoordinator, RuntimeConfigCoordinatorClosed,
};

/// How long to wait for a config-persistence permit before refusing the
/// mutation (mirrors the dynamic-neighbor CRUD reserve deadline).
const PERSIST_RESERVE_TIMEOUT: Duration = Duration::from_secs(2);
const OWNED_FIB_ACTOR_TIMEOUT: Duration = Duration::from_mins(10);
const COORDINATOR_CLOSED: &str = "runtime config coordinator is closed";

/// Dependencies for the FIB-table control hook, wired from `main.rs`.
pub struct FibTableControlDeps {
    /// FIB reconciler command channel. `None` when the reconciler did not spawn
    /// (no `[[fib_tables]]` at startup, or non-Linux / netlink setup failure).
    pub fib_cmd_tx: Option<mpsc::Sender<FibRuntimeCommand>>,
    /// Peer-manager channel — the live-config validation authority.
    pub peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    /// RIB-manager channel, the owner of ADR-0113 outbound prefix-limit
    /// admission. `None` disables the prepared limit transaction (unit tests
    /// and non-transaction consumers of these deps).
    pub rib_tx: Option<mpsc::Sender<rustbgpd_rib::RibUpdate>>,
    /// Config-persistence channel. `None` when the control surface is wired
    /// without a persistence sink (unit tests, embedders). The daemon always
    /// loads its config from a file, so it always supplies one.
    pub config_tx: Option<mpsc::Sender<ConfigEvent>>,
    /// Coordinator lock shared with the SIGHUP reload FIB step.
    pub lock: RuntimeConfigCoordinator,
    /// Optional confirmed config transaction gate. While a confirmed
    /// transaction is applying or pending confirmation, targeted FIB-table CRUD
    /// must fail closed so it cannot be overwritten by timeout rollback.
    pub config_mutation_gate: Option<ConfigMutationGateFn>,
    /// The `[[fib_tables]]` set present at startup. When the reconciler is not
    /// running, `List` falls back to this so a non-Linux / netlink-failure
    /// daemon still shows its configured tables, and an empty set distinguishes
    /// "restart required to enable FIB" from "runtime unavailable". The set is
    /// static while the reconciler is absent (mutations are rejected and SIGHUP
    /// can't hot-apply), so it stays accurate.
    pub startup_tables: Vec<FibTableConfig>,
    /// Commit-confirm revert journal path (ADR-0076 Decision 6 durability):
    /// `<runtime_state_dir>/commit-confirm-journal.json`. Only the config
    /// transaction controller uses it; `None` disables journaling (unit tests
    /// and non-transaction consumers of these deps).
    pub confirm_journal_path: Option<std::path::PathBuf>,
    /// Applied-config history directory
    /// (`<runtime_state_dir>/config-history/`, see `config_history`). Only
    /// the config transaction controller reads it (history listing and
    /// rollback resolution); the config persister owns the writes. `None`
    /// disables history/rollback (unit tests and non-transaction consumers).
    pub config_history_dir: Option<std::path::PathBuf>,
}

struct OwnedFibControlError(FibTableControlError);

impl From<RuntimeConfigCoordinatorClosed> for OwnedFibControlError {
    fn from(_: RuntimeConfigCoordinatorClosed) -> Self {
        Self(FibTableControlError::Unavailable(COORDINATOR_CLOSED.into()))
    }
}

impl From<FibTableControlError> for OwnedFibControlError {
    fn from(error: FibTableControlError) -> Self {
        Self(error)
    }
}

/// Build the `FibTableControlFn` the RIB service calls for FIB-table CRUD.
#[must_use]
#[cfg(test)]
pub fn make_fib_table_control_fn(deps: FibTableControlDeps) -> FibTableControlFn {
    make_fib_table_control_fn_inner(deps, None)
}

/// Build the daemon's fail-stop-owned FIB-table CRUD hook.
#[must_use]
pub fn make_owned_fib_table_control_fn(
    deps: FibTableControlDeps,
    watchdog: RuntimeConfigSettlementWatchdog,
    daemon_gate: DaemonGate,
) -> FibTableControlFn {
    make_fib_table_control_fn_inner(deps, Some((watchdog, daemon_gate)))
}

fn make_fib_table_control_fn_inner(
    deps: FibTableControlDeps,
    settlement: Option<(RuntimeConfigSettlementWatchdog, DaemonGate)>,
) -> FibTableControlFn {
    let deps = Arc::new(deps);
    Arc::new(move |request| {
        let deps = deps.clone();
        let settlement = settlement.clone();
        Box::pin(async move { handle(deps, settlement, request).await }) as FibTableControlFuture
    })
}

async fn handle(
    deps: Arc<FibTableControlDeps>,
    settlement: Option<(RuntimeConfigSettlementWatchdog, DaemonGate)>,
    request: FibTableControlRequest,
) -> Result<proto::ListFibTablesResponse, FibTableControlError> {
    match request {
        FibTableControlRequest::List => {
            let _guard = deps
                .lock
                .acquire()
                .await
                .map_err(|_| FibTableControlError::Unavailable(COORDINATOR_CLOSED.into()))?;
            // A running reconciler is the source of truth; otherwise fall back
            // to the startup set so configured tables stay visible even when
            // the actor failed to spawn (non-Linux / netlink failure).
            let (tables, runtime_available) = match read_current_tables(
                deps.fib_cmd_tx.as_ref(),
                FibTableControlError::Unavailable,
            )
            .await?
            {
                Some(current) => (current, true),
                None => (deps.startup_tables.clone(), false),
            };
            Ok(proto::ListFibTablesResponse {
                tables: tables.iter().map(config_to_proto).collect(),
                runtime_available,
            })
        }
        FibTableControlRequest::Set(table) => {
            mutate(deps, settlement, Mutation::Upsert(proto_to_config(table))).await
        }
        FibTableControlRequest::Delete { name } => {
            mutate(deps, settlement, Mutation::Delete(name)).await
        }
    }
}

enum Mutation {
    Upsert(FibTableConfig),
    Delete(String),
}

impl Mutation {
    const fn operation_label(&self) -> &'static str {
        match self {
            Self::Upsert(_) => "RibService.SetFibTable",
            Self::Delete(_) => "RibService.DeleteFibTable",
        }
    }

    const fn kind(&self) -> RuntimeConfigOperationKind {
        match self {
            Self::Upsert(_) => RuntimeConfigOperationKind::FibSet,
            Self::Delete(_) => RuntimeConfigOperationKind::FibDelete,
        }
    }
}

async fn mutate(
    deps: Arc<FibTableControlDeps>,
    settlement: Option<(RuntimeConfigSettlementWatchdog, DaemonGate)>,
    mutation: Mutation,
) -> Result<proto::ListFibTablesResponse, FibTableControlError> {
    // A mutation needs a running reconciler and a persistence sink. Resolve
    // both up front so a missing one fails before we spawn the durable task.
    let fib_cmd_tx = deps
        .fib_cmd_tx
        .clone()
        .ok_or_else(|| runtime_unavailable_error(!deps.startup_tables.is_empty()))?;
    let config_tx = deps.config_tx.clone().ok_or_else(|| {
        FibTableControlError::FailedPrecondition(
            "FIB-table CRUD is unavailable: this daemon is running without config persistence"
                .to_string(),
        )
    })?;
    // Reserve before ownership. A full or closed persistence queue therefore
    // cannot strand the coordinator or create an owned mutation with no way to
    // stage its durable candidate.
    let persist_permit = reserve_persist_permit(&config_tx).await?;
    let kind = mutation.kind();
    let operation_name = mutation.operation_label();
    let peer_mgr_tx = deps.peer_mgr_tx.clone();
    let config_mutation_gate = deps.config_mutation_gate.clone();
    let body = move |owned: Option<OwnedRuntimeConfigOperation>| async move {
        owned_fib_mutation_body(
            owned,
            config_mutation_gate,
            operation_name,
            fib_cmd_tx,
            peer_mgr_tx,
            mutation,
            persist_permit,
        )
        .await
    };
    let (context, attachment) = OwnedRuntimeConfigRequestContext::unary();
    let result: Result<_, OwnedFibControlError> = if let Some((watchdog, daemon_gate)) = settlement
    {
        watchdog
            .execute_owned(
                kind,
                deps.lock.clone(),
                daemon_gate,
                context.response_attached(),
                move |operation| body(Some(operation)),
            )
            .await
    } else {
        let coordinator = deps.lock.clone();
        let join = tokio::spawn(async move {
            let _guard = coordinator.acquire().await?;
            match body(None).await {
                OwnedRuntimeConfigOutcome::CleanNoEffect(result) => result,
                OwnedRuntimeConfigOutcome::PublishedDurable(value)
                | OwnedRuntimeConfigOutcome::AcknowledgedAuthority(value) => Ok(value),
                OwnedRuntimeConfigOutcome::Fenced { error, .. } => {
                    let _ = error;
                    std::future::pending().await
                }
            }
        });
        match join.await {
            Ok(result) => result,
            Err(_) => Err(OwnedFibControlError(FibTableControlError::Internal(
                "FIB-table mutation task did not complete".to_string(),
            ))),
        }
    };
    drop(attachment);
    result.map_err(|error| error.0)
}

struct StagedFibPersistence {
    commit: oneshot::Sender<oneshot::Sender<ConfigPersistCommitOutcome>>,
}

enum StagedFibCommitOutcome {
    Settled(ConfigPersistCommitOutcome),
    NotDelivered,
    AcknowledgementLost,
}

impl StagedFibPersistence {
    async fn commit(self) -> StagedFibCommitOutcome {
        let (reply, acknowledgement) = oneshot::channel();
        // The caller is applying its runtime change. A dropped commit channel
        // means that apply failed, or the caller is gone: either way the staged
        // write must not land.
        if self.commit.send(reply).is_err() {
            return StagedFibCommitOutcome::NotDelivered;
        }
        match acknowledgement.await {
            Ok(outcome) => StagedFibCommitOutcome::Settled(outcome),
            Err(_) => StagedFibCommitOutcome::AcknowledgementLost,
        }
    }
}

enum AcceptedDispatch<T, E> {
    NotAccepted(E),
    Replied(T),
    AcceptedReplyLost(E),
}

async fn stage_fib_persistence(
    permit: mpsc::OwnedPermit<ConfigEvent>,
    snapshots: Vec<FibTableSnapshot>,
) -> Result<StagedFibPersistence, FibTableControlError> {
    let (staged_tx, staged_rx) = oneshot::channel();
    let (commit_tx, commit_rx) = oneshot::channel();
    permit.send(ConfigEvent::FibTablesReplaced {
        tables: snapshots,
        ack: Some(ConfigPersistAck::Staged {
            staged: staged_tx,
            commit: commit_rx,
        }),
    });
    match staged_rx.await {
        Ok(Ok(())) => Ok(StagedFibPersistence { commit: commit_tx }),
        Ok(Err(error)) => Err(config_persist_error(error)),
        Err(_) => Err(FibTableControlError::Internal(
            "config bridge dropped FIB-table staging acknowledgement".to_string(),
        )),
    }
}

fn config_persist_error(error: ConfigPersistError) -> FibTableControlError {
    match error {
        ConfigPersistError::Rejected(error) => match error {
            CatalogMutationError::NotFound(message) => FibTableControlError::NotFound(message),
            CatalogMutationError::Invalid(message) => {
                FibTableControlError::InvalidArgument(message)
            }
            CatalogMutationError::StillReferenced { .. }
            | CatalogMutationError::RestartRequired(_) => {
                FibTableControlError::FailedPrecondition(error.to_string())
            }
            CatalogMutationError::Internal(message) => FibTableControlError::Internal(message),
        },
        ConfigPersistError::Write(message) => FibTableControlError::FailedPrecondition(message),
    }
}

async fn stage_pm_candidate(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    snapshots: Vec<FibTableSnapshot>,
) -> AcceptedDispatch<Result<(), String>, FibTableControlError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    match tokio::time::timeout(
        OWNED_FIB_ACTOR_TIMEOUT,
        peer_mgr_tx.send(PeerManagerCommand::StageFibTables {
            tables: snapshots,
            reply: reply_tx,
        }),
    )
    .await
    {
        Err(_) => AcceptedDispatch::NotAccepted(FibTableControlError::Unavailable(
            "peer manager FIB staging queue timed out before accepting command".to_string(),
        )),
        Ok(Err(_)) => AcceptedDispatch::NotAccepted(FibTableControlError::Unavailable(
            "peer manager unavailable before accepting FIB staging command".to_string(),
        )),
        Ok(Ok(())) => match tokio::time::timeout(OWNED_FIB_ACTOR_TIMEOUT, reply_rx).await {
            Ok(Ok(result)) => AcceptedDispatch::Replied(result),
            Err(_) => AcceptedDispatch::AcceptedReplyLost(FibTableControlError::Internal(
                "peer manager accepted FIB staging but reply timed out".to_string(),
            )),
            Ok(Err(_)) => AcceptedDispatch::AcceptedReplyLost(FibTableControlError::Internal(
                "peer manager accepted FIB staging but dropped its reply".to_string(),
            )),
        },
    }
}

async fn dispatch_owned_replace(
    fib_cmd_tx: &mpsc::Sender<FibRuntimeCommand>,
    tables: Vec<FibTableConfig>,
) -> AcceptedDispatch<OwnedFibReplaceOutcome, FibTableControlError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    match tokio::time::timeout(
        OWNED_FIB_ACTOR_TIMEOUT,
        fib_cmd_tx.send(FibRuntimeCommand::OwnedReplaceTables {
            tables,
            reply: reply_tx,
        }),
    )
    .await
    {
        Err(_) => AcceptedDispatch::NotAccepted(FibTableControlError::Unavailable(
            "FIB reconciler queue timed out before accepting owned replacement".to_string(),
        )),
        Ok(Err(_)) => AcceptedDispatch::NotAccepted(FibTableControlError::Unavailable(
            "FIB reconciler unavailable before accepting owned replacement".to_string(),
        )),
        Ok(Ok(())) => match tokio::time::timeout(OWNED_FIB_ACTOR_TIMEOUT, reply_rx).await {
            Ok(Ok(outcome)) => AcceptedDispatch::Replied(outcome),
            Err(_) => AcceptedDispatch::AcceptedReplyLost(FibTableControlError::Internal(
                "FIB reconciler accepted owned replacement but reply timed out".to_string(),
            )),
            Ok(Err(_)) => AcceptedDispatch::AcceptedReplyLost(FibTableControlError::Internal(
                "FIB reconciler accepted owned replacement but dropped its reply".to_string(),
            )),
        },
    }
}

/// Typed reconciler settlement used by the config-transaction executor.
pub(crate) enum FibTransactionReplaceOutcome {
    /// The command was definitely rejected before the actor accepted it.
    NotAccepted(FibTableControlError),
    /// The actor proved the requested replacement is active.
    Applied,
    /// The actor rejected the replacement and proved it produced no effect.
    RejectedNoEffect(FibTableControlError),
    /// The actor reported a failed internal compensation.
    KnownDivergence(FibTableControlError),
    /// The actor accepted the replacement but its reply was lost.
    AcknowledgementLost(FibTableControlError),
}

/// Replace the runtime table set without collapsing accepted-reply loss into
/// the same error as a definitely rejected handoff.
pub(crate) async fn replace_tables_for_transaction(
    fib_cmd_tx: &mpsc::Sender<FibRuntimeCommand>,
    tables: Vec<FibTableConfig>,
) -> FibTransactionReplaceOutcome {
    match dispatch_owned_replace(fib_cmd_tx, tables).await {
        AcceptedDispatch::NotAccepted(error) => FibTransactionReplaceOutcome::NotAccepted(error),
        AcceptedDispatch::AcceptedReplyLost(error) => {
            FibTransactionReplaceOutcome::AcknowledgementLost(error)
        }
        AcceptedDispatch::Replied(OwnedFibReplaceOutcome::Applied) => {
            FibTransactionReplaceOutcome::Applied
        }
        AcceptedDispatch::Replied(OwnedFibReplaceOutcome::RejectedNoEffect(error)) => {
            FibTransactionReplaceOutcome::RejectedNoEffect(
                FibTableControlError::FailedPrecondition(error),
            )
        }
        AcceptedDispatch::Replied(OwnedFibReplaceOutcome::CompensationAmbiguous(error)) => {
            FibTransactionReplaceOutcome::KnownDivergence(FibTableControlError::Internal(error))
        }
    }
}

enum CompensationOutcome {
    Complete,
    KnownFailure(FibTableControlError),
    AcknowledgementLost(FibTableControlError),
}

async fn restore_pm_snapshot(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    snapshots: Vec<FibTableSnapshot>,
) -> CompensationOutcome {
    let (reply_tx, reply_rx) = oneshot::channel();
    match tokio::time::timeout(
        OWNED_FIB_ACTOR_TIMEOUT,
        peer_mgr_tx.send(PeerManagerCommand::SetFibTablesSnapshot {
            tables: snapshots,
            reply: reply_tx,
        }),
    )
    .await
    {
        Err(_) => CompensationOutcome::KnownFailure(FibTableControlError::Internal(
            "peer manager rollback queue timed out before accepting command".to_string(),
        )),
        Ok(Err(_)) => CompensationOutcome::KnownFailure(FibTableControlError::Internal(
            "peer manager unavailable during FIB snapshot rollback".to_string(),
        )),
        Ok(Ok(())) => match tokio::time::timeout(OWNED_FIB_ACTOR_TIMEOUT, reply_rx).await {
            Ok(Ok(())) => CompensationOutcome::Complete,
            Err(_) => CompensationOutcome::AcknowledgementLost(FibTableControlError::Internal(
                "peer manager accepted FIB snapshot rollback but reply timed out".to_string(),
            )),
            Ok(Err(_)) => CompensationOutcome::AcknowledgementLost(FibTableControlError::Internal(
                "peer manager accepted FIB snapshot rollback but dropped its reply".to_string(),
            )),
        },
    }
}

fn fenced_fib(
    error: FibTableControlError,
    reason: RuntimeConfigFenceReason,
) -> OwnedRuntimeConfigOutcome<proto::ListFibTablesResponse, OwnedFibControlError> {
    OwnedRuntimeConfigOutcome::Fenced {
        error: error.into(),
        reason,
    }
}

fn settle_pm_compensation(
    outcome: CompensationOutcome,
    original: FibTableControlError,
) -> OwnedRuntimeConfigOutcome<proto::ListFibTablesResponse, OwnedFibControlError> {
    match outcome {
        CompensationOutcome::Complete => {
            OwnedRuntimeConfigOutcome::CleanNoEffect(Err(original.into()))
        }
        CompensationOutcome::KnownFailure(error) => {
            fenced_fib(error, RuntimeConfigFenceReason::KnownDivergence)
        }
        CompensationOutcome::AcknowledgementLost(error) => {
            fenced_fib(error, RuntimeConfigFenceReason::AcknowledgementLost)
        }
    }
}

fn response(candidate: &[FibTableConfig]) -> proto::ListFibTablesResponse {
    proto::ListFibTablesResponse {
        tables: candidate.iter().map(config_to_proto).collect(),
        runtime_available: true,
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "linear typed settlement matrix keeps every authority transition visible"
)]
async fn owned_fib_mutation_body(
    owned: Option<OwnedRuntimeConfigOperation>,
    config_mutation_gate: Option<ConfigMutationGateFn>,
    operation_name: &'static str,
    fib_cmd_tx: mpsc::Sender<FibRuntimeCommand>,
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    mutation: Mutation,
    persist_permit: mpsc::OwnedPermit<ConfigEvent>,
) -> OwnedRuntimeConfigOutcome<proto::ListFibTablesResponse, OwnedFibControlError> {
    if let Some(gate) = config_mutation_gate
        && let Err(error) = gate(operation_name).await
    {
        return OwnedRuntimeConfigOutcome::CleanNoEffect(Err(
            FibTableControlError::FailedPrecondition(error).into(),
        ));
    }
    let previous =
        match read_current_tables(Some(&fib_cmd_tx), FibTableControlError::Internal).await {
            Ok(Some(tables)) => tables,
            Ok(None) => Vec::new(),
            Err(error) => return OwnedRuntimeConfigOutcome::CleanNoEffect(Err(error.into())),
        };
    let candidate = match apply_mutation(previous.clone(), mutation) {
        Ok(candidate) => candidate,
        Err(error) => return OwnedRuntimeConfigOutcome::CleanNoEffect(Err(error.into())),
    };
    let previous_snapshots = previous.iter().map(config_to_snapshot).collect::<Vec<_>>();
    let snapshots = candidate.iter().map(config_to_snapshot).collect::<Vec<_>>();

    if let Some(operation) = &owned {
        operation.advance_phase(RuntimeConfigSettlementPhase::Mutating);
    }
    let staged = match stage_fib_persistence(persist_permit, snapshots.clone()).await {
        Ok(staged) => staged,
        Err(error) => return OwnedRuntimeConfigOutcome::CleanNoEffect(Err(error.into())),
    };
    match stage_pm_candidate(&peer_mgr_tx, snapshots).await {
        AcceptedDispatch::NotAccepted(error) => {
            drop(staged);
            return OwnedRuntimeConfigOutcome::CleanNoEffect(Err(error.into()));
        }
        AcceptedDispatch::Replied(Err(error)) => {
            drop(staged);
            return OwnedRuntimeConfigOutcome::CleanNoEffect(Err(
                FibTableControlError::InvalidArgument(error).into(),
            ));
        }
        AcceptedDispatch::AcceptedReplyLost(error) => {
            return fenced_fib(error, RuntimeConfigFenceReason::AcknowledgementLost);
        }
        AcceptedDispatch::Replied(Ok(())) => {}
    }

    let replacement = dispatch_owned_replace(&fib_cmd_tx, candidate.clone()).await;
    match replacement {
        AcceptedDispatch::AcceptedReplyLost(error) => {
            return fenced_fib(error, RuntimeConfigFenceReason::AcknowledgementLost);
        }
        AcceptedDispatch::Replied(OwnedFibReplaceOutcome::CompensationAmbiguous(error)) => {
            return fenced_fib(
                FibTableControlError::Internal(error),
                RuntimeConfigFenceReason::KnownDivergence,
            );
        }
        AcceptedDispatch::NotAccepted(error) => {
            if let Some(operation) = &owned {
                operation.advance_phase(RuntimeConfigSettlementPhase::SettlingRollback);
            }
            drop(staged);
            return settle_pm_compensation(
                restore_pm_snapshot(&peer_mgr_tx, previous_snapshots).await,
                error,
            );
        }
        AcceptedDispatch::Replied(OwnedFibReplaceOutcome::RejectedNoEffect(error)) => {
            if let Some(operation) = &owned {
                operation.advance_phase(RuntimeConfigSettlementPhase::SettlingRollback);
            }
            drop(staged);
            return settle_pm_compensation(
                restore_pm_snapshot(&peer_mgr_tx, previous_snapshots).await,
                FibTableControlError::FailedPrecondition(error),
            );
        }
        AcceptedDispatch::Replied(OwnedFibReplaceOutcome::Applied) => {}
    }

    if let Some(operation) = &owned {
        operation.advance_phase(RuntimeConfigSettlementPhase::SettlingRollback);
    }
    match staged.commit().await {
        StagedFibCommitOutcome::Settled(ConfigPersistCommitOutcome::PublishedDurable) => {
            OwnedRuntimeConfigOutcome::PublishedDurable(response(&candidate))
        }
        StagedFibCommitOutcome::Settled(ConfigPersistCommitOutcome::PublicationAmbiguous(
            error,
        )) => fenced_fib(
            FibTableControlError::Internal(format!(
                "FIB candidate is visible but publication durability is unproved: {error}"
            )),
            RuntimeConfigFenceReason::PublicationAmbiguous,
        ),
        StagedFibCommitOutcome::AcknowledgementLost => fenced_fib(
            FibTableControlError::Internal(
                "config bridge dropped staged FIB commit acknowledgement".to_string(),
            ),
            RuntimeConfigFenceReason::AcknowledgementLost,
        ),
        StagedFibCommitOutcome::NotDelivered => {
            compensate_fib_not_published(
                &fib_cmd_tx,
                &peer_mgr_tx,
                previous,
                previous_snapshots,
                FibTableControlError::Internal(
                    "config bridge rejected staged FIB commit before delivery".to_string(),
                ),
            )
            .await
        }
        StagedFibCommitOutcome::Settled(ConfigPersistCommitOutcome::NotPublished(error)) => {
            compensate_fib_not_published(
                &fib_cmd_tx,
                &peer_mgr_tx,
                previous,
                previous_snapshots,
                FibTableControlError::FailedPrecondition(format!(
                    "FIB candidate was not published: {error}"
                )),
            )
            .await
        }
    }
}

async fn compensate_fib_not_published(
    fib_cmd_tx: &mpsc::Sender<FibRuntimeCommand>,
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    previous: Vec<FibTableConfig>,
    previous_snapshots: Vec<FibTableSnapshot>,
    original: FibTableControlError,
) -> OwnedRuntimeConfigOutcome<proto::ListFibTablesResponse, OwnedFibControlError> {
    match dispatch_owned_replace(fib_cmd_tx, previous).await {
        AcceptedDispatch::Replied(OwnedFibReplaceOutcome::Applied) => {}
        AcceptedDispatch::AcceptedReplyLost(error) => {
            return fenced_fib(error, RuntimeConfigFenceReason::AcknowledgementLost);
        }
        AcceptedDispatch::NotAccepted(error) => {
            return fenced_fib(error, RuntimeConfigFenceReason::KnownDivergence);
        }
        AcceptedDispatch::Replied(
            OwnedFibReplaceOutcome::RejectedNoEffect(error)
            | OwnedFibReplaceOutcome::CompensationAmbiguous(error),
        ) => {
            return fenced_fib(
                FibTableControlError::Internal(format!("FIB rollback failed: {error}")),
                RuntimeConfigFenceReason::KnownDivergence,
            );
        }
    }
    settle_pm_compensation(
        restore_pm_snapshot(peer_mgr_tx, previous_snapshots).await,
        original,
    )
}

/// Read the reconciler's current table set. `Ok(None)` means no reconciler is
/// running (used by `List` to report `runtime_available = false`).
pub(crate) async fn read_current_tables(
    fib_cmd_tx: Option<&mpsc::Sender<FibRuntimeCommand>>,
    actor_error: fn(String) -> FibTableControlError,
) -> Result<Option<Vec<FibTableConfig>>, FibTableControlError> {
    let Some(tx) = fib_cmd_tx else {
        return Ok(None);
    };
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(FibRuntimeCommand::GetTables { reply: reply_tx })
        .await
        .map_err(|_| actor_error("FIB reconciler command channel closed".to_string()))?;
    let tables = reply_rx
        .await
        .map_err(|_| actor_error("FIB reconciler dropped the GetTables reply".to_string()))?;
    Ok(Some(tables))
}

fn apply_mutation(
    mut current: Vec<FibTableConfig>,
    mutation: Mutation,
) -> Result<Vec<FibTableConfig>, FibTableControlError> {
    match mutation {
        Mutation::Upsert(table) => {
            if let Some(existing) = current.iter_mut().find(|t| t.name == table.name) {
                *existing = table;
            } else {
                current.push(table);
            }
            Ok(current)
        }
        Mutation::Delete(name) => {
            let before = current.len();
            current.retain(|t| t.name != name);
            if current.len() == before {
                return Err(FibTableControlError::NotFound(format!(
                    "no FIB table named '{name}'"
                )));
            }
            Ok(current)
        }
    }
}

async fn reserve_persist_permit(
    config_tx: &mpsc::Sender<ConfigEvent>,
) -> Result<mpsc::OwnedPermit<ConfigEvent>, FibTableControlError> {
    tokio::time::timeout(PERSIST_RESERVE_TIMEOUT, config_tx.clone().reserve_owned())
        .await
        .map_err(|_| {
            FibTableControlError::Unavailable(
                "config persistence queue busy — refusing mutation to avoid drift".to_string(),
            )
        })?
        .map_err(|_| {
            FibTableControlError::Unavailable("config persistence unavailable".to_string())
        })
}

pub(crate) fn runtime_unavailable_error(startup_had_tables: bool) -> FibTableControlError {
    if startup_had_tables {
        FibTableControlError::FailedPrecondition(
            "the FIB reconciler is unavailable (it did not spawn at startup — non-Linux platform \
             or netlink setup failure); restart rustbgpd to apply [[fib_tables]] edits"
                .to_string(),
        )
    } else {
        FibTableControlError::FailedPrecondition(
            "no [[fib_tables]] were present at startup, so the FIB reconciler is not running; add \
             a table to the config and restart rustbgpd to start it"
                .to_string(),
        )
    }
}

fn proto_to_config(table: proto::FibTableConfig) -> FibTableConfig {
    // An empty `families` repeated field is indistinguishable from "omitted"
    // (proto3 has no presence on repeated), so mirror the TOML default of both
    // unicast families rather than letting validation reject an empty set.
    let families = if table.families.is_empty() {
        crate::config::default_fib_families()
    } else {
        table.families
    };
    FibTableConfig {
        name: table.name,
        table_id: table.table_id,
        metric: table.metric,
        families,
        allowed_peer_groups: table.allowed_peer_groups,
        allowed_neighbors: table.allowed_neighbors,
        max_routes: table.max_routes,
        maximum_paths: table.maximum_paths,
        maximum_paths_ebgp: table.maximum_paths_ebgp,
        maximum_paths_ibgp: table.maximum_paths_ibgp,
    }
}

fn config_to_proto(table: &FibTableConfig) -> proto::FibTableConfig {
    proto::FibTableConfig {
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

fn config_to_snapshot(table: &FibTableConfig) -> FibTableSnapshot {
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

#[cfg(test)]
mod tests {
    use super::*;
    use rustbgpd_api::peer_types::PeerManagerCommand;
    use rustbgpd_api::proto::rib_service_server::RibService as _;
    use rustbgpd_api::rib_service::RibService;
    use rustbgpd_api::server::AccessMode;
    use tokio::sync::Mutex;
    use tonic::{Code, Request, Status};

    use crate::test_support::basic_fib_table as table;

    #[derive(Clone, Copy)]
    enum ReadFailure {
        SendClosed,
        ReplyDropped,
    }

    #[derive(Clone, Copy)]
    enum MutationRpc {
        Set,
        Delete,
    }

    impl MutationRpc {
        async fn call(self, service: &RibService) -> Result<(), Status> {
            match self {
                Self::Set => service
                    .set_fib_table(Request::new(proto::SetFibTableRequest {
                        table: Some(config_to_proto(&table("core", 1001))),
                    }))
                    .await
                    .map(|_| ()),
                Self::Delete => service
                    .delete_fib_table(Request::new(proto::DeleteFibTableRequest {
                        name: "edge".to_string(),
                    }))
                    .await
                    .map(|_| ()),
            }
        }
    }

    fn failing_fib_actor(
        first_reply: Option<Vec<FibTableConfig>>,
        failure: ReadFailure,
    ) -> mpsc::Sender<FibRuntimeCommand> {
        let (tx, mut rx) = mpsc::channel(2);
        if first_reply.is_none() && matches!(failure, ReadFailure::SendClosed) {
            drop(rx);
            return tx;
        }
        tokio::spawn(async move {
            if let Some(tables) = first_reply {
                let Some(FibRuntimeCommand::GetTables { reply }) = rx.recv().await else {
                    panic!("expected initial GetTables")
                };
                reply.send(tables).expect("caller awaits initial roster");
            }
            match failure {
                ReadFailure::SendClosed => drop(rx),
                ReadFailure::ReplyDropped => {
                    let Some(FibRuntimeCommand::GetTables { reply }) = rx.recv().await else {
                        panic!("expected failing GetTables")
                    };
                    drop(reply);
                }
            }
        });
        tx
    }

    fn rpc_service(
        fib_cmd_tx: Option<mpsc::Sender<FibRuntimeCommand>>,
        startup_tables: Vec<FibTableConfig>,
    ) -> RibService {
        let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel(1);
        tokio::spawn(async move {
            if let Some(command) = peer_mgr_rx.recv().await {
                let PeerManagerCommand::StageFibTables { reply, .. } = command else {
                    panic!("actor-read test reached an unexpected peer-manager command")
                };
                let _ = reply.send(Err(
                    "unexpected peer-manager staging in FIB actor-read test".to_string(),
                ));
            }
        });
        let (config_tx, mut config_rx) = mpsc::channel(1);
        tokio::spawn(async move {
            assert!(
                config_rx.recv().await.is_none(),
                "actor-read test unexpectedly reached persistence"
            );
        });
        let control = make_fib_table_control_fn(FibTableControlDeps {
            fib_cmd_tx,
            peer_mgr_tx,
            rib_tx: None,
            config_tx: Some(config_tx),
            lock: RuntimeConfigCoordinator::new(),
            config_mutation_gate: None,
            startup_tables,
            confirm_journal_path: None,
            config_history_dir: None,
        });
        let (rib_tx, _rib_rx) = mpsc::channel(1);
        RibService::with_status_snapshots(rib_tx, Arc::new(Vec::new), Arc::new(Vec::new))
            .with_fib_table_control(AccessMode::ReadWrite, Some(control))
    }

    #[tokio::test]
    async fn closed_coordinator_rejects_fib_before_actor_or_persistence() {
        let (fib_tx, mut fib_rx) = mpsc::channel(1);
        let (peer_tx, mut peer_rx) = mpsc::channel(1);
        let (config_tx, mut config_rx) = mpsc::channel(1);
        let coordinator = RuntimeConfigCoordinator::new();
        coordinator.close();
        let deps = Arc::new(FibTableControlDeps {
            fib_cmd_tx: Some(fib_tx),
            peer_mgr_tx: peer_tx,
            rib_tx: None,
            config_tx: Some(config_tx),
            lock: coordinator,
            config_mutation_gate: None,
            startup_tables: vec![table("edge", 1000)],
            confirm_journal_path: None,
            config_history_dir: None,
        });

        let list_error = handle(deps.clone(), None, FibTableControlRequest::List)
            .await
            .unwrap_err();
        assert!(matches!(list_error, FibTableControlError::Unavailable(_)));
        let set_error = mutate(deps.clone(), None, Mutation::Upsert(table("core", 1001)))
            .await
            .unwrap_err();
        assert!(matches!(set_error, FibTableControlError::Unavailable(_)));
        assert!(matches!(
            fib_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        assert!(matches!(
            peer_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        assert!(matches!(
            config_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    fn assert_actor_read_error(status: &Status, code: Code, failure: ReadFailure) {
        let expected = match failure {
            ReadFailure::SendClosed => "FIB reconciler command channel closed",
            ReadFailure::ReplyDropped => "FIB reconciler dropped the GetTables reply",
        };
        assert_eq!(status.message(), expected);
        assert_eq!(status.code(), code);
    }

    #[tokio::test]
    async fn list_fib_tables_actor_read_outages_are_unavailable() {
        for failure in [ReadFailure::SendClosed, ReadFailure::ReplyDropped] {
            let status = rpc_service(Some(failing_fib_actor(None, failure)), vec![])
                .list_fib_tables(Request::new(proto::ListFibTablesRequest {}))
                .await
                .unwrap_err();
            assert_actor_read_error(&status, Code::Unavailable, failure);
        }
    }

    #[tokio::test]
    async fn fib_table_mutation_initial_reads_remain_internal() {
        for rpc in [MutationRpc::Set, MutationRpc::Delete] {
            for failure in [ReadFailure::SendClosed, ReadFailure::ReplyDropped] {
                let status = rpc
                    .call(&rpc_service(Some(failing_fib_actor(None, failure)), vec![]))
                    .await
                    .unwrap_err();
                assert_actor_read_error(&status, Code::Internal, failure);
            }
        }
    }

    #[tokio::test]
    async fn list_fib_tables_preserves_hook_internal_error() {
        let control: FibTableControlFn = Arc::new(|_| {
            Box::pin(async {
                Err(FibTableControlError::Internal(
                    "sentinel hook failure".to_string(),
                ))
            })
        });
        let (rib_tx, _rib_rx) = mpsc::channel(1);
        let status =
            RibService::with_status_snapshots(rib_tx, Arc::new(Vec::new), Arc::new(Vec::new))
                .with_fib_table_control(AccessMode::ReadWrite, Some(control))
                .list_fib_tables(Request::new(proto::ListFibTablesRequest {}))
                .await
                .unwrap_err();
        assert_eq!(status.code(), Code::Internal);
        assert_eq!(status.message(), "sentinel hook failure");
    }

    #[tokio::test]
    async fn list_fib_tables_without_actor_returns_startup_snapshot() {
        let response = rpc_service(None, vec![table("edge", 1000)])
            .list_fib_tables(Request::new(proto::ListFibTablesRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(!response.runtime_available);
        assert_eq!(response.tables, [config_to_proto(&table("edge", 1000))]);
    }

    #[tokio::test]
    async fn persistence_stage_write_failure_precedes_runtime_and_snapshot() {
        let original = table("edge", 1000);
        let original_snapshot = config_to_snapshot(&original);

        let fib_state = Arc::new(Mutex::new(vec![original.clone()]));
        let fib_state_for_task = fib_state.clone();
        let (fib_tx, mut fib_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            while let Some(cmd) = fib_rx.recv().await {
                match cmd {
                    FibRuntimeCommand::GetTables { reply } => {
                        let _ = reply.send(fib_state_for_task.lock().await.clone());
                    }
                    FibRuntimeCommand::OwnedReplaceTables { tables, reply } => {
                        *fib_state_for_task.lock().await = tables;
                        let _ = reply.send(OwnedFibReplaceOutcome::Applied);
                    }
                }
            }
        });

        let peer_snapshot = Arc::new(Mutex::new(vec![original_snapshot.clone()]));
        let peer_snapshot_for_task = peer_snapshot.clone();
        let (peer_tx, mut peer_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            while let Some(cmd) = peer_rx.recv().await {
                match cmd {
                    PeerManagerCommand::StageFibTables { tables, reply } => {
                        *peer_snapshot_for_task.lock().await = tables;
                        let _ = reply.send(Ok(()));
                    }
                    PeerManagerCommand::SetFibTablesSnapshot { tables, reply } => {
                        *peer_snapshot_for_task.lock().await = tables;
                        let _ = reply.send(());
                    }
                    _ => panic!("unexpected peer-manager command in FIB control test"),
                }
            }
        });

        let (config_tx, mut config_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            if let Some(ConfigEvent::FibTablesReplaced { ack: Some(ack), .. }) =
                config_rx.recv().await
            {
                ack.fail_write("desired config validation failed");
            }
        });

        let deps = Arc::new(FibTableControlDeps {
            fib_cmd_tx: Some(fib_tx),
            peer_mgr_tx: peer_tx,
            rib_tx: None,
            config_tx: Some(config_tx),
            lock: RuntimeConfigCoordinator::new(),
            config_mutation_gate: None,
            startup_tables: vec![original.clone()],
            confirm_journal_path: None,
            config_history_dir: None,
        });
        let err = mutate(deps, None, Mutation::Upsert(table("core", 1001)))
            .await
            .expect_err("persistence rejection must fail the mutation");
        assert!(
            matches!(err, FibTableControlError::FailedPrecondition(ref message) if message == "desired config validation failed"),
            "{err:?}"
        );
        assert_eq!(*fib_state.lock().await, vec![original]);
        assert_eq!(*peer_snapshot.lock().await, vec![original_snapshot]);
    }

    #[tokio::test(start_paused = true)]
    async fn persistence_reserve_closed_and_timeout_are_clean_preownership_failures() {
        let (closed_tx, closed_rx) = mpsc::channel(1);
        drop(closed_rx);
        assert!(matches!(
            reserve_persist_permit(&closed_tx).await,
            Err(FibTableControlError::Unavailable(ref message))
                if message == "config persistence unavailable"
        ));

        let (busy_tx, _busy_rx) = mpsc::channel(1);
        let _held = busy_tx.clone().reserve_owned().await.unwrap();
        let waiter = tokio::spawn(async move { reserve_persist_permit(&busy_tx).await });
        tokio::time::advance(PERSIST_RESERVE_TIMEOUT).await;
        assert!(matches!(
            waiter.await.unwrap(),
            Err(FibTableControlError::Unavailable(ref message)) if message.contains("queue busy")
        ));
    }

    #[tokio::test]
    async fn persistence_stage_rejection_and_ack_loss_are_typed_clean_failures() {
        for drop_ack in [false, true] {
            let (tx, mut rx) = mpsc::channel(1);
            let permit = tx.clone().reserve_owned().await.unwrap();
            tokio::spawn(async move {
                let ConfigEvent::FibTablesReplaced { ack: Some(ack), .. } =
                    rx.recv().await.unwrap()
                else {
                    panic!("expected staged FIB event")
                };
                if drop_ack {
                    drop(ack);
                } else {
                    let ConfigPersistAck::Staged { staged, .. } = ack else {
                        panic!("expected staged FIB acknowledgement")
                    };
                    let _ = staged.send(Err(ConfigPersistError::Rejected(
                        CatalogMutationError::invalid("invalid staged FIB candidate"),
                    )));
                }
            });
            let Err(error) = stage_fib_persistence(permit, Vec::new()).await else {
                panic!("stage failure must not return a commit handle");
            };
            assert!(matches!(error, FibTableControlError::InvalidArgument(_)) || drop_ack);
            if drop_ack {
                assert!(matches!(error, FibTableControlError::Internal(_)));
            }
        }
    }

    #[tokio::test]
    async fn peer_manager_stage_distinguishes_send_nack_and_accepted_reply_loss() {
        let (closed_tx, closed_rx) = mpsc::channel(1);
        drop(closed_rx);
        assert!(matches!(
            stage_pm_candidate(&closed_tx, Vec::new()).await,
            AcceptedDispatch::NotAccepted(_)
        ));

        for drop_reply in [false, true] {
            let (tx, mut rx) = mpsc::channel(1);
            tokio::spawn(async move {
                let PeerManagerCommand::StageFibTables { reply, .. } = rx.recv().await.unwrap()
                else {
                    panic!("expected StageFibTables")
                };
                if drop_reply {
                    drop(reply);
                } else {
                    let _ = reply.send(Err("candidate rejected".to_string()));
                }
            });
            let outcome = stage_pm_candidate(&tx, Vec::new()).await;
            if drop_reply {
                assert!(matches!(outcome, AcceptedDispatch::AcceptedReplyLost(_)));
            } else {
                assert!(matches!(outcome, AcceptedDispatch::Replied(Err(_))));
            }
        }
    }

    #[derive(Clone, Copy)]
    enum CommitBehavior {
        Applied,
        Rejected,
        PublicationAmbiguous,
        AckLost,
        HandoffLost,
    }

    #[derive(Clone)]
    enum FibBehavior {
        Reply(OwnedFibReplaceOutcome),
        ReplyLost,
    }

    type PersistOutcome = ConfigPersistCommitOutcome;

    async fn run_owned_body(
        fib_behavior: FibBehavior,
        commit_behavior: CommitBehavior,
        rollback_ack: bool,
    ) -> (
        OwnedRuntimeConfigOutcome<proto::ListFibTablesResponse, OwnedFibControlError>,
        usize,
    ) {
        let original = table("edge", 1000);
        let candidate = table("core", 1001);
        let (config_tx, mut config_rx) = mpsc::channel(1);
        let permit = config_tx.reserve_owned().await.unwrap();
        tokio::spawn(async move {
            let ConfigEvent::FibTablesReplaced { ack: Some(ack), .. } =
                config_rx.recv().await.unwrap()
            else {
                panic!("expected staged FIB event")
            };
            let ConfigPersistAck::Staged { staged, commit } = ack else {
                panic!("expected staged FIB persistence")
            };
            staged.send(Ok(())).unwrap();
            if matches!(commit_behavior, CommitBehavior::HandoffLost) {
                drop(commit);
                return;
            }
            let Ok(reply) = commit.await else { return };
            match commit_behavior {
                CommitBehavior::Applied => reply.send(PersistOutcome::PublishedDurable).unwrap(),
                CommitBehavior::Rejected => reply
                    .send(PersistOutcome::NotPublished("commit rejected".to_string()))
                    .unwrap(),
                CommitBehavior::PublicationAmbiguous => reply
                    .send(PersistOutcome::PublicationAmbiguous(
                        "directory sync failed".to_string(),
                    ))
                    .unwrap(),
                CommitBehavior::AckLost => drop(reply),
                CommitBehavior::HandoffLost => unreachable!(),
            }
        });
        let rollback_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let rollback_count_actor = rollback_count.clone();
        let (peer_tx, mut peer_rx) = mpsc::channel(2);
        tokio::spawn(async move {
            while let Some(command) = peer_rx.recv().await {
                match command {
                    PeerManagerCommand::StageFibTables { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    PeerManagerCommand::SetFibTablesSnapshot { reply, .. } => {
                        rollback_count_actor.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        if rollback_ack {
                            let _ = reply.send(());
                        }
                    }
                    _ => panic!("unexpected peer-manager command"),
                }
            }
        });
        let (fib_tx, mut fib_rx) = mpsc::channel(2);
        let expect_runtime_rollback = matches!(
            (&fib_behavior, commit_behavior),
            (
                FibBehavior::Reply(OwnedFibReplaceOutcome::Applied),
                CommitBehavior::Rejected | CommitBehavior::HandoffLost
            )
        );
        tokio::spawn(async move {
            let FibRuntimeCommand::GetTables { reply } = fib_rx.recv().await.unwrap() else {
                panic!("expected GetTables")
            };
            reply.send(vec![original]).unwrap();
            let FibRuntimeCommand::OwnedReplaceTables { reply, .. } = fib_rx.recv().await.unwrap()
            else {
                panic!("expected OwnedReplaceTables")
            };
            match fib_behavior {
                FibBehavior::Reply(outcome) => {
                    let _ = reply.send(outcome);
                }
                FibBehavior::ReplyLost => drop(reply),
            }
            if expect_runtime_rollback {
                let FibRuntimeCommand::OwnedReplaceTables { reply, .. } =
                    fib_rx.recv().await.unwrap()
                else {
                    panic!("expected owned FIB rollback")
                };
                let _ = reply.send(OwnedFibReplaceOutcome::Applied);
            }
        });

        let outcome = owned_fib_mutation_body(
            None,
            None,
            "test FIB Set",
            fib_tx,
            peer_tx,
            Mutation::Upsert(candidate),
            permit,
        )
        .await;
        let count = rollback_count.load(std::sync::atomic::Ordering::SeqCst);
        (outcome, count)
    }

    #[tokio::test]
    async fn owned_fib_commit_success_is_clean_and_all_uncertainty_is_ambiguous() {
        let (outcome, rollback) = run_owned_body(
            FibBehavior::Reply(OwnedFibReplaceOutcome::Applied),
            CommitBehavior::Applied,
            true,
        )
        .await;
        assert!(matches!(
            outcome,
            OwnedRuntimeConfigOutcome::PublishedDurable(_)
        ));
        assert_eq!(rollback, 0);

        for behavior in [CommitBehavior::Rejected, CommitBehavior::HandoffLost] {
            let (outcome, rollback) = run_owned_body(
                FibBehavior::Reply(OwnedFibReplaceOutcome::Applied),
                behavior,
                true,
            )
            .await;
            assert!(matches!(
                outcome,
                OwnedRuntimeConfigOutcome::CleanNoEffect(Err(_))
            ));
            assert_eq!(rollback, 1);
        }

        let (ack_lost, rollback) = run_owned_body(
            FibBehavior::Reply(OwnedFibReplaceOutcome::Applied),
            CommitBehavior::AckLost,
            true,
        )
        .await;
        assert!(matches!(
            ack_lost,
            OwnedRuntimeConfigOutcome::Fenced {
                reason: RuntimeConfigFenceReason::AcknowledgementLost,
                ..
            }
        ));
        assert_eq!(rollback, 0);

        let (publication_ambiguous, rollback) = run_owned_body(
            FibBehavior::Reply(OwnedFibReplaceOutcome::Applied),
            CommitBehavior::PublicationAmbiguous,
            true,
        )
        .await;
        assert!(matches!(
            publication_ambiguous,
            OwnedRuntimeConfigOutcome::Fenced {
                reason: RuntimeConfigFenceReason::PublicationAmbiguous,
                ..
            }
        ));
        assert_eq!(rollback, 0);
    }

    #[tokio::test]
    async fn typed_fib_outcomes_control_compensation_without_string_parsing() {
        let (clean, rollback) = run_owned_body(
            FibBehavior::Reply(OwnedFibReplaceOutcome::RejectedNoEffect(
                "rejected".to_string(),
            )),
            CommitBehavior::Applied,
            true,
        )
        .await;
        assert!(matches!(
            clean,
            OwnedRuntimeConfigOutcome::CleanNoEffect(Err(_))
        ));
        assert_eq!(rollback, 1);

        for behavior in [
            FibBehavior::Reply(OwnedFibReplaceOutcome::CompensationAmbiguous(
                "self-revert uncertain".to_string(),
            )),
            FibBehavior::ReplyLost,
        ] {
            let (ambiguous, rollback) =
                run_owned_body(behavior, CommitBehavior::Applied, true).await;
            assert!(matches!(
                ambiguous,
                OwnedRuntimeConfigOutcome::Fenced { .. }
            ));
            assert_eq!(rollback, 0, "accepted ambiguity must never compensate");
        }

        let (rollback_lost, rollback) = run_owned_body(
            FibBehavior::Reply(OwnedFibReplaceOutcome::RejectedNoEffect(
                "rejected".to_string(),
            )),
            CommitBehavior::Applied,
            false,
        )
        .await;
        assert!(matches!(
            rollback_lost,
            OwnedRuntimeConfigOutcome::Fenced {
                reason: RuntimeConfigFenceReason::AcknowledgementLost,
                ..
            }
        ));
        assert_eq!(rollback, 1);
    }

    #[test]
    fn fib_set_delete_settlement_inventory_is_closed() {
        fn production(source: &'static str) -> &'static str {
            source
                .split_once("\n#[cfg(test)]\nmod tests")
                .map_or(source, |parts| parts.0)
        }
        let fib = production(include_str!("fib_table_control.rs"));
        let settlement = production(include_str!(
            "../crates/api/src/runtime_config_settlement.rs"
        ));
        let main = production(include_str!("main.rs"));
        assert_eq!(fib.matches("RuntimeConfigOperationKind::FibSet").count(), 1);
        assert_eq!(
            fib.matches("RuntimeConfigOperationKind::FibDelete").count(),
            1
        );
        assert_eq!(settlement.matches("    FibSet,").count(), 1);
        assert_eq!(settlement.matches("    FibDelete,").count(), 1);
        assert_eq!(fib.matches(".execute_owned(").count(), 1);
        assert_eq!(
            fib.matches("FibRuntimeCommand::OwnedReplaceTables").count(),
            1
        );
        assert_eq!(main.matches("make_owned_fib_table_control_fn(").count(), 1);

        let reserve = fib
            .find("reserve_persist_permit(&config_tx).await?")
            .unwrap();
        let execute = fib.find(".execute_owned(").unwrap();
        assert!(
            reserve < execute,
            "persistence capacity must precede ownership"
        );
        let body = fib
            .split_once("async fn owned_fib_mutation_body")
            .unwrap()
            .1
            .split_once("async fn compensate_fib_not_published")
            .unwrap()
            .0;
        for forbidden in [".code()", ".message()", "to_string().contains"] {
            assert!(
                !body.contains(forbidden),
                "typed settlement bypass: {forbidden}"
            );
        }
        let disk = body.find("stage_fib_persistence(").unwrap();
        let pm = body.find("stage_pm_candidate(").unwrap();
        let actor = body.find("dispatch_owned_replace(").unwrap();
        let commit = body.find("staged.commit().await").unwrap();
        assert!(disk < pm && pm < actor && actor < commit);
    }

    #[test]
    fn upsert_adds_a_new_table() {
        let out = apply_mutation(
            vec![table("edge", 1000)],
            Mutation::Upsert(table("core", 1001)),
        )
        .unwrap();
        assert_eq!(out.len(), 2);
        assert!(out.iter().any(|t| t.name == "core" && t.table_id == 1001));
    }

    #[test]
    fn upsert_replaces_in_place_by_name() {
        // A table_id/metric change for an existing name is a full replacement,
        // not a second entry — the reconciler treats it as a table-key move.
        let mut replacement = table("edge", 2000);
        replacement.metric = 250;
        let out = apply_mutation(vec![table("edge", 1000)], Mutation::Upsert(replacement)).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].table_id, 2000);
        assert_eq!(out[0].metric, 250);
    }

    #[test]
    fn delete_removes_by_name() {
        let out = apply_mutation(
            vec![table("edge", 1000), table("core", 1001)],
            Mutation::Delete("edge".to_string()),
        )
        .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "core");
    }

    #[test]
    fn delete_missing_name_is_not_found() {
        let err = apply_mutation(
            vec![table("edge", 1000)],
            Mutation::Delete("nope".to_string()),
        )
        .unwrap_err();
        assert!(matches!(err, FibTableControlError::NotFound(_)));
    }

    #[test]
    fn proto_empty_families_defaults_to_both_unicast() {
        // proto3 repeated has no presence, so an empty `families` is "omitted"
        // and must default like TOML rather than be rejected by validation.
        let cfg = proto_to_config(proto::FibTableConfig {
            name: "edge".to_string(),
            table_id: 1000,
            metric: 200,
            families: vec![],
            ..Default::default()
        });
        assert_eq!(cfg.families, vec!["ipv4_unicast", "ipv6_unicast"]);
    }

    #[test]
    fn proto_explicit_families_are_preserved() {
        let cfg = proto_to_config(proto::FibTableConfig {
            name: "edge".to_string(),
            table_id: 1000,
            metric: 200,
            families: vec!["ipv6_unicast".to_string()],
            ..Default::default()
        });
        assert_eq!(cfg.families, vec!["ipv6_unicast"]);
    }
}
