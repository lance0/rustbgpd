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
//!   apply (`ReplaceTables`) → persist. Concurrent CRUD calls and SIGHUP FIB
//!   reloads can't interleave and clobber each other.
//! - **Validate before dispatch.** The candidate set is validated against the
//!   live config (peer-group references, reserved/duplicate ids, families, ECMP
//!   caps) by the peer manager before it ever reaches the reconciler.
//! - **Persist only after the actor acknowledges**, and only the exact accepted
//!   set. If persistence rejects the accepted set, the control path rolls the
//!   reconciler and peer-manager snapshot back; if rollback itself fails, that
//!   failure is reported and logged rather than hidden.
//! - **Durable after dispatch.** The mutation runs in a detached task whose
//!   join handle the request future awaits; a canceled gRPC call cannot split a
//!   successful apply from its persistence.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, mpsc, oneshot};

use rustbgpd_api::peer_types::{ConfigEvent, FibTableSnapshot, PeerManagerCommand};
use rustbgpd_api::proto;
use rustbgpd_api::rib_service::{
    FibTableControlError, FibTableControlFn, FibTableControlFuture, FibTableControlRequest,
};
use rustbgpd_api::server::ConfigMutationGateFn;
use tracing::error;

use crate::config::FibTableConfig;
use crate::fib_runtime::FibRuntimeCommand;

/// How long to wait for a config-persistence permit before refusing the
/// mutation (mirrors the dynamic-neighbor CRUD reserve deadline).
const PERSIST_RESERVE_TIMEOUT: Duration = Duration::from_secs(2);

/// Dependencies for the FIB-table control hook, wired from `main.rs`.
pub struct FibTableControlDeps {
    /// FIB reconciler command channel. `None` when the reconciler did not spawn
    /// (no `[[fib_tables]]` at startup, or non-Linux / netlink setup failure).
    pub fib_cmd_tx: Option<mpsc::Sender<FibRuntimeCommand>>,
    /// Peer-manager channel — the live-config validation authority.
    pub peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    /// Config-persistence channel. `None` when the daemon was started without
    /// `--config` (nothing to persist to).
    pub config_tx: Option<mpsc::Sender<ConfigEvent>>,
    /// Coordinator lock shared with the SIGHUP reload FIB step.
    pub lock: Arc<Mutex<()>>,
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
}

/// Build the `FibTableControlFn` the RIB service calls for FIB-table CRUD.
#[must_use]
pub fn make_fib_table_control_fn(deps: FibTableControlDeps) -> FibTableControlFn {
    let deps = Arc::new(deps);
    Arc::new(move |request| {
        let deps = deps.clone();
        Box::pin(async move { handle(deps, request).await }) as FibTableControlFuture
    })
}

async fn handle(
    deps: Arc<FibTableControlDeps>,
    request: FibTableControlRequest,
) -> Result<proto::ListFibTablesResponse, FibTableControlError> {
    match request {
        FibTableControlRequest::List => {
            let _guard = deps.lock.lock().await;
            // A running reconciler is the source of truth; otherwise fall back
            // to the startup set so configured tables stay visible even when
            // the actor failed to spawn (non-Linux / netlink failure).
            let (tables, runtime_available) =
                match read_current_tables(deps.fib_cmd_tx.as_ref()).await? {
                    Some(current) => (current, true),
                    None => (deps.startup_tables.clone(), false),
                };
            Ok(proto::ListFibTablesResponse {
                tables: tables.iter().map(config_to_proto).collect(),
                runtime_available,
            })
        }
        FibTableControlRequest::Set(table) => {
            mutate(deps, Mutation::Upsert(proto_to_config(table))).await
        }
        FibTableControlRequest::Delete { name } => mutate(deps, Mutation::Delete(name)).await,
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
}

async fn mutate(
    deps: Arc<FibTableControlDeps>,
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
            "FIB-table CRUD requires a persisted config (start rustbgpd with --config)".to_string(),
        )
    })?;
    let peer_mgr_tx = deps.peer_mgr_tx.clone();
    let lock = deps.lock.clone();
    let config_mutation_gate = deps.config_mutation_gate.clone();
    let operation = mutation.operation_label();

    // Run the critical section in a detached task so a canceled gRPC request
    // cannot split a successful `ReplaceTables` from its persistence: once the
    // task starts it runs to completion regardless of the awaiting future.
    let join = tokio::spawn(async move {
        let _guard = lock.lock().await;
        if let Some(gate) = &config_mutation_gate {
            gate(operation)
                .await
                .map_err(FibTableControlError::FailedPrecondition)?;
        }

        let current = read_current_tables(Some(&fib_cmd_tx))
            .await?
            .unwrap_or_default();
        let candidate = apply_mutation(current, mutation)?;
        commit_fib_tables_locked(&fib_cmd_tx, &peer_mgr_tx, &config_tx, candidate).await
    });

    join.await.map_err(|_| {
        FibTableControlError::Internal("FIB-table mutation task did not complete".to_string())
    })?
}

/// Commit a full `[[fib_tables]]` replacement while the caller holds the shared
/// runtime-config coordinator lock.
///
/// This is the single safety-critical FIB commit path used by targeted FIB CRUD
/// and config transactions: stage the peer-manager snapshot, apply to the
/// reconciler, persist the exact accepted set, and roll back on every
/// post-stage failure.
pub(crate) async fn commit_fib_tables_locked(
    fib_cmd_tx: &mpsc::Sender<FibRuntimeCommand>,
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    config_tx: &mpsc::Sender<ConfigEvent>,
    candidate: Vec<FibTableConfig>,
) -> Result<proto::ListFibTablesResponse, FibTableControlError> {
    let previous_tables = read_current_tables(Some(fib_cmd_tx))
        .await?
        .unwrap_or_default();
    let previous_snapshots: Vec<FibTableSnapshot> =
        previous_tables.iter().map(config_to_snapshot).collect();
    let snapshots: Vec<FibTableSnapshot> = candidate.iter().map(config_to_snapshot).collect();

    // Validate AND stage the candidate into the peer manager's live config in
    // one atomic command. This closes the TOCTOU against peer-group deletion:
    // once staged, the candidate's `allowed_peer_groups` are visible to
    // `peer_group_references`, so a concurrent delete is rejected (and if a
    // delete raced ahead, the candidate fails validation here). The peer manager
    // processes commands one at a time, so the check and commit cannot
    // interleave with another config mutation.
    stage_candidate(peer_mgr_tx, snapshots.clone()).await?;

    // From here the candidate is staged in the live config, so every early exit
    // must roll it back to `previous` to keep the snapshot from drifting ahead
    // of the runtime/disk state.
    let permit = match reserve_persist_permit(config_tx).await {
        Ok(permit) => permit,
        Err(error) => {
            return Err(
                rollback_snapshot_after_error(peer_mgr_tx, previous_snapshots, error).await,
            );
        }
    };

    // Apply to the reconciler and wait for its acknowledgement.
    if let Err(error) = replace_tables(fib_cmd_tx, candidate.clone()).await {
        return Err(rollback_snapshot_after_error(peer_mgr_tx, previous_snapshots, error).await);
    }

    // Persist exactly the accepted set, only after the ack. The live config
    // snapshot already holds the candidate (staged above). Await the bridge and
    // persister acknowledgement before releasing the coordinator lock, otherwise
    // an immediate SIGHUP can reload stale disk and overwrite the accepted
    // runtime snapshot.
    let (persist_ack_tx, persist_ack_rx) = oneshot::channel();
    permit.send(ConfigEvent::FibTablesReplaced {
        tables: snapshots,
        ack: Some(persist_ack_tx),
    });
    let persist_result = persist_ack_rx.await.map_err(|_| {
        FibTableControlError::Internal(
            "config bridge dropped FIB-table persistence acknowledgement".to_string(),
        )
    })?;
    if let Err(error) = persist_result {
        return Err(rollback_applied_tables_after_error(
            fib_cmd_tx,
            peer_mgr_tx,
            previous_tables,
            previous_snapshots,
            FibTableControlError::FailedPrecondition(error),
        )
        .await);
    }

    Ok(proto::ListFibTablesResponse {
        tables: candidate.iter().map(config_to_proto).collect(),
        runtime_available: true,
    })
}

/// Read the reconciler's current table set. `Ok(None)` means no reconciler is
/// running (used by `List` to report `runtime_available = false`).
async fn read_current_tables(
    fib_cmd_tx: Option<&mpsc::Sender<FibRuntimeCommand>>,
) -> Result<Option<Vec<FibTableConfig>>, FibTableControlError> {
    let Some(tx) = fib_cmd_tx else {
        return Ok(None);
    };
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(FibRuntimeCommand::GetTables { reply: reply_tx })
        .await
        .map_err(|_| {
            FibTableControlError::Internal("FIB reconciler command channel closed".to_string())
        })?;
    let tables = reply_rx.await.map_err(|_| {
        FibTableControlError::Internal("FIB reconciler dropped the GetTables reply".to_string())
    })?;
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

/// Atomically validate the candidate against the live config and, on success,
/// stage it into the peer manager's `current_config.fib_tables`. Returns
/// `InvalidArgument` if it doesn't validate (nothing is staged in that case).
async fn stage_candidate(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    tables: Vec<FibTableSnapshot>,
) -> Result<(), FibTableControlError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    peer_mgr_tx
        .send(PeerManagerCommand::StageFibTables {
            tables,
            reply: reply_tx,
        })
        .await
        .map_err(|_| {
            FibTableControlError::Internal("peer manager command channel closed".to_string())
        })?;
    reply_rx
        .await
        .map_err(|_| {
            FibTableControlError::Internal(
                "peer manager dropped the StageFibTables reply".to_string(),
            )
        })?
        .map_err(FibTableControlError::InvalidArgument)
}

/// Restore the peer manager's staged `current_config.fib_tables` to `previous`
/// after a post-stage failure (reserve or reconciler apply), so the live
/// config snapshot can't drift ahead of the runtime/disk state.
async fn rollback_snapshot(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    previous: Vec<FibTableSnapshot>,
) -> Result<(), FibTableControlError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    peer_mgr_tx
        .send(PeerManagerCommand::SetFibTablesSnapshot {
            tables: previous,
            reply: reply_tx,
        })
        .await
        .map_err(|_| {
            FibTableControlError::Internal(
                "peer manager command channel closed during FIB-table snapshot rollback"
                    .to_string(),
            )
        })?;
    reply_rx.await.map_err(|_| {
        FibTableControlError::Internal(
            "peer manager dropped the SetFibTablesSnapshot rollback reply".to_string(),
        )
    })
}

async fn rollback_snapshot_after_error(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    previous_snapshots: Vec<FibTableSnapshot>,
    original: FibTableControlError,
) -> FibTableControlError {
    match rollback_snapshot(peer_mgr_tx, previous_snapshots).await {
        Ok(()) => original,
        Err(snapshot_rollback) => {
            combine_fib_rollback_errors(&original, None, Some(snapshot_rollback))
        }
    }
}

async fn rollback_applied_tables_after_error(
    fib_cmd_tx: &mpsc::Sender<FibRuntimeCommand>,
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    previous_tables: Vec<FibTableConfig>,
    previous_snapshots: Vec<FibTableSnapshot>,
    original: FibTableControlError,
) -> FibTableControlError {
    if let Err(runtime_rollback) = replace_tables(fib_cmd_tx, previous_tables).await {
        return combine_fib_rollback_errors(&original, Some(runtime_rollback), None);
    }
    match rollback_snapshot(peer_mgr_tx, previous_snapshots).await {
        Ok(()) => original,
        Err(snapshot_rollback) => {
            combine_fib_rollback_errors(&original, None, Some(snapshot_rollback))
        }
    }
}

fn combine_fib_rollback_errors(
    original: &FibTableControlError,
    runtime_rollback: Option<FibTableControlError>,
    snapshot_rollback: Option<FibTableControlError>,
) -> FibTableControlError {
    error!(
        %original,
        ?runtime_rollback,
        ?snapshot_rollback,
        "FIB-table rollback failed"
    );
    let mut message = format!("{original}; rollback failed");
    if let Some(error) = runtime_rollback {
        let _ = write!(message, "; runtime rollback: {error}");
    }
    if let Some(error) = snapshot_rollback {
        let _ = write!(message, "; snapshot rollback: {error}");
    }
    FibTableControlError::Internal(message)
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

async fn replace_tables(
    fib_cmd_tx: &mpsc::Sender<FibRuntimeCommand>,
    tables: Vec<FibTableConfig>,
) -> Result<(), FibTableControlError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    fib_cmd_tx
        .send(FibRuntimeCommand::ReplaceTables {
            tables,
            reply: reply_tx,
        })
        .await
        .map_err(|_| {
            FibTableControlError::Internal("FIB reconciler command channel closed".to_string())
        })?;
    reply_rx
        .await
        .map_err(|_| {
            FibTableControlError::Internal(
                "FIB reconciler dropped the ReplaceTables reply".to_string(),
            )
        })?
        // The reconciler reverted (RIB/dump bail or a removed-table withdraw
        // that would orphan a kernel row) — surface it without persisting.
        .map_err(FibTableControlError::FailedPrecondition)
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

    use crate::test_support::basic_fib_table as table;

    #[tokio::test]
    async fn persistence_rejection_rolls_back_runtime_and_snapshot() {
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
                    FibRuntimeCommand::ReplaceTables { tables, reply } => {
                        *fib_state_for_task.lock().await = tables;
                        let _ = reply.send(Ok(()));
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
                let _ = ack.send(Err("desired config validation failed".to_string()));
            }
        });

        let deps = Arc::new(FibTableControlDeps {
            fib_cmd_tx: Some(fib_tx),
            peer_mgr_tx: peer_tx,
            config_tx: Some(config_tx),
            lock: Arc::new(Mutex::new(())),
            config_mutation_gate: None,
            startup_tables: vec![original.clone()],
        });
        let err = mutate(deps, Mutation::Upsert(table("core", 1001)))
            .await
            .expect_err("persistence rejection must fail the mutation");
        assert!(
            matches!(err, FibTableControlError::FailedPrecondition(ref message) if message == "desired config validation failed"),
            "{err:?}"
        );
        assert_eq!(*fib_state.lock().await, vec![original]);
        assert_eq!(*peer_snapshot.lock().await, vec![original_snapshot]);
    }

    #[tokio::test]
    async fn persistence_rejection_reports_snapshot_rollback_failure() {
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
                    FibRuntimeCommand::ReplaceTables { tables, reply } => {
                        *fib_state_for_task.lock().await = tables;
                        let _ = reply.send(Ok(()));
                    }
                }
            }
        });

        let peer_snapshot = Arc::new(Mutex::new(vec![original_snapshot]));
        let peer_snapshot_for_task = peer_snapshot.clone();
        let (peer_tx, mut peer_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            while let Some(cmd) = peer_rx.recv().await {
                match cmd {
                    PeerManagerCommand::StageFibTables { tables, reply } => {
                        *peer_snapshot_for_task.lock().await = tables;
                        let _ = reply.send(Ok(()));
                    }
                    PeerManagerCommand::SetFibTablesSnapshot { reply, .. } => {
                        drop(reply);
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
                let _ = ack.send(Err("desired config validation failed".to_string()));
            }
        });

        let deps = Arc::new(FibTableControlDeps {
            fib_cmd_tx: Some(fib_tx),
            peer_mgr_tx: peer_tx,
            config_tx: Some(config_tx),
            lock: Arc::new(Mutex::new(())),
            config_mutation_gate: None,
            startup_tables: vec![original.clone()],
        });
        let err = mutate(deps, Mutation::Upsert(table("core", 1001)))
            .await
            .expect_err("persistence rejection must fail the mutation");
        assert!(
            matches!(err, FibTableControlError::Internal(ref message)
                if message.contains("desired config validation failed")
                    && message.contains("snapshot rollback")
                    && message.contains("SetFibTablesSnapshot rollback reply")),
            "{err:?}"
        );
        assert_eq!(*fib_state.lock().await, vec![original]);
        let peer_snapshot = peer_snapshot.lock().await;
        assert_eq!(peer_snapshot.len(), 2);
        assert!(peer_snapshot.iter().any(|table| table.name == "edge"));
        assert!(peer_snapshot.iter().any(|table| table.name == "core"));
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
