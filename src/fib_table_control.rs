//! Runtime `[[fib_tables]]` CRUD control (gRPC `RibService.SetFibTable` /
//! `DeleteFibTable` / `ListFibTables`).
//!
//! This is the binary-owned hook behind `RibService`'s `FibTableControlFn`.
//! It lives here, not in the API crate, because it needs the binary config
//! types, the FIB reconciler command channel (PR1's `FibRuntimeCommand`), the
//! peer-manager validator, and the config-persistence channel — none of which
//! the API crate can see across the crate boundary.
//!
//! Safety properties (see ADR-0061 / the FIB-hardening plan):
//! - **Atomic read-modify-write.** A single coordinator `Mutex`, shared with
//!   the SIGHUP reload path, is held across read (`GetTables`) → validate →
//!   apply (`ReplaceTables`) → persist. Concurrent CRUD calls and SIGHUP FIB
//!   reloads can't interleave and clobber each other.
//! - **Validate before dispatch.** The candidate set is validated against the
//!   live config (peer-group references, reserved/duplicate ids, families, ECMP
//!   caps) by the peer manager before it ever reaches the reconciler.
//! - **Persist only after the actor acknowledges**, and only the exact accepted
//!   set — so runtime and on-disk config can't drift.
//! - **Durable after dispatch.** The mutation runs in a detached task whose
//!   join handle the request future awaits; a canceled gRPC call cannot split a
//!   successful apply from its persistence.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, mpsc, oneshot};

use rustbgpd_api::peer_types::{ConfigEvent, FibTableSnapshot, PeerManagerCommand};
use rustbgpd_api::proto;
use rustbgpd_api::rib_service::{
    FibTableControlError, FibTableControlFn, FibTableControlFuture, FibTableControlRequest,
};

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
    /// Whether `[[fib_tables]]` were present at startup. Distinguishes the
    /// "restart required to enable FIB" case from "runtime unavailable" when
    /// the reconciler isn't running.
    pub startup_had_tables: bool,
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
            let current = read_current_tables(deps.fib_cmd_tx.as_ref()).await?;
            let runtime_available = current.is_some();
            let tables = current
                .unwrap_or_default()
                .iter()
                .map(config_to_proto)
                .collect();
            Ok(proto::ListFibTablesResponse {
                tables,
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

async fn mutate(
    deps: Arc<FibTableControlDeps>,
    mutation: Mutation,
) -> Result<proto::ListFibTablesResponse, FibTableControlError> {
    // A mutation needs a running reconciler and a persistence sink. Resolve
    // both up front so a missing one fails before we spawn the durable task.
    let fib_cmd_tx = deps
        .fib_cmd_tx
        .clone()
        .ok_or_else(|| runtime_unavailable_error(deps.startup_had_tables))?;
    let config_tx = deps.config_tx.clone().ok_or_else(|| {
        FibTableControlError::FailedPrecondition(
            "FIB-table CRUD requires a persisted config (start rustbgpd with --config)".to_string(),
        )
    })?;
    let peer_mgr_tx = deps.peer_mgr_tx.clone();
    let lock = deps.lock.clone();

    // Run the critical section in a detached task so a canceled gRPC request
    // cannot split a successful `ReplaceTables` from its persistence: once the
    // task starts it runs to completion regardless of the awaiting future.
    let join = tokio::spawn(async move {
        let _guard = lock.lock().await;

        let current = read_current_tables(Some(&fib_cmd_tx))
            .await?
            .unwrap_or_default();
        let candidate = apply_mutation(current, mutation)?;
        let snapshots: Vec<FibTableSnapshot> = candidate.iter().map(config_to_snapshot).collect();

        // Validate against the live config before touching the reconciler.
        validate_candidate(&peer_mgr_tx, snapshots.clone()).await?;

        // Reserve persistence capacity before applying, so we never apply a
        // change we then can't record (which would drift runtime vs disk).
        let permit = reserve_persist_permit(&config_tx).await?;

        // Apply to the reconciler and wait for its acknowledgement.
        replace_tables(&fib_cmd_tx, candidate.clone()).await?;

        // Persist exactly the accepted set, only after the ack.
        permit.send(ConfigEvent::FibTablesReplaced(snapshots));

        Ok(proto::ListFibTablesResponse {
            tables: candidate.iter().map(config_to_proto).collect(),
            runtime_available: true,
        })
    });

    join.await.map_err(|_| {
        FibTableControlError::Internal("FIB-table mutation task did not complete".to_string())
    })?
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

async fn validate_candidate(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    tables: Vec<FibTableSnapshot>,
) -> Result<(), FibTableControlError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    peer_mgr_tx
        .send(PeerManagerCommand::ValidateFibTables {
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
                "peer manager dropped the ValidateFibTables reply".to_string(),
            )
        })?
        .map_err(FibTableControlError::InvalidArgument)
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

fn runtime_unavailable_error(startup_had_tables: bool) -> FibTableControlError {
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
    FibTableConfig {
        name: table.name,
        table_id: table.table_id,
        metric: table.metric,
        families: table.families,
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
