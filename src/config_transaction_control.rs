//! Binary-owned config transaction apply hook.
//!
//! `ConfigService` lives in the API crate, but committing a transaction needs
//! binary-only state: the FIB reconciler command channel, config persistence,
//! peer-manager validation, and the runtime-config lock shared with SIGHUP.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use rustbgpd_api::peer_types::{
    ConfigEvent, PeerKey, PeerManagerCommand, PeerManagerNeighborConfig,
    RuntimeConfigTransactionPlanError, RuntimeConfigTransactionStatus,
};
use rustbgpd_api::proto;
use rustbgpd_api::server::{ConfigTransactionApplyError, ConfigTransactionApplyFn};
use tracing::error;

use crate::config::{Config, Neighbor, diff_neighbors};
use crate::fib_table_control::{
    FibTableControlDeps, commit_fib_tables_locked, runtime_unavailable_error,
};

const PERSIST_RESERVE_TIMEOUT: Duration = Duration::from_secs(2);
const FIB_SECTION: &str = "[[fib_tables]]";
const DYNAMIC_SECTION: &str = "[[dynamic_neighbors]]";
const NEIGHBOR_ADD_SECTION: &str = "[[neighbors]] add";
const NEIGHBOR_DELETE_SECTION: &str = "[[neighbors]] delete";

/// Build the daemon-owned apply hook wired into `ConfigService`.
#[must_use]
pub fn make_config_transaction_apply_fn(deps: FibTableControlDeps) -> ConfigTransactionApplyFn {
    let deps = Arc::new(deps);
    Arc::new(move |request| {
        let deps = deps.clone();
        Box::pin(async move { apply_config_transaction(deps, request).await })
    })
}

async fn apply_config_transaction(
    deps: Arc<FibTableControlDeps>,
    request: proto::ApplyConfigTransactionRequest,
) -> Result<proto::ConfigTransactionApplyResponse, ConfigTransactionApplyError> {
    if request.expected_runtime_snapshot_token.is_empty() {
        return Err(ConfigTransactionApplyError::InvalidArgument(
            "expected_runtime_snapshot_token is required for ApplyConfigTransaction".to_string(),
        ));
    }

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
                "Committed [[neighbors]] add/delete transaction.\n".to_string(),
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
    StaticNeighbors,
}

fn apply_family(sections: &[String]) -> Option<ApplyFamily> {
    match sections {
        [section] if section == FIB_SECTION => Some(ApplyFamily::FibTables),
        [section] if section == DYNAMIC_SECTION => Some(ApplyFamily::DynamicNeighbors),
        sections
            if !sections.is_empty()
                && sections
                    .iter()
                    .all(|s| s == NEIGHBOR_ADD_SECTION || s == NEIGHBOR_DELETE_SECTION) =>
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
    if !neighbor_diff.changed.is_empty()
        || committed_sections
            .iter()
            .any(|s| s != NEIGHBOR_ADD_SECTION && s != NEIGHBOR_DELETE_SECTION)
    {
        let error = ConfigTransactionApplyError::Internal(
            "static-neighbor transaction executor received a non-static-add/delete diff"
                .to_string(),
        );
        return Err(rollback_snapshot_after_error(peer_mgr_tx, previous_toml, error).await);
    }

    let mut applied = Vec::new();
    let added = match resolve_added_neighbors(candidate, &neighbor_diff.added) {
        Ok(added) => added,
        Err(error) => {
            return Err(rollback_snapshot_after_error(peer_mgr_tx, previous_toml, error).await);
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
    Ok(())
}

fn resolve_added_neighbors(
    candidate: &Config,
    added: &[Neighbor],
) -> Result<Vec<PeerManagerNeighborConfig>, ConfigTransactionApplyError> {
    let resolved = candidate
        .resolved_neighbors()
        .map_err(|error| ConfigTransactionApplyError::InvalidArgument(error.to_string()))?;
    let peer_map: std::collections::HashMap<PeerKey, _> = resolved
        .into_iter()
        .map(|neighbor| {
            (
                PeerKey::new(
                    neighbor.transport_config.remote_addr.ip(),
                    neighbor.transport_config.peer_interface.clone(),
                ),
                neighbor,
            )
        })
        .collect();
    added
        .iter()
        .map(|neighbor| {
            let address = neighbor.address.parse().map_err(|error| {
                ConfigTransactionApplyError::InvalidArgument(format!(
                    "invalid neighbor address {:?}: {error}",
                    neighbor.address
                ))
            })?;
            let key = PeerKey::new(address, neighbor.interface.clone());
            let resolved = peer_map.get(&key).ok_or_else(|| {
                ConfigTransactionApplyError::Internal(format!(
                    "candidate neighbor {key} missing from resolved neighbor map",
                ))
            })?;
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
    stage_config_snapshot(peer_mgr_tx, previous)
        .await
        .map(|_| ())
        .map_err(|error| {
            ConfigTransactionApplyError::Internal(format!(
                "config snapshot rollback failed: {error}"
            ))
        })
}

async fn rollback_snapshot_after_error(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    previous_toml: String,
    original: ConfigTransactionApplyError,
) -> ConfigTransactionApplyError {
    match rollback_config_snapshot(peer_mgr_tx, previous_toml).await {
        Ok(()) => original,
        Err(rollback_error) => combine_rollback_errors(&original, None, Some(rollback_error)),
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
        .map_err(ConfigTransactionApplyError::FailedPrecondition)
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
        .map_err(ConfigTransactionApplyError::FailedPrecondition)
}

enum AppliedStaticOp {
    Added(PeerKey),
    Deleted(Box<PeerManagerNeighborConfig>),
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
        (static_result, snapshot_result) => {
            combine_rollback_errors(&original, static_result.err(), snapshot_result.err())
        }
    }
}

fn combine_rollback_errors(
    original: &ConfigTransactionApplyError,
    static_rollback: Option<ConfigTransactionApplyError>,
    snapshot_rollback: Option<ConfigTransactionApplyError>,
) -> ConfigTransactionApplyError {
    error!(
        %original,
        ?static_rollback,
        ?snapshot_rollback,
        "config transaction rollback failed"
    );
    let mut message = format!("{original}; rollback failed");
    if let Some(error) = static_rollback {
        let _ = write!(message, "; static rollback: {error}");
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

fn stage_config_snapshot_error_to_apply_error(error: String) -> ConfigTransactionApplyError {
    if error.starts_with("failed to serialize previous runtime config snapshot") {
        ConfigTransactionApplyError::Internal(error)
    } else {
        ConfigTransactionApplyError::InvalidArgument(error)
    }
}

fn rejected_response(runtime_snapshot_token: String) -> proto::ConfigTransactionApplyResponse {
    proto::ConfigTransactionApplyResponse {
        status: proto::ConfigTransactionPlanStatus::Rejected.into(),
        runtime_snapshot_token,
        committed_sections: Vec::new(),
        human_text: "Config transaction is not committable by the current apply executor.\nRun PlanConfigTransaction for section classification.\n".to_string(),
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
    use std::collections::VecDeque;
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

    fn table(name: &str, table_id: u32) -> FibTableConfig {
        FibTableConfig {
            name: name.to_string(),
            table_id,
            metric: 200,
            families: vec!["ipv4_unicast".to_string()],
            allowed_peer_groups: Vec::new(),
            allowed_neighbors: Vec::new(),
            max_routes: None,
            maximum_paths: None,
            maximum_paths_ebgp: None,
            maximum_paths_ibgp: None,
        }
    }

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

    #[test]
    fn stage_snapshot_serialization_error_maps_internal() {
        let error = stage_config_snapshot_error_to_apply_error(
            "failed to serialize previous runtime config snapshot: synthetic".to_string(),
        );
        assert!(matches!(error, ConfigTransactionApplyError::Internal(_)));

        let error = stage_config_snapshot_error_to_apply_error(
            "invalid candidate config transaction: synthetic".to_string(),
        );
        assert!(matches!(
            error,
            ConfigTransactionApplyError::InvalidArgument(_)
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
        mut rx: mpsc::Receiver<PeerManagerCommand>,
        plan: RuntimeConfigTransactionPlan,
        snapshot_toml: Arc<Mutex<String>>,
        peers: Arc<Mutex<Vec<PeerManagerNeighborConfig>>>,
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
                PeerManagerCommand::AddPeer { config, reply, .. } => {
                    let mut peers = peers.lock().await;
                    let key = PeerKey::new(config.address, config.interface.clone());
                    if peers
                        .iter()
                        .any(|peer| PeerKey::new(peer.address, peer.interface.clone()) == key)
                    {
                        let _ = reply.send(Err(format!("peer {key} already exists")));
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
                        let _ = reply.send(Err(format!("peer {peer} not found")));
                    }
                }
                _ => panic!("unexpected peer-manager command in snapshot transaction test"),
            }
        }
    }

    async fn fake_snapshot_peer_manager_with_stage_results(
        mut rx: mpsc::Receiver<PeerManagerCommand>,
        plan: RuntimeConfigTransactionPlan,
        snapshot_toml: Arc<Mutex<String>>,
        peers: Arc<Mutex<Vec<PeerManagerNeighborConfig>>>,
        stage_results: Arc<Mutex<VecDeque<Result<(), String>>>>,
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
                PeerManagerCommand::AddPeer { config, reply, .. } => {
                    let mut peers = peers.lock().await;
                    let key = PeerKey::new(config.address, config.interface.clone());
                    if peers
                        .iter()
                        .any(|peer| PeerKey::new(peer.address, peer.interface.clone()) == key)
                    {
                        let _ = reply.send(Err(format!("peer {key} already exists")));
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
                        let _ = reply.send(Err(format!("peer {peer} not found")));
                    }
                }
                _ => panic!("unexpected peer-manager command in snapshot transaction test"),
            }
        }
    }

    fn deps(
        fib_cmd_tx: Option<mpsc::Sender<FibRuntimeCommand>>,
        peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
        config_tx: Option<mpsc::Sender<rustbgpd_api::peer_types::ConfigEvent>>,
        startup_tables: Vec<FibTableConfig>,
    ) -> Arc<FibTableControlDeps> {
        Arc::new(FibTableControlDeps {
            fib_cmd_tx,
            peer_mgr_tx,
            config_tx,
            lock: Arc::new(Mutex::new(())),
            startup_tables,
        })
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
            Err("stage rollback failed".to_string()),
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
    async fn static_neighbor_changed_diff_rolls_back_snapshot() {
        let previous_toml = base_toml("");
        let candidate_toml = previous_toml.replace("remote_asn = 65002", "remote_asn = 65102");
        let snapshot_toml = Arc::new(Mutex::new(previous_toml.clone()));
        let peers = Arc::new(Mutex::new(Vec::new()));
        let (peer_tx, peer_rx) = mpsc::channel(8);
        tokio::spawn(fake_snapshot_peer_manager(
            peer_rx,
            plan(
                RuntimeConfigTransactionStatus::Committable,
                vec!["[[neighbors]] add".to_string()],
            ),
            snapshot_toml.clone(),
            peers,
        ));
        let (config_tx, _config_rx) = mpsc::channel(8);

        let err = apply_config_transaction(
            deps(None, peer_tx, Some(config_tx), Vec::new()),
            proto::ApplyConfigTransactionRequest {
                candidate_toml,
                expected_runtime_snapshot_token: "kv1:old:1".to_string(),
                client_request_id: String::new(),
                comment: String::new(),
            },
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, ConfigTransactionApplyError::Internal(ref message) if message.contains("non-static-add/delete diff")),
            "{err:?}"
        );
        assert_eq!(*snapshot_toml.lock().await, previous_toml);
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
