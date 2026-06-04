//! Binary-owned config transaction apply hook.
//!
//! `ConfigService` lives in the API crate, but committing a transaction needs
//! binary-only state: the FIB reconciler command channel, config persistence,
//! peer-manager validation, and the runtime-config lock shared with SIGHUP.

use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};

use rustbgpd_api::peer_types::{PeerManagerCommand, RuntimeConfigTransactionStatus};
use rustbgpd_api::proto;
use rustbgpd_api::server::{ConfigTransactionApplyError, ConfigTransactionApplyFn};

use crate::config::Config;
use crate::fib_table_control::{
    FibTableControlDeps, commit_fib_tables_locked, runtime_unavailable_error,
};

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

        if plan.supported_sections.len() != 1 || plan.supported_sections[0] != "[[fib_tables]]" {
            return Ok(rejected_response(plan.runtime_snapshot_token));
        }

        let candidate = Config::load_toml_with_diagnostics(
            &request.candidate_toml,
            "candidate config transaction",
        )
        .map_err(ConfigTransactionApplyError::InvalidArgument)?;
        let fib_cmd_tx = deps.fib_cmd_tx.clone().ok_or_else(|| {
            fib_error_to_apply_error(runtime_unavailable_error(!deps.startup_tables.is_empty()))
        })?;
        let config_tx = deps.config_tx.clone().ok_or_else(|| {
            ConfigTransactionApplyError::FailedPrecondition(
                "config transactions require a persisted config (start rustbgpd with --config)"
                    .to_string(),
            )
        })?;
        // The post-commit token is computed by the planner under the
        // peer-manager's key and returned in the plan; the apply path no longer
        // hashes the candidate itself (it could not produce a key-consistent
        // token). For a committable single-family FIB candidate the resulting
        // live config equals the candidate, so this token matches a fresh plan.
        let runtime_snapshot_token = plan.post_commit_runtime_snapshot_token;

        let response = commit_fib_tables_locked(
            &fib_cmd_tx,
            &deps.peer_mgr_tx,
            &config_tx,
            candidate.fib_tables.clone(),
        )
        .await
        .map_err(fib_error_to_apply_error)?;

        Ok(proto::ConfigTransactionApplyResponse {
            status: proto::ConfigTransactionPlanStatus::Committable.into(),
            runtime_snapshot_token,
            committed_sections: vec!["[[fib_tables]]".to_string()],
            human_text: format!(
                "Committed [[fib_tables]] transaction.\n{} table(s) active.\n",
                response.tables.len()
            ),
        })
    });

    join.await.map_err(|_| {
        ConfigTransactionApplyError::Internal(
            "config transaction apply task did not complete".to_string(),
        )
    })?
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

fn plan_error_to_status(error: String) -> ConfigTransactionApplyError {
    if error.starts_with("runtime config snapshot changed") {
        ConfigTransactionApplyError::FailedPrecondition(error)
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
    };
    use rustbgpd_api::rib_service::FibTableControlError;
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
    async fn apply_rejects_valid_non_fib_candidate_without_mutation() {
        let (peer_tx, peer_rx) = mpsc::channel(8);
        let staged = Arc::new(Mutex::new(Vec::new()));
        tokio::spawn(fake_peer_manager(
            peer_rx,
            plan(
                RuntimeConfigTransactionStatus::Committable,
                vec!["[[dynamic_neighbors]]".to_string()],
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
