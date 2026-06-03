use crate::connection::Connection;
use crate::error::CliError;
use crate::proto::config_service_client::ConfigServiceClient;
use crate::proto::{
    ApplyConfigTransactionRequest, ConfigTransactionApplyResponse, ConfigTransactionPlanResponse,
    ConfigTransactionPlanStatus, DiffRuntimeConfigRequest, DiffRuntimeConfigResponse,
    PlanConfigTransactionRequest,
};

pub async fn diff(connection: Connection, from_file: &str, json: bool) -> Result<(), CliError> {
    let candidate_toml = read_candidate_toml(from_file)?;
    let mut client =
        ConfigServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .diff_runtime_config(DiffRuntimeConfigRequest { candidate_toml })
        .await?
        .into_inner();

    if json {
        println!("{}", resp.diff_json);
    } else {
        print!("{}", resp.human_text);
    }
    Ok(())
}

pub async fn plan(
    connection: Connection,
    from_file: &str,
    expected_runtime_snapshot_token: Option<&str>,
    json: bool,
) -> Result<(), CliError> {
    let candidate_toml = read_candidate_toml(from_file)?;
    let mut client =
        ConfigServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .plan_config_transaction(PlanConfigTransactionRequest {
            candidate_toml,
            expected_runtime_snapshot_token: expected_runtime_snapshot_token
                .unwrap_or_default()
                .to_string(),
        })
        .await?
        .into_inner();

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&plan_to_json(&resp)).unwrap()
        );
    } else {
        print_plan_human(&resp);
    }
    Ok(())
}

pub async fn apply(
    connection: Connection,
    from_file: &str,
    expected_runtime_snapshot_token: &str,
    client_request_id: Option<&str>,
    comment: Option<&str>,
    json: bool,
) -> Result<(), CliError> {
    if expected_runtime_snapshot_token.is_empty() {
        return Err(CliError::Argument(
            "--expected-runtime-snapshot-token must not be empty".to_string(),
        ));
    }
    let candidate_toml = read_candidate_toml(from_file)?;
    let mut client =
        ConfigServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .apply_config_transaction(ApplyConfigTransactionRequest {
            candidate_toml,
            expected_runtime_snapshot_token: expected_runtime_snapshot_token.to_string(),
            client_request_id: client_request_id.unwrap_or_default().to_string(),
            comment: comment.unwrap_or_default().to_string(),
        })
        .await?
        .into_inner();

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&apply_to_json(&resp)).unwrap()
        );
    } else {
        print_apply_human(&resp);
    }
    Ok(())
}

fn read_candidate_toml(from_file: &str) -> Result<String, CliError> {
    std::fs::read_to_string(from_file)
        .map_err(|error| CliError::Argument(format!("failed to read {from_file}: {error}")))
}

fn status_label(status: i32) -> &'static str {
    match ConfigTransactionPlanStatus::try_from(status)
        .unwrap_or(ConfigTransactionPlanStatus::Unspecified)
    {
        ConfigTransactionPlanStatus::Unspecified => "unspecified",
        ConfigTransactionPlanStatus::Noop => "noop",
        ConfigTransactionPlanStatus::Committable => "committable",
        ConfigTransactionPlanStatus::Rejected => "rejected",
    }
}

fn diff_to_json(diff: Option<&DiffRuntimeConfigResponse>) -> serde_json::Value {
    let Some(diff) = diff else {
        return serde_json::Value::Null;
    };
    let parsed_diff_json = serde_json::from_str(&diff.diff_json)
        .unwrap_or_else(|_| serde_json::Value::String(diff.diff_json.clone()));
    serde_json::json!({
        "has_actionable_changes": diff.has_actionable_changes,
        "has_reload_applied_changes": diff.has_reload_applied_changes,
        "has_restart_required_changes": diff.has_restart_required_changes,
        "has_informational_changes": diff.has_informational_changes,
        "has_any_changes": diff.has_any_changes,
        "human_text": diff.human_text,
        "diff_json": parsed_diff_json,
    })
}

fn plan_to_json(resp: &ConfigTransactionPlanResponse) -> serde_json::Value {
    serde_json::json!({
        "status": status_label(resp.status),
        "runtime_snapshot_token": resp.runtime_snapshot_token,
        "diff": diff_to_json(resp.diff.as_ref()),
        "supported_sections": resp.supported_sections,
        "unsupported_sections": resp.unsupported_sections,
        "restart_required_sections": resp.restart_required_sections,
        "human_text": resp.human_text,
    })
}

fn apply_to_json(resp: &ConfigTransactionApplyResponse) -> serde_json::Value {
    serde_json::json!({
        "status": status_label(resp.status),
        "runtime_snapshot_token": resp.runtime_snapshot_token,
        "committed_sections": resp.committed_sections,
        "human_text": resp.human_text,
    })
}

fn print_plan_human(resp: &ConfigTransactionPlanResponse) {
    print!("{}", resp.human_text);
    print_transaction_tail(
        resp.status,
        &resp.runtime_snapshot_token,
        &[
            ("supported_sections", &resp.supported_sections),
            ("unsupported_sections", &resp.unsupported_sections),
            ("restart_required_sections", &resp.restart_required_sections),
        ],
    );
}

fn print_apply_human(resp: &ConfigTransactionApplyResponse) {
    print!("{}", resp.human_text);
    print_transaction_tail(
        resp.status,
        &resp.runtime_snapshot_token,
        &[("committed_sections", &resp.committed_sections)],
    );
}

fn print_transaction_tail(
    status: i32,
    runtime_snapshot_token: &str,
    sections: &[(&str, &Vec<String>)],
) {
    println!("status: {}", status_label(status));
    if !runtime_snapshot_token.is_empty() {
        println!("runtime_snapshot_token: {runtime_snapshot_token}");
    }
    for (label, values) in sections {
        if !values.is_empty() {
            println!("{label}: {}", values.join(", "));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::connection::connect;
    use crate::test_support::spawn_mock_server;

    #[tokio::test]
    async fn diff_sends_candidate_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("candidate.toml");
        std::fs::write(&path, "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\n").unwrap();
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        diff(connection, path.to_str().unwrap(), true)
            .await
            .unwrap();

        assert_eq!(server.state.config_diff_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            server.state.last_config_diff.lock().await.as_deref(),
            Some("[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\n")
        );
    }

    #[tokio::test]
    async fn plan_sends_candidate_file_and_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("candidate.toml");
        std::fs::write(&path, "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\n").unwrap();
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        plan(connection, path.to_str().unwrap(), Some("kv1:old:1"), true)
            .await
            .unwrap();

        assert_eq!(server.state.config_plan_calls.load(Ordering::SeqCst), 1);
        let request = server.state.last_config_plan.lock().await.clone().unwrap();
        assert_eq!(
            request.candidate_toml,
            "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\n"
        );
        assert_eq!(request.expected_runtime_snapshot_token, "kv1:old:1");
    }

    #[tokio::test]
    async fn apply_sends_candidate_token_and_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("candidate.toml");
        std::fs::write(&path, "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\n").unwrap();
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        apply(
            connection,
            path.to_str().unwrap(),
            "kv1:old:1",
            Some("deploy-123"),
            Some("roll candidate"),
            true,
        )
        .await
        .unwrap();

        assert_eq!(server.state.config_apply_calls.load(Ordering::SeqCst), 1);
        let request = server.state.last_config_apply.lock().await.clone().unwrap();
        assert_eq!(
            request.candidate_toml,
            "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\n"
        );
        assert_eq!(request.expected_runtime_snapshot_token, "kv1:old:1");
        assert_eq!(request.client_request_id, "deploy-123");
        assert_eq!(request.comment, "roll candidate");
    }

    #[test]
    fn plan_json_shape_is_stable() {
        let value = plan_to_json(&ConfigTransactionPlanResponse {
            status: ConfigTransactionPlanStatus::Committable as i32,
            runtime_snapshot_token: "kv1:planned:1".to_string(),
            diff: Some(DiffRuntimeConfigResponse {
                has_actionable_changes: true,
                has_reload_applied_changes: true,
                has_restart_required_changes: false,
                has_informational_changes: false,
                has_any_changes: true,
                human_text: "Reload-applied changes:\n".to_string(),
                diff_json: "{\"reload_applied\":{}}".to_string(),
            }),
            supported_sections: vec!["[[fib_tables]]".to_string()],
            unsupported_sections: vec!["[policy]".to_string()],
            restart_required_sections: vec!["[global]".to_string()],
            human_text: "Config transaction is rejected.\n".to_string(),
        });

        assert_eq!(value["status"], "committable");
        assert_eq!(value["runtime_snapshot_token"], "kv1:planned:1");
        assert_eq!(value["supported_sections"][0], "[[fib_tables]]");
        assert_eq!(value["unsupported_sections"][0], "[policy]");
        assert_eq!(value["restart_required_sections"][0], "[global]");
        assert_eq!(
            value["diff"]["diff_json"]["reload_applied"],
            serde_json::json!({})
        );
    }

    #[test]
    fn apply_json_shape_is_stable() {
        let value = apply_to_json(&ConfigTransactionApplyResponse {
            status: ConfigTransactionPlanStatus::Committable as i32,
            runtime_snapshot_token: "kv1:committed:2".to_string(),
            committed_sections: vec!["[[dynamic_neighbors]]".to_string()],
            human_text: "Committed [[dynamic_neighbors]] transaction.\n".to_string(),
        });

        assert_eq!(value["status"], "committable");
        assert_eq!(value["runtime_snapshot_token"], "kv1:committed:2");
        assert_eq!(value["committed_sections"][0], "[[dynamic_neighbors]]");
        assert_eq!(
            value["human_text"],
            "Committed [[dynamic_neighbors]] transaction.\n"
        );
    }
}
