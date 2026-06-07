use crate::connection::Connection;
use crate::error::CliError;
use crate::proto::config_service_client::ConfigServiceClient;
use crate::proto::{
    AbortConfigTransactionRequest, ApplyConfigTransactionRequest, ConfigTransactionApplyResponse,
    ConfigTransactionConfirmation, ConfigTransactionConfirmationStatus,
    ConfigTransactionPlanResponse, ConfigTransactionPlanStatus, ConfigTransactionStatusResponse,
    ConfirmConfigTransactionRequest, DiffRuntimeConfigRequest, DiffRuntimeConfigResponse,
    GetConfigTransactionStatusRequest, PlanConfigTransactionRequest,
};

const MAX_CONFIRM_ID_CHARS: usize = 128;
const MAX_CONFIRM_TIMEOUT_SECONDS: u32 = 86_400;

pub struct ApplyOptions<'a> {
    pub from_file: &'a str,
    pub expected_runtime_snapshot_token: &'a str,
    pub client_request_id: Option<&'a str>,
    pub comment: Option<&'a str>,
    pub confirm_id: Option<&'a str>,
    pub confirm_timeout_seconds: Option<u32>,
}

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
        print_json(plan_to_json(&resp))?;
    } else {
        print_plan_human(&resp);
    }
    Ok(())
}

pub async fn apply(
    connection: Connection,
    options: ApplyOptions<'_>,
    json: bool,
) -> Result<(), CliError> {
    if options.expected_runtime_snapshot_token.is_empty() {
        return Err(CliError::Argument(
            "--expected-runtime-snapshot-token must not be empty".to_string(),
        ));
    }
    if options.confirm_id.is_none() && options.confirm_timeout_seconds.is_some() {
        return Err(CliError::Argument(
            "--confirm-timeout requires --confirm-id".to_string(),
        ));
    }
    if let Some(confirm_id) = options.confirm_id {
        validate_confirm_id(confirm_id)?;
    }
    if matches!(
        options.confirm_timeout_seconds,
        Some(timeout_seconds) if timeout_seconds > MAX_CONFIRM_TIMEOUT_SECONDS
    ) {
        return Err(CliError::Argument(format!(
            "--confirm-timeout must be <= {MAX_CONFIRM_TIMEOUT_SECONDS}"
        )));
    }
    let candidate_toml = read_candidate_toml(options.from_file)?;
    let mut client =
        ConfigServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .apply_config_transaction(ApplyConfigTransactionRequest {
            candidate_toml,
            expected_runtime_snapshot_token: options.expected_runtime_snapshot_token.to_string(),
            client_request_id: options.client_request_id.unwrap_or_default().to_string(),
            comment: options.comment.unwrap_or_default().to_string(),
            confirm_id: options.confirm_id.unwrap_or_default().to_string(),
            confirm_timeout_seconds: options.confirm_timeout_seconds.unwrap_or_default(),
        })
        .await?
        .into_inner();

    if json {
        print_json(apply_to_json(&resp))?;
    } else {
        print_apply_human(&resp);
    }
    Ok(())
}

pub async fn confirm(connection: Connection, confirm_id: &str, json: bool) -> Result<(), CliError> {
    validate_confirm_id(confirm_id)?;
    let mut client =
        ConfigServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .confirm_config_transaction(ConfirmConfigTransactionRequest {
            confirm_id: confirm_id.to_string(),
        })
        .await?
        .into_inner();

    if json {
        print_json(serde_json::json!({
            "confirmation": confirmation_to_json(resp.confirmation.as_ref()),
            "human_text": resp.human_text,
        }))?;
    } else {
        print!("{}", resp.human_text);
        print_confirmation(resp.confirmation.as_ref());
    }
    Ok(())
}

pub async fn abort(connection: Connection, confirm_id: &str, json: bool) -> Result<(), CliError> {
    validate_confirm_id(confirm_id)?;
    let mut client =
        ConfigServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .abort_config_transaction(AbortConfigTransactionRequest {
            confirm_id: confirm_id.to_string(),
        })
        .await?
        .into_inner();

    if json {
        print_json(serde_json::json!({
            "confirmation": confirmation_to_json(resp.confirmation.as_ref()),
            "runtime_snapshot_token": resp.runtime_snapshot_token,
            "human_text": resp.human_text,
        }))?;
    } else {
        print!("{}", resp.human_text);
        if !resp.runtime_snapshot_token.is_empty() {
            println!("runtime_snapshot_token: {}", resp.runtime_snapshot_token);
        }
        print_confirmation(resp.confirmation.as_ref());
    }
    Ok(())
}

pub async fn status(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut client =
        ConfigServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .get_config_transaction_status(GetConfigTransactionStatusRequest {})
        .await?
        .into_inner();

    if json {
        print_json(status_to_json(&resp))?;
    } else {
        print!("{}", resp.human_text);
        print_confirmation(resp.confirmation.as_ref());
    }
    Ok(())
}

fn read_candidate_toml(from_file: &str) -> Result<String, CliError> {
    std::fs::read_to_string(from_file)
        .map_err(|error| CliError::Argument(format!("failed to read {from_file}: {error}")))
}

fn validate_confirm_id(confirm_id: &str) -> Result<(), CliError> {
    if confirm_id.trim().is_empty() {
        return Err(CliError::Argument(
            "confirm_id must not be empty".to_string(),
        ));
    }
    if confirm_id.chars().count() > MAX_CONFIRM_ID_CHARS {
        return Err(CliError::Argument(format!(
            "confirm_id must be at most {MAX_CONFIRM_ID_CHARS} characters"
        )));
    }
    if confirm_id.chars().any(char::is_control) {
        return Err(CliError::Argument(
            "confirm_id must not contain control characters".to_string(),
        ));
    }
    Ok(())
}

fn print_json(value: serde_json::Value) -> Result<(), CliError> {
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
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

fn confirmation_status_label(status: i32) -> &'static str {
    match ConfigTransactionConfirmationStatus::try_from(status)
        .unwrap_or(ConfigTransactionConfirmationStatus::Unspecified)
    {
        ConfigTransactionConfirmationStatus::Unspecified => "unspecified",
        ConfigTransactionConfirmationStatus::None => "none",
        ConfigTransactionConfirmationStatus::Pending => "pending",
        ConfigTransactionConfirmationStatus::Confirmed => "confirmed",
        ConfigTransactionConfirmationStatus::Aborted => "aborted",
        ConfigTransactionConfirmationStatus::AutoReverted => "auto_reverted",
        ConfigTransactionConfirmationStatus::AutoRevertFailed => "auto_revert_failed",
        ConfigTransactionConfirmationStatus::AbortFailed => "abort_failed",
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
        "confirmation": confirmation_to_json(resp.confirmation.as_ref()),
    })
}

fn confirmation_to_json(confirmation: Option<&ConfigTransactionConfirmation>) -> serde_json::Value {
    let Some(confirmation) = confirmation else {
        return serde_json::Value::Null;
    };
    serde_json::json!({
        "status": confirmation_status_label(confirmation.status),
        "confirm_id": confirmation.confirm_id,
        "timeout_seconds": confirmation.timeout_seconds,
        "deadline_unix_seconds": confirmation.deadline_unix_seconds,
        "committed_sections": confirmation.committed_sections,
        "runtime_snapshot_token": confirmation.runtime_snapshot_token,
        "human_text": confirmation.human_text,
    })
}

fn status_to_json(resp: &ConfigTransactionStatusResponse) -> serde_json::Value {
    serde_json::json!({
        "confirmation": confirmation_to_json(resp.confirmation.as_ref()),
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
    print_confirmation(resp.confirmation.as_ref());
}

fn print_confirmation(confirmation: Option<&ConfigTransactionConfirmation>) {
    let Some(confirmation) = confirmation else {
        return;
    };
    println!(
        "confirmation_status: {}",
        confirmation_status_label(confirmation.status)
    );
    if !confirmation.confirm_id.is_empty() {
        println!("confirm_id: {}", confirmation.confirm_id);
    }
    if confirmation.timeout_seconds > 0 {
        println!("confirm_timeout_seconds: {}", confirmation.timeout_seconds);
    }
    if confirmation.deadline_unix_seconds > 0 {
        println!(
            "confirm_deadline_unix_seconds: {}",
            confirmation.deadline_unix_seconds
        );
    }
    if !confirmation.runtime_snapshot_token.is_empty() {
        println!(
            "confirmation_runtime_snapshot_token: {}",
            confirmation.runtime_snapshot_token
        );
    }
    if !confirmation.committed_sections.is_empty() {
        println!(
            "confirmation_committed_sections: {}",
            confirmation.committed_sections.join(", ")
        );
    }
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
            ApplyOptions {
                from_file: path.to_str().unwrap(),
                expected_runtime_snapshot_token: "kv1:old:1",
                client_request_id: Some("deploy-123"),
                comment: Some("roll candidate"),
                confirm_id: Some("confirm-123"),
                confirm_timeout_seconds: Some(120),
            },
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
        assert_eq!(request.confirm_id, "confirm-123");
        assert_eq!(request.confirm_timeout_seconds, 120);
    }

    #[tokio::test]
    async fn apply_rejects_empty_confirm_id_before_rpc() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        let err = apply(
            connection,
            ApplyOptions {
                from_file: "/does/not/matter.toml",
                expected_runtime_snapshot_token: "kv1:old:1",
                client_request_id: None,
                comment: None,
                confirm_id: Some(""),
                confirm_timeout_seconds: Some(120),
            },
            true,
        )
        .await
        .expect_err("empty confirm_id must fail before RPC");

        assert!(
            matches!(err, CliError::Argument(ref message) if message == "confirm_id must not be empty"),
            "{err:?}"
        );
        assert_eq!(server.state.config_apply_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn apply_rejects_too_long_confirm_id_before_rpc() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        let confirm_id = "x".repeat(MAX_CONFIRM_ID_CHARS + 1);

        let err = apply(
            connection,
            ApplyOptions {
                from_file: "/does/not/matter.toml",
                expected_runtime_snapshot_token: "kv1:old:1",
                client_request_id: None,
                comment: None,
                confirm_id: Some(confirm_id.as_str()),
                confirm_timeout_seconds: Some(120),
            },
            true,
        )
        .await
        .expect_err("over-limit confirm_id must fail before RPC");

        assert!(
            matches!(err, CliError::Argument(ref message) if message == "confirm_id must be at most 128 characters"),
            "{err:?}"
        );
        assert_eq!(server.state.config_apply_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn apply_rejects_control_char_confirm_id_before_rpc() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        let err = apply(
            connection,
            ApplyOptions {
                from_file: "/does/not/matter.toml",
                expected_runtime_snapshot_token: "kv1:old:1",
                client_request_id: None,
                comment: None,
                confirm_id: Some("bad\nid"),
                confirm_timeout_seconds: Some(120),
            },
            true,
        )
        .await
        .expect_err("control-character confirm_id must fail before RPC");

        assert!(
            matches!(err, CliError::Argument(ref message) if message == "confirm_id must not contain control characters"),
            "{err:?}"
        );
        assert_eq!(server.state.config_apply_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn apply_rejects_confirm_timeout_without_confirm_id_before_rpc() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        let err = apply(
            connection,
            ApplyOptions {
                from_file: "/does/not/matter.toml",
                expected_runtime_snapshot_token: "kv1:old:1",
                client_request_id: None,
                comment: None,
                confirm_id: None,
                confirm_timeout_seconds: Some(120),
            },
            true,
        )
        .await
        .expect_err("confirm timeout without confirm_id must fail before RPC");

        assert!(
            matches!(err, CliError::Argument(ref message) if message == "--confirm-timeout requires --confirm-id"),
            "{err:?}"
        );
        assert_eq!(server.state.config_apply_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn apply_rejects_too_large_confirm_timeout_before_rpc() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        let err = apply(
            connection,
            ApplyOptions {
                from_file: "/does/not/matter.toml",
                expected_runtime_snapshot_token: "kv1:old:1",
                client_request_id: None,
                comment: None,
                confirm_id: Some("deploy-123"),
                confirm_timeout_seconds: Some(MAX_CONFIRM_TIMEOUT_SECONDS + 1),
            },
            true,
        )
        .await
        .expect_err("over-limit confirm timeout must fail before RPC");

        assert!(
            matches!(err, CliError::Argument(ref message) if message == "--confirm-timeout must be <= 86400"),
            "{err:?}"
        );
        assert_eq!(server.state.config_apply_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn confirm_sends_confirm_id() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        confirm(connection, "confirm-123", true).await.unwrap();

        assert_eq!(server.state.config_confirm_calls.load(Ordering::SeqCst), 1);
        let request = server
            .state
            .last_config_confirm
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(request.confirm_id, "confirm-123");
    }

    #[tokio::test]
    async fn confirm_rejects_empty_confirm_id_before_rpc() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        let err = confirm(connection, "", true)
            .await
            .expect_err("empty confirm_id must fail before RPC");

        assert!(
            matches!(err, CliError::Argument(ref message) if message == "confirm_id must not be empty"),
            "{err:?}"
        );
        assert_eq!(server.state.config_confirm_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn confirm_rejects_invalid_confirm_id_before_rpc() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        let err = confirm(connection, "   ", true)
            .await
            .expect_err("blank confirm_id must fail before RPC");
        assert!(
            matches!(err, CliError::Argument(ref message) if message == "confirm_id must not be empty"),
            "{err:?}"
        );

        let connection = connect(&server.addr, None).await.unwrap();
        let err = confirm(connection, "bad\nid", true)
            .await
            .expect_err("control-character confirm_id must fail before RPC");
        assert!(
            matches!(err, CliError::Argument(ref message) if message == "confirm_id must not contain control characters"),
            "{err:?}"
        );

        assert_eq!(server.state.config_confirm_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn confirm_rpc_error_maps_to_cli_error() {
        let server = spawn_mock_server(None).await;
        *server.state.config_confirm_error.lock().await =
            Some((tonic::Code::FailedPrecondition, "no pending".to_string()));
        let connection = connect(&server.addr, None).await.unwrap();

        let err = confirm(connection, "confirm-123", true)
            .await
            .expect_err("confirm RPC error must surface as CLI error");

        assert!(
            matches!(err, CliError::Rpc(ref message) if message.contains("no pending")),
            "{err:?}"
        );
        assert_eq!(server.state.config_confirm_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn abort_sends_confirm_id() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        abort(connection, "confirm-123", true).await.unwrap();

        assert_eq!(server.state.config_abort_calls.load(Ordering::SeqCst), 1);
        let request = server.state.last_config_abort.lock().await.clone().unwrap();
        assert_eq!(request.confirm_id, "confirm-123");
    }

    #[tokio::test]
    async fn abort_rejects_empty_confirm_id_before_rpc() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        let err = abort(connection, "", true)
            .await
            .expect_err("empty confirm_id must fail before RPC");

        assert!(
            matches!(err, CliError::Argument(ref message) if message == "confirm_id must not be empty"),
            "{err:?}"
        );
        assert_eq!(server.state.config_abort_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn abort_rejects_too_long_confirm_id_before_rpc() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        let confirm_id = "x".repeat(MAX_CONFIRM_ID_CHARS + 1);

        let err = abort(connection, &confirm_id, true)
            .await
            .expect_err("over-limit confirm_id must fail before RPC");

        assert!(
            matches!(err, CliError::Argument(ref message) if message == "confirm_id must be at most 128 characters"),
            "{err:?}"
        );
        assert_eq!(server.state.config_abort_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn abort_rejects_control_char_confirm_id_before_rpc() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        let err = abort(connection, "bad\nid", true)
            .await
            .expect_err("control-character confirm_id must fail before RPC");

        assert!(
            matches!(err, CliError::Argument(ref message) if message == "confirm_id must not contain control characters"),
            "{err:?}"
        );
        assert_eq!(server.state.config_abort_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn abort_rpc_error_maps_to_cli_error() {
        let server = spawn_mock_server(None).await;
        *server.state.config_abort_error.lock().await =
            Some((tonic::Code::Internal, "abort failed".to_string()));
        let connection = connect(&server.addr, None).await.unwrap();

        let err = abort(connection, "confirm-123", true)
            .await
            .expect_err("abort RPC error must surface as CLI error");

        assert!(
            matches!(err, CliError::Rpc(ref message) if message.contains("abort failed")),
            "{err:?}"
        );
        assert_eq!(server.state.config_abort_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn status_calls_config_status_rpc() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        status(connection, true).await.unwrap();

        assert_eq!(server.state.config_status_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn status_rpc_error_maps_to_cli_error() {
        let server = spawn_mock_server(None).await;
        *server.state.config_status_error.lock().await =
            Some((tonic::Code::Internal, "status unavailable".to_string()));
        let connection = connect(&server.addr, None).await.unwrap();

        let err = status(connection, true)
            .await
            .expect_err("status RPC error must surface as CLI error");

        assert!(
            matches!(err, CliError::Rpc(ref message) if message.contains("status unavailable")),
            "{err:?}"
        );
        assert_eq!(server.state.config_status_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn confirmation_status_labels_include_abort_failed() {
        assert_eq!(
            confirmation_status_label(ConfigTransactionConfirmationStatus::AbortFailed as i32),
            "abort_failed"
        );
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
            confirmation: Some(ConfigTransactionConfirmation {
                status: ConfigTransactionConfirmationStatus::Pending as i32,
                confirm_id: "confirm-123".to_string(),
                timeout_seconds: 120,
                deadline_unix_seconds: 1_787_000_000,
                committed_sections: vec!["[[dynamic_neighbors]]".to_string()],
                runtime_snapshot_token: "kv1:committed:2".to_string(),
                human_text: "Confirmed config transaction is pending confirmation.".to_string(),
            }),
        });

        assert_eq!(value["status"], "committable");
        assert_eq!(value["runtime_snapshot_token"], "kv1:committed:2");
        assert_eq!(value["committed_sections"][0], "[[dynamic_neighbors]]");
        assert_eq!(
            value["human_text"],
            "Committed [[dynamic_neighbors]] transaction.\n"
        );
        assert_eq!(value["confirmation"]["status"], "pending");
        assert_eq!(value["confirmation"]["confirm_id"], "confirm-123");
        assert_eq!(value["confirmation"]["timeout_seconds"], 120);
        assert_eq!(
            value["confirmation"]["committed_sections"][0],
            "[[dynamic_neighbors]]"
        );
    }

    #[test]
    fn status_json_shape_is_stable() {
        let value = status_to_json(&ConfigTransactionStatusResponse {
            confirmation: Some(ConfigTransactionConfirmation {
                status: ConfigTransactionConfirmationStatus::Pending as i32,
                confirm_id: "confirm-123".to_string(),
                timeout_seconds: 120,
                deadline_unix_seconds: 1_787_000_000,
                committed_sections: vec!["[[dynamic_neighbors]]".to_string()],
                runtime_snapshot_token: "kv1:committed:2".to_string(),
                human_text: "Confirmed config transaction is pending confirmation.".to_string(),
            }),
            human_text: "Confirmed config transaction pending.\n".to_string(),
        });

        assert_eq!(
            value["human_text"],
            "Confirmed config transaction pending.\n"
        );
        assert_eq!(value["confirmation"]["status"], "pending");
        assert_eq!(value["confirmation"]["confirm_id"], "confirm-123");
        assert_eq!(value["confirmation"]["timeout_seconds"], 120);
        assert_eq!(
            value["confirmation"]["deadline_unix_seconds"],
            1_787_000_000u64
        );
        assert_eq!(
            value["confirmation"]["committed_sections"][0],
            "[[dynamic_neighbors]]"
        );
        assert_eq!(
            value["confirmation"]["runtime_snapshot_token"],
            "kv1:committed:2"
        );
    }

    #[test]
    fn status_json_confirmation_null_when_absent() {
        let value = status_to_json(&ConfigTransactionStatusResponse {
            confirmation: None,
            human_text: "No confirmed config transaction.\n".to_string(),
        });
        assert!(value["confirmation"].is_null());
        assert_eq!(value["human_text"], "No confirmed config transaction.\n");
    }
}
