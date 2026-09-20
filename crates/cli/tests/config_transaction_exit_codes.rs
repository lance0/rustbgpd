//! Real-process exit codes for `config plan`, `apply`, and `rollback` across
//! the committable/committed, noop, and rejected transaction statuses, plus
//! plain/versioned output contracts for the remaining configuration documents.

// The shared mock resolves `crate::proto`.
use rustbgpd_api::proto::{self, ConfigTransactionPlanStatus as Status};
use std::process::Output;
use std::sync::atomic::Ordering;

#[path = "../src/test_support.rs"]
#[allow(
    dead_code,
    reason = "shared CLI mock includes services unused by this contract"
)]
mod test_support;

const CANDIDATE: &str = "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\n";

async fn run(addr: &str, args: &[&str]) -> Output {
    tokio::process::Command::new(env!("CARGO_BIN_EXE_rbgp"))
        .args(["--addr", addr])
        .args(args)
        .env("NO_COLOR", "1")
        .env_remove("RUSTBGPD_TOKEN_FILE")
        .output()
        .await
        .unwrap()
}

/// A streaming-capable mock whose streamed plan answers `plan` and whose
/// apply and rollback receipts answer `receipt`.
async fn server(plan: Status, receipt: Status) -> test_support::MockServerHandle {
    let server = test_support::spawn_mock_server(None).await;
    let state = &server.state;
    state.config_streaming_enabled.store(true, Ordering::SeqCst);
    state
        .config_stream_plan_status
        .store(plan as usize, Ordering::SeqCst);
    state
        .config_apply_status
        .store(receipt as usize, Ordering::SeqCst);
    server
}

fn candidate() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("candidate.toml");
    std::fs::write(&path, CANDIDATE).unwrap();
    let path = path.to_str().unwrap().to_string();
    (dir, path)
}

/// The full JSON receipt is still printed, whatever the exit code.
fn assert_json_status(output: &Output, code: i32, status: &str) {
    assert_eq!(output.status.code(), Some(code), "{output:?}");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("stdout must be one JSON receipt ({error}): {output:?}"));
    assert_eq!(json["status"], status, "{json}");
    assert!(json["human_text"].is_string(), "{json}");
}

#[tokio::test]
async fn plan_exits_zero_noop_two_committable_three_rejected() {
    let (_dir, path) = candidate();
    for (status, code, label) in [
        (Status::Noop, 0, "noop"),
        (Status::Committable, 2, "committable"),
        (Status::Rejected, 3, "rejected"),
    ] {
        let server = server(status, Status::Committable).await;
        let output = run(&server.addr, &["--json", "config", "plan", &path]).await;
        assert_json_status(&output, code, label);
        let mut versioned = run(
            &server.addr,
            &["--json", "--json-version", "1", "config", "plan", &path],
        )
        .await;
        let document: serde_json::Value = serde_json::from_slice(&versioned.stdout).unwrap();
        assert_eq!(document["format_version"], "1.0");
        versioned.stdout = serde_json::to_vec(&document["data"]).unwrap();
        assert_json_status(&versioned, code, label);
    }
}

async fn apply(addr: &str, path: &str, plan_token: Option<&str>) -> Output {
    let mut args = vec![
        "--json",
        "config",
        "apply",
        path,
        "--expected-runtime-snapshot-token",
        "kv1:planned:1",
    ];
    if let Some(token) = plan_token {
        args.extend(["--plan-token", token]);
    }
    run(addr, &args).await
}

#[tokio::test]
async fn apply_exits_zero_committed_or_noop_and_three_rejected() {
    let (_dir, path) = candidate();
    let apply_calls = |server: &test_support::MockServerHandle| {
        server
            .state
            .config_stream_apply_calls
            .load(Ordering::SeqCst)
    };

    // Committed: implicit committable plan, then a committable apply receipt.
    let server_committed = server(Status::Committable, Status::Committable).await;
    let output = apply(&server_committed.addr, &path, None).await;
    assert_json_status(&output, 0, "committable");
    assert_eq!(apply_calls(&server_committed), 1);

    // Noop and rejected implicit plans return without calling Apply.
    for (status, code, label) in [(Status::Noop, 0, "noop"), (Status::Rejected, 3, "rejected")] {
        let server = server(status, Status::Committable).await;
        let output = apply(&server.addr, &path, None).await;
        assert_json_status(&output, code, label);
        assert_eq!(apply_calls(&server), 0, "{label}");
    }

    // The daemon's apply-time re-plan can itself reject or find nothing to do.
    for (receipt, code, label) in [(Status::Noop, 0, "noop"), (Status::Rejected, 3, "rejected")] {
        let server = server(Status::Committable, receipt).await;
        let output = apply(&server.addr, &path, Some("reviewed-plan-token")).await;
        assert_json_status(&output, code, label);
        assert_eq!(apply_calls(&server), 1, "{label}");
    }
}

#[tokio::test]
async fn rollback_exits_zero_committed_or_noop_and_three_rejected() {
    for (receipt, code, label) in [
        (Status::Committable, 0, "committable"),
        (Status::Noop, 0, "noop"),
        (Status::Rejected, 3, "rejected"),
    ] {
        let server = server(Status::Committable, receipt).await;
        let output = run(&server.addr, &["--json", "config", "rollback", "1"]).await;
        assert_json_status(&output, code, label);
    }
}

#[tokio::test]
async fn rejected_human_receipts_print_unchanged_and_exit_three() {
    let (_dir, path) = candidate();
    let server = server(Status::Rejected, Status::Rejected).await;
    for args in [
        vec!["config", "plan", &path],
        vec![
            "config",
            "apply",
            &path,
            "--expected-runtime-snapshot-token",
            "kv1:planned:1",
        ],
        vec!["config", "rollback", "1"],
    ] {
        let output = run(&server.addr, &args).await;
        assert_eq!(output.status.code(), Some(3), "{args:?}: {output:?}");
        assert!(output.stderr.is_empty(), "{args:?}: {output:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("status: rejected"), "{args:?}: {stdout}");
    }
}

#[tokio::test]
async fn unrecognized_receipt_status_fails_closed_after_printing() {
    let (_dir, path) = candidate();
    let server = server(Status::Committable, Status::Committable).await;
    // An out-of-range value: the mock serves a stored 0 as committable.
    server
        .state
        .config_apply_status
        .store(999, Ordering::SeqCst);
    server
        .state
        .config_stream_plan_status
        .store(999, Ordering::SeqCst);
    for args in [
        vec!["--json", "config", "plan", &path],
        // An explicit token bypasses implicit planning, so this exercises
        // an unknown final apply receipt rather than an unknown plan.
        vec![
            "--json",
            "config",
            "apply",
            &path,
            "--expected-runtime-snapshot-token",
            "kv1:planned:1",
            "--plan-token",
            "reviewed-plan-token",
        ],
        vec!["--json", "config", "rollback", "1"],
    ] {
        let output = run(&server.addr, &args).await;
        assert_eq!(output.status.code(), Some(1), "{args:?}: {output:?}");
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(json["status"], "unspecified", "{json}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("invalid"), "{args:?}: {stderr}");
    }
}

#[tokio::test]
async fn remaining_config_documents_preserve_plain_and_versioned_payloads() {
    let server = test_support::spawn_mock_server(None).await;
    *server.state.config_effective_toml.lock().await = Some(
        "[global]\nasn = 65001\n[future_settings]\nenabled = false\nvalues = [3, 1, 3]\n"
            .to_string(),
    );
    for command in [
        vec!["config", "confirm", "process-confirm"],
        vec!["config", "abort", "process-abort"],
        vec!["config", "history"],
        vec!["config", "effective"],
    ] {
        let mut plain_args = vec!["--json"];
        plain_args.extend_from_slice(&command);
        let plain = run(&server.addr, &plain_args).await;
        assert_eq!(plain.status.code(), Some(0), "{command:?}: {plain:?}");
        assert!(plain.stderr.is_empty(), "{command:?}: {plain:?}");
        let payload: serde_json::Value = serde_json::from_slice(&plain.stdout).unwrap();
        // Ordinary output remains the command object, without version metadata.
        assert!(payload.is_object());
        assert!(payload.get("format_version").is_none());
        match command[1] {
            "confirm" => assert_eq!(payload["confirmation"]["confirm_id"], "process-confirm"),
            "abort" => assert_eq!(payload["runtime_snapshot_token"], "kv1:rollback:3"),
            "history" => assert_eq!(payload["entries"].as_array().unwrap().len(), 2),
            "effective" => assert_eq!(
                payload,
                serde_json::json!({
                    "global": {"asn": 65001},
                    "future_settings": {"enabled": false, "values": [3, 1, 3]},
                })
            ),
            _ => unreachable!(),
        }
        let mut versioned_args = vec!["--json", "--json-version", "1"];
        versioned_args.extend_from_slice(&command);
        let versioned = run(&server.addr, &versioned_args).await;
        assert_eq!(
            versioned.status.code(),
            Some(0),
            "{command:?}: {versioned:?}"
        );
        assert!(versioned.stderr.is_empty(), "{command:?}: {versioned:?}");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&versioned.stdout).unwrap(),
            serde_json::json!({"format": "rbgp-json", "format_version": "1.0", "data": payload})
        );
    }

    // Malformed daemon TOML cannot become a successful or partial JSON document.
    *server.state.config_effective_toml.lock().await = Some("invalid = [".to_string());
    for args in [
        vec!["--json", "config", "effective"],
        vec!["--json", "--json-version", "1", "config", "effective"],
    ] {
        let output = run(&server.addr, &args).await;
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("unparseable effective config TOML")
        );
    }
}
