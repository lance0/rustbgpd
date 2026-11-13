//! Health output, liveness isolation, and failed probe exit contracts.

use rustbgpd_api::proto;
use std::sync::atomic::Ordering;

#[path = "../src/test_support.rs"]
#[allow(
    dead_code,
    reason = "shared CLI mock includes services unused by this contract"
)]
mod test_support;

async fn run(addr: &str, args: &[&str]) -> std::process::Output {
    tokio::process::Command::new(env!("CARGO_BIN_EXE_rbgp"))
        .args(["--addr", addr])
        .args(args)
        .env("NO_COLOR", "1")
        .env_remove("RUSTBGPD_TOKEN_FILE")
        .output()
        .await
        .unwrap()
}

#[tokio::test]
async fn health_preserves_default_output_and_liveness_discloses_no_counts() {
    let server = test_support::spawn_mock_server(None).await;
    let output = run(&server.addr, &["health"]).await;
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "Status:            healthy\nUptime:            00:00:42\nEstablished peers: 2\nRoutes:            10\nVersion:           0.0.0-mock\n"
    );
    let output = run(&server.addr, &["--json", "health"]).await;
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!({
            "healthy": true, "uptime_seconds": 42, "active_peers": 2, "total_routes": 10,
            "daemon_version": "0.0.0-mock"
        })
    );
    let output = run(&server.addr, &["health", "--liveness"]).await;
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"alive\n");
    let output = run(&server.addr, &["--json", "health", "--liveness"]).await;
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!({"alive": true})
    );
    assert_eq!(server.state.health_calls.load(Ordering::SeqCst), 2);
    assert_eq!(server.state.liveness_calls.load(Ordering::SeqCst), 2);
}

/// A daemon that reports no version gets no `Version:` line and a JSON
/// `null`, not an empty string.
#[tokio::test]
async fn health_without_a_daemon_version_omits_it() {
    let server = test_support::spawn_mock_server(None).await;
    *server.state.health_daemon_version.lock().await = Some(String::new());
    let output = run(&server.addr, &["health"]).await;
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "Status:            healthy\nUptime:            00:00:42\nEstablished peers: 2\nRoutes:            10\n"
    );
    let output = run(&server.addr, &["--json", "health"]).await;
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!({
            "healthy": true, "uptime_seconds": 42, "active_peers": 2, "total_routes": 10,
            "daemon_version": null
        })
    );
}

#[tokio::test]
async fn refused_and_unreachable_liveness_probes_fail_without_stdout() {
    let server = test_support::spawn_mock_server(Some("secret")).await;
    let output = run(&server.addr, &["health", "--liveness"]).await;
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty());
    assert_eq!(server.state.liveness_calls.load(Ordering::SeqCst), 0);
    let dir = tempfile::tempdir().unwrap();
    let output = run(
        &format!("unix://{}", dir.path().join("missing.sock").display()),
        &["health", "--liveness"],
    )
    .await;
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty());
}
