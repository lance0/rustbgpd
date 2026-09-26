//! Daemon-wide mutations run without a prompt when stdin and stdout are not
//! terminals, and an omitted scope is a usage error that never reaches the
//! daemon.

use std::process::{Command, Output, Stdio};

// `test_support` resolves protobuf types through `crate::proto`.
use rustbgpd_api::proto;

#[path = "../src/test_support.rs"]
#[allow(
    dead_code,
    reason = "shared CLI mock includes services unused by this contract"
)]
mod test_support;

fn rbgp(addr: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rbgp"))
        .args(["--addr", addr, "--no-color"])
        .args(args)
        .stdin(Stdio::null())
        .env_remove("RUSTBGPD_TOKEN_FILE")
        .output()
        .unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn omitted_chain_scope_is_a_usage_error_without_rpc() {
    let server = test_support::spawn_mock_server(None).await;
    for args in [
        vec!["policy", "chain", "set-import", "p1"],
        vec!["policy", "chain", "set-export", "--yes", "p1"],
        vec!["policy", "chain", "clear-import"],
        vec!["policy", "chain", "clear-export", "-y"],
    ] {
        let output = rbgp(&server.addr, &args);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        let error = stderr(&output);
        assert!(
            error.contains("the following required arguments were not provided"),
            "{args:?}: {error}"
        );
        assert!(
            error.contains("<--neighbor <NEIGHBOR>|--global>"),
            "{args:?}: {error}"
        );
        assert!(output.stdout.is_empty(), "{args:?}: {output:?}");
    }
    let state = &server.state;
    assert!(state.last_set_global_import_chain.lock().await.is_none());
    assert!(state.last_set_global_export_chain.lock().await.is_none());
    assert!(state.last_clear_global_import_chain.lock().await.is_none());
    assert!(state.last_clear_global_export_chain.lock().await.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_global_scope_changes_global_chain_without_warning() {
    let server = test_support::spawn_mock_server(None).await;
    let output = rbgp(
        &server.addr,
        &["policy", "chain", "set-export", "--global", "p1"],
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let request = server.state.last_set_global_export_chain.lock().await;
    assert_eq!(
        request.as_ref().map(|r| r.policy_names.clone()),
        Some(vec!["p1".to_string()])
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn neighbor_scope_neither_warns_nor_touches_global_chain() {
    let server = test_support::spawn_mock_server(None).await;
    let output = rbgp(
        &server.addr,
        &["policy", "chain", "clear-import", "--neighbor", "10.0.0.2"],
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert!(
        server
            .state
            .last_clear_global_import_chain
            .lock()
            .await
            .is_none()
    );
    assert!(
        server
            .state
            .last_clear_neighbor_import_chain
            .lock()
            .await
            .is_some()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_runs_without_prompt_when_not_a_terminal() {
    let server = test_support::spawn_mock_server(None).await;
    let output = rbgp(&server.addr, &["shutdown"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("Shutdown requested"));
}

#[test]
fn gshut_requires_an_explicit_scope_before_transport() {
    let directory = tempfile::tempdir().unwrap();
    let absent = format!("unix://{}/absent.sock", directory.path().display());
    for args in [
        vec!["gshut"],
        vec!["gshut", "--clear"],
        vec!["gshut", "--yes"],
    ] {
        let output = rbgp(&absent, &args);
        // A connection attempt would report the absent socket; exit 2
        // without it proves the all-peers toggle never reached transport.
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        let error = stderr(&output);
        assert!(
            error.contains("<--neighbor <NEIGHBOR>|--all>"),
            "{args:?}: {error}"
        );
        assert!(
            !error.contains("cannot reach rustbgpd"),
            "{args:?}: {error}"
        );
    }
    for args in [
        vec!["gshut", "--all"],
        vec!["gshut", "--neighbor", "10.0.0.2", "--clear"],
    ] {
        let output = rbgp(&absent, &args);
        // Non-interactive runs go on to transport without a prompt.
        assert_eq!(output.status.code(), Some(1), "{args:?}: {output:?}");
        let error = stderr(&output);
        assert!(error.contains("cannot reach rustbgpd"), "{args:?}: {error}");
        assert!(!error.contains("[y/N]"), "{args:?}: {error}");
    }
}

#[test]
fn explicit_scope_flags_conflict_with_neighbor() {
    let directory = tempfile::tempdir().unwrap();
    let absent = format!("unix://{}/absent.sock", directory.path().display());
    for args in [
        vec![
            "policy",
            "chain",
            "set-import",
            "--global",
            "--neighbor",
            "10.0.0.2",
            "p1",
        ],
        vec![
            "policy",
            "chain",
            "set-export",
            "--global",
            "--peer",
            "10.0.0.2",
            "p1",
        ],
        vec![
            "policy",
            "chain",
            "clear-import",
            "--global",
            "--neighbor",
            "10.0.0.2",
        ],
        vec![
            "policy",
            "chain",
            "clear-export",
            "--neighbor",
            "10.0.0.2",
            "--global",
        ],
        vec!["gshut", "--all", "--neighbor", "10.0.0.2"],
    ] {
        let output = rbgp(&absent, &args);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        let error = stderr(&output);
        assert!(error.contains("cannot be used with"), "{args:?}: {error}");
        assert!(
            !error.contains("cannot reach rustbgpd"),
            "{args:?}: {error}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_scope_neighbor_is_a_usage_error_before_transport() {
    // An empty address means every peer to SetGracefulShutdown, so an empty
    // `--neighbor` must not pass as a neighbor scope that skips the prompt.
    let server = test_support::spawn_mock_server(None).await;
    for neighbor in ["", " \t"] {
        for args in [
            vec![
                "policy",
                "chain",
                "set-import",
                "--neighbor",
                neighbor,
                "p1",
            ],
            vec!["policy", "chain", "set-export", "--peer", neighbor, "p1"],
            vec!["policy", "chain", "clear-import", "--neighbor", neighbor],
            vec!["policy", "chain", "clear-export", "--neighbor", neighbor],
            vec!["gshut", "--neighbor", neighbor],
            vec!["gshut", "--peer", neighbor, "--clear"],
        ] {
            let output = rbgp(&server.addr, &args);
            assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
            let error = stderr(&output);
            assert!(
                error.contains("'--neighbor <NEIGHBOR>': neighbor address must not be empty\n"),
                "{args:?}: {error}"
            );
            assert!(output.stdout.is_empty(), "{args:?}: {output:?}");
        }
    }
    let state = &server.state;
    assert!(state.last_set_neighbor_import_chain.lock().await.is_none());
    assert!(state.last_set_neighbor_export_chain.lock().await.is_none());
    assert!(
        state
            .last_clear_neighbor_import_chain
            .lock()
            .await
            .is_none()
    );
    assert!(
        state
            .last_clear_neighbor_export_chain
            .lock()
            .await
            .is_none()
    );
}
