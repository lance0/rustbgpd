//! Daemon-wide mutations run without a prompt when stdin and stdout are not
//! terminals, and an omitted scope still selects the global chain or every
//! peer while warning that the form is deprecated.

use std::process::{Command, Output, Stdio};

// `test_support` resolves protobuf types through `crate::proto`.
use rustbgpd_api::proto;

#[path = "../src/test_support.rs"]
#[allow(
    dead_code,
    reason = "shared CLI mock includes services unused by this contract"
)]
mod test_support;

const CHAIN_WARNING: &str = "warning: omitting --neighbor selects the global chain; \
    pass --global (this will become an error in a future release)";
const GSHUT_WARNING: &str = "warning: omitting --neighbor selects all peers; \
    pass --all (this will become an error in a future release)";

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
async fn omitted_chain_scope_clears_global_chain_with_deprecation_warning() {
    let server = test_support::spawn_mock_server(None).await;
    let output = rbgp(&server.addr, &["policy", "chain", "clear-import"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(stderr(&output).trim_end(), CHAIN_WARNING);
    assert!(!stderr(&output).contains("[y/N]"));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Global import chain cleared"),
        "{output:?}"
    );
    assert!(
        server
            .state
            .last_clear_global_import_chain
            .lock()
            .await
            .is_some()
    );
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
fn gshut_scope_warning_is_emitted_only_when_scope_is_omitted() {
    let directory = tempfile::tempdir().unwrap();
    let absent = format!("unix://{}/absent.sock", directory.path().display());
    for (args, warned) in [
        (vec!["gshut"], true),
        (vec!["gshut", "--clear"], true),
        (vec!["gshut", "--all"], false),
        (vec!["gshut", "--neighbor", "10.0.0.2"], false),
    ] {
        let output = rbgp(&absent, &args);
        // The warning precedes the connection attempt, which proves the
        // command went on to transport without waiting for an answer.
        assert_eq!(output.status.code(), Some(1), "{args:?}: {output:?}");
        let error = stderr(&output);
        assert!(error.contains("cannot reach rustbgpd"), "{args:?}: {error}");
        assert_eq!(error.contains(GSHUT_WARNING), warned, "{args:?}: {error}");
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
                error.contains("neighbor address must not be empty"),
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
