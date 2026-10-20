//! `rbgp rib add` and `rbgp rib delete` report the unicast injection outcome,
//! and `rbgp rib delete --allow-missing` succeeds on an absent route, through
//! the mock gRPC server.

use std::process::{Command, Output};

use rustbgpd_api::proto;

#[path = "../src/test_support.rs"]
#[allow(
    dead_code,
    reason = "shared CLI mock includes services unused by this contract"
)]
mod test_support;

const PREFIX: &str = "198.51.100.0/24";

fn rbgp(addr: &str, json: bool, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rbgp"));
    command.args(["--addr", addr]);
    if json {
        command.arg("--json");
    }
    command
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .expect("run rbgp")
}

fn assert_json(output: &Output, action: &str, outcome: &str) {
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!({"ok": true, "action": action, "target": PREFIX, "outcome": outcome})
    );
}

fn assert_text(output: &Output, text: &str) {
    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8(output.stdout.clone()).unwrap(), text);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rib_add_reports_injection_outcome() {
    let server = test_support::spawn_mock_server(None).await;
    let add = ["rib", "add", PREFIX, "--next-hop", "192.0.2.1"];
    for (outcome, name) in [
        (proto::PathInjectOutcome::Created, "created"),
        (proto::PathInjectOutcome::Replaced, "replaced"),
        (proto::PathInjectOutcome::Unchanged, "unchanged"),
        (proto::PathInjectOutcome::Unspecified, "unknown"),
    ] {
        *server.state.add_path_response.lock().await = proto::AddPathResponse {
            outcome: outcome as i32,
        };
        assert_json(&rbgp(&server.addr, true, &add), "add_route", name);
        // An older daemon reports no outcome; keep the original line for it.
        let expected = if name == "unknown" {
            format!("Route {PREFIX} added\n")
        } else {
            format!("Route {PREFIX} added ({name})\n")
        };
        assert_text(&rbgp(&server.addr, false, &add), &expected);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rib_delete_allow_missing_reports_not_present() {
    let server = test_support::spawn_mock_server(None).await;
    let delete = |allow_missing: bool| {
        let mut args = vec!["rib", "delete", PREFIX];
        if allow_missing {
            args.push("--allow-missing");
        }
        args
    };

    for allow_missing in [false, true] {
        let args = delete(allow_missing);
        assert_json(&rbgp(&server.addr, true, &args), "delete_route", "deleted");
        assert_text(
            &rbgp(&server.addr, false, &args),
            &format!("Route {PREFIX} deleted\n"),
        );
        let sent = server.state.last_delete_path.lock().await.clone().unwrap();
        assert_eq!(sent.allow_missing, allow_missing);
    }

    *server.state.delete_path_missing.lock().await = true;
    assert_json(
        &rbgp(&server.addr, true, &delete(true)),
        "delete_route",
        "not_present",
    );
    assert_text(
        &rbgp(&server.addr, false, &delete(true)),
        &format!("Route {PREFIX} not present\n"),
    );
    // Without the flag, a missing route stays an error.
    for json in [false, true] {
        let output = rbgp(&server.addr, json, &delete(false));
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
    }

    // The flag combines with the lease-owner flags. An absent route has no
    // owner to check, so any owner gets `not present`.
    *server.state.injected_entry_owner.lock().await = "rtbh-pop1".to_string();
    for flags in [&["--override-owner"][..], &["--owner", "ctl"][..]] {
        let args = [&delete(true)[..], flags].concat();
        assert_text(
            &rbgp(&server.addr, false, &args),
            &format!("Route {PREFIX} not present\n"),
        );
        let sent = server.state.last_delete_path.lock().await.clone().unwrap();
        assert!(sent.allow_missing, "{sent:?}");
    }
    *server.state.injected_entry_owner.lock().await = String::new();

    // An older daemon ignores the flag and reports no outcome. It returns OK
    // only after removing a route, so that is never reported as not present.
    *server.state.delete_path_legacy.lock().await = true;
    *server.state.delete_path_missing.lock().await = false;
    for allow_missing in [false, true] {
        let args = delete(allow_missing);
        assert_json(&rbgp(&server.addr, true, &args), "delete_route", "unknown");
        assert_text(
            &rbgp(&server.addr, false, &args),
            &format!("Route {PREFIX} deleted (the daemon did not report an outcome)\n"),
        );
    }
    *server.state.delete_path_missing.lock().await = true;
    let output = rbgp(&server.addr, false, &delete(true));
    assert_eq!(output.status.code(), Some(1), "{output:?}");
}
