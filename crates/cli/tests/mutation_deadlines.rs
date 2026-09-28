//! Mutation RPCs stop at a deadline with an outcome-unknown error instead of
//! waiting forever on a daemon that accepts the connection but never answers.

#![cfg(unix)]

use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn mutations_against_a_silent_daemon_report_an_unknown_outcome() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("silent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    // Accept every connection and hold it open without ever writing a byte.
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming() {
            held.push(stream);
        }
    });
    let address = format!("unix://{}", socket.display());

    let apply = "the daemon may still apply this change";
    for (args, rpc, outcome, verify) in [
        (
            &["neighbor", "192.0.2.1", "reset"][..],
            "ResetNeighbor",
            apply,
            "`rbgp neighbor 192.0.2.1`",
        ),
        (
            &["neighbor", "192.0.2.1", "delete"][..],
            "DeleteNeighbor",
            apply,
            "`rbgp neighbor 192.0.2.1`",
        ),
        (
            &["gshut", "--all", "--yes"][..],
            "SetGracefulShutdown",
            apply,
            "`rbgp neighbor`",
        ),
        (
            &["mrt-dump"][..],
            "TriggerMrtDump",
            apply,
            "MRT output directory",
        ),
        (
            &["config", "confirm", "maint-1"][..],
            "ConfirmConfigTransaction",
            "the transaction may still commit or roll back",
            "`rbgp config status`",
        ),
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_rbgp"))
            .args(["--addr", &address, "--no-color"])
            .args(args)
            .env("RBGP_TEST_MUTATION_RPC_TIMEOUT_MS", "300")
            .env_remove("RUSTBGPD_TOKEN_FILE")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start rbgp");
        let deadline = Instant::now() + Duration::from_secs(20);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() > deadline {
                child.kill().unwrap();
                let output = child.wait_with_output().unwrap();
                panic!("{args:?} still waiting on a silent daemon: {output:?}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let output = child.wait_with_output().unwrap();
        let error = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{args:?}: {error}");
        assert!(output.stdout.is_empty(), "{args:?}: {output:?}");
        for expected in [
            "deadline exceeded",
            rpc,
            "outcome unknown: ",
            outcome,
            "; verify with ",
            verify,
        ] {
            assert!(
                error.contains(expected),
                "{args:?}: missing {expected:?} in {error}"
            );
        }
    }
}
