//! Parser errors and semantic validation keep distinct process exit codes.

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    let directory = tempfile::tempdir().unwrap();
    let address = format!("unix://{}/absent.sock", directory.path().display());
    Command::new(env!("CARGO_BIN_EXE_rbgp"))
        .args(["--addr", &address, "--no-color"])
        .args(args)
        .output()
        .expect("run rbgp against an absent socket")
}

#[test]
fn parser_and_neighbor_usage_errors_exit_two_before_transport() {
    for args in [
        vec!["--unknown-flag"],
        vec!["unknown-command"],
        vec!["--addr"],
        vec!["top", "--interval", "not-a-number"],
        vec!["neighbor", "lst"],
        vec!["neighbor", "list"],
        vec!["neighbor", "999.999.999.999"],
        vec!["neighbor", "fe80::1%"],
        vec!["neighbor", "fe80::1%eth0%eth1"],
        vec!["neighbor", "192.0.2.1%eth0"],
    ] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("error:"), "{args:?}: {error}");
        assert!(
            !error.contains("cannot reach rustbgpd"),
            "{args:?}: {error}"
        );
    }
}

#[test]
fn semantic_argument_errors_keep_exit_one_before_transport() {
    for (args, message) in [
        (vec!["top", "--interval", "0"], "interval must be between"),
        (vec!["top", "--interval", "61"], "interval must be between"),
        (
            vec!["policy", "chain", "set-import", "--global"],
            "set-import requires",
        ),
        (
            vec!["policy", "chain", "set-export", "--neighbor", "10.0.0.2"],
            "set-export requires",
        ),
    ] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(1), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains(message), "{args:?}: {error}");
        assert!(
            !error.contains("cannot reach rustbgpd"),
            "{args:?}: {error}"
        );
    }
}

#[test]
fn valid_neighbor_addresses_and_list_mode_reach_transport() {
    for args in [
        vec!["neighbor"],
        vec!["summary"],
        vec!["neighbor", "192.0.2.1"],
        vec!["neighbor", "2001:db8::1"],
        vec!["neighbor", "fe80::1%eth0"],
        vec!["neighbor", "fe80::1%7", "reset"],
    ] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(1), "{args:?}: {output:?}");
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("cannot reach rustbgpd"), "{args:?}: {error}");
    }
}

#[test]
fn help_and_man_distinguish_parsing_from_argument_validation() {
    for args in [vec!["--help"], vec!["man"]] {
        let output = run(&args);
        assert!(output.status.success(), "{args:?}: {output:?}");
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(
            text.contains("1  error (argument validation,"),
            "{args:?}: {text}"
        );
        assert!(
            text.contains("2  parser or usage error"),
            "{args:?}: {text}"
        );
    }
}

#[test]
fn transport_error_exits_one_when_the_stderr_terminal_has_hung_up() {
    let directory = tempfile::tempdir().unwrap();
    let address = format!("unix://{}/absent.sock", directory.path().display());
    // A pty whose master is closed: writes to the slave fail with EIO, as
    // they do once an SSH session drops.
    let pty = nix::pty::openpty(None, None).expect("open a pty pair");
    drop(pty.master);
    let status = Command::new(env!("CARGO_BIN_EXE_rbgp"))
        .args(["--addr", &address, "--no-color", "neighbor"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::from(pty.slave))
        .status()
        .expect("run rbgp with a hung-up stderr");
    assert_eq!(
        status.code(),
        Some(1),
        "a lost terminal must not turn the error exit into a panic"
    );
}

#[test]
fn top_needs_a_terminal_on_stdin_and_stdout_before_transport() {
    use std::process::Stdio;

    let directory = tempfile::tempdir().unwrap();
    let address = format!("unix://{}/absent.sock", directory.path().display());
    for (case, stdin_is_tty, stdout_is_tty) in [
        ("rbgp top > file", true, false),
        ("rbgp top < /dev/null", false, true),
    ] {
        let pty = nix::pty::openpty(None, None).expect("open a pty pair");
        let tty = || Stdio::from(pty.slave.try_clone().expect("clone pty slave"));
        let output = Command::new(env!("CARGO_BIN_EXE_rbgp"))
            .args(["--addr", &address, "--no-color", "top"])
            .stdin(if stdin_is_tty { tty() } else { Stdio::null() })
            .stdout(if stdout_is_tty { tty() } else { Stdio::piped() })
            .stderr(Stdio::piped())
            .output()
            .expect("run rbgp top");
        let error = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{case}: {error}");
        assert!(
            error.contains("rbgp top needs an interactive terminal on stdin and stdout"),
            "{case}: {error}"
        );
        assert!(!error.contains("cannot reach rustbgpd"), "{case}: {error}");
        assert!(
            output.stdout.is_empty(),
            "{case}: no escape codes into a redirected stdout"
        );
        drop(pty.master);
    }
}
