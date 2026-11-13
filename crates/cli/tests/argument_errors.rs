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

/// `EX_USAGE`: the parser's code, distinct from every detailed exit code.
const USAGE: i32 = 64;

#[test]
fn parser_and_neighbor_usage_errors_exit_usage_before_transport() {
    for args in [
        vec!["--unknown-flag"],
        vec!["unknown-command"],
        vec!["--addr"],
        vec!["top", "--interval", "not-a-number"],
        vec!["neighbor", "lst"],
        vec!["neighbor", "list"],
        vec!["neighbor", "lst", "delete"],
        vec!["neighbor", "999.999.999.999"],
        vec!["neighbor", "fe80::1%"],
        vec!["neighbor", "fe80::1%eth0%eth1"],
        vec!["neighbor", "192.0.2.1%eth0"],
    ] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(USAGE), "{args:?}: {output:?}");
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
        vec!["neighbor", "swp1"],
        vec!["neighbor", "swp1", "delete"],
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
            text.contains("64 parser or usage error"),
            "{args:?}: {text}"
        );
    }
}

/// Load-bearing: restoring "usage error (exit `2`)" in operations.md or
/// "malformed CLI input exits 2" in api.md fails this. `rustbgpd --check
/// --strict` and other daemon modes really do exit 2 and are not matched.
#[test]
fn reference_docs_give_rbgp_usage_errors_exit_64() {
    for (name, text) in [
        (
            "operations",
            include_str!("../../../docs/reference/operations.md"),
        ),
        ("api", include_str!("../../../docs/reference/api.md")),
    ] {
        let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
        for stale in [
            "usage error (exit `2`)",
            "usage error (exit 2)",
            "malformed CLI input exits 2",
        ] {
            assert!(!text.contains(stale), "{name}.md still says {stale:?}");
        }
    }
}

/// A script gating on `config diff`/`plan` (2 = changes present) or `doctor`
/// (2 = red checks) must never read a renamed flag or a missing argument as
/// that outcome.
#[test]
fn usage_errors_never_exit_with_a_detailed_code() {
    for args in [
        vec!["config", "diff", "--bogus", "candidate.toml"],
        vec!["config", "diff", "--history", "not-a-number"],
        vec!["config", "plan", "--bogus", "candidate.toml"],
        vec!["config", "plan"],
        vec!["config", "apply", "--bogus", "candidate.toml"],
        vec!["config", "apply"],
        vec!["config", "confirm", "--bogus", "deploy-1"],
        vec!["config", "confirm"],
        vec!["config", "abort", "--bogus", "deploy-1"],
        vec!["config", "abort"],
        vec!["doctor", "--bogus"],
        vec!["doctor", "--output"],
    ] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(USAGE), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("error:"), "{args:?}: {error}");
    }
    // Help is not an error.
    for args in [vec!["config", "plan", "--help"], vec!["doctor", "--help"]] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(0), "{args:?}: {output:?}");
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

/// Load-bearing: deleting any `json_no_effect` arm, or warning a second
/// time in dispatch, changes the stderr comparison below.
#[test]
fn json_no_op_commands_warn_once_and_keep_stdout_and_exit() {
    use std::io::Write as _;
    use std::process::Stdio;

    let directory = tempfile::tempdir().unwrap();
    let address = format!("unix://{}/absent.sock", directory.path().display());
    let policy = "policy p {\n    term t { accept }\n}\n";
    let empty = directory.path().join("empty.capture");
    std::fs::write(&empty, b"").unwrap();
    let empty = empty.to_str().unwrap();
    let run_with = |json: bool, args: &[&str], stdin: &str| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_rbgp"))
            .args(["--addr", &address, "--no-color"])
            .args(json.then_some("-j"))
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run rbgp");
        let mut input = child.stdin.take().unwrap();
        // A command that never reads stdin may exit first; EPIPE is fine.
        let _ = input.write_all(stdin.as_bytes());
        drop(input);
        child.wait_with_output().unwrap()
    };
    for (args, stdin, target) in [
        (vec!["metrics"], "", "`metrics`"),
        (vec!["top"], "", "`top`"),
        (vec!["completions", "bash"], "", "`completions`"),
        (vec!["man"], "", "`man`"),
        (vec!["policy", "fmt", "-"], policy, "`policy fmt`"),
        (
            vec![
                "diff",
                "snapshot",
                "from-mrt",
                empty,
                "--view",
                "adj-rib-out-capture",
                "--neighbor",
                "192.0.2.1",
                "--neighbor-asn",
                "65001",
            ],
            "",
            "`diff snapshot from-mrt`",
        ),
        (
            vec!["diff", "snapshot", "from-bmp", empty],
            "",
            "`diff snapshot from-bmp`",
        ),
    ] {
        let plain = run_with(false, &args, stdin);
        let json = run_with(true, &args, stdin);
        assert_eq!(json.status.code(), plain.status.code(), "{args:?}");
        assert_eq!(json.stdout, plain.stdout, "{args:?}");
        let plain_error = String::from_utf8(plain.stderr).unwrap();
        let json_error = String::from_utf8(json.stderr).unwrap();
        assert!(!plain_error.contains("--json has no effect"), "{args:?}");
        assert_eq!(
            json_error.matches("--json has no effect").count(),
            1,
            "{args:?}: {json_error}"
        );
        let warning = format!("warning: --json has no effect on {target}");
        let rest = json_error
            .strip_prefix(&warning)
            .and_then(|rest| rest.split_once('\n'))
            .unwrap_or_else(|| panic!("{args:?}: {json_error}"))
            .1;
        assert_eq!(rest, plain_error, "{args:?}");
    }
    // A command that `-j` does change prints no warning.
    let output = run_with(true, &["neighbor"], "");
    assert!(!String::from_utf8_lossy(&output.stderr).contains("has no effect"));
}
