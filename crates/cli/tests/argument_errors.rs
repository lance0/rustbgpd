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
        (vec!["policy", "chain", "set-import"], "set-import requires"),
        (vec!["policy", "chain", "set-export"], "set-export requires"),
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
