//! First-party one-shot stdout is fallible, quiet on a closed peer, and
//! byte-for-byte stable when healthy.

use std::ffi::OsString;
use std::os::{fd::OwnedFd, unix::net::UnixStream};
use std::process::{Command, Output, Stdio};

fn config(port: u16, warned: bool) -> String {
    let policy = if warned {
        String::new()
    } else {
        "import_policy_chain = [\"allow\"]\nexport_policy_chain = [\"allow\"]\n".into()
    };
    format!(
        r#"[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = {port}
runtime_state_dir = "/tmp/rustbgpd-daemon-stdout-closed"

[global.telemetry]
log_format = "json"

[global.telemetry.grpc_uds]
enabled = true
path = "/tmp/rustbgpd-daemon-stdout-closed/grpc.sock"
mode = 0o600
principal = "operator"

[security.grpc]
enforcement = "tier"

[security.grpc.roles]
operator = "operator"

[policy.definitions.allow]
default_action = "permit"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
{policy}"#
    )
}

fn run(args: &[OsString], closed_stdout: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rustbgpd"));
    command.args(args).env("NO_COLOR", "1");
    if closed_stdout {
        let (peer, stdout) = UnixStream::pair().expect("stdout socket pair");
        drop(peer);
        command.stdout(Stdio::from(OwnedFd::from(stdout)));
    }
    command.output().expect("run rustbgpd")
}

fn args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

fn fixture() -> (tempfile::TempDir, OsString, OsString, OsString) {
    let temp = tempfile::tempdir().expect("tempdir");
    let clean = temp.path().join("clean.toml");
    let warned = temp.path().join("warned.toml");
    let changed = temp.path().join("changed.toml");
    std::fs::write(&clean, config(1179, false)).expect("write clean config");
    std::fs::write(&warned, config(1179, true)).expect("write warned config");
    std::fs::write(&changed, config(1180, false)).expect("write changed config");
    (temp, clean.into(), warned.into(), changed.into())
}

#[test]
fn all_nine_daemon_stdout_sites_fail_closed_without_new_stderr() {
    let (_temp, clean, warned, changed) = fixture();
    let rows = [
        ("version", args(&["--version"])),
        ("man", args(&["--man"])),
        ("help", args(&["--help"])),
        ("schema", args(&["--dump-config-schema"])),
        ("init-lab", args(&["--init-config", "lab", "--stdout"])),
        ("clean-check", vec!["--check".into(), clean.clone()]),
        ("warn-check", vec!["--check".into(), warned.clone()]),
        (
            "text-diff",
            vec![clean.clone(), "--diff".into(), changed.clone()],
        ),
        (
            "json-diff",
            vec![clean, "--diff".into(), changed, "--json".into()],
        ),
    ];
    for (name, row) in rows {
        let healthy = run(&row, false);
        assert!(!healthy.stdout.is_empty(), "{name}: no healthy stdout");
        let closed = run(&row, true);
        assert_eq!(closed.status.code(), Some(1), "{name}: {closed:?}");
        assert!(closed.stdout.is_empty(), "{name}: stdout was captured");
        assert_eq!(
            closed.stderr, healthy.stderr,
            "{name}: closed stdout added a diagnostic"
        );
    }
}

#[test]
fn healthy_check_and_diff_bytes_streams_and_statuses_are_exact() {
    let (_temp, clean, warned, changed) = fixture();
    let clean_check = run(&["--check".into(), clean.clone()], false);
    assert_eq!(clean_check.status.code(), Some(0));
    assert_eq!(
        clean_check.stdout,
        format!("config OK: {}\n", clean.to_string_lossy()).as_bytes()
    );
    assert!(clean_check.stderr.is_empty());

    let warn_check = run(&["--check".into(), warned.clone()], false);
    assert_eq!(warn_check.status.code(), Some(0));
    assert_eq!(
        warn_check.stdout,
        format!(
            "config VALID, 1 WARNING — NOT a clean check: {}\n",
            warned.to_string_lossy()
        )
        .as_bytes()
    );
    let rule = "=".repeat(74);
    let warning = format!(
        "\n{rule}\nWARNING: 1 eBGP neighbor resolves no explicit policy.\n\n\
         \x20\x2010.0.0.2 (AS 65002): no import policy and no export policy\n\n\
         Every direction listed above is unfiltered. An unfiltered import direction\n\
         accepts every route the peer sends; an unfiltered export direction re-advertises\n\
         every route selected for that peer, as received. If that is what you meant, this\n\
         is the expected result for a permit-all route server. If it is not, configure an\n\
         import_policy_chain / export_policy_chain there, or set\n\
         [global] ebgp_requires_policy = true to fail closed until you do.\n{rule}\n\n"
    );
    assert_eq!(warn_check.stderr, warning.as_bytes());

    let no_diff = run(&[clean.clone(), "--diff".into(), clean.clone()], false);
    assert_eq!(no_diff.status.code(), Some(0), "{no_diff:?}");
    assert!(no_diff.stderr.is_empty());
    assert_eq!(no_diff.stdout, b"No changes.\n");

    let text = run(&[clean.clone(), "--diff".into(), changed.clone()], false);
    assert_eq!(text.status.code(), Some(1), "{text:?}");
    assert!(text.stderr.is_empty());
    assert_eq!(
        text.stdout,
        b"\x1b[33mRestart-required changes:\x1b[39m\n  \x1b[33m!\x1b[39m [global] changed\n\n\
          Plan: no neighbor changes \xc2\xb7 daemon restart required for some changes\n"
    );

    let json = run(&[clean, "--diff".into(), changed, "--json".into()], false);
    assert_eq!(json.status.code(), Some(1), "{json:?}");
    assert!(json.stderr.is_empty());
    let value: serde_json::Value =
        serde_json::from_slice(&json.stdout).expect("complete JSON diff");
    assert_eq!(value["has_actionable_changes"], true);
    assert_eq!(value["restart_required"]["global_changed"], true);
    let mut expected = serde_json::to_vec_pretty(&value).unwrap();
    expected.push(b'\n');
    assert_eq!(
        json.stdout, expected,
        "JSON bytes or terminal newline drift"
    );
}
