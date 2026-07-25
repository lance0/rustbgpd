//! Exit-code contract for `rustbgpd --check` and `rustbgpd --check --strict`.
//!
//! `--check` is the last gate before a config reaches a production box, and
//! a valid-but-risky config warns there without failing — deliberately, so
//! that adding a warning never breaks a deployment that meant it. `--strict`
//! is the opt-in for gates that cannot accept that: same warnings, nonzero
//! exit. These tests pin both halves plus the rejection of `--strict` on its
//! own, because an accepted-but-ignored `--strict` would make a CI gate
//! report success for a config nobody checked.

use std::process::Command;

/// A config with one eBGP neighbor that resolves no policy in either
/// direction — valid, and the shape `--check` warns about.
const WARNS: &str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
runtime_state_dir = "/tmp/rustbgpd-check-strict"

[global.telemetry]
log_format = "json"

[global.telemetry.grpc_uds]
enabled = true
path = "/tmp/rustbgpd-check-strict/grpc.sock"
mode = 0o600
principal = "operator"

[security.grpc]
enforcement = "tier"

[security.grpc.roles]
operator = "operator"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
"#;

/// The same config with both directions of that neighbor policed: valid
/// with nothing to warn about, so `--strict` must not change its exit code.
const CLEAN: &str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
runtime_state_dir = "/tmp/rustbgpd-check-strict"

[global.telemetry]
log_format = "json"

[global.telemetry.grpc_uds]
enabled = true
path = "/tmp/rustbgpd-check-strict/grpc.sock"
mode = 0o600
principal = "operator"

[security.grpc]
enforcement = "tier"

[security.grpc.roles]
operator = "operator"

[policy.definitions.from-peer]
default_action = "permit"

[policy.definitions.to-peer]
default_action = "permit"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
import_policy_chain = ["from-peer"]
export_policy_chain = ["to-peer"]
"#;

/// Run the daemon binary with `args` plus a config file holding
/// `config_toml`; returns `(exit_code, stdout, stderr)`.
fn run(config_toml: &str, args: &[&str]) -> (Option<i32>, String, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("config.toml");
    std::fs::write(&config, config_toml).expect("write config");
    let output = Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
        .args(args)
        .arg(&config)
        // Warnings are framed for a terminal; keep assertions on text.
        .env("NO_COLOR", "1")
        .output()
        .expect("run rustbgpd");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Backward compatibility: warnings alone never fail a plain `--check`.
#[test]
fn check_without_strict_exits_zero_on_warnings() {
    let (code, stdout, stderr) = run(WARNS, &["--check"]);
    assert_eq!(code, Some(0), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("config VALID, 1 WARNING — NOT a clean check"),
        "summary line did not report the warning:\n{stdout}"
    );
    assert!(
        stderr.contains("WARNING"),
        "warning was not framed on stderr:\n{stderr}"
    );
}

/// The feature: the same config, the same warnings, a failing exit code.
#[test]
fn check_strict_exits_nonzero_on_warnings() {
    let (code, stdout, stderr) = run(WARNS, &["--check", "--strict"]);
    assert_eq!(code, Some(1), "stdout:\n{stdout}\nstderr:\n{stderr}");
    // The config is still valid; only the exit code changes.
    assert!(
        stdout.contains("config VALID, 1 WARNING — NOT a clean check"),
        "summary line changed under --strict:\n{stdout}"
    );
    assert!(
        stderr.contains("--strict"),
        "stderr does not say why the check failed:\n{stderr}"
    );
}

/// `--strict` must not fail a check that had nothing to report, or it would
/// be a gate nobody can pass.
#[test]
fn check_strict_exits_zero_on_a_clean_config() {
    let (code, stdout, stderr) = run(CLEAN, &["--check", "--strict"]);
    assert_eq!(code, Some(0), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("config OK"),
        "clean check did not print the OK summary:\n{stdout}"
    );
}

/// Silently accepting `--strict` without `--check` would start the daemon
/// for an invocation that meant to validate and exit.
#[test]
fn strict_without_check_is_rejected() {
    let (code, stdout, stderr) = run(CLEAN, &["--strict"]);
    assert_eq!(code, Some(2), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stderr.contains("--strict can only be used with --check"),
        "rejection did not name the requirement:\n{stderr}"
    );
}

/// The exit-code ladder is only usable if it is written down where an
/// operator wiring a gate will look.
#[test]
fn help_documents_the_exit_codes() {
    let output = Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
        .arg("--help")
        .output()
        .expect("run rustbgpd --help");
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("--strict"), "help does not list --strict");
    assert!(
        help.contains("Exit status:"),
        "help does not document exit status:\n{help}"
    );
}
