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

/// A validation-origin warning: an iBGP route-reflector client with an ORR
/// vantage and no neighbor feeding BGP-LS. The condition is detected inside
/// `Config::validate`, which runs before logging is initialized — so before
/// this was routed through the collected warning set, `--check` reported
/// nothing and `--strict` had nothing to fail on. iBGP throughout, so the
/// unpoliced-eBGP warning cannot contribute to the count.
const ORR_WARNS: &str = r#"
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
remote_asn = 65001
route_reflector_client = true
orr_vantage = "192.0.2.7"
"#;

/// The pre-ADR-0064 gRPC authorization mode. A genuine risk in the
/// operator's own config, so `--check` reports it and `--strict` fails on
/// it; iBGP and no ORR vantage, so it is the only warning.
const LEGACY_GRPC_WARNS: &str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
runtime_state_dir = "/tmp/rustbgpd-check-strict"

[global.telemetry]
log_format = "json"

[security.grpc]
enforcement = "legacy"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65001
"#;

/// Three distinct warning kinds at once: an unpoliced eBGP neighbor, an
/// unresolvable ORR vantage, and legacy gRPC enforcement. The count is what
/// `--strict` gates on, so a fix that surfaced each warning without summing
/// them into one total would still report the wrong number here.
const THREE_KINDS: &str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
runtime_state_dir = "/tmp/rustbgpd-check-strict"

[global.telemetry]
log_format = "json"

[security.grpc]
enforcement = "legacy"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65001
route_reflector_client = true
orr_vantage = "192.0.2.7"
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

/// A warning raised inside `Config::validate` has to reach the operator.
/// It is detected before `init_logging` runs, so logging it there wrote to
/// no subscriber: `--check` printed a clean result for a config with a
/// permanently inert ORR configuration in it.
#[test]
fn check_reports_a_validation_origin_warning() {
    let (code, stdout, stderr) = run(ORR_WARNS, &["--check"]);
    assert_eq!(code, Some(0), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("config VALID, 1 WARNING — NOT a clean check"),
        "summary line did not count the validation warning:\n{stdout}"
    );
    assert!(
        stderr.contains("orr_vantage") && stderr.contains("linkstate"),
        "warning did not name the condition:\n{stderr}"
    );
    assert!(
        stderr.contains("Add \"linkstate\" to the families"),
        "warning did not give the action:\n{stderr}"
    );
}

/// The point of routing validation diagnostics through the counted set: a
/// warning that never surfaced could never fail the gate, whatever its
/// severity.
#[test]
fn check_strict_fails_on_a_validation_origin_warning() {
    let (code, stdout, stderr) = run(ORR_WARNS, &["--check", "--strict"]);
    assert_eq!(code, Some(1), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("config VALID, 1 WARNING — NOT a clean check"),
        "summary line changed under --strict:\n{stdout}"
    );
}

/// Legacy gRPC enforcement is a risk in the operator's own config, not an
/// unfinished feature of the release, so `--check` reports it and it must
/// state the migration action rather than only the state.
#[test]
fn check_reports_legacy_grpc_enforcement() {
    let (code, stdout, stderr) = run(LEGACY_GRPC_WARNS, &["--check"]);
    assert_eq!(code, Some(0), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("config VALID, 1 WARNING — NOT a clean check"),
        "summary line did not count the legacy-enforcement warning:\n{stdout}"
    );
    assert!(
        stderr.contains("security.grpc.enforcement = \"legacy\""),
        "warning did not name the condition:\n{stderr}"
    );
    assert!(
        stderr.contains("max_tier cap"),
        "warning did not name the consequence:\n{stderr}"
    );
    assert!(
        stderr.contains("To migrate:")
            && stderr.contains("[security.grpc.roles]")
            && stderr.contains("security.grpc.enforcement = \"tier\""),
        "warning did not give the migration action:\n{stderr}"
    );
}

#[test]
fn check_strict_fails_on_legacy_grpc_enforcement() {
    let (code, stdout, stderr) = run(LEGACY_GRPC_WARNS, &["--check", "--strict"]);
    assert_eq!(code, Some(1), "stdout:\n{stdout}\nstderr:\n{stderr}");
}

/// The aggregate. `--strict` gates on the total, so every kind has to be
/// summed into the one count — the case a per-warning fix gets wrong.
#[test]
fn check_counts_every_warning_kind_together() {
    let (code, stdout, stderr) = run(THREE_KINDS, &["--check"]);
    assert_eq!(code, Some(0), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("config VALID, 3 WARNINGS — NOT a clean check"),
        "the three warning kinds were not summed into one total:\n{stdout}"
    );
    for expected in [
        "eBGP neighbor",
        "orr_vantage",
        "security.grpc.enforcement = \"legacy\"",
    ] {
        assert!(
            stderr.contains(expected),
            "{expected:?} missing from the framed warnings:\n{stderr}"
        );
    }
    assert_eq!(
        stderr.matches("WARNING:").count(),
        3,
        "each kind gets its own framed block:\n{stderr}"
    );

    let (code, _, _) = run(THREE_KINDS, &["--check", "--strict"]);
    assert_eq!(code, Some(1), "strict must fail the same config");
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
