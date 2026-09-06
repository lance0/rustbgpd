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
ebgp_requires_policy = false

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
ebgp_requires_policy = false

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
ebgp_requires_policy = false

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

/// The pre-ADR-0064 gRPC authorization mode, removed in v0.63.0: the
/// config no longer loads at all, so `--check` fails with the migration
/// message rather than warning.
const LEGACY_GRPC_REJECTED: &str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
runtime_state_dir = "/tmp/rustbgpd-check-strict"
ebgp_requires_policy = false

[global.telemetry]
log_format = "json"

[security.grpc]
enforcement = "legacy"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65001
"#;

/// Two distinct warning kinds at once: an unpoliced eBGP neighbor and an
/// unresolvable ORR vantage. The count is what `--strict` gates on, so a
/// fix that surfaced each warning without summing them into one total
/// would still report the wrong number here.
const TWO_KINDS: &str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
runtime_state_dir = "/tmp/rustbgpd-check-strict"
ebgp_requires_policy = false

[global.telemetry]
log_format = "json"

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

fn legacy_omission(config: &str) -> String {
    config.replace("ebgp_requires_policy = false\n", "")
}

fn dynamic_config(enforced: bool, policy_complete: bool) -> String {
    let group_policy = if policy_complete {
        "import_policy = [{ action = \"permit\", prefix = \"0.0.0.0/0\", le = 32 }]\n\
         export_policy = [{ action = \"permit\", prefix = \"0.0.0.0/0\", le = 32 }]"
    } else {
        ""
    };
    let mut config = format!(
        r#"
{base}
[peer_groups.ix]
{group_policy}

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix"
remote_asn = 0
"#,
        base = WARNS.replace(
            "[[neighbors]]\naddress = \"10.0.0.2\"\nremote_asn = 65002",
            ""
        )
    );
    if enforced {
        config = config.replacen(
            "ebgp_requires_policy = false",
            "ebgp_requires_policy = true",
            1,
        );
    }
    config
}

#[test]
fn check_dynamic_range_policy_warning_matrix() {
    for (enforced, consequence) in [(false, "unfiltered"), (true, "reserved deny")] {
        let config = dynamic_config(enforced, false);
        let (code, stdout, stderr) = run(&config, &["--check"]);
        assert_eq!(code, Some(0), "stdout:\n{stdout}\nstderr:\n{stderr}");
        assert!(stdout.contains("config VALID, 1 WARNING — NOT a clean check"));
        assert!(stderr.contains(consequence), "{stderr}");
        assert!(stderr.contains(
            "dynamic range 192.0.2.0/24 via peer group \"ix\" (any AS): \
             no import policy and no export policy"
        ));
        assert!(!stderr.contains("AS 0"), "{stderr}");

        let (code, stdout, stderr) = run(&config, &["--check", "--strict"]);
        assert_eq!(code, Some(1), "stdout:\n{stdout}\nstderr:\n{stderr}");
    }
    for enforced in [false, true] {
        let clean = dynamic_config(enforced, true);
        for args in [&["--check"][..], &["--check", "--strict"][..]] {
            let (code, stdout, stderr) = run(&clean, args);
            assert_eq!(code, Some(0), "stdout:\n{stdout}\nstderr:\n{stderr}");
            assert!(stdout.contains("config OK"), "{stdout}");
            assert!(!stderr.contains("WARNING"), "{stderr}");
        }
    }
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
    assert!(stderr.contains("1 eBGP neighbor resolves no explicit policy."));
    assert!(stderr.contains("  10.0.0.2 (AS 65002): no import policy and no export policy"));
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

#[test]
fn legacy_omission_advisory_obeys_check_and_strict_exit_contract() {
    let config = legacy_omission(CLEAN);
    let (code, stdout, stderr) = run(&config, &["--check"]);
    assert_eq!(code, Some(0), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("config VALID, 1 WARNING — NOT a clean check"));
    assert!(stderr.contains("rfc8212_secure_default_ready"), "{stderr}");

    let (code, stdout, stderr) = run(&config, &["--check", "--strict"]);
    assert_eq!(code, Some(1), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("config VALID, 1 WARNING — NOT a clean check"));
}

#[test]
fn unpoliced_legacy_omission_aggregates_two_independent_warnings() {
    let config = legacy_omission(WARNS);
    let (code, stdout, stderr) = run(&config, &["--check"]);
    assert_eq!(code, Some(0), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("config VALID, 2 WARNINGS — NOT a clean check"));
    assert!(stderr.contains("rfc8212_secure_default_ready"), "{stderr}");
    assert!(stderr.contains("eBGP neighbor"), "{stderr}");
    assert_eq!(stderr.matches("WARNING:").count(), 2, "{stderr}");
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

/// Legacy gRPC enforcement was removed in v0.63.0: `--check` (strict or
/// not) fails at load with the one-shot migration message. Restoring the
/// typed enum bypasses the post-deserialize pointer and makes this red.
#[test]
fn check_rejects_legacy_grpc_enforcement() {
    for args in [&["--check"][..], &["--check", "--strict"][..]] {
        let (code, stdout, stderr) = run(LEGACY_GRPC_REJECTED, args);
        assert_eq!(code, Some(1), "stdout:\n{stdout}\nstderr:\n{stderr}");
        assert!(
            stderr.contains("security.grpc.enforcement = \"legacy\" was removed in v0.63.0"),
            "rejection did not name the removal:\n{stderr}"
        );
        assert!(
            stderr.contains("delete the whole [security.grpc] block"),
            "rejection did not give the delete-the-block guidance:\n{stderr}"
        );
        assert!(
            stderr.contains("enforcement = \"tier\"")
                && stderr.contains("[security.grpc.roles]")
                && stderr.contains("\"<your-principal>\" = \"operator\""),
            "rejection did not carry the paste block:\n{stderr}"
        );
    }
}

/// The aggregate. `--strict` gates on the total, so every kind has to be
/// summed into the one count — the case a per-warning fix gets wrong.
#[test]
fn check_counts_every_warning_kind_together() {
    let (code, stdout, stderr) = run(TWO_KINDS, &["--check"]);
    assert_eq!(code, Some(0), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("config VALID, 2 WARNINGS — NOT a clean check"),
        "the two warning kinds were not summed into one total:\n{stdout}"
    );
    for expected in ["eBGP neighbor", "orr_vantage"] {
        assert!(
            stderr.contains(expected),
            "{expected:?} missing from the framed warnings:\n{stderr}"
        );
    }
    assert_eq!(
        stderr.matches("WARNING:").count(),
        2,
        "each kind gets its own framed block:\n{stderr}"
    );

    let (code, _, _) = run(TWO_KINDS, &["--check", "--strict"]);
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

// Public test-only credentials; no production trust or identity. The self-signed
// certificate also supplies the parsable trust anchor for credential staging.
const CHECK_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIBkDCCATegAwIBAgIUWBew9zSvvaMDf6NTvWkDQhnqZMowCgYIKoZIzj0EAwIw
HTEbMBkGA1UEAwwSY2hlY2stb25seS5pbnZhbGlkMCAXDTI2MDkwNjIwNDczMVoY
DzIxMjYwODEzMjA0NzMxWjAdMRswGQYDVQQDDBJjaGVjay1vbmx5LmludmFsaWQw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQXpxOPohjjciNp9QoIOBbMOcfcvfG8
HSDVxnJSAh7pMGExMb0MC8eZFIGxIzruHB5P4ngSmaL12b53Ulf8LzP2o1MwUTAd
BgNVHQ4EFgQUs8OQThYHP98r+3/s2vLfUNDj1TEwHwYDVR0jBBgwFoAUs8OQThYH
P98r+3/s2vLfUNDj1TEwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBE
AiBArx1qm8xKbxXK30JD2jdvMVo+XFwWGNDNzwYCRfb60QIgH3Q55VHUZXHwgysl
YBFeoacrRlcf4t7VyeI4yAEG1q0=
-----END CERTIFICATE-----
"#;

const CHECK_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgkjGF+oW40C122VHs
dnnXYQmOuXKiyn5YqHW6HXuPO82hRANCAAQXpxOPohjjciNp9QoIOBbMOcfcvfG8
HSDVxnJSAh7pMGExMb0MC8eZFIGxIzruHB5P4ngSmaL12b53Ulf8LzP2
-----END PRIVATE KEY-----
"#;

const CHECK_OTHER_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgjeO14atCpqcNqPEa
Rtlb9nDn67rfual7vOqr+TE+LTOhRANCAARnMjqr0ixHq1wJFlwSaI8/WaZSWjWe
FWGU7BfKJXFHDCCB80GJVXFyqzevL7nVMaEClgzXRnChIMvy8A6Uzeui
-----END PRIVATE KEY-----
"#;
// These envelopes decode to bytes that are not an X.509 certificate or key.
const INVALID_CERT_DER: &str =
    "-----BEGIN CERTIFICATE-----\nbm90LWEtdGxzLWNlcnRpZmljYXRl\n-----END CERTIFICATE-----\n";
const INVALID_KEY_DER: &str =
    "-----BEGIN PRIVATE KEY-----\nbm90LWEtdGxzLXByaXZhdGUta2V5\n-----END PRIVATE KEY-----\n";

fn check_tls_material(cert: &str, key: &str, ca: &str, expected_error: Option<&str>) {
    let dir = tempfile::tempdir().unwrap();
    let cert_file = dir.path().join("server.pem");
    let key_file = dir.path().join("server.key");
    let ca_file = dir.path().join("client-ca.pem");
    std::fs::write(&cert_file, cert).unwrap();
    std::fs::write(&key_file, key).unwrap();
    std::fs::write(&ca_file, ca).unwrap();
    // A valid check must succeed even when its configured port is occupied,
    // and must not create the UDS parent or runtime state directory.
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let runtime_dir = dir.path().join("not-created");
    let config = format!(
        "{}\n[global.telemetry.grpc_tcp]\naddress = {:?}\n\
         tls_cert_file = {cert_file:?}\ntls_key_file = {key_file:?}\n\
         tls_client_ca_file = {ca_file:?}\n",
        CLEAN.replace("/tmp/rustbgpd-check-strict", runtime_dir.to_str().unwrap()),
        occupied.local_addr().unwrap().to_string(),
    );
    for args in [&["--check"][..], &["--check", "--strict"][..]] {
        let (code, stdout, stderr) = run(&config, args);
        if let Some(expected) = expected_error {
            assert_eq!(
                code,
                Some(1),
                "{args:?}: stdout:\n{stdout}\nstderr:\n{stderr}"
            );
            assert!(stdout.is_empty(), "{stdout}");
            assert!(stderr.contains(expected), "{stderr}");
            // Neither a parsed credential nor rejected PEM/DER is diagnostic text.
            for material in [cert, key, ca] {
                for line in material.lines().filter(|line| !line.starts_with("-----")) {
                    assert!(!stderr.contains(line), "credential content in stderr");
                }
            }
        } else {
            assert_eq!(
                code,
                Some(0),
                "{args:?}: stdout:\n{stdout}\nstderr:\n{stderr}"
            );
            assert!(stdout.contains("config OK"), "{stdout}");
            assert!(stderr.is_empty(), "{stderr}");
        }
        assert!(
            !runtime_dir.exists(),
            "check created runtime or listener state"
        );
    }
}

#[test]
fn check_tls_accepts_valid_material_without_binding() {
    check_tls_material(CHECK_CERT, CHECK_KEY, CHECK_CERT, None);
}

#[test]
fn check_tls_rejects_mismatched_certificate_and_key() {
    check_tls_material(
        CHECK_CERT,
        CHECK_OTHER_KEY,
        CHECK_CERT,
        Some("certificate/private-key"),
    );
}

#[test]
fn check_tls_rejects_invalid_certificate_der() {
    check_tls_material(
        INVALID_CERT_DER,
        CHECK_KEY,
        CHECK_CERT,
        Some("certificate/private-key"),
    );
}

#[test]
fn check_tls_rejects_invalid_key_der() {
    check_tls_material(
        CHECK_CERT,
        INVALID_KEY_DER,
        CHECK_CERT,
        Some("certificate/private-key"),
    );
}

#[test]
fn check_tls_rejects_invalid_pem_payload() {
    check_tls_material(
        "-----BEGIN CERTIFICATE-----\nnot-valid-base64!\n-----END CERTIFICATE-----\n",
        CHECK_KEY,
        CHECK_CERT,
        Some("certificate PEM"),
    );
}

#[test]
fn check_tls_rejects_invalid_client_ca_der() {
    for ca in [
        INVALID_CERT_DER.to_string(),
        format!("{CHECK_CERT}{INVALID_CERT_DER}"),
    ] {
        check_tls_material(CHECK_CERT, CHECK_KEY, &ca, Some("client-CA"));
    }
}
