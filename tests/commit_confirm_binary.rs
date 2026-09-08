//! Real-binary proof of durable commit-confirm (ADR-0076 Decision 6).
//!
//! Each scenario drives the actual `rustbgpd` binary through `rbgp` over the
//! default runtime-dir UDS listener, then SIGKILLs the daemon to prove the
//! boot-time revert journal closes the "confirmed-by-restart" hole:
//!
//! - unconfirmed window + SIGKILL → restart follows the config-adjacent v3
//!   locator, boots the PREVIOUS config, saves the unconfirmed candidate aside,
//!   consumes the fixed pending files, and prints a path-redacted loud banner;
//! - confirm + SIGKILL → the new config is retained and no v3 pending files
//!   remain;
//! - in-process timeout auto-revert → all v3 pending files are consumed;
//! - an upgrade with retired v2 authority pending → startup refuses it
//!   untouched before loading the unconfirmed candidate;
//! - v2 history survives restart and restores only after source verification
//!   is available;
//! - any locator-free retired journal → boot refuses with N-1 recovery
//!   guidance and leaves the evidence untouched.

use std::fs::File;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const JOURNAL_FILE_NAME: &str = "commit-confirm-journal.json";
const LOCATOR_SUFFIX: &str = ".commit-confirm-locator.json";
const V3_RAW_FILE_NAME: &str = "commit-confirm-v3-prior.toml";
const V3_METADATA_FILE_NAME: &str = "commit-confirm-v3-metadata.json";

struct Daemon {
    child: Child,
    stderr_path: PathBuf,
}

impl Daemon {
    fn spawn(config_path: &Path, stderr_path: PathBuf) -> Self {
        let stderr = File::create(&stderr_path).expect("failed to create daemon stderr log");
        let stdout = stderr
            .try_clone()
            .expect("failed to clone daemon audit log handle");
        let child = Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
            .arg(config_path)
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("failed to spawn rustbgpd binary");
        Self { child, stderr_path }
    }

    fn assert_still_running(&mut self) {
        match self.child.try_wait() {
            Ok(None) => {}
            Ok(Some(status)) => panic!(
                "rustbgpd exited before test completed: {status}\nstderr:\n{}",
                self.stderr()
            ),
            Err(e) => panic!("failed to query rustbgpd child status: {e}"),
        }
    }

    fn stderr(&self) -> String {
        std::fs::read_to_string(&self.stderr_path).unwrap_or_else(|e| {
            format!(
                "<failed to read daemon stderr {}: {e}>",
                self.stderr_path.display()
            )
        })
    }

    fn grpc_audit_method_count(&self, method: &str) -> usize {
        self.stderr()
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|event| event["fields"]["method"].as_str() == Some(method))
            .count()
    }

    /// SIGKILL — no shutdown coordination, simulating a crash inside the
    /// confirm window.
    fn sigkill(mut self) {
        self.child.kill().expect("failed to SIGKILL rustbgpd");
        self.child.wait().expect("failed to reap rustbgpd");
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn rbgp(grpc_addr: &str, args: &[&str]) -> Output {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_rbgp") {
        let mut cmd = Command::new(path);
        cmd.arg("--addr").arg(grpc_addr).args(args).output()
    } else {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
        let mut cmd = Command::new(cargo);
        cmd.args(["run", "--quiet", "-p", "rustbgpctl", "--bin", "rbgp", "--"])
            .arg("--addr")
            .arg(grpc_addr)
            .args(args)
            .output()
    }
    .expect("failed to spawn rbgp subprocess")
}

fn rbgp_json(grpc_addr: &str, args: &[&str]) -> serde_json::Value {
    let output = rbgp(grpc_addr, args);
    // `config diff`/`config plan` exit 2 when changes are present (the
    // detailed exit-code contract); their JSON is still the successful
    // answer. Everything else must exit 0; 1 stays an error.
    let code = output.status.code();
    assert!(
        output.status.success() || code == Some(2),
        "rbgp {args:?} failed (exit {code:?})\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    serde_json::from_slice(&output.stdout).expect("rbgp JSON output must parse")
}

#[test]
fn actual_binary_rejects_retired_config_from_file_aliases() {
    // Load-bearing: restoring any hidden alias makes the real parser accept
    // that invocation, so its exit/stderr assertions go red before connect.
    for args in [
        vec!["config", "diff", "--from-file", "candidate.toml"],
        vec!["config", "plan", "--from-file", "candidate.toml"],
        vec![
            "config",
            "apply",
            "--from-file",
            "candidate.toml",
            "--expected-runtime-snapshot-token",
            "kv1:old:1",
        ],
    ] {
        let output = rbgp("http://127.0.0.1:1", &args);
        assert_eq!(output.status.code(), Some(2), "args: {args:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("unexpected argument '--from-file'"),
            "args: {args:?}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn wait_until_serving(grpc_addr: &str, daemon: &mut Daemon) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if rbgp(grpc_addr, &["--json", "config", "status"])
            .status
            .success()
        {
            return;
        }
        daemon.assert_still_running();
        thread::sleep(Duration::from_millis(100));
    }
    panic!(
        "rustbgpd gRPC never became ready\ndaemon stderr:\n{}",
        daemon.stderr()
    );
}

struct Lab {
    config_path: PathBuf,
    candidate_path: PathBuf,
    journal_path: PathBuf,
    raw_path: PathBuf,
    metadata_path: PathBuf,
    locator_path: PathBuf,
    grpc_addr: String,
    dir: PathBuf,
}

fn base_toml(runtime_dir: &Path, extra: &str) -> String {
    format!(
        r#"
[security.grpc]
enforcement = "tier"

[security.grpc.roles]
"rustbgpd://operator/commit-confirm-test" = "operator"

[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 0
runtime_state_dir = "{runtime_dir}"

[global.telemetry]
log_format = "json"

[global.telemetry.grpc_uds]
path = "{runtime_dir}/grpc.sock"
principal = "rustbgpd://operator/commit-confirm-test"

[peer_groups.ix-members]
{extra}
"#,
        runtime_dir = runtime_dir.display()
    )
}

const DYNAMIC_NEIGHBOR_EXTRA: &str = r#"
[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
remote_asn = 65010
"#;

/// Set up config + candidate files in `dir` and return the paths.
fn lab(dir: &Path) -> Lab {
    // Causal destructive-red proof: removing either privacy clamp makes the
    // real v3 publisher reject the locator or pending parent before candidate
    // persistence, so every confirmed-apply scenario fails at `apply`.
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .expect("failed to make config parent owner-only");
    let runtime_dir = dir.join("runtime");
    std::fs::create_dir_all(&runtime_dir).expect("failed to create runtime dir");
    std::fs::set_permissions(&runtime_dir, std::fs::Permissions::from_mode(0o700))
        .expect("failed to make runtime state dir owner-only");
    let config_path = dir.join("rustbgpd.toml");
    let mut locator_path = config_path.clone().into_os_string();
    locator_path.push(LOCATOR_SUFFIX);
    let locator_path = PathBuf::from(locator_path);
    let base = base_toml(&runtime_dir, "");
    let parsed: toml::Value = toml::from_str(&base).expect("base config must parse");
    let principal = "rustbgpd://operator/commit-confirm-test";
    assert_eq!(
        parsed["security"]["grpc"]["enforcement"].as_str(),
        Some("tier"),
        "mutation proof: binary fixture must exercise Tier authorization"
    );
    assert_eq!(
        parsed["global"]["telemetry"]["grpc_uds"]["principal"].as_str(),
        Some(principal)
    );
    assert_eq!(
        parsed["security"]["grpc"]["roles"][principal].as_str(),
        Some("operator")
    );
    std::fs::write(&config_path, base).expect("failed to write config");
    let candidate_path = dir.join("candidate.toml");
    std::fs::write(
        &candidate_path,
        base_toml(&runtime_dir, DYNAMIC_NEIGHBOR_EXTRA),
    )
    .expect("failed to write candidate");
    Lab {
        config_path,
        candidate_path,
        journal_path: runtime_dir.join(JOURNAL_FILE_NAME),
        raw_path: runtime_dir.join(V3_RAW_FILE_NAME),
        metadata_path: runtime_dir.join(V3_METADATA_FILE_NAME),
        locator_path,
        grpc_addr: format!("unix://{}", runtime_dir.join("grpc.sock").display()),
        dir: dir.to_path_buf(),
    }
}

fn large_prior_lab(dir: &Path) -> Lab {
    let lab = lab(dir);
    let mut members = String::new();
    for index in 1..=320 {
        use std::fmt::Write as _;
        writeln!(
            members,
            r#"
[[neighbors]]
address = "2001:db8::{index:x}"
remote_asn = 65010
peer_group = "ix-members"
description = {:?}
"#,
            "member-shape-".repeat(2_700)
        )
        .unwrap();
    }
    let runtime_dir = lab
        .journal_path
        .parent()
        .expect("journal has runtime parent");
    let prior = base_toml(runtime_dir, &members);
    let candidate = base_toml(runtime_dir, &format!("{members}\n{DYNAMIC_NEIGHBOR_EXTRA}"));
    assert!(prior.len() > 10 * 1024 * 1024);
    std::fs::write(&lab.config_path, prior).expect("failed to write large normalized prior input");
    std::fs::write(&lab.candidate_path, candidate).expect("failed to write large candidate");
    lab
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            write!(out, "{byte:02x}").unwrap();
            out
        })
}

fn write_v2_pending_authority(lab: &Lab, envelope: &serde_json::Value, confirm_id: &str) {
    let prior = envelope["normalized_toml"].as_str().unwrap();
    let prior_hex = envelope["sha256"].as_str().unwrap();
    let source_hex = envelope["source_sha256"].as_str().unwrap();
    let manifest = &envelope["manifest"];
    assert_eq!(manifest["toml_sha256"], prior_hex);
    assert_eq!(manifest["rpol_units"].as_array().map(Vec::len), Some(0));
    assert_eq!(manifest["datasets"].as_array().map(Vec::len), Some(0));
    let prior_json = serde_json::to_string(prior).unwrap();
    let journal = format!(
        "{{\"version\":2,\"confirm_id\":{confirm_id:?},\"deadline_unix_seconds\":9,\"rollback_failed\":false,\"prior\":{{\"sha256\":\"{prior_hex}\",\"source_sha256\":\"{source_hex}\",\"normalized_toml\":{prior_json},\"manifest\":{{\"toml_sha256\":\"{prior_hex}\",\"rpol_units\":[],\"datasets\":[]}}}}}}\n"
    );
    let path_wire = |path: &Path| {
        format!(
            "{{\"encoding\":\"unix-bytes-hex\",\"value\":\"{}\"}}",
            hex(path.as_os_str().as_bytes())
        )
    };
    let locator = format!(
        "{{\"version\":2,\"confirm_id\":{confirm_id:?},\"journal_path\":{},\"config_target\":{},\"prior_sha256\":\"{prior_hex}\",\"prior_source_sha256\":\"{source_hex}\"}}\n",
        path_wire(&lab.journal_path),
        path_wire(&lab.config_path),
    );
    std::fs::write(&lab.journal_path, journal).unwrap();
    std::fs::set_permissions(&lab.journal_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&lab.locator_path, locator).unwrap();
    std::fs::set_permissions(&lab.locator_path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

impl Lab {
    fn spawn(&self, stderr_name: &str) -> Daemon {
        let mut daemon = Daemon::spawn(&self.config_path, self.dir.join(stderr_name));
        wait_until_serving(&self.grpc_addr, &mut daemon);
        daemon
    }

    fn assert_no_v3_authority(&self, context: &str) {
        assert!(!self.locator_path.exists(), "{context}: locator remains");
    }

    fn assert_no_v3_residue_eventually(&self, context: &str) {
        let raw_tombstone = self
            .raw_path
            .with_file_name("commit-confirm-v3-prior.cleanup");
        let metadata_tombstone = self
            .metadata_path
            .with_file_name("commit-confirm-v3-metadata.cleanup");
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.raw_path.exists()
            || self.metadata_path.exists()
            || raw_tombstone.exists()
            || metadata_tombstone.exists()
        {
            assert!(
                Instant::now() < deadline,
                "{context}: non-authoritative v3 residue remains"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn apply_plain(&self, candidate: &Path) {
        let plan = rbgp_json(
            &self.grpc_addr,
            &["--json", "config", "plan", candidate.to_str().unwrap()],
        );
        let token = plan["runtime_snapshot_token"].as_str().unwrap();
        let output = rbgp(
            &self.grpc_addr,
            &[
                "--json",
                "config",
                "apply",
                candidate.to_str().unwrap(),
                "--expected-runtime-snapshot-token",
                token,
            ],
        );
        assert!(
            output.status.success(),
            "plain apply failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Plan + confirmed-apply the dynamic-neighbor candidate; asserts the
    /// transaction commits and enters the pending confirm window.
    fn apply_confirmed(&self, daemon: &Daemon, confirm_id: &str, timeout_seconds: &str) {
        let plan_audits_before = daemon.grpc_audit_method_count("StreamPlanConfigTransaction");
        let plan = rbgp_json(
            &self.grpc_addr,
            &[
                "--json",
                "config",
                "plan",
                self.candidate_path.to_str().unwrap(),
            ],
        );
        assert_eq!(plan["status"], "committable", "plan: {plan}");
        let plan_token = plan["plan_token"]
            .as_str()
            .expect("streamed plan JSON must expose its single-use plan token");
        assert!(
            !plan_token.is_empty(),
            "streamed plan token must not be empty"
        );
        assert_eq!(
            daemon.grpc_audit_method_count("StreamPlanConfigTransaction"),
            plan_audits_before + 1,
            "the reviewed streamed Plan must emit exactly one production audit event"
        );
        let token = plan["runtime_snapshot_token"]
            .as_str()
            .expect("plan must return a runtime snapshot token");

        let apply_output = rbgp(
            &self.grpc_addr,
            &[
                "--json",
                "config",
                "apply",
                self.candidate_path.to_str().unwrap(),
                "--expected-runtime-snapshot-token",
                token,
                "--plan-token",
                plan_token,
                "--confirm-id",
                confirm_id,
                "--confirm-timeout",
                timeout_seconds,
            ],
        );
        assert!(
            apply_output.status.success(),
            "confirmed apply failed\nstdout:\n{}\nstderr:\n{}\ndaemon logs:\n{}",
            String::from_utf8_lossy(&apply_output.stdout),
            String::from_utf8_lossy(&apply_output.stderr),
            std::fs::read_dir(&self.dir)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "log"))
                .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
                .collect::<Vec<_>>()
                .join("\n")
        );
        let apply: serde_json::Value =
            serde_json::from_slice(&apply_output.stdout).expect("apply output must be JSON");
        assert_eq!(apply["status"], "committable", "apply: {apply}");
        assert_eq!(apply["confirmation"]["status"], "pending", "apply: {apply}");
        assert_eq!(
            daemon.grpc_audit_method_count("StreamPlanConfigTransaction"),
            plan_audits_before + 1,
            "explicit Apply must consume the reviewed Plan token without an implicit second Plan"
        );

        // Commit persisted the (unconfirmed) candidate to the config file and
        // journaled the revert state.
        let on_disk = std::fs::read_to_string(&self.config_path).unwrap();
        assert!(
            on_disk.contains("192.0.2.0/24"),
            "commit must persist the candidate:\n{on_disk}"
        );
        assert!(
            !self.journal_path.exists(),
            "v3 must not reuse the legacy path"
        );
        assert!(
            self.locator_path.exists(),
            "confirmed apply must publish the v3 locator last"
        );
        let raw = std::fs::read(&self.raw_path).unwrap();
        let metadata = std::fs::read(&self.metadata_path).unwrap();
        let locator = std::fs::read(&self.locator_path).unwrap();
        assert!(!raw.is_empty(), "real-binary writer must publish the prior");
        assert!(
            metadata.starts_with(b"{\"version\":3,"),
            "real-binary writer must emit canonical v3 metadata"
        );
        assert!(
            locator.starts_with(b"{\"version\":3,"),
            "real-binary writer must emit the canonical v3 locator"
        );
    }
}

fn metadata_history(lab: &Lab, expected_rows: usize) -> Vec<serde_json::Value> {
    let history = rbgp_json(&lab.grpc_addr, &["--json", "config", "history"]);
    let entries = history["entries"].as_array().expect("history entries");
    assert_eq!(entries.len(), expected_rows, "{history}");
    for (index, entry) in entries.iter().enumerate() {
        assert_eq!(entry["index"], index);
        assert_eq!(entry["provenance_status"], "metadata_only");
        assert_eq!(entry["rollback_eligible"], false);
        assert_eq!(
            entry["metadata_only_reason"],
            "normalized_toml_exceeds_v2_payload_limit"
        );
        assert!(entry["normalized_toml_bytes"].as_u64().unwrap() > 10 * 1024 * 1024);
        assert_eq!(entry["source_sha256"].as_str().unwrap().len(), 64);
    }
    entries.clone()
}

fn assert_metadata_matches(entry: &serde_json::Value, accepted: &[u8]) {
    use sha2::Digest as _;

    assert_eq!(entry["normalized_toml_bytes"], accepted.len());
    assert_eq!(entry["sha256"], hex(&sha2::Sha256::digest(accepted)));
}

#[test]
fn streamed_confirmed_apply_above_eight_mib_aborts_to_previous_config() {
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    let lab = large_prior_lab(temp.path());
    // Load-bearing streamed-path proof: this candidate cannot traverse the
    // legacy unary RPC's four-MiB decoder. Reverting either CLI streaming call
    // site makes the confirmed apply fail before commit.
    assert!(
        std::fs::metadata(&lab.candidate_path).unwrap().len() > 8 * 1024 * 1024,
        "confirmed-apply fixture must stay above eight MiB"
    );

    let mut daemon = lab.spawn("daemon.stderr.log");
    let boot_history = metadata_history(&lab, 1);
    let human_plan = rbgp(
        &lab.grpc_addr,
        &["config", "plan", lab.candidate_path.to_str().unwrap()],
    );
    assert_eq!(human_plan.status.code(), Some(2));
    let human_stdout = String::from_utf8(human_plan.stdout).unwrap();
    let exposed_token = human_stdout
        .lines()
        .find_map(|line| line.strip_prefix("plan_token: "))
        .expect("streamed plan human output must expose its single-use plan token");
    assert!(!exposed_token.is_empty());
    lab.apply_confirmed(&daemon, "stream-abort", "600");
    assert!(
        std::fs::metadata(&lab.raw_path).unwrap().len() > 10 * 1024 * 1024,
        "real-binary writer must publish a genuinely normalized prior above 10 MiB"
    );
    // Boot preserves the operator file, so its normalized identity comes from
    // the independently persisted commit-confirm prior, not the raw input.
    assert_metadata_matches(&boot_history[0], &std::fs::read(&lab.raw_path).unwrap());
    let candidate_history = metadata_history(&lab, 2);
    assert_metadata_matches(
        &candidate_history[0],
        &std::fs::read(&lab.config_path).unwrap(),
    );
    assert_ne!(candidate_history[0]["sha256"], boot_history[0]["sha256"]);
    let mut retained_boot = boot_history[0].clone();
    retained_boot["index"] = 1.into();
    assert_eq!(candidate_history[1], retained_boot);
    let abort = rbgp_json(
        &lab.grpc_addr,
        &["--json", "config", "abort", "stream-abort"],
    );
    assert_eq!(abort["confirmation"]["status"], "aborted", "{abort}");
    let persisted = std::fs::read_to_string(&lab.config_path).unwrap();
    let restored_history = metadata_history(&lab, 3);
    assert_metadata_matches(&restored_history[0], persisted.as_bytes());
    for field in ["sha256", "source_sha256", "normalized_toml_bytes"] {
        assert_eq!(restored_history[0][field], boot_history[0][field]);
    }
    for (index, entry) in candidate_history.iter().enumerate() {
        let mut retained = entry.clone();
        retained["index"] = (index + 1).into();
        assert_eq!(restored_history[index + 1], retained);
    }
    assert!(
        !persisted.contains("192.0.2.0/24"),
        "abort must restore the pre-transaction config"
    );
    lab.assert_no_v3_authority("abort must consume v3 authority");
    lab.assert_no_v3_residue_eventually("abort must clean v3 residue");
    let ranges = rbgp_json(&lab.grpc_addr, &["--json", "dynamic-neighbor", "list"]);
    assert_eq!(
        ranges.as_array().map(Vec::len),
        Some(0),
        "aborted daemon must run the previous config: {ranges}"
    );
    daemon.assert_still_running();
}

#[test]
fn unsafe_fixed_raw_slot_refuses_before_real_binary_apply() {
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    let lab = lab(temp.path());
    let previous = std::fs::read(&lab.config_path).unwrap();
    let mut daemon = lab.spawn("daemon.stderr.log");
    let plan = rbgp_json(
        &lab.grpc_addr,
        &[
            "--json",
            "config",
            "plan",
            lab.candidate_path.to_str().unwrap(),
        ],
    );
    let token = plan["runtime_snapshot_token"].as_str().unwrap();
    std::fs::create_dir(&lab.raw_path).unwrap();
    let apply = rbgp(
        &lab.grpc_addr,
        &[
            "--json",
            "config",
            "apply",
            lab.candidate_path.to_str().unwrap(),
            "--expected-runtime-snapshot-token",
            token,
            "--confirm-id",
            "unsafe-raw",
            "--confirm-timeout",
            "60",
        ],
    );
    assert!(!apply.status.success());
    assert_eq!(std::fs::read(&lab.config_path).unwrap(), previous);
    assert!(lab.raw_path.is_dir(), "unsafe replacement must survive");
    assert!(!lab.locator_path.exists() && !lab.metadata_path.exists());
    let ranges = rbgp_json(&lab.grpc_addr, &["--json", "dynamic-neighbor", "list"]);
    assert_eq!(ranges.as_array().map(Vec::len), Some(0));
    daemon.assert_still_running();
}

#[test]
fn sigkill_in_confirm_window_boots_previous_config_and_saves_candidate_aside() {
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    let lab = lab(temp.path());

    let daemon = lab.spawn("first.stderr.log");
    lab.apply_confirmed(&daemon, "kill-window", "600");
    daemon.sigkill();

    // Restart: boot must revert BEFORE adopting the on-disk (unconfirmed)
    // candidate — regardless of the 600s deadline still having time left.
    let mut daemon = lab.spawn("second.stderr.log");
    let on_disk = std::fs::read_to_string(&lab.config_path).unwrap();
    assert!(
        !on_disk.contains("192.0.2.0/24"),
        "boot must restore the pre-transaction config:\n{on_disk}"
    );
    let backup_path = lab.dir.join("rustbgpd.toml.unconfirmed");
    let saved_aside = std::fs::read_to_string(&backup_path)
        .expect("the unconfirmed candidate must be saved aside");
    assert!(
        saved_aside.contains("192.0.2.0/24"),
        "saved-aside file must hold the unconfirmed candidate:\n{saved_aside}"
    );
    lab.assert_no_v3_authority("boot revert must consume v3 authority");
    lab.assert_no_v3_residue_eventually("boot revert must clean v3 residue");
    let stderr = daemon.stderr();
    assert!(
        stderr.contains("commit-confirm boot revert")
            && stderr.contains("kill-window")
            && stderr.contains("saved beside its recorded target"),
        "boot banner must name the transaction without exposing paths:\n{stderr}"
    );
    for secret in [
        backup_path.to_string_lossy().as_ref(),
        lab.config_path.to_string_lossy().as_ref(),
        lab.journal_path.to_string_lossy().as_ref(),
        lab.raw_path.to_string_lossy().as_ref(),
        lab.metadata_path.to_string_lossy().as_ref(),
    ] {
        assert!(
            !stderr.contains(secret),
            "v3 boot banner must redact persisted path {secret:?}:\n{stderr}"
        );
    }

    // The reverted daemon is running the previous config.
    let ranges = rbgp_json(&lab.grpc_addr, &["--json", "dynamic-neighbor", "list"]);
    assert_eq!(
        ranges.as_array().map(Vec::len),
        Some(0),
        "reverted daemon must not run the candidate's dynamic neighbors: {ranges}"
    );
    daemon.assert_still_running();
}

#[test]
fn confirm_then_sigkill_retains_new_config_and_leaves_no_journal() {
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    let lab = lab(temp.path());

    let daemon = lab.spawn("first.stderr.log");
    lab.apply_confirmed(&daemon, "kill-confirmed", "600");
    let confirm = rbgp_json(
        &lab.grpc_addr,
        &["--json", "config", "confirm", "kill-confirmed"],
    );
    assert_eq!(confirm["confirmation"]["status"], "confirmed", "{confirm}");
    lab.assert_no_v3_authority("confirm must consume v3 authority");
    lab.assert_no_v3_residue_eventually("confirm must clean v3 residue");
    daemon.sigkill();

    let mut daemon = lab.spawn("second.stderr.log");
    let on_disk = std::fs::read_to_string(&lab.config_path).unwrap();
    assert!(
        on_disk.contains("192.0.2.0/24"),
        "the confirmed config must survive the restart:\n{on_disk}"
    );
    assert!(!daemon.stderr().contains("commit-confirm boot revert"));
    let ranges = rbgp_json(&lab.grpc_addr, &["--json", "dynamic-neighbor", "list"]);
    assert_eq!(
        ranges.as_array().map(Vec::len),
        Some(1),
        "confirmed daemon must run the new config: {ranges}"
    );
    daemon.assert_still_running();
}

#[test]
fn in_process_timeout_auto_revert_consumes_journal() {
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    let lab = lab(temp.path());

    let mut daemon = lab.spawn("daemon.stderr.log");
    lab.apply_confirmed(&daemon, "timeout-revert", "2");

    // Poll for the auto-revert (2s timer + rollback work).
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let status = rbgp_json(&lab.grpc_addr, &["--json", "config", "status"]);
        match status["confirmation"]["status"].as_str() {
            Some("pending") => {}
            Some("auto_reverted") => break,
            other => panic!("unexpected confirmation status {other:?}: {status}"),
        }
        assert!(
            Instant::now() < deadline,
            "auto-revert did not happen in time\ndaemon stderr:\n{}",
            daemon.stderr()
        );
        daemon.assert_still_running();
        thread::sleep(Duration::from_millis(200));
    }

    lab.assert_no_v3_authority("timeout auto-revert must consume v3 authority");
    lab.assert_no_v3_residue_eventually("timeout auto-revert must clean v3 residue");
    let on_disk = std::fs::read_to_string(&lab.config_path).unwrap();
    assert!(
        !on_disk.contains("192.0.2.0/24"),
        "auto-revert must restore the pre-transaction config:\n{on_disk}"
    );
    daemon.assert_still_running();
}

#[test]
fn real_binary_refuses_v2_authority_untouched_before_candidate_load() {
    // Destructive proof: restoring v2 dispatch mutates/removes the authority;
    // ignoring it boots the candidate. Both break the exact refusal and
    // byte-identical evidence assertions below.
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    let lab = lab(temp.path());
    let daemon = lab.spawn("prior.stderr.log");
    let effective = rbgp(&lab.grpc_addr, &["config", "effective"]);
    assert!(effective.status.success());
    let prior_path = lab.dir.join("normalized-prior.toml");
    std::fs::write(&prior_path, effective.stdout).unwrap();
    lab.apply_plain(&lab.candidate_path);
    lab.apply_plain(&prior_path);
    let history_dir = lab.journal_path.parent().unwrap().join("config-history");
    let latest = std::fs::read_dir(&history_dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("v2-"))
        .max_by_key(|entry| entry.file_name())
        .unwrap();
    let envelope: serde_json::Value =
        serde_json::from_slice(&std::fs::read(latest.path()).unwrap()).unwrap();
    daemon.sigkill();

    std::fs::copy(&lab.candidate_path, &lab.config_path).unwrap();
    write_v2_pending_authority(&lab, &envelope, "upgrade-v2");
    std::fs::write(&lab.config_path, "invalid candidate = [").unwrap();
    let locator_before = std::fs::read(&lab.locator_path).unwrap();
    let journal_before = std::fs::read(&lab.journal_path).unwrap();
    let candidate_before = std::fs::read(&lab.config_path).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
        .arg(&lab.config_path)
        .output()
        .expect("failed to spawn rustbgpd binary");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    for needle in [
        "retired v2 commit-confirm authority",
        "rustbgpd v0.64.0",
        "left untouched",
    ] {
        assert!(stderr.contains(needle), "missing {needle:?}:\n{stderr}");
    }
    assert_eq!(std::fs::read(&lab.locator_path).unwrap(), locator_before);
    assert_eq!(std::fs::read(&lab.journal_path).unwrap(), journal_before);
    assert_eq!(std::fs::read(&lab.config_path).unwrap(), candidate_before);
    assert!(!lab.dir.join("rustbgpd.toml.unconfirmed").exists());
}

#[test]
fn locator_free_retired_journal_refuses_boot_untouched() {
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    let lab = lab(temp.path());
    // Any occupant may be pending authority; v0.65 never parses or removes it.
    let retired = "{\"confirm_id\": \"deploy-1\", \"dead";
    std::fs::write(&lab.journal_path, retired).expect("failed to write torn journal");

    let output = Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
        .arg(&lab.config_path)
        .output()
        .expect("failed to spawn rustbgpd binary");
    assert_eq!(
        output.status.code(),
        Some(1),
        "daemon must refuse to boot on a torn journal"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    for needle in [
        "refusing to boot",
        &*lab.journal_path.to_string_lossy(),
        "rustbgpd v0.64.0",
        "delete it only after proving",
        "left untouched",
    ] {
        assert!(
            stderr.contains(needle),
            "refusal must mention {needle:?}:\n{stderr}"
        );
    }
    // Fail closed: nothing touched.
    assert_eq!(std::fs::read_to_string(&lab.journal_path).unwrap(), retired);
    assert!(
        std::fs::read_to_string(&lab.config_path)
            .unwrap()
            .contains("[peer_groups.ix-members]")
    );
}

/// Red proof: removing v2 provenance, restart deduplication, or the verified
/// v2 restore changes the exact history/receipt assertions and leaves disk or
/// the live dynamic-neighbor roster on the candidate generation.
#[test]
fn v2_history_survives_restart_and_restores_after_source_verification() {
    // End-to-end proof over the real binary: apply a config, restart the daemon
    // (history must survive without a duplicate boot row), then prove a v2 row
    // is verified and restored through the normal transaction path.
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    let lab = lab(temp.path());
    std::fs::write(
        lab.dir.join("external.rpol"),
        "policy external { term rest { accept } }\n",
    )
    .unwrap();
    let runtime_dir = lab.dir.join("runtime");
    let external = format!(
        "\n[policy]\nrpol_files = [{:?}]\n",
        lab.dir.join("external.rpol").display().to_string()
    );
    let base_extra = format!(
        "{external}\n[[fib_tables]]\nname = \"history-proof\"\ntable_id = 1001\nmetric = 200\nfamilies = [\"ipv4_unicast\"]\n"
    );
    std::fs::write(&lab.config_path, base_toml(&runtime_dir, &base_extra)).unwrap();
    std::fs::write(
        &lab.candidate_path,
        base_toml(
            &runtime_dir,
            &format!(
                "{external}\n[[fib_tables]]\nname = \"history-proof\"\ntable_id = 1001\nmetric = 201\nfamilies = [\"ipv4_unicast\"]\n"
            ),
        ),
    )
    .unwrap();

    let daemon = lab.spawn("first.stderr.log");
    // Plain (unconfirmed) pure-FIB apply while external policy is declared.
    let plan = rbgp_json(
        &lab.grpc_addr,
        &[
            "--json",
            "config",
            "plan",
            lab.candidate_path.to_str().unwrap(),
        ],
    );
    assert_eq!(plan["status"], "committable", "plan: {plan}");
    let token = plan["runtime_snapshot_token"].as_str().unwrap();
    let apply = rbgp_json(
        &lab.grpc_addr,
        &[
            "--json",
            "config",
            "apply",
            lab.candidate_path.to_str().unwrap(),
            "--expected-runtime-snapshot-token",
            token,
        ],
    );
    assert_eq!(apply["status"], "committable", "apply: {apply}");

    // History: boot config + applied candidate, newest first.
    let history = rbgp_json(&lab.grpc_addr, &["--json", "config", "history"]);
    let entries = history["entries"].as_array().expect("entries array");
    assert_eq!(entries.len(), 2, "boot + apply must be recorded: {history}");
    assert!(entries.iter().all(|entry| {
        entry["provenance_status"] == "recorded"
            && entry["source_sha256"]
                .as_str()
                .is_some_and(|digest| !digest.is_empty())
    }));
    assert_ne!(
        entries[0]["sha256"], entries[1]["sha256"],
        "distinct configs must have distinct hashes: {history}"
    );
    let expected_history = history.clone();

    // Restart: history survives on disk, and the boot-time re-record of the
    // unchanged running config deduplicates instead of growing history.
    daemon.sigkill();
    let mut daemon = lab.spawn("second.stderr.log");
    let history = rbgp_json(&lab.grpc_addr, &["--json", "config", "history"]);
    assert_eq!(
        history, expected_history,
        "history must survive a restart without duplicate boot entries"
    );

    // Rolling back past the retained history fails cleanly.
    let out_of_range = rbgp(&lab.grpc_addr, &["--json", "config", "rollback", "5"]);
    assert!(
        !out_of_range.status.success(),
        "rollback past history must fail"
    );
    let stderr = String::from_utf8_lossy(&out_of_range.stderr);
    assert!(
        stderr.contains("out of range"),
        "out-of-range rollback must say so:\n{stderr}"
    );
    // ...and must not have changed anything.
    let after_failed = std::fs::read_to_string(&lab.config_path).unwrap();
    assert!(
        after_failed.contains("metric = 201"),
        "failed rollback must not touch the config:\n{after_failed}"
    );

    let on_disk = std::fs::read_to_string(&lab.config_path).unwrap();
    assert!(
        on_disk.contains("metric = 201"),
        "candidate must still be active before rollback:\n{on_disk}"
    );
    assert!(!lab.journal_path.exists());
    assert!(!lab.locator_path.exists());

    // The retained manifest is verification authority, not adoption authority:
    // changed live external bytes refuse without touching runtime or disk.
    std::fs::write(
        lab.dir.join("external.rpol"),
        "policy external { term rest { reject } }\n",
    )
    .unwrap();
    let changed = rbgp(&lab.grpc_addr, &["--json", "config", "rollback", "1"]);
    assert!(!changed.status.success(), "changed provenance must refuse");
    let changed_error = String::from_utf8_lossy(&changed.stderr);
    assert!(
        changed_error.contains("missing, unreadable, or changed"),
        "{changed_error}"
    );
    assert!(!changed_error.contains(lab.dir.to_string_lossy().as_ref()));
    assert_eq!(std::fs::read_to_string(&lab.config_path).unwrap(), on_disk);
    std::fs::write(
        lab.dir.join("external.rpol"),
        "policy external { term rest { accept } }\n",
    )
    .unwrap();

    let rollback = rbgp_json(&lab.grpc_addr, &["--json", "config", "rollback", "1"]);
    assert!(
        rollback["human_text"]
            .as_str()
            .is_some_and(|text| text.contains("Rolled back to applied config 1")),
        "v2 rollback receipt must name the exact common index: {rollback}"
    );

    // MUTATION PROOF: verified rollback changes durable and live state to the
    // older accepted generation without opening a commit-confirm journal.
    assert!(
        !std::fs::read_to_string(&lab.config_path)
            .unwrap()
            .contains("metric = 201"),
        "verified v2 rollback must persist metric 200"
    );
    assert_eq!(
        rbgp_json(&lab.grpc_addr, &["--json", "config", "history"])["entries"]
            .as_array()
            .map(Vec::len),
        Some(3),
        "restoring a non-newest generation must append an accepted receipt"
    );
    assert!(!lab.journal_path.exists());
    assert!(!lab.locator_path.exists());
    daemon.assert_still_running();
}

/// `rbgp doctor --pre-upgrade CONFIG` against the real binary: a pending
/// confirmed transaction turns the upgrade check red with the exact next
/// action and resolves nothing on the operator's behalf; a staged posture
/// change is red without any rewrite; after explicit settlement the same
/// command is green, and the documented sequence continues with the
/// coordinated stop, the inactive check, and the candidate check on the
/// stopped daemon's file. Every green result is dated and never claims a
/// fence.
#[test]
fn doctor_pre_upgrade_stops_on_pending_confirmation_and_passes_after_settlement() {
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    let lab = lab(temp.path());
    // Doctor probes the BGP listen port of a reachable daemon, so the lab
    // config must bind a real port rather than `listen_port = 0`.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind an ephemeral port")
        .local_addr()
        .expect("local addr")
        .port();
    for path in [&lab.config_path, &lab.candidate_path] {
        let text = std::fs::read_to_string(path).expect("read lab config");
        let rewritten = text.replace("listen_port = 0", &format!("listen_port = {port}"));
        assert_ne!(rewritten, text, "lab config must declare listen_port = 0");
        // The post-stop strict check requires explicit policy on the dynamic
        // range added by the transaction, even for intentional permit-all.
        let rewritten = rewritten.replace(
            "[peer_groups.ix-members]",
            "[peer_groups.ix-members]\nimport_policy_chain = [\"permit-all\"]\nexport_policy_chain = [\"permit-all\"]",
        );
        let rewritten =
            format!("{rewritten}\n[policy.definitions.permit-all]\ndefault_action = \"permit\"\n");
        std::fs::write(path, rewritten).expect("write lab config");
    }
    let mut daemon = lab.spawn("doctor-pre-upgrade.log");
    wait_until_serving(&lab.grpc_addr, &mut daemon);
    let config = lab.config_path.to_str().expect("utf-8 config path");
    let doctor = |bundle: &str| {
        let output = rbgp(
            &lab.grpc_addr,
            &[
                "--json",
                "doctor",
                "--pre-upgrade",
                config,
                "--output",
                &temp.path().join(bundle).display().to_string(),
            ],
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|e| panic!("doctor output must be JSON: {e}\n{output:?}"));
        (output.status.code(), report)
    };
    let check = |report: &serde_json::Value, name: &str| -> (String, String) {
        let check = report["checks"]
            .as_array()
            .expect("checks array")
            .iter()
            .find(|check| check["name"] == name)
            .unwrap_or_else(|| panic!("missing check {name}: {report}"));
        (
            check["status"].as_str().expect("status").to_string(),
            check["detail"].as_str().expect("detail").to_string(),
        )
    };

    // Green observation before any transaction exists.
    let (code, report) = doctor("pre-upgrade-1.tar.gz");
    assert_eq!(code, Some(0), "green pre-upgrade run: {report}");
    assert_eq!(report["pre_upgrade"]["ok"], true, "{report}");
    assert!(
        report["pre_upgrade"]["observed_at_unix_seconds"].is_u64(),
        "{report}"
    );
    for name in [
        "upgrade.transaction",
        "upgrade.settlement",
        "upgrade.posture",
    ] {
        let (status, detail) = check(&report, name);
        assert_eq!(status, "ok", "{name}: {detail}");
        assert!(
            detail.contains("as of unix"),
            "{name} must be dated: {detail}"
        );
    }

    // A transaction that starts after that observation makes the same
    // command red with the exact next action; doctor resolves nothing.
    lab.apply_confirmed(&daemon, "upgrade-window", "600");
    let on_disk_before = std::fs::read(&lab.config_path).expect("read config");
    let (code, report) = doctor("pre-upgrade-2.tar.gz");
    assert_eq!(code, Some(2), "pending confirmation is red: {report}");
    assert_eq!(report["pre_upgrade"]["ok"], false, "{report}");
    let (status, detail) = check(&report, "upgrade.transaction");
    assert_eq!(status, "fail", "{detail}");
    for fragment in [
        "upgrade-window is pending until unix",
        "rbgp config confirm upgrade-window",
        "rbgp config abort upgrade-window",
        "before the coordinated stop",
    ] {
        assert!(detail.contains(fragment), "missing {fragment:?}: {detail}");
    }
    let status = rbgp_json(&lab.grpc_addr, &["--json", "config", "status"]);
    assert_eq!(
        status["confirmation"]["status"], "pending",
        "doctor must not confirm or abort: {status}"
    );
    assert_eq!(
        std::fs::read(&lab.config_path).expect("read config"),
        on_disk_before,
        "doctor must not rewrite the config"
    );

    // Explicit settlement, then the same command is green again.
    let confirmed = rbgp_json(
        &lab.grpc_addr,
        &["--json", "config", "confirm", "upgrade-window"],
    );
    assert_eq!(
        confirmed["confirmation"]["status"], "confirmed",
        "{confirmed}"
    );
    let (code, report) = doctor("pre-upgrade-3.tar.gz");
    assert_eq!(code, Some(0), "settled transaction is green: {report}");
    let (status, detail) = check(&report, "upgrade.transaction");
    assert_eq!(status, "ok", "{detail}");
    assert!(
        detail.contains("terminal (confirmed)") && detail.contains("not a fence"),
        "{detail}"
    );

    // A staged epoch-2 file against the live epoch-1 daemon is red and
    // names the offline migration without performing it.
    let staged = temp.path().join("staged-epoch2.toml");
    // The confirmed apply materialized the live posture into the file
    // (`config_epoch = 1` plus explicit `false`); stage epoch 2 on top of it.
    let live_file = std::fs::read_to_string(&lab.config_path).expect("read config");
    let staged_text = if live_file.contains("config_epoch = 1") {
        live_file.replace("config_epoch = 1", "config_epoch = 2")
    } else {
        format!("config_epoch = 2\n{live_file}")
    };
    std::fs::write(&staged, staged_text).expect("write staged");
    let staged_bytes = std::fs::read(&staged).expect("read staged");
    let output = rbgp(
        &lab.grpc_addr,
        &[
            "--json",
            "doctor",
            "--pre-upgrade",
            staged.to_str().expect("utf-8"),
            "--output",
            &temp
                .path()
                .join("pre-upgrade-4.tar.gz")
                .display()
                .to_string(),
        ],
    );
    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("doctor output must be JSON");
    let (status, detail) = check(&report, "upgrade.posture");
    assert_eq!(status, "fail", "{detail}");
    assert!(
        detail.contains("changes the RFC 8212 posture")
            && detail.contains("--migrate-config pin-legacy --offline"),
        "{detail}"
    );
    assert_eq!(std::fs::read(&staged).expect("read staged"), staged_bytes);

    // The documented sequence continues outside doctor: coordinated stop,
    // verify inactive and authority, correct the staged posture, then check
    // the final candidate bytes with the candidate binary.
    let sigterm = Command::new("kill")
        .args(["-TERM", &daemon.child.id().to_string()])
        .status()
        .expect("send SIGTERM");
    assert!(sigterm.success(), "kill -TERM failed: {sigterm}");
    let exit = daemon.child.wait().expect("reap rustbgpd");
    assert!(exit.success(), "coordinated stop must exit 0: {exit}");
    assert!(
        matches!(daemon.child.try_wait(), Ok(Some(_))),
        "daemon must be inactive before the candidate check"
    );
    lab.assert_no_v3_authority("post-stop pre-upgrade check");
    let migration = Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
        .args(["--migrate-config", "pin-legacy", "--offline"])
        .arg(&staged)
        .output()
        .expect("restore the staged file's live posture offline");
    assert!(
        migration.status.success(),
        "offline migration failed: {migration:?}"
    );
    let migrated = std::fs::read_to_string(&staged).expect("read migrated candidate");
    assert!(migrated.contains("config_epoch = 1"));
    assert!(migrated.contains("ebgp_requires_policy = false"));
    let candidate_check = Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
        .args(["--check", "--strict"])
        .arg(&staged)
        .output()
        .expect("run candidate --check");
    assert!(
        candidate_check.status.success(),
        "candidate check on the stopped daemon's file failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&candidate_check.stdout),
        String::from_utf8_lossy(&candidate_check.stderr)
    );
    drop(daemon);
}
