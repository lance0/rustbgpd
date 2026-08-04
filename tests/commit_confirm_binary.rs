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
//! - an upgrade with v2 authority pending → startup dispatches v2 before
//!   loading the unconfirmed candidate;
//! - v2 history survives restart and restores only after source verification
//!   is available;
//! - a torn legacy journal with no v2 locator → boot still refuses, naming
//!   both legacy files.

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
        let child = Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
            .arg(config_path)
            .stdout(Stdio::null())
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
        assert!(!self.raw_path.exists(), "{context}: raw prior remains");
        assert!(!self.metadata_path.exists(), "{context}: metadata remains");
    }

    fn apply_plain(&self, candidate: &Path) {
        let plan = rbgp_json(
            &self.grpc_addr,
            &[
                "--json",
                "config",
                "plan",
                "--from-file",
                candidate.to_str().unwrap(),
            ],
        );
        let token = plan["runtime_snapshot_token"].as_str().unwrap();
        let output = rbgp(
            &self.grpc_addr,
            &[
                "--json",
                "config",
                "apply",
                "--from-file",
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
    fn apply_confirmed(&self, confirm_id: &str, timeout_seconds: &str) {
        let plan = rbgp_json(
            &self.grpc_addr,
            &[
                "--json",
                "config",
                "plan",
                "--from-file",
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
        let token = plan["runtime_snapshot_token"]
            .as_str()
            .expect("plan must return a runtime snapshot token");

        let apply_output = rbgp(
            &self.grpc_addr,
            &[
                "--json",
                "config",
                "apply",
                "--from-file",
                self.candidate_path.to_str().unwrap(),
                "--expected-runtime-snapshot-token",
                token,
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
    assert_eq!(
        rbgp_json(&lab.grpc_addr, &["--json", "config", "history"])["entries"]
            .as_array()
            .map(Vec::len),
        Some(0),
        "oversize boot snapshot must explicitly leave bounded history empty"
    );
    let human_plan = rbgp(
        &lab.grpc_addr,
        &[
            "config",
            "plan",
            "--from-file",
            lab.candidate_path.to_str().unwrap(),
        ],
    );
    assert_eq!(human_plan.status.code(), Some(2));
    let human_stdout = String::from_utf8(human_plan.stdout).unwrap();
    let exposed_token = human_stdout
        .lines()
        .find_map(|line| line.strip_prefix("plan_token: "))
        .expect("streamed plan human output must expose its single-use plan token");
    assert!(!exposed_token.is_empty());
    lab.apply_confirmed("stream-abort", "600");
    assert!(
        std::fs::metadata(&lab.raw_path).unwrap().len() > 10 * 1024 * 1024,
        "real-binary writer must publish a genuinely normalized prior above 10 MiB"
    );
    let abort = rbgp_json(
        &lab.grpc_addr,
        &["--json", "config", "abort", "stream-abort"],
    );
    assert_eq!(abort["confirmation"]["status"], "aborted", "{abort}");
    assert_eq!(
        rbgp_json(&lab.grpc_addr, &["--json", "config", "history"])["entries"]
            .as_array()
            .map(Vec::len),
        Some(0),
        "oversize candidate and rollback must leave history unchanged"
    );
    let persisted = std::fs::read_to_string(&lab.config_path).unwrap();
    assert!(
        !persisted.contains("192.0.2.0/24"),
        "abort must restore the pre-transaction config"
    );
    lab.assert_no_v3_authority("abort must consume v3 authority");
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
            "--from-file",
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
            "--from-file",
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
    lab.apply_confirmed("kill-window", "600");
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
    lab.apply_confirmed("kill-confirmed", "600");
    let confirm = rbgp_json(
        &lab.grpc_addr,
        &["--json", "config", "confirm", "kill-confirmed"],
    );
    assert_eq!(confirm["confirmation"]["status"], "confirmed", "{confirm}");
    lab.assert_no_v3_authority("confirm must consume v3 authority");
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
    lab.apply_confirmed("timeout-revert", "2");

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
    let on_disk = std::fs::read_to_string(&lab.config_path).unwrap();
    assert!(
        !on_disk.contains("192.0.2.0/24"),
        "auto-revert must restore the pre-transaction config:\n{on_disk}"
    );
    daemon.assert_still_running();
}

#[test]
fn real_binary_boot_dispatches_v2_authority_before_candidate_load() {
    // Destructive proof: deleting or reordering main's v3-then-v2 fallback
    // boots the dynamic-neighbor candidate instead of restoring this prior.
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
    let mut daemon = lab.spawn("revert.stderr.log");
    assert!(!lab.locator_path.exists() && !lab.journal_path.exists());
    assert!(
        !std::fs::read_to_string(&lab.config_path)
            .unwrap()
            .contains("192.0.2.0/24")
    );
    let backup = std::fs::read_to_string(lab.dir.join("rustbgpd.toml.unconfirmed")).unwrap();
    assert!(backup.contains("192.0.2.0/24"));
    let ranges = rbgp_json(&lab.grpc_addr, &["--json", "dynamic-neighbor", "list"]);
    assert_eq!(ranges.as_array().map(Vec::len), Some(0));
    assert!(daemon.stderr().contains("upgrade-v2"));
    daemon.assert_still_running();
}

#[test]
fn torn_journal_refuses_boot_naming_both_files() {
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    let lab = lab(temp.path());
    // Causal destructive-red proof for the retained compatibility lane: if
    // locator absence stops dispatching v1, this truncated legacy journal no
    // longer produces the exact fail-closed refusal below.
    // Truncated mid-JSON, as a crash during a non-atomic write would leave.
    std::fs::write(&lab.journal_path, "{\"confirm_id\": \"deploy-1\", \"dead")
        .expect("failed to write torn journal");

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
        &*lab.config_path.to_string_lossy(),
    ] {
        assert!(
            stderr.contains(needle),
            "refusal must mention {needle:?}:\n{stderr}"
        );
    }
    // Fail closed: nothing touched.
    assert!(lab.journal_path.exists());
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
            "--from-file",
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
            "--from-file",
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
