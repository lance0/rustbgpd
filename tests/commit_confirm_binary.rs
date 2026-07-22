//! Real-binary proof of durable commit-confirm (ADR-0076 Decision 6).
//!
//! Each scenario drives the actual `rustbgpd` binary through `rbgp` over the
//! default runtime-dir UDS listener, then SIGKILLs the daemon to prove the
//! boot-time revert journal closes the "confirmed-by-restart" hole:
//!
//! - unconfirmed window + SIGKILL → restart boots the PREVIOUS config, saves
//!   the unconfirmed candidate aside, consumes the journal, and prints the
//!   loud banner;
//! - confirm + SIGKILL → the new config is retained and no journal remains;
//! - in-process timeout auto-revert → the journal is consumed;
//! - torn journal on disk → boot refuses, naming both files.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const JOURNAL_FILE_NAME: &str = "commit-confirm-journal.json";

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
    let runtime_dir = dir.join("runtime");
    std::fs::create_dir_all(&runtime_dir).expect("failed to create runtime dir");
    let config_path = dir.join("rustbgpd.toml");
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
        grpc_addr: format!("unix://{}", runtime_dir.join("grpc.sock").display()),
        dir: dir.to_path_buf(),
    }
}

impl Lab {
    fn spawn(&self, stderr_name: &str) -> Daemon {
        let mut daemon = Daemon::spawn(&self.config_path, self.dir.join(stderr_name));
        wait_until_serving(&self.grpc_addr, &mut daemon);
        daemon
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
        let token = plan["runtime_snapshot_token"]
            .as_str()
            .expect("plan must return a runtime snapshot token");

        let apply = rbgp_json(
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
            self.journal_path.exists(),
            "confirmed apply must write the revert journal"
        );
    }
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
    assert!(
        !lab.journal_path.exists(),
        "boot revert must consume the journal"
    );
    let stderr = daemon.stderr();
    assert!(
        stderr.contains("commit-confirm boot revert")
            && stderr.contains("kill-window")
            && stderr.contains("rustbgpd.toml.unconfirmed"),
        "boot banner must name the transaction and the saved-aside file:\n{stderr}"
    );

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
    assert!(
        !lab.journal_path.exists(),
        "confirm must consume the revert journal"
    );
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

    assert!(
        !lab.journal_path.exists(),
        "timeout auto-revert must consume the revert journal"
    );
    let on_disk = std::fs::read_to_string(&lab.config_path).unwrap();
    assert!(
        !on_disk.contains("192.0.2.0/24"),
        "auto-revert must restore the pre-transaction config:\n{on_disk}"
    );
    daemon.assert_still_running();
}

#[test]
fn torn_journal_refuses_boot_naming_both_files() {
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    let lab = lab(temp.path());
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

#[test]
fn history_and_rollback_restore_previous_config_across_restart() {
    // End-to-end quartet proof over the real binary: apply a config, restart
    // the daemon (history must survive and not grow via dedup), then
    // `config rollback 1` must restore the pre-apply config — proven on the
    // on-disk config AND the daemon's runtime state, not just the receipt.
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    let lab = lab(temp.path());

    let daemon = lab.spawn("first.stderr.log");
    // Plain (unconfirmed) apply of the dynamic-neighbor candidate.
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
    assert_ne!(
        entries[0]["sha256"], entries[1]["sha256"],
        "distinct configs must have distinct hashes: {history}"
    );
    let boot_hash = entries[1]["sha256"].as_str().unwrap().to_string();

    // Restart: history survives on disk, and the boot-time re-record of the
    // unchanged running config deduplicates instead of growing history.
    daemon.sigkill();
    let mut daemon = lab.spawn("second.stderr.log");
    let history = rbgp_json(&lab.grpc_addr, &["--json", "config", "history"]);
    assert_eq!(
        history["entries"].as_array().map(Vec::len),
        Some(2),
        "history must survive a restart without duplicate boot entries: {history}"
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
    assert!(
        std::fs::read_to_string(&lab.config_path)
            .unwrap()
            .contains("192.0.2.0/24"),
        "failed rollback must not touch the config"
    );

    // rollback 1 restores the pre-apply (boot) config through the
    // transaction path.
    let rollback = rbgp_json(&lab.grpc_addr, &["--json", "config", "rollback", "1"]);
    assert_eq!(rollback["status"], "committable", "rollback: {rollback}");
    // MUTATION PROOF (disk): the candidate's dynamic-neighbor range is gone
    // from the persisted config.
    let on_disk = std::fs::read_to_string(&lab.config_path).unwrap();
    assert!(
        !on_disk.contains("192.0.2.0/24"),
        "rollback must restore the pre-apply config on disk:\n{on_disk}"
    );
    // MUTATION PROOF (runtime): the daemon no longer runs the candidate's
    // dynamic-neighbor range.
    let ranges = rbgp_json(&lab.grpc_addr, &["--json", "dynamic-neighbor", "list"]);
    assert_eq!(
        ranges.as_array().map(Vec::len),
        Some(0),
        "rolled-back daemon must not run the candidate's dynamic neighbors: {ranges}"
    );
    // The rollback commit is itself recorded as the newest history entry,
    // with the boot config's content hash.
    let history = rbgp_json(&lab.grpc_addr, &["--json", "config", "history"]);
    let entries = history["entries"].as_array().expect("entries array");
    assert_eq!(
        entries.len(),
        3,
        "rollback commit is a new entry: {history}"
    );
    assert_eq!(
        entries[0]["sha256"].as_str().unwrap(),
        boot_hash,
        "newest entry must be the restored boot config: {history}"
    );
    daemon.assert_still_running();
}
