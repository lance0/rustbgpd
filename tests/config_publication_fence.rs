//! A config transaction's publication does not overwrite an operator edit
//! made while the transaction was applying.
//!
//! The debug-build settlement control holds the transaction at its staged
//! commit, after the runtime change and before the rename. The test edits
//! the config file there and then releases the hold. The transaction must
//! fail, compensate its runtime change, and leave the edit on disk.

#![cfg(debug_assertions)]

#[path = "support/mod.rs"]
mod support;

use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const CONTROL_ENV: &str = "RUSTBGPD_TEST_SETTLEMENT_CONTROL_DIR";
const CONTROL_VERSION: &str = "settlement-control-v1";
const CHECKPOINT: &str = "staged_commit_before_publish";
const NONCE: &str = "00000000000000000000000000002901";
const EDIT: &str = "# operator edit made while the transaction applied";

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// Write a control file the way the settlement control expects: owner-only,
/// complete before it is visible.
fn control_write(dir: &Path, name: &str, body: &str) {
    let temporary = dir.join(format!(".{name}.tmp"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .unwrap();
    file.write_all(body.as_bytes()).unwrap();
    file.sync_all().unwrap();
    std::fs::rename(&temporary, dir.join(name)).unwrap();
    File::open(dir).unwrap().sync_all().unwrap();
}

fn rbgp(sock: &str, args: &[&str]) -> Output {
    Command::new(support::rbgp_binary())
        .arg("-s")
        .arg(sock)
        .args(args)
        .output()
        .expect("run rbgp")
}

fn wait_for(what: &str, limit: Duration, daemon: &mut Daemon, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + limit;
    while !done() {
        assert!(
            daemon.0.try_wait().unwrap().is_none(),
            "rustbgpd exited while waiting for {what}"
        );
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn transaction_publication_keeps_an_edit_made_during_the_apply() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    private_dir(root);
    let runtime = root.join("runtime");
    private_dir(&runtime);
    let control = root.join("settlement-control");
    private_dir(&control);
    control_write(
        &control,
        "settings.v1",
        &format!("version={CONTROL_VERSION}\nbudget_ms=60000\ngrace_ms=5000\n"),
    );
    let base = format!(
        r#"[security.grpc]
enforcement = "tier"

[security.grpc.roles]
"rustbgpd://operator/publication-fence" = "operator"

[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 0
listen_addresses = ["127.0.0.2"]
runtime_state_dir = "{runtime}"

[global.telemetry]
log_format = "json"

[global.telemetry.grpc_uds]
path = "{runtime}/grpc.sock"
principal = "rustbgpd://operator/publication-fence"
"#,
        runtime = runtime.display()
    );
    let config = root.join("rustbgpd.toml");
    std::fs::write(&config, &base).unwrap();
    let candidate: PathBuf = root.join("candidate.toml");
    std::fs::write(
        &candidate,
        format!("{base}\n[peer_groups.fenced]\nfamilies = [\"ipv4_unicast\"]\n"),
    )
    .unwrap();

    let log = File::create(root.join("rustbgpd.log")).unwrap();
    let mut daemon = Daemon(
        Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
            .arg(&config)
            .env(CONTROL_ENV, &control)
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap(),
    );
    let sock_path = runtime.join("grpc.sock");
    support::wait_until_grpc_socket_accepts(&sock_path, &mut daemon.0);
    let sock = format!("unix://{}", sock_path.display());

    let plan = rbgp(
        &sock,
        &["--json", "config", "plan", candidate.to_str().unwrap()],
    );
    let plan: serde_json::Value =
        serde_json::from_slice(&plan.stdout).unwrap_or_else(|_| panic!("plan JSON: {plan:?}"));
    assert_eq!(plan["status"], "committable", "{plan}");
    let snapshot = plan["runtime_snapshot_token"].as_str().unwrap().to_string();
    let plan_token = plan["plan_token"].as_str().unwrap().to_string();

    let command =
        format!("version={CONTROL_VERSION}\nnonce={NONCE}\ncheckpoint={CHECKPOINT}\naction=hold\n");
    control_write(&control, "arm.v1", &command);
    let apply = Command::new(support::rbgp_binary())
        .args(["-s", &sock, "config", "apply", candidate.to_str().unwrap()])
        .args(["--expected-runtime-snapshot-token", &snapshot])
        .args(["--plan-token", &plan_token])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // The receipt is the handshake: the transaction holds at its staged
    // commit, with the runtime change applied and nothing published.
    wait_for(
        "the staged-commit hold",
        Duration::from_secs(60),
        &mut daemon,
        || control.join("receipt.v1").exists(),
    );
    let edited = format!("{}\n{EDIT}\n", std::fs::read_to_string(&config).unwrap());
    std::fs::write(&config, &edited).unwrap();
    control_write(&control, "release.v1", &command);

    let output = apply.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let on_disk = std::fs::read_to_string(&config).unwrap();
    assert!(
        on_disk.contains(EDIT),
        "the publication overwrote the operator edit; apply: {output:?}\nconfig:\n{on_disk}"
    );
    assert!(!output.status.success(), "{output:?}");
    assert!(
        stderr.contains("changed on disk after the daemon last read or wrote it"),
        "{stderr}"
    );

    // Compensated: the daemon is up and the runtime holds no trace of the
    // candidate's peer group.
    let group = rbgp(&sock, &["--json", "peer-group", "get", "fenced"]);
    assert!(
        !group.status.success(),
        "the peer group survived: {group:?}"
    );
    let status = rbgp(&sock, &["--json", "config", "status"]);
    assert!(status.status.success(), "{status:?}");
    assert!(daemon.0.try_wait().unwrap().is_none(), "rustbgpd exited");
}
