//! ADR-0054 §1 invariant test: route-reflector deployments (empty
//! `[[evpn_instances]]`) MUST NOT instantiate the EVPN Linux dataplane
//! reconciler. No netlink socket is opened, no background task is
//! spawned.
//!
//! The test boots the real `rustbgpd` binary with a minimal config
//! that has no `[[evpn_instances]]` entries, waits for the daemon to
//! finish startup (proxied by waiting for the gRPC socket to accept
//! connections, the same shape as `evpn_instances_binary.rs`), then
//! reads the daemon's structured-JSON stderr log for the marker line
//! the supervisor emits when it short-circuits on an empty instance
//! table.
//!
//! When the line shape changes, this test changes alongside it. That's
//! the trade-off for asserting on a log message — a more robust
//! assertion would require a metrics surface for "dataplane actor
//! spawned: yes/no", which is queued under Phase 6's gRPC status
//! work.

use std::fs::File;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Daemon {
    child: Child,
    stderr_path: PathBuf,
    stdout_path: PathBuf,
}

impl Daemon {
    fn spawn(config_path: &Path, stderr_path: PathBuf, stdout_path: PathBuf) -> Self {
        let stderr = File::create(&stderr_path).expect("failed to create daemon stderr log");
        let stdout = File::create(&stdout_path).expect("failed to create daemon stdout log");
        let child = Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
            .arg(config_path)
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("failed to spawn rustbgpd binary");
        Self {
            child,
            stderr_path,
            stdout_path,
        }
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

    fn stdout(&self) -> String {
        std::fs::read_to_string(&self.stdout_path).unwrap_or_else(|e| {
            format!(
                "<failed to read daemon stdout {}: {e}>",
                self.stdout_path.display()
            )
        })
    }

    fn structured_logs(&self) -> String {
        // The rustbgpd binary's tracing subscriber writes JSON-formatted
        // logs to stdout (tracing_subscriber::fmt::Subscriber default).
        // Console banner goes to stderr. We need the structured logs
        // for the supervisor's "no EVPN instances configured" line.
        format!(
            "--- stdout (structured logs) ---\n{}\n--- stderr (banner) ---\n{}",
            self.stdout(),
            self.stderr()
        )
    }

    fn shutdown(mut self, grpc_addr: &str) {
        let _ = rbgp(
            grpc_addr,
            &["shutdown", "--reason", "rr-only invariant test"],
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(_status)) => return,
                Ok(None) => thread::sleep(Duration::from_millis(50)),
                Err(_) => break,
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
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

fn wait_for_health(grpc_addr: &str, daemon: &mut Daemon) {
    // Same shape as `evpn_instances_binary.rs::wait_for_cli_json`:
    // poll an idempotent CLI command until it returns success, then
    // we know the gRPC server is up. `evpn instances` is a read-only
    // RPC that works whether or not [[evpn_instances]] is configured
    // (returns an empty list when none).
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        let out = rbgp(grpc_addr, &["--json", "evpn", "instances"]);
        if out.status.success() {
            return;
        }
        daemon.assert_still_running();
        thread::sleep(Duration::from_millis(150));
    }
    panic!(
        "daemon never became reachable on {grpc_addr}\ndaemon stderr:\n{}",
        daemon.stderr()
    );
}

fn write_config(dir: &Path) -> PathBuf {
    let runtime_dir = dir.join("runtime");
    std::fs::create_dir_all(&runtime_dir).expect("failed to create runtime dir");
    let config_path = dir.join("rustbgpd.toml");
    let config = format!(
        r#"
[security.grpc]
enforcement = "tier"

[security.grpc.roles]
"rustbgpd://operator/evpn-rr-test" = "operator"

[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 0
runtime_state_dir = "{runtime_dir}"

[global.telemetry]
log_format = "json"

[global.telemetry.grpc_uds]
path = "{runtime_dir}/grpc.sock"
principal = "rustbgpd://operator/evpn-rr-test"
"#,
        runtime_dir = runtime_dir.display()
    );
    let parsed: toml::Value = toml::from_str(&config).expect("test config must parse");
    let principal = "rustbgpd://operator/evpn-rr-test";
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
    std::fs::write(&config_path, config).expect("failed to write test config");
    config_path
}

#[test]
fn rr_only_deployment_does_not_spawn_evpn_dataplane_actor() {
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))
        .expect("make temp dir private");
    let config_path = write_config(temp.path());
    let grpc_sock = temp.path().join("runtime").join("grpc.sock");
    let grpc_addr = format!("unix://{}", grpc_sock.display());
    let stderr_path = temp.path().join("rustbgpd.stderr.log");
    let stdout_path = temp.path().join("rustbgpd.stdout.log");

    let mut daemon = Daemon::spawn(&config_path, stderr_path, stdout_path);
    wait_for_health(&grpc_addr, &mut daemon);
    daemon.assert_still_running();

    // The supervisor logs at INFO level when EVPN L2 instances,
    // IP-VRFs, and managed netdevs are all empty. JSON-mode telemetry
    // emits one line per record; we look for the marker substring
    // rather than parsing each record so the assertion stays resilient
    // to surrounding fields.
    let logs = daemon.structured_logs();
    assert!(
        logs.contains("no EVPN L2 instances, IP-VRFs, or managed netdevs configured"),
        "expected the RR-only short-circuit log line in daemon logs, \
         but got:\n{logs}"
    );

    // And conversely, the supervisor's "EVPN dataplane reconcile applied"
    // / "EVPN dataplane apply failures" logs must not appear — they're
    // only emitted from the spawned actor's report logger task.
    assert!(
        !logs.contains("EVPN dataplane reconcile applied")
            && !logs.contains("EVPN dataplane apply failures"),
        "expected NO dataplane-actor activity logs in RR-only daemon, \
         but got:\n{logs}"
    );

    daemon.shutdown(&grpc_addr);
}
