//! Real-daemon proof for typed config-publication failures.

use std::fs::File;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

const FIRST_NEIGHBOR: &str = "192.0.2.1";
const SECOND_NEIGHBOR: &str = "192.0.2.2";
const FAILSTOP_GRACE_WITH_JITTER: Duration = Duration::from_secs(7);

struct Daemon {
    child: Child,
    log_path: PathBuf,
}

impl Daemon {
    fn spawn(config: &Path, log_path: PathBuf, fault: Option<&str>) -> Self {
        Self::spawn_with_fault(
            config,
            log_path,
            fault.map(|value| ("RUSTBGPD_TEST_CONFIG_PUBLISH_FAILURE", value)),
        )
    }

    fn spawn_with_fault(config: &Path, log_path: PathBuf, fault: Option<(&str, &str)>) -> Self {
        let stderr = File::create(&log_path).expect("create daemon log");
        let stdout = stderr.try_clone().expect("clone daemon log handle");
        let mut command = Command::new(env!("CARGO_BIN_EXE_rustbgpd"));
        command
            .arg(config)
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        if let Some((name, value)) = fault {
            command.env(name, value);
        }
        let child = command.spawn().expect("spawn rustbgpd");
        Self { child, log_path }
    }

    fn assert_running(&mut self) {
        if let Some(status) = self.child.try_wait().expect("query daemon status") {
            panic!("rustbgpd exited early with {status}\nlog:\n{}", self.log());
        }
    }

    fn wait_for_exit(&mut self, timeout: Duration) -> ExitStatus {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().expect("query daemon status") {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "daemon did not exit\n{}",
                self.log()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }

    fn sighup(&self) {
        let pid = i32::try_from(self.child.id()).expect("daemon PID fits i32");
        kill(Pid::from_raw(pid), Signal::SIGHUP).expect("send SIGHUP");
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

fn rbgp_command(grpc_addr: &str, args: &[&str]) -> Command {
    let mut command = if let Ok(path) = std::env::var("CARGO_BIN_EXE_rbgp") {
        Command::new(path)
    } else {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
        let mut command = Command::new(cargo);
        command.args(["run", "--quiet", "-p", "rustbgpctl", "--bin", "rbgp", "--"]);
        command
    };
    command.arg("--addr").arg(grpc_addr).args(args);
    command
}

fn rbgp(grpc_addr: &str, args: &[&str]) -> Output {
    rbgp_command(grpc_addr, args).output().expect("run rbgp")
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
        daemon.assert_running();
        thread::sleep(Duration::from_millis(50));
    }
    panic!("daemon never served gRPC\n{}", daemon.log());
}

fn unused_loopback_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .expect("reserve loopback port")
        .local_addr()
        .expect("read loopback port")
}

fn http_get(addr: SocketAddr, path: &str) -> Option<String> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(100)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .ok()?;
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    Some(response)
}

fn ready_status(addr: SocketAddr) -> Option<u16> {
    http_get(addr, "/readyz")?
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn settlement_metrics(addr: SocketAddr) -> String {
    http_get(addr, "/metrics")
        .and_then(|response| {
            response
                .split_once("\r\n\r\n")
                .map(|(_, body)| body.to_string())
        })
        .expect("scrape settlement metrics")
}

fn assert_settlement_metrics(text: &str, kind: &str, phase: &str, attachment: &str, reason: &str) {
    for (name, value) in [
        ("bgp_runtime_config_settlement_active", "1"),
        ("bgp_runtime_config_settlement_elapsed_seconds", ""),
        ("bgp_runtime_config_settlement_budget_seconds", "1800"),
        ("bgp_runtime_config_settlement_fail_stops_total", "1"),
    ] {
        let lines = text
            .lines()
            .filter(|line| line.starts_with(&format!("{name}{{")))
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 1, "expected one {name} tuple:\n{text}");
        let line = lines[0];
        for label in [
            format!("kind=\"{kind}\""),
            format!("phase=\"{phase}\""),
            format!("response_attached=\"{attachment}\""),
            format!("fence_reason=\"{reason}\""),
        ] {
            assert!(line.contains(&label), "missing {label} in {line}");
        }
        assert!(
            value.is_empty() || line.ends_with(value),
            "unexpected value in {line}"
        );
    }
}

fn assert_one_redacted_diagnostic(daemon: &Daemon) {
    let matching = daemon
        .log()
        .lines()
        .filter(|line| line.contains("runtime config settlement fail-stop armed"))
        .map(str::to_string)
        .collect::<Vec<_>>();
    assert_eq!(matching.len(), 1, "log:\n{}", daemon.log());
    for forbidden in ["injected", "rustbgpd.toml", "grpc.sock", FIRST_NEIGHBOR] {
        assert!(
            !matching[0].contains(forbidden),
            "diagnostic leaked {forbidden}"
        );
    }
}

fn wait_until_ready(addr: SocketAddr, daemon: &mut Daemon, expected: u16) {
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        if ready_status(addr) == Some(expected) {
            return;
        }
        daemon.assert_running();
        thread::sleep(Duration::from_millis(20));
    }
    panic!(
        "daemon never reported readiness {expected}\n{}",
        daemon.log()
    );
}

fn wait_output(mut child: Child, timeout: Duration) -> Output {
    let deadline = Instant::now() + timeout;
    while child.try_wait().expect("query rbgp status").is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("rbgp did not finish before fail-stop deadline");
        }
        thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output().expect("collect rbgp output")
}

fn config(runtime_dir: &Path, metrics: SocketAddr) -> String {
    format!(
        r#"
[security.grpc]
enforcement = "tier"

[security.grpc.roles]
"rustbgpd://operator/persistence-failstop-test" = "operator"

[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 0
runtime_state_dir = "{}"

[global.telemetry]
log_format = "json"
prometheus_addr = "{metrics}"

[global.telemetry.grpc_uds]
path = "{}/grpc.sock"
principal = "rustbgpd://operator/persistence-failstop-test"
"#,
        runtime_dir.display(),
        runtime_dir.display()
    )
}

fn exercise(fault: &str, published: bool) {
    let dir = tempfile::tempdir().expect("create test dir");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let runtime_dir = dir.path().join("runtime");
    std::fs::create_dir(&runtime_dir).unwrap();
    std::fs::set_permissions(&runtime_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let config_path = dir.path().join("rustbgpd.toml");
    let metrics = unused_loopback_addr();
    std::fs::write(&config_path, config(&runtime_dir, metrics)).unwrap();
    let grpc_addr = format!("unix://{}", runtime_dir.join("grpc.sock").display());

    let mut daemon = Daemon::spawn(
        &config_path,
        dir.path().join("fault-daemon.log"),
        Some(fault),
    );
    wait_until_serving(&grpc_addr, &mut daemon);
    wait_until_ready(metrics, &mut daemon, 200);

    let first = rbgp_command(
        &grpc_addr,
        &["neighbor", FIRST_NEIGHBOR, "add", "--remote-asn", "65002"],
    )
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .expect("start first mutation");
    wait_until_ready(metrics, &mut daemon, 503);
    let recovery_fenced_at = Instant::now();
    assert_settlement_metrics(
        &settlement_metrics(metrics),
        "neighbor_add",
        "settling_rollback",
        "attached",
        if fault == "not_published" {
            "known_divergence"
        } else {
            "publication_ambiguous"
        },
    );

    let second = rbgp_command(
        &grpc_addr,
        &["neighbor", SECOND_NEIGHBOR, "add", "--remote-asn", "65003"],
    )
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .expect("start rejected mutation");

    let second = wait_output(second, Duration::from_secs(2));
    assert!(
        !second.status.success(),
        "second mutation unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr)
    );
    daemon.assert_running();

    let status = daemon
        .wait_for_exit(FAILSTOP_GRACE_WITH_JITTER.saturating_sub(recovery_fenced_at.elapsed()));
    assert_eq!(status.code(), Some(70), "log:\n{}", daemon.log());
    assert_one_redacted_diagnostic(&daemon);
    assert!(
        recovery_fenced_at.elapsed() <= FAILSTOP_GRACE_WITH_JITTER,
        "exit 70 exceeded the five-second grace plus test jitter"
    );
    assert!(!wait_output(first, Duration::from_secs(2)).status.success());

    let bytes = std::fs::read(&config_path).expect("read persisted config");
    assert!(!bytes.is_empty(), "published config must never be empty");
    let parsed: toml::Value = toml::from_slice(&bytes).expect("persisted config must parse");
    let neighbors = parsed
        .get("neighbors")
        .and_then(toml::Value::as_array)
        .map_or(0, Vec::len);
    assert_eq!(neighbors, usize::from(published));
    let text = String::from_utf8(bytes).unwrap();
    assert_eq!(text.contains(FIRST_NEIGHBOR), published);
    assert!(!text.contains(SECOND_NEIGHBOR));
    assert!(!config_path.with_extension("toml.tmp").exists());

    let mut restarted = Daemon::spawn(&config_path, dir.path().join("restart-daemon.log"), None);
    wait_until_serving(&grpc_addr, &mut restarted);
    let first_state = rbgp(&grpc_addr, &["--json", "neighbor", FIRST_NEIGHBOR]);
    assert_eq!(first_state.status.success(), published);
    let second_state = rbgp(&grpc_addr, &["--json", "neighbor", SECOND_NEIGHBOR]);
    assert!(!second_state.status.success());
}

#[test]
fn pre_rename_failure_fences_and_restart_loads_prior_config() {
    exercise("not_published", false);
}

#[test]
fn post_rename_failure_fences_and_restart_loads_complete_candidate() {
    exercise("publication_ambiguous", true);
}

fn exercise_sighup_ack_loss(fault: &str) {
    let dir = tempfile::tempdir().expect("create test dir");
    let runtime_dir = dir.path().join("runtime");
    std::fs::create_dir(&runtime_dir).unwrap();
    let config_path = dir.path().join("rustbgpd.toml");
    let metrics = unused_loopback_addr();
    let initial = config(&runtime_dir, metrics);
    std::fs::write(&config_path, &initial).unwrap();
    let grpc_addr = format!("unix://{}", runtime_dir.join("grpc.sock").display());
    let mut daemon = Daemon::spawn_with_fault(
        &config_path,
        dir.path().join("sighup-fault-daemon.log"),
        Some(("RUSTBGPD_TEST_SIGHUP_ACK_LOSS", fault)),
    );
    wait_until_serving(&grpc_addr, &mut daemon);
    wait_until_ready(metrics, &mut daemon, 200);

    std::fs::write(
        &config_path,
        format!("{initial}\n[[neighbors]]\naddress = \"{FIRST_NEIGHBOR}\"\nremote_asn = 65002\n"),
    )
    .unwrap();
    daemon.sighup();
    wait_until_ready(metrics, &mut daemon, 503);
    let fenced_at = Instant::now();
    assert_settlement_metrics(
        &settlement_metrics(metrics),
        "sighup",
        if fault == "reconcile" {
            "mutating"
        } else {
            "settling_rollback"
        },
        "detached",
        "acknowledgement_lost",
    );
    let rejected = rbgp(
        &grpc_addr,
        &["neighbor", SECOND_NEIGHBOR, "add", "--remote-asn", "65003"],
    );
    assert!(!rejected.status.success());
    daemon.assert_running();
    let status =
        daemon.wait_for_exit(FAILSTOP_GRACE_WITH_JITTER.saturating_sub(fenced_at.elapsed()));
    assert_eq!(status.code(), Some(70), "log:\n{}", daemon.log());
    assert_one_redacted_diagnostic(&daemon);
}

#[test]
fn sighup_reconcile_ack_loss_fences_and_exits_once() {
    exercise_sighup_ack_loss("reconcile");
}

#[test]
fn sighup_bridge_persister_ack_loss_fences_and_exits_once() {
    exercise_sighup_ack_loss("bridge");
}
