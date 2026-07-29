//! Exit-code contract for daemon shutdown causes.
//!
//! Operator-initiated shutdown (SIGTERM) exits 0; a component failure
//! exits non-zero, so supervisors like systemd with `Restart=on-failure`
//! restart the daemon instead of treating it as a clean stop. Three
//! component failures are covered, all provoked by holding the port the
//! daemon needs: the gRPC server exiting unexpectedly, the BGP listener
//! failing to bind, and the metrics/readiness listener failing to bind.

use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Daemon {
    child: Child,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

impl Daemon {
    fn logs(&self) -> String {
        let read = |path: &Path| {
            std::fs::read_to_string(path)
                .unwrap_or_else(|e| format!("<failed to read {}: {e}>", path.display()))
        };
        format!(
            "stdout:\n{}\nstderr:\n{}",
            read(&self.stdout_path),
            read(&self.stderr_path)
        )
    }

    /// Wait for the daemon to exit within `timeout`.
    fn wait_within(&mut self, timeout: Duration) -> ExitStatus {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(status)) => return status,
                Ok(None) => thread::sleep(Duration::from_millis(100)),
                Err(e) => panic!("failed to poll rustbgpd: {e}"),
            }
        }
        panic!("rustbgpd did not exit within timeout\n{}", self.logs());
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

fn write_config_with_metrics(
    dir: &Path,
    grpc_port: u16,
    bgp_port: u16,
    metrics_port: Option<u16>,
) -> PathBuf {
    let runtime_dir = dir.join("runtime");
    std::fs::create_dir_all(&runtime_dir).expect("create runtime dir");
    let token_path = dir.join("grpc-token");
    std::fs::write(&token_path, "exit-code-test-token\n").expect("write test token");
    let config_path = dir.join("rustbgpd.toml");
    let prometheus_addr = metrics_port
        .map(|port| format!("prometheus_addr = \"127.0.0.1:{port}\""))
        .unwrap_or_default();
    let config = format!(
        r#"
[security.grpc]
enforcement = "tier"

[security.grpc.roles]
"rustbgpd://observer/exit-code-test" = "observer"

[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = {bgp_port}
runtime_state_dir = "{runtime_dir}"

[global.telemetry]
log_format = "json"
{prometheus_addr}

[global.telemetry.grpc_tcp]
address = "127.0.0.1:{grpc_port}"
token_file = "{token_path}"
principal = "rustbgpd://observer/exit-code-test"
"#,
        runtime_dir = runtime_dir.display(),
        token_path = token_path.display()
    );
    std::fs::write(&config_path, config).expect("write test config");
    config_path
}

fn write_config(dir: &Path, grpc_port: u16, bgp_port: u16) -> PathBuf {
    write_config_with_metrics(dir, grpc_port, bgp_port, None)
}

fn spawn_daemon(dir: &Path, config_path: &Path) -> Daemon {
    let stdout_path = dir.join("rustbgpd.stdout.log");
    let stderr_path = dir.join("rustbgpd.stderr.log");
    Daemon {
        child: Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
            .arg(config_path)
            .stdout(Stdio::from(
                std::fs::File::create(&stdout_path).expect("daemon stdout log"),
            ))
            .stderr(Stdio::from(
                std::fs::File::create(&stderr_path).expect("daemon stderr log"),
            ))
            .spawn()
            .expect("spawn rustbgpd"),
        stdout_path,
        stderr_path,
    }
}

/// Grab a free localhost port. Racy in principle, fine for a test.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind 127.0.0.1:0")
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn grpc_bind_failure_exits_nonzero() {
    let temp = tempfile::tempdir().expect("create temp dir");
    // Hold the gRPC port so the daemon's listener bind fails with
    // AddrInUse — the gRPC server task exits, which must shut the
    // daemon down with a non-zero exit code.
    let occupied = TcpListener::bind("127.0.0.1:0").expect("bind occupied port");
    let grpc_port = occupied.local_addr().unwrap().port();
    let config_path = write_config(temp.path(), grpc_port, free_port());

    let mut daemon = spawn_daemon(temp.path(), &config_path);
    let status = daemon.wait_within(Duration::from_secs(120));
    assert_eq!(
        status.code(),
        Some(1),
        "gRPC server failure must exit 1, got {status}\n{}",
        daemon.logs()
    );
}

#[test]
fn metrics_listener_bind_failure_exits_nonzero() {
    let temp = tempfile::tempdir().expect("create temp dir");
    let occupied = TcpListener::bind("127.0.0.1:0").expect("bind occupied metrics port");
    let metrics_port = occupied.local_addr().unwrap().port();
    let config_path =
        write_config_with_metrics(temp.path(), free_port(), free_port(), Some(metrics_port));

    let mut daemon = spawn_daemon(temp.path(), &config_path);
    let status = daemon.wait_within(Duration::from_secs(30));
    let logs = daemon.logs();
    assert!(
        logs.contains("failed to bind configured metrics/readiness listener"),
        "the diagnostic must identify the configured health surface\n{logs}"
    );
    assert!(
        logs.contains(&format!("127.0.0.1:{metrics_port}")),
        "the diagnostic must identify the configured address\n{logs}"
    );
    assert!(
        logs.contains("Address already in use"),
        "the diagnostic must preserve the bind cause\n{logs}"
    );
    assert_eq!(
        status.code(),
        Some(1),
        "metrics/readiness bind failure must exit 1, got {status}\n{logs}"
    );
}

#[test]
fn bgp_listener_bind_failure_exits_nonzero() {
    let temp = tempfile::tempdir().expect("create temp dir");
    // Hold the BGP listen port with a live listener. SO_REUSEADDR lets a
    // new generation rebind over a closed-but-lingering endpoint, never
    // over an active LISTEN, so this bind genuinely fails — and a daemon
    // that cannot accept inbound sessions must exit rather than run deaf.
    let occupied = TcpListener::bind("0.0.0.0:0").expect("bind occupied port");
    let bgp_port = occupied.local_addr().unwrap().port();
    let config_path = write_config(temp.path(), free_port(), bgp_port);

    let mut daemon = spawn_daemon(temp.path(), &config_path);
    let status = daemon.wait_within(Duration::from_secs(120));
    let logs = daemon.logs();
    assert!(
        logs.contains("failed to bind BGP listener"),
        "the daemon must exit for the BGP listener, not some other cause\n{logs}"
    );
    assert_eq!(
        status.code(),
        Some(1),
        "BGP listener bind failure must exit 1, got {status}\n{logs}"
    );
}

#[test]
fn sigterm_exits_zero() {
    let temp = tempfile::tempdir().expect("create temp dir");

    // `free_port()` is bind-then-release, so a parallel workspace test can
    // steal the port before the daemon binds it; the daemon then exits
    // non-zero (the very contract under test). Retry with fresh ports.
    let mut daemon = 'spawned: {
        for attempt in 1..=3 {
            let grpc_port = free_port();
            let config_path = write_config(temp.path(), grpc_port, free_port());
            let mut daemon = spawn_daemon(temp.path(), &config_path);

            // Wait until the gRPC listener is up so SIGTERM lands on a
            // fully started daemon.
            let deadline = Instant::now() + Duration::from_secs(120);
            loop {
                if TcpStream::connect(("127.0.0.1", grpc_port)).is_ok() {
                    break 'spawned daemon;
                }
                if let Ok(Some(status)) = daemon.child.try_wait() {
                    if attempt < 3 {
                        eprintln!(
                            "rustbgpd exited before listening on {grpc_port} \
                             (attempt {attempt}): {status}; retrying with fresh ports"
                        );
                        break;
                    }
                    panic!(
                        "rustbgpd exited before listening on {grpc_port}: {status}\n{}",
                        daemon.logs()
                    );
                }
                assert!(
                    Instant::now() < deadline,
                    "rustbgpd did not listen on {grpc_port} within timeout\n{}",
                    daemon.logs()
                );
                thread::sleep(Duration::from_millis(100));
            }
        }
        unreachable!("spawn retry loop either breaks 'spawned or panics");
    };

    let sigterm = Command::new("kill")
        .args(["-TERM", &daemon.child.id().to_string()])
        .status()
        .expect("send SIGTERM");
    assert!(sigterm.success(), "kill -TERM failed: {sigterm}");

    let status = daemon.wait_within(Duration::from_secs(120));
    assert_eq!(
        status.code(),
        Some(0),
        "SIGTERM must exit 0, got {status}\n{}",
        daemon.logs()
    );
}
