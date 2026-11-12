//! Real-daemon proof that a SIGHUP received during a reload is coalesced into
//! one follow-up reload that re-reads the config file, and that `rbgp reload`
//! waits for the reload that read the file after its signal.

mod support;

use std::fs::File;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

use support::{RetainOnPanic, bound_metrics_addr, rbgp_binary};

const FIRST_NEIGHBOR: &str = "192.0.2.1";
const SECOND_NEIGHBOR: &str = "192.0.2.2";
const WAIT: Duration = Duration::from_secs(30);

struct Daemon {
    child: Child,
    log_path: PathBuf,
    read_hold: Option<UnixListener>,
}

impl Daemon {
    fn spawn(config: &Path, log_path: PathBuf, hold: bool) -> Self {
        let stderr = File::create(&log_path).expect("create daemon log");
        let stdout = stderr.try_clone().expect("clone daemon log handle");
        let mut command = Command::new(env!("CARGO_BIN_EXE_rustbgpd"));
        command
            .arg(config)
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .env_remove("RUSTBGPD_TEST_SIGHUP_READ_HOLD");
        let read_hold = hold.then(|| {
            let path = log_path.with_extension("hold.sock");
            let listener = UnixListener::bind(&path).expect("bind SIGHUP read hold");
            listener
                .set_nonblocking(true)
                .expect("poll SIGHUP read hold");
            command.env("RUSTBGPD_TEST_SIGHUP_READ_HOLD", path);
            listener
        });
        Self {
            child: command.spawn().expect("spawn rustbgpd"),
            log_path,
            read_hold,
        }
    }

    /// Accept the next reload parked after its config-file read.
    fn wait_for_read_hold(&mut self) -> UnixStream {
        let deadline = Instant::now() + WAIT;
        let mut hold = loop {
            match self.read_hold.as_ref().unwrap().accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("accept SIGHUP read hold: {error}"),
            }
            self.assert_running();
            assert!(
                Instant::now() < deadline,
                "no reload reached the config-read hold\n{}",
                self.log()
            );
            thread::sleep(Duration::from_millis(20));
        };
        hold.set_nonblocking(false).unwrap();
        hold.set_read_timeout(Some(WAIT)).unwrap();
        let mut marker = [0];
        hold.read_exact(&mut marker)
            .expect("read SIGHUP read marker");
        assert_eq!(marker, [1]);
        hold
    }

    fn assert_no_parked_reload(&self) {
        match self.read_hold.as_ref().unwrap().accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Ok(_) => panic!(
                "an extra reload reached the config-read hold\n{}",
                self.log()
            ),
            Err(error) => panic!("accept SIGHUP read hold: {error}"),
        }
    }

    fn assert_running(&mut self) {
        if let Some(status) = self.child.try_wait().expect("query daemon status") {
            panic!("rustbgpd exited early with {status}\nlog:\n{}", self.log());
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
    let mut command = Command::new(rbgp_binary());
    command
        .arg("--addr")
        .arg(grpc_addr)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn rbgp(grpc_addr: &str, args: &[&str]) -> Output {
    rbgp_command(grpc_addr, args).output().expect("run rbgp")
}

fn wait_until_serving(grpc_addr: &str, daemon: &mut Daemon) {
    let deadline = Instant::now() + WAIT;
    while !rbgp(grpc_addr, &["--json", "config", "status"])
        .status
        .success()
    {
        daemon.assert_running();
        assert!(
            Instant::now() < deadline,
            "daemon never served gRPC\n{}",
            daemon.log()
        );
        thread::sleep(Duration::from_millis(50));
    }
}

fn metrics_addr(daemon: &mut Daemon) -> SocketAddr {
    let deadline = Instant::now() + WAIT;
    loop {
        if let Some(addr) = bound_metrics_addr(&daemon.log()) {
            return addr;
        }
        daemon.assert_running();
        assert!(
            Instant::now() < deadline,
            "daemon did not report its metrics endpoint\n{}",
            daemon.log()
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn http_get(addr: SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(1)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

fn wait_until_ready(daemon: &mut Daemon, addr: SocketAddr) {
    let deadline = Instant::now() + WAIT;
    while !http_get(addr, "/readyz").starts_with("HTTP/1.1 200") {
        daemon.assert_running();
        assert!(
            Instant::now() < deadline,
            "daemon never became ready\n{}",
            daemon.log()
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn reload_outcome_count(addr: SocketAddr, outcome: &str) -> u64 {
    let response = http_get(addr, "/metrics");
    let series = format!("bgp_sighup_reload_outcomes_total{{outcome=\"{outcome}\"}} ");
    response
        .lines()
        .find_map(|line| line.strip_prefix(&series))
        .unwrap_or_else(|| panic!("missing {series}"))
        .trim()
        .parse()
        .unwrap()
}

/// Wait on the counter itself: each signal is observed before the next step.
fn wait_for_outcome_count(daemon: &mut Daemon, addr: SocketAddr, outcome: &str, count: u64) {
    let deadline = Instant::now() + WAIT;
    loop {
        let current = reload_outcome_count(addr, outcome);
        assert!(current <= count, "{outcome} passed {count}: {current}");
        if current == count {
            return;
        }
        daemon.assert_running();
        assert!(
            Instant::now() < deadline,
            "{outcome} never reached {count}\n{}",
            daemon.log()
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn base_config(runtime_dir: &Path) -> String {
    format!(
        r#"
[security.grpc]
enforcement = "tier"

[security.grpc.roles]
"rustbgpd://operator/sighup-coalescing-test" = "operator"

[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 0
runtime_state_dir = "{0}"

[global.telemetry]
log_format = "json"
prometheus_addr = "127.0.0.1:0"

[global.telemetry.grpc_uds]
path = "{0}/grpc.sock"
principal = "rustbgpd://operator/sighup-coalescing-test"
"#,
        runtime_dir.display(),
    )
}

fn with_neighbors(base: &str, neighbors: &[&str]) -> String {
    let mut config = base.to_string();
    for (index, address) in neighbors.iter().enumerate() {
        config.push_str(&format!(
            "\n[[neighbors]]\naddress = \"{address}\"\nremote_asn = {}\n",
            65002 + index
        ));
    }
    config
}

struct Fixture {
    _dir: RetainOnPanic,
    config_path: PathBuf,
    base: String,
    grpc_addr: String,
    daemon: Daemon,
    metrics: SocketAddr,
}

fn start(hold: bool) -> Fixture {
    let dir = RetainOnPanic::new(tempfile::tempdir().expect("create test dir"));
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let runtime_dir = dir.path().join("runtime");
    std::fs::create_dir(&runtime_dir).unwrap();
    std::fs::set_permissions(&runtime_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let config_path = dir.path().join("rustbgpd.toml");
    let base = base_config(&runtime_dir);
    std::fs::write(&config_path, &base).unwrap();
    let grpc_addr = format!("unix://{}", runtime_dir.join("grpc.sock").display());
    let mut daemon = Daemon::spawn(&config_path, dir.path().join("daemon.log"), hold);
    wait_until_serving(&grpc_addr, &mut daemon);
    let metrics = metrics_addr(&mut daemon);
    wait_until_ready(&mut daemon, metrics);
    Fixture {
        _dir: dir,
        config_path,
        base,
        grpc_addr,
        daemon,
        metrics,
    }
}

fn neighbor_exists(grpc_addr: &str, address: &str) -> bool {
    rbgp(grpc_addr, &["--json", "neighbor", address])
        .status
        .success()
}

/// Reload 1 parks after reading `first`; `extra` further signals arrive
/// during it (the first through `rbgp reload` when `via_rbgp`), then the
/// second edit is written and reload 1 released.
fn exercise(first_valid: bool, extra: u64, via_rbgp: bool) {
    let mut fixture = start(true);
    let first = if first_valid {
        with_neighbors(&fixture.base, &[FIRST_NEIGHBOR])
    } else {
        format!("{}\n[[neighbors]\n", fixture.base)
    };
    std::fs::write(&fixture.config_path, first).unwrap();
    fixture.daemon.sighup();
    let mut reload_one = fixture.daemon.wait_for_read_hold();

    let mut waiter = None;
    for count in 1..=extra {
        if via_rbgp && count == 1 {
            waiter = Some(
                rbgp_command(&fixture.grpc_addr, &["--json", "reload", "--timeout", "60"])
                    .spawn()
                    .expect("start rbgp reload"),
            );
        } else {
            fixture.daemon.sighup();
        }
        wait_for_outcome_count(&mut fixture.daemon, fixture.metrics, "coalesced", count);
    }
    // Written after reload 1 read the file: only a follow-up can apply it.
    std::fs::write(
        &fixture.config_path,
        with_neighbors(&fixture.base, &[FIRST_NEIGHBOR, SECOND_NEIGHBOR]),
    )
    .unwrap();
    reload_one.write_all(&[1]).expect("release reload 1");
    let first_outcome = if first_valid {
        "complete"
    } else {
        "rejected_no_effect"
    };
    wait_for_outcome_count(&mut fixture.daemon, fixture.metrics, first_outcome, 1);

    let mut follow_up = fixture.daemon.wait_for_read_hold();
    if let Some(waiter) = waiter.as_mut() {
        // Reload 1 has settled and the follow-up is parked, so rbgp reload has
        // nothing to return yet. A negative check needs an observation window:
        // rbgp polls every 100 ms, so this gives it several polls in which it
        // could wrongly return reload 1's record, which predates its signal.
        thread::sleep(Duration::from_millis(500));
        assert!(
            waiter.try_wait().unwrap().is_none(),
            "rbgp reload returned on the reload that predates its signal"
        );
    }
    follow_up.write_all(&[1]).expect("release follow-up reload");
    let expected_complete = if first_valid { 2 } else { 1 };
    wait_for_outcome_count(
        &mut fixture.daemon,
        fixture.metrics,
        "complete",
        expected_complete,
    );

    assert!(neighbor_exists(&fixture.grpc_addr, SECOND_NEIGHBOR));
    assert_eq!(reload_outcome_count(fixture.metrics, "coalesced"), extra);
    assert_eq!(
        reload_outcome_count(fixture.metrics, "rejected_no_effect"),
        u64::from(!first_valid)
    );
    fixture.daemon.assert_no_parked_reload();
    if let Some(waiter) = waiter {
        let output = waiter.wait_with_output().expect("collect rbgp reload");
        assert!(
            output.status.success(),
            "rbgp reload failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let receipt: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(receipt["record"]["outcome"], "complete");
    }
}

#[test]
fn sighup_during_a_reload_runs_one_follow_up_that_reads_the_later_edit() {
    exercise(true, 1, false);
}

#[test]
fn several_sighups_during_one_reload_fold_into_one_follow_up() {
    exercise(true, 3, false);
}

#[test]
fn follow_up_runs_after_a_rejected_reload_and_rbgp_reload_waits_for_it() {
    exercise(false, 1, true);
}

#[test]
fn rbgp_reload_exit_code_follows_the_settled_outcome() {
    let fixture = start(false);
    std::fs::write(
        &fixture.config_path,
        format!("{}\n[[neighbors]\n", fixture.base),
    )
    .unwrap();
    let rejected = rbgp(&fixture.grpc_addr, &["--json", "reload"]);
    assert_eq!(
        rejected.status.code(),
        Some(3),
        "stderr:\n{}",
        String::from_utf8_lossy(&rejected.stderr)
    );
    let receipt: serde_json::Value = serde_json::from_slice(&rejected.stdout).unwrap();
    assert_eq!(receipt["record"]["outcome"], "rejected_no_effect");

    std::fs::write(
        &fixture.config_path,
        with_neighbors(&fixture.base, &[FIRST_NEIGHBOR]),
    )
    .unwrap();
    let applied = rbgp(&fixture.grpc_addr, &["reload"]);
    assert!(
        applied.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&applied.stderr)
    );
    assert!(String::from_utf8_lossy(&applied.stdout).starts_with("Last SIGHUP: complete"));
    assert!(neighbor_exists(&fixture.grpc_addr, FIRST_NEIGHBOR));
}
