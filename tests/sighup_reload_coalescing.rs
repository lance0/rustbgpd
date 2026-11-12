//! Real-daemon proof that a SIGHUP received during a reload is coalesced into
//! one follow-up reload that re-reads the config file, that shutdown drops a
//! pending follow-up, and that `rbgp reload` waits for the reload that read
//! the file after its signal.

mod support;

use std::fs::File;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

use support::{RetainOnPanic, bound_metrics_addr, rbgp_binary};

const FIRST_NEIGHBOR: &str = "192.0.2.1";
const SECOND_NEIGHBOR: &str = "192.0.2.2";
const WAIT: Duration = Duration::from_secs(30);
const FOLLOW_UP_STARTED: &str = "starting the follow-up reload";
const FOLLOW_UP_DROPPED: &str = "shutdown dropped the pending follow-up SIGHUP reload";

/// Debug-build seams in the daemon; each parks until the test sends a byte.
#[derive(Clone, Copy)]
enum Hold {
    /// A reload has read the config file.
    Read,
    /// The signal loop has handled a reload's settlement.
    Settled,
}

struct Daemon {
    child: Child,
    log_path: PathBuf,
    read_hold: Option<UnixListener>,
    settled_hold: Option<UnixListener>,
}

impl Daemon {
    fn spawn(config: &Path, log_path: PathBuf, holds: bool) -> Self {
        Self::spawn_with_env(config, log_path, holds, &[])
    }

    fn spawn_with_env(config: &Path, log_path: PathBuf, holds: bool, env: &[(&str, &str)]) -> Self {
        let stderr = File::create(&log_path).expect("create daemon log");
        let stdout = stderr.try_clone().expect("clone daemon log handle");
        let mut command = Command::new(env!("CARGO_BIN_EXE_rustbgpd"));
        command
            .arg(config)
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .env_remove("RUSTBGPD_TEST_SIGHUP_READ_HOLD")
            .env_remove("RUSTBGPD_TEST_SIGHUP_SETTLED_HOLD")
            .env_remove("RUSTBGPD_TEST_SIGHUP_BEFORE_RUN")
            .envs(env.iter().copied());
        let mut bind = |variable: &str, extension: &str| {
            holds.then(|| {
                let path = log_path.with_extension(extension);
                let listener = UnixListener::bind(&path).expect("bind SIGHUP test hold");
                listener
                    .set_nonblocking(true)
                    .expect("poll SIGHUP test hold");
                command.env(variable, path);
                listener
            })
        };
        let read_hold = bind("RUSTBGPD_TEST_SIGHUP_READ_HOLD", "read.sock");
        let settled_hold = bind("RUSTBGPD_TEST_SIGHUP_SETTLED_HOLD", "settled.sock");
        Self {
            child: command.spawn().expect("spawn rustbgpd"),
            log_path,
            read_hold,
            settled_hold,
        }
    }

    fn listener(&self, hold: Hold) -> &UnixListener {
        match hold {
            Hold::Read => self.read_hold.as_ref(),
            Hold::Settled => self.settled_hold.as_ref(),
        }
        .expect("daemon spawned with test holds")
    }

    /// Accept the daemon's next arrival at `hold`.
    fn wait_for_hold(&mut self, hold: Hold) -> UnixStream {
        let deadline = Instant::now() + WAIT;
        let mut stream = loop {
            match self.listener(hold).accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("accept SIGHUP test hold: {error}"),
            }
            self.assert_running();
            assert!(
                Instant::now() < deadline,
                "the daemon never reached the test hold\n{}",
                self.log()
            );
            thread::sleep(Duration::from_millis(20));
        };
        stream.set_nonblocking(false).unwrap();
        stream.set_read_timeout(Some(WAIT)).unwrap();
        let mut marker = [0];
        stream
            .read_exact(&mut marker)
            .expect("read test hold marker");
        assert_eq!(marker, [1]);
        stream
    }

    /// Call after exit: a reload that reached the read hold left its
    /// connection in the listener's backlog, so an empty backlog is final.
    fn assert_no_further_reload(&self) {
        match self.listener(Hold::Read).accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Ok(_) => panic!("an extra reload read the config\n{}", self.log()),
            Err(error) => panic!("accept SIGHUP read hold: {error}"),
        }
    }

    fn assert_running(&mut self) {
        if let Some(status) = self.child.try_wait().expect("query daemon status") {
            panic!("rustbgpd exited early with {status}\nlog:\n{}", self.log());
        }
    }

    fn wait_for_exit(&mut self) -> ExitStatus {
        let deadline = Instant::now() + WAIT;
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

    fn log_count(&self, message: &str) -> usize {
        self.log()
            .lines()
            .filter(|line| line.contains(message))
            .count()
    }

    fn signal(&self, signal: Signal) {
        let pid = i32::try_from(self.child.id()).expect("daemon PID fits i32");
        kill(Pid::from_raw(pid), signal).expect("signal rustbgpd");
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

/// The Shutdown RPC sets the daemon's shutdown watch before it answers, so
/// the request is pending for the signal loop's next turn once this returns.
fn request_shutdown(grpc_addr: &str) {
    let output = rbgp(grpc_addr, &["shutdown", "--yes", "--reason", "test"]);
    assert!(
        output.status.success(),
        "rbgp shutdown failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
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
    dir: RetainOnPanic,
    config_path: PathBuf,
    base: String,
    grpc_addr: String,
    daemon: Daemon,
    metrics: SocketAddr,
}

impl Fixture {
    fn start(holds: bool) -> Self {
        Self::start_with_env(holds, &[])
    }

    fn start_with_env(holds: bool, env: &[(&str, &str)]) -> Self {
        let dir = RetainOnPanic::new(tempfile::tempdir().expect("create test dir"));
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let runtime_dir = dir.path().join("runtime");
        std::fs::create_dir(&runtime_dir).unwrap();
        std::fs::set_permissions(&runtime_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let config_path = dir.path().join("rustbgpd.toml");
        let base = base_config(&runtime_dir);
        std::fs::write(&config_path, &base).unwrap();
        let grpc_addr = format!("unix://{}", runtime_dir.join("grpc.sock").display());
        let daemon =
            Daemon::spawn_with_env(&config_path, dir.path().join("daemon.log"), holds, env);
        let mut fixture = Self {
            dir,
            config_path,
            base,
            grpc_addr,
            daemon,
            metrics: SocketAddr::from(([127, 0, 0, 1], 0)),
        };
        fixture.serve();
        fixture
    }

    fn serve(&mut self) {
        wait_until_serving(&self.grpc_addr, &mut self.daemon);
        self.metrics = metrics_addr(&mut self.daemon);
        wait_until_ready(&mut self.daemon, self.metrics);
    }

    fn write(&self, config: &str) {
        std::fs::write(&self.config_path, config).unwrap();
    }
}

fn neighbor_exists(grpc_addr: &str, address: &str) -> bool {
    rbgp(grpc_addr, &["--json", "neighbor", address])
        .status
        .success()
}

/// Reload 1 parks after reading `first`; `extra` further signals arrive
/// during it (the first through `rbgp reload` when `via_rbgp`), then the
/// second edit is written and reload 1 released. Shutdown is requested while
/// the loop is parked after the follow-up settles, so a second follow-up that
/// was wrongly left pending would be dropped and logged instead of hiding.
fn exercise(first_valid: bool, extra: u64, via_rbgp: bool) {
    let mut fixture = Fixture::start(true);
    let first = if first_valid {
        with_neighbors(&fixture.base, &[FIRST_NEIGHBOR])
    } else {
        format!("{}\n[[neighbors]\n", fixture.base)
    };
    fixture.write(&first);
    fixture.daemon.signal(Signal::SIGHUP);
    let mut reload_one = fixture.daemon.wait_for_hold(Hold::Read);

    let mut waiter = None;
    for count in 1..=extra {
        if via_rbgp && count == 1 {
            waiter = Some(
                rbgp_command(&fixture.grpc_addr, &["--json", "reload", "--timeout", "60"])
                    .spawn()
                    .expect("start rbgp reload"),
            );
        } else {
            fixture.daemon.signal(Signal::SIGHUP);
        }
        wait_for_outcome_count(&mut fixture.daemon, fixture.metrics, "coalesced", count);
    }
    // Written after reload 1 read the file: only a follow-up can apply it.
    fixture.write(&with_neighbors(
        &fixture.base,
        &[FIRST_NEIGHBOR, SECOND_NEIGHBOR],
    ));
    reload_one.write_all(&[1]).expect("release reload 1");
    fixture
        .daemon
        .wait_for_hold(Hold::Settled)
        .write_all(&[1])
        .expect("release reload 1 settlement");

    let mut follow_up = fixture.daemon.wait_for_hold(Hold::Read);
    if let Some(waiter) = waiter.as_mut() {
        // Reload 1 has settled and the follow-up is parked, so rbgp reload has
        // nothing to return yet. A negative check needs an observation window:
        // rbgp polls every 500 ms, so this gives it several polls in which it
        // could wrongly return reload 1's record, which predates its signal.
        thread::sleep(Duration::from_millis(1600));
        assert!(
            waiter.try_wait().unwrap().is_none(),
            "rbgp reload returned on the reload that predates its signal"
        );
    }
    follow_up.write_all(&[1]).expect("release follow-up reload");
    let mut follow_up_settled = fixture.daemon.wait_for_hold(Hold::Settled);

    assert!(neighbor_exists(&fixture.grpc_addr, SECOND_NEIGHBOR));
    let expected_complete = if first_valid { 2 } else { 1 };
    assert_eq!(
        reload_outcome_count(fixture.metrics, "complete"),
        expected_complete
    );
    assert_eq!(reload_outcome_count(fixture.metrics, "coalesced"), extra);
    assert_eq!(
        reload_outcome_count(fixture.metrics, "rejected_no_effect"),
        u64::from(!first_valid)
    );
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

    request_shutdown(&fixture.grpc_addr);
    follow_up_settled
        .write_all(&[1])
        .expect("release follow-up settlement");
    let status = fixture.daemon.wait_for_exit();
    assert!(status.success(), "{status}\n{}", fixture.daemon.log());
    assert_eq!(fixture.daemon.log_count(FOLLOW_UP_STARTED), 1);
    assert_eq!(fixture.daemon.log_count(FOLLOW_UP_DROPPED), 0);
    fixture.daemon.assert_no_further_reload();
}

#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug-build SIGHUP test holds"
)]
fn sighup_during_a_reload_runs_one_follow_up_that_reads_the_later_edit() {
    exercise(true, 1, false);
}

#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug-build SIGHUP test holds"
)]
fn several_sighups_during_one_reload_fold_into_one_follow_up() {
    exercise(true, 3, false);
}

#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug-build SIGHUP test holds"
)]
fn follow_up_runs_after_a_rejected_reload_and_rbgp_reload_waits_for_it() {
    exercise(false, 1, true);
}

/// Load-bearing: without the boot-time SIGHUP block, the HUP the daemon sends
/// itself after config load and logging init takes the default action and
/// the fixture never serves. With it, the held signal runs one reload. The
/// startup line names the config and state dir, and readiness is logged once.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug-build early-SIGHUP seam"
)]
fn sighup_during_startup_is_held_until_the_handler_and_runs_one_reload() {
    let mut fixture = Fixture::start_with_env(false, &[("RUSTBGPD_TEST_SIGHUP_BEFORE_RUN", "1")]);
    wait_for_outcome_count(&mut fixture.daemon, fixture.metrics, "complete", 1);
    let log = fixture.daemon.log();
    let runtime_dir = fixture.dir.path().join("runtime");
    for field in [
        format!("\"config\":\"{}\"", fixture.config_path.display()),
        format!("\"runtime_state_dir\":\"{}\"", runtime_dir.display()),
    ] {
        assert!(
            log.lines()
                .any(|line| line.contains("starting rustbgpd") && line.contains(&field)),
            "startup line lacks {field}\n{log}"
        );
    }
    assert_eq!(fixture.daemon.log_count("rustbgpd ready:"), 1, "{log}");

    request_shutdown(&fixture.grpc_addr);
    let status = fixture.daemon.wait_for_exit();
    assert!(status.success(), "{status}\n{}", fixture.daemon.log());
    // Counted after exit, so a second reload queued behind shutdown shows.
    assert_eq!(
        fixture.daemon.log_count("SIGHUP received"),
        1,
        "{}",
        fixture.daemon.log()
    );
}

/// The turn after a settlement has both a due follow-up and a pending
/// shutdown request; shutdown must win every time.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug-build SIGHUP test holds"
)]
fn shutdown_drops_a_pending_follow_up_instead_of_starting_it() {
    for _ in 0..4 {
        let mut fixture = Fixture::start(true);
        fixture.daemon.signal(Signal::SIGHUP);
        let mut reload_one = fixture.daemon.wait_for_hold(Hold::Read);
        fixture.daemon.signal(Signal::SIGHUP);
        wait_for_outcome_count(&mut fixture.daemon, fixture.metrics, "coalesced", 1);
        reload_one.write_all(&[1]).expect("release reload 1");
        let mut settled = fixture.daemon.wait_for_hold(Hold::Settled);
        request_shutdown(&fixture.grpc_addr);
        settled.write_all(&[1]).expect("release settlement");

        let status = fixture.daemon.wait_for_exit();
        assert!(status.success(), "{status}\n{}", fixture.daemon.log());
        assert_eq!(
            fixture.daemon.log_count(FOLLOW_UP_DROPPED),
            1,
            "{}",
            fixture.daemon.log()
        );
        assert_eq!(fixture.daemon.log_count(FOLLOW_UP_STARTED), 0);
        fixture.daemon.assert_no_further_reload();
    }
}

/// A signal queued while the loop handles a settlement is already served by
/// the follow-up that starts next, which reads the file after it; it must not
/// count as coalesced or schedule a second follow-up.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug-build SIGHUP test holds"
)]
fn a_signal_queued_before_a_follow_up_starts_is_served_by_it() {
    let mut fixture = Fixture::start(true);
    fixture.daemon.signal(Signal::SIGHUP);
    let mut reload_one = fixture.daemon.wait_for_hold(Hold::Read);
    fixture.daemon.signal(Signal::SIGHUP);
    wait_for_outcome_count(&mut fixture.daemon, fixture.metrics, "coalesced", 1);
    reload_one.write_all(&[1]).expect("release reload 1");
    let mut settled = fixture.daemon.wait_for_hold(Hold::Settled);
    fixture.daemon.signal(Signal::SIGHUP);
    // The loop is parked in the settlement arm, so nothing observable marks
    // the signal's arrival; give the runtime's signal driver time to queue it.
    thread::sleep(Duration::from_millis(300));
    settled
        .write_all(&[1])
        .expect("release reload 1 settlement");

    fixture
        .daemon
        .wait_for_hold(Hold::Read)
        .write_all(&[1])
        .expect("release follow-up reload");
    let mut follow_up_settled = fixture.daemon.wait_for_hold(Hold::Settled);
    assert_eq!(reload_outcome_count(fixture.metrics, "coalesced"), 1);
    assert_eq!(reload_outcome_count(fixture.metrics, "complete"), 2);
    request_shutdown(&fixture.grpc_addr);
    follow_up_settled
        .write_all(&[1])
        .expect("release follow-up settlement");
    let status = fixture.daemon.wait_for_exit();
    assert!(status.success(), "{status}\n{}", fixture.daemon.log());
    assert_eq!(fixture.daemon.log_count(FOLLOW_UP_STARTED), 1);
    assert_eq!(fixture.daemon.log_count(FOLLOW_UP_DROPPED), 0);
    fixture.daemon.assert_no_further_reload();
}

/// `--timeout` also bounds connection setup. A loopback listener with a full
/// accept queue never completes another TCP handshake.
#[test]
fn rbgp_reload_timeout_bounds_the_connect() {
    use nix::sys::socket::{
        AddressFamily, Backlog, SockFlag, SockType, SockaddrIn, bind, getsockname, listen, socket,
    };
    use std::os::fd::AsRawFd as _;
    let listener = socket(
        AddressFamily::Inet,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC,
        None,
    )
    .expect("create listener");
    bind(listener.as_raw_fd(), &SockaddrIn::new(127, 0, 0, 1, 0)).expect("bind listener");
    listen(&listener, Backlog::new(0).unwrap()).expect("listen");
    let port = getsockname::<SockaddrIn>(listener.as_raw_fd())
        .expect("listener address")
        .port();
    let _queued = TcpStream::connect(("127.0.0.1", port)).expect("fill the accept queue");

    let started = Instant::now();
    let output = rbgp(
        &format!("http://127.0.0.1:{port}"),
        &["reload", "--timeout", "1"],
    );
    let elapsed = started.elapsed();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr:\n{stderr}");
    assert!(
        stderr.contains("timed out after 1s before SIGHUP was sent"),
        "stderr:\n{stderr}"
    );
    assert!(elapsed < Duration::from_secs(3), "{elapsed:?}");
}

#[test]
fn rbgp_reload_exit_code_follows_the_settled_outcome() {
    let fixture = Fixture::start(false);
    fixture.write(&format!("{}\n[[neighbors]\n", fixture.base));
    let rejected = rbgp(&fixture.grpc_addr, &["--json", "reload"]);
    assert_eq!(
        rejected.status.code(),
        Some(3),
        "stderr:\n{}",
        String::from_utf8_lossy(&rejected.stderr)
    );
    let receipt: serde_json::Value = serde_json::from_slice(&rejected.stdout).unwrap();
    assert_eq!(receipt["record"]["outcome"], "rejected_no_effect");

    fixture.write(&with_neighbors(&fixture.base, &[FIRST_NEIGHBOR]));
    let applied = rbgp(&fixture.grpc_addr, &["reload"]);
    assert!(
        applied.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&applied.stderr)
    );
    assert!(String::from_utf8_lossy(&applied.stdout).starts_with("Last SIGHUP: complete"));
    assert!(neighbor_exists(&fixture.grpc_addr, FIRST_NEIGHBOR));
}

/// A restarted daemon's reload record says nothing about the reload the
/// command's signal started, even when it began after the signal.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug-build SIGHUP test holds"
)]
fn rbgp_reload_reports_a_daemon_restart_instead_of_its_record() {
    let mut fixture = Fixture::start(true);
    let waiter = rbgp_command(&fixture.grpc_addr, &["--json", "reload", "--timeout", "60"])
        .spawn()
        .expect("start rbgp reload");
    let waiter_pid = Pid::from_raw(i32::try_from(waiter.id()).unwrap());
    // The reload its signal started is parked: freeze rbgp before replacing
    // the daemon so its next read lands on the new process.
    let _parked = fixture.daemon.wait_for_hold(Hold::Read);
    kill(waiter_pid, Signal::SIGSTOP).expect("stop rbgp reload");
    fixture.daemon.signal(Signal::SIGKILL);
    fixture.daemon.wait_for_exit();

    let log_path = fixture.dir.path().join("restarted.log");
    fixture.daemon = Daemon::spawn(&fixture.config_path, log_path, false);
    fixture.serve();
    fixture.daemon.signal(Signal::SIGHUP);
    wait_for_outcome_count(&mut fixture.daemon, fixture.metrics, "complete", 1);
    kill(waiter_pid, Signal::SIGCONT).expect("resume rbgp reload");

    let deadline = Instant::now() + WAIT;
    let mut waiter = waiter;
    while waiter.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "rbgp reload did not finish");
        thread::sleep(Duration::from_millis(20));
    }
    let output = waiter.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr:\n{stderr}");
    // Which one depends on whether rbgp's next read reconnected to the new
    // daemon or first saw the old transport fail.
    assert!(
        stderr.contains("the daemon restarted while waiting; reload outcome unknown")
            || stderr.contains("the daemon exited while waiting; reload outcome unknown"),
        "stderr:\n{stderr}"
    );
    assert!(output.stdout.is_empty());
}
