//! Exit-code contract for daemon shutdown causes.
//!
//! Operator-initiated shutdown (SIGTERM) exits 0; a component failure
//! exits non-zero, so supervisors like systemd with `Restart=on-failure`
//! restart the daemon instead of treating it as a clean stop. Live proofs cover
//! startup binds, the RIB manager, and both inbound-admission tasks.

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use bytes::Bytes;
use rustbgpd_wire::constants::{HEADER_LEN, MAX_MESSAGE_LEN};
use rustbgpd_wire::message::{Message, decode_message, encode_message};
use rustbgpd_wire::notification::{NotificationCode, cease_subcode};
use rustbgpd_wire::open::OpenMessage;

fn private_tempdir() -> tempfile::TempDir {
    let temp = tempfile::tempdir().expect("create temp dir");
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))
        .expect("make temp dir private");
    temp
}

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
    spawn_daemon_with_env(dir, config_path, None)
}

fn spawn_daemon_with_env(dir: &Path, config_path: &Path, env: Option<(&str, &str)>) -> Daemon {
    let stdout_path = dir.join("rustbgpd.stdout.log");
    let stderr_path = dir.join("rustbgpd.stderr.log");
    let mut command = Command::new(env!("CARGO_BIN_EXE_rustbgpd"));
    command.arg(config_path);
    if let Some((key, value)) = env {
        command.env(key, value);
    }
    Daemon {
        child: command
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

fn write_rib_fault_config(dir: &Path) -> PathBuf {
    let config_path = write_config(dir, DAEMON_CHOOSES, DAEMON_CHOOSES);
    let config = std::fs::read_to_string(&config_path)
        .expect("read test config")
        .replace(
            "listen_port = 0",
            "listen_port = 0\nlisten_addresses = [\"127.0.0.1\"]",
        );
    std::fs::write(
        &config_path,
        format!(
            "{config}\n[[neighbors]]\naddress = \"127.0.0.1\"\nremote_asn = 65020\ngraceful_restart = false\n"
        ),
    )
    .expect("write RIB fault config");
    config_path
}

/// Port the config asks for when the test does not care about the value.
///
/// Picking one by binding `127.0.0.1:0` and dropping the listener reserves
/// nothing: the kernel can hand that exact port to a parallel test before
/// the daemon binds it, and this suite would read the resulting `AddrInUse`
/// as the bind failure it is asserting on (LAN-941). Port 0 lets the
/// process that serves the port be the one that binds it.
const DAEMON_CHOOSES: u16 = 0;

/// The gRPC TCP port the daemon reports it actually bound, for tests that
/// have to talk to it. Only the gRPC TCP listener logs `bound_addr`.
fn wait_for_bound_grpc_port(daemon: &mut Daemon) -> u16 {
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        let logs = daemon.logs();
        if let Some(port) = logs
            .split("\"bound_addr\":\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .and_then(|addr| addr.rsplit(':').next()?.parse().ok())
        {
            return port;
        }
        if let Ok(Some(status)) = daemon.child.try_wait() {
            panic!("rustbgpd exited before binding its gRPC listener: {status}\n{logs}");
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!(
        "rustbgpd never logged a bound gRPC listener\n{}",
        daemon.logs()
    );
}

fn wait_for_bound_bgp_port(daemon: &mut Daemon) -> u16 {
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        let logs = daemon.logs();
        if let Some(port) = logs
            .split(r#""addr":"127.0.0.1:"#)
            .skip(1)
            .filter_map(|rest| rest.split('"').next()?.parse().ok())
            .find(|port| *port != 0)
        {
            return port;
        }
        if let Ok(Some(status)) = daemon.child.try_wait() {
            panic!("rustbgpd exited before binding BGP: {status}\n{logs}");
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!(
        "rustbgpd never logged a bound BGP listener\n{}",
        daemon.logs()
    );
}

fn read_bgp_message(stream: &mut TcpStream) -> Message {
    let mut frame = vec![0; HEADER_LEN];
    stream.read_exact(&mut frame).expect("read BGP header");
    let total = usize::from(u16::from_be_bytes([frame[16], frame[17]]));
    assert!((HEADER_LEN..=usize::from(MAX_MESSAGE_LEN)).contains(&total));
    frame.resize(total, 0);
    stream
        .read_exact(&mut frame[HEADER_LEN..])
        .expect("read BGP body");
    decode_message(&mut Bytes::from(frame), MAX_MESSAGE_LEN).expect("decode daemon BGP frame")
}

fn establish_bgp_and_observe_shutdown(port: u16) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect BGP peer");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let open = Message::Open(OpenMessage {
        version: 4,
        my_as: 65020,
        hold_time: 90,
        bgp_identifier: "10.0.0.2".parse().unwrap(),
        capabilities: vec![],
    });
    stream
        .write_all(&encode_message(&open).expect("encode OPEN"))
        .expect("write OPEN");
    assert!(matches!(read_bgp_message(&mut stream), Message::Open(_)));
    stream
        .write_all(&encode_message(&Message::Keepalive).unwrap())
        .expect("write KEEPALIVE");

    let mut established = false;
    loop {
        match read_bgp_message(&mut stream) {
            Message::Keepalive => established = true,
            Message::Notification(notification) => {
                assert!(established, "shutdown followed an established session");
                assert_eq!(notification.code, NotificationCode::Cease);
                assert_eq!(notification.subcode, cease_subcode::ADMINISTRATIVE_SHUTDOWN);
                return;
            }
            _ => {}
        }
    }
}

fn run_bgp_ingress_fault(mode: &str, connect: bool) -> (ExitStatus, String) {
    let temp = private_tempdir();
    let config_path = write_rib_fault_config(temp.path());
    let mut daemon = spawn_daemon_with_env(
        temp.path(),
        &config_path,
        Some(("RUSTBGPD_TEST_BGP_INGRESS_EXIT", mode)),
    );
    let port = wait_for_bound_bgp_port(&mut daemon);
    let _connection = connect.then(|| {
        TcpStream::connect(("127.0.0.1", port)).expect("connect to real bound BGP listener")
    });
    let status = daemon.wait_within(Duration::from_secs(30));
    (status, daemon.logs())
}

#[test]
fn grpc_bind_failure_exits_nonzero() {
    let temp = private_tempdir();
    // Hold the gRPC port so the daemon's listener bind fails with
    // AddrInUse — the gRPC server task exits, which must shut the
    // daemon down with a non-zero exit code.
    let occupied = TcpListener::bind("127.0.0.1:0").expect("bind occupied port");
    let grpc_port = occupied.local_addr().unwrap().port();
    let config_path = write_config(temp.path(), grpc_port, DAEMON_CHOOSES);

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
fn rib_manager_panic_drains_established_peer_and_exits_nonzero() {
    let temp = private_tempdir();
    let config_path = write_rib_fault_config(temp.path());
    let mut daemon = spawn_daemon_with_env(
        temp.path(),
        &config_path,
        Some(("RUSTBGPD_TEST_RIB_PANIC_ON_PEER_UP", "1")),
    );
    establish_bgp_and_observe_shutdown(wait_for_bound_bgp_port(&mut daemon));

    let status = daemon.wait_within(Duration::from_secs(30));
    let logs = daemon.logs();
    assert_eq!(status.code(), Some(1), "RIB failure must exit 1\n{logs}");
    assert!(logs.contains("RIB manager exited unexpectedly"), "{logs}");
    assert!(
        logs.contains("initiating shutdown due to RIB manager failure"),
        "{logs}"
    );
    assert!(logs.contains("shutdown requested"), "{logs}");

    let reports = std::fs::read_dir(temp.path().join("runtime/crash"))
        .expect("panic report directory")
        .flatten()
        .map(|entry| std::fs::read_to_string(entry.path()).expect("read panic report"))
        .collect::<Vec<_>>();
    assert_eq!(reports.len(), 1, "one durable panic report: {reports:?}");
    assert!(reports[0].contains("triggered before route-page generation advance"));
}

#[test]
fn rib_supervision_is_fail_stop_and_uses_common_peer_teardown() {
    let source = include_str!("../src/main.rs");
    let retained = source
        .find("let mut rib_handle = tokio::spawn(rib_manager.run());")
        .expect("RIB JoinHandle must be retained");
    let arm = source
        .find("result = &mut rib_handle => {")
        .expect("shutdown select must supervise the RIB task");
    let exact_arm = &source[arm..source[arm..].find("            }").unwrap() + arm];
    assert!(exact_arm.contains("RIB manager exited unexpectedly"));
    assert!(exact_arm.contains("component_failed = true;"));
    assert!(exact_arm.contains("break;"));
    assert!(
        !exact_arm.contains("Ok(") && !exact_arm.contains("is_ok") && !exact_arm.contains("is_err")
    );
    let teardown = source
        .find("send(PeerManagerCommand::Shutdown)")
        .expect("component failure must retain coordinated peer shutdown");
    assert!(retained < arm && arm < teardown);
}

#[test]
fn bgp_ingress_tasks_are_retained_unconditionally_supervised_and_torn_down() {
    let source = include_str!("../src/main.rs");
    let production = source.split_once("\n#[cfg(test)]\nmod tests").unwrap().0;
    assert_eq!(
        production
            .matches("std::env::var(TEST_BGP_INGRESS_EXIT_ENV)")
            .count(),
        1
    );
    let teardown = production
        .find("send(PeerManagerCommand::Shutdown)")
        .unwrap();
    for (handle, diagnostic) in [
        (
            "bgp_listener_handle",
            "BGP listener task exited unexpectedly",
        ),
        (
            "bgp_forwarder_handle",
            "BGP accept-forwarding task exited unexpectedly",
        ),
    ] {
        let retained = production
            .find(&format!("let mut {handle} = tokio::spawn"))
            .unwrap_or_else(|| panic!("{handle} not retained"));
        let arm = production
            .find(&format!("result = &mut {handle} => {{"))
            .unwrap_or_else(|| panic!("{handle} not selected"));
        let body = production[arm..].split_once("\n            }").unwrap().0;
        assert!(body.contains(diagnostic), "{handle}: {body}");
        assert!(
            body.contains("component_failed = true;"),
            "{handle}: {body}"
        );
        assert!(body.contains("break;"), "{handle}: {body}");
        assert!(
            !body.contains("is_ok") && !body.contains("is_err"),
            "{handle}: {body}"
        );
        assert!(retained < arm && arm < teardown, "{handle} ordering");
    }
    let rpc = production
        .split_once("changed = rpc_shutdown_rx.changed() => {")
        .unwrap()
        .1;
    let rpc = rpc.split_once("\n            }").unwrap().0;
    assert!(
        !rpc.contains("component_failed"),
        "Shutdown RPC must stay clean"
    );
}

#[test]
fn bound_bgp_listener_panic_uses_common_shutdown_and_exits_nonzero() {
    let (status, logs) = run_bgp_ingress_fault("listener_panic", false);
    assert_eq!(
        status.code(),
        Some(1),
        "listener task panic must exit 1\n{logs}"
    );
    assert!(
        logs.contains("injected BGP listener task panic after successful bind"),
        "{logs}"
    );
    assert!(
        logs.contains("BGP listener task exited unexpectedly"),
        "{logs}"
    );
    assert!(
        logs.contains("initiating shutdown due to BGP listener task failure"),
        "{logs}"
    );
}

#[test]
fn accepted_connection_forwarder_return_uses_common_shutdown_and_exits_nonzero() {
    let (status, logs) = run_bgp_ingress_fault("forwarder_return", true);
    assert_eq!(
        status.code(),
        Some(1),
        "forwarder return must exit 1\n{logs}"
    );
    assert!(
        logs.contains("BGP accept-forwarding task exited unexpectedly"),
        "{logs}"
    );
    assert!(
        logs.contains("initiating shutdown due to BGP accept-forwarding task failure"),
        "{logs}"
    );
}

#[test]
fn help_and_man_distinguish_bgp_bind_modes_and_supervised_exits() {
    let output = |flag| {
        let output = Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
            .arg(flag)
            .output()
            .expect("run rustbgpd display mode");
        assert!(output.status.success());
        String::from_utf8(output.stdout).expect("display output is UTF-8")
    };
    let help = output("--help");
    assert!(help.contains("legacy BGP mode bound neither family; an explicit listen_addresses"));
    assert!(help.contains("endpoint failed to bind; configured metrics/readiness bind failure;"));
    assert!(help.contains("or unexpected RIB manager, gRPC server, BGP listener task,"));
    assert!(help.contains("or BGP accept-forwarding task exit"));
    let man = output("--man");
    assert!(man.contains("legacy BGP listen mode could bind\nneither family; explicit\n.B listen_addresses\nmode could not bind every configured endpoint"));
    assert!(man.contains("the RIB manager, gRPC server, BGP listener task,\nor BGP accept-forwarding task exited unexpectedly"));
}

#[test]
fn metrics_listener_bind_failure_exits_nonzero() {
    let temp = private_tempdir();
    let occupied = TcpListener::bind("127.0.0.1:0").expect("bind occupied metrics port");
    let metrics_port = occupied.local_addr().unwrap().port();
    let config_path = write_config_with_metrics(
        temp.path(),
        DAEMON_CHOOSES,
        DAEMON_CHOOSES,
        Some(metrics_port),
    );

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
    let temp = private_tempdir();
    // Hold the BGP listen port on BOTH address families with live
    // listeners. SO_REUSEADDR lets a new generation rebind over a
    // closed-but-lingering endpoint, never over an active LISTEN, so both
    // binds genuinely fail — and a daemon that cannot accept inbound
    // sessions on either family must exit rather than run deaf. (A single
    // failed family degrades to a warning instead; see the test below.)
    let (_v4_occupier, _v6_occupier, bgp_port) = {
        let mut attempt = 0;
        loop {
            let v4 = TcpListener::bind("0.0.0.0:0").expect("bind occupied v4 port");
            let port = v4.local_addr().unwrap().port();
            // A specific [::1] listener is enough to make the daemon's
            // wildcard [::] bind fail with AddrInUse.
            match TcpListener::bind(("::1", port)) {
                Ok(v6) => break (v4, v6, port),
                Err(_) => {
                    attempt += 1;
                    assert!(attempt < 10, "no port occupiable on both families found");
                }
            }
        }
    };
    let config_path = write_config(temp.path(), DAEMON_CHOOSES, bgp_port);

    let mut daemon = spawn_daemon(temp.path(), &config_path);
    let status = daemon.wait_within(Duration::from_secs(120));
    let logs = daemon.logs();
    assert!(
        logs.contains("failed to bind BGP listener on either address family"),
        "the daemon must exit for the BGP listener, not some other cause\n{logs}"
    );
    assert_eq!(
        status.code(),
        Some(1),
        "BGP listener bind failure must exit 1, got {status}\n{logs}"
    );
}

#[test]
fn bgp_listener_single_family_bind_failure_degrades_and_serves() {
    let temp = private_tempdir();
    // Hold only the IPv4 side of the BGP listen port. The daemon must NOT
    // exit: it warns about the unavailable family and keeps serving the
    // other, then still shuts down cleanly on SIGTERM.
    let occupied = TcpListener::bind("0.0.0.0:0").expect("bind occupied v4 port");
    let bgp_port = occupied.local_addr().unwrap().port();
    let config_path = write_config(temp.path(), DAEMON_CHOOSES, bgp_port);

    let mut daemon = spawn_daemon(temp.path(), &config_path);

    // Startup completed: the gRPC listener answers while the v4 BGP bind
    // failed, proving the daemon degraded instead of exiting.
    let grpc_port = wait_for_bound_grpc_port(&mut daemon);
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if TcpStream::connect(("127.0.0.1", grpc_port)).is_ok() {
            break;
        }
        if let Ok(Some(status)) = daemon.child.try_wait() {
            panic!(
                "rustbgpd exited instead of degrading to one listener family: {status}\n{}",
                daemon.logs()
            );
        }
        assert!(
            Instant::now() < deadline,
            "rustbgpd did not start within timeout\n{}",
            daemon.logs()
        );
        thread::sleep(Duration::from_millis(100));
    }

    // The IPv6 side of the port is genuinely served by the degraded daemon.
    TcpStream::connect(("::1", bgp_port))
        .expect("inbound IPv6 BGP connection must establish on the surviving family");

    let sigterm = Command::new("kill")
        .args(["-TERM", &daemon.child.id().to_string()])
        .status()
        .expect("send SIGTERM");
    assert!(sigterm.success(), "kill -TERM failed: {sigterm}");
    let status = daemon.wait_within(Duration::from_secs(120));
    let logs = daemon.logs();
    assert!(
        logs.contains("failed to bind the BGP listener for this address family"),
        "the degradation warning must name the failed family bind\n{logs}"
    );
    assert_eq!(
        status.code(),
        Some(0),
        "a single failed listener family must not fail the daemon, got {status}\n{logs}"
    );
}

#[test]
fn sigterm_exits_zero() {
    let temp = private_tempdir();

    let config_path = write_config(temp.path(), DAEMON_CHOOSES, DAEMON_CHOOSES);
    let hidden = "unknown-mode-must-not-be-echoed";
    let mut daemon = spawn_daemon_with_env(
        temp.path(),
        &config_path,
        Some(("RUSTBGPD_TEST_BGP_INGRESS_EXIT", hidden)),
    );

    // Wait until the gRPC listener is up so SIGTERM lands on a fully
    // started daemon. No spawn retry: the daemon picks its own ports, so a
    // bind failure here is a real one rather than a lost port race.
    let grpc_port = wait_for_bound_grpc_port(&mut daemon);
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if TcpStream::connect(("127.0.0.1", grpc_port)).is_ok() {
            break;
        }
        if let Ok(Some(status)) = daemon.child.try_wait() {
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

    let sigterm = Command::new("kill")
        .args(["-TERM", &daemon.child.id().to_string()])
        .status()
        .expect("send SIGTERM");
    assert!(sigterm.success(), "kill -TERM failed: {sigterm}");

    let status = daemon.wait_within(Duration::from_secs(120));
    let logs = daemon.logs();
    assert_eq!(
        status.code(),
        Some(0),
        "SIGTERM must exit 0, got {status}\n{logs}"
    );
    assert!(
        logs.contains("ignoring invalid RUSTBGPD_TEST_BGP_INGRESS_EXIT"),
        "{logs}"
    );
    assert!(
        !logs.contains(hidden),
        "unknown environment value leaked: {logs}"
    );
}
