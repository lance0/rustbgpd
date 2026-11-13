//! Exit-code contract for daemon shutdown causes.
//!
//! Operator-initiated shutdown (SIGTERM) exits 0; a component failure
//! exits non-zero, so supervisors like systemd with `Restart=on-failure`
//! restart the daemon instead of treating it as a clean stop. Live proofs cover
//! startup binds, the RIB manager, RPKI subsystem, both inbound-admission tasks,
//! and the peer manager; the Shutdown RPC proof pins the intentional exit-0 path
//! beside them. A SIGTERM also publishes the Graceful Restart marker window
//! from the committed runtime configuration, runtime changes included.

#[path = "support/cargo.rs"]
mod cargo;

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use bytes::Bytes;
use rustbgpd_api::proto;
use rustbgpd_wire::constants::{HEADER_LEN, MAX_MESSAGE_LEN};
use rustbgpd_wire::message::{Message, decode_message, encode_message};
use rustbgpd_wire::notification::{NotificationCode, cease_subcode};
use rustbgpd_wire::open::OpenMessage;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tonic::{Code, Request, transport::Endpoint};

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
    std::fs::set_permissions(&runtime_dir, std::fs::Permissions::from_mode(0o700))
        .expect("make runtime dir private");
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

fn assert_one_rpki_failure_receipt(logs: &str, expected_task: &str) {
    let receipts = logs
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|event| event["fields"]["message"] == "RPKI subsystem task exited unexpectedly")
        .collect::<Vec<_>>();
    assert_eq!(receipts.len(), 1, "expected one RPKI receipt\n{logs}");
    let fields = &receipts[0]["fields"];
    assert_eq!(fields["task"], expected_task);
    assert_eq!(fields["outcome"], "panic");
    assert_eq!(fields["resolution_complete"], serde_json::Value::Bool(true));
    assert_eq!(fields["panic_count"], serde_json::Value::from(1));
    assert_eq!(fields["panic_classes"], expected_task);
}

fn write_rib_fault_config(dir: &Path) -> PathBuf {
    let config_path = write_config(dir, DAEMON_CHOOSES, DAEMON_CHOOSES);
    add_loopback_neighbor(&config_path);
    config_path
}

/// Listen on 127.0.0.1 only and configure the loopback test peer (AS 65020).
fn add_loopback_neighbor(config_path: &Path) {
    let config = std::fs::read_to_string(config_path)
        .expect("read test config")
        .replace(
            "listen_port = 0",
            "listen_port = 0\nlisten_addresses = [\"127.0.0.1\"]",
        );
    std::fs::write(
        config_path,
        format!(
            "{config}\n[[neighbors]]\naddress = \"127.0.0.1\"\nremote_asn = 65020\ngraceful_restart = false\n"
        ),
    )
    .expect("write loopback neighbor config");
}

fn write_rpki_fault_config(dir: &Path) -> PathBuf {
    let config_path = write_config(dir, DAEMON_CHOOSES, DAEMON_CHOOSES);
    let config = std::fs::read_to_string(&config_path).expect("read test config");
    std::fs::write(
        &config_path,
        format!("{config}\n[rpki]\n[[rpki.cache_servers]]\naddress = \"127.0.0.1:3323\"\n"),
    )
    .expect("write RPKI fault config");
    config_path
}

fn write_initial_peer_failure_config(dir: &Path) -> PathBuf {
    let config_path = write_config_with_metrics(dir, DAEMON_CHOOSES, DAEMON_CHOOSES, Some(0));
    let marker = "[global]\nasn = 65001";
    let replacement = "[global]\nasn = 65001\nwarm_cache_checkpoint_on_shutdown = true";
    let config = std::fs::read_to_string(&config_path).expect("read test config");
    assert!(config.contains(marker), "missing global config marker");
    let config = config.replacen(marker, replacement, 1);
    std::fs::write(
        &config_path,
        format!(
            r#"{config}
[[neighbors]]
address = "127.0.0.1"
remote_asn = 65020
description = "peer-one"
graceful_restart = true
[[neighbors]]
address = "127.0.0.2"
remote_asn = 65021
description = "peer-two"
"#
        ),
    )
    .expect("write initial-peer failure config");
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
    observe_administrative_shutdown(&mut establish_bgp(port));
}

/// Complete the OPEN/KEEPALIVE exchange as AS 65020 and return the session's
/// connection once the daemon's KEEPALIVE arrived.
fn establish_bgp(port: u16) -> TcpStream {
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
    loop {
        match read_bgp_message(&mut stream) {
            Message::Keepalive => return stream,
            Message::Notification(notification) => {
                panic!("session refused before it was established: {notification:?}")
            }
            _ => {}
        }
    }
}

/// Read the established session until the daemon's shutdown NOTIFICATION. A
/// connection the daemon closed or reset earlier fails the read.
fn observe_administrative_shutdown(stream: &mut TcpStream) {
    loop {
        if let Message::Notification(notification) = read_bgp_message(stream) {
            assert_eq!(notification.code, NotificationCode::Cease);
            assert_eq!(notification.subcode, cease_subcode::ADMINISTRATIVE_SHUTDOWN);
            return;
        }
    }
}

/// The port in the `addr` field of the first log line carrying `message`.
fn wait_for_logged_port_with_message(daemon: &mut Daemon, message: &str) -> u16 {
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        let logs = daemon.logs();
        if let Some(port) = logs
            .lines()
            .filter(|line| line.contains(message))
            .filter_map(|line| line.split(r#""addr":"127.0.0.1:"#).nth(1))
            .find_map(|rest| rest.split('"').next()?.parse().ok())
        {
            return port;
        }
        if let Ok(Some(status)) = daemon.child.try_wait() {
            panic!("rustbgpd exited before logging {message:?}: {status}\n{logs}");
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("rustbgpd never logged {message:?}\n{}", daemon.logs());
}

/// One HTTP GET against the daemon's metrics/readiness listener.
fn http_get(port: u16, path: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

/// Poll `/metrics` until it carries `row`; the listener may refuse or stall
/// a request while its server restarts.
fn wait_for_metric_row(daemon: &mut Daemon, port: u16, row: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let scrape = http_get(port, "/metrics");
        if let Ok(scrape) = &scrape
            && scrape.contains(row)
        {
            return scrape.clone();
        }
        if let Ok(Some(status)) = daemon.child.try_wait() {
            panic!(
                "rustbgpd exited while waiting for {row:?}: {status}\n{}",
                daemon.logs()
            );
        }
        assert!(
            Instant::now() < deadline,
            "/metrics never carried {row:?}; last scrape: {scrape:?}\n{}",
            daemon.logs()
        );
        thread::sleep(Duration::from_millis(50));
    }
}

fn rbgp_command(grpc_addr: &str) -> Command {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_rbgp") {
        let mut cmd = Command::new(path);
        cmd.arg("--addr").arg(grpc_addr);
        cmd
    } else {
        let mut cmd = cargo::command();
        cmd.args(["run", "--quiet", "-p", "rustbgpctl", "--bin", "rbgp", "--"])
            .arg("--addr")
            .arg(grpc_addr);
        cmd
    }
}

fn rbgp(grpc_addr: &str, args: &[&str]) -> std::process::Output {
    rbgp_command(grpc_addr)
        .args(args)
        .output()
        .expect("failed to spawn rbgp subprocess")
}

fn spawn_rbgp_watch(dir: &Path, grpc_addr: &str) -> Daemon {
    let stdout_path = dir.join("rbgp-watch.stdout.log");
    let stderr_path = dir.join("rbgp-watch.stderr.log");
    Daemon {
        child: rbgp_command(grpc_addr)
            .arg("watch")
            .stdout(Stdio::from(
                std::fs::File::create(&stdout_path).expect("watcher stdout log"),
            ))
            .stderr(Stdio::from(
                std::fs::File::create(&stderr_path).expect("watcher stderr log"),
            ))
            .spawn()
            .expect("spawn rbgp watch"),
        stdout_path,
        stderr_path,
    }
}

fn wait_for_route_watcher_subscriber(daemon: &mut Daemon, watcher: &mut Daemon, grpc_addr: &str) {
    let expected = "bgp_event_stream_subscribers{service=\"watch_events\",source=\"route\"} 1";
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut last_metrics = String::new();
    while Instant::now() < deadline {
        let output = rbgp(grpc_addr, &["metrics"]);
        last_metrics = format!(
            "status: {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if output.status.success() && String::from_utf8_lossy(&output.stdout).contains(expected) {
            return;
        }
        if let Ok(Some(status)) = daemon.child.try_wait() {
            panic!(
                "rustbgpd exited before the route watcher subscribed: {status}\n{}",
                daemon.logs()
            );
        }
        if let Ok(Some(status)) = watcher.child.try_wait() {
            panic!(
                "rbgp watch exited before its route subscription became visible: {status}\n{}",
                watcher.logs()
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!(
        "route watcher subscription never became visible\nlast metrics:\n{last_metrics}\n{}\n{}",
        daemon.logs(),
        watcher.logs()
    );
}

fn run_bgp_ingress_fault(mode: &str, connect: bool) -> (ExitStatus, String, Vec<String>) {
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
    let logs = daemon.logs();
    let reports = match std::fs::read_dir(temp.path().join("runtime/crash")) {
        Ok(entries) => entries
            .map(|entry| entry.expect("read panic report directory entry"))
            .map(|entry| std::fs::read_to_string(entry.path()).expect("read panic report"))
            .collect(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => panic!("read panic report directory: {error}"),
    };
    (status, logs, reports)
}

#[test]
fn initial_peer_rejection_uses_shortened_coordinated_teardown() {
    let temp = private_tempdir();
    let config_path = write_initial_peer_failure_config(temp.path());
    let mut daemon = spawn_daemon_with_env(
        temp.path(),
        &config_path,
        Some(("RUSTBGPD_TEST_INITIAL_PEER_REJECTION_AT", "2")),
    );
    let status = daemon.wait_within(Duration::from_secs(30));
    let logs = daemon.logs();

    assert_eq!(
        status.code(),
        Some(1),
        "peer-add failure must exit 1\n{logs}"
    );
    for message in [
        "failed to add configured peer during startup",
        "peer-two: peer 127.0.0.2%rustbgpd-test-invalid-interface has an interface but is not IPv6 link-local",
        "initiating shortened coordinated shutdown after configured-peer startup failure",
        "peer manager shutting down 1 peers",
        "shutdown requested",
    ] {
        assert!(logs.contains(message), "missing {message:?}\n{logs}");
    }
    for absent in [
        "metrics server listening",
        "finished GR restart marker publication for coordinated shutdown",
        "failed to clear GR restart marker",
    ] {
        assert!(!logs.contains(absent), "unexpected {absent:?}\n{logs}");
    }
    assert!(!temp.path().join("runtime/gr-restart.toml").exists());
    let warm_bundle = temp.path().join("runtime/warm-bundle-v1");
    assert!(
        !warm_bundle.exists() || std::fs::read_dir(warm_bundle).unwrap().next().is_none(),
        "incomplete boot must not publish a warm checkpoint"
    );
}

fn observer_request<T>(message: T) -> Request<T> {
    let mut request = Request::new(message);
    request.metadata_mut().insert(
        "authorization",
        "Bearer exit-code-test-token".parse().unwrap(),
    );
    request
}

/// The Unix handshake holds main after gRPC bind and releases it only after
/// every pre-install RPC has answered. Byte 2 acknowledges the completed
/// registration, including the zero-peer path.
#[tokio::test]
async fn initial_roster_unknown_peer_reads_are_retryable_until_registration() {
    for configured in [true, false] {
        let temp = private_tempdir();
        let config_path = write_config(temp.path(), DAEMON_CHOOSES, DAEMON_CHOOSES);
        if configured {
            let mut config = std::fs::OpenOptions::new()
                .append(true)
                .open(&config_path)
                .unwrap();
            writeln!(
                config,
                "\n[[neighbors]]\naddress = \"127.0.0.2\"\nremote_asn = 65020"
            )
            .unwrap();
        }
        let hold_path = temp.path().join("roster-hold.sock");
        let hold = tokio::net::UnixListener::bind(&hold_path).unwrap();
        let mut daemon = spawn_daemon_with_env(
            temp.path(),
            &config_path,
            Some((
                "RUSTBGPD_TEST_INITIAL_ROSTER_HOLD",
                hold_path.to_str().unwrap(),
            )),
        );
        let (mut handshake, _) = tokio::time::timeout(Duration::from_secs(30), hold.accept())
            .await
            .expect("daemon must reach post-bind hold")
            .unwrap();
        let mut marker = [0];
        tokio::time::timeout(Duration::from_secs(10), handshake.read_exact(&mut marker))
            .await
            .expect("post-bind hold marker")
            .unwrap();
        assert_eq!(marker, [1]);

        let port = wait_for_bound_grpc_port(&mut daemon);
        let channel = Endpoint::from_shared(format!("http://127.0.0.1:{port}"))
            .unwrap()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(10))
            .connect()
            .await
            .unwrap();
        let mut neighbor =
            proto::neighbor_service_client::NeighborServiceClient::new(channel.clone());
        let mut policy = proto::policy_service_client::PolicyServiceClient::new(channel.clone());
        let mut rib = proto::rib_service_client::RibServiceClient::new(channel.clone());
        let mut bfd = proto::bfd_service_client::BfdServiceClient::new(channel);
        let peer = "127.0.0.2";
        let unknown = "127.0.0.99";
        let neighbor_read = || {
            observer_request(proto::GetNeighborStateRequest {
                address: peer.into(),
                ..Default::default()
            })
        };
        let policy_read = || {
            observer_request(proto::GetPolicyStatsRequest {
                allow_partial: false,
                peer_address: peer.into(),
                direction: "import".into(),
            })
        };
        let policy_chain_read = || {
            observer_request(proto::GetNeighborPolicyChainsRequest {
                address: peer.into(),
            })
        };
        let rib_read = || {
            observer_request(proto::ListRoutesRequest {
                neighbor_address: peer.into(),
                ..Default::default()
            })
        };
        let bfd_read = || {
            observer_request(proto::GetBfdSessionsRequest {
                peer_address: peer.into(),
            })
        };
        assert_eq!(
            neighbor
                .get_neighbor_state(neighbor_read())
                .await
                .unwrap_err()
                .code(),
            Code::Unavailable
        );
        assert_eq!(
            policy
                .get_policy_stats(policy_read())
                .await
                .unwrap_err()
                .code(),
            Code::Unavailable
        );
        assert_eq!(
            policy
                .get_neighbor_policy_chains(observer_request(
                    proto::GetNeighborPolicyChainsRequest {
                        address: unknown.into(),
                    },
                ))
                .await
                .unwrap_err()
                .code(),
            Code::Unavailable
        );
        if configured {
            // Configured chain data can be published before the peer roster.
            policy
                .get_neighbor_policy_chains(policy_chain_read())
                .await
                .unwrap();
        }
        assert_eq!(
            rib.list_received_routes(rib_read())
                .await
                .unwrap_err()
                .code(),
            Code::Unavailable
        );
        assert_eq!(
            bfd.get_bfd_sessions(bfd_read()).await.unwrap_err().code(),
            Code::Unavailable
        );

        handshake.write_all(&[1]).await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), handshake.read_exact(&mut marker))
            .await
            .expect("initial roster completion marker")
            .unwrap();
        assert_eq!(marker, [2]);
        if configured {
            neighbor.get_neighbor_state(neighbor_read()).await.unwrap();
            policy.get_policy_stats(policy_read()).await.unwrap();
            policy
                .get_neighbor_policy_chains(policy_chain_read())
                .await
                .unwrap();
            rib.list_received_routes(rib_read()).await.unwrap();
            bfd.get_bfd_sessions(bfd_read()).await.unwrap();
        }
        assert_eq!(
            neighbor
                .get_neighbor_state(observer_request(proto::GetNeighborStateRequest {
                    address: unknown.into(),
                    ..Default::default()
                }))
                .await
                .unwrap_err()
                .code(),
            Code::NotFound
        );
        assert_eq!(
            policy
                .get_policy_stats(observer_request(proto::GetPolicyStatsRequest {
                    allow_partial: false,
                    peer_address: unknown.into(),
                    direction: "import".into(),
                }))
                .await
                .unwrap_err()
                .code(),
            Code::NotFound
        );
        assert_eq!(
            policy
                .get_neighbor_policy_chains(observer_request(
                    proto::GetNeighborPolicyChainsRequest {
                        address: unknown.into(),
                    }
                ))
                .await
                .unwrap_err()
                .code(),
            Code::NotFound
        );
        assert_eq!(
            rib.list_received_routes(observer_request(proto::ListRoutesRequest {
                neighbor_address: unknown.into(),
                ..Default::default()
            }))
            .await
            .unwrap_err()
            .code(),
            Code::NotFound
        );
        assert_eq!(
            bfd.get_bfd_sessions(observer_request(proto::GetBfdSessionsRequest {
                peer_address: unknown.into(),
            }))
            .await
            .unwrap_err()
            .code(),
            Code::NotFound
        );
    }
}

/// Load-bearing: a group-writable `runtime_state_dir` lets another local
/// user plant symlinks under daemon-owned state, so boot must refuse it
/// rather than continue with a warning.
#[test]
fn unsafe_runtime_state_dir_refuses_boot() {
    let temp = private_tempdir();
    let config_path = write_config(temp.path(), DAEMON_CHOOSES, DAEMON_CHOOSES);
    let runtime_dir = temp.path().join("runtime");
    std::fs::set_permissions(&runtime_dir, std::fs::Permissions::from_mode(0o775))
        .expect("make runtime dir group-writable");

    let mut daemon = spawn_daemon(temp.path(), &config_path);
    let status = daemon.wait_within(Duration::from_secs(60));
    let logs = daemon.logs();
    assert_eq!(
        status.code(),
        Some(1),
        "unsafe state dir must exit 1\n{logs}"
    );
    assert!(
        logs.contains("refusing to start: runtime_state_dir must be"),
        "{logs}"
    );
    // The reason reaches stderr, not only the structured log.
    let stderr = std::fs::read_to_string(&daemon.stderr_path).unwrap();
    assert!(
        stderr.contains("error: refusing to start: runtime_state_dir")
            && stderr.contains(&runtime_dir.display().to_string())
            && stderr.contains("775"),
        "stderr must name the refused directory and why:\n{stderr}"
    );
    assert!(
        std::fs::read_dir(&runtime_dir).unwrap().next().is_none(),
        "nothing may be written under a refused state dir"
    );
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
fn operations_key_log_table_covers_supervised_failures() {
    let production = include_str!("../src/main.rs")
        .split_once("\n#[cfg(test)]\nmod tests")
        .unwrap()
        .0;
    let key_log_table = include_str!("../docs/reference/operations.md")
        .split_once("## Key log messages")
        .expect("operations guide must retain the Key log messages section")
        .1
        .split_once("\n---")
        .expect("Key log messages table must retain its section boundary")
        .0;

    for (handle, diagnostic) in [
        ("grpc_handle", "gRPC server exited unexpectedly"),
        ("rib_handle", "RIB manager exited unexpectedly"),
        (
            "bgp_listener_handle",
            "BGP listener task exited unexpectedly",
        ),
        (
            "bgp_forwarder_handle",
            "BGP accept-forwarding task exited unexpectedly",
        ),
        ("peer_mgr_handle", "peer manager task exited unexpectedly"),
        (
            "lease_expiry_handle",
            "injection lease expiry task exited unexpectedly",
        ),
    ] {
        let arm_header = format!("            result = &mut {handle} => {{");
        assert_eq!(
            production.matches(&arm_header).count(),
            1,
            "expected exactly one supervision arm for {handle}"
        );
        let arm = production
            .split_once(&arm_header)
            .unwrap_or_else(|| panic!("missing supervision arm for {handle}"))
            .1
            .split_once("\n            }")
            .unwrap_or_else(|| panic!("unterminated supervision arm for {handle}"))
            .0;
        let exact_error = format!("                error!(?result, \"{diagnostic}\");");
        assert!(
            arm.lines().any(|line| line == exact_error),
            "{handle} arm must emit exact diagnostic {diagnostic:?}:\n{arm}"
        );
        assert!(
            arm.lines()
                .any(|line| line == "                component_failed = true;"),
            "{handle} arm must mark the component failure:\n{arm}"
        );
        assert!(
            arm.lines().any(|line| line == "                break;"),
            "{handle} arm must enter coordinated shutdown:\n{arm}"
        );
        let expected_row =
            format!("| `{diagnostic}` | ERROR | Fatal — coordinated shutdown follows |");
        assert!(
            key_log_table.lines().any(|line| line == expected_row),
            "missing exact operations row {expected_row:?}"
        );
    }

    // The metrics/readiness server is restarted in place: neither it nor its
    // supervisor ending may enter coordinated shutdown.
    let metrics_arm = production
        .split_once("            result = &mut metrics_handle, if !metrics_supervisor_exited => {")
        .expect("the metrics/readiness supervisor arm must stay guarded against a second poll")
        .1
        .split_once("\n            }")
        .unwrap()
        .0;
    assert!(!metrics_arm.contains("component_failed"), "{metrics_arm}");
    assert!(!metrics_arm.contains("break"), "{metrics_arm}");
    for row in [
        "| `metrics/readiness server exited unexpectedly; restarting it in place` | ERROR | ",
        "| `metrics/readiness supervisor exited unexpectedly; /metrics, /readyz and /livez stay down until the daemon restarts` | ERROR | ",
    ] {
        assert!(
            key_log_table.lines().any(|line| line.starts_with(row)),
            "missing operations row {row:?}"
        );
    }
    assert!(!key_log_table.contains("| `metrics/readiness server exited unexpectedly` |"));

    let rpki_diagnostic = "RPKI subsystem task exited unexpectedly";
    assert_eq!(production.matches(rpki_diagnostic).count(), 1);
    assert!(production.contains("match rpki_failure_rx.as_mut()"));
    assert!(production.contains("None => std::future::pending().await"));
    assert!(production.contains("timeout_at(notice.deadline, &mut handle)"));
    assert!(production.contains("component_failed = true;"));
    let expected_row =
        format!("| `{rpki_diagnostic}` | ERROR | Fatal — coordinated shutdown follows |");
    assert!(key_log_table.lines().any(|line| line == expected_row));
}

/// Port of the first `127.0.0.1` listener the daemon logged on a line that
/// `wanted` accepts.
fn wait_for_logged_port(daemon: &mut Daemon, wanted: impl Fn(&str) -> bool) -> u16 {
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        let logs = daemon.logs();
        if let Some(port) = logs
            .lines()
            .filter(|line| wanted(line))
            .filter_map(|line| {
                let rest = line.split(r#""addr":"127.0.0.1:"#).nth(1)?;
                rest.split('"').next()?.parse().ok()
            })
            .find(|port| *port != 0)
        {
            return port;
        }
        if let Ok(Some(status)) = daemon.child.try_wait() {
            panic!("rustbgpd exited before binding: {status}\n{logs}");
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("rustbgpd never logged the listener\n{}", daemon.logs());
}

/// Accept the daemon's next RTR connection, failing if the daemon exits.
fn accept_rtr(listener: &TcpListener, daemon: &mut Daemon) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(30)))
                    .unwrap();
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("accept RTR connection: {error}"),
        }
        if let Ok(Some(status)) = daemon.child.try_wait() {
            panic!(
                "rustbgpd exited instead of connecting to the cache: {status}\n{}",
                daemon.logs()
            );
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("no RTR connection from rustbgpd\n{}", daemon.logs());
}

fn read_rtr_pdu(stream: &mut TcpStream) -> rustbgpd_rpki::rtr_codec::RtrPdu {
    let mut frame = vec![0; 8];
    stream.read_exact(&mut frame).expect("read RTR header");
    let total = u32::from_be_bytes([frame[4], frame[5], frame[6], frame[7]]) as usize;
    frame.resize(total, 0);
    stream.read_exact(&mut frame[8..]).expect("read RTR body");
    rustbgpd_rpki::rtr_codec::RtrPdu::decode(&frame)
        .expect("decode RTR PDU")
        .0
}

/// Answer a query with a one-VRP full table at `serial`.
fn write_rtr_full_table(stream: &mut TcpStream, serial: u32) {
    use rustbgpd_rpki::rtr_codec::{RTR_VERSION_2, RtrPdu};
    let mut frame = Vec::new();
    for pdu in [
        RtrPdu::CacheResponse { session_id: 7 },
        RtrPdu::Ipv4Prefix {
            flags: 1,
            prefix_len: 24,
            max_len: 24,
            prefix: "203.0.113.0".parse().unwrap(),
            asn: 65001,
        },
        RtrPdu::EndOfData {
            session_id: 7,
            serial,
            refresh: 3600,
            retry: 1,
            expire: 7200,
        },
    ] {
        pdu.encode_with_version(&mut frame, RTR_VERSION_2).unwrap();
    }
    stream.write_all(&frame).expect("write RTR full table");
}

/// The peer has neither closed the connection nor sent anything for a
/// moment. For BGP, anything pending must not be a NOTIFICATION.
fn assert_connection_stays_open(stream: &mut TcpStream, bgp: bool, logs: &str) {
    stream
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    loop {
        match stream.peek(&mut [0; 1]) {
            Ok(0) => panic!("rustbgpd closed the connection\n{logs}"),
            Ok(_) if bgp => {
                let message = read_bgp_message(stream);
                assert!(
                    !matches!(message, Message::Notification(_)),
                    "unexpected {message:?}\n{logs}"
                );
            }
            Ok(_) => panic!("unexpected data on an idle RTR session\n{logs}"),
            Err(error) => {
                assert!(
                    matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ),
                    "connection failed: {error}\n{logs}"
                );
                return;
            }
        }
    }
}

fn scrape_metrics(port: u16) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect metrics");
    stream
        .write_all(b"GET /metrics HTTP/1.0\r\nHost: metrics\r\nConnection: close\r\n\r\n")
        .expect("write metrics request");
    let mut body = String::new();
    stream.read_to_string(&mut body).expect("read metrics");
    body
}

/// A panic in one cache's RTR client restarts that client's session and
/// nothing else: the daemon, an Established BGP session and the other
/// cache's RTR session carry on, the restart is counted for that cache only,
/// and the client comes back with a Reset Query. An ordinary reconnect would
/// have resumed with a Serial Query.
#[test]
fn rpki_client_panic_restarts_that_client_and_leaves_bgp_and_other_caches_up() {
    use rustbgpd_rpki::rtr_codec::RtrPdu;

    let temp = private_tempdir();
    let panicking_cache = TcpListener::bind("127.0.0.1:0").expect("bind first RTR cache");
    let other_cache = TcpListener::bind("127.0.0.1:0").expect("bind second RTR cache");
    let panicking_addr = panicking_cache.local_addr().unwrap();
    let other_addr = other_cache.local_addr().unwrap();
    let config_path =
        write_config_with_metrics(temp.path(), DAEMON_CHOOSES, DAEMON_CHOOSES, Some(0));
    let config = std::fs::read_to_string(&config_path)
        .expect("read test config")
        .replace(
            "listen_port = 0",
            "listen_port = 0\nlisten_addresses = [\"127.0.0.1\"]",
        );
    std::fs::write(
        &config_path,
        format!(
            "{config}\n[[neighbors]]\naddress = \"127.0.0.1\"\nremote_asn = 65020\n\
             graceful_restart = false\n[rpki]\n[[rpki.cache_servers]]\n\
             address = \"{panicking_addr}\"\nretry_interval = 1\n[[rpki.cache_servers]]\n\
             address = \"{other_addr}\"\n"
        ),
    )
    .expect("write RTR restart config");
    let mut daemon = spawn_daemon_with_env(
        temp.path(),
        &config_path,
        Some(("RUSTBGPD_TEST_RPKI_TASK_EXIT", "rtr_client_panic")),
    );

    // Both clients synchronize.
    let mut first_session = accept_rtr(&panicking_cache, &mut daemon);
    assert_eq!(read_rtr_pdu(&mut first_session), RtrPdu::ResetQuery);
    write_rtr_full_table(&mut first_session, 100);
    let mut other_session = accept_rtr(&other_cache, &mut daemon);
    assert_eq!(read_rtr_pdu(&mut other_session), RtrPdu::ResetQuery);
    write_rtr_full_table(&mut other_session, 100);

    // A BGP session reaches Established.
    let is_metrics = |line: &str| line.contains("metrics server listening");
    let metrics_port = wait_for_logged_port(&mut daemon, is_metrics);
    let bgp_port = wait_for_logged_port(&mut daemon, |line| !is_metrics(line));
    let mut bgp = TcpStream::connect(("127.0.0.1", bgp_port)).expect("connect BGP peer");
    bgp.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let open = Message::Open(OpenMessage {
        version: 4,
        my_as: 65020,
        hold_time: 90,
        bgp_identifier: "10.0.0.2".parse().unwrap(),
        capabilities: vec![],
    });
    bgp.write_all(&encode_message(&open).expect("encode OPEN"))
        .expect("write OPEN");
    assert!(matches!(read_bgp_message(&mut bgp), Message::Open(_)));
    bgp.write_all(&encode_message(&Message::Keepalive).unwrap())
        .expect("write KEEPALIVE");
    while !matches!(read_bgp_message(&mut bgp), Message::Keepalive) {}

    let cache_label = |addr: std::net::SocketAddr| format!("{{cache=\"{addr}\"}}");
    let before = scrape_metrics(metrics_port);
    for addr in [panicking_addr, other_addr] {
        let seeded = format!("bgp_rpki_rtr_client_restarts_total{} 0", cache_label(addr));
        assert!(before.contains(&seeded), "missing {seeded}\n{before}");
    }

    // The first cache drops its session; the client's next connection
    // attempt panics, and the attempt after that reaches the cache.
    drop(first_session);
    let mut second_session = accept_rtr(&panicking_cache, &mut daemon);
    assert_eq!(read_rtr_pdu(&mut second_session), RtrPdu::ResetQuery);
    write_rtr_full_table(&mut second_session, 101);

    let logs = daemon.logs();
    for message in [
        "injected RTR client task panic",
        "RTR client panicked; restarting its session with the held data retained",
    ] {
        assert!(logs.contains(message), "missing {message:?}\n{logs}");
    }
    for absent in [
        "RPKI subsystem task exited unexpectedly",
        "initiating coordinated shutdown",
    ] {
        assert!(!logs.contains(absent), "unexpected {absent:?}\n{logs}");
    }
    assert_connection_stays_open(&mut bgp, true, &logs);
    assert_connection_stays_open(&mut other_session, false, &logs);
    assert!(
        matches!(daemon.child.try_wait(), Ok(None)),
        "rustbgpd must keep running\n{logs}"
    );

    let after = scrape_metrics(metrics_port);
    for expected in [
        format!(
            "bgp_rpki_rtr_client_restarts_total{} 1",
            cache_label(panicking_addr)
        ),
        format!(
            "bgp_rpki_rtr_client_restarts_total{} 0",
            cache_label(other_addr)
        ),
        format!("bgp_rpki_cache_connected{} 1", cache_label(other_addr)),
    ] {
        assert!(after.contains(&expected), "missing {expected}\n{after}");
    }

    let reports = std::fs::read_dir(temp.path().join("runtime/crash"))
        .expect("panic report directory")
        .flatten()
        .map(|entry| std::fs::read_to_string(entry.path()).expect("read panic report"))
        .collect::<Vec<_>>();
    assert_eq!(reports.len(), 1, "one durable panic report: {reports:?}");
    assert!(reports[0].contains("injected RTR client task panic"));
}

#[test]
fn rpki_manager_panic_is_attributed_and_exits_nonzero() {
    let temp = private_tempdir();
    let config_path = write_rpki_fault_config(temp.path());
    let mut daemon = spawn_daemon_with_env(
        temp.path(),
        &config_path,
        Some(("RUSTBGPD_TEST_RPKI_TASK_EXIT", "vrp_manager_panic")),
    );
    let status = daemon.wait_within(Duration::from_secs(30));
    let logs = daemon.logs();
    assert_eq!(status.code(), Some(1), "manager panic must exit 1\n{logs}");
    assert_one_rpki_failure_receipt(&logs, "VrpManager");
    for message in [
        "initiating shutdown due to RPKI subsystem task failure",
        "initiating coordinated shutdown",
        "rustbgpd exiting",
    ] {
        assert!(logs.contains(message), "missing {message:?}\n{logs}");
    }

    let reports = std::fs::read_dir(temp.path().join("runtime/crash"))
        .expect("panic report directory")
        .flatten()
        .map(|entry| std::fs::read_to_string(entry.path()).expect("read panic report"))
        .collect::<Vec<_>>();
    assert_eq!(reports.len(), 1, "one durable panic report: {reports:?}");
    assert!(reports[0].contains("injected VRP manager task panic"));
}

#[test]
fn rpki_supervision_covers_every_task_and_common_teardown() {
    let source = include_str!("../src/main.rs");
    let setup = source
        .split_once("let mut rpki_tasks = JoinSet::new();")
        .expect("RPKI task set must be explicit")
        .1
        .split_once("// Spawn MRT manager")
        .expect("RPKI setup boundary")
        .0;
    for kind in [
        "RpkiTaskKind::VrpManager",
        "RpkiTaskKind::VrpForwarder",
        "RpkiTaskKind::AspaForwarder",
        "RpkiTaskKind::RtrClient",
    ] {
        assert!(setup.contains(kind), "missing supervised task class {kind}");
    }
    assert_eq!(setup.matches("rpki_tasks.spawn(").count(), 4);
    assert_eq!(setup.matches("register_rpki_task_kind(").count(), 4);
    assert!(source.contains("None => std::future::pending().await"));
    assert!(source.contains("tasks.join_next_with_id()"));
    assert!(source.contains("tasks.abort_all();"));
    assert!(source.contains("RPKI subsystem task exited unexpectedly"));
    let admission_close = source
        .find("daemon_gate.begin_shutdown();")
        .expect("shutdown admission must close");
    let runtime_config_close = source
        .find("runtime_config_lock.close();")
        .expect("runtime-config admission must close");
    let teardown_start = source
        .find("if let Some(handle) = rpki_supervisor.take() {")
        .expect("RPKI supervisor teardown");
    let settlement_start = source
        .find("let settlement_wait = runtime_config_settlement.clone();")
        .expect("runtime-config settlement boundary");
    assert!(
        admission_close < runtime_config_close
            && runtime_config_close < teardown_start
            && teardown_start < settlement_start
    );
    let teardown = &source[teardown_start..settlement_start];
    assert!(source.contains("timeout_at(notice.deadline, &mut handle)"));
    assert!(teardown.contains("handle.abort();"));
    assert!(teardown.contains("handle.await"));
}

#[test]
fn peer_manager_panic_uses_common_shutdown_and_exits_nonzero() {
    let temp = private_tempdir();
    let config_path = write_config(temp.path(), DAEMON_CHOOSES, DAEMON_CHOOSES);
    let mut daemon = spawn_daemon_with_env(
        temp.path(),
        &config_path,
        Some(("RUSTBGPD_TEST_PEER_MANAGER_PANIC", "1")),
    );
    let status = daemon.wait_within(Duration::from_secs(30));
    let logs = daemon.logs();
    assert_eq!(
        status.code(),
        Some(1),
        "peer manager task panic must exit 1\n{logs}"
    );
    for message in [
        "injected peer manager task panic",
        "peer manager task exited unexpectedly",
        "initiating shutdown due to peer manager task failure",
        "initiating coordinated shutdown",
        "rustbgpd exiting",
    ] {
        assert!(logs.contains(message), "missing {message:?}\n{logs}");
    }
    // The supervision arm consumed the JoinHandle; the teardown must not
    // join it a second time (that would panic the daemon mid-teardown).
    assert!(!logs.contains("peer manager task panicked"), "{logs}");
    assert!(
        !logs.contains("JoinHandle polled after completion"),
        "{logs}"
    );
    let reports = std::fs::read_dir(temp.path().join("runtime/crash"))
        .expect("panic report directory")
        .flatten()
        .map(|entry| std::fs::read_to_string(entry.path()).expect("read panic report"))
        .collect::<Vec<_>>();
    assert_eq!(reports.len(), 1, "one durable panic report: {reports:?}");
    assert!(reports[0].contains("injected peer manager task panic"));
}

/// An unexpected exit of the ADR-0141 lease expiry task is a component
/// failure: leases would otherwise stop expiring unseen.
///
/// Break-to-red: without its supervision arm the daemon keeps running.
#[test]
fn lease_expiry_panic_uses_common_shutdown_and_exits_nonzero() {
    let temp = private_tempdir();
    let config_path = write_config(temp.path(), DAEMON_CHOOSES, DAEMON_CHOOSES);
    let mut daemon = spawn_daemon_with_env(
        temp.path(),
        &config_path,
        Some(("RUSTBGPD_TEST_LEASE_EXPIRY_PANIC", "1")),
    );
    let status = daemon.wait_within(Duration::from_secs(30));
    let logs = daemon.logs();
    assert_eq!(
        status.code(),
        Some(1),
        "lease expiry task panic must exit 1\n{logs}"
    );
    for message in [
        "injected lease expiry task panic",
        "injection lease expiry task exited unexpectedly",
        "initiating shutdown due to injection lease expiry failure",
        "initiating coordinated shutdown",
        "rustbgpd exiting",
    ] {
        assert!(logs.contains(message), "missing {message:?}\n{logs}");
    }
    assert!(!logs.contains("RIB manager exited unexpectedly"), "{logs}");
    assert!(
        !logs.contains("JoinHandle polled after completion"),
        "{logs}"
    );
}

/// The lease expiry arm reports a closed RIB channel as the RIB's failure by
/// joining the RIB handle, as the dampening adapter arm does.
#[test]
fn lease_expiry_arm_attributes_a_closed_rib_channel_to_the_rib() {
    let source = include_str!("../src/main.rs");
    let arm_start = source
        .find("            result = &mut lease_expiry_handle => {")
        .expect("shutdown select must supervise the lease expiry task");
    let arm = &source[arm_start..];
    let arm = &arm[..arm.find("\n            }").unwrap()];
    let closed = arm
        .find("ExpiryExit::RibChannelClosed")
        .expect("the arm must distinguish a closed RIB channel");
    let join = arm
        .find("(&mut rib_handle).await")
        .expect("the arm must join the RIB handle");
    let rib_error = arm
        .find("error!(?result, \"RIB manager exited unexpectedly\");")
        .expect("the arm must report the RIB failure");
    let own_error = arm
        .find("error!(?result, \"injection lease expiry task exited unexpectedly\");")
        .expect("the arm must report its own failure otherwise");
    assert!(closed < join && join < rib_error && rib_error < own_error);
}

#[test]
fn shutdown_rpc_exits_zero_with_peer_manager_supervised() {
    let temp = private_tempdir();
    let config_path = write_rpki_fault_config(temp.path());
    let hidden = "unknown-value-must-not-be-echoed";
    let mut daemon = spawn_daemon_with_env(
        temp.path(),
        &config_path,
        Some(("RUSTBGPD_TEST_PEER_MANAGER_PANIC", hidden)),
    );
    // Startup is complete once the gRPC TCP listener is bound; the Shutdown
    // RPC then rides the implicit owner-only local socket.
    wait_for_bound_grpc_port(&mut daemon);
    let grpc_addr = format!("unix://{}", temp.path().join("runtime/grpc.sock").display());
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let output = rbgp(&grpc_addr, &["shutdown", "--reason", "exit-code test"]);
        if output.status.success() {
            break;
        }
        if let Ok(Some(status)) = daemon.child.try_wait() {
            panic!(
                "rustbgpd exited before accepting the Shutdown RPC: {status}\n{}",
                daemon.logs()
            );
        }
        assert!(
            Instant::now() < deadline,
            "rbgp shutdown never succeeded\nstderr:\n{}\n{}",
            String::from_utf8_lossy(&output.stderr),
            daemon.logs()
        );
        thread::sleep(Duration::from_millis(100));
    }

    let status = daemon.wait_within(Duration::from_secs(120));
    let logs = daemon.logs();
    assert_eq!(
        status.code(),
        Some(0),
        "Shutdown RPC must exit 0, got {status}\n{logs}"
    );
    // The peer manager exited as part of the ordered teardown, not through
    // the supervision arm.
    assert!(logs.contains("shutdown initiated via gRPC"), "{logs}");
    assert!(
        logs.contains("peer manager shutting down 0 peers"),
        "{logs}"
    );
    assert!(
        !logs.contains("peer manager task exited unexpectedly"),
        "{logs}"
    );
    assert!(
        !logs.contains("RPKI subsystem task exited unexpectedly"),
        "{logs}"
    );
    assert!(
        logs.contains("ignoring invalid RUSTBGPD_TEST_PEER_MANAGER_PANIC"),
        "{logs}"
    );
    assert!(
        !logs.contains(hidden),
        "unknown environment value leaked: {logs}"
    );
}

#[test]
fn shutdown_rpc_with_active_watch_cleans_up_uds() {
    let temp = private_tempdir();
    let config_path = write_config(temp.path(), DAEMON_CHOOSES, DAEMON_CHOOSES);
    let mut daemon = spawn_daemon(temp.path(), &config_path);
    wait_for_bound_grpc_port(&mut daemon);

    let socket_path = temp.path().join("runtime/grpc.sock");
    let socket_deadline = Instant::now() + Duration::from_secs(120);
    while !socket_path.exists() {
        if let Ok(Some(status)) = daemon.child.try_wait() {
            panic!(
                "rustbgpd exited before binding its UDS listener: {status}\n{}",
                daemon.logs()
            );
        }
        assert!(
            Instant::now() < socket_deadline,
            "gRPC UDS listener never appeared\n{}",
            daemon.logs()
        );
        thread::sleep(Duration::from_millis(100));
    }
    let grpc_addr = format!("unix://{}", socket_path.display());
    let mut watcher = spawn_rbgp_watch(temp.path(), &grpc_addr);
    wait_for_route_watcher_subscriber(&mut daemon, &mut watcher, &grpc_addr);

    let output = rbgp(
        &grpc_addr,
        &["shutdown", "--reason", "active watch cleanup test"],
    );
    assert!(
        output.status.success(),
        "Shutdown RPC failed\nstdout:\n{}\nstderr:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        daemon.logs()
    );

    let status = daemon.wait_within(Duration::from_secs(120));
    let logs = daemon.logs();
    assert_eq!(
        status.code(),
        Some(0),
        "Shutdown RPC with an active watcher must exit 0, got {status}\n{logs}"
    );
    let _watcher_status = watcher.wait_within(Duration::from_secs(30));
    assert!(
        !socket_path.exists(),
        "gRPC UDS socket survived coordinated shutdown with an active watcher\n{logs}\n{}",
        watcher.logs()
    );
}

#[test]
fn grpc_listener_accept_end_with_active_watch_fail_stops_within_grace() {
    let temp = private_tempdir();
    let config_path = write_config(temp.path(), DAEMON_CHOOSES, DAEMON_CHOOSES);
    // Connection 1 is the watch; connection 2 makes the listener unusable.
    let mut daemon = spawn_daemon_with_env(
        temp.path(),
        &config_path,
        Some(("RUSTBGPD_TEST_GRPC_TCP_LISTENER_UNUSABLE_AFTER", "2")),
    );
    let grpc_port = wait_for_bound_grpc_port(&mut daemon);
    let socket_path = temp.path().join("runtime/grpc.sock");
    let socket_deadline = Instant::now() + Duration::from_secs(120);
    while !socket_path.exists() {
        assert!(
            matches!(daemon.child.try_wait(), Ok(None)) && Instant::now() < socket_deadline,
            "gRPC UDS listener never appeared\n{}",
            daemon.logs()
        );
        thread::sleep(Duration::from_millis(100));
    }

    let tcp_addr = format!("http://127.0.0.1:{grpc_port}");
    let watch_stdout = temp.path().join("rbgp-watch.stdout.log");
    let watch_stderr = temp.path().join("rbgp-watch.stderr.log");
    let mut watcher = Daemon {
        child: rbgp_command(&tcp_addr)
            .arg("--token-file")
            .arg(temp.path().join("grpc-token"))
            .arg("watch")
            .stdout(Stdio::from(
                std::fs::File::create(&watch_stdout).expect("watcher stdout log"),
            ))
            .stderr(Stdio::from(
                std::fs::File::create(&watch_stderr).expect("watcher stderr log"),
            ))
            .spawn()
            .expect("spawn rbgp watch"),
        stdout_path: watch_stdout,
        stderr_path: watch_stderr,
    };
    let uds_addr = format!("unix://{}", socket_path.display());
    wait_for_route_watcher_subscriber(&mut daemon, &mut watcher, &uds_addr);

    assert!(
        matches!(watcher.child.try_wait(), Ok(None)),
        "{}",
        watcher.logs()
    );
    let trigger = TcpStream::connect(("127.0.0.1", grpc_port)).expect("second gRPC TCP connection");
    let triggered = Instant::now();
    let status = daemon.wait_within(Duration::from_secs(30));
    let elapsed = triggered.elapsed();
    drop(trigger);
    let logs = daemon.logs();
    for message in [
        "injected gRPC TCP listener shutdown",
        "listener socket unusable; stopping its accept loop",
        "stopped accepting and its open connections did not close within 1000 ms",
        "gRPC listener exited unexpectedly",
        "gRPC server exited unexpectedly",
        "rustbgpd exiting",
    ] {
        assert!(logs.contains(message), "missing {message:?}\n{logs}");
    }
    assert_eq!(status.code(), Some(1), "{logs}");
    assert!(
        elapsed < Duration::from_secs(15),
        "fail-stop took {elapsed:?}\n{logs}"
    );
}

#[test]
fn peer_manager_supervision_is_fail_stop_and_joins_once() {
    let source = include_str!("../src/main.rs");
    let production = source.split_once("\n#[cfg(test)]\nmod tests").unwrap().0;
    let retained = production
        .find("let mut peer_mgr_handle = tokio::spawn(async move {")
        .expect("peer manager JoinHandle must be retained");
    let arm = production
        .find("result = &mut peer_mgr_handle => {")
        .expect("shutdown select must supervise the peer manager task");
    let body = production[arm..].split_once("\n            }").unwrap().0;
    assert!(
        body.contains("peer manager task exited unexpectedly"),
        "{body}"
    );
    assert!(body.contains("peer_mgr_exited = true;"), "{body}");
    assert!(body.contains("component_failed = true;"), "{body}");
    assert!(body.contains("break;"), "{body}");
    assert!(
        !body.contains("is_ok") && !body.contains("is_err"),
        "{body}"
    );
    let teardown = production
        .find("send(PeerManagerCommand::Shutdown)")
        .expect("component failure must retain coordinated peer shutdown");
    let join = production
        .find("if !peer_mgr_exited && let Err(e) = peer_mgr_handle.await {")
        .expect("coordinated teardown must join the peer manager exactly once");
    assert!(retained < arm && arm < teardown && teardown < join);
    assert_eq!(production.matches("peer_mgr_handle.await").count(), 1);
    let rpc = production
        .split_once("changed = rpc_shutdown_rx.changed(), if !rpc_shutdown_closed => {")
        .unwrap()
        .1;
    let rpc = rpc.split_once("\n            }").unwrap().0;
    assert!(
        !rpc.contains("peer_mgr"),
        "Shutdown RPC arm must not touch the peer manager"
    );
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
    assert_eq!(production.matches("accept_tx.clone()").count(), 0);
    assert_eq!(
        production
            .matches("BgpForwarderOutcome::AcceptChannelClosed")
            .count(),
        2
    );
    assert!(production.contains("let result = (&mut bgp_listener_handle).await;"));
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
        .split_once("changed = rpc_shutdown_rx.changed(), if !rpc_shutdown_closed => {")
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
    let (status, logs, _reports) = run_bgp_ingress_fault("listener_panic", false);
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
    assert!(
        !logs.contains("BGP accept-forwarding task exited unexpectedly"),
        "{logs}"
    );
    assert!(!logs.contains("AcceptChannelClosed"), "{logs}");
}

#[test]
fn accepted_connection_forwarder_return_uses_common_shutdown_and_exits_nonzero() {
    let (status, logs, reports) = run_bgp_ingress_fault("forwarder_return", true);
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
    assert!(
        !logs.contains("BGP listener task exited unexpectedly"),
        "{logs}"
    );
    assert_eq!(logs.matches("shutdown requested").count(), 1, "{logs}");
    assert!(reports.is_empty(), "unexpected panic reports: {reports:?}");
}

#[test]
fn accepted_connection_forwarder_panic_drains_half_admitted_candidate_and_exits_nonzero() {
    let (status, logs, reports) = run_bgp_ingress_fault("forwarder_panic", true);
    assert_eq!(
        status.code(),
        Some(1),
        "forwarder panic must exit 1\n{logs}"
    );
    assert_eq!(reports.len(), 1, "one durable panic report: {reports:?}");
    assert!(
        reports[0].contains("injected BGP accept-forwarding task panic after inbound dispatch"),
        "{reports:?}"
    );
    for message in [
        "BGP accept-forwarding task exited unexpectedly",
        "initiating shutdown due to BGP accept-forwarding task failure",
        "initiating coordinated shutdown",
        "peer manager shutting down 1 peers",
        "rustbgpd exiting",
    ] {
        assert!(logs.contains(message), "missing {message:?}\n{logs}");
    }
    assert!(
        !logs.contains("BGP listener task exited unexpectedly"),
        "{logs}"
    );
    let peer_shutdown = logs.find("peer manager shutting down 1 peers").unwrap();
    let exit = logs.find("rustbgpd exiting").unwrap();
    let shutdowns = logs
        .match_indices("shutdown requested")
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    assert_eq!(shutdowns.len(), 2, "{logs}");
    assert!(
        shutdowns
            .iter()
            .all(|index| peer_shutdown < *index && *index < exit),
        "{logs}"
    );
    for absent in [
        "rustbgpd did not exit within timeout",
        "JoinHandle polled after completion",
        "peer shutdown timed out",
        "peer task join error during shutdown",
    ] {
        assert!(!logs.contains(absent), "unexpected {absent:?}\n{logs}");
    }
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
    assert!(help.contains("or unexpected RIB manager, peer manager, RPKI subsystem,"));
    assert!(help.contains("gRPC server, BGP listener task, BGP accept-forwarding task,"));
    assert!(help.contains("or injection lease expiry task exit)"));
    assert!(!help.contains("metrics/readiness server"));
    let man = output("--man");
    assert!(man.contains("legacy BGP listen mode could bind\nneither family; explicit\n.B listen_addresses\nmode could not bind every configured endpoint"));
    assert!(man.contains("the RIB manager, peer manager, RPKI subsystem,\ngRPC server, BGP listener task, BGP accept-forwarding task, or injection\nlease expiry task exited unexpectedly"));
    assert!(!man.contains("metrics/readiness\nserver"));
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

/// A metrics/readiness server that ends on its own is restarted in place
/// and never ends the daemon. The listener is broken only after a BGP session
/// is Established; that session's connection then stays open until the
/// SIGTERM sent at the end, `/readyz` answers 200 again and the restart is
/// counted.
#[test]
fn metrics_server_exit_restarts_in_place_and_keeps_bgp_sessions_established() {
    let temp = private_tempdir();
    let config_path =
        write_config_with_metrics(temp.path(), DAEMON_CHOOSES, DAEMON_CHOOSES, Some(0));
    add_loopback_neighbor(&config_path);
    let fault_path = temp.path().join("metrics-fault.sock");
    let fault_listener =
        std::os::unix::net::UnixListener::bind(&fault_path).expect("bind fault socket");
    fault_listener.set_nonblocking(true).unwrap();
    let mut daemon = spawn_daemon_with_env(
        temp.path(),
        &config_path,
        Some((
            "RUSTBGPD_TEST_METRICS_LISTENER_UNUSABLE",
            fault_path.to_str().expect("UTF-8 temp path"),
        )),
    );
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut fault = loop {
        match fault_listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("accept fault connection: {error}"),
        }
        if let Ok(Some(status)) = daemon.child.try_wait() {
            panic!(
                "rustbgpd exited before arming the fault: {status}\n{}",
                daemon.logs()
            );
        }
        assert!(
            Instant::now() < deadline,
            "fault never armed\n{}",
            daemon.logs()
        );
        thread::sleep(Duration::from_millis(50));
    };
    fault.set_nonblocking(false).unwrap();
    let mut armed = [0];
    fault.read_exact(&mut armed).expect("read armed byte");
    assert_eq!(armed, [1]);

    let metrics_port = wait_for_logged_port_with_message(&mut daemon, "metrics server listening");
    let mut peer = establish_bgp(wait_for_logged_port_with_message(
        &mut daemon,
        "BGP listener bound",
    ));
    let established = "bgp_peer_session_established{interface=\"\",peer=\"127.0.0.1\"} 1\n";
    let before = wait_for_metric_row(&mut daemon, metrics_port, established);
    assert!(
        before.contains("bgp_management_server_crashes_total{server=\"metrics\"} 0\n"),
        "the restart counter must be exported at 0\n{before}"
    );
    let readyz = http_get(metrics_port, "/readyz").expect("/readyz before the fault");
    assert!(readyz.starts_with("HTTP/1.1 200 OK"), "{readyz}");

    fault.write_all(&[1]).expect("trigger the listener fault");

    // Only the restarted server can report its own restart.
    let after = wait_for_metric_row(
        &mut daemon,
        metrics_port,
        "bgp_management_server_crashes_total{server=\"metrics\"} 1\n",
    );
    assert!(
        after.contains(established),
        "the session must stay Established\n{after}"
    );
    let readyz = http_get(metrics_port, "/readyz").expect("/readyz after the restart");
    assert!(readyz.starts_with("HTTP/1.1 200 OK"), "{readyz}");
    let logs = daemon.logs();
    for message in [
        "listener socket unusable; stopping its accept loop",
        "metrics/readiness server exited unexpectedly; restarting it in place",
    ] {
        assert!(logs.contains(message), "missing {message:?}\n{logs}");
    }
    assert!(!logs.contains("initiating coordinated shutdown"), "{logs}");

    let sigterm = Command::new("kill")
        .args(["-TERM", &daemon.child.id().to_string()])
        .status()
        .expect("send SIGTERM");
    assert!(sigterm.success(), "kill -TERM failed: {sigterm}");
    // The first NOTIFICATION on the original connection is the requested stop.
    observe_administrative_shutdown(&mut peer);
    let status = daemon.wait_within(Duration::from_secs(120));
    let logs = daemon.logs();
    assert_eq!(
        status.code(),
        Some(0),
        "a restarted metrics/readiness server must not fail the later stop\n{logs}"
    );
    assert_eq!(
        logs.matches("metrics/readiness server exited unexpectedly")
            .count(),
        1,
        "{logs}"
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

/// The owner-only gRPC socket, once the daemon answers on it.
fn wait_for_owner_socket(daemon: &mut Daemon, dir: &Path) -> String {
    let grpc_addr = format!("unix://{}", dir.join("runtime/grpc.sock").display());
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let output = rbgp(&grpc_addr, &["neighbor"]);
        if output.status.success() {
            return grpc_addr;
        }
        if let Ok(Some(status)) = daemon.child.try_wait() {
            panic!(
                "rustbgpd exited before serving gRPC: {status}\n{}",
                daemon.logs()
            );
        }
        assert!(
            Instant::now() < deadline,
            "rustbgpd never served gRPC\nstderr:\n{}\n{}",
            String::from_utf8_lossy(&output.stderr),
            daemon.logs()
        );
        thread::sleep(Duration::from_millis(100));
    }
}

fn rbgp_ok(daemon: &Daemon, grpc_addr: &str, args: &[&str]) {
    let output = rbgp(grpc_addr, args);
    assert!(
        output.status.success(),
        "rbgp {args:?} failed\nstdout:\n{}\nstderr:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        daemon.logs()
    );
}

/// SIGTERM the daemon (warm checkpoint off, the default) and return the
/// restart-marker window its coordinated shutdown published, if any.
fn sigterm_restart_marker_window(daemon: &mut Daemon, dir: &Path) -> Option<u64> {
    let sigterm = Command::new("kill")
        .args(["-TERM", &daemon.child.id().to_string()])
        .status()
        .expect("send SIGTERM");
    assert!(sigterm.success(), "kill -TERM failed: {sigterm}");
    let status = daemon.wait_within(Duration::from_secs(120));
    let logs = daemon.logs();
    assert_eq!(status.code(), Some(0), "SIGTERM must exit 0\n{logs}");
    let window = logs
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|event| {
            event["fields"]["message"]
                == "finished GR restart marker publication for coordinated shutdown"
        })
        .map(|event| {
            event["fields"]["restart_time_secs"]
                .as_u64()
                .unwrap_or_else(|| panic!("marker publication names its window\n{logs}"))
        });
    assert_eq!(
        dir.join("runtime/gr-restart.toml").exists(),
        window.is_some(),
        "the marker file agrees with the publication log\n{logs}"
    );
    window
}

/// A Graceful Restart neighbor added through gRPC after boot is covered by
/// the restart marker: without it the next start is cold and the neighbor's
/// helper flushes the routes it kept for us.
#[test]
fn sigterm_marker_window_covers_a_gr_neighbor_added_at_runtime() {
    let temp = private_tempdir();
    let config_path = write_config(temp.path(), DAEMON_CHOOSES, DAEMON_CHOOSES);
    let mut daemon = spawn_daemon(temp.path(), &config_path);
    let grpc_addr = wait_for_owner_socket(&mut daemon, temp.path());
    rbgp_ok(
        &daemon,
        &grpc_addr,
        &["neighbor", "127.0.0.2", "add", "--remote-asn", "65002"],
    );
    assert_eq!(
        sigterm_restart_marker_window(&mut daemon, temp.path()),
        Some(120),
        "the default gr_restart_time of the added neighbor"
    );
}

/// Raising `gr_restart_time` at runtime widens the marker window to match.
#[test]
fn sigterm_marker_window_follows_a_gr_restart_time_raised_at_runtime() {
    let temp = private_tempdir();
    let config_path = write_config(temp.path(), DAEMON_CHOOSES, DAEMON_CHOOSES);
    let mut config = std::fs::read_to_string(&config_path).expect("read test config");
    config.push_str(
        r#"
[peer_groups.gr]
gr_restart_time = 30

[[neighbors]]
address = "127.0.0.2"
remote_asn = 65002
peer_group = "gr"
"#,
    );
    std::fs::write(&config_path, config).expect("write test config");
    let group = temp.path().join("peer-group-gr.json");
    std::fs::write(&group, r#"{"gr_restart_time": 300}"#).expect("write peer group");
    let mut daemon = spawn_daemon(temp.path(), &config_path);
    let grpc_addr = wait_for_owner_socket(&mut daemon, temp.path());
    rbgp_ok(
        &daemon,
        &grpc_addr,
        &[
            "peer-group",
            "set",
            "gr",
            "--from-file",
            group.to_str().expect("utf-8 temp path"),
        ],
    );
    assert_eq!(
        sigterm_restart_marker_window(&mut daemon, temp.path()),
        Some(300)
    );
}
