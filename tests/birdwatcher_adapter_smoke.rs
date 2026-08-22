//! Smoke test: the external birdwatcher-adapter serves its
//! Birdwatcher-shaped status/peer/accepted-route subset from a live rustbgpd
//! gRPC endpoint.
//! (The adapter replaced the removed in-daemon looking glass server;
//! this test pins the REST surface operators migrate to.)
//!
//! Starts one birdwatcher-adapter against an absent gRPC Unix socket,
//! observes its `502 Bad Gateway`, then starts rustbgpd without restarting
//! the adapter and fetches `/status`,
//! `/protocols/bgp`, and `/routes/peer/{peer}` and asserts the
//! response shapes.
//!
//! A second neighbor (127.0.0.1) is driven by a minimal in-test BGP
//! speaker that establishes a real session and announces two routes: a
//! clean one (exercises the per-route `age` receive timestamp) and one
//! carrying the daemon's own AS in its AS_PATH, which the loop check
//! rejects and the reject-retention store keeps — exercising the
//! `/routes/filtered/{id}` view (reason token + synthesized reason
//! community) and the real `routes.filtered` neighbor-summary count
//! end-to-end.
//! The clean prefix carries two Add-Path candidates so the exact-route
//! views also prove multiplicity and order.
//!
//! A third neighbor (127.0.0.2, announce-nothing receiver) exercises the
//! `/routes/noexport/{id}` view from both sides: the accepted route is
//! exported to the receiver (so its noexport view is empty) while split
//! horizon suppresses it toward its announcer (so it appears in the
//! announcer's noexport view with the gate name and the synthesized
//! noexport-reason community).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Proc {
    child: Child,
    name: &'static str,
    stderr_path: PathBuf,
}
type DaemonPorts = (Proc, u16, u16, u16);

impl Proc {
    fn stderr(&self) -> String {
        std::fs::read_to_string(&self.stderr_path)
            .unwrap_or_else(|e| format!("<failed to read {} stderr: {e}>", self.name))
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Port the spawned process is asked for when it should choose its own.
///
/// This test never picks a port itself. Discovering one by binding
/// `127.0.0.1:0` and dropping the listener reserves nothing — the kernel
/// can hand that exact port to a parallel test before the spawned process
/// binds it, and the spawn then dies with `AddrInUse` (LAN-941, reproduced
/// here as `birdwatcher-adapter exited before serving /status`). Asking
/// for port 0 makes the process that serves the port the one that binds
/// it; it reports the address it got and the test reads it back.
const PROCESS_CHOOSES: u16 = 0;

/// Poll `log` until `extract` finds what the process reported, failing
/// fast if the process dies first.
fn wait_for_logged<T>(
    proc_: &mut Proc,
    log: &Path,
    what: &str,
    extract: impl Fn(&str) -> Option<T>,
) -> T {
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        let logged = std::fs::read_to_string(log).unwrap_or_default();
        if let Some(value) = extract(&logged) {
            return value;
        }
        if let Ok(Some(status)) = proc_.child.try_wait() {
            panic!(
                "{} exited before reporting {what}: {status}\nstderr:\n{}",
                proc_.name,
                proc_.stderr()
            );
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "{} did not report {what} within timeout\nstderr:\n{}",
        proc_.name,
        proc_.stderr()
    );
}

/// Port from the first `"<field>":"<addr>:<port>"` pair in the daemon's
/// JSON log whose address starts with `prefix`.
fn logged_port(logs: &str, field: &str, prefix: &str) -> Option<u16> {
    logs.split(&format!("\"{field}\":\""))
        .skip(1)
        .filter_map(|rest| rest.split('"').next())
        .find(|addr| addr.starts_with(prefix) && !addr.ends_with(":0"))
        .and_then(|addr| addr.rsplit(':').next()?.parse().ok())
}

/// Minimal HTTP/1.1 GET over a raw TcpStream — avoids an HTTP client
/// dev-dependency for a smoke test.
fn http_get(port: u16, path: &str) -> Option<(u16, String)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    let (head, body) = response.split_once("\r\n\r\n")?;
    let status: u16 = head.split_whitespace().nth(1)?.parse().ok()?;
    Some((status, body.to_string()))
}

fn get_json(port: u16, path: &str, context: &str) -> serde_json::Value {
    let (status, body) =
        http_get(port, path).unwrap_or_else(|| panic!("{context}: GET {path} failed"));
    assert_eq!(
        status, 200,
        "{context}: GET {path} returned {status}: {body}"
    );
    serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("{context}: GET {path} body is not JSON ({e}): {body}"))
}

fn wait_for_exact_json_error(port: u16, path: &str, expected_status: u16, message: &str) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let (status, body) = http_get(port, path).expect("HTTP error response");
        if status == expected_status {
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&body).unwrap(),
                serde_json::json!({ "message": message }),
                "GET {path} returned the wrong JSON error"
            );
            return;
        }
        assert!(
            Instant::now() < deadline,
            "GET {path} did not reach HTTP {expected_status}: last response was {status} {body}"
        );
        thread::sleep(Duration::from_millis(200));
    }
}

fn wait_for_http_status(port: u16, path: &str, expected: u16, proc_: &mut Proc) {
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        if matches!(http_get(port, path), Some((status, _)) if status == expected) {
            return;
        }
        if let Ok(Some(status)) = proc_.child.try_wait() {
            panic!(
                "{} exited before serving {path}: {status}\nstderr:\n{}",
                proc_.name,
                proc_.stderr()
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!(
        "{} did not serve {path} with HTTP {expected} within timeout\nstderr:\n{}",
        proc_.name,
        proc_.stderr()
    );
}

fn wait_for_http(port: u16, path: &str, proc_: &mut Proc) {
    wait_for_http_status(port, path, 200, proc_);
}

/// Wait until `port` accepts a TCP connection (daemon gRPC readiness).
fn wait_for_tcp(port: u16, proc_: &mut Proc) {
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        if let Ok(Some(status)) = proc_.child.try_wait() {
            panic!(
                "{} exited before listening on {port}: {status}\nstderr:\n{}",
                proc_.name,
                proc_.stderr()
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!(
        "{} did not listen on {port} within timeout\nstderr:\n{}",
        proc_.name,
        proc_.stderr()
    );
}

/// Spawn the daemon on ports it chooses itself and wait for its gRPC TCP
/// listener. Returns the daemon plus the TCP gRPC and IPv4 BGP ports it
/// reports binding, plus metrics, which the rest needs; the adapter still
/// talks to `grpc_socket`.
fn spawn_daemon_listening(dir: &Path, grpc_socket: &Path, token_path: &Path) -> DaemonPorts {
    if grpc_socket.exists() {
        std::fs::remove_file(grpc_socket).expect("remove stale test gRPC socket");
    }
    let config_path = write_config(
        dir,
        PROCESS_CHOOSES,
        PROCESS_CHOOSES,
        PROCESS_CHOOSES,
        grpc_socket,
        token_path,
    );
    let daemon_stdout = dir.join("rustbgpd.stdout.log");
    let daemon_stderr = dir.join("rustbgpd.stderr.log");
    let mut daemon = Proc {
        child: Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
            .arg(&config_path)
            .stdout(Stdio::from(
                std::fs::File::create(&daemon_stdout).expect("daemon stdout log"),
            ))
            .stderr(Stdio::from(
                std::fs::File::create(&daemon_stderr).expect("daemon stderr log"),
            ))
            .spawn()
            .expect("spawn rustbgpd"),
        name: "rustbgpd",
        stderr_path: daemon_stderr,
    };
    // The daemon logs JSON to stdout: `bound_addr` on the gRPC TCP
    // listener, and `addr` on the exact loopback BGP listener used below.
    let grpc_port = wait_for_logged(
        &mut daemon,
        &daemon_stdout,
        "a bound gRPC listener",
        |logs| logged_port(logs, "bound_addr", "127.0.0.1:"),
    );
    let bgp_port = wait_for_logged(
        &mut daemon,
        &daemon_stdout,
        "a bound IPv4 BGP listener",
        |logs| logged_port(logs, "addr", "127.0.0.1:"),
    );
    let metrics_port = wait_for_logged(
        &mut daemon,
        &daemon_stdout,
        "a bound metrics listener",
        |logs| {
            logs.lines()
                .find(|line| line.contains(r#""message":"metrics server listening""#))
                .and_then(|line| logged_port(line, "addr", "127.0.0.1:"))
        },
    );
    assert_ne!(bgp_port, metrics_port, "BGP and metrics ports must differ");
    wait_for_tcp(grpc_port, &mut daemon);
    (daemon, grpc_port, bgp_port, metrics_port)
}

/// Mutation proof: dropping Tier enforcement, the bearer credential, or the
/// direct unauthenticated call makes this stop observing `Unauthenticated`.
fn wait_for_unauthenticated_get_global(port: u16, proc_: &mut Proc) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build gRPC probe runtime");
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        let result = runtime.block_on(async {
            let endpoint = format!("http://127.0.0.1:{port}");
            let mut client =
                rustbgpd_api::proto::global_service_client::GlobalServiceClient::connect(endpoint)
                    .await
                    .ok()?;
            Some(
                client
                    .get_global(rustbgpd_api::proto::GetGlobalRequest {})
                    .await,
            )
        });
        if matches!(
            result,
            // Canonical gRPC status 16 = UNAUTHENTICATED. The root package
            // intentionally has no direct tonic dependency.
            Some(Err(ref status)) if status.code() as i32 == 16
        ) {
            return;
        }
        if let Ok(Some(status)) = proc_.child.try_wait() {
            panic!(
                "{} exited before the unauthenticated gRPC probe: {status}\nstderr:\n{}",
                proc_.name,
                proc_.stderr()
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!(
        "unauthenticated GetGlobal was not rejected\ndaemon stderr:\n{}",
        proc_.stderr()
    );
}

fn write_config(
    dir: &Path,
    grpc_port: u16,
    bgp_port: u16,
    metrics_port: u16,
    grpc_socket: &Path,
    token_path: &Path,
) -> PathBuf {
    let runtime_dir = dir.join("runtime");
    std::fs::create_dir_all(&runtime_dir).expect("create runtime dir");
    let config_path = dir.join("rustbgpd.toml");
    let config = format!(
        r#"
[security.grpc]
enforcement = "tier"

[security.grpc.roles]
"rustbgpd://observer/birdwatcher-test" = "observer"

[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = {bgp_port}
listen_addresses = ["127.0.0.1"]
runtime_state_dir = "{runtime_dir}"

[global.telemetry]
log_format = "json"
prometheus_addr = "127.0.0.1:{metrics_port}"

[policy.reject_retention]
capacity = 2
[global.telemetry.grpc_tcp]
address = "127.0.0.1:{grpc_port}"
token_file = "{token_path}"
principal = "rustbgpd://observer/birdwatcher-test"

[global.telemetry.grpc_uds]
path = "{grpc_socket}"
mode = 0o600
token_file = "{token_path}"
principal = "rustbgpd://observer/birdwatcher-test"

[[neighbors]]
address = "192.0.2.10"
remote_asn = 65010
description = "smoke peer"
graceful_restart = false

[[neighbors]]
address = "127.0.0.1"
remote_asn = 65020
description = "live peer"
graceful_restart = false
max_prefixes = 5
route_server_client = true

[neighbors.add_path]
receive = true
receive_max = 4

[[neighbors]]
address = "127.0.0.2"
remote_asn = 65030
description = "receiver peer"
graceful_restart = false

[neighbors.add_path]
send = true
send_max = 4
"#,
        runtime_dir = runtime_dir.display(),
        grpc_socket = grpc_socket.display(),
        token_path = token_path.display(),
    );
    let parsed: toml::Value = toml::from_str(&config).expect("test config must parse");
    let graceful_restart = parsed["neighbors"]
        .as_array()
        .expect("neighbors must be an array")
        .iter()
        .map(|neighbor| {
            neighbor
                .get("graceful_restart")
                .and_then(toml::Value::as_bool)
        })
        .collect::<Vec<_>>();
    assert_eq!(graceful_restart, vec![Some(false); 3]);
    let principal = "rustbgpd://observer/birdwatcher-test";
    assert_eq!(
        parsed["security"]["grpc"]["enforcement"].as_str(),
        Some("tier")
    );
    assert_eq!(
        parsed["global"]["telemetry"]["grpc_tcp"]["principal"].as_str(),
        Some(principal)
    );
    assert_eq!(
        parsed["global"]["telemetry"]["grpc_uds"]["path"].as_str(),
        Some(grpc_socket.to_str().expect("UTF-8 test socket path"))
    );
    assert_eq!(
        parsed["global"]["telemetry"]["grpc_uds"]["principal"].as_str(),
        Some(principal)
    );
    assert_eq!(
        parsed["security"]["grpc"]["roles"][principal].as_str(),
        Some("observer"),
        "mutation proof: adapter smoke must pin the least-privilege observer role"
    );
    std::fs::write(&config_path, config).expect("write test config");
    config_path
}

/// Minimal BGP speaker: connect to the daemon's listen port, complete
/// the OPEN/KEEPALIVE handshake as legacy AS 65020 (no capabilities —
/// implicit IPv4 unicast), and announce two routes: 10.99.0.0/24 with a
/// clean path (accepted) and 10.98.0.0/24 with the daemon's own AS in
/// the path (rejected as an AS_PATH loop, lands in reject retention).
/// The returned stream must stay alive for the session to survive; the
/// daemon's own messages are left unread (a handful of bytes, well
/// within the socket buffer for the test's lifetime).
fn establish_bgp_and_announce(bgp_port: u16) -> TcpStream {
    use rustbgpd_wire::attribute::{AsPath, AsPathSegment, Origin, PathAttribute};
    use rustbgpd_wire::message::{Message, encode_message};
    use rustbgpd_wire::open::OpenMessage;
    use rustbgpd_wire::update::UpdateMessage;
    use rustbgpd_wire::{AddPathFamily, AddPathMode, Afi, Capability, LargeCommunity, Safi};

    let mut stream = TcpStream::connect(("127.0.0.1", bgp_port)).expect("connect to BGP port");
    let open = Message::Open(OpenMessage {
        version: 4,
        my_as: 65020,
        hold_time: 90,
        bgp_identifier: "10.0.0.2".parse().unwrap(),
        capabilities: vec![
            Capability::FourOctetAs { asn: 65020 },
            Capability::AddPath(vec![AddPathFamily {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                send_receive: AddPathMode::Send,
            }]),
        ],
    });
    let encode_update =
        |as_sequence: Vec<u32>, nlri: &'static [u8], med: u32, forge_reason: bool| {
            let mut attrs = Vec::new();
            let mut attributes = vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(as_sequence)],
                }),
                // Non-loopback: the daemon's UPDATE validation rejects a
                // loopback NEXT_HOP (subcode 8).
                PathAttribute::NextHop("192.0.2.99".parse().unwrap()),
                PathAttribute::Med(med),
            ];
            if forge_reason {
                attributes.push(PathAttribute::Communities(vec![
                    (65520 << 16) | 99,
                    (64512 << 16) | 3,
                ]));
                attributes.push(PathAttribute::LargeCommunities(vec![
                    LargeCommunity::new(65001, 1101, 99),
                    LargeCommunity::new(65001, 999, 7),
                    LargeCommunity::new(64496, 65520, 99),
                    LargeCommunity::new(64496, 65521, 3),
                ]));
            }
            rustbgpd_wire::attribute::encode_path_attributes(&attributes, &mut attrs, true, false)
                .expect("encode path attributes");
            Message::Update(UpdateMessage {
                withdrawn_routes: bytes::Bytes::new(),
                path_attributes: attrs.into(),
                nlri: bytes::Bytes::from_static(nlri),
            })
        };
    // RFC 7911 NLRI: four-byte path id, then the ordinary prefix encoding.
    let accepted_11 = encode_update(vec![65020], &[0, 0, 0, 11, 24, 10, 99, 0], 10, false);
    let accepted_22 = encode_update(vec![65020], &[0, 0, 0, 22, 24, 10, 99, 0], 20, false);
    // 10.98.0.0/24, daemon's own AS 65001 in path → as_path_loop reject.
    let looped = encode_update(vec![65020, 65001], &[0, 0, 0, 30, 24, 10, 98, 0], 30, true);
    for msg in [
        &open,
        &Message::Keepalive,
        &accepted_11,
        &accepted_22,
        &looped,
    ] {
        let encoded = encode_message(msg).expect("encode BGP message");
        stream.write_all(&encoded).expect("write BGP message");
    }
    stream
}

fn announce_additional_route(stream: &mut TcpStream) {
    use rustbgpd_wire::attribute::{AsPath, AsPathSegment, Origin, PathAttribute};
    use rustbgpd_wire::message::{Message, encode_message};
    use rustbgpd_wire::update::UpdateMessage;

    let mut attrs = Vec::new();
    rustbgpd_wire::attribute::encode_path_attributes(
        &[
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65020])],
            }),
            PathAttribute::NextHop("192.0.2.99".parse().unwrap()),
            PathAttribute::Med(31),
        ],
        &mut attrs,
        true,
        false,
    )
    .expect("encode additional route attributes");
    let update = Message::Update(UpdateMessage {
        withdrawn_routes: bytes::Bytes::new(),
        path_attributes: attrs.into(),
        nlri: bytes::Bytes::from_static(&[0, 0, 0, 31, 24, 10, 97, 0]),
    });
    stream
        .write_all(&encode_message(&update).expect("encode additional route"))
        .expect("announce additional route");
}

fn announce_third_candidate(stream: &mut TcpStream) {
    use rustbgpd_wire::attribute::{AsPath, AsPathSegment, Origin, PathAttribute};
    use rustbgpd_wire::message::{Message, encode_message};
    use rustbgpd_wire::update::UpdateMessage;

    let mut attrs = Vec::new();
    rustbgpd_wire::attribute::encode_path_attributes(
        &[
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65020])],
            }),
            PathAttribute::NextHop("192.0.2.99".parse().unwrap()),
            PathAttribute::Med(30),
        ],
        &mut attrs,
        true,
        false,
    )
    .expect("encode third candidate attributes");
    let update = Message::Update(UpdateMessage {
        withdrawn_routes: bytes::Bytes::new(),
        path_attributes: attrs.into(),
        nlri: bytes::Bytes::from_static(&[0, 0, 0, 33, 24, 10, 99, 0]),
    });
    stream
        .write_all(&encode_message(&update).expect("encode third candidate"))
        .expect("announce third candidate");
}

fn announce_additional_rejected_route(stream: &mut TcpStream) {
    use rustbgpd_wire::attribute::{AsPath, AsPathSegment, Origin, PathAttribute};
    use rustbgpd_wire::message::{Message, encode_message};
    use rustbgpd_wire::update::UpdateMessage;

    let mut attrs = Vec::new();
    rustbgpd_wire::attribute::encode_path_attributes(
        &[
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65020, 65001])],
            }),
            PathAttribute::NextHop("192.0.2.99".parse().unwrap()),
        ],
        &mut attrs,
        true,
        false,
    )
    .expect("encode additional rejected route attributes");
    for (path_id, prefix) in [(32, [10, 96, 0]), (33, [10, 95, 0])] {
        let mut nlri = vec![0, 0, 0, path_id, 24];
        nlri.extend_from_slice(&prefix);
        let update = Message::Update(UpdateMessage {
            withdrawn_routes: bytes::Bytes::new(),
            path_attributes: attrs.clone().into(),
            nlri: nlri.into(),
        });
        stream
            .write_all(&encode_message(&update).expect("encode additional rejected route"))
            .expect("announce additional rejected route");
    }
}

/// Second minimal speaker: complete the handshake as AS 65030 from
/// source address 127.0.0.2 (the daemon maps sessions to configured
/// neighbors by source IP) and announce nothing — a pure receiver, so
/// the daemon's export path advertises the accepted route to it. The
/// std TcpStream API cannot bind a source address; borrow tokio's
/// TcpSocket for the connect and hand back a blocking std stream.
fn establish_bgp_receiver(bgp_port: u16) -> TcpStream {
    use rustbgpd_wire::message::{Message, encode_message};
    use rustbgpd_wire::open::OpenMessage;
    use rustbgpd_wire::{AddPathFamily, AddPathMode, Afi, Capability, Safi};

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .expect("build tokio runtime");
    let stream = rt
        .block_on(async {
            let socket = tokio::net::TcpSocket::new_v4()?;
            socket.bind("127.0.0.2:0".parse().unwrap())?;
            socket
                .connect(format!("127.0.0.1:{bgp_port}").parse().unwrap())
                .await?
                .into_std()
        })
        .expect("connect to BGP port from 127.0.0.2");
    stream
        .set_nonblocking(false)
        .expect("blocking receiver stream");

    let open = Message::Open(OpenMessage {
        version: 4,
        my_as: 65030,
        hold_time: 90,
        bgp_identifier: "10.0.0.3".parse().unwrap(),
        capabilities: vec![Capability::AddPath(vec![AddPathFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            send_receive: AddPathMode::Receive,
        }])],
    });
    let mut stream = stream;
    for msg in [&open, &Message::Keepalive] {
        let encoded = encode_message(msg).expect("encode BGP message");
        stream.write_all(&encoded).expect("write BGP message");
    }
    stream
}

/// Inverse of the servers' `format_epoch_secs` (`"YYYY-MM-DD HH:MM:SS"`
/// → Unix epoch seconds) so two `age` renderings can be compared with
/// clock-recovery jitter tolerance. Howard Hinnant's `days_from_civil`.
fn epoch_from_timestamp(s: &str) -> u64 {
    let parts: Vec<u64> = s
        .split(|c: char| !c.is_ascii_digit())
        .filter(|p| !p.is_empty())
        .map(|p| p.parse().expect("numeric timestamp field"))
        .collect();
    let [y, m, d, h, mi, se, ..] = parts[..] else {
        panic!("unexpected timestamp shape: {s:?}");
    };
    let y = if m <= 2 { y - 1 } else { y };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    days * 86_400 + h * 3_600 + mi * 60 + se
}

#[test]
fn ixp_contract_gate_tracks_adapter_and_live_smoke_changes() {
    let workflow = include_str!("../.github/workflows/ixp-compat.yml");
    for path in [
        "examples/birdwatcher-adapter/**",
        "tests/birdwatcher_adapter_smoke.rs",
    ] {
        let entry = format!("      - \"{path}\"");
        assert_eq!(workflow.lines().filter(|line| *line == entry).count(), 2);
    }
    let installer = "      - uses: ./.github/actions/install-protobuf";
    assert_eq!(workflow.matches(installer).count(), 1);
    let checkout = workflow.find("actions/checkout@v7").unwrap();
    let installer = workflow.find(installer).unwrap();
    let oracle = workflow
        .find("tests/compat/ixp-manager-birdseye/run.sh")
        .unwrap();
    assert!(checkout < installer && installer < oracle);

    let consumer = include_str!("compat/ixp-manager-birdseye/adapter-consumer.php");
    for journey in [
        "$consumer->symbols()",
        "$consumer->protocolTable(",
        "$consumer->routesForTable(",
    ] {
        assert_eq!(
            consumer.matches(journey).count(),
            1,
            "pinned live consumer journey drifted: {journey}"
        );
    }
    let adapter = include_str!("../examples/birdwatcher-adapter/src/main.rs");
    let causes = adapter
        .split_once("fn arouteserver_reject_cause(")
        .unwrap()
        .1
        .split_once("fn apply_ars_family(")
        .unwrap()
        .0
        .split_whitespace()
        .collect::<String>();
    for exact in [
        r#"("policy_reject","rs-hygiene:reject-long-as-path")=>Some(1)"#,
        r#"("policy_reject","rs-hygiene:reject-black-list-prefix")iflate_cause()=>Some(3)"#,
        r#"("next_hop_ownership",_)=>Some(5)"#,
        r#"iflate_cause()&&detail.ends_with(":reject-irrdb-origin-as-filtered")=>{Some(9)}"#,
        r#"iflate_cause()&&detail.ends_with(":reject-irrdb-prefix-filtered")=>{Some(12)}"#,
    ] {
        assert!(causes.contains(exact), "cause mapping drifted: {exact}");
    }
    assert!(causes.contains("(3..=128).contains(&route.prefix_length)"));
    assert!(causes.contains("address.segments()[0]&0xe000==0x2000"));
    let inventory = adapter
        .split_once("async fn protocol_rows(")
        .unwrap()
        .1
        .split_once("async fn protocols_bgp(")
        .unwrap()
        .0;
    assert_eq!(inventory.matches("list_neighbors(state).await?").count(), 1);
    assert_eq!(inventory.matches(".await?").count(), 1);
    assert!(!inventory.contains("PolicyServiceClient"), "{inventory}");
    assert!(!inventory.contains("ListRejectedRoutes"), "{inventory}");
    assert!(!inventory.contains("list_rejected_routes"), "{inventory}");
    let table = adapter
        .split_once("async fn routes_table(")
        .unwrap()
        .1
        .split_once("async fn routes_export(")
        .unwrap()
        .0;
    assert_eq!(
        adapter.matches(".route(\"/routes/table/{table}\"").count(),
        1
    );
    assert_eq!(table.matches("list_neighbors(&state).await?").count(), 1);
    assert_eq!(
        table.matches("list_received_routes(request).await").count(),
        1
    );
    assert_eq!(table.matches("list_best_routes(request).await").count(), 1);
    assert!(table.contains("neighbor_address: String::new()"), "{table}");
    assert!(!table.contains("for neighbor"), "{table}");
    let inference = adapter
        .split_once("fn table_address_family(")
        .unwrap()
        .1
        .split_once("async fn routes_table(")
        .unwrap()
        .0;
    for family in ["Ipv4Unicast", "Ipv6Unicast", "Unspecified"] {
        assert!(inference.contains(family), "missing {family}: {inference}");
    }
}

#[test]
fn adapter_serves_birdwatcher_shaped_status_peer_accepted_filtered_and_noexport_subset() {
    let temp = tempfile::tempdir().expect("create temp dir");
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))
        .expect("make temp dir private");
    let grpc_socket = temp.path().join("rustbgpd.grpc.sock");
    let token_path = temp.path().join("grpc-token");
    let aliases_path = temp.path().join("protocol-aliases");
    std::fs::write(&token_path, "birdwatcher-smoke-token\n").expect("write test token");
    std::fs::write(
        &aliases_path,
        "pb_0001_as65020=127.0.0.1@master4\npb_0002_as65030=127.0.0.2@master4\n",
    )
    .expect("write initial aliases");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"));
    let ars_context = temp.path().join("arouteserver-context.yml");
    let context =
        std::fs::read_to_string(workspace.join("tests/interop/m90-differential/context.yml"))
            .expect("read renderer context")
            .replacen("192.0.2.11", "127.0.0.1", 1);
    std::fs::write(&ars_context, context).expect("write smoke renderer context");
    let ars_output = temp.path().join("arouteserver-render");
    let rendered = Command::new(&cargo)
        .current_dir(workspace)
        .args(["run", "--quiet", "-p", "rs-config-render", "--"])
        .arg("--context")
        .arg(&ars_context)
        .arg("--out-dir")
        .arg(&ars_output)
        .status()
        .expect("run rs-config-render");
    assert!(
        rendered.success(),
        "rs-config-render must emit smoke artifact"
    );
    let ars_artifact = ars_output.join("birdwatcher-reject-communities.json");
    assert!(
        ars_artifact.is_file(),
        "renderer must emit startup artifact"
    );

    // Spawn the adapter before its Unix socket exists. Built via
    // `cargo run` (same fallback pattern the rbgp test helper uses) —
    // the workspace build has usually compiled it already.
    let adapter_stderr = temp.path().join("adapter.stderr.log");
    let mut adapter = Proc {
        child: Command::new(&cargo)
            .args(["run", "--quiet", "-p", "birdwatcher-adapter", "--"])
            .arg("--grpc-addr")
            .arg(format!("unix://{}", grpc_socket.display()))
            .arg("--grpc-token-file")
            .arg(&token_path)
            .arg("--listen")
            .arg(format!("127.0.0.1:{PROCESS_CHOOSES}"))
            .arg("--protocol-alias-file")
            .arg(&aliases_path)
            .arg("--arouteserver-reject-communities-file")
            .arg(&ars_artifact)
            .args(["--max-routes", "2"])
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                std::fs::File::create(&adapter_stderr).expect("adapter stderr log"),
            ))
            .spawn()
            .expect("spawn birdwatcher-adapter"),
        name: "birdwatcher-adapter",
        stderr_path: adapter_stderr.clone(),
    };
    let adapter_pid = adapter.child.id();
    // The adapter logs the address it bound. Its only loopback address is
    // that listener (the daemon endpoint is a Unix socket), and the text
    // format interleaves ANSI escapes with the field name, so match on the
    // address itself rather than on `addr=`.
    let adapter_port = wait_for_logged(
        &mut adapter,
        &adapter_stderr,
        "a bound HTTP listener",
        |logs| {
            logs.split("127.0.0.1:")
                .nth(1)?
                .split(|c: char| !c.is_ascii_digit())
                .next()?
                .parse()
                .ok()
        },
    );
    wait_for_http_status(adapter_port, "/status", 502, &mut adapter);
    for path in [
        "/route/10.99.0.0%2F24/protocol/pb_0001_as65020",
        "/route/10.99.0.0%2F24/export/pb_0002_as65030",
        "/route/10.99.0.128%2F25/table/master4",
        "/routes/table/master4",
    ] {
        wait_for_exact_json_error(adapter_port, path, 502, "Upstream daemon request failed");
    }

    // Now start the daemon. The adapter's lazy UDS channel must reconnect on
    // a later request; replacing the adapter would make the PID assertion red.
    // A parallel TCP listener retains the smoke's explicit unauthenticated
    // rejection probe while the adapter itself uses only the UDS.
    let (mut daemon, grpc_port, bgp_port, metrics_port) =
        spawn_daemon_listening(temp.path(), &grpc_socket, &token_path);
    wait_for_unauthenticated_get_global(grpc_port, &mut daemon);
    wait_for_http(adapter_port, "/status", &mut adapter);
    assert_eq!(
        adapter.child.id(),
        adapter_pid,
        "adapter must recover in place"
    );

    // /status — birdwatcher envelope with the api block and a status
    // object carrying the clock fields.
    let status = get_json(adapter_port, "/status", "adapter");
    assert!(
        status["api"].is_object(),
        "/status must carry api: {status}"
    );
    for key in [
        "Version",
        "result_from_cache",
        "version",
        "from_cache",
        "max_routes",
    ] {
        assert!(
            status["api"].get(key).is_some(),
            "missing api.{key}: {status}"
        );
    }
    assert_eq!(
        status["api"]["Version"], status["api"]["version"],
        "{status}"
    );
    assert_eq!(status["api"]["max_routes"], 2, "{status}");
    assert!(
        status["api"]["version"]
            .as_str()
            .is_some_and(|version| version.starts_with("rustbgpd ")),
        "api.version is product identity, not a Bird's Eye compatibility claim: {status}"
    );
    for key in ["server_time", "last_reboot", "last_reconfig"] {
        assert!(
            status["status"][key]
                .as_str()
                .is_some_and(|value| value.ends_with("+00:00")),
            "status.{key} must be RFC3339 with a UTC offset: {status}"
        );
    }
    let current_server = status["status"]["current_server"]
        .as_str()
        .unwrap_or_default();
    assert!(
        !current_server.is_empty(),
        "/status must carry status.current_server: {status}"
    );
    let last_reconfig = status["status"]["last_reconfig"]
        .as_str()
        .unwrap_or_default();
    assert!(
        !last_reconfig.is_empty(),
        "/status must carry the accepted generation timestamp: {status}"
    );
    let current_server_epoch = epoch_from_timestamp(current_server);
    let last_reconfig_epoch = epoch_from_timestamp(last_reconfig);
    assert!(
        last_reconfig_epoch > 0,
        "last_reconfig must be a parseable timestamp: {last_reconfig:?}"
    );
    assert!(
        last_reconfig_epoch <= current_server_epoch,
        "last_reconfig must not be later than current_server: {status}"
    );
    assert!(
        current_server_epoch - last_reconfig_epoch <= 120,
        "initial accepted generation must be recent after daemon startup: {status}"
    );

    // /protocols/bgp — the configured peer appears under its
    // "bgp_<addr>" protocol id with identity fields.
    let protocols = get_json(adapter_port, "/protocols/bgp", "adapter");
    let peer = &protocols["protocols"]["bgp_192.0.2.10"];
    assert!(
        peer.is_object(),
        "response must contain the configured peer: {protocols}"
    );
    assert_eq!(peer["neighbor_address"], "192.0.2.10", "{protocols}");
    assert_eq!(peer["neighbor_as"], 65010, "{protocols}");
    assert_eq!(peer["connection"], " Active", "{protocols}");
    for field in ["source_address", "keepalive", "bgp_session"] {
        assert!(peer.get(field).is_none(), "{field}: {protocols}");
    }

    let alias_peer = &protocols["protocols"]["pb_0001_as65020"];
    assert_eq!(alias_peer["protocol"], "pb_0001_as65020", "{protocols}");
    assert_eq!(alias_peer["table"], "master4", "{protocols}");
    let detail = get_json(adapter_port, "/protocol/pb_0001_as65020", "adapter");
    assert_eq!(
        detail["protocol"], *alias_peer,
        "detail must equal inventory row"
    );
    let symbols = get_json(adapter_port, "/symbols", "adapter");
    assert_eq!(
        symbols["symbols"]["protocol"],
        serde_json::json!(["bgp_192.0.2.10", "pb_0001_as65020", "pb_0002_as65030"]),
        "symbols must be sorted and deduplicated: {symbols}"
    );
    assert_eq!(
        symbols["symbols"]["routing table"],
        serde_json::json!(["master", "master4"]),
        "{symbols}"
    );
    let (missing_status, missing_body) =
        http_get(adapter_port, "/protocol/does_not_exist").expect("unknown protocol response");
    assert_eq!(missing_status, 404, "{missing_body}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&missing_body).unwrap(),
        serde_json::json!({"message":"Protocol not found"})
    );
    wait_for_exact_json_error(
        adapter_port,
        "/route/not-a-prefix/protocol/pb_0001_as65020",
        400,
        "Invalid route prefix",
    );
    wait_for_exact_json_error(
        adapter_port,
        "/route/not-a-prefix/table/master4",
        400,
        "Invalid route prefix",
    );
    wait_for_exact_json_error(
        adapter_port,
        "/route/10.99.0.0%2F24/table/does_not_exist",
        404,
        "Table not found",
    );
    wait_for_exact_json_error(
        adapter_port,
        "/routes/table/does_not_exist",
        404,
        "Table not found",
    );
    assert_eq!(
        get_json(
            adapter_port,
            "/route/203.0.113.0%2F24/table/master4",
            "adapter",
        )["routes"],
        serde_json::json!([]),
        "an installed-ancestor miss is an empty successful table search"
    );
    assert_eq!(
        get_json(adapter_port, "/routes/table/master4", "adapter")["routes"],
        serde_json::json!([]),
        "a live empty table is a successful atomic response"
    );
    for path in [
        "/route/10.99.0.0%2F24/protocol/does_not_exist",
        "/route/10.99.0.0%2F24/export/does_not_exist",
    ] {
        wait_for_exact_json_error(adapter_port, path, 404, "Protocol not found");
    }

    // /routes/peer/{peer} — empty route set still returns the full
    // envelope with an empty routes array.
    let routes = get_json(adapter_port, "/routes/peer/192.0.2.10", "adapter");
    assert!(routes["api"].is_object(), "{routes}");
    assert_eq!(routes["routes"], serde_json::json!([]), "{routes}");

    // Same via the single-table protocol route (exercises the
    // "bgp_<addr>" id parsing).
    let by_protocol = get_json(adapter_port, "/routes/protocol/bgp_192.0.2.10", "adapter");
    assert_eq!(
        routes, by_protocol,
        "/routes/protocol must match /routes/peer"
    );

    // Establish a real session from the in-test BGP speaker and
    // announce one route; the adapter must serve it with a non-empty
    // `age` receive timestamp.
    // Its two Add-Path candidates must both survive in path-id order.
    let mut bgp_session = establish_bgp_and_announce(bgp_port);
    let deadline = Instant::now() + Duration::from_secs(60);
    let live = loop {
        let live = get_json(adapter_port, "/routes/peer/127.0.0.1", "adapter");
        if live["routes"].as_array().is_some_and(|r| r.len() == 2) {
            break live;
        }
        assert!(
            Instant::now() < deadline,
            "announced route did not appear on the adapter\nadapter: {live}\ndaemon stderr:\n{}",
            daemon.stderr()
        );
        thread::sleep(Duration::from_millis(200));
    };
    for route in live["routes"].as_array().unwrap() {
        assert_eq!(route["network"], "10.99.0.0/24", "{live}");
        assert_eq!(route["from_protocol"], "pb_0001_as65020", "{live}");
        assert_eq!(route["primary"], false, "received views stay non-primary");
    }
    assert_eq!(
        live["routes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|route| route["bgp"]["med"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        [10, 20],
        "Add-Path candidates must remain in daemon order: {live}"
    );
    let aliased_live = get_json(adapter_port, "/routes/protocol/pb_0001_as65020", "adapter");
    assert_eq!(
        aliased_live, live,
        "alias and bare peer must resolve identically"
    );
    let exact_received = get_json(
        adapter_port,
        "/route/10.99.0.0%2F24/protocol/pb_0001_as65020",
        "adapter",
    );
    assert_eq!(
        exact_received, live,
        "exact protocol route must preserve every candidate and its order"
    );
    let table_lookup = get_json(
        adapter_port,
        "/route/10.99.0.128%2F25/table/master4",
        "adapter",
    );
    assert_eq!(table_lookup["routes"].as_array().unwrap().len(), 2);
    assert!(
        table_lookup["routes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|route| route["network"] == "10.99.0.0/24"),
        "LPM must return only paths from the matched /24: {table_lookup}"
    );
    assert_eq!(
        table_lookup["routes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|route| route["bgp"]["med"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        [10, 20],
        "installed winner must render first, followed by every alternative: {table_lookup}"
    );
    assert_eq!(
        table_lookup["routes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|route| route["primary"].as_bool().unwrap())
            .collect::<Vec<_>>(),
        [true, false]
    );
    let full_table = get_json(adapter_port, "/routes/table/master4", "adapter");
    assert_eq!(
        full_table["routes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|route| (
                route["bgp"]["med"].as_u64().unwrap(),
                route["primary"].as_bool().unwrap()
            ))
            .collect::<Vec<_>>(),
        [(10, true), (20, false)],
        "the atomic table keeps the installed winner before the inactive Add-Path candidate"
    );
    let age = live["routes"][0]["age"].as_str().unwrap_or_default();
    assert!(!age.is_empty(), "adapter age must be populated");
    // The receive timestamp must parse and sit in the recent past.
    let age_epoch = epoch_from_timestamp(age);
    assert!(age_epoch > 0, "age must be a parseable timestamp: {age:?}");

    // /routes/filtered/{id} — the looped announcement was rejected and
    // retained; the adapter must serve it with the reason token and the
    // synthesized reject-reason large community.
    let deadline = Instant::now() + Duration::from_secs(60);
    let filtered = loop {
        let filtered = get_json(adapter_port, "/routes/filtered/pb_0001_as65020", "adapter");
        if filtered["routes"].as_array().is_some_and(|r| r.len() == 1) {
            break filtered;
        }
        assert!(
            Instant::now() < deadline,
            "rejected route did not appear on the filtered view\nadapter: {filtered}\ndaemon stderr:\n{}",
            daemon.stderr()
        );
        thread::sleep(Duration::from_millis(200));
    };
    let reject = &filtered["routes"][0];
    assert_eq!(reject["network"], "10.98.0.0/24", "{filtered}");
    assert_eq!(reject["reject_reason"], "as_path_loop", "{filtered}");
    assert_eq!(reject["from_protocol"], "pb_0001_as65020", "{filtered}");
    assert_eq!(
        reject["bgp"]["communities"],
        serde_json::json!([[65520, 0]]),
        "ARouteServer presentation must scrub forged values and stay conservative: {filtered}"
    );
    assert_eq!(
        reject["bgp"]["large_communities"],
        serde_json::json!([[65001, 1101, 99], [65001, 999, 7], [64496, 65520, 0]]),
        "ARouteServer presentation must scrub both configured namespaces: {filtered}"
    );

    // IXP Manager v7.4 asks for `{daemon ASN}:1101:*`. This view uses only
    // retained rejects, strips the peer's forged value in that reserved
    // namespace, preserves unrelated communities, and synthesizes one
    // conservative reason (as_path_loop is deliberately generic here).
    let ixp_filtered = get_json(
        adapter_port,
        "/routes/lc-zwild/protocol/pb_0001_as65020/65001/1101",
        "adapter",
    );
    assert_eq!(ixp_filtered["routes"].as_array().unwrap().len(), 1);
    assert_eq!(ixp_filtered["routes"][0]["network"], "10.98.0.0/24");
    let ixp_communities = ixp_filtered["routes"][0]["bgp"]["large_communities"]
        .as_array()
        .unwrap();
    assert!(ixp_communities.contains(&serde_json::json!([65001, 999, 7])));
    assert!(ixp_communities.contains(&serde_json::json!([64496, 65520, 99])));
    assert!(ixp_communities.contains(&serde_json::json!([64496, 65521, 3])));
    assert_eq!(
        ixp_communities
            .iter()
            .filter(|community| community[0] == 65001 && community[1] == 1101)
            .collect::<Vec<_>>(),
        [&serde_json::json!([65001, 1101, 0])]
    );
    for path in [
        "/routes/lc-zwild/protocol/pb_0001_as65020/65002/1101",
        "/routes/lc-zwild/protocol/pb_0001_as65020/65001/1102",
    ] {
        assert_eq!(
            get_json(adapter_port, path, "adapter")["routes"],
            serde_json::json!([])
        );
    }

    // /protocols/bgp — the neighbor summary serves the real filtered
    // count from the same retention store.
    let protocols = get_json(adapter_port, "/protocols/bgp", "adapter");
    assert_eq!(
        protocols["protocols"]["pb_0001_as65020"]["routes"]["filtered"], 1,
        "{protocols}"
    );
    let live_protocol = &protocols["protocols"]["pb_0001_as65020"];
    assert_eq!(live_protocol["routes"]["imported"], 1, "{protocols}");
    assert_eq!(live_protocol["route_limit_at"], 1, "{protocols}");
    assert_eq!(live_protocol["import_limit"], 5, "{protocols}");
    assert_eq!(live_protocol["limit_action"], "shutdown", "{protocols}");
    assert_eq!(live_protocol["source_address"], "127.0.0.1", "{protocols}");
    assert_eq!(live_protocol["keepalive"], 30, "{protocols}");
    assert_eq!(live_protocol["connection"], " Established", "{protocols}");
    assert_eq!(
        live_protocol["bgp_session"],
        serde_json::json!(["external", "route-server", "AS4"]),
        "{protocols}"
    );
    assert!(
        live_protocol.get("import_limit_action").is_none(),
        "{protocols}"
    );
    assert_eq!(
        protocols["protocols"]["pb_0001_as65020"]["state"], "up",
        "{protocols}"
    );
    assert_eq!(
        protocols["protocols"]["pb_0001_as65020"]["bgp_state"], "Established",
        "{protocols}"
    );
    assert!(
        protocols["protocols"]["pb_0001_as65020"]["state_changed"]
            .as_str()
            .is_some_and(|value| value.ends_with("+00:00")),
        "live inventory state_changed must carry an RFC3339 UTC offset: {protocols}"
    );

    // A configured peer with no live session has no retention store —
    // the filtered view is empty, not an error.
    let down = get_json(adapter_port, "/routes/filtered/bgp_192.0.2.10", "adapter");
    assert_eq!(down["routes"], serde_json::json!([]), "{down}");
    let down_ixp = get_json(
        adapter_port,
        "/routes/lc-zwild/protocol/bgp_192.0.2.10/65001/1101",
        "adapter",
    );
    assert_eq!(down_ixp["routes"], serde_json::json!([]), "{down_ixp}");

    // /routes/noexport/{id} — the accepted route is Loc-RIB best, but
    // split horizon suppresses it toward its own announcer: the
    // announcer's noexport view must serve it with the stopping gate
    // name and the synthesized noexport-reason community.
    let deadline = Instant::now() + Duration::from_secs(60);
    let noexport = loop {
        let noexport = get_json(adapter_port, "/routes/noexport/pb_0001_as65020", "adapter");
        if noexport["routes"].as_array().is_some_and(|r| r.len() == 1) {
            break noexport;
        }
        assert!(
            Instant::now() < deadline,
            "suppressed route did not appear on the noexport view\nadapter: {noexport}\ndaemon stderr:\n{}",
            daemon.stderr()
        );
        thread::sleep(Duration::from_millis(200));
    };
    let suppressed = &noexport["routes"][0];
    assert_eq!(suppressed["network"], "10.99.0.0/24", "{noexport}");
    assert_eq!(suppressed["noexport_reason"], "split_horizon", "{noexport}");
    assert_eq!(suppressed["from_protocol"], "pb_0001_as65020", "{noexport}");
    assert!(
        suppressed["bgp"]["large_communities"]
            .as_array()
            .is_some_and(|lcs| lcs.contains(&serde_json::json!([64496, 65521, 1]))),
        "noexport route must carry the synthesized split_horizon community: {noexport}"
    );

    // Bring up the announce-nothing receiver peer: the daemon exports
    // the accepted route to it. Once the export shows on the neighbor
    // summary, the exported route must NOT appear in the receiver's
    // noexport view (mutation proof: exported ≠ noexport).
    let _receiver_session = establish_bgp_receiver(bgp_port);
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let protocols = get_json(adapter_port, "/protocols/bgp", "adapter");
        let exported = &protocols["protocols"]["pb_0002_as65030"]["routes"]["exported"];
        let receiver_noexport =
            get_json(adapter_port, "/routes/noexport/pb_0002_as65030", "adapter");
        if exported == 2 && receiver_noexport["routes"] == serde_json::json!([]) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "exported route must leave the receiver's noexport view\nprotocols: {protocols}\nnoexport: {receiver_noexport}\ndaemon stderr:\n{}",
            daemon.stderr()
        );
        thread::sleep(Duration::from_millis(200));
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    let exact_exported = loop {
        let exported = get_json(
            adapter_port,
            "/route/10.99.0.0%2F24/export/pb_0002_as65030",
            "adapter",
        );
        if exported["routes"]
            .as_array()
            .is_some_and(|routes| routes.len() == 2)
        {
            break exported;
        }
        assert!(
            Instant::now() < deadline,
            "exact export did not retain both candidates: {exported}\ndaemon stderr:\n{}",
            daemon.stderr()
        );
        thread::sleep(Duration::from_millis(200));
    };
    assert_eq!(
        exact_exported["routes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|route| route["bgp"]["med"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        [10, 20],
        "export candidates must preserve order: {exact_exported}"
    );
    assert!(
        exact_exported["routes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|route| route["from_protocol"] == "pb_0001_as65020"),
        "export identity is the source alias, never the target id: {exact_exported}"
    );

    // A configured peer with no live session has no outbound export
    // state — the noexport view is empty, not an error.
    let down_noexport = get_json(adapter_port, "/routes/noexport/bgp_192.0.2.10", "adapter");
    assert_eq!(
        down_noexport["routes"],
        serde_json::json!([]),
        "{down_noexport}"
    );

    announce_additional_route(&mut bgp_session);
    let over_limit = "Number of routes exceeds maximum allowed (3/2)";
    // The full route arrays now exceed the cap, but the exact result remains
    // two candidates: nonmatching routes are filtered before limit checking.
    let exact_received_after_nonmatch = get_json(
        adapter_port,
        "/route/10.99.0.0%2F24/protocol/pb_0001_as65020",
        "adapter",
    );
    assert_eq!(exact_received_after_nonmatch, exact_received);
    let exact_export_after_nonmatch = get_json(
        adapter_port,
        "/route/10.99.0.0%2F24/export/pb_0002_as65030",
        "adapter",
    );
    assert_eq!(exact_export_after_nonmatch, exact_exported);
    wait_for_exact_json_error(
        adapter_port,
        "/routes/protocol/pb_0001_as65020",
        403,
        over_limit,
    );
    wait_for_exact_json_error(
        adapter_port,
        "/routes/export/pb_0002_as65030",
        403,
        over_limit,
    );
    announce_additional_rejected_route(&mut bgp_session);
    let deadline = Instant::now() + Duration::from_secs(60);
    let overflow = loop {
        let body = get_json(adapter_port, "/routes/filtered/pb_0001_as65020", "adapter");
        if body["retention"]["evictions_since_reset"].as_u64() >= Some(1) {
            break body;
        }
        assert!(
            Instant::now() < deadline,
            "retention overflow did not settle: {body}"
        );
        thread::sleep(Duration::from_millis(200));
    };
    let routes = overflow["routes"].as_array().unwrap();
    assert_eq!(routes.len(), 2, "{overflow}");
    assert_eq!(routes[0]["network"], "10.95.0.0/24", "{overflow}");
    assert_eq!(routes[1]["network"], "10.96.0.0/24", "{overflow}");
    assert_eq!(overflow["api"]["max_routes"], 2, "{overflow}");
    assert_eq!(
        overflow["retention"]["evictions_since_reset"], 1,
        "{overflow}"
    );
    assert_eq!(
        overflow["retention"]["may_be_incomplete"], true,
        "{overflow}"
    );
    let ixp_overflow = get_json(
        adapter_port,
        "/routes/lc-zwild/protocol/pb_0001_as65020/65001/1101",
        "adapter",
    );
    assert_eq!(
        ixp_overflow["routes"].as_array().unwrap().len(),
        2,
        "{ixp_overflow}"
    );
    assert_eq!(ixp_overflow["retention"], overflow["retention"]);
    let metrics = http_get(metrics_port, "/metrics")
        .expect("scrape daemon metrics")
        .1;
    assert!(
        metrics.contains("bgp_rejected_route_retention_evictions_total{peer=\"127.0.0.1\"} 1"),
        "live eviction counter missing"
    );
    let daemon_log = std::fs::read_to_string(temp.path().join("rustbgpd.stdout.log")).unwrap();
    assert_eq!(
        daemon_log
            .matches("rejected-route retention evicted an older entry")
            .count(),
        1,
        "the first eviction emits exactly one bounded warning"
    );
    announce_third_candidate(&mut bgp_session);
    wait_for_exact_json_error(
        adapter_port,
        "/route/10.99.0.128%2F25/table/master4",
        403,
        over_limit,
    );

    // A file-backed alias generation swaps in place. The prior name must
    // disappear, and a malformed later generation must retain the exact
    // last-good resolver without replacing the process.
    let next_aliases = temp.path().join("protocol-aliases.next");
    std::fs::write(
        &next_aliases,
        "pb_reloaded_as65020=127.0.0.1@master4\npb_0002_as65030=127.0.0.2@master4\n",
    )
    .expect("stage reloaded aliases");
    std::fs::rename(&next_aliases, &aliases_path).expect("atomically publish aliases");
    assert!(
        Command::new("kill")
            .args(["-HUP", &adapter_pid.to_string()])
            .status()
            .expect("signal adapter")
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let (old_status, _) = http_get(adapter_port, "/protocol/pb_0001_as65020").unwrap();
        let (new_status, _) = http_get(adapter_port, "/protocol/pb_reloaded_as65020").unwrap();
        if old_status == 404 && new_status == 200 {
            break;
        }
        assert!(Instant::now() < deadline, "alias generation did not swap");
        thread::sleep(Duration::from_millis(50));
    }
    let rejected_before = adapter.stderr().matches("reload rejected").count();
    std::fs::write(&next_aliases, "malformed alias\n").expect("stage malformed aliases");
    std::fs::rename(&next_aliases, &aliases_path).expect("publish malformed aliases");
    assert!(
        Command::new("kill")
            .args(["-HUP", &adapter_pid.to_string()])
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while adapter.stderr().matches("reload rejected").count() == rejected_before {
        assert!(
            Instant::now() < deadline,
            "malformed reload was not observed"
        );
        thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        http_get(adapter_port, "/protocol/pb_0001_as65020")
            .unwrap()
            .0,
        404
    );
    assert_eq!(
        http_get(adapter_port, "/protocol/pb_reloaded_as65020")
            .unwrap()
            .0,
        200
    );
    assert_eq!(
        adapter.child.id(),
        adapter_pid,
        "alias reload must retain one PID"
    );

    // Direct aliases remain a separate startup-only compatibility path.
    // Exercise the real branch so file mode cannot accidentally replace it.
    let direct_stderr = temp.path().join("direct-adapter.stderr.log");
    let mut direct_adapter = Proc {
        child: Command::new(&cargo)
            .args(["run", "--quiet", "-p", "birdwatcher-adapter", "--"])
            .arg("--grpc-addr")
            .arg(format!("unix://{}", grpc_socket.display()))
            .arg("--grpc-token-file")
            .arg(&token_path)
            .args([
                "--listen",
                "127.0.0.1:0",
                "--protocol-alias",
                "pb_direct_as65020=127.0.0.1@master4",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::from(std::fs::File::create(&direct_stderr).unwrap()))
            .spawn()
            .expect("spawn direct-alias adapter"),
        name: "direct-alias adapter",
        stderr_path: direct_stderr.clone(),
    };
    let direct_port = wait_for_logged(
        &mut direct_adapter,
        &direct_stderr,
        "direct listener",
        |logs| {
            logs.split("127.0.0.1:")
                .nth(1)?
                .split(|c: char| !c.is_ascii_digit())
                .next()?
                .parse()
                .ok()
        },
    );
    assert_eq!(
        get_json(direct_port, "/protocol/pb_direct_as65020", "direct adapter")["protocol"]["protocol"],
        "pb_direct_as65020"
    );
    let invalid_direct = Command::new(&cargo)
        .args(["run", "--quiet", "-p", "birdwatcher-adapter", "--"])
        .env("NO_COLOR", "1")
        .arg("--grpc-addr")
        .arg(format!("unix://{}", grpc_socket.display()))
        .args([
            "--listen",
            "127.0.0.1:0",
            "--protocol-alias",
            "direct_bad=not-an-ip@master4",
        ])
        .output()
        .expect("run invalid direct alias");
    let invalid_direct = String::from_utf8(invalid_direct.stderr).unwrap();
    assert!(
        invalid_direct.contains("invalid protocol alias")
            && invalid_direct.contains("direct_bad=not-an-ip@master4")
            && invalid_direct.contains("malformed peer IP"),
        "direct startup diagnostics must remain detailed: {invalid_direct}"
    );
}
