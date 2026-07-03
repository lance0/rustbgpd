//! Smoke test: the external birdwatcher-adapter must serve the same
//! birdwatcher REST contract as the deprecated in-daemon looking
//! glass, for the same daemon state.
//!
//! Spawns one rustbgpd (in-daemon looking glass + gRPC TCP enabled)
//! and one birdwatcher-adapter pointed at that gRPC endpoint, then
//! fetches `/status`, `/protocols/bgp`, and `/routes/peer/{peer}`
//! from both and asserts structural equality after blanking the
//! clock-dependent fields (`current_server`, `last_reboot`,
//! `state_changed`, `state` — the configured 192.0.2.10 peer has no
//! live counterpart, so its FSM state cycles).
//!
//! A second neighbor (127.0.0.1) is driven by a minimal in-test BGP
//! speaker that establishes a real session and announces one route, so
//! the per-route `age` field is exercised end-to-end: both servers
//! must render a non-empty receive timestamp for the same route, equal
//! within clock-recovery jitter.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Proc {
    child: Child,
    name: &'static str,
    stderr_path: PathBuf,
}

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

/// Grab a free localhost port. Racy in principle, fine for a test.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind 127.0.0.1:0")
        .local_addr()
        .unwrap()
        .port()
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

fn wait_for_http(port: u16, path: &str, proc_: &mut Proc) {
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        if matches!(http_get(port, path), Some((200, _))) {
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
        "{} did not serve {path} within timeout\nstderr:\n{}",
        proc_.name,
        proc_.stderr()
    );
}

fn write_config(dir: &Path, grpc_port: u16, lg_port: u16, bgp_port: u16) -> PathBuf {
    let runtime_dir = dir.join("runtime");
    std::fs::create_dir_all(&runtime_dir).expect("create runtime dir");
    let config_path = dir.join("rustbgpd.toml");
    let config = format!(
        r#"
[security.grpc]
enforcement = "legacy"

[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = {bgp_port}
runtime_state_dir = "{runtime_dir}"

[global.telemetry]
log_format = "json"

[global.telemetry.grpc_tcp]
address = "127.0.0.1:{grpc_port}"

[global.telemetry.looking_glass]
addr = "127.0.0.1:{lg_port}"

[[neighbors]]
address = "192.0.2.10"
remote_asn = 65010
description = "smoke peer"

[[neighbors]]
address = "127.0.0.1"
remote_asn = 65020
description = "live peer"
"#,
        runtime_dir = runtime_dir.display()
    );
    std::fs::write(&config_path, config).expect("write test config");
    config_path
}

/// Minimal BGP speaker: connect to the daemon's listen port, complete
/// the OPEN/KEEPALIVE handshake as legacy AS 65020 (no capabilities —
/// implicit IPv4 unicast), and announce one route. The returned stream
/// must stay alive for the session to survive; the daemon's own
/// messages are left unread (a handful of bytes, well within the
/// socket buffer for the test's lifetime).
fn establish_bgp_and_announce(bgp_port: u16) -> TcpStream {
    use rustbgpd_wire::attribute::{AsPath, AsPathSegment, Origin, PathAttribute};
    use rustbgpd_wire::message::{Message, encode_message};
    use rustbgpd_wire::open::OpenMessage;
    use rustbgpd_wire::update::UpdateMessage;

    let mut stream = TcpStream::connect(("127.0.0.1", bgp_port)).expect("connect to BGP port");
    let open = Message::Open(OpenMessage {
        version: 4,
        my_as: 65020,
        hold_time: 90,
        bgp_identifier: "10.0.0.2".parse().unwrap(),
        capabilities: Vec::new(),
    });
    let mut attrs = Vec::new();
    rustbgpd_wire::attribute::encode_path_attributes(
        &[
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65020])],
            }),
            // Non-loopback: the daemon's UPDATE validation rejects a
            // loopback NEXT_HOP (subcode 8).
            PathAttribute::NextHop("192.0.2.99".parse().unwrap()),
        ],
        &mut attrs,
        false,
        false,
    )
    .expect("encode path attributes");
    let update = Message::Update(UpdateMessage {
        withdrawn_routes: bytes::Bytes::new(),
        path_attributes: attrs.into(),
        // 10.99.0.0/24
        nlri: bytes::Bytes::from_static(&[24, 10, 99, 0]),
    });
    for msg in [&open, &Message::Keepalive, &update] {
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
    let [y, m, d, h, mi, se] = parts[..] else {
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

/// Blank the clock-dependent fields so the two responses (taken at
/// slightly different instants, over different uptime sources) compare
/// structurally. Every blanked field is first asserted non-empty.
fn normalize(mut value: serde_json::Value) -> serde_json::Value {
    if let Some(status) = value.get_mut("status").and_then(|s| s.as_object_mut()) {
        for key in ["current_server", "last_reboot"] {
            let v = status.get(key).and_then(|v| v.as_str()).unwrap_or_default();
            assert!(!v.is_empty(), "status.{key} must be populated");
            status.insert(key.to_string(), "".into());
        }
    }
    if let Some(protocols) = value.get_mut("protocols").and_then(|p| p.as_object_mut()) {
        for (id, proto) in protocols.iter_mut() {
            let obj = proto.as_object_mut().expect("protocol entry is an object");
            for key in ["state_changed", "state"] {
                let v = obj.get(key).and_then(|v| v.as_str()).unwrap_or_default();
                assert!(!v.is_empty(), "protocols.{id}.{key} must be populated");
                obj.insert(key.to_string(), "".into());
            }
        }
    }
    value
}

#[test]
fn adapter_matches_in_daemon_looking_glass() {
    let temp = tempfile::tempdir().expect("create temp dir");
    let grpc_port = free_port();
    let lg_port = free_port();
    let adapter_port = free_port();
    let bgp_port = free_port();
    let config_path = write_config(temp.path(), grpc_port, lg_port, bgp_port);

    // Spawn the daemon (serves both gRPC and the in-daemon looking
    // glass). Structured logs go to stdout, the banner to stderr.
    let daemon_stdout = temp.path().join("rustbgpd.stdout.log");
    let daemon_stderr = temp.path().join("rustbgpd.stderr.log");
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
    wait_for_http(lg_port, "/status", &mut daemon);

    // The configured looking glass must emit the deprecation warning.
    let daemon_logs = std::fs::read_to_string(&daemon_stdout).expect("read daemon stdout");
    assert!(
        daemon_logs.contains("DEPRECATED") && daemon_logs.contains("birdwatcher-adapter"),
        "daemon startup must warn that the in-daemon looking glass is deprecated:\n{daemon_logs}"
    );

    // Spawn the adapter against the daemon's gRPC endpoint. Built via
    // `cargo run` (same fallback pattern the rbgp test helper uses) —
    // the workspace build has usually compiled it already.
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let adapter_stderr = temp.path().join("adapter.stderr.log");
    let mut adapter = Proc {
        child: Command::new(cargo)
            .args(["run", "--quiet", "-p", "birdwatcher-adapter", "--"])
            .arg("--grpc-addr")
            .arg(format!("http://127.0.0.1:{grpc_port}"))
            .arg("--listen")
            .arg(format!("127.0.0.1:{adapter_port}"))
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                std::fs::File::create(&adapter_stderr).expect("adapter stderr log"),
            ))
            .spawn()
            .expect("spawn birdwatcher-adapter"),
        name: "birdwatcher-adapter",
        stderr_path: adapter_stderr,
    };
    wait_for_http(adapter_port, "/status", &mut adapter);

    // /status — equal after blanking the two clock fields.
    let core = normalize(get_json(lg_port, "/status", "in-daemon"));
    let ext = normalize(get_json(adapter_port, "/status", "adapter"));
    assert_eq!(core, ext, "/status must match");

    // /protocols/bgp — protocol id, neighbor_address, neighbor_as,
    // description, table, and route counters must match; state and
    // state_changed are blanked (unconnectable peer cycles its FSM).
    let core = get_json(lg_port, "/protocols/bgp", "in-daemon");
    assert!(
        core["protocols"]["bgp_192.0.2.10"].is_object(),
        "in-daemon response must contain the configured peer: {core}"
    );
    let core = normalize(core);
    let ext = normalize(get_json(adapter_port, "/protocols/bgp", "adapter"));
    assert_eq!(core, ext, "/protocols/bgp must match");

    // /routes/peer/{peer} — byte-equivalent JSON (empty route set; the
    // envelope, api block, and routes array shape must be identical).
    let core = get_json(lg_port, "/routes/peer/192.0.2.10", "in-daemon");
    let ext = get_json(adapter_port, "/routes/peer/192.0.2.10", "adapter");
    assert_eq!(core, ext, "/routes/peer must match exactly");

    // Same via the single-table protocol route (exercises the
    // "bgp_<addr>" id parsing on both sides).
    let core = get_json(lg_port, "/routes/protocol/bgp_192.0.2.10", "in-daemon");
    let ext = get_json(adapter_port, "/routes/protocol/bgp_192.0.2.10", "adapter");
    assert_eq!(core, ext, "/routes/protocol must match exactly");

    // Establish a real session from the in-test BGP speaker and
    // announce one route, then compare the non-empty route sets —
    // including the `age` receive timestamp both servers must now
    // derive from the same RIB receive instant.
    let _bgp_session = establish_bgp_and_announce(bgp_port);
    let deadline = Instant::now() + Duration::from_secs(60);
    let (mut core, mut ext) = loop {
        let core = get_json(lg_port, "/routes/peer/127.0.0.1", "in-daemon");
        let ext = get_json(adapter_port, "/routes/peer/127.0.0.1", "adapter");
        if core["routes"].as_array().is_some_and(|r| r.len() == 1)
            && ext["routes"].as_array().is_some_and(|r| r.len() == 1)
        {
            break (core, ext);
        }
        assert!(
            Instant::now() < deadline,
            "announced route did not appear on both servers\nin-daemon: {core}\nadapter: {ext}\ndaemon stderr:\n{}",
            daemon.stderr()
        );
        thread::sleep(Duration::from_millis(200));
    };

    // Non-empty age on both sides, equal within clock-recovery jitter
    // (each server independently truncates `now - elapsed` to seconds).
    let core_age = core["routes"][0]["age"].as_str().unwrap_or_default();
    let ext_age = ext["routes"][0]["age"].as_str().unwrap_or_default();
    assert!(!core_age.is_empty(), "in-daemon age must be populated");
    assert!(!ext_age.is_empty(), "adapter age must be populated");
    let delta = epoch_from_timestamp(core_age).abs_diff(epoch_from_timestamp(ext_age));
    assert!(
        delta <= 2,
        "age must agree within jitter: in-daemon {core_age:?} vs adapter {ext_age:?}"
    );

    // With age blanked, the live-route responses must match exactly.
    core["routes"][0]["age"] = "".into();
    ext["routes"][0]["age"] = "".into();
    assert_eq!(core, ext, "/routes/peer for the live peer must match");
    assert_eq!(
        core["routes"][0]["network"], "10.99.0.0/24",
        "announced route must be served"
    );
}
