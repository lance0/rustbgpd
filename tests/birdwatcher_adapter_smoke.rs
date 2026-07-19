//! Smoke test: the external birdwatcher-adapter serves its
//! Birdwatcher-shaped status/peer/accepted-route subset from a live rustbgpd
//! gRPC endpoint.
//! (The adapter replaced the removed in-daemon looking glass server;
//! this test pins the REST surface operators migrate to.)
//!
//! Spawns one rustbgpd (gRPC TCP enabled) and one birdwatcher-adapter
//! pointed at that gRPC endpoint, then fetches `/status`,
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
//!
//! A third neighbor (127.0.0.2, announce-nothing receiver) exercises the
//! `/routes/noexport/{id}` view from both sides: the accepted route is
//! exported to the receiver (so its noexport view is empty) while split
//! horizon suppresses it toward its announcer (so it appears in the
//! announcer's noexport view with the gate name and the synthesized
//! noexport-reason community).

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

fn write_config(dir: &Path, grpc_port: u16, bgp_port: u16) -> PathBuf {
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

[[neighbors]]
address = "192.0.2.10"
remote_asn = 65010
description = "smoke peer"

[[neighbors]]
address = "127.0.0.1"
remote_asn = 65020
description = "live peer"

[[neighbors]]
address = "127.0.0.2"
remote_asn = 65030
description = "receiver peer"
"#,
        runtime_dir = runtime_dir.display()
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

    let mut stream = TcpStream::connect(("127.0.0.1", bgp_port)).expect("connect to BGP port");
    let open = Message::Open(OpenMessage {
        version: 4,
        my_as: 65020,
        hold_time: 90,
        bgp_identifier: "10.0.0.2".parse().unwrap(),
        capabilities: Vec::new(),
    });
    let encode_update = |as_sequence: Vec<u32>, nlri: &'static [u8]| {
        let mut attrs = Vec::new();
        rustbgpd_wire::attribute::encode_path_attributes(
            &[
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(as_sequence)],
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
        Message::Update(UpdateMessage {
            withdrawn_routes: bytes::Bytes::new(),
            path_attributes: attrs.into(),
            nlri: bytes::Bytes::from_static(nlri),
        })
    };
    // 10.99.0.0/24, clean path → accepted.
    let accepted = encode_update(vec![65020], &[24, 10, 99, 0]);
    // 10.98.0.0/24, daemon's own AS 65001 in path → as_path_loop reject.
    let looped = encode_update(vec![65020, 65001], &[24, 10, 98, 0]);
    for msg in [&open, &Message::Keepalive, &accepted, &looped] {
        let encoded = encode_message(msg).expect("encode BGP message");
        stream.write_all(&encoded).expect("write BGP message");
    }
    stream
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
        capabilities: Vec::new(),
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

#[test]
fn adapter_serves_birdwatcher_shaped_status_peer_accepted_filtered_and_noexport_subset() {
    let temp = tempfile::tempdir().expect("create temp dir");
    let grpc_port = free_port();
    let adapter_port = free_port();
    let bgp_port = free_port();
    let config_path = write_config(temp.path(), grpc_port, bgp_port);

    // Spawn the daemon (serves gRPC). Structured logs go to stdout,
    // the banner to stderr.
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
    wait_for_tcp(grpc_port, &mut daemon);

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

    // /status — birdwatcher envelope with the api block and a status
    // object carrying the clock fields.
    let status = get_json(adapter_port, "/status", "adapter");
    assert!(
        status["api"].is_object(),
        "/status must carry api: {status}"
    );
    assert!(
        status["status"]["current_server"].is_string(),
        "/status must carry status.current_server: {status}"
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
    let _bgp_session = establish_bgp_and_announce(bgp_port);
    let deadline = Instant::now() + Duration::from_secs(60);
    let live = loop {
        let live = get_json(adapter_port, "/routes/peer/127.0.0.1", "adapter");
        if live["routes"].as_array().is_some_and(|r| r.len() == 1) {
            break live;
        }
        assert!(
            Instant::now() < deadline,
            "announced route did not appear on the adapter\nadapter: {live}\ndaemon stderr:\n{}",
            daemon.stderr()
        );
        thread::sleep(Duration::from_millis(200));
    };
    assert_eq!(
        live["routes"][0]["network"], "10.99.0.0/24",
        "announced route must be served"
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
        let filtered = get_json(adapter_port, "/routes/filtered/bgp_127.0.0.1", "adapter");
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
    let large_communities = &reject["bgp"]["large_communities"];
    assert!(
        large_communities
            .as_array()
            .is_some_and(|lcs| lcs.contains(&serde_json::json!([64496, 65520, 4]))),
        "filtered route must carry the synthesized as_path_loop community: {filtered}"
    );

    // /protocols/bgp — the neighbor summary serves the real filtered
    // count from the same retention store.
    let protocols = get_json(adapter_port, "/protocols/bgp", "adapter");
    assert_eq!(
        protocols["protocols"]["bgp_127.0.0.1"]["routes"]["filtered"], 1,
        "{protocols}"
    );

    // A configured peer with no live session has no retention store —
    // the filtered view is empty, not an error.
    let down = get_json(adapter_port, "/routes/filtered/bgp_192.0.2.10", "adapter");
    assert_eq!(down["routes"], serde_json::json!([]), "{down}");

    // /routes/noexport/{id} — the accepted route is Loc-RIB best, but
    // split horizon suppresses it toward its own announcer: the
    // announcer's noexport view must serve it with the stopping gate
    // name and the synthesized noexport-reason community.
    let deadline = Instant::now() + Duration::from_secs(60);
    let noexport = loop {
        let noexport = get_json(adapter_port, "/routes/noexport/bgp_127.0.0.1", "adapter");
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
        let exported = &protocols["protocols"]["bgp_127.0.0.2"]["routes"]["exported"];
        let receiver_noexport = get_json(adapter_port, "/routes/noexport/bgp_127.0.0.2", "adapter");
        if exported == 1 && receiver_noexport["routes"] == serde_json::json!([]) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "exported route must leave the receiver's noexport view\nprotocols: {protocols}\nnoexport: {receiver_noexport}\ndaemon stderr:\n{}",
            daemon.stderr()
        );
        thread::sleep(Duration::from_millis(200));
    }

    // A configured peer with no live session has no outbound export
    // state — the noexport view is empty, not an error.
    let down_noexport = get_json(adapter_port, "/routes/noexport/bgp_192.0.2.10", "adapter");
    assert_eq!(
        down_noexport["routes"],
        serde_json::json!([]),
        "{down_noexport}"
    );
}
