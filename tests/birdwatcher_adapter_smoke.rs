//! Smoke test: the external birdwatcher-adapter must serve the same
//! birdwatcher REST contract as the deprecated in-daemon looking
//! glass, for the same daemon state.
//!
//! Spawns one rustbgpd (in-daemon looking glass + gRPC TCP enabled)
//! and one birdwatcher-adapter pointed at that gRPC endpoint, then
//! fetches `/status`, `/protocols/bgp`, and `/routes/peer/{peer}`
//! from both and asserts structural equality after blanking the
//! clock-dependent fields (`current_server`, `last_reboot`,
//! `state_changed`, `state` — the configured peer has no live
//! counterpart, so its FSM state cycles).

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

fn write_config(dir: &Path, grpc_port: u16, lg_port: u16) -> PathBuf {
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
listen_port = 0
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
"#,
        runtime_dir = runtime_dir.display()
    );
    std::fs::write(&config_path, config).expect("write test config");
    config_path
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
    let config_path = write_config(temp.path(), grpc_port, lg_port);

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
}
