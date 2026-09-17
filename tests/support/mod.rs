//! Shared harness pieces for the real-daemon integration tests.

#![allow(
    dead_code,
    reason = "each integration target compiles this module and uses a subset of it"
)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// Temporary test directory that survives on panic.
///
/// The daemon under test writes its log inside the test's temporary
/// directory, so dropping that directory on an assertion failure destroys
/// the only evidence of why the daemon misbehaved. This guard disarms
/// cleanup while the thread is panicking and names the retained path in the
/// captured test output.
pub struct RetainOnPanic {
    dir: Option<tempfile::TempDir>,
}

impl RetainOnPanic {
    pub fn new(dir: tempfile::TempDir) -> Self {
        Self { dir: Some(dir) }
    }

    pub fn path(&self) -> &Path {
        self.dir
            .as_ref()
            .expect("temporary directory is held until drop")
            .path()
    }
}

impl Drop for RetainOnPanic {
    fn drop(&mut self) {
        let Some(dir) = self.dir.take() else {
            return;
        };
        if std::thread::panicking() {
            let path = dir.keep();
            eprintln!(
                "test panicked: daemon logs and state retained at {}",
                path.display()
            );
        }
    }
}

/// Resolve the `rbgp` CLI binary next to the daemon binary under test.
///
/// `CARGO_BIN_EXE_rbgp` is honoured when the invoker exports it; otherwise
/// the binary must already sit next to `rustbgpd` in the build profile
/// directory, which `cargo test --workspace` guarantees. Falling back to
/// `cargo run` instead would put a build lock and a workspace freshness
/// check on the hot path of grace-window assertions, where seconds of
/// build-load stall turn a live-daemon rejection into a missed deadline.
pub fn rbgp_binary() -> &'static Path {
    static RBGP: OnceLock<PathBuf> = OnceLock::new();
    RBGP.get_or_init(|| {
        let path = std::env::var_os("CARGO_BIN_EXE_rbgp").map_or_else(
            || {
                Path::new(env!("CARGO_BIN_EXE_rustbgpd"))
                    .parent()
                    .expect("rustbgpd binary has a profile directory")
                    .join("rbgp")
            },
            PathBuf::from,
        );
        assert!(
            path.is_file(),
            "build rbgp before this test (cargo test --workspace builds it); missing {}",
            path.display()
        );
        path
    })
}

/// First endpoint a daemon's JSON log reports under `message` in `field`
/// that `accept` admits. A requested port 0 is never evidence of a bound
/// endpoint.
fn logged_endpoint(
    log: &str,
    message: &str,
    field: &str,
    accept: impl Fn(&SocketAddr) -> bool,
) -> Option<SocketAddr> {
    log.lines().find_map(|line| {
        let entry: serde_json::Value = serde_json::from_str(line).ok()?;
        let fields = &entry["fields"];
        if fields["message"] != message {
            return None;
        }
        fields[field]
            .as_str()?
            .parse::<SocketAddr>()
            .ok()
            .filter(|addr| addr.port() != 0 && accept(addr))
    })
}

/// Loopback metrics endpoint the daemon reported binding.
pub fn bound_metrics_addr(log: &str) -> Option<SocketAddr> {
    logged_endpoint(log, "metrics server listening", "addr", |addr| {
        addr.ip().is_loopback()
    })
}

/// gRPC TCP endpoint the daemon reported binding.
pub fn bound_grpc_addr(log: &str) -> Option<SocketAddr> {
    logged_endpoint(log, "starting gRPC TCP listener", "bound_addr", |_| true)
}

/// Loopback BGP endpoint the daemon reported binding.
///
/// Tests configure `listen_port = 0` and read the port back here, so the
/// daemon that serves a port is the one that picks it. Reserving a port by
/// binding and releasing it first lets another socket take it in between. A
/// wildcard listener does not count: stubs dial loopback, and a legacy
/// dual-family daemon that lost its IPv4 bind reports only `[::]`.
pub fn bound_bgp_addr(log: &str) -> Option<SocketAddr> {
    logged_endpoint(log, "BGP listener bound", "addr", |addr| {
        addr.ip().is_loopback()
    })
}

/// Block until the daemon's gRPC unix socket at `sock` accepts a connection.
///
/// The daemon binds and logs its BGP listener before it serves gRPC, so a
/// bound BGP port is no evidence that `grpc.sock` exists yet; a CLI call in
/// that window fails with "socket does not exist". The daemon binds and
/// listens on the socket before it reports listener startup, so a successful
/// connect means the listener is up. Panics if the daemon exits first or the
/// socket never accepts.
#[cfg(unix)]
pub fn wait_until_grpc_socket_accepts(sock: &Path, daemon: &mut std::process::Child) {
    use std::time::{Duration, Instant};

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if std::os::unix::net::UnixStream::connect(sock).is_ok() {
            return;
        }
        if let Some(status) = daemon.try_wait().expect("query daemon status") {
            panic!(
                "rustbgpd exited with {status} before serving {}",
                sock.display()
            );
        }
        assert!(
            Instant::now() < deadline,
            "rustbgpd never served its gRPC socket at {}",
            sock.display()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Hand the BGP port choice of a rendered IXP Manager candidate to the daemon.
///
/// The renderer refuses an export that asks for port 0, so tests render the
/// default port and edit the result with [`edit_rendered_config`].
pub fn daemon_chooses_bgp_port(config: &str) -> String {
    let edited = config.replacen("\nlisten_port = 179\n", "\nlisten_port = 0\n", 1);
    assert_ne!(edited, config, "rendered config has no default listen_port");
    edited
}

/// Edit a rendered candidate's `config.toml`, re-run the strict check on the
/// result, and re-record the file digest the activation verifies.
pub fn edit_rendered_config(dir: &Path, checker: &Path, edit: impl FnOnce(&str) -> String) {
    use sha2::{Digest, Sha256};

    let path = dir.join("config.toml");
    let rendered = std::fs::read_to_string(&path).expect("read rendered config");
    let config = edit(&rendered);
    std::fs::write(&path, &config).expect("write edited config");
    let checked = Command::new(checker)
        .args(["--check", "--strict"])
        .arg(&path)
        .output()
        .expect("run strict check");
    assert!(
        checked.status.success(),
        "edited config must pass the strict check:\n{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    let receipt_path = dir.join("render-receipt.json");
    let mut receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&receipt_path).expect("read render receipt"))
            .expect("parse render receipt");
    let digest: String = Sha256::digest(config.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    receipt["generated_files"]["config.toml"] = digest.into();
    let mut encoded = serde_json::to_vec_pretty(&receipt).expect("serialize render receipt");
    encoded.push(b'\n');
    std::fs::write(&receipt_path, encoded).expect("write render receipt");
}
