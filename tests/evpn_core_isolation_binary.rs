//! Privileged netns proof of the ADR-0140 core-isolation hold through
//! the real daemon binary and its release paths.
//!
//! The outer pass creates a throwaway netns and re-runs this test inside
//! it. The inner pass builds an 802.3ad bond with two veth members,
//! starts the daemon with `[evpn_core_isolation] enabled = true` and no
//! EVPN session (so the startup hold stays armed), and asserts:
//!
//! - the startup hold takes both members administratively down and
//!   writes the ownership receipt;
//! - `--runtime-state-dir` that differs from the config is refused, and
//!   `--release-core-isolation` refuses while the daemon holds the lock;
//! - after SIGKILL the members stay down, and the release helper raises
//!   them, removes the receipt and exits 0;
//! - a restarted daemon holds them again, and SIGTERM raises them and
//!   removes the receipt.
//!
//! Gates on `EVPN_LINUX_NETNS=1`; run via
//! `bash crates/evpn-linux/tests/docker/run-netns-tests.sh core_isolation_daemon`.

#![cfg(target_os = "linux")]

use std::fs::File;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const RECEIPT: &str = "evpn-core-isolation-owned.json";

fn inner_netns_pass(test: &str) -> bool {
    if std::env::var("RUSTBGPD_CORE_ISOLATION_INNER").is_ok() {
        return true;
    }
    let ns = format!("rbgp-ci-{}", std::process::id());
    let _ = Command::new("ip").args(["netns", "delete", &ns]).output();
    ip(&["netns", "add", &ns]);
    let status = Command::new("ip")
        .args(["netns", "exec", &ns])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "--nocapture", test])
        .env("RUSTBGPD_CORE_ISOLATION_INNER", "1")
        .status()
        .expect("spawn inner");
    let _ = Command::new("ip").args(["netns", "delete", &ns]).output();
    assert!(status.success(), "inner test invocation failed");
    false
}

fn netns_enabled() -> bool {
    let enabled = std::env::var("EVPN_LINUX_NETNS").as_deref() == Ok("1");
    if !enabled {
        eprintln!(
            "skipping: set EVPN_LINUX_NETNS=1 to run the privileged core-isolation daemon test"
        );
    }
    enabled
}

fn ip(args: &[&str]) {
    let out = Command::new("ip").args(args).output().expect("spawn ip");
    assert!(
        out.status.success(),
        "ip {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn admin_up(name: &str) -> bool {
    let flags = std::fs::read_to_string(format!("/sys/class/net/{name}/flags")).unwrap();
    u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16).unwrap() & 1 == 1
}

fn wait_for(what: &str, log: &Path, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if condition() {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!(
        "timed out waiting for {what}\nlog:\n{}",
        std::fs::read_to_string(log).unwrap_or_default()
    );
}

fn write_config(dir: &Path) -> (PathBuf, PathBuf) {
    let runtime = dir.join("runtime");
    std::fs::create_dir_all(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.join("rustbgpd.toml");
    std::fs::write(
        &path,
        format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 0
runtime_state_dir = "{runtime}"

[global.telemetry]
log_format = "json"

[global.telemetry.grpc_uds]
path = "{runtime}/grpc.sock"

[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.10"

[[ethernet_segments]]
esi = "00:11:22:33:44:55:66:77:88:01"
member_vnis = [100]
originator_ip = "10.0.0.10"
interface = "bond0"

[evpn_core_isolation]
enabled = true
backstop_seconds = 600
"#,
            runtime = runtime.display()
        ),
    )
    .unwrap();
    (path, runtime)
}

fn rustbgpd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
}

fn start(config: &Path, runtime: &Path, log: &Path) -> Child {
    rustbgpd()
        .arg("--runtime-state-dir")
        .arg(runtime)
        .arg(config)
        .stdout(Stdio::from(File::create(log).unwrap()))
        .stderr(Stdio::from(File::options().append(true).open(log).unwrap()))
        .spawn()
        .expect("spawn rustbgpd")
}

fn release(runtime: &Path) -> std::process::Output {
    rustbgpd()
        .arg("--release-core-isolation")
        .arg("--runtime-state-dir")
        .arg(runtime)
        .output()
        .expect("spawn release helper")
}

#[test]
fn core_isolation_hold_survives_a_crash_and_every_release_path_raises_it() {
    if !netns_enabled()
        || !inner_netns_pass(
            "core_isolation_hold_survives_a_crash_and_every_release_path_raises_it",
        )
    {
        return;
    }
    ip(&["link", "set", "lo", "up"]);
    ip(&["link", "add", "bond0", "type", "bond", "mode", "802.3ad"]);
    for (member, peer) in [("m0", "p0"), ("m1", "p1")] {
        ip(&["link", "add", member, "type", "veth", "peer", "name", peer]);
        ip(&["link", "set", peer, "up"]);
        ip(&["link", "set", member, "master", "bond0"]);
        ip(&["link", "set", member, "up"]);
    }
    ip(&["link", "set", "bond0", "up"]);

    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let (config, runtime) = write_config(temp.path());
    let log = temp.path().join("rustbgpd.log");
    let receipt = runtime.join(RECEIPT);

    // A stop hook pointed at another directory cannot pass silently.
    let mismatch = rustbgpd()
        .args(["--runtime-state-dir", "/var/lib/elsewhere", "--check"])
        .arg(&config)
        .output()
        .unwrap();
    assert_eq!(mismatch.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&mismatch.stderr).contains("differs from the config"),
        "{}",
        String::from_utf8_lossy(&mismatch.stderr)
    );

    let mut daemon = start(&config, &runtime, &log);
    wait_for("startup hold", &log, || {
        !admin_up("m0") && !admin_up("m1") && receipt.exists()
    });

    let refused = release(&runtime);
    assert_eq!(refused.status.code(), Some(1), "live daemon holds the lock");
    assert!(!admin_up("m0"));

    // Crash: nothing in-process runs, the links stay down.
    daemon.kill().unwrap();
    daemon.wait().unwrap();
    thread::sleep(Duration::from_millis(500));
    assert!(!admin_up("m0") && !admin_up("m1"));
    let released = release(&runtime);
    assert!(
        released.status.success(),
        "helper failed: {}",
        String::from_utf8_lossy(&released.stderr)
    );
    assert!(admin_up("m0") && admin_up("m1"));
    assert!(!receipt.exists());

    // Restart holds again; a clean stop releases.
    let mut daemon = start(&config, &runtime, &log);
    wait_for("startup hold after restart", &log, || {
        !admin_up("m0") && !admin_up("m1") && receipt.exists()
    });
    let term = Command::new("kill")
        .args(["-TERM", &daemon.id().to_string()])
        .status()
        .unwrap();
    assert!(term.success());
    let status = daemon.wait().unwrap();
    let text = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(status.success(), "rustbgpd exited {status}\n{text}");
    assert!(
        admin_up("m0") && admin_up("m1"),
        "clean shutdown raises\n{text}"
    );
    assert!(!receipt.exists());
    assert!(
        text.contains("releasing core-isolation holds for shutdown"),
        "{text}"
    );
}
