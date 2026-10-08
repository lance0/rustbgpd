//! Privileged netns proof that `esi = "auto-lacp"` is a runtime
//! readiness condition, not a startup gate.
//!
//! The outer pass creates a throwaway netns and re-runs this test inside
//! it. The inner pass builds an 802.3ad PE bond whose veth peer does not
//! speak LACP yet, starts the real daemon, and asserts:
//!
//! - the daemon starts and stays up while the bond has no partner, and
//!   logs the segment NotReady with reason `no_partner` while
//!   originating no Type 4 route and listing no segment;
//! - once a synthetic CE bond negotiates LACP, the segment becomes Ready
//!   with the CE's type 1 ESI and its Type 4 route is originated, with no
//!   restart;
//! - replacing the CE's LACP system MAC withdraws the old Type 4 route
//!   and originates one under the new ESI.
//!
//! A second test starts the daemon with no Ethernet Segment and adds
//! the first one — `auto-lacp` — by SIGHUP: the readiness probe and the
//! segment actor both start live, the segment reaches Ready with no
//! restart, and coordinated shutdown drains the live-started actor.
//!
//! Gates on `EVPN_LINUX_NETNS=1`; run via
//! `bash crates/evpn-linux/tests/docker/run-netns-tests.sh auto_lacp_daemon`.

#![cfg(target_os = "linux")]

#[path = "support/cargo.rs"]
mod cargo;

use std::fs::File;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Outer pass: re-run `test` inside a throwaway netns and return
/// `false`. Inner pass: return `true` so the caller runs the body.
fn inner_netns_pass(test: &str) -> bool {
    if std::env::var("RUSTBGPD_AUTOLACP_INNER").is_ok() {
        return true;
    }
    let ns = format!("rbgp-{}-{test}", std::process::id());
    let _ = Command::new("ip").args(["netns", "delete", &ns]).output();
    ip(&["netns", "add", &ns]);
    let status = Command::new("ip")
        .args(["netns", "exec", &ns])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "--nocapture", test])
        .env("RUSTBGPD_AUTOLACP_INNER", "1")
        .status()
        .expect("spawn inner");
    let _ = Command::new("ip").args(["netns", "delete", &ns]).output();
    assert!(status.success(), "inner test invocation failed");
    false
}

fn netns_enabled() -> bool {
    let enabled = std::env::var("EVPN_LINUX_NETNS").as_deref() == Ok("1");
    if !enabled {
        eprintln!("skipping: set EVPN_LINUX_NETNS=1 to run the privileged auto-lacp daemon test");
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

fn rbgp(grpc_addr: &str, args: &[&str]) -> Output {
    let mut cmd = if let Ok(path) = std::env::var("CARGO_BIN_EXE_rbgp") {
        Command::new(path)
    } else {
        let mut cmd = cargo::command();
        cmd.args(["run", "--quiet", "-p", "rustbgpctl", "--bin", "rbgp", "--"]);
        cmd
    };
    cmd.arg("--addr")
        .arg(grpc_addr)
        .args(args)
        .output()
        .expect("spawn rbgp")
}

fn rbgp_json(grpc_addr: &str, args: &[&str]) -> Option<serde_json::Value> {
    let out = rbgp(grpc_addr, args);
    out.status
        .success()
        .then(|| serde_json::from_slice(&out.stdout).ok())
        .flatten()
}

/// ESIs of locally listed segments and originated Type 4 routes.
fn observed(grpc_addr: &str) -> Option<(Vec<String>, Vec<String>)> {
    let esis = |v: serde_json::Value, key: &str| -> Vec<String> {
        let rows = if key.is_empty() { v } else { v[key].clone() };
        rows.as_array()
            .into_iter()
            .flatten()
            .filter_map(|row| row["esi"].as_str().map(str::to_string))
            .collect()
    };
    let segments = rbgp_json(grpc_addr, &["--json", "evpn", "es", "list"])?;
    let type4 = rbgp_json(grpc_addr, &["--json", "evpn", "--route-type", "4"])?;
    Some((esis(segments, "segments"), esis(type4, "")))
}

struct Daemon {
    child: Child,
    stderr_path: std::path::PathBuf,
}

impl Daemon {
    fn stderr(&self) -> String {
        std::fs::read_to_string(&self.stderr_path).unwrap_or_default()
    }

    /// Poll the daemon log until it contains every needle.
    fn wait_for_log(&mut self, needles: &[&str]) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            self.assert_running();
            let log = self.stderr();
            if needles.iter().all(|needle| log.contains(needle)) {
                return;
            }
            thread::sleep(Duration::from_millis(250));
        }
        panic!(
            "timed out waiting for log {needles:?}\nstderr:\n{}",
            self.stderr()
        );
    }

    fn assert_running(&mut self) {
        if let Ok(Some(status)) = self.child.try_wait() {
            panic!("rustbgpd exited: {status}\nstderr:\n{}", self.stderr());
        }
    }

    /// Poll until `pred` holds over the observed segment / Type 4 ESIs.
    fn wait_for(
        &mut self,
        grpc_addr: &str,
        what: &str,
        pred: impl Fn(&[String], &[String]) -> bool,
    ) -> (Vec<String>, Vec<String>) {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut last = None;
        while Instant::now() < deadline {
            self.assert_running();
            if let Some((segments, type4)) = observed(grpc_addr) {
                if pred(&segments, &type4) {
                    return (segments, type4);
                }
                last = Some((segments, type4));
            }
            thread::sleep(Duration::from_millis(250));
        }
        panic!(
            "timed out waiting for {what}; last observed {last:?}\nstderr:\n{}",
            self.stderr()
        );
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

const AUTO_LACP_SEGMENT: &str = r#"
[[ethernet_segments]]
esi = "auto-lacp"
interface = "pe-bond"
member_vnis = [100]
originator_ip = "10.0.0.10"
"#;

fn write_config(dir: &Path, segments: &str) -> std::path::PathBuf {
    let runtime_dir = dir.join("runtime");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::set_permissions(&runtime_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.join("rustbgpd.toml");
    std::fs::write(
        &path,
        format!(
            r#"
[security.grpc]
enforcement = "tier"

[security.grpc.roles]
"rustbgpd://operator/auto-lacp-test" = "operator"

[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 0
runtime_state_dir = "{runtime}"

[global.telemetry]
log_format = "json"

[global.telemetry.grpc_uds]
path = "{runtime}/grpc.sock"
principal = "rustbgpd://operator/auto-lacp-test"

[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.10"
{segments}"#,
            runtime = runtime_dir.display()
        ),
    )
    .unwrap();
    path
}

fn lacp_bond(name: &str, system_mac: &str, user_port_key: &str) {
    ip(&[
        "link",
        "add",
        name,
        "type",
        "bond",
        "mode",
        "802.3ad",
        "lacp_rate",
        "fast",
        "ad_actor_system",
        system_mac,
        "ad_user_port_key",
        user_port_key,
    ]);
}

/// PE bond with carrier but no LACP partner: its veth peer is a plain
/// interface until [`ce_adopts_peer_port`].
fn pe_bond_without_partner() {
    ip(&["link", "set", "lo", "up"]);
    lacp_bond("pe-bond", "02:aa:bb:cc:dd:ee", "3");
    lacp_bond("ce-bond", "02:11:22:33:44:55", "7");
    ip(&[
        "link", "add", "pe-port", "type", "veth", "peer", "name", "ce-port",
    ]);
    ip(&["link", "set", "pe-port", "master", "pe-bond"]);
    ip(&["link", "set", "ce-port", "up"]);
    ip(&["link", "set", "pe-bond", "up"]);
}

/// The CE adopts the PE's peer port, so LACP converges.
fn ce_adopts_peer_port() {
    ip(&["link", "set", "ce-port", "down"]);
    ip(&["link", "set", "ce-port", "master", "ce-bond"]);
    ip(&["link", "set", "ce-bond", "up"]);
}

fn start_daemon(dir: &Path, config: &Path) -> Daemon {
    let stderr_path = dir.join("rustbgpd.stderr.log");
    Daemon {
        child: Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
            .arg(config)
            // JSON logs go to stdout; keep both streams in one log.
            .stdout(Stdio::from(File::create(&stderr_path).unwrap()))
            .stderr(Stdio::from(
                File::options().append(true).open(&stderr_path).unwrap(),
            ))
            .spawn()
            .expect("spawn rustbgpd"),
        stderr_path,
    }
}

fn private_tempdir() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    temp
}

fn signal(daemon: &Daemon, name: &str) {
    let out = Command::new("kill")
        .args([&format!("-{name}"), &daemon.child.id().to_string()])
        .output()
        .expect("spawn kill");
    assert!(out.status.success(), "kill -{name} failed");
}

#[test]
fn auto_lacp_segment_follows_lacp_partner_without_restart() {
    if !netns_enabled()
        || !inner_netns_pass("auto_lacp_segment_follows_lacp_partner_without_restart")
    {
        return;
    }
    pe_bond_without_partner();
    let temp = private_tempdir();
    let config = write_config(temp.path(), AUTO_LACP_SEGMENT);
    let grpc_addr = format!("unix://{}/runtime/grpc.sock", temp.path().display());
    let mut daemon = start_daemon(temp.path(), &config);

    // NotReady: the daemon is up, lists no segment, originates no Type 4.
    daemon.wait_for(&grpc_addr, "NotReady with no routes", |segments, type4| {
        segments.is_empty() && type4.is_empty()
    });
    let stderr = daemon.stderr();
    assert!(
        stderr.contains("auto-lacp Ethernet Segment not ready") && stderr.contains("no_partner"),
        "NotReady reason must be observable:\n{stderr}"
    );

    // The CE adopts the peer port and LACP converges: Ready, no restart.
    ce_adopts_peer_port();
    let ce_prefix = "01:02:11:22:33:44:55:";
    let (segments, _) = daemon.wait_for(&grpc_addr, "Ready under the CE's ESI", |s, t| {
        s.len() == 1 && s[0].starts_with(ce_prefix) && t == s
    });
    let first = segments[0].clone();
    let octets: Vec<u8> = first
        .split(':')
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect();
    assert_eq!(octets.len(), 10);
    assert_eq!(octets[9], 0);
    assert_eq!(
        u16::from_be_bytes([octets[7], octets[8]]) >> 6,
        7,
        "ESI must carry the CE's port key, not the PE's: {first}"
    );

    // CE replaced (new LACP system MAC): old routes withdrawn, new ESI
    // originated, still no restart.
    ip(&["link", "set", "ce-bond", "down"]);
    ip(&[
        "link",
        "set",
        "ce-bond",
        "type",
        "bond",
        "ad_actor_system",
        "02:11:22:33:44:66",
    ]);
    ip(&["link", "set", "ce-bond", "up"]);
    let (segments, type4) =
        daemon.wait_for(&grpc_addr, "re-origination under the new ESI", |s, t| {
            s.len() == 1 && s[0].starts_with("01:02:11:22:33:44:66:") && t == s
        });
    assert!(!type4.contains(&first), "old Type 4 must be withdrawn");
    assert_eq!(segments, type4);
    daemon.assert_running();
}

#[test]
fn first_auto_lacp_segment_added_by_sighup_starts_live_and_drains_on_shutdown() {
    if !netns_enabled()
        || !inner_netns_pass(
            "first_auto_lacp_segment_added_by_sighup_starts_live_and_drains_on_shutdown",
        )
    {
        return;
    }
    pe_bond_without_partner();
    let temp = private_tempdir();
    let config = write_config(temp.path(), "");
    let grpc_addr = format!("unix://{}/runtime/grpc.sock", temp.path().display());
    let mut daemon = start_daemon(temp.path(), &config);

    // No Ethernet Segment: no segment task, no probe.
    daemon.wait_for(&grpc_addr, "startup with no segment", |segments, type4| {
        segments.is_empty() && type4.is_empty()
    });
    assert!(
        !daemon
            .stderr()
            .contains("starting the EVPN segment orchestrator"),
        "no segment, no segment task:\n{}",
        daemon.stderr()
    );

    // First segment by SIGHUP: committed not ready, probe started live.
    write_config(temp.path(), AUTO_LACP_SEGMENT);
    signal(&daemon, "HUP");
    daemon.wait_for_log(&["auto-lacp Ethernet Segment not ready", "no_partner"]);
    daemon.wait_for(&grpc_addr, "NotReady with no routes", |segments, type4| {
        segments.is_empty() && type4.is_empty()
    });

    // LACP converges: the segment actor starts and the segment is Ready.
    ce_adopts_peer_port();
    let (segments, type4) = daemon.wait_for(&grpc_addr, "Ready under the CE's ESI", |s, t| {
        s.len() == 1 && s[0].starts_with("01:02:11:22:33:44:55:") && t == s
    });
    assert_eq!(segments, type4);
    daemon.wait_for_log(&["starting the EVPN segment orchestrator"]);

    // Coordinated shutdown drains the live-started actor.
    signal(&daemon, "TERM");
    let status = daemon.child.wait().expect("wait for rustbgpd");
    let log = daemon.stderr();
    assert!(status.success(), "rustbgpd exited {status}\nstderr:\n{log}");
    assert!(
        log.contains("draining EVPN segment orchestrator"),
        "the live-started segment actor must be drained:\n{log}"
    );
}
