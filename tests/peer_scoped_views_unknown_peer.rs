//! Peer-scoped `rbgp` views against a real daemon: an address that names no
//! peer exits non-zero naming the address in every output mode, while a
//! configured peer with no routes keeps its successful empty state.

mod support;

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};

const CONFIGURED: &str = "127.0.0.2";
const UNKNOWN: &str = "192.0.2.99";

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn write_config(dir: &Path) -> std::path::PathBuf {
    let runtime_dir = dir.join("runtime");
    std::fs::create_dir_all(&runtime_dir).expect("create runtime dir");
    std::fs::set_permissions(&runtime_dir, std::fs::Permissions::from_mode(0o700))
        .expect("make runtime dir private");
    let config_path = dir.join("rustbgpd.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 0
listen_addresses = ["127.0.0.1"]
runtime_state_dir = "{runtime_dir}"

[global.telemetry]
log_format = "json"

[global.telemetry.grpc_uds]
path = "{runtime_dir}/grpc.sock"

[[neighbors]]
address = "{CONFIGURED}"
remote_asn = 65002
"#,
            runtime_dir = runtime_dir.display()
        ),
    )
    .expect("write test config");
    config_path
}

fn rbgp(grpc_addr: &str, args: &[&str]) -> Output {
    Command::new(support::rbgp_binary())
        .arg("--addr")
        .arg(grpc_addr)
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .expect("run rbgp")
}

fn describe(args: &[&str], output: &Output) -> String {
    format!(
        "rbgp {}\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        args.join(" "),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    )
}

/// Every peer-scoped view, in each output form it supports, for `peer`.
fn views(peer: &str) -> Vec<Vec<&str>> {
    let mut views = Vec::new();
    for view in ["received", "advertised"] {
        views.push(vec!["rib", view, peer]);
        views.push(vec!["-j", "rib", view, peer]);
        views.push(vec!["rib", view, peer, "--count"]);
        views.push(vec!["-j", "rib", view, peer, "--count"]);
        views.push(vec!["--json-lines", "rib", view, peer]);
        views.push(vec!["evpn", view, peer]);
        views.push(vec!["-j", "evpn", view, peer]);
    }
    for args in [
        vec!["flowspec", "received", peer],
        vec!["-j", "flowspec", "received", peer],
        vec!["bfd", "show", peer],
        vec!["-j", "bfd", "show", peer],
    ] {
        views.push(args);
    }
    views
}

#[test]
fn peer_scoped_views_fail_for_unknown_peer_and_stay_empty_for_configured_peer() {
    let temp = support::RetainOnPanic::new(tempfile::tempdir().expect("create temp dir"));
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))
        .expect("make temp dir private");
    let config_path = write_config(temp.path());
    let log = std::fs::File::create(temp.path().join("rustbgpd.log")).expect("daemon log");
    let mut daemon = Daemon(
        Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
            .arg(&config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            .spawn()
            .expect("spawn rustbgpd"),
    );
    let sock = temp.path().join("runtime").join("grpc.sock");
    support::wait_until_grpc_socket_accepts(&sock, &mut daemon.0);
    let grpc_addr = format!("unix://{}", sock.display());

    for args in views(CONFIGURED) {
        let output = rbgp(&grpc_addr, &args);
        assert!(output.status.success(), "{}", describe(&args, &output));
    }

    let expected = format!("Error: not found: neighbor {UNKNOWN} not found");
    for args in views(UNKNOWN) {
        let output = rbgp(&grpc_addr, &args);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{}",
            describe(&args, &output)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(&expected),
            "{}",
            describe(&args, &output)
        );
    }
}
