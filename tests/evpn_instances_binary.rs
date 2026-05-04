use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Daemon {
    child: Child,
}

impl Daemon {
    fn spawn(config_path: &Path) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
            .arg(config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn rustbgpd binary");
        Self { child }
    }

    fn assert_still_running(&mut self) {
        match self.child.try_wait() {
            Ok(None) => {}
            Ok(Some(status)) => panic!("rustbgpd exited before test completed: {status}"),
            Err(e) => panic!("failed to query rustbgpd child status: {e}"),
        }
    }

    fn shutdown(mut self, grpc_addr: &str) {
        let _ = rustbgpctl(grpc_addr, &["shutdown", "--reason", "evpn binary test"]);
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(_status)) => return,
                Ok(None) => thread::sleep(Duration::from_millis(50)),
                Err(_) => break,
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
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

fn rustbgpctl(grpc_addr: &str, args: &[&str]) -> Output {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_rustbgpctl") {
        let mut cmd = Command::new(path);
        cmd.arg("--addr").arg(grpc_addr).args(args).output()
    } else {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
        let mut cmd = Command::new(cargo);
        cmd.args(["run", "--quiet", "-p", "rustbgpctl", "--"])
            .arg("--addr")
            .arg(grpc_addr)
            .args(args)
            .output()
    }
    .expect("failed to spawn rustbgpctl subprocess")
}

fn wait_for_cli_json(grpc_addr: &str) -> Output {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last = None;
    while Instant::now() < deadline {
        let output = rustbgpctl(grpc_addr, &["--json", "evpn", "instances"]);
        if output.status.success() {
            return output;
        }
        last = Some(output);
        thread::sleep(Duration::from_millis(100));
    }
    let output = last.expect("rustbgpctl was never invoked");
    panic!(
        "rustbgpctl evpn instances did not succeed before timeout\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn write_config(dir: &Path) -> PathBuf {
    let runtime_dir = dir.join("runtime");
    let config_path = dir.join("rustbgpd.toml");
    let config = format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 0
runtime_state_dir = "{runtime_dir}"

[global.telemetry]
log_format = "json"

[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200", "65000:201"]
local_vtep_ip = "10.0.0.10"
bridge = "br200"
advertise_svi_mac = true

[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.10"
"#,
        runtime_dir = runtime_dir.display()
    );
    std::fs::write(&config_path, config).expect("failed to write test config");
    config_path
}

#[test]
fn daemon_binary_surfaces_configured_evpn_instances_through_rustbgpctl() {
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    let config_path = write_config(temp.path());
    let grpc_sock = temp.path().join("runtime").join("grpc.sock");
    let grpc_addr = format!("unix://{}", grpc_sock.display());
    let mut daemon = Daemon::spawn(&config_path);

    let json_output = wait_for_cli_json(&grpc_addr);
    daemon.assert_still_running();

    let instances: serde_json::Value =
        serde_json::from_slice(&json_output.stdout).expect("CLI JSON output must parse");
    let rows = instances
        .as_array()
        .expect("top-level JSON must be an array");
    assert_eq!(rows.len(), 2, "config declares exactly two EVPN instances");

    assert_eq!(rows[0]["vni"], 100);
    assert_eq!(rows[0]["rd"], "65000:100");
    assert_eq!(rows[0]["route_targets"], serde_json::json!(["65000:100"]));
    assert_eq!(rows[0]["local_vtep_ip"], "10.0.0.10");
    assert_eq!(rows[0]["bridge"], "");
    assert_eq!(rows[0]["advertise_svi_mac"], false);

    assert_eq!(rows[1]["vni"], 200);
    assert_eq!(rows[1]["rd"], "65000:200");
    assert_eq!(
        rows[1]["route_targets"],
        serde_json::json!(["65000:200", "65000:201"])
    );
    assert_eq!(rows[1]["local_vtep_ip"], "10.0.0.10");
    assert_eq!(rows[1]["bridge"], "br200");
    assert_eq!(rows[1]["advertise_svi_mac"], true);

    let human_output = rustbgpctl(&grpc_addr, &["evpn", "instances"]);
    assert!(
        human_output.status.success(),
        "human CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&human_output.stdout),
        String::from_utf8_lossy(&human_output.stderr),
    );
    let human = String::from_utf8(human_output.stdout).expect("human output must be utf-8");
    assert!(
        human.contains("vni=100 rd=65000:100 vtep=10.0.0.10 rts=[65000:100]"),
        "human output missing VNI 100 row:\n{human}"
    );
    assert!(
        human.contains(
            "vni=200 rd=65000:200 vtep=10.0.0.10 rts=[65000:200,65000:201] bridge=br200 advertise-svi-mac"
        ),
        "human output missing full VNI 200 row:\n{human}"
    );

    daemon.shutdown(&grpc_addr);
}
