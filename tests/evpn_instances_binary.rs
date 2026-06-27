use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Daemon {
    child: Child,
    stderr_path: PathBuf,
}

impl Daemon {
    fn spawn(config_path: &Path, stderr_path: PathBuf) -> Self {
        let stderr = File::create(&stderr_path).expect("failed to create daemon stderr log");
        let child = Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
            .arg(config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("failed to spawn rustbgpd binary");
        Self { child, stderr_path }
    }

    fn assert_still_running(&mut self) {
        match self.child.try_wait() {
            Ok(None) => {}
            Ok(Some(status)) => panic!(
                "rustbgpd exited before test completed: {status}\nstderr:\n{}",
                self.stderr()
            ),
            Err(e) => panic!("failed to query rustbgpd child status: {e}"),
        }
    }

    fn stderr(&self) -> String {
        std::fs::read_to_string(&self.stderr_path).unwrap_or_else(|e| {
            format!(
                "<failed to read daemon stderr {}: {e}>",
                self.stderr_path.display()
            )
        })
    }

    fn shutdown(mut self, grpc_addr: &str) {
        let _ = rbgp(grpc_addr, &["shutdown", "--reason", "evpn binary test"]);
        // The daemon has coordinated shutdown paths; this no-peer test should
        // finish well inside 5s even on a slow CI runner.
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

fn rbgp(grpc_addr: &str, args: &[&str]) -> Output {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_rbgp") {
        let mut cmd = Command::new(path);
        cmd.arg("--addr").arg(grpc_addr).args(args).output()
    } else {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
        let mut cmd = Command::new(cargo);
        cmd.args(["run", "--quiet", "-p", "rustbgpctl", "--bin", "rbgp", "--"])
            .arg("--addr")
            .arg(grpc_addr)
            .args(args)
            .output()
    }
    .expect("failed to spawn rbgp subprocess")
}

fn wait_for_cli_json(grpc_addr: &str, daemon: &mut Daemon) -> Output {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last = None;
    while Instant::now() < deadline {
        let output = rbgp(grpc_addr, &["--json", "evpn", "instances"]);
        if output.status.success() {
            return output;
        }
        last = Some(output);
        daemon.assert_still_running();
        thread::sleep(Duration::from_millis(100));
    }
    let output = last.expect("rbgp was never invoked");
    panic!(
        "rbgp evpn instances did not succeed before timeout\nstatus: {}\nstdout:\n{}\nstderr:\n{}\ndaemon stderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        daemon.stderr(),
    );
}

fn write_config(dir: &Path) -> PathBuf {
    let runtime_dir = dir.join("runtime");
    std::fs::create_dir_all(&runtime_dir).expect("failed to create runtime dir");
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

[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200", "65000:201"]
local_vtep_ip = "10.0.0.10"
bridge = "br200"
bridge_vlan = 20
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

fn optional_json_string<'a>(row: &'a serde_json::Value, key: &str) -> &'a str {
    row.get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
}

#[test]
fn daemon_binary_surfaces_configured_evpn_instances_through_rbgp() {
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    let config_path = write_config(temp.path());
    let grpc_sock = temp.path().join("runtime").join("grpc.sock");
    let grpc_addr = format!("unix://{}", grpc_sock.display());
    let stderr_path = temp.path().join("rustbgpd.stderr.log");
    let mut daemon = Daemon::spawn(&config_path, stderr_path);

    let json_output = wait_for_cli_json(&grpc_addr, &mut daemon);
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
    assert_eq!(optional_json_string(&rows[0], "bridge"), "");
    assert!(
        rows[0].as_object().unwrap().contains_key("bridge_vlan"),
        "bridge_vlan must be present even when absent in config"
    );
    assert!(rows[0]["bridge_vlan"].is_null());
    assert_eq!(rows[0]["advertise_svi_mac"], false);
    assert_eq!(rows[0]["readiness"], "unbound");
    assert_eq!(optional_json_string(&rows[0], "not_ready_reason"), "");

    assert_eq!(rows[1]["vni"], 200);
    assert_eq!(rows[1]["rd"], "65000:200");
    assert_eq!(
        rows[1]["route_targets"],
        serde_json::json!(["65000:200", "65000:201"])
    );
    assert_eq!(rows[1]["local_vtep_ip"], "10.0.0.10");
    assert_eq!(optional_json_string(&rows[1], "bridge"), "br200");
    assert_eq!(rows[1]["bridge_vlan"], 20);
    assert_eq!(rows[1]["advertise_svi_mac"], true);
    assert_eq!(rows[1]["readiness"], "not-ready");
    assert_eq!(
        optional_json_string(&rows[1], "not_ready_reason"),
        "bridge br200 not found"
    );

    let human_output = rbgp(&grpc_addr, &["evpn", "instances"]);
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
            "vni=200 rd=65000:200 vtep=10.0.0.10 rts=[65000:200,65000:201] readiness=not-ready bridge=br200 bridge-vlan=20 advertise-svi-mac originated-local-macs=0 reason=[bridge br200 not found]"
        ),
        "human output missing full VNI 200 row:\n{human}"
    );

    daemon.shutdown(&grpc_addr);
}
