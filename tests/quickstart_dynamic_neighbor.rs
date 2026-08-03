//! Real-binary receipt for the Quickstart passwordless peer-group flow.
//!
//! The test stages both starter paths named by the guide, isolates their
//! runtime listeners, extracts the JSON and CLI commands from the guide
//! itself, and proves runtime apply plus durable persistence.

use std::fs::File;
use std::os::unix::fs::PermissionsExt as _;
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
        let stderr = File::create(&stderr_path).expect("create daemon stderr log");
        let child = Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
            .arg(config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("spawn rustbgpd");
        Self { child, stderr_path }
    }

    fn assert_running(&mut self) {
        match self.child.try_wait() {
            Ok(None) => {}
            Ok(Some(status)) => panic!(
                "rustbgpd exited early: {status}\nstderr:\n{}",
                self.stderr()
            ),
            Err(error) => panic!("query rustbgpd status: {error}"),
        }
    }

    fn stderr(&self) -> String {
        std::fs::read_to_string(&self.stderr_path)
            .unwrap_or_else(|error| format!("<failed to read daemon stderr: {error}>"))
    }

    fn shutdown(mut self, grpc_addr: &str, cwd: &Path) {
        let output = rbgp(grpc_addr, cwd, &["shutdown", "--reason", "quickstart test"]);
        assert!(
            output.status.success(),
            "rbgp shutdown failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => thread::sleep(Duration::from_millis(50)),
                Err(_) => break,
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        panic!("rustbgpd did not stop after rbgp shutdown");
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

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn rbgp(grpc_addr: &str, cwd: &Path, args: &[&str]) -> Output {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_rbgp") {
        let mut command = Command::new(path);
        command
            .arg("--addr")
            .arg(grpc_addr)
            .args(args)
            .current_dir(cwd)
            .output()
    } else {
        let sibling = Path::new(env!("CARGO_BIN_EXE_rustbgpd"))
            .parent()
            .expect("rustbgpd binary has parent")
            .join("rbgp");
        if sibling.is_file() {
            let mut command = Command::new(sibling);
            command
                .arg("--addr")
                .arg(grpc_addr)
                .args(args)
                .current_dir(cwd)
                .output()
        } else {
            let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
            let mut command = Command::new(cargo);
            command
                .arg("run")
                .arg("--quiet")
                .arg("--manifest-path")
                .arg(repo_root().join("Cargo.toml"))
                .args(["-p", "rustbgpctl", "--bin", "rbgp", "--"])
                .arg("--addr")
                .arg(grpc_addr)
                .args(args)
                .current_dir(cwd)
                .output()
        }
    }
    .expect("run rbgp")
}

fn wait_until_serving(grpc_addr: &str, cwd: &Path, daemon: &mut Daemon) {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last = None;
    while Instant::now() < deadline {
        let output = rbgp(grpc_addr, cwd, &["--json", "peer-group", "list"]);
        if output.status.success() {
            return;
        }
        last = Some(output);
        daemon.assert_running();
        thread::sleep(Duration::from_millis(100));
    }
    let last = last.expect("rbgp readiness probe ran");
    panic!(
        "rustbgpd gRPC never became ready\nstatus: {}\nstdout:\n{}\nstderr:\n{}\ndaemon stderr:\n{}",
        last.status,
        String::from_utf8_lossy(&last.stdout),
        String::from_utf8_lossy(&last.stderr),
        daemon.stderr()
    );
}

fn documented_flow() -> (String, Vec<String>) {
    let quickstart =
        std::fs::read_to_string(repo_root().join("docs/QUICKSTART.md")).expect("read Quickstart");
    let start = quickstart
        .find("cat > ix-members.json <<'JSON'")
        .expect("Quickstart passwordless JSON start");
    let block = &quickstart[start..];
    let end = block
        .find("# Manage Linux unicast FIB-export tables.")
        .expect("Quickstart passwordless flow end");
    let block = &block[..end];
    let json_start = block.find('{').expect("documented JSON object");
    let json_end = block.find("\nJSON\n").expect("documented JSON terminator");
    let json = block[json_start..json_end].to_string();
    let commands = block
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("rbgp "))
        .map(str::to_owned)
        .collect::<Vec<_>>();

    let parsed: serde_json::Value = serde_json::from_str(&json).expect("documented JSON parses");
    assert_eq!(
        parsed,
        serde_json::json!({
            "families": ["ipv4_unicast"],
            "route_server_client": true
        }),
        "Quickstart JSON must stay ordinary and omit both password fields"
    );
    assert_eq!(
        commands,
        [
            "rbgp peer-group set ix-members --from-file ix-members.json",
            "rbgp --json peer-group get ix-members",
            "rbgp dynamic-neighbor add 10.0.0.0/24 --peer-group ix-members",
            "rbgp --json dynamic-neighbor list",
        ],
        "the documented prerequisite/group/range flow changed"
    );
    (json, commands)
}

fn lab_profile() -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
        .args(["--init-config", "lab", "--stdout"])
        .current_dir(repo_root())
        .output()
        .expect("generate lab profile");
    assert!(
        output.status.success(),
        "lab profile generation failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("lab profile is UTF-8")
}

fn isolated_config(source: &str, runtime_dir: &Path) -> String {
    let mut config: toml::Value = toml::from_str(source).expect("starter config parses");
    let global = config
        .get_mut("global")
        .and_then(toml::Value::as_table_mut)
        .expect("starter has [global]");
    global.insert("listen_port".into(), toml::Value::Integer(0));
    global.insert(
        "runtime_state_dir".into(),
        toml::Value::String(runtime_dir.display().to_string()),
    );
    let telemetry = global
        .get_mut("telemetry")
        .and_then(toml::Value::as_table_mut)
        .expect("starter has [global.telemetry]");
    telemetry.insert(
        "prometheus_addr".into(),
        toml::Value::String("127.0.0.1:0".into()),
    );
    // Preserve absence so minimal exercises the production implicit listener;
    // explicit starter listeners still need their path isolated.
    if let Some(grpc_uds) = telemetry
        .get_mut("grpc_uds")
        .and_then(toml::Value::as_table_mut)
    {
        grpc_uds.insert(
            "path".into(),
            toml::Value::String(runtime_dir.join("grpc.sock").display().to_string()),
        );
        grpc_uds.insert("enabled".into(), toml::Value::Boolean(true));
    }
    toml::to_string_pretty(&config).expect("serialize isolated starter")
}

fn assert_success(label: &str, command: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{label}: {command} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn strict_check(config_path: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
        .args(["--check", "--strict"])
        .arg(config_path)
        .current_dir(repo_root())
        .output()
        .expect("run strict config gate")
}

fn run_starter(label: &str, source: &str, group_json: &str, commands: &[String]) {
    let temp = tempfile::tempdir().expect("create scenario tempdir");
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))
        .expect("make temp dir private");
    let runtime_dir = temp.path().join(format!("{label}-runtime"));
    std::fs::create_dir_all(&runtime_dir).expect("create runtime dir");
    let config_path = temp.path().join("config.toml");
    std::fs::write(&config_path, isolated_config(source, &runtime_dir))
        .expect("write isolated config");
    std::fs::write(temp.path().join("ix-members.json"), group_json)
        .expect("write documented group JSON");

    let grpc_addr = format!("unix://{}", runtime_dir.join("grpc.sock").display());
    let mut daemon = Daemon::spawn(&config_path, temp.path().join("rustbgpd.stderr.log"));
    wait_until_serving(&grpc_addr, temp.path(), &mut daemon);

    let missing = rbgp(
        &grpc_addr,
        temp.path(),
        &[
            "dynamic-neighbor",
            "add",
            "10.0.0.0/24",
            "--peer-group",
            "ix-members",
        ],
    );
    assert!(
        !missing.status.success(),
        "{label}: missing peer group unexpectedly accepted"
    );
    let missing_stderr = String::from_utf8_lossy(&missing.stderr).to_ascii_lowercase();
    assert!(
        missing_stderr.contains("peer_group") && missing_stderr.contains("not defined"),
        "{label}: missing-group rejection lost its prerequisite meaning:\n{missing_stderr}"
    );
    let initial_ranges = rbgp(
        &grpc_addr,
        temp.path(),
        &["--json", "dynamic-neighbor", "list"],
    );
    assert_success(label, "initial dynamic-neighbor list", &initial_ranges);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&initial_ranges.stdout).unwrap(),
        serde_json::json!([]),
        "{label}: rejected range became visible"
    );

    let mut group = None;
    let mut ranges = None;
    for documented in commands {
        let args = documented.split_whitespace().skip(1).collect::<Vec<_>>();
        let output = rbgp(&grpc_addr, temp.path(), &args);
        assert_success(label, documented, &output);
        if documented == "rbgp --json peer-group get ix-members" {
            group = Some(
                serde_json::from_slice::<serde_json::Value>(&output.stdout)
                    .expect("peer-group get JSON"),
            );
        } else if documented == "rbgp --json dynamic-neighbor list" {
            ranges = Some(
                serde_json::from_slice::<serde_json::Value>(&output.stdout)
                    .expect("dynamic-neighbor list JSON"),
            );
        }
    }

    let group = group.expect("documented peer-group get ran");
    assert_eq!(group["name"], "ix-members", "{label}: wrong group name");
    assert_eq!(
        group["families"],
        serde_json::json!(["ipv4_unicast"]),
        "{label}: wrong group families"
    );
    assert_eq!(
        group["route_server_client"], true,
        "{label}: route-server-client bit was not applied"
    );
    assert_eq!(
        group["has_md5_password"], false,
        "{label}: passwordless group reports a password"
    );
    assert!(
        !group.as_object().unwrap().contains_key("md5_password"),
        "{label}: read output exposed a password field"
    );

    let ranges = ranges.expect("documented dynamic-neighbor list ran");
    assert_eq!(
        ranges,
        serde_json::json!([{
            "prefix": "10.0.0.0/24",
            "peer_group": "ix-members",
            "remote_asn": 0,
            "description": ""
        }]),
        "{label}: runtime range differs from the documented command"
    );

    let persisted = std::fs::read_to_string(&config_path).expect("read persisted config");
    assert!(
        !persisted.contains("md5_password"),
        "{label}: passwordless persistence wrote a password field"
    );
    let persisted_toml: toml::Value = toml::from_str(&persisted).expect("persisted TOML parses");
    let persisted_group = &persisted_toml["peer_groups"]["ix-members"];
    assert_eq!(
        persisted_group["families"]
            .as_array()
            .expect("persisted families")
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>(),
        ["ipv4_unicast"]
    );
    assert_eq!(persisted_group["route_server_client"].as_bool(), Some(true));
    let persisted_ranges = persisted_toml["dynamic_neighbors"]
        .as_array()
        .expect("persisted dynamic-neighbor array");
    assert_eq!(persisted_ranges.len(), 1);
    assert_eq!(persisted_ranges[0]["prefix"].as_str(), Some("10.0.0.0/24"));
    assert_eq!(
        persisted_ranges[0]["peer_group"].as_str(),
        Some("ix-members")
    );

    daemon.shutdown(&grpc_addr, temp.path());

    let mut strict_probe = persisted_toml.clone();
    let policy = strict_probe["policy"]
        .as_table_mut()
        .expect("starter has global policy assignments");
    policy.remove("import_chain");
    policy.remove("export_chain");
    let strict_probe_path = temp.path().join("strict-probe.toml");
    std::fs::write(
        &strict_probe_path,
        toml::to_string_pretty(&strict_probe).expect("serialize strict probe"),
    )
    .expect("write strict probe");
    let strict_probe_output = strict_check(&strict_probe_path);
    assert!(
        !strict_probe_output.status.success(),
        "{label}: strict-only policy warning probe unexpectedly passed"
    );

    let strict = strict_check(&config_path);
    assert!(
        strict.status.success(),
        "{label}: persisted Quickstart flow failed final --check --strict\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&strict.stdout),
        String::from_utf8_lossy(&strict.stderr)
    );
    assert!(
        String::from_utf8_lossy(&strict.stdout).contains("config OK"),
        "{label}: strict gate exited cleanly without its success receipt"
    );
}

#[test]
fn documented_passwordless_dynamic_neighbor_flow_works_for_both_starters() {
    let (group_json, commands) = documented_flow();
    let lab = lab_profile();
    let minimal = std::fs::read_to_string(repo_root().join("examples/minimal/config.toml"))
        .expect("read examples/minimal config");

    run_starter("lab", &lab, &group_json, &commands);
    run_starter("minimal", &minimal, &group_json, &commands);
}
