//! Native mTLS CLI proof with the shared M44 certificate identities.

mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn output(mut command: tokio::process::Command) -> Output {
    command.kill_on_drop(true);
    tokio::time::timeout(Duration::from_secs(40), command.output())
        .await
        .expect("CLI completed within its bounded read/connection budgets")
        .expect("run rbgp")
}

fn cli(addr: &str, certs: &Path, identity: Option<&str>) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(support::rbgp_binary());
    command
        .env("RUSTBGPD_ADDR", addr)
        .env("RUSTBGPD_TLS_CA", certs.join("ca.pem"))
        .env("RUSTBGPD_TLS_SERVER_NAME", "rustbgpd.local")
        .env_remove("RUSTBGPD_TLS_CERT")
        .env_remove("RUSTBGPD_TLS_KEY")
        .env_remove("RUSTBGPD_TOKEN_FILE");
    if let Some(identity) = identity {
        command
            .env("RUSTBGPD_TLS_CERT", certs.join(format!("{identity}.pem")))
            .env("RUSTBGPD_TLS_KEY", certs.join(format!("{identity}.key")));
    }
    command
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_failure(output: &Output, expected: &str) {
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains(expected), "expected {expected}: {error}");
    assert!(!error.contains("PRIVATE KEY"), "{error}");
    assert!(!error.contains("private-fixture-token"), "{error}");
    assert!(!error.contains("is the daemon running"), "{error}");
}

#[tokio::test]
async fn native_mtls_supports_cli_reads_mutation_and_distinct_rejections() {
    let temp = support::RetainOnPanic::new(tempfile::tempdir().unwrap());
    let dir = temp.path();
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
    let certs = dir.join("certs");
    let generated = Command::new("bash")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/interop/scripts/gen-m44-certs.sh"))
        .env("RUSTBGPD_MTLS_CERT_DIR", &certs)
        .output()
        .unwrap();
    assert_success(&generated);
    let runtime = dir.join("runtime");
    fs::create_dir(&runtime).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    let config = dir.join("rustbgpd.toml");
    fs::write(
        &config,
        format!(
            r#"
[global]
asn = 65001
router_id = "127.0.0.1"
listen_port = 0
listen_addresses = ["127.0.0.1"]
runtime_state_dir = {runtime:?}

[global.telemetry]
log_format = "json"
prometheus_addr = "127.0.0.1:0"

[global.telemetry.grpc_tcp]
address = "127.0.0.1:0"
tls_cert_file = {server_cert:?}
tls_key_file = {server_key:?}
tls_client_ca_file = {ca:?}

[security.grpc.roles]
"rustbgpd://operator/ci" = "operator"

[[neighbors]]
address = "127.0.0.2"
remote_asn = 65002
"#,
            runtime = runtime.to_str().unwrap(),
            server_cert = certs.join("server.pem").to_str().unwrap(),
            server_key = certs.join("server.key").to_str().unwrap(),
            ca = certs.join("ca.pem").to_str().unwrap(),
        ),
    )
    .unwrap();
    let log = dir.join("daemon.log");
    let mut daemon = Daemon(
        Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
            .arg(&config)
            .stdout(Stdio::from(fs::File::create(&log).unwrap()))
            .stderr(Stdio::from(
                fs::File::create(dir.join("daemon.stderr")).unwrap(),
            ))
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    let addr = loop {
        let logs = fs::read_to_string(&log).unwrap();
        if let Some(addr) = support::bound_grpc_addr(&logs) {
            break format!("https://{addr}");
        }
        assert!(
            daemon.0.try_wait().unwrap().is_none(),
            "daemon exited: {logs}"
        );
        assert!(Instant::now() < deadline, "no bound gRPC listener: {logs}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    };

    for args in [vec!["health"], vec!["neighbor", "127.0.0.2"]] {
        let mut command = cli(&addr, &certs, Some("operator"));
        command.args(args);
        assert_success(&output(command).await);
    }
    let token = dir.join("bearer.token");
    fs::write(&token, "private-fixture-token\n").unwrap();
    let mut command = cli(&addr, &certs, Some("operator"));
    command.env("RUSTBGPD_TOKEN_FILE", &token).arg("health");
    assert_success(&output(command).await);

    let mut command = cli(&addr, &certs, Some("operator"));
    command.args(["--tls-server-name", "wrong.example", "health"]);
    assert_failure(&output(command).await, "name does not match");

    let mut command = cli(&addr, &certs, Some("operator"));
    command.env_remove("RUSTBGPD_TLS_CA").arg("health");
    assert_failure(&output(command).await, "HTTPS requires --tls-ca");

    let mut command = cli(&addr, &certs, Some("operator"));
    // A leaf from the same fixture is not the server's issuing CA.
    command
        .arg("--tls-ca")
        .arg(certs.join("intruder.pem"))
        .arg("health");
    assert_failure(&output(command).await, "server certificate is not trusted");

    let mut command = cli(&addr, &certs, Some("operator"));
    command.env_remove("RUSTBGPD_TLS_KEY").arg("health");
    assert_failure(&output(command).await, "--tls-key");

    let mut command = cli(&addr, &certs, Some("operator"));
    command
        .arg("--tls-key")
        .arg(certs.join("intruder.key"))
        .arg("health");
    let mismatched = output(command).await;
    assert_failure(&mismatched, "invalid TLS configuration");
    assert!(String::from_utf8_lossy(&mismatched.stderr).contains("KeyMismatch"));

    let mut command = cli(&addr, &certs, None);
    command.arg("health");
    assert_failure(&output(command).await, "client identity is not configured");

    let mut command = cli(&addr, &certs, Some("intruder"));
    command.arg("health");
    let denied = output(command).await;
    assert_failure(&denied, "permission denied");
    assert!(String::from_utf8_lossy(&denied.stderr).contains("rustbgpd://intruder/ci"));

    let mut command = cli(&addr, &certs, Some("operator"));
    command.args(["neighbor", "127.0.0.2", "delete"]);
    assert_success(&output(command).await);
    let mut command = cli(&addr, &certs, Some("operator"));
    command.args(["neighbor", "--json"]);
    let neighbors = output(command).await;
    assert_success(&neighbors);
    assert!(!String::from_utf8_lossy(&neighbors.stdout).contains("127.0.0.2"));

    let mut command = cli(&addr, &certs, Some("operator"));
    command
        .args(["doctor", "--json", "--output"])
        .arg(dir.join("doctor.tar.gz"));
    let doctor = output(command).await;
    let report: serde_json::Value = serde_json::from_slice(&doctor.stdout).unwrap();
    assert!(report["checks"].as_array().unwrap().iter().any(|check| {
        check["name"] == "daemon.authz.identity"
            && check["detail"]
                .as_str()
                .unwrap()
                .contains("TLS with a client certificate")
    }));
}
