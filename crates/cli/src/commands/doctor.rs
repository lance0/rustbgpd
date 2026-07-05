use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::connection::Connection;
use crate::error::CliError;
use crate::output;
use crate::proto::control_service_client::ControlServiceClient;
use crate::proto::global_service_client::GlobalServiceClient;
use crate::proto::{GetGlobalRequest, HealthRequest, MetricsRequest};

#[derive(Serialize)]
struct BundleManifest<'a> {
    generated_at_unix_seconds: u64,
    cli_version: &'a str,
    daemon_address: &'a str,
    token_file_configured: bool,
    files: Vec<&'static str>,
    note: &'static str,
}

#[derive(Serialize)]
struct HealthSnapshot {
    healthy: bool,
    uptime_seconds: u64,
    active_peers: u32,
    total_routes: u32,
}

#[derive(Serialize)]
struct GlobalSnapshot {
    asn: u32,
    router_id: String,
    listen_port: u32,
    tcp_ao_support: String,
    tcp_ao_detail: String,
}

#[derive(Serialize)]
struct EnvironmentSnapshot<'a> {
    os: &'a str,
    arch: &'a str,
    current_dir: String,
    daemon_address: &'a str,
    token_file_configured: bool,
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn default_bundle_dir() -> PathBuf {
    PathBuf::from(format!("rustbgpd-support-{}", now_unix_seconds()))
}

fn tcp_ao_support_label(value: i32) -> &'static str {
    match crate::proto::TcpAoSupport::try_from(value) {
        Ok(crate::proto::TcpAoSupport::Supported) => "supported",
        Ok(crate::proto::TcpAoSupport::Unsupported) => "unsupported",
        Ok(crate::proto::TcpAoSupport::ProbeFailed) => "probe_failed",
        Ok(crate::proto::TcpAoSupport::Unspecified) | Err(_) => "unknown",
    }
}

fn redact_text(input: &str) -> String {
    input
        .lines()
        .map(|line| {
            let lower = line.to_ascii_lowercase();
            if lower.contains("password")
                || lower.contains("secret")
                || lower.contains("token")
                || lower.contains("bearer")
            {
                "[REDACTED]".to_string()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), CliError> {
    let bytes = serde_json::to_vec_pretty(value)?;
    fs::write(path, bytes)?;
    Ok(())
}

pub async fn run(
    connection: Connection,
    output_dir: Option<&Path>,
    daemon_address: &str,
    token_file_configured: bool,
    json: bool,
) -> Result<(), CliError> {
    let bundle_dir = output_dir
        .map(PathBuf::from)
        .unwrap_or_else(default_bundle_dir);
    fs::create_dir_all(&bundle_dir)?;

    let mut control =
        ControlServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let mut global =
        GlobalServiceClient::with_interceptor(connection.channel(), connection.interceptor());

    let health = control.get_health(HealthRequest {}).await?.into_inner();
    let global_state = global.get_global(GetGlobalRequest {}).await?.into_inner();
    let metrics = control.get_metrics(MetricsRequest {}).await?.into_inner();

    write_json(
        &bundle_dir.join("health.json"),
        &HealthSnapshot {
            healthy: health.healthy,
            uptime_seconds: health.uptime_seconds,
            active_peers: health.active_peers,
            total_routes: health.total_routes,
        },
    )?;
    write_json(
        &bundle_dir.join("global.json"),
        &GlobalSnapshot {
            asn: global_state.asn,
            router_id: global_state.router_id,
            listen_port: global_state.listen_port,
            tcp_ao_support: tcp_ao_support_label(global_state.tcp_ao_support).to_string(),
            tcp_ao_detail: redact_text(&global_state.tcp_ao_detail),
        },
    )?;
    fs::write(
        bundle_dir.join("metrics.prom"),
        redact_text(&metrics.prometheus_text),
    )?;
    write_json(
        &bundle_dir.join("environment.json"),
        &EnvironmentSnapshot {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            current_dir: std::env::current_dir()?.display().to_string(),
            daemon_address,
            token_file_configured,
        },
    )?;
    write_json(
        &bundle_dir.join("manifest.json"),
        &BundleManifest {
            generated_at_unix_seconds: now_unix_seconds(),
            cli_version: env!("CARGO_PKG_VERSION"),
            daemon_address,
            token_file_configured,
            files: vec![
                "manifest.json",
                "health.json",
                "global.json",
                "metrics.prom",
                "environment.json",
            ],
            note: "No daemon config file or bearer token material is copied.",
        },
    )?;

    if json {
        output::print_json_line(&serde_json::json!({
            "bundle_dir": bundle_dir.display().to_string()
        }))?;
    } else {
        println!("Support bundle written: {}", bundle_dir.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::connection::connect;
    use crate::test_support::spawn_mock_server;

    #[test]
    fn redact_text_replaces_sensitive_lines() {
        let redacted = redact_text("ok 1\napi_token=secret\npassword = nope\nok 2");
        assert_eq!(redacted, "ok 1\n[REDACTED]\n[REDACTED]\nok 2");
    }

    #[tokio::test]
    async fn doctor_writes_bundle_and_calls_core_rpcs() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let bundle = dir.path().join("bundle");

        run(connection, Some(&bundle), &server.addr, false, true)
            .await
            .unwrap();

        assert!(bundle.join("manifest.json").exists());
        assert!(bundle.join("health.json").exists());
        assert!(bundle.join("global.json").exists());
        assert!(bundle.join("metrics.prom").exists());
        assert!(bundle.join("environment.json").exists());
        assert_eq!(server.state.health_calls.load(Ordering::SeqCst), 1);
        assert_eq!(server.state.global_calls.load(Ordering::SeqCst), 1);
        assert_eq!(server.state.metrics_calls.load(Ordering::SeqCst), 1);

        let manifest = fs::read_to_string(bundle.join("manifest.json")).unwrap();
        assert!(manifest.contains("No daemon config file or bearer token material is copied."));
    }
}
