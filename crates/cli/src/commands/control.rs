use crate::connection::{
    Connection, MRT_DUMP_RPC_TIMEOUT, MUTATION_RPC_TIMEOUT, mutation_budget, mutation_rpc,
    read_rpc, rpc_with_timeout,
};
use crate::error::CliError;
use crate::output::{self, JsonHealth, outln};
use crate::proto::control_service_client::ControlServiceClient;
use crate::proto::{
    CheckLivenessRequest, HealthRequest, MetricsRequest, ShutdownRequest, TriggerMrtDumpRequest,
};
use std::collections::BTreeMap;
use std::net::SocketAddr;

/// `google.rpc.Status`, the payload of the `grpc-status-details-bin` trailer.
#[derive(Clone, PartialEq, prost::Message)]
struct RpcStatus {
    #[prost(message, repeated, tag = "3")]
    details: Vec<prost_types::Any>,
}

/// `google.rpc.ErrorInfo`, reason and domain only.
#[derive(Clone, PartialEq, prost::Message)]
struct ErrorInfo {
    #[prost(string, tag = "1")]
    reason: String,
    #[prost(string, tag = "2")]
    domain: String,
}

/// The daemon-gate reason (`DAEMON_SHUTTING_DOWN`,
/// `RUNTIME_CONFIG_RECOVERY_FENCE`, ...) of a `GetHealth` `UNAVAILABLE`:
/// the `google.rpc.ErrorInfo` reason in the `rustbgpd` domain. `None` for a
/// probe deadline miss or any other status. A gate fault lasts until the
/// daemon exits, so a caller should not retry it.
pub(crate) fn health_gate_reason(status: &tonic::Status) -> Option<String> {
    use prost::Message as _;
    if status.code() != tonic::Code::Unavailable {
        return None;
    }
    RpcStatus::decode(status.details())
        .ok()?
        .details
        .iter()
        .filter(|any| any.type_url == "type.googleapis.com/google.rpc.ErrorInfo")
        .filter_map(|any| ErrorInfo::decode(any.value.as_slice()).ok())
        .find(|info| info.domain == "rustbgpd")
        .map(|info| info.reason)
}

/// `rbgp health` error for a `GetHealth` status: a daemon-gate fault names
/// its reason instead of reading as a temporary miss.
fn health_error(status: tonic::Status) -> CliError {
    match health_gate_reason(&status) {
        Some(reason) => CliError::Rpc(format!("daemon not ready ({reason}): {}", status.message())),
        None => status.into(),
    }
}

/// Sum a complete, unique, valid IPv4 + IPv6 RPKI VRP gauge snapshot.
/// `Some(0)` distinguishes a synchronized empty table from an unusable snapshot.
pub(crate) fn rpki_vrp_count_sum(prometheus_text: &str) -> Option<u64> {
    const NAME: &str = "bgp_rpki_vrp_count";

    let mut by_family = [None, None];
    for line in prometheus_text.lines().map(str::trim) {
        let Some(rest) = line.strip_prefix(NAME) else {
            continue;
        };
        let family = if let Some(value) = rest.strip_prefix(r#"{afi="ipv4"}"#) {
            Some((0, value))
        } else if let Some(value) = rest.strip_prefix(r#"{afi="ipv6"}"#) {
            Some((1, value))
        } else if rest.is_empty()
            || rest.starts_with('{')
            || rest.as_bytes().first().is_some_and(u8::is_ascii_whitespace)
        {
            return None;
        } else {
            continue;
        };
        let (index, value_text) = family?;
        if by_family[index].is_some()
            || !value_text
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_whitespace)
        {
            return None;
        };
        let mut fields = value_text.split_ascii_whitespace();
        let value = fields.next()?.parse::<u64>().ok()?;
        if fields.next().is_some() {
            return None;
        }
        by_family[index] = Some(value);
    }
    by_family[0]?.checked_add(by_family[1]?)
}

/// Parse the exact per-cache retained End-of-Data readiness gauge family.
/// Any malformed exact-name row invalidates the snapshot; similarly-prefixed
/// metric families are unrelated and ignored.
pub(crate) fn rpki_cache_end_of_data_readiness(
    prometheus_text: &str,
) -> Option<BTreeMap<SocketAddr, bool>> {
    const NAME: &str = "bgp_rpki_cache_end_of_data_ready";
    let mut readiness = BTreeMap::new();

    for line in prometheus_text.lines().map(str::trim) {
        let Some(rest) = line.strip_prefix(NAME) else {
            continue;
        };
        if !rest.starts_with('{') {
            if rest.is_empty() || rest.as_bytes().first().is_some_and(u8::is_ascii_whitespace) {
                return None;
            }
            continue;
        }
        let labels_and_value = rest.strip_prefix(r#"{cache=""#)?;
        let (cache, value_text) = labels_and_value.split_once(r#""}"#)?;
        if cache.is_empty()
            || !value_text
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_whitespace)
        {
            return None;
        }
        let cache = cache.parse::<SocketAddr>().ok()?;
        let mut fields = value_text.split_ascii_whitespace();
        let value = match fields.next()? {
            "0" => false,
            "1" => true,
            _ => return None,
        };
        if fields.next().is_some() || readiness.insert(cache, value).is_some() {
            return None;
        }
    }
    Some(readiness)
}

fn json_health(resp: &crate::proto::HealthResponse) -> JsonHealth {
    JsonHealth {
        healthy: resp.healthy,
        uptime_seconds: resp.uptime_seconds,
        active_peers: resp.active_peers,
        total_routes: resp.total_routes,
        daemon_version: (!resp.daemon_version.is_empty()).then(|| resp.daemon_version.clone()),
    }
}

pub async fn health(connection: Connection, json: bool, liveness: bool) -> Result<(), CliError> {
    let mut client =
        ControlServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    if liveness {
        read_rpc(
            "CheckLiveness",
            client.check_liveness(CheckLivenessRequest {}),
        )
        .await?;
        if json {
            output::print_json_pretty(&serde_json::json!({"alive": true}))?;
        } else {
            outln!("alive")?;
        }
        return Ok(());
    }
    let resp = read_rpc("GetHealth", client.get_health(HealthRequest {}))
        .await
        .map_err(health_error)?
        .into_inner();

    if json {
        let out = json_health(&resp);
        output::print_json_pretty(&out)?;
    } else {
        // `active_peers` counts configured peers whose session reports
        // Established.
        outln!(
            "Status:            {}",
            output::colored_health(resp.healthy)
        )?;
        outln!(
            "Uptime:            {}",
            output::format_duration(resp.uptime_seconds)
        )?;
        outln!("Established peers: {}", resp.active_peers)?;
        outln!("Routes:            {}", resp.total_routes)?;
        // The running process, which can differ from the binary on disk
        // after a package upgrade without a restart.
        if !resp.daemon_version.is_empty() {
            outln!("Version:           {}", resp.daemon_version)?;
        }
    }
    Ok(())
}

pub async fn metrics(connection: Connection) -> Result<(), CliError> {
    let mut client = connection.metrics_client();
    let resp = read_rpc("GetMetrics", client.get_metrics(MetricsRequest {}))
        .await?
        .into_inner();
    output::print_text(&resp.prometheus_text)?;
    Ok(())
}

pub async fn shutdown(
    connection: Connection,
    reason: Option<String>,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        ControlServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    mutation_rpc(
        "Shutdown",
        MUTATION_RPC_TIMEOUT,
        "`rbgp health`",
        client.shutdown(ShutdownRequest {
            reason: reason.unwrap_or_default(),
        }),
    )
    .await?;
    output::print_result(json, "shutdown", "", "Shutdown requested")
}

/// The daemon treats a disconnected caller as a cancellation until the RIB
/// snapshot arrives: a queued dump is skipped and a snapshot wait is
/// abandoned. Once encoding starts the dump runs to completion. Say so
/// instead of the generic "may still apply" notice.
fn mrt_dump_deadline(status: tonic::Status) -> tonic::Status {
    if status.code() != tonic::Code::DeadlineExceeded {
        return status;
    }
    tonic::Status::deadline_exceeded(format!(
        "{}; a dump still queued or waiting for its RIB snapshot is cancelled when \
         rbgp disconnects, but one already encoding or writing still completes; check \
         for a new file in the `[mrt] output_dir` directory",
        status.message()
    ))
}

pub async fn mrt_dump(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut client =
        ControlServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = rpc_with_timeout(
        "TriggerMrtDump",
        mutation_budget(MRT_DUMP_RPC_TIMEOUT),
        client.trigger_mrt_dump(TriggerMrtDumpRequest {}),
    )
    .await
    .map_err(mrt_dump_deadline)?
    .into_inner();

    if json {
        output::print_json_line(&serde_json::json!({ "file_path": resp.file_path }))?;
    } else {
        outln!("MRT dump written: {}", resp.file_path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::connection::connect;
    use crate::test_support::{spawn_mock_server, spawn_mock_uds_server};

    #[test]
    fn health_json_projection_covers_curated_response() {
        let state = crate::proto::HealthResponse {
            healthy: false,
            uptime_seconds: u64::MAX,
            active_peers: 17,
            total_routes: 19,
            daemon_version: "test-version".into(),
        };
        assert_eq!(
            serde_json::to_value(json_health(&state)).unwrap(),
            serde_json::json!({
                "healthy": false, "uptime_seconds": u64::MAX, "active_peers": 17, "total_routes": 19,
                "daemon_version": "test-version"
            })
        );
    }

    #[tokio::test]
    async fn health_calls_rpc_on_token_protected_server() {
        let server = spawn_mock_server(Some("secret")).await;
        let token_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(token_file.path(), "secret\n").unwrap();
        let connection = connect(&server.addr, Some(token_file.path().to_str().unwrap()))
            .await
            .unwrap();

        health(connection, true, false).await.unwrap();

        assert_eq!(server.state.health_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn health_calls_rpc_over_uds() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("rustbgpd.sock");
        let server = spawn_mock_uds_server(&socket_path, None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        health(connection, true, false).await.unwrap();

        assert_eq!(server.state.health_calls.load(Ordering::SeqCst), 1);
    }

    /// A daemon-gate fault names its machine-readable reason instead of
    /// reading as a temporary miss; any other `UNAVAILABLE` keeps the
    /// shared mapping.
    #[tokio::test]
    async fn health_names_the_daemon_gate_reason() {
        let server = spawn_mock_server(None).await;
        *server.state.health_gate_reason.lock().await = Some("DAEMON_SHUTTING_DOWN");
        let connection = connect(&server.addr, None).await.unwrap();

        let error = health(connection, true, false).await.unwrap_err();

        assert_eq!(
            error.to_string(),
            "daemon not ready (DAEMON_SHUTTING_DOWN): daemon is shutting down"
        );
        assert_eq!(server.state.health_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            health_gate_reason(&tonic::Status::unavailable("RIB manager probe timed out")),
            None
        );
    }

    #[tokio::test]
    async fn liveness_calls_only_liveness_rpc_over_uds() {
        let dir = tempfile::tempdir().unwrap();
        let server = spawn_mock_uds_server(&dir.path().join("grpc.sock"), None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        health(connection, true, true).await.unwrap();
        assert_eq!(server.state.liveness_calls.load(Ordering::SeqCst), 1);
        assert_eq!(server.state.health_calls.load(Ordering::SeqCst), 0);
    }

    /// Red proof: the old unprefixed, single-sample parser fails this aggregate.
    #[test]
    fn rpki_vrp_count_sums_only_valid_exact_name_samples() {
        let production = r#"
# HELP bgp_rpki_vrp_count Number of RPKI VRP entries by address family
# TYPE bgp_rpki_vrp_count gauge
bgp_rpki_vrp_count{afi="ipv4"} 120
bgp_rpki_vrp_count{afi="ipv6"} 30
bgp_rpki_vrp_count_total{afi="ipv4"} 9000
unrelated_metric 7
"#;
        assert_eq!(rpki_vrp_count_sum(production), Some(150));
        assert_eq!(
            rpki_vrp_count_sum("bgp_rpki_vrp_counting 9\nbgp_rpki_vrp_count_extra{afi=\"ipv4\"} 8"),
            None
        );
        assert_eq!(
            rpki_vrp_count_sum(
                "bgp_rpki_vrp_count{afi=\"ipv4\"} 0\nbgp_rpki_vrp_count{afi=\"ipv6\"} 0"
            ),
            Some(0)
        );
        for invalid in [
            "bgp_rpki_vrp_count{afi=\"ipv4\"} 1",
            "bgp_rpki_vrp_count{afi=\"ipv4\"} 1\nbgp_rpki_vrp_count{afi=\"ipv4\"} 2\nbgp_rpki_vrp_count{afi=\"ipv6\"} 3",
            "bgp_rpki_vrp_count{afi=\"other\"} 1",
            "bgp_rpki_vrp_count 1",
            "bgp_rpki_vrp_count{afi=\"ipv4\" not-a-number",
            "bgp_rpki_vrp_count{afi=\"ipv4\"} 18446744073709551615\nbgp_rpki_vrp_count{afi=\"ipv6\"} 1",
        ] {
            assert_eq!(rpki_vrp_count_sum(invalid), None, "{invalid}");
        }
    }

    #[test]
    fn rpki_cache_readiness_requires_exact_typed_unique_samples() {
        let parsed = rpki_cache_end_of_data_readiness(
            "bgp_rpki_cache_end_of_data_ready{cache=\"192.0.2.1:8282\"} 1\n\
             bgp_rpki_cache_end_of_data_ready{cache=\"[2001:db8::1]:8282\"} 0\n\
             bgp_rpki_cache_end_of_data_ready_total{cache=\"192.0.2.1:8282\"} 9",
        )
        .unwrap();
        assert_eq!(parsed.len(), 2);
        assert!(parsed[&"192.0.2.1:8282".parse().unwrap()]);
        assert!(!parsed[&"[2001:db8::1]:8282".parse().unwrap()]);

        for invalid in [
            "bgp_rpki_cache_end_of_data_ready 1",
            "bgp_rpki_cache_end_of_data_ready{cache=\"192.0.2.1:8282\",extra=\"x\"} 1",
            "bgp_rpki_cache_end_of_data_ready{other=\"192.0.2.1:8282\"} 1",
            "bgp_rpki_cache_end_of_data_ready{cache=\"not-an-address\"} 1",
            "bgp_rpki_cache_end_of_data_ready{cache=\"192.0.2.1:8282\"} 2",
            "bgp_rpki_cache_end_of_data_ready{cache=\"192.0.2.1:8282\"} 1 extra",
            "bgp_rpki_cache_end_of_data_ready{cache=\"[2001:db8::1]:8282\"} 1\n\
             bgp_rpki_cache_end_of_data_ready{cache=\"[2001:0db8:0:0:0:0:0:1]:8282\"} 1",
        ] {
            assert_eq!(rpki_cache_end_of_data_readiness(invalid), None, "{invalid}");
        }
        assert_eq!(
            rpki_cache_end_of_data_readiness(
                "bgp_rpki_cache_end_of_data_readiness{cache=\"bad\"} 7"
            ),
            Some(BTreeMap::new())
        );
    }
}
