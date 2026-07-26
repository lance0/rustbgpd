use crate::connection::Connection;
use crate::error::CliError;
use crate::output::{self, JsonHealth};
use crate::proto::control_service_client::ControlServiceClient;
use crate::proto::{HealthRequest, MetricsRequest, ShutdownRequest, TriggerMrtDumpRequest};

/// Sum a complete, unique, valid IPv4 + IPv6 RPKI VRP gauge snapshot.
/// `Some(0)` distinguishes a synchronized empty table from an unusable snapshot.
pub(crate) fn rpki_vrp_count_sum(prometheus_text: &str) -> Option<u64> {
    const NAME: &str = "bgp_rpki_vrp_count";

    let mut by_family = [None, None];
    for line in prometheus_text.lines().map(str::trim) {
        let Some(rest) = line.strip_prefix(NAME) else {
            continue;
        };
        let family = if let Some(value) = rest.strip_prefix(r#"{af="ipv4"}"#) {
            Some((0, value))
        } else if let Some(value) = rest.strip_prefix(r#"{af="ipv6"}"#) {
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

pub async fn health(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut client =
        ControlServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client.get_health(HealthRequest {}).await?.into_inner();

    if json {
        let out = JsonHealth {
            healthy: resp.healthy,
            uptime_seconds: resp.uptime_seconds,
            active_peers: resp.active_peers,
            total_routes: resp.total_routes,
        };
        output::print_json_pretty(&out)?;
    } else {
        println!("Status:  {}", output::colored_health(resp.healthy));
        println!("Uptime:  {}", output::format_duration(resp.uptime_seconds));
        println!("Peers:   {}", resp.active_peers);
        println!("Routes:  {}", resp.total_routes);
    }
    Ok(())
}

pub async fn metrics(connection: Connection) -> Result<(), CliError> {
    let mut client =
        ControlServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client.get_metrics(MetricsRequest {}).await?.into_inner();
    print!("{}", resp.prometheus_text);
    Ok(())
}

pub async fn shutdown(
    connection: Connection,
    reason: Option<String>,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        ControlServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    client
        .shutdown(ShutdownRequest {
            reason: reason.unwrap_or_default(),
        })
        .await?;
    output::print_result(json, "shutdown", "", "Shutdown requested")
}

pub async fn mrt_dump(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut client =
        ControlServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .trigger_mrt_dump(TriggerMrtDumpRequest {})
        .await?
        .into_inner();

    if json {
        output::print_json_line(&serde_json::json!({ "file_path": resp.file_path }))?;
    } else {
        println!("MRT dump written: {}", resp.file_path);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::connection::connect;
    use crate::test_support::{spawn_mock_server, spawn_mock_uds_server};

    #[tokio::test]
    async fn health_calls_rpc_on_token_protected_server() {
        let server = spawn_mock_server(Some("secret")).await;
        let token_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(token_file.path(), "secret\n").unwrap();
        let connection = connect(&server.addr, Some(token_file.path().to_str().unwrap()))
            .await
            .unwrap();

        health(connection, true).await.unwrap();

        assert_eq!(server.state.health_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn health_calls_rpc_over_uds() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("rustbgpd.sock");
        let server = spawn_mock_uds_server(&socket_path, None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        health(connection, true).await.unwrap();

        assert_eq!(server.state.health_calls.load(Ordering::SeqCst), 1);
    }

    /// Red proof: the old unprefixed, single-sample parser fails this aggregate.
    #[test]
    fn rpki_vrp_count_sums_only_valid_exact_name_samples() {
        let production = r#"
# HELP bgp_rpki_vrp_count Number of RPKI VRP entries by address family
# TYPE bgp_rpki_vrp_count gauge
bgp_rpki_vrp_count{af="ipv4"} 120
bgp_rpki_vrp_count{af="ipv6"} 30
bgp_rpki_vrp_count_total{af="ipv4"} 9000
unrelated_metric 7
"#;
        assert_eq!(rpki_vrp_count_sum(production), Some(150));
        assert_eq!(
            rpki_vrp_count_sum("bgp_rpki_vrp_counting 9\nbgp_rpki_vrp_count_extra{af=\"ipv4\"} 8"),
            None
        );
        assert_eq!(
            rpki_vrp_count_sum(
                "bgp_rpki_vrp_count{af=\"ipv4\"} 0\nbgp_rpki_vrp_count{af=\"ipv6\"} 0"
            ),
            Some(0)
        );
        for invalid in [
            "bgp_rpki_vrp_count{af=\"ipv4\"} 1",
            "bgp_rpki_vrp_count{af=\"ipv4\"} 1\nbgp_rpki_vrp_count{af=\"ipv4\"} 2\nbgp_rpki_vrp_count{af=\"ipv6\"} 3",
            "bgp_rpki_vrp_count{af=\"other\"} 1",
            "bgp_rpki_vrp_count 1",
            "bgp_rpki_vrp_count{af=\"ipv4\" not-a-number",
            "bgp_rpki_vrp_count{af=\"ipv4\"} 18446744073709551615\nbgp_rpki_vrp_count{af=\"ipv6\"} 1",
        ] {
            assert_eq!(rpki_vrp_count_sum(invalid), None, "{invalid}");
        }
    }
}
