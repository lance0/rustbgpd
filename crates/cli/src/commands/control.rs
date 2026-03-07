use crate::connection::Connection;
use crate::error::CliError;
use crate::output::{self, JsonHealth};
use crate::proto::control_service_client::ControlServiceClient;
use crate::proto::{HealthRequest, MetricsRequest, ShutdownRequest, TriggerMrtDumpRequest};

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
        println!(
            "{}",
            serde_json::to_string_pretty(&out).expect("failed to serialize health output as JSON")
        );
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
    output::print_result(json, "shutdown", "", "Shutdown requested");
    Ok(())
}

pub async fn mrt_dump(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut client =
        ControlServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .trigger_mrt_dump(TriggerMrtDumpRequest {})
        .await?
        .into_inner();

    if json {
        println!("{}", serde_json::json!({ "file_path": resp.file_path }));
    } else {
        println!("MRT dump written: {}", resp.file_path);
    }
    Ok(())
}
