use tonic::transport::Channel;

use crate::error::CliError;
use crate::output::{self, JsonHealth};
use crate::proto::control_service_client::ControlServiceClient;
use crate::proto::{HealthRequest, MetricsRequest, ShutdownRequest};

pub async fn health(channel: Channel, json: bool) -> Result<(), CliError> {
    let mut client = ControlServiceClient::new(channel);
    let resp = client.get_health(HealthRequest {}).await?.into_inner();

    if json {
        let out = JsonHealth {
            healthy: resp.healthy,
            uptime_seconds: resp.uptime_seconds,
            active_peers: resp.active_peers,
            total_routes: resp.total_routes,
        };
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else {
        println!(
            "Status:  {}",
            if resp.healthy { "healthy" } else { "unhealthy" }
        );
        println!("Uptime:  {}", output::format_duration(resp.uptime_seconds));
        println!("Peers:   {}", resp.active_peers);
        println!("Routes:  {}", resp.total_routes);
    }
    Ok(())
}

pub async fn metrics(channel: Channel) -> Result<(), CliError> {
    let mut client = ControlServiceClient::new(channel);
    let resp = client.get_metrics(MetricsRequest {}).await?.into_inner();
    print!("{}", resp.prometheus_text);
    Ok(())
}

pub async fn shutdown(
    channel: Channel,
    reason: Option<String>,
    json: bool,
) -> Result<(), CliError> {
    let mut client = ControlServiceClient::new(channel);
    client
        .shutdown(ShutdownRequest {
            reason: reason.unwrap_or_default(),
        })
        .await?;
    output::print_result(json, "shutdown", "", "Shutdown requested");
    Ok(())
}
