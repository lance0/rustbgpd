use crate::connection::Connection;
use crate::error::CliError;
use crate::output::{self, JsonRouteEvent};
use crate::proto::WatchRoutesRequest;
use crate::proto::rib_service_client::RibServiceClient;

fn format_event_type(t: i32) -> &'static str {
    match t {
        1 => "added",
        2 => "withdrawn",
        3 => "best_changed",
        _ => "unknown",
    }
}

pub async fn run(
    connection: Connection,
    neighbor: Option<String>,
    family: Option<i32>,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        RibServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let mut stream = client
        .watch_routes(WatchRoutesRequest {
            neighbor_address: neighbor.unwrap_or_default(),
            afi_safi: family.unwrap_or(0),
        })
        .await?
        .into_inner();

    while let Some(event) = stream.message().await? {
        let prefix = format!("{}/{}", event.prefix, event.prefix_length);
        if json {
            let out = JsonRouteEvent {
                event_type: format_event_type(event.event_type).to_string(),
                prefix,
                peer_address: event.peer_address.clone(),
                afi_safi: output::format_family(event.afi_safi).to_string(),
                timestamp: event.timestamp.clone(),
                path_id: event.path_id,
            };
            println!(
                "{}",
                serde_json::to_string(&out).expect("failed to serialize route event as JSON")
            );
        } else {
            let path_id_str = if event.path_id > 0 {
                format!(" path_id={}", event.path_id)
            } else {
                String::new()
            };
            println!(
                "[{}] {} {} from {}{}",
                event.timestamp,
                output::colored_event_type(format_event_type(event.event_type)),
                prefix,
                event.peer_address,
                path_id_str,
            );
        }
    }
    Ok(())
}
