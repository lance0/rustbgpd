use crate::connection::Connection;
use crate::error::CliError;
use crate::output::{self, JsonRouteEvent};
use crate::proto::rib_service_client::RibServiceClient;
use crate::proto::{ListRouteEventsRequest, RouteEvent, WatchRoutesRequest};

fn format_event_type(t: i32) -> &'static str {
    match t {
        1 => "added",
        2 => "withdrawn",
        3 => "best_changed",
        _ => "unknown",
    }
}

fn json_event(event: &RouteEvent) -> JsonRouteEvent {
    JsonRouteEvent {
        event_type: format_event_type(event.event_type).to_string(),
        prefix: format!("{}/{}", event.prefix, event.prefix_length),
        peer_address: event.peer_address.clone(),
        previous_peer_address: event.previous_peer_address.clone(),
        afi_safi: output::format_family(event.afi_safi).to_string(),
        timestamp: event.timestamp.clone(),
        path_id: event.path_id,
    }
}

fn print_event(event: &RouteEvent, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string(&json_event(event))
                .expect("failed to serialize route event as JSON")
        );
        return;
    }

    let prefix = format!("{}/{}", event.prefix, event.prefix_length);
    let path_id_str = if event.path_id > 0 {
        format!(" path_id={}", event.path_id)
    } else {
        String::new()
    };
    let previous_peer = if event.previous_peer_address.is_empty() {
        String::new()
    } else {
        format!(" previous={}", event.previous_peer_address)
    };
    println!(
        "[{}] {} {} from {}{}{}",
        event.timestamp,
        output::colored_event_type(format_event_type(event.event_type)),
        prefix,
        event.peer_address,
        previous_peer,
        path_id_str,
    );
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
        print_event(&event, json);
    }
    Ok(())
}

pub async fn history(
    connection: Connection,
    neighbor: Option<String>,
    family: Option<i32>,
    limit: u32,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        RibServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let response = client
        .list_route_events(ListRouteEventsRequest {
            neighbor_address: neighbor.unwrap_or_default(),
            afi_safi: family.unwrap_or(0),
            limit,
        })
        .await?
        .into_inner();

    for event in response.events {
        print_event(&event, json);
    }
    Ok(())
}
