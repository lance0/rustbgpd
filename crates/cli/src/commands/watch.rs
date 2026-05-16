use crate::connection::Connection;
use crate::error::CliError;
use crate::output::{self, JsonRouteEvent};
use crate::proto::event_service_client::EventServiceClient;
use crate::proto::rib_service_client::RibServiceClient;
use crate::proto::{
    AddressFamily, BgpEvent, BgpEventType, EventCategory, ListRouteEventsRequest, RouteEvent,
    WatchEventsRequest, WatchRoutesRequest,
};
use std::net::IpAddr;

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

fn parse_bgp_event_type(s: &str) -> Result<i32, CliError> {
    match s {
        "added" | "route_added" => Ok(BgpEventType::RouteAdded as i32),
        "withdrawn" | "route_withdrawn" => Ok(BgpEventType::RouteWithdrawn as i32),
        "best_changed" | "route_best_changed" => Ok(BgpEventType::RouteBestChanged as i32),
        other => Err(CliError::Argument(format!(
            "unsupported event type {other:?}; expected added, withdrawn, or best_changed"
        ))),
    }
}

fn bgp_event_type_json_label(event_type: i32) -> &'static str {
    match BgpEventType::try_from(event_type) {
        Ok(BgpEventType::RouteAdded) => "route_added",
        Ok(BgpEventType::RouteWithdrawn) => "route_withdrawn",
        Ok(BgpEventType::RouteBestChanged) => "route_best_changed",
        _ => "unknown",
    }
}

fn bgp_event_type_display_label(event_type: i32) -> &'static str {
    match BgpEventType::try_from(event_type) {
        Ok(BgpEventType::RouteAdded) => "added",
        Ok(BgpEventType::RouteWithdrawn) => "withdrawn",
        Ok(BgpEventType::RouteBestChanged) => "best_changed",
        _ => "unknown",
    }
}

fn json_bgp_event(event: &BgpEvent) -> serde_json::Value {
    serde_json::json!({
        "timestamp": event.timestamp,
        "category": match EventCategory::try_from(event.category) {
            Ok(EventCategory::Route) => "route",
            Ok(EventCategory::Session) => "session",
            Ok(EventCategory::Policy) => "policy",
            Ok(EventCategory::Dataplane) => "dataplane",
            _ => "unknown",
        },
        "event_type": bgp_event_type_json_label(event.event_type),
        "severity": output::format_severity(event.severity),
        "peer_address": event.peer_address,
        "previous_peer_address": event.previous_peer_address,
        "prefix": if event.prefix.is_empty() {
            String::new()
        } else {
            format!("{}/{}", event.prefix, event.prefix_length)
        },
        "afi_safi": output::format_family(event.afi_safi),
        "summary": event.summary,
    })
}

fn print_bgp_event(event: &BgpEvent, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string(&json_bgp_event(event))
                .expect("failed to serialize BGP event as JSON")
        );
        return;
    }

    println!(
        "[{}] {} {}",
        event.timestamp,
        output::colored_event_type(bgp_event_type_display_label(event.event_type)),
        event.summary
    );
}

fn parse_optional_prefix_filter(
    prefix: Option<String>,
    family: Option<i32>,
) -> Result<(String, u32), CliError> {
    let Some(prefix) = prefix else {
        return Ok((String::new(), 0));
    };
    let (addr, length) = output::parse_prefix_addr(&prefix).map_err(CliError::Argument)?;
    match (family, addr) {
        (Some(f), IpAddr::V4(_)) if f == AddressFamily::Ipv6Unicast as i32 => {
            return Err(CliError::Argument(
                "--prefix family does not match --family".into(),
            ));
        }
        (Some(f), IpAddr::V6(_)) if f == AddressFamily::Ipv4Unicast as i32 => {
            return Err(CliError::Argument(
                "--prefix family does not match --family".into(),
            ));
        }
        _ => {}
    }
    Ok((addr.to_string(), length))
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

pub async fn events_watch(
    connection: Connection,
    neighbor: Option<String>,
    family: Option<i32>,
    prefix: Option<String>,
    event_types: Vec<String>,
    json: bool,
) -> Result<(), CliError> {
    let (prefix, prefix_length) = parse_optional_prefix_filter(prefix, family)?;

    let event_types = event_types
        .iter()
        .map(String::as_str)
        .map(parse_bgp_event_type)
        .collect::<Result<Vec<_>, _>>()?;
    let mut client =
        EventServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let mut stream = client
        .watch_events(WatchEventsRequest {
            categories: vec![EventCategory::Route as i32],
            event_types,
            neighbor_address: neighbor.unwrap_or_default(),
            afi_safi: family.unwrap_or(0),
            prefix,
            prefix_length,
        })
        .await?
        .into_inner();

    while let Some(event) = stream.message().await? {
        print_bgp_event(&event, json);
    }
    Ok(())
}

pub async fn history(
    connection: Connection,
    neighbor: Option<String>,
    family: Option<i32>,
    prefix: Option<String>,
    limit: u32,
    json: bool,
) -> Result<(), CliError> {
    let (prefix, prefix_length) = parse_optional_prefix_filter(prefix, family)?;

    let mut client =
        RibServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let response = client
        .list_route_events(ListRouteEventsRequest {
            neighbor_address: neighbor.unwrap_or_default(),
            afi_safi: family.unwrap_or(0),
            limit,
            prefix,
            prefix_length,
        })
        .await?
        .into_inner();

    for event in response.events {
        print_event(&event, json);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bgp_event_display_labels_match_route_event_coloring_labels() {
        assert_eq!(
            bgp_event_type_display_label(BgpEventType::RouteAdded as i32),
            "added"
        );
        assert_eq!(
            bgp_event_type_display_label(BgpEventType::RouteWithdrawn as i32),
            "withdrawn"
        );
        assert_eq!(
            bgp_event_type_display_label(BgpEventType::RouteBestChanged as i32),
            "best_changed"
        );
    }
}
