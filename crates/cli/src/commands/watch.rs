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
        "state_changed" | "session_state_changed" => Ok(BgpEventType::SessionStateChanged as i32),
        "established" | "session_established" => Ok(BgpEventType::SessionEstablished as i32),
        "lost" | "session_lost" => Ok(BgpEventType::SessionLost as i32),
        "peer_enabled" => Ok(BgpEventType::PeerEnabled as i32),
        "peer_disabled" => Ok(BgpEventType::PeerDisabled as i32),
        "notification_sent" => Ok(BgpEventType::NotificationSent as i32),
        "notification_received" => Ok(BgpEventType::NotificationReceived as i32),
        "stream_lagged" | "lagged" => Ok(BgpEventType::StreamLagged as i32),
        other => Err(CliError::Argument(format!(
            "unsupported event type {other:?}; expected added, withdrawn, best_changed, state_changed, established, lost, peer_enabled, peer_disabled, notification_sent, notification_received, or stream_lagged"
        ))),
    }
}

fn parse_event_category(s: &str) -> Result<i32, CliError> {
    match s {
        "route" => Ok(EventCategory::Route as i32),
        "session" => Ok(EventCategory::Session as i32),
        other => Err(CliError::Argument(format!(
            "unsupported event category {other:?}; expected route or session"
        ))),
    }
}

fn bgp_event_type_json_label(event_type: i32) -> &'static str {
    match BgpEventType::try_from(event_type) {
        Ok(BgpEventType::RouteAdded) => "route_added",
        Ok(BgpEventType::RouteWithdrawn) => "route_withdrawn",
        Ok(BgpEventType::RouteBestChanged) => "route_best_changed",
        Ok(BgpEventType::SessionStateChanged) => "session_state_changed",
        Ok(BgpEventType::SessionEstablished) => "session_established",
        Ok(BgpEventType::SessionLost) => "session_lost",
        Ok(BgpEventType::PeerEnabled) => "peer_enabled",
        Ok(BgpEventType::PeerDisabled) => "peer_disabled",
        Ok(BgpEventType::NotificationSent) => "notification_sent",
        Ok(BgpEventType::NotificationReceived) => "notification_received",
        Ok(BgpEventType::StreamLagged) => "stream_lagged",
        _ => "unknown",
    }
}

fn bgp_event_type_display_label(event_type: i32) -> &'static str {
    match BgpEventType::try_from(event_type) {
        Ok(BgpEventType::RouteAdded) => "added",
        Ok(BgpEventType::RouteWithdrawn) => "withdrawn",
        Ok(BgpEventType::RouteBestChanged) => "best_changed",
        Ok(BgpEventType::SessionStateChanged) => "state_changed",
        Ok(BgpEventType::SessionEstablished) => "established",
        Ok(BgpEventType::SessionLost) => "lost",
        Ok(BgpEventType::PeerEnabled) => "peer_enabled",
        Ok(BgpEventType::PeerDisabled) => "peer_disabled",
        Ok(BgpEventType::NotificationSent) => "notification_sent",
        Ok(BgpEventType::NotificationReceived) => "notification_received",
        Ok(BgpEventType::StreamLagged) => "stream_lagged",
        _ => "unknown",
    }
}

fn json_bgp_event(event: &BgpEvent) -> serde_json::Value {
    let mut value = serde_json::json!({
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
        "afi_safi": if event.afi_safi == AddressFamily::Unspecified as i32 {
            serde_json::Value::Null
        } else {
            serde_json::Value::String(output::format_family(event.afi_safi).to_string())
        },
        "summary": event.summary,
    });
    if let Some(crate::proto::bgp_event::Payload::Session(session)) = event.payload.as_ref()
        && let Some(object) = value.as_object_mut()
    {
        object.insert(
            "old_state".to_string(),
            serde_json::Value::String(session.old_state.clone()),
        );
        object.insert(
            "new_state".to_string(),
            serde_json::Value::String(session.new_state.clone()),
        );
        object.insert(
            "session_role".to_string(),
            serde_json::Value::String(session.session_role.clone()),
        );
        object.insert(
            "reason".to_string(),
            serde_json::Value::String(session.reason.clone()),
        );
    }
    if let Some(crate::proto::bgp_event::Payload::Notification(notification)) =
        event.payload.as_ref()
        && let Some(object) = value.as_object_mut()
    {
        object.insert(
            "direction".to_string(),
            serde_json::Value::String(notification.direction.clone()),
        );
        object.insert(
            "code".to_string(),
            serde_json::Value::Number(notification.code.into()),
        );
        object.insert(
            "subcode".to_string(),
            serde_json::Value::Number(notification.subcode.into()),
        );
        object.insert(
            "description".to_string(),
            serde_json::Value::String(notification.description.clone()),
        );
        object.insert(
            "session_role".to_string(),
            serde_json::Value::String(notification.session_role.clone()),
        );
        object.insert(
            "shutdown_reason".to_string(),
            serde_json::Value::String(notification.shutdown_reason.clone()),
        );
        object.insert(
            "reason".to_string(),
            serde_json::Value::String(notification.reason.clone()),
        );
    }
    if let Some(crate::proto::bgp_event::Payload::StreamLag(lag)) = event.payload.as_ref()
        && let Some(object) = value.as_object_mut()
    {
        object.insert(
            "source_category".to_string(),
            serde_json::Value::String(
                match EventCategory::try_from(lag.source_category) {
                    Ok(EventCategory::Route) => "route",
                    Ok(EventCategory::Session) => "session",
                    Ok(EventCategory::Policy) => "policy",
                    Ok(EventCategory::Dataplane) => "dataplane",
                    _ => "unknown",
                }
                .to_string(),
            ),
        );
        object.insert(
            "missed_count".to_string(),
            serde_json::Value::Number(lag.missed_count.into()),
        );
        object.insert(
            "reason".to_string(),
            serde_json::Value::String(lag.reason.clone()),
        );
    }
    value
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
    categories: Vec<String>,
    neighbor: Option<String>,
    family: Option<i32>,
    prefix: Option<String>,
    event_types: Vec<String>,
    json: bool,
) -> Result<(), CliError> {
    let categories = categories
        .iter()
        .map(String::as_str)
        .map(parse_event_category)
        .collect::<Result<Vec<_>, _>>()?;
    let session_only = categories.len() == 1 && categories[0] == EventCategory::Session as i32;
    if session_only && (family.is_some() || prefix.is_some()) {
        return Err(CliError::Argument(
            "--family and --prefix are route-only filters and cannot be used with --category session"
                .into(),
        ));
    }
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
            categories,
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

    #[test]
    fn json_bgp_event_session_uses_null_family() {
        let event = BgpEvent {
            timestamp: "1".to_string(),
            category: EventCategory::Session as i32,
            event_type: BgpEventType::SessionEstablished as i32,
            severity: 1,
            peer_address: "10.0.0.1".to_string(),
            afi_safi: AddressFamily::Unspecified as i32,
            summary: "session established".to_string(),
            payload: Some(crate::proto::bgp_event::Payload::Session(
                crate::proto::SessionEvent {
                    event_type: BgpEventType::SessionEstablished as i32,
                    peer_address: "10.0.0.1".to_string(),
                    timestamp: "1".to_string(),
                    old_state: "OpenConfirm".to_string(),
                    new_state: "Established".to_string(),
                    session_role: "primary".to_string(),
                    reason: "session established".to_string(),
                },
            )),
            ..Default::default()
        };

        let value = json_bgp_event(&event);
        assert!(value["afi_safi"].is_null());
    }

    #[test]
    fn json_bgp_event_stream_lag_includes_missed_count() {
        let event = BgpEvent {
            timestamp: "2".to_string(),
            category: EventCategory::Route as i32,
            event_type: BgpEventType::StreamLagged as i32,
            severity: 2,
            afi_safi: AddressFamily::Unspecified as i32,
            summary: "route event stream lagged; missed 7 event(s)".to_string(),
            payload: Some(crate::proto::bgp_event::Payload::StreamLag(
                crate::proto::StreamLagEvent {
                    source_category: EventCategory::Route as i32,
                    missed_count: 7,
                    reason: "route event stream lagged; missed 7 event(s)".to_string(),
                },
            )),
            ..Default::default()
        };

        let value = json_bgp_event(&event);
        assert_eq!(value["event_type"], "stream_lagged");
        assert_eq!(value["severity"], "warning");
        assert_eq!(value["source_category"], "route");
        assert_eq!(value["missed_count"], 7);
        assert!(value["afi_safi"].is_null());
    }

    #[test]
    fn json_bgp_event_notification_includes_code_and_direction() {
        let event = BgpEvent {
            timestamp: "2".to_string(),
            category: EventCategory::Session as i32,
            event_type: BgpEventType::NotificationSent as i32,
            severity: 2,
            peer_address: "10.0.0.1".to_string(),
            afi_safi: AddressFamily::Unspecified as i32,
            summary: "BGP NOTIFICATION sent for peer 10.0.0.1: 6/7 (Connection Collision Resolution)".to_string(),
            payload: Some(crate::proto::bgp_event::Payload::Notification(
                crate::proto::NotificationEvent {
                    event_type: BgpEventType::NotificationSent as i32,
                    peer_address: "10.0.0.1".to_string(),
                    timestamp: "2".to_string(),
                    direction: "sent".to_string(),
                    code: 6,
                    subcode: 7,
                    description: "Connection Collision Resolution".to_string(),
                    session_role: "primary".to_string(),
                    shutdown_reason: String::new(),
                    reason: "BGP NOTIFICATION sent for peer 10.0.0.1: 6/7 (Connection Collision Resolution)".to_string(),
                },
            )),
            ..Default::default()
        };

        let value = json_bgp_event(&event);
        assert_eq!(value["event_type"], "notification_sent");
        assert_eq!(value["direction"], "sent");
        assert_eq!(value["code"], 6);
        assert_eq!(value["subcode"], 7);
        assert_eq!(value["description"], "Connection Collision Resolution");
        assert!(value["afi_safi"].is_null());
    }
}
