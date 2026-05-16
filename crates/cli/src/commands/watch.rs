use crate::connection::Connection;
use crate::error::CliError;
use crate::output::{self, JsonRouteEvent};
use crate::proto::event_service_client::EventServiceClient;
use crate::proto::rib_service_client::RibServiceClient;
use crate::proto::{
    AddressFamily, BgpEvent, BgpEventType, EventCategory, ListRouteEventsRequest,
    ListSessionEventsRequest, RouteEvent, RouteEventType, WatchEventsRequest, WatchRoutesRequest,
};
use std::net::IpAddr;

pub struct EventsWatchOptions {
    pub categories: Vec<String>,
    pub neighbor: Option<String>,
    pub family: Option<i32>,
    pub prefix: Option<String>,
    pub event_types: Vec<String>,
    pub backfill: u32,
    pub json: bool,
}

fn format_event_type(t: i32) -> &'static str {
    match RouteEventType::try_from(t) {
        Ok(RouteEventType::Added) => "added",
        Ok(RouteEventType::Withdrawn) => "withdrawn",
        Ok(RouteEventType::BestChanged) => "best_changed",
        _ => "unknown",
    }
}

fn json_event(event: &RouteEvent) -> JsonRouteEvent {
    JsonRouteEvent {
        event_id: event.event_id,
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
    let event_id_str = if event.event_id > 0 {
        format!(" id={}", event.event_id)
    } else {
        String::new()
    };
    let previous_peer = if event.previous_peer_address.is_empty() {
        String::new()
    } else {
        format!(" previous={}", event.previous_peer_address)
    };
    println!(
        "[{}] {} {} from {}{}{}{}",
        event.timestamp,
        output::colored_event_type(format_event_type(event.event_type)),
        prefix,
        event.peer_address,
        previous_peer,
        path_id_str,
        event_id_str,
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
        "policy_changed" => Ok(BgpEventType::PolicyChanged as i32),
        "dataplane_status_changed" | "dataplane_changed" => {
            Ok(BgpEventType::DataplaneStatusChanged as i32)
        }
        "stream_lagged" | "lagged" => Ok(BgpEventType::StreamLagged as i32),
        other => Err(CliError::Argument(format!(
            "unsupported event type {other:?}; expected added, withdrawn, best_changed, state_changed, established, lost, peer_enabled, peer_disabled, notification_sent, notification_received, policy_changed, dataplane_status_changed, or stream_lagged"
        ))),
    }
}

fn parse_session_bgp_event_type(s: &str) -> Result<i32, CliError> {
    let event_type = parse_bgp_event_type(s)?;
    match BgpEventType::try_from(event_type) {
        Ok(BgpEventType::SessionStateChanged)
        | Ok(BgpEventType::SessionEstablished)
        | Ok(BgpEventType::SessionLost)
        | Ok(BgpEventType::PeerEnabled)
        | Ok(BgpEventType::PeerDisabled) => Ok(event_type),
        _ => Err(CliError::Argument(format!(
            "unsupported session event type {s:?}; expected state_changed, established, lost, peer_enabled, or peer_disabled"
        ))),
    }
}

fn parse_event_category(s: &str) -> Result<i32, CliError> {
    match s {
        "route" => Ok(EventCategory::Route as i32),
        "session" => Ok(EventCategory::Session as i32),
        "policy" => Ok(EventCategory::Policy as i32),
        "dataplane" => Ok(EventCategory::Dataplane as i32),
        other => Err(CliError::Argument(format!(
            "unsupported event category {other:?}; expected route, session, policy, or dataplane"
        ))),
    }
}

fn bgp_event_type_is_route(event_type: i32) -> bool {
    matches!(
        BgpEventType::try_from(event_type),
        Ok(BgpEventType::RouteAdded
            | BgpEventType::RouteWithdrawn
            | BgpEventType::RouteBestChanged)
    )
}

fn validate_route_only_filters(
    categories: &[i32],
    event_types: &[i32],
    family: Option<i32>,
    prefix: Option<&str>,
) -> Result<(), CliError> {
    let route_category_selected =
        categories.is_empty() || categories.contains(&(EventCategory::Route as i32));
    let route_type_selected =
        event_types.is_empty() || event_types.iter().copied().any(bgp_event_type_is_route);
    if !(route_category_selected && route_type_selected) && (family.is_some() || prefix.is_some()) {
        return Err(CliError::Argument(
            "--family and --prefix are route-only filters; remove them or select a route category/type"
                .into(),
        ));
    }
    Ok(())
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
        Ok(BgpEventType::PolicyChanged) => "policy_changed",
        Ok(BgpEventType::DataplaneStatusChanged) => "dataplane_status_changed",
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
        Ok(BgpEventType::PolicyChanged) => "policy_changed",
        Ok(BgpEventType::DataplaneStatusChanged) => "dataplane_status_changed",
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
    if let Some(crate::proto::bgp_event::Payload::Route(route)) = event.payload.as_ref()
        && let Some(object) = value.as_object_mut()
        && route.event_id > 0
    {
        object.insert(
            "event_id".to_string(),
            serde_json::Value::Number(route.event_id.into()),
        );
    }
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
    if let Some(crate::proto::bgp_event::Payload::Policy(policy)) = event.payload.as_ref()
        && let Some(object) = value.as_object_mut()
    {
        object.insert(
            "operation".to_string(),
            serde_json::Value::String(policy.operation.clone()),
        );
        object.insert(
            "target_type".to_string(),
            serde_json::Value::String(policy.target_type.clone()),
        );
        object.insert(
            "target".to_string(),
            serde_json::Value::String(policy.target.clone()),
        );
        object.insert(
            "affected_peer_count".to_string(),
            serde_json::Value::Number(policy.affected_peer_count.into()),
        );
        object.insert(
            "reason".to_string(),
            serde_json::Value::String(policy.reason.clone()),
        );
    }
    if let Some(crate::proto::bgp_event::Payload::Dataplane(dataplane)) = event.payload.as_ref()
        && let Some(object) = value.as_object_mut()
    {
        object.insert(
            "source".to_string(),
            serde_json::Value::String(dataplane.source.clone()),
        );
        object.insert(
            "installed".to_string(),
            serde_json::Value::from(dataplane.installed),
        );
        object.insert(
            "rejected".to_string(),
            serde_json::Value::from(dataplane.rejected),
        );
        object.insert(
            "failed".to_string(),
            serde_json::Value::from(dataplane.failed),
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

fn route_event_id(event: &BgpEvent) -> Option<u64> {
    match event.payload.as_ref() {
        Some(crate::proto::bgp_event::Payload::Route(route)) => Some(route.event_id),
        _ => None,
    }
}

fn format_bgp_event_line(event: &BgpEvent) -> String {
    let event_id = route_event_id(event)
        .filter(|id| *id > 0)
        .map_or_else(String::new, |id| format!(" id={id}"));
    format!(
        "[{}] {} {}{}",
        event.timestamp,
        output::colored_event_type(bgp_event_type_display_label(event.event_type)),
        event.summary,
        event_id
    )
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

    println!("{}", format_bgp_event_line(event));
}

fn is_route_event_type(event_type: i32) -> bool {
    matches!(
        BgpEventType::try_from(event_type),
        Ok(BgpEventType::RouteAdded)
            | Ok(BgpEventType::RouteWithdrawn)
            | Ok(BgpEventType::RouteBestChanged)
    )
}

fn route_event_type_to_bgp_event_type(event_type: i32) -> i32 {
    match RouteEventType::try_from(event_type) {
        Ok(RouteEventType::Added) => BgpEventType::RouteAdded as i32,
        Ok(RouteEventType::Withdrawn) => BgpEventType::RouteWithdrawn as i32,
        Ok(RouteEventType::BestChanged) => BgpEventType::RouteBestChanged as i32,
        _ => BgpEventType::Unspecified as i32,
    }
}

fn wants_route_events(categories: &[i32], event_types: &[i32]) -> bool {
    (categories.is_empty() || categories.contains(&(EventCategory::Route as i32)))
        && (event_types.is_empty() || event_types.iter().copied().any(is_route_event_type))
}

fn route_history_event_matches_types(event: &RouteEvent, event_types: &[i32]) -> bool {
    event_types.is_empty()
        || event_types.contains(&route_event_type_to_bgp_event_type(event.event_type))
}

fn route_history_request_limit(backfill: u32, event_types: &[i32]) -> u32 {
    if event_types.is_empty() { backfill } else { 0 }
}

fn route_event_to_bgp_event(event: RouteEvent) -> BgpEvent {
    let event_type = route_event_type_to_bgp_event_type(event.event_type);
    let event_label = match BgpEventType::try_from(event_type) {
        Ok(BgpEventType::RouteAdded) => "added",
        Ok(BgpEventType::RouteWithdrawn) => "withdrawn",
        Ok(BgpEventType::RouteBestChanged) => "best changed",
        _ => "changed",
    };
    let summary = format!(
        "route {event_label} {}/{}",
        event.prefix, event.prefix_length
    );

    BgpEvent {
        timestamp: event.timestamp.clone(),
        category: EventCategory::Route as i32,
        event_type,
        severity: crate::proto::EventSeverity::Info as i32,
        peer_address: event.peer_address.clone(),
        previous_peer_address: event.previous_peer_address.clone(),
        prefix: event.prefix.clone(),
        prefix_length: event.prefix_length,
        afi_safi: event.afi_safi,
        summary,
        payload: Some(crate::proto::bgp_event::Payload::Route(event)),
    }
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

fn validate_event_filter_categories(
    categories: &[i32],
    neighbor: &Option<String>,
    family: Option<i32>,
    prefix: &Option<String>,
) -> Result<(), CliError> {
    if categories.is_empty() {
        return Ok(());
    }

    let wants_route = categories.contains(&(EventCategory::Route as i32));
    let wants_session = categories.contains(&(EventCategory::Session as i32));
    if !wants_route && (family.is_some() || prefix.is_some()) {
        return Err(CliError::Argument(
            "--family and --prefix require --category route because they are route-only filters"
                .into(),
        ));
    }
    if !wants_route && !wants_session && neighbor.is_some() {
        return Err(CliError::Argument(
            "--address requires --category route or --category session because dataplane events are peerless"
                .into(),
        ));
    }

    Ok(())
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
    options: EventsWatchOptions,
) -> Result<(), CliError> {
    let EventsWatchOptions {
        categories,
        neighbor,
        family,
        prefix,
        event_types,
        backfill,
        json,
    } = options;

    let categories = categories
        .iter()
        .map(String::as_str)
        .map(parse_event_category)
        .collect::<Result<Vec<_>, _>>()?;
    validate_event_filter_categories(&categories, &neighbor, family, &prefix)?;

    let event_types = event_types
        .iter()
        .map(String::as_str)
        .map(parse_bgp_event_type)
        .collect::<Result<Vec<_>, _>>()?;
    let route_events_requested = wants_route_events(&categories, &event_types);
    if backfill > 0 && !route_events_requested {
        return Err(CliError::Argument(
            "--backfill requires a route-capable event stream".into(),
        ));
    }
    validate_route_only_filters(&categories, &event_types, family, prefix.as_deref())?;
    let (prefix, prefix_length) = parse_optional_prefix_filter(prefix, family)?;
    let mut client =
        EventServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let mut stream = client
        .watch_events(WatchEventsRequest {
            categories,
            event_types: event_types.clone(),
            neighbor_address: neighbor.clone().unwrap_or_default(),
            afi_safi: family.unwrap_or(0),
            prefix: prefix.clone(),
            prefix_length,
        })
        .await?
        .into_inner();

    let mut last_backfilled_route_event_id = 0;
    if backfill > 0 {
        let mut rib_client =
            RibServiceClient::with_interceptor(connection.channel(), connection.interceptor());
        let response = rib_client
            .list_route_events(ListRouteEventsRequest {
                neighbor_address: neighbor.unwrap_or_default(),
                afi_safi: family.unwrap_or(0),
                // Ask for the full bounded ring only when local type
                // filtering could otherwise shrink the requested window.
                limit: route_history_request_limit(backfill, &event_types),
                prefix,
                prefix_length,
            })
            .await?
            .into_inner();
        let mut events = response
            .events
            .into_iter()
            .filter(|event| route_history_event_matches_types(event, &event_types))
            .collect::<Vec<_>>();
        if events.len() > backfill as usize {
            events.drain(0..events.len() - backfill as usize);
        }
        for event in events {
            last_backfilled_route_event_id = last_backfilled_route_event_id.max(event.event_id);
            let event = route_event_to_bgp_event(event);
            print_bgp_event(&event, json);
        }
    }

    while let Some(event) = stream.message().await? {
        if last_backfilled_route_event_id > 0
            && route_event_id(&event).is_some_and(|id| id <= last_backfilled_route_event_id)
        {
            continue;
        }
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

pub async fn session_history(
    connection: Connection,
    neighbor: Option<String>,
    event_types: Vec<String>,
    limit: u32,
    json: bool,
) -> Result<(), CliError> {
    let event_types = event_types
        .iter()
        .map(String::as_str)
        .map(parse_session_bgp_event_type)
        .collect::<Result<Vec<_>, _>>()?;
    let mut client =
        EventServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let response = client
        .list_session_events(ListSessionEventsRequest {
            neighbor_address: neighbor.unwrap_or_default(),
            event_types,
            limit,
        })
        .await?
        .into_inner();

    for event in response.events {
        print_bgp_event(&event, json);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_route_event_includes_event_id() {
        let event = RouteEvent {
            event_type: 1,
            prefix: "203.0.113.0".to_string(),
            prefix_length: 24,
            peer_address: "10.0.0.1".to_string(),
            afi_safi: AddressFamily::Ipv4Unicast as i32,
            timestamp: "1".to_string(),
            previous_peer_address: String::new(),
            path_id: 0,
            event_id: 42,
        };

        let value = serde_json::to_value(json_event(&event)).unwrap();
        assert_eq!(value["event_id"], 42);
    }

    #[test]
    fn backfill_route_detection_requires_route_capable_filter() {
        assert!(wants_route_events(&[], &[]));
        assert!(wants_route_events(
            &[EventCategory::Route as i32],
            &[BgpEventType::RouteAdded as i32]
        ));
        assert!(!wants_route_events(
            &[EventCategory::Session as i32],
            &[BgpEventType::SessionEstablished as i32]
        ));
        assert!(!wants_route_events(
            &[],
            &[BgpEventType::SessionEstablished as i32]
        ));
    }

    #[test]
    fn route_history_event_type_filter_matches_route_aliases() {
        let event = RouteEvent {
            event_type: 3,
            prefix: "203.0.113.0".to_string(),
            prefix_length: 24,
            peer_address: "10.0.0.1".to_string(),
            afi_safi: AddressFamily::Ipv4Unicast as i32,
            timestamp: "1".to_string(),
            previous_peer_address: "10.0.0.2".to_string(),
            path_id: 0,
            event_id: 7,
        };

        assert!(route_history_event_matches_types(
            &event,
            &[BgpEventType::RouteBestChanged as i32]
        ));
        assert!(!route_history_event_matches_types(
            &event,
            &[BgpEventType::RouteAdded as i32]
        ));
    }

    #[test]
    fn route_history_event_converts_to_bgp_event_shape() {
        let event = RouteEvent {
            event_type: 1,
            prefix: "203.0.113.0".to_string(),
            prefix_length: 24,
            peer_address: "10.0.0.1".to_string(),
            afi_safi: AddressFamily::Ipv4Unicast as i32,
            timestamp: "1".to_string(),
            previous_peer_address: String::new(),
            path_id: 0,
            event_id: 42,
        };

        let event = route_event_to_bgp_event(event);
        let value = json_bgp_event(&event);
        assert_eq!(value["category"], "route");
        assert_eq!(value["event_type"], "route_added");
        assert_eq!(value["summary"], "route added 203.0.113.0/24");
        assert_eq!(value["event_id"], 42);
    }

    #[test]
    fn bgp_event_text_route_events_include_event_id() {
        let event = route_event_to_bgp_event(RouteEvent {
            event_type: RouteEventType::Added as i32,
            prefix: "203.0.113.0".to_string(),
            prefix_length: 24,
            peer_address: "10.0.0.1".to_string(),
            afi_safi: AddressFamily::Ipv4Unicast as i32,
            timestamp: "1".to_string(),
            previous_peer_address: String::new(),
            path_id: 0,
            event_id: 42,
        });

        assert!(format_bgp_event_line(&event).ends_with(" id=42"));
    }

    #[test]
    fn route_history_request_limit_only_expands_when_type_filtering() {
        assert_eq!(route_history_request_limit(5, &[]), 5);
        assert_eq!(
            route_history_request_limit(5, &[BgpEventType::RouteAdded as i32]),
            0
        );
    }

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
        assert_eq!(
            bgp_event_type_display_label(BgpEventType::PolicyChanged as i32),
            "policy_changed"
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

    #[test]
    fn json_bgp_event_policy_includes_mutation_fields() {
        let event = BgpEvent {
            timestamp: "1".to_string(),
            category: EventCategory::Policy as i32,
            event_type: BgpEventType::PolicyChanged as i32,
            severity: 1,
            summary: "policy set policy audit-policy".to_string(),
            payload: Some(crate::proto::bgp_event::Payload::Policy(
                crate::proto::PolicyEvent {
                    event_type: BgpEventType::PolicyChanged as i32,
                    operation: "set".to_string(),
                    target_type: "policy".to_string(),
                    target: "audit-policy".to_string(),
                    affected_peer_count: 2,
                    timestamp: "1".to_string(),
                    reason: "policy set policy audit-policy".to_string(),
                    ..Default::default()
                },
            )),
            ..Default::default()
        };

        let value = json_bgp_event(&event);
        assert_eq!(value["category"], "policy");
        assert_eq!(value["event_type"], "policy_changed");
        assert_eq!(value["operation"], "set");
        assert_eq!(value["target_type"], "policy");
        assert_eq!(value["target"], "audit-policy");
        assert_eq!(value["affected_peer_count"], 2);
    }

    #[test]
    fn event_filter_rejects_route_only_filters_without_route_category() {
        let categories = vec![
            EventCategory::Session as i32,
            EventCategory::Dataplane as i32,
        ];
        let err = validate_event_filter_categories(
            &categories,
            &None,
            Some(AddressFamily::Ipv4Unicast as i32),
            &None,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("--category route"));

        let err = validate_event_filter_categories(
            &categories,
            &None,
            None,
            &Some("203.0.113.0/24".to_string()),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("--category route"));
    }

    #[test]
    fn event_filter_allows_peer_for_session_dataplane_category() {
        let categories = vec![
            EventCategory::Session as i32,
            EventCategory::Dataplane as i32,
        ];
        validate_event_filter_categories(&categories, &Some("10.0.0.1".to_string()), None, &None)
            .unwrap();
    }

    #[test]
    fn event_filter_rejects_peer_for_dataplane_only_category() {
        let categories = vec![EventCategory::Dataplane as i32];
        let err = validate_event_filter_categories(
            &categories,
            &Some("10.0.0.1".to_string()),
            None,
            &None,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("peerless"));
    }

    #[test]
    fn json_bgp_event_dataplane_includes_summary_counts() {
        let event = BgpEvent {
            timestamp: "1".to_string(),
            category: EventCategory::Dataplane as i32,
            event_type: BgpEventType::DataplaneStatusChanged as i32,
            severity: 2,
            afi_safi: AddressFamily::Unspecified as i32,
            summary: "dataplane fib status changed".to_string(),
            payload: Some(crate::proto::bgp_event::Payload::Dataplane(
                crate::proto::DataplaneEvent {
                    source: "fib".to_string(),
                    installed: 2,
                    rejected: 1,
                    failed: 1,
                },
            )),
            ..Default::default()
        };

        let value = json_bgp_event(&event);
        assert_eq!(value["category"], "dataplane");
        assert_eq!(value["event_type"], "dataplane_status_changed");
        assert_eq!(value["source"], "fib");
        assert_eq!(value["installed"], 2);
        assert_eq!(value["rejected"], 1);
        assert_eq!(value["failed"], 1);
        assert!(value["afi_safi"].is_null());
    }

    #[test]
    fn route_only_filters_reject_policy_only_category() {
        let categories = vec![EventCategory::Policy as i32];
        let err = validate_route_only_filters(&categories, &[], None, Some("203.0.113.0/24"))
            .unwrap_err();
        assert!(err.to_string().contains("route-only filters"));
    }

    #[test]
    fn route_only_filters_allow_mixed_route_policy_category() {
        let categories = vec![EventCategory::Route as i32, EventCategory::Policy as i32];
        validate_route_only_filters(&categories, &[], None, Some("203.0.113.0/24")).unwrap();
    }

    #[test]
    fn route_only_filters_reject_policy_type_without_route_type() {
        let event_types = vec![BgpEventType::PolicyChanged as i32];
        let err = validate_route_only_filters(&[], &event_types, None, Some("203.0.113.0/24"))
            .unwrap_err();
        assert!(err.to_string().contains("route-only filters"));
    }

    #[test]
    fn route_only_filters_allow_mixed_route_policy_types() {
        let event_types = vec![
            BgpEventType::RouteAdded as i32,
            BgpEventType::PolicyChanged as i32,
        ];
        validate_route_only_filters(&[], &event_types, None, Some("203.0.113.0/24")).unwrap();
    }

    #[test]
    fn json_route_event_shape_is_stable() {
        let event = RouteEvent {
            event_type: crate::proto::RouteEventType::BestChanged as i32,
            prefix: "203.0.113.0".to_string(),
            prefix_length: 24,
            peer_address: "10.0.0.2".to_string(),
            previous_peer_address: "10.0.0.1".to_string(),
            afi_safi: AddressFamily::Ipv4Unicast as i32,
            timestamp: "123".to_string(),
            path_id: 7,
            event_id: 0,
        };

        let value = serde_json::to_value(json_event(&event)).unwrap();
        assert_eq!(value["event_type"], "best_changed");
        assert_eq!(value["prefix"], "203.0.113.0/24");
        assert_eq!(value["peer_address"], "10.0.0.2");
        assert_eq!(value["previous_peer_address"], "10.0.0.1");
        assert_eq!(value["afi_safi"], "ipv4_unicast");
        assert_eq!(value["timestamp"], "123");
        assert_eq!(value["path_id"], 7);
    }

    #[test]
    fn json_bgp_event_route_shape_is_stable() {
        let event = BgpEvent {
            timestamp: "123".to_string(),
            category: EventCategory::Route as i32,
            event_type: BgpEventType::RouteWithdrawn as i32,
            severity: crate::proto::EventSeverity::Warning as i32,
            peer_address: "10.0.0.2".to_string(),
            previous_peer_address: "10.0.0.1".to_string(),
            prefix: "203.0.113.0".to_string(),
            prefix_length: 24,
            afi_safi: AddressFamily::Ipv4Unicast as i32,
            summary: "route withdrawn 203.0.113.0/24".to_string(),
            ..Default::default()
        };

        let value = json_bgp_event(&event);
        assert_eq!(value["category"], "route");
        assert_eq!(value["event_type"], "route_withdrawn");
        assert_eq!(value["severity"], "warning");
        assert_eq!(value["peer_address"], "10.0.0.2");
        assert_eq!(value["previous_peer_address"], "10.0.0.1");
        assert_eq!(value["prefix"], "203.0.113.0/24");
        assert_eq!(value["afi_safi"], "ipv4_unicast");
        assert_eq!(value["summary"], "route withdrawn 203.0.113.0/24");
    }

    #[test]
    fn session_history_type_parser_rejects_route_types() {
        assert_eq!(
            parse_session_bgp_event_type("established").unwrap(),
            BgpEventType::SessionEstablished as i32
        );
        assert!(parse_session_bgp_event_type("added").is_err());
    }
}
