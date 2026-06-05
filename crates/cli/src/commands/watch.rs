use crate::connection::Connection;
use crate::error::CliError;
use crate::output::{self, JsonRouteEvent};
use crate::proto::event_service_client::EventServiceClient;
use crate::proto::rib_service_client::RibServiceClient;
use crate::proto::{
    AddressFamily, BgpEvent, BgpEventType, EventCategory, EvpnRouteEntry, ListEvpnEventsRequest,
    ListPolicyEventsRequest, ListRouteEventsRequest, ListSessionEventsRequest, RouteEvent,
    RouteEventType, StreamLagEvent, WatchEventsRequest, WatchRoutesRequest,
};
use std::net::IpAddr;

pub struct EventsWatchOptions {
    pub categories: Vec<String>,
    pub neighbor: Option<String>,
    pub family: Option<i32>,
    pub prefix: Option<String>,
    pub event_types: Vec<String>,
    pub backfill: u32,
    /// ADR-0072 durable cursor (`--from-event-id`). When `Some`,
    /// the CLI subscribes via `SubscribeFromEvent` instead of
    /// `WatchEvents`, replays committed events with
    /// `event_id > N` from the daemon's local outbox, then attaches
    /// the live stream. `Some(0)` replays everything retained. Mutually
    /// exclusive with `--backfill` because the two operate on
    /// independent ID spaces (process-local vs durable).
    pub from_event_id: Option<u64>,
    pub json: bool,
}

fn format_event_type(t: i32) -> &'static str {
    match RouteEventType::try_from(t) {
        Ok(RouteEventType::Added) => "added",
        Ok(RouteEventType::Withdrawn) => "withdrawn",
        Ok(RouteEventType::BestChanged) => "best_changed",
        Ok(RouteEventType::PolicyFiltered) => "policy_filtered",
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
        target_peer_address: event.target_peer_address.clone(),
        afi_safi: output::format_family(event.afi_safi).to_string(),
        timestamp: event.timestamp.clone(),
        path_id: event.path_id,
        missed_count: 0,
        reason: event.reason.clone(),
    }
}

fn print_event(event: &RouteEvent, json: bool) -> Result<(), CliError> {
    if json {
        output::print_json_line(&json_event(event))?;
        return Ok(());
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
    let target_peer = if event.target_peer_address.is_empty() {
        String::new()
    } else {
        format!(" target={}", event.target_peer_address)
    };
    let reason = if event.reason.is_empty() {
        String::new()
    } else {
        format!(" reason={}", event.reason)
    };
    println!(
        "[{}] {} {} from {}{}{}{}{}{}",
        event.timestamp,
        output::colored_event_type(format_event_type(event.event_type)),
        prefix,
        event.peer_address,
        previous_peer,
        target_peer,
        reason,
        path_id_str,
        event_id_str,
    );
    Ok(())
}

fn parse_bgp_event_type(s: &str) -> Result<i32, CliError> {
    match s {
        "added" | "route_added" => Ok(BgpEventType::RouteAdded as i32),
        "withdrawn" | "route_withdrawn" => Ok(BgpEventType::RouteWithdrawn as i32),
        "best_changed" | "route_best_changed" => Ok(BgpEventType::RouteBestChanged as i32),
        "policy_filtered" | "route_policy_filtered" => Ok(BgpEventType::RoutePolicyFiltered as i32),
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
        "dataplane_route_installed" | "fib_installed" => {
            Ok(BgpEventType::DataplaneRouteInstalled as i32)
        }
        "dataplane_route_withdrawn" | "fib_withdrawn" => {
            Ok(BgpEventType::DataplaneRouteWithdrawn as i32)
        }
        "dataplane_route_failed" | "fib_failed" => Ok(BgpEventType::DataplaneRouteFailed as i32),
        "evpn_added" | "evpn_route_added" => Ok(BgpEventType::EvpnRouteAdded as i32),
        "evpn_withdrawn" | "evpn_route_withdrawn" => Ok(BgpEventType::EvpnRouteWithdrawn as i32),
        "evpn_best_changed" | "evpn_route_best_changed" => {
            Ok(BgpEventType::EvpnRouteBestChanged as i32)
        }
        "bfd_up" | "bfd_session_up" => Ok(BgpEventType::BfdSessionUp as i32),
        "bfd_down" | "bfd_session_down" => Ok(BgpEventType::BfdSessionDown as i32),
        "bfd_state_changed" | "bfd_session_state_changed" => {
            Ok(BgpEventType::BfdSessionStateChanged as i32)
        }
        "otc_route_blocked" => Ok(BgpEventType::OtcRouteBlocked as i32),
        "stream_lagged" | "lagged" => Ok(BgpEventType::StreamLagged as i32),
        other => Err(CliError::Argument(format!(
            "unsupported event type {other:?}; expected added, withdrawn, best_changed, policy_filtered, state_changed, established, lost, peer_enabled, peer_disabled, notification_sent, notification_received, policy_changed, otc_route_blocked, dataplane_status_changed, dataplane_route_installed, dataplane_route_withdrawn, dataplane_route_failed, evpn_added, evpn_withdrawn, evpn_best_changed, bfd_up, bfd_down, bfd_state_changed, or stream_lagged"
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

fn parse_policy_bgp_event_type(s: &str) -> Result<i32, CliError> {
    let event_type = parse_bgp_event_type(s)?;
    match BgpEventType::try_from(event_type) {
        Ok(BgpEventType::PolicyChanged) => Ok(event_type),
        _ => Err(CliError::Argument(format!(
            "unsupported policy event type {s:?}; expected policy_changed"
        ))),
    }
}

fn parse_evpn_bgp_event_type(s: &str) -> Result<i32, CliError> {
    let event_type = parse_bgp_event_type(s)?;
    match BgpEventType::try_from(event_type) {
        Ok(BgpEventType::EvpnRouteAdded)
        | Ok(BgpEventType::EvpnRouteWithdrawn)
        | Ok(BgpEventType::EvpnRouteBestChanged) => Ok(event_type),
        _ => Err(CliError::Argument(format!(
            "unsupported EVPN event type {s:?}; expected evpn_added, evpn_withdrawn, or evpn_best_changed"
        ))),
    }
}

fn parse_event_category(s: &str) -> Result<i32, CliError> {
    match s {
        "route" => Ok(EventCategory::Route as i32),
        "session" => Ok(EventCategory::Session as i32),
        "policy" => Ok(EventCategory::Policy as i32),
        "dataplane" => Ok(EventCategory::Dataplane as i32),
        "evpn" => Ok(EventCategory::Evpn as i32),
        "bfd" => Ok(EventCategory::Bfd as i32),
        other => Err(CliError::Argument(format!(
            "unsupported event category {other:?}; expected route, session, policy, dataplane, evpn, or bfd"
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

fn bgp_event_type_is_dataplane_route(event_type: i32) -> bool {
    matches!(
        BgpEventType::try_from(event_type),
        Ok(BgpEventType::DataplaneRouteInstalled)
            | Ok(BgpEventType::DataplaneRouteWithdrawn)
            | Ok(BgpEventType::DataplaneRouteFailed)
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
    let dataplane_category_selected =
        categories.is_empty() || categories.contains(&(EventCategory::Dataplane as i32));
    let dataplane_type_selected = event_types.is_empty()
        || event_types
            .iter()
            .copied()
            .any(bgp_event_type_is_dataplane_route);
    if !((route_category_selected && route_type_selected)
        || (dataplane_category_selected && dataplane_type_selected))
        && (family.is_some() || prefix.is_some())
    {
        return Err(CliError::Argument(
            "--family and --prefix require route or dataplane route events; remove them or select a compatible category/type"
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
        Ok(BgpEventType::RoutePolicyFiltered) => "route_policy_filtered",
        Ok(BgpEventType::SessionStateChanged) => "session_state_changed",
        Ok(BgpEventType::SessionEstablished) => "session_established",
        Ok(BgpEventType::SessionLost) => "session_lost",
        Ok(BgpEventType::PeerEnabled) => "peer_enabled",
        Ok(BgpEventType::PeerDisabled) => "peer_disabled",
        Ok(BgpEventType::NotificationSent) => "notification_sent",
        Ok(BgpEventType::NotificationReceived) => "notification_received",
        Ok(BgpEventType::PolicyChanged) => "policy_changed",
        Ok(BgpEventType::DataplaneStatusChanged) => "dataplane_status_changed",
        Ok(BgpEventType::DataplaneRouteInstalled) => "dataplane_route_installed",
        Ok(BgpEventType::DataplaneRouteWithdrawn) => "dataplane_route_withdrawn",
        Ok(BgpEventType::DataplaneRouteFailed) => "dataplane_route_failed",
        Ok(BgpEventType::EvpnRouteAdded) => "evpn_route_added",
        Ok(BgpEventType::EvpnRouteWithdrawn) => "evpn_route_withdrawn",
        Ok(BgpEventType::EvpnRouteBestChanged) => "evpn_route_best_changed",
        Ok(BgpEventType::BfdSessionUp) => "bfd_session_up",
        Ok(BgpEventType::BfdSessionDown) => "bfd_session_down",
        Ok(BgpEventType::BfdSessionStateChanged) => "bfd_session_state_changed",
        Ok(BgpEventType::OtcRouteBlocked) => "otc_route_blocked",
        Ok(BgpEventType::StreamLagged) => "stream_lagged",
        _ => "unknown",
    }
}

fn bgp_event_type_display_label(event_type: i32) -> &'static str {
    match BgpEventType::try_from(event_type) {
        Ok(BgpEventType::RouteAdded) => "added",
        Ok(BgpEventType::RouteWithdrawn) => "withdrawn",
        Ok(BgpEventType::RouteBestChanged) => "best_changed",
        Ok(BgpEventType::RoutePolicyFiltered) => "policy_filtered",
        Ok(BgpEventType::SessionStateChanged) => "state_changed",
        Ok(BgpEventType::SessionEstablished) => "established",
        Ok(BgpEventType::SessionLost) => "lost",
        Ok(BgpEventType::PeerEnabled) => "peer_enabled",
        Ok(BgpEventType::PeerDisabled) => "peer_disabled",
        Ok(BgpEventType::NotificationSent) => "notification_sent",
        Ok(BgpEventType::NotificationReceived) => "notification_received",
        Ok(BgpEventType::PolicyChanged) => "policy_changed",
        Ok(BgpEventType::DataplaneStatusChanged) => "dataplane_status_changed",
        Ok(BgpEventType::DataplaneRouteInstalled) => "dataplane_route_installed",
        Ok(BgpEventType::DataplaneRouteWithdrawn) => "dataplane_route_withdrawn",
        Ok(BgpEventType::DataplaneRouteFailed) => "dataplane_route_failed",
        Ok(BgpEventType::EvpnRouteAdded) => "evpn_added",
        Ok(BgpEventType::EvpnRouteWithdrawn) => "evpn_withdrawn",
        Ok(BgpEventType::EvpnRouteBestChanged) => "evpn_best_changed",
        Ok(BgpEventType::BfdSessionUp) => "bfd_up",
        Ok(BgpEventType::BfdSessionDown) => "bfd_down",
        Ok(BgpEventType::BfdSessionStateChanged) => "bfd_state_changed",
        Ok(BgpEventType::OtcRouteBlocked) => "otc_route_blocked",
        Ok(BgpEventType::StreamLagged) => "stream_lagged",
        _ => "unknown",
    }
}

fn evpn_route_type_label(t: u32) -> &'static str {
    match t {
        1 => "ead",
        2 => "mac-ip",
        3 => "imet",
        4 => "es",
        5 => "ip-prefix",
        _ => "unknown",
    }
}

fn json_evpn_route_entry(route: &EvpnRouteEntry) -> serde_json::Value {
    serde_json::json!({
        "route_type": route.route_type,
        "route_type_name": evpn_route_type_label(route.route_type),
        "rd": route.rd,
        "esi": route.esi,
        "ethernet_tag": route.ethernet_tag,
        "mac": route.mac,
        "ip": route.ip,
        "prefix": route.prefix,
        "gateway": route.gateway,
        "label": route.label,
        "label2": route.label2,
        "next_hop": route.next_hop,
        "peer": route.peer_address,
        "as_path": route.as_path,
        "communities": route.communities,
        "extended_communities": route.extended_communities,
        "tunnel_type": route.tunnel_type,
    })
}

fn json_bgp_event(event: &BgpEvent) -> serde_json::Value {
    let mut value = serde_json::json!({
        "timestamp": event.timestamp,
        "category": match EventCategory::try_from(event.category) {
            Ok(EventCategory::Route) => "route",
            Ok(EventCategory::Session) => "session",
            Ok(EventCategory::Policy) => "policy",
            Ok(EventCategory::Dataplane) => "dataplane",
            Ok(EventCategory::Evpn) => "evpn",
            Ok(EventCategory::Bfd) => "bfd",
            _ => "unknown",
        },
        "event_type": bgp_event_type_json_label(event.event_type),
        "severity": output::format_severity(event.severity),
        "peer_address": event.peer_address,
        "previous_peer_address": event.previous_peer_address,
        "target_peer_address": event.target_peer_address,
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
    if let Some(object) = value.as_object_mut()
        && let Some(event_id) = event
            .event_id
            .or_else(|| route_event_id(event).filter(|id| *id > 0))
    {
        object.insert(
            "event_id".to_string(),
            serde_json::Value::Number(event_id.into()),
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
    if let Some(crate::proto::bgp_event::Payload::DataplaneRoute(route)) = event.payload.as_ref()
        && let Some(object) = value.as_object_mut()
    {
        object.insert(
            "source".to_string(),
            serde_json::Value::String(route.source.clone()),
        );
        object.insert(
            "action".to_string(),
            serde_json::Value::String(route.action.clone()),
        );
        object.insert(
            "table_name".to_string(),
            serde_json::Value::String(route.table_name.clone()),
        );
        object.insert(
            "table_id".to_string(),
            serde_json::Value::from(route.table_id),
        );
        object.insert("metric".to_string(), serde_json::Value::from(route.metric));
        object.insert(
            "next_hop".to_string(),
            serde_json::Value::String(route.next_hop.clone()),
        );
        object.insert(
            "reason".to_string(),
            serde_json::Value::String(route.reason.clone()),
        );
    }
    if let Some(crate::proto::bgp_event::Payload::Evpn(evpn)) = event.payload.as_ref()
        && let Some(object) = value.as_object_mut()
    {
        object.insert(
            "route_type".to_string(),
            serde_json::Value::Number(evpn.route_type.into()),
        );
        object.insert(
            "route_type_name".to_string(),
            serde_json::Value::String(evpn_route_type_label(evpn.route_type).to_string()),
        );
        object.insert("rd".to_string(), serde_json::Value::String(evpn.rd.clone()));
        object.insert(
            "route_key".to_string(),
            serde_json::Value::String(evpn.route_key.clone()),
        );
        object.insert(
            "reason".to_string(),
            serde_json::Value::String(evpn.reason.clone()),
        );
        object.insert(
            "route".to_string(),
            evpn.route
                .as_ref()
                .map_or(serde_json::Value::Null, json_evpn_route_entry),
        );
        object.insert(
            "previous_route".to_string(),
            evpn.previous_route
                .as_ref()
                .map_or(serde_json::Value::Null, json_evpn_route_entry),
        );
    }
    if let Some(crate::proto::bgp_event::Payload::OtcRouteBlocked(otc)) = event.payload.as_ref()
        && let Some(object) = value.as_object_mut()
    {
        // ADR-0072 follow-up — surface the OTC payload fields the
        // operator actually needs for incident reconstruction.
        // Without these the --json output is just the envelope +
        // summary string, which loses prefixes, role pair, OTC
        // value, AS_PATH, etc. Matches the shared bridge formatter
        // in crates/api/src/json_format.rs so external consumers
        // and the CLI render identical JSON.
        object.insert(
            "direction".to_string(),
            serde_json::Value::String(otc.direction.clone()),
        );
        object.insert(
            "reason".to_string(),
            serde_json::Value::String(otc.reason.clone()),
        );
        object.insert(
            "prefixes".to_string(),
            serde_json::Value::Array(
                otc.prefixes
                    .iter()
                    .cloned()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
        object.insert("count".to_string(), serde_json::Value::from(otc.count));
        object.insert(
            "local_role".to_string(),
            serde_json::Value::String(otc.local_role.clone()),
        );
        object.insert(
            "remote_role".to_string(),
            serde_json::Value::String(otc.remote_role.clone()),
        );
        object.insert(
            "otc_value".to_string(),
            otc.otc_value
                .map_or(serde_json::Value::Null, serde_json::Value::from),
        );
        object.insert(
            "as_path".to_string(),
            serde_json::Value::String(otc.as_path.clone()),
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
                    Ok(EventCategory::Evpn) => "evpn",
                    Ok(EventCategory::Bfd) => "bfd",
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
    // Envelope-level `event_id` (ADR-0072) takes precedence — it
    // exists for every category on the SubscribeFromEvent path and
    // is the durable cursor source. Fall back to the nested
    // `RouteEvent.event_id` for legacy `WatchEvents` / `WatchRoutes`
    // route events that don't carry an envelope id.
    let event_id = event
        .event_id
        .or_else(|| route_event_id(event).filter(|id| *id > 0))
        .map_or_else(String::new, |id| format!(" id={id}"));
    format!(
        "[{}] {} {}{}",
        event.timestamp,
        output::colored_event_type(bgp_event_type_display_label(event.event_type)),
        event.summary,
        event_id
    )
}

fn print_bgp_event(event: &BgpEvent, json: bool) -> Result<(), CliError> {
    if json {
        output::print_json_line(&json_bgp_event(event))?;
        return Ok(());
    }

    println!("{}", format_bgp_event_line(event));
    Ok(())
}

fn json_route_stream_lag_event(event: &BgpEvent, lag: &StreamLagEvent) -> JsonRouteEvent {
    JsonRouteEvent {
        event_id: 0,
        event_type: bgp_event_type_display_label(event.event_type).to_string(),
        prefix: String::new(),
        peer_address: String::new(),
        previous_peer_address: String::new(),
        target_peer_address: String::new(),
        afi_safi: output::format_family(event.afi_safi).to_string(),
        timestamp: event.timestamp.clone(),
        path_id: 0,
        missed_count: lag.missed_count,
        reason: lag.reason.clone(),
    }
}

fn json_route_watch_event(event: &BgpEvent) -> Result<serde_json::Value, CliError> {
    match event.payload.as_ref() {
        Some(crate::proto::bgp_event::Payload::Route(route)) => {
            Ok(serde_json::to_value(json_event(route))?)
        }
        Some(crate::proto::bgp_event::Payload::StreamLag(lag)) => Ok(serde_json::to_value(
            json_route_stream_lag_event(event, lag),
        )?),
        _ => Ok(json_bgp_event(event)),
    }
}

fn print_route_watch_event(event: &BgpEvent, json: bool) -> Result<(), CliError> {
    if json {
        output::print_json_line(&json_route_watch_event(event)?)?;
        return Ok(());
    }

    if let Some(crate::proto::bgp_event::Payload::Route(route)) = event.payload.as_ref() {
        print_event(route, false)?;
    } else {
        print_bgp_event(event, false)?;
    }
    Ok(())
}

fn is_route_event_type(event_type: i32) -> bool {
    matches!(
        BgpEventType::try_from(event_type),
        Ok(BgpEventType::RouteAdded)
            | Ok(BgpEventType::RouteWithdrawn)
            | Ok(BgpEventType::RouteBestChanged)
            | Ok(BgpEventType::RoutePolicyFiltered)
    )
}

fn route_event_type_to_bgp_event_type(event_type: i32) -> i32 {
    match RouteEventType::try_from(event_type) {
        Ok(RouteEventType::Added) => BgpEventType::RouteAdded as i32,
        Ok(RouteEventType::Withdrawn) => BgpEventType::RouteWithdrawn as i32,
        Ok(RouteEventType::BestChanged) => BgpEventType::RouteBestChanged as i32,
        Ok(RouteEventType::PolicyFiltered) => BgpEventType::RoutePolicyFiltered as i32,
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
        Ok(BgpEventType::RoutePolicyFiltered) => "policy filtered",
        _ => "changed",
    };
    let summary = format!(
        "route {event_label} {}/{}",
        event.prefix, event.prefix_length
    );
    let summary = if event_type == BgpEventType::RoutePolicyFiltered as i32 {
        format!(
            "{summary} target={} reason={}",
            event.target_peer_address, event.reason
        )
    } else {
        summary
    };

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
        target_peer_address: event.target_peer_address.clone(),
        event_id: None,
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
    let wants_dataplane = categories.contains(&(EventCategory::Dataplane as i32));
    let wants_evpn = categories.contains(&(EventCategory::Evpn as i32));
    // EVENT_CATEGORY_POLICY carries OtcRouteBlocked which IS peer-
    // scoped (the structured event stores the peer address), so
    // `--address` is meaningful here. The legacy PolicyChanged
    // entries scope by peer too when the mutation targets one
    // neighbor; --address narrows to those.
    let wants_policy = categories.contains(&(EventCategory::Policy as i32));
    if !wants_route && !wants_dataplane && (family.is_some() || prefix.is_some()) {
        return Err(CliError::Argument(
            "--family and --prefix require --category route or --category dataplane".into(),
        ));
    }
    if !wants_route
        && !wants_session
        && !wants_dataplane
        && !wants_evpn
        && !wants_policy
        && neighbor.is_some()
    {
        return Err(CliError::Argument(
            "--address requires --category route, --category session, --category dataplane, --category evpn, or --category policy"
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
        .watch_route_events(WatchRoutesRequest {
            neighbor_address: neighbor.unwrap_or_default(),
            afi_safi: family.unwrap_or(0),
        })
        .await?
        .into_inner();

    while let Some(event) = stream.message().await? {
        print_route_watch_event(&event, json)?;
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
        from_event_id,
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
    if backfill > 0 && from_event_id.is_some() {
        return Err(CliError::Argument(
            "--from-event-id and --backfill are mutually exclusive: \
             --backfill replays the daemon's process-local route ring \
             (resets on restart), while --from-event-id replays the \
             durable event outbox (survives restart). Pick one."
                .into(),
        ));
    }
    if backfill > 0 && !route_events_requested {
        return Err(CliError::Argument(
            "--backfill requires a route-capable event stream".into(),
        ));
    }
    validate_route_only_filters(&categories, &event_types, family, prefix.as_deref())?;
    let (prefix, prefix_length) = parse_optional_prefix_filter(prefix, family)?;

    // ADR-0072 durable cursor path. SubscribeFromEvent replays
    // committed events with `event_id > N`, then attaches live. The
    // server emits a leading `StreamLagEvent` if `N` is older than
    // the retention floor — the existing print path already renders
    // it as a stream_lag payload.
    //
    // Some event types are EHM-only (no legacy WatchEvents
    // broadcast). Today that's `OtcRouteBlocked` — the OTC
    // route-leak decision is published exclusively through the
    // durable outbox under EVENT_CATEGORY_POLICY. If the user
    // asked for one of those types without `--from-event-id`, we
    // transparently route through SubscribeFromEvent in live-only
    // mode (`from_event_id = None`) so the filter actually works.
    // If EHM is disabled, the server returns FailedPrecondition,
    // which the CLI surfaces as a clear error rather than the
    // silent zero-event-stream the legacy path would produce.
    let request_requires_ehm = event_types.contains(&(BgpEventType::OtcRouteBlocked as i32));
    if from_event_id.is_some() || request_requires_ehm {
        let mut client =
            EventServiceClient::with_interceptor(connection.channel(), connection.interceptor());
        let request = crate::proto::SubscribeFromEventRequest {
            from_event_id,
            categories,
            event_types,
            neighbor_address: neighbor.unwrap_or_default(),
            afi_safi: family.unwrap_or(0),
            prefix,
            prefix_length,
        };
        let mut stream = client.subscribe_from_event(request).await?.into_inner();
        while let Some(event) = stream.message().await? {
            print_bgp_event(&event, json)?;
        }
        return Ok(());
    }

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
            print_bgp_event(&event, json)?;
        }
    }

    while let Some(event) = stream.message().await? {
        if last_backfilled_route_event_id > 0
            && route_event_id(&event).is_some_and(|id| id <= last_backfilled_route_event_id)
        {
            continue;
        }
        print_bgp_event(&event, json)?;
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
        print_event(&event, json)?;
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
        print_bgp_event(&event, json)?;
    }
    Ok(())
}

pub async fn policy_history(
    connection: Connection,
    neighbor: Option<String>,
    event_types: Vec<String>,
    limit: u32,
    json: bool,
) -> Result<(), CliError> {
    let event_types = event_types
        .iter()
        .map(String::as_str)
        .map(parse_policy_bgp_event_type)
        .collect::<Result<Vec<_>, _>>()?;
    let mut client =
        EventServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let response = client
        .list_policy_events(ListPolicyEventsRequest {
            neighbor_address: neighbor.unwrap_or_default(),
            event_types,
            limit,
        })
        .await?
        .into_inner();

    for event in response.events {
        print_bgp_event(&event, json)?;
    }
    Ok(())
}

pub async fn evpn_history(
    connection: Connection,
    neighbor: Option<String>,
    route_type: Option<u32>,
    rd: Option<String>,
    event_types: Vec<String>,
    limit: u32,
    json: bool,
) -> Result<(), CliError> {
    let event_types = event_types
        .iter()
        .map(String::as_str)
        .map(parse_evpn_bgp_event_type)
        .collect::<Result<Vec<_>, _>>()?;
    let mut client =
        EventServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let response = client
        .list_evpn_events(ListEvpnEventsRequest {
            neighbor_address: neighbor.unwrap_or_default(),
            event_types,
            limit,
            route_type_filter: route_type.unwrap_or(0),
            rd_filter: rd.unwrap_or_default(),
        })
        .await?
        .into_inner();

    for event in response.events {
        print_bgp_event(&event, json)?;
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
            target_peer_address: String::new(),
            path_id: 0,
            event_id: 42,
            reason: String::new(),
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
            target_peer_address: String::new(),
            path_id: 0,
            event_id: 7,
            reason: String::new(),
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
            target_peer_address: String::new(),
            path_id: 0,
            event_id: 42,
            reason: String::new(),
        };

        let event = route_event_to_bgp_event(event);
        let value = json_bgp_event(&event);
        assert_eq!(value["category"], "route");
        assert_eq!(value["event_type"], "route_added");
        assert_eq!(value["summary"], "route added 203.0.113.0/24");
        assert_eq!(value["event_id"], 42);
    }

    #[test]
    fn policy_filtered_route_event_json_includes_target_peer_and_reason() {
        let event = RouteEvent {
            event_type: RouteEventType::PolicyFiltered as i32,
            prefix: "203.0.113.0".to_string(),
            prefix_length: 24,
            peer_address: "10.0.0.1".to_string(),
            afi_safi: AddressFamily::Ipv4Unicast as i32,
            timestamp: "1".to_string(),
            previous_peer_address: String::new(),
            target_peer_address: "10.0.0.2".to_string(),
            path_id: 9,
            event_id: 42,
            reason: "policy_denied".to_string(),
        };

        let value = serde_json::to_value(json_event(&event)).unwrap();
        assert_eq!(value["event_type"], "policy_filtered");
        assert_eq!(value["peer_address"], "10.0.0.1");
        assert_eq!(value["target_peer_address"], "10.0.0.2");
        assert_eq!(value["reason"], "policy_denied");

        let bgp_event = route_event_to_bgp_event(event);
        let value = json_bgp_event(&bgp_event);
        assert_eq!(value["event_type"], "route_policy_filtered");
        assert_eq!(value["target_peer_address"], "10.0.0.2");
        assert_eq!(
            value["summary"],
            "route policy filtered 203.0.113.0/24 target=10.0.0.2 reason=policy_denied"
        );
    }

    #[test]
    fn parse_policy_filtered_route_event_aliases() {
        assert_eq!(
            parse_bgp_event_type("policy_filtered").unwrap(),
            BgpEventType::RoutePolicyFiltered as i32
        );
        assert_eq!(
            parse_bgp_event_type("route_policy_filtered").unwrap(),
            BgpEventType::RoutePolicyFiltered as i32
        );
        assert!(is_route_event_type(
            BgpEventType::RoutePolicyFiltered as i32
        ));
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
            target_peer_address: String::new(),
            path_id: 0,
            event_id: 42,
            reason: String::new(),
        });

        assert!(format_bgp_event_line(&event).ends_with(" id=42"));
    }

    #[test]
    fn json_bgp_event_surfaces_otc_route_blocked_payload() {
        // Regression: --json output must surface every
        // OtcRouteBlockedEvent payload field. Earlier versions
        // dropped the payload arm and rendered only the envelope +
        // summary string, hiding prefixes, role pair, OTC value,
        // and AS_PATH from operators driving the CLI.
        let payload = crate::proto::OtcRouteBlockedEvent {
            event_type: BgpEventType::OtcRouteBlocked as i32,
            peer_address: "10.0.0.2".to_string(),
            timestamp: "1".to_string(),
            direction: "ingress".to_string(),
            reason: "ingress_from_customer_rsclient".to_string(),
            prefixes: vec!["203.0.113.0/24".to_string(), "2001:db8::/32".to_string()],
            count: 2,
            local_role: "provider".to_string(),
            remote_role: "customer".to_string(),
            otc_value: Some(65002),
            as_path: "65002 {65003 65004}".to_string(),
            summary:
                "OTC ingress blocked 2 route(s) on peer 10.0.0.2 (ingress_from_customer_rsclient)"
                    .to_string(),
        };
        let event = BgpEvent {
            timestamp: "1".to_string(),
            category: EventCategory::Policy as i32,
            event_type: BgpEventType::OtcRouteBlocked as i32,
            severity: crate::proto::EventSeverity::Warning as i32,
            peer_address: "10.0.0.2".to_string(),
            previous_peer_address: String::new(),
            prefix: String::new(),
            prefix_length: 0,
            afi_safi: AddressFamily::Unspecified as i32,
            summary: payload.summary.clone(),
            target_peer_address: String::new(),
            event_id: Some(7),
            payload: Some(crate::proto::bgp_event::Payload::OtcRouteBlocked(payload)),
        };

        let value = json_bgp_event(&event);
        assert_eq!(value["category"], "policy");
        assert_eq!(value["event_type"], "otc_route_blocked");
        assert_eq!(value["event_id"], 7);
        assert_eq!(value["direction"], "ingress");
        assert_eq!(value["reason"], "ingress_from_customer_rsclient");
        assert_eq!(value["count"], 2);
        assert_eq!(value["local_role"], "provider");
        assert_eq!(value["remote_role"], "customer");
        assert_eq!(value["otc_value"], 65002);
        // AS_SET segment survives lossless via {…} notation.
        assert_eq!(value["as_path"], "65002 {65003 65004}");
        let prefixes = value["prefixes"].as_array().expect("prefixes array");
        assert_eq!(prefixes.len(), 2);
        assert_eq!(prefixes[0], "203.0.113.0/24");
        assert_eq!(prefixes[1], "2001:db8::/32");
    }

    #[test]
    fn json_bgp_event_omits_otc_value_when_payload_value_absent() {
        // Malformed_length path: the attribute couldn't be decoded
        // and otc_value is None. The CLI JSON must surface that as
        // a JSON null, not silently drop the field or emit zero.
        let payload = crate::proto::OtcRouteBlockedEvent {
            event_type: BgpEventType::OtcRouteBlocked as i32,
            peer_address: "10.0.0.2".to_string(),
            timestamp: "1".to_string(),
            direction: "ingress".to_string(),
            reason: "malformed_length".to_string(),
            prefixes: vec!["203.0.113.0/24".to_string()],
            count: 1,
            local_role: "provider".to_string(),
            remote_role: String::new(),
            otc_value: None,
            as_path: String::new(),
            summary: "summary".to_string(),
        };
        let event = BgpEvent {
            timestamp: "1".to_string(),
            category: EventCategory::Policy as i32,
            event_type: BgpEventType::OtcRouteBlocked as i32,
            severity: crate::proto::EventSeverity::Warning as i32,
            peer_address: "10.0.0.2".to_string(),
            previous_peer_address: String::new(),
            prefix: String::new(),
            prefix_length: 0,
            afi_safi: AddressFamily::Unspecified as i32,
            summary: payload.summary.clone(),
            target_peer_address: String::new(),
            event_id: Some(7),
            payload: Some(crate::proto::bgp_event::Payload::OtcRouteBlocked(payload)),
        };
        let value = json_bgp_event(&event);
        assert!(value["otc_value"].is_null());
        assert_eq!(value["remote_role"], "");
    }

    #[test]
    fn validate_event_filter_categories_accepts_policy_with_address() {
        // OTC events ride on EVENT_CATEGORY_POLICY and are peer-
        // scoped. The CLI must not reject the natural shape
        // `--category policy --address 10.0.0.2` before the
        // request even reaches the EHM auto-route.
        validate_event_filter_categories(
            &[EventCategory::Policy as i32],
            &Some("10.0.0.2".to_string()),
            None,
            &None,
        )
        .expect("--address must be allowed on --category policy");
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
        assert_eq!(
            bgp_event_type_display_label(BgpEventType::EvpnRouteAdded as i32),
            "evpn_added"
        );
    }

    #[test]
    fn parse_bgp_event_type_accepts_aliases_and_rejects_unknown() {
        assert_eq!(
            parse_bgp_event_type("added").unwrap(),
            BgpEventType::RouteAdded as i32
        );
        assert_eq!(
            parse_bgp_event_type("route_added").unwrap(),
            BgpEventType::RouteAdded as i32
        );
        assert_eq!(
            parse_bgp_event_type("session_established").unwrap(),
            BgpEventType::SessionEstablished as i32
        );
        assert_eq!(
            parse_bgp_event_type("dataplane_changed").unwrap(),
            BgpEventType::DataplaneStatusChanged as i32
        );
        assert_eq!(
            parse_bgp_event_type("dataplane_route_installed").unwrap(),
            BgpEventType::DataplaneRouteInstalled as i32
        );
        assert_eq!(
            parse_bgp_event_type("fib_failed").unwrap(),
            BgpEventType::DataplaneRouteFailed as i32
        );
        assert_eq!(
            parse_bgp_event_type("evpn_best_changed").unwrap(),
            BgpEventType::EvpnRouteBestChanged as i32
        );
        assert_eq!(
            parse_bgp_event_type("policy_filtered").unwrap(),
            BgpEventType::RoutePolicyFiltered as i32
        );
        assert!(parse_bgp_event_type("not_an_event").is_err());
    }

    #[test]
    fn parse_bfd_category_and_event_types() {
        // The API already filters BFD events; the CLI must accept the `bfd`
        // category and the bfd_* event types (and their aliases) so
        // `rustbgpctl events watch --category bfd` works.
        assert_eq!(
            parse_event_category("bfd").unwrap(),
            EventCategory::Bfd as i32
        );
        assert_eq!(
            parse_bgp_event_type("bfd_up").unwrap(),
            BgpEventType::BfdSessionUp as i32
        );
        assert_eq!(
            parse_bgp_event_type("bfd_session_down").unwrap(),
            BgpEventType::BfdSessionDown as i32
        );
        assert_eq!(
            parse_bgp_event_type("bfd_state_changed").unwrap(),
            BgpEventType::BfdSessionStateChanged as i32
        );
        // Round-trips through the display + JSON labels.
        assert_eq!(
            bgp_event_type_display_label(BgpEventType::BfdSessionUp as i32),
            "bfd_up"
        );
        assert_eq!(
            bgp_event_type_json_label(BgpEventType::BfdSessionStateChanged as i32),
            "bfd_session_state_changed"
        );
    }

    #[test]
    fn parse_evpn_bgp_event_type_accepts_only_evpn_route_events() {
        assert_eq!(
            parse_evpn_bgp_event_type("evpn_added").unwrap(),
            BgpEventType::EvpnRouteAdded as i32
        );
        assert!(parse_evpn_bgp_event_type("added").is_err());
        assert!(parse_evpn_bgp_event_type("dataplane_changed").is_err());
    }

    #[test]
    fn parse_policy_bgp_event_type_accepts_only_policy_changed() {
        assert_eq!(
            parse_policy_bgp_event_type("policy_changed").unwrap(),
            BgpEventType::PolicyChanged as i32
        );
        assert!(parse_policy_bgp_event_type("established").is_err());
        assert!(parse_policy_bgp_event_type("dataplane_changed").is_err());
    }

    #[test]
    fn parse_event_category_accepts_supported_categories_only() {
        assert_eq!(
            parse_event_category("route").unwrap(),
            EventCategory::Route as i32
        );
        assert_eq!(
            parse_event_category("session").unwrap(),
            EventCategory::Session as i32
        );
        assert_eq!(
            parse_event_category("policy").unwrap(),
            EventCategory::Policy as i32
        );
        assert_eq!(
            parse_event_category("dataplane").unwrap(),
            EventCategory::Dataplane as i32
        );
        assert_eq!(
            parse_event_category("evpn").unwrap(),
            EventCategory::Evpn as i32
        );
        assert!(parse_event_category("bmp").is_err());
    }

    #[test]
    fn parse_optional_prefix_filter_validates_family_and_splits_prefix() {
        let (prefix, length) = parse_optional_prefix_filter(
            Some("203.0.113.0/24".to_string()),
            Some(AddressFamily::Ipv4Unicast as i32),
        )
        .unwrap();
        assert_eq!(prefix, "203.0.113.0");
        assert_eq!(length, 24);

        let err = parse_optional_prefix_filter(
            Some("2001:db8::/64".to_string()),
            Some(AddressFamily::Ipv4Unicast as i32),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("--prefix family"));
    }

    #[test]
    fn json_route_event_omits_empty_optional_fields() {
        let event = RouteEvent {
            event_id: 0,
            event_type: crate::proto::RouteEventType::Added as i32,
            prefix: "203.0.113.0".to_string(),
            prefix_length: 24,
            peer_address: "192.0.2.1".to_string(),
            afi_safi: AddressFamily::Ipv4Unicast as i32,
            timestamp: "123".to_string(),
            previous_peer_address: String::new(),
            target_peer_address: String::new(),
            path_id: 0,
            reason: String::new(),
        };

        let value = serde_json::to_value(json_event(&event)).unwrap();
        assert_eq!(value["event_type"], "added");
        assert_eq!(value["prefix"], "203.0.113.0/24");
        assert_eq!(value["peer_address"], "192.0.2.1");
        assert_eq!(value["afi_safi"], "ipv4_unicast");
        assert!(value.get("previous_peer_address").is_none());
        assert!(value.get("path_id").is_none());
        assert!(value.get("missed_count").is_none());
        assert!(value.get("reason").is_none());
    }

    #[test]
    fn json_route_event_includes_previous_peer_and_path_id() {
        let event = RouteEvent {
            event_id: 0,
            event_type: crate::proto::RouteEventType::BestChanged as i32,
            prefix: "2001:db8::".to_string(),
            prefix_length: 64,
            peer_address: "2001:db8::1".to_string(),
            afi_safi: AddressFamily::Ipv6Unicast as i32,
            timestamp: "123".to_string(),
            previous_peer_address: "2001:db8::2".to_string(),
            target_peer_address: String::new(),
            path_id: 17,
            reason: String::new(),
        };

        let value = serde_json::to_value(json_event(&event)).unwrap();
        assert_eq!(value["event_type"], "best_changed");
        assert_eq!(value["prefix"], "2001:db8::/64");
        assert_eq!(value["previous_peer_address"], "2001:db8::2");
        assert_eq!(value["path_id"], 17);
    }

    #[test]
    fn json_bgp_event_route_includes_common_route_fields() {
        let event = BgpEvent {
            timestamp: "1".to_string(),
            category: EventCategory::Route as i32,
            event_type: BgpEventType::RouteBestChanged as i32,
            severity: 1,
            peer_address: "192.0.2.1".to_string(),
            previous_peer_address: "192.0.2.2".to_string(),
            prefix: "203.0.113.0".to_string(),
            prefix_length: 24,
            afi_safi: AddressFamily::Ipv4Unicast as i32,
            summary: "route best changed 203.0.113.0/24".to_string(),
            ..Default::default()
        };

        let value = json_bgp_event(&event);
        assert_eq!(value["category"], "route");
        assert_eq!(value["event_type"], "route_best_changed");
        assert_eq!(value["severity"], "info");
        assert_eq!(value["peer_address"], "192.0.2.1");
        assert_eq!(value["previous_peer_address"], "192.0.2.2");
        assert_eq!(value["prefix"], "203.0.113.0/24");
        assert_eq!(value["afi_safi"], "ipv4_unicast");
        assert_eq!(value["summary"], "route best changed 203.0.113.0/24");
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
            event_id: None,
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
    fn json_bgp_event_session_includes_envelope_event_id() {
        let event = BgpEvent {
            timestamp: "1".to_string(),
            category: EventCategory::Session as i32,
            event_type: BgpEventType::SessionEstablished as i32,
            severity: 1,
            peer_address: "10.0.0.1".to_string(),
            summary: "session established".to_string(),
            event_id: Some(42),
            ..Default::default()
        };

        let value = json_bgp_event(&event);
        assert_eq!(value["event_id"], 42);
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
            event_id: None,
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
    fn json_route_watch_stream_lag_uses_route_event_shape() {
        let event = BgpEvent {
            timestamp: "2".to_string(),
            category: EventCategory::Route as i32,
            event_type: BgpEventType::StreamLagged as i32,
            severity: 2,
            afi_safi: AddressFamily::Unspecified as i32,
            summary: "route event stream lagged; missed 7 event(s)".to_string(),
            event_id: None,
            payload: Some(crate::proto::bgp_event::Payload::StreamLag(
                crate::proto::StreamLagEvent {
                    source_category: EventCategory::Route as i32,
                    missed_count: 7,
                    reason: "route event stream lagged; missed 7 event(s)".to_string(),
                },
            )),
            ..Default::default()
        };

        let value = json_route_watch_event(&event).unwrap();
        assert_eq!(value["event_type"], "stream_lagged");
        assert_eq!(value["missed_count"], 7);
        assert_eq!(
            value["reason"],
            "route event stream lagged; missed 7 event(s)"
        );
        assert!(value.get("category").is_none());
        assert!(value.get("severity").is_none());
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
            event_id: None,
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
            event_id: None,
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
    fn event_filter_rejects_route_filters_without_route_or_dataplane_category() {
        let categories = vec![EventCategory::Session as i32, EventCategory::Policy as i32];
        let err = validate_event_filter_categories(
            &categories,
            &None,
            Some(AddressFamily::Ipv4Unicast as i32),
            &None,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("--category route or --category dataplane"));

        let err = validate_event_filter_categories(
            &categories,
            &None,
            None,
            &Some("203.0.113.0/24".to_string()),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("--category route or --category dataplane"));
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
    fn event_filter_allows_peer_for_evpn_category() {
        let categories = vec![EventCategory::Evpn as i32];
        validate_event_filter_categories(&categories, &Some("10.0.0.1".to_string()), None, &None)
            .unwrap();
    }

    #[test]
    fn event_filter_allows_peer_for_dataplane_route_events() {
        let categories = vec![EventCategory::Dataplane as i32];
        validate_event_filter_categories(&categories, &Some("10.0.0.1".to_string()), None, &None)
            .unwrap();
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
            event_id: None,
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
    fn json_bgp_event_dataplane_route_includes_route_fields() {
        let event = BgpEvent {
            timestamp: "1".to_string(),
            category: EventCategory::Dataplane as i32,
            event_type: BgpEventType::DataplaneRouteFailed as i32,
            severity: 2,
            peer_address: "10.0.0.1".to_string(),
            prefix: "203.0.113.0".to_string(),
            prefix_length: 24,
            afi_safi: AddressFamily::Ipv4Unicast as i32,
            summary: "dataplane fib route failed 203.0.113.0/24".to_string(),
            event_id: None,
            payload: Some(crate::proto::bgp_event::Payload::DataplaneRoute(
                crate::proto::DataplaneRouteEvent {
                    source: "fib".to_string(),
                    action: "failed".to_string(),
                    table_name: "blue".to_string(),
                    table_id: 100,
                    metric: 20,
                    prefix: "203.0.113.0".to_string(),
                    prefix_length: 24,
                    next_hop: "192.0.2.1".to_string(),
                    peer_address: "10.0.0.1".to_string(),
                    timestamp: "1".to_string(),
                    reason: "install_failed:permission denied".to_string(),
                },
            )),
            ..Default::default()
        };

        let value = json_bgp_event(&event);
        assert_eq!(value["category"], "dataplane");
        assert_eq!(value["event_type"], "dataplane_route_failed");
        assert_eq!(value["prefix"], "203.0.113.0/24");
        assert_eq!(value["afi_safi"], "ipv4_unicast");
        assert_eq!(value["source"], "fib");
        assert_eq!(value["action"], "failed");
        assert_eq!(value["table_name"], "blue");
        assert_eq!(value["table_id"], 100);
        assert_eq!(value["metric"], 20);
        assert_eq!(value["next_hop"], "192.0.2.1");
        assert_eq!(value["reason"], "install_failed:permission denied");
    }

    #[test]
    fn json_bgp_event_evpn_includes_route_key_and_payloads() {
        let event = BgpEvent {
            timestamp: "1".to_string(),
            category: EventCategory::Evpn as i32,
            event_type: BgpEventType::EvpnRouteBestChanged as i32,
            severity: 1,
            peer_address: "10.0.0.2".to_string(),
            previous_peer_address: "10.0.0.3".to_string(),
            afi_safi: AddressFamily::L2vpnEvpn as i32,
            summary: "EVPN route best changed mac".to_string(),
            event_id: None,
            payload: Some(crate::proto::bgp_event::Payload::Evpn(
                crate::proto::EvpnRouteEvent {
                    event_type: BgpEventType::EvpnRouteBestChanged as i32,
                    peer_address: "10.0.0.2".to_string(),
                    previous_peer_address: "10.0.0.3".to_string(),
                    timestamp: "1".to_string(),
                    route_type: 2,
                    rd: "65000:100".to_string(),
                    route_key: "type=2 rd=65000:100 mac=aa:bb:cc:dd:ee:ff".to_string(),
                    route: Some(EvpnRouteEntry {
                        route_type: 2,
                        rd: "65000:100".to_string(),
                        mac: "aa:bb:cc:dd:ee:ff".to_string(),
                        peer_address: "10.0.0.2".to_string(),
                        ..Default::default()
                    }),
                    previous_route: None,
                    reason: "EVPN route best changed mac".to_string(),
                },
            )),
            ..Default::default()
        };

        let value = json_bgp_event(&event);
        assert_eq!(value["category"], "evpn");
        assert_eq!(value["event_type"], "evpn_route_best_changed");
        assert_eq!(value["route_type"], 2);
        assert_eq!(value["route_type_name"], "mac-ip");
        assert_eq!(value["rd"], "65000:100");
        assert_eq!(
            value["route_key"],
            "type=2 rd=65000:100 mac=aa:bb:cc:dd:ee:ff"
        );
        assert_eq!(value["route"]["mac"], "aa:bb:cc:dd:ee:ff");
        assert!(value["previous_route"].is_null());
    }

    #[test]
    fn route_only_filters_reject_policy_only_category() {
        let categories = vec![EventCategory::Policy as i32];
        let err = validate_route_only_filters(&categories, &[], None, Some("203.0.113.0/24"))
            .unwrap_err();
        assert!(err.to_string().contains("route or dataplane route events"));
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
        assert!(err.to_string().contains("route or dataplane route events"));
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
            target_peer_address: String::new(),
            reason: String::new(),
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
