//! Shared JSON-lines formatter for `BgpEvent` (ADR-0072 PR5).
//!
//! Prost-generated types don't carry `serde::Serialize` impls without
//! the optional `serde` feature on prost (which we don't enable to
//! avoid an extra build-graph dep). The CLI's existing
//! `JsonRouteEvent` shape is route-only and pre-dates the envelope-
//! level `event_id`. This module is the single hand-rolled formatter
//! both `rustbgpctl watch --from-event-id` and the
//! `examples/event-bridge/` reference binary call into.
//!
//! Compact line shape (one event per line, newline-terminated):
//!
//! ```text
//! {"event_id":42,"timestamp":"1748305...","category":"route",
//!  "event_type":"BGP_EVENT_TYPE_ROUTE_ADDED","severity":"info","peer":"10.0.0.1",
//!  "previous_peer":"","target_peer":"","prefix":"10.1.0.0",
//!  "prefix_length":24,"afi_safi":"ipv4_unicast","summary":"…",
//!  "payload":{ … category-specific structured fields … }}
//! ```
//!
//! `payload` is only present for events we know how to render
//! structurally (route, EVPN, session-lifecycle, session-notification,
//! policy, BFD, stream-lag, dataplane). For unknown payload variants
//! we fall back to a `"payload":{"type":"unknown"}` placeholder so
//! consumers always see a complete object.

use serde_json::{Map, Value, json};

use crate::proto;

/// Render a single `BgpEvent` as a one-line JSON string.
///
/// The output does NOT include a trailing newline; bridge / CLI
/// callers add their own (so they can tee, prefix, etc. before
/// emitting).
#[must_use]
pub fn bgp_event_to_json_line(event: &proto::BgpEvent) -> String {
    let mut obj = Map::new();

    if let Some(id) = event.event_id {
        obj.insert("event_id".into(), json!(id));
    }
    obj.insert("timestamp".into(), json!(event.timestamp));
    obj.insert("category".into(), json!(category_name(event.category)));
    obj.insert(
        "event_type".into(),
        json!(event_type_name(event.event_type)),
    );
    obj.insert("severity".into(), json!(severity_name(event.severity)));
    obj.insert("peer".into(), json!(event.peer_address));
    obj.insert("previous_peer".into(), json!(event.previous_peer_address));
    obj.insert("target_peer".into(), json!(event.target_peer_address));
    obj.insert("prefix".into(), json!(event.prefix));
    obj.insert("prefix_length".into(), json!(event.prefix_length));
    obj.insert("afi_safi".into(), address_family_value(event.afi_safi));
    obj.insert("summary".into(), json!(event.summary));

    if let Some(payload) = &event.payload {
        obj.insert("payload".into(), render_payload(payload));
    }

    Value::Object(obj).to_string()
}

fn category_name(v: i32) -> String {
    match proto::EventCategory::try_from(v) {
        Ok(proto::EventCategory::Unspecified) => "unspecified".to_string(),
        Ok(proto::EventCategory::Route) => "route".to_string(),
        Ok(proto::EventCategory::Session) => "session".to_string(),
        Ok(proto::EventCategory::Policy) => "policy".to_string(),
        Ok(proto::EventCategory::Dataplane) => "dataplane".to_string(),
        Ok(proto::EventCategory::Evpn) => "evpn".to_string(),
        Ok(proto::EventCategory::Bfd) => "bfd".to_string(),
        Err(_) => format!("unknown_{v}"),
    }
}

fn event_type_name(v: i32) -> String {
    proto::BgpEventType::try_from(v)
        .map_or_else(|_| format!("unknown_{v}"), |t| t.as_str_name().to_string())
}

fn severity_name(v: i32) -> String {
    match proto::EventSeverity::try_from(v) {
        Ok(proto::EventSeverity::Unspecified) => "unspecified".to_string(),
        Ok(proto::EventSeverity::Info) => "info".to_string(),
        Ok(proto::EventSeverity::Warning) => "warning".to_string(),
        Ok(proto::EventSeverity::Error) => "error".to_string(),
        Err(_) => format!("unknown_{v}"),
    }
}

fn address_family_value(v: i32) -> Value {
    match proto::AddressFamily::try_from(v) {
        Ok(proto::AddressFamily::Unspecified) => Value::Null,
        Ok(family) => json!(
            family
                .as_str_name()
                .strip_prefix("ADDRESS_FAMILY_")
                .unwrap_or(family.as_str_name())
                .to_ascii_lowercase()
        ),
        Err(_) => json!(format!("unknown_{v}")),
    }
}

fn render_payload(payload: &proto::bgp_event::Payload) -> Value {
    match payload {
        proto::bgp_event::Payload::Route(r) => json!({
            "type": "route",
            "prefix": r.prefix,
            "prefix_length": r.prefix_length,
            "afi_safi": r.afi_safi,
            "peer": r.peer_address,
            "previous_peer": r.previous_peer_address,
            "target_peer": r.target_peer_address,
            "path_id": r.path_id,
            "reason": r.reason,
            "event_id": r.event_id,
        }),
        proto::bgp_event::Payload::Session(s) => json!({
            "type": "session",
            "peer": s.peer_address,
            "old_state": s.old_state,
            "new_state": s.new_state,
            "session_role": s.session_role,
            "reason": s.reason,
        }),
        proto::bgp_event::Payload::Notification(n) => json!({
            "type": "notification",
            "peer": n.peer_address,
            "direction": n.direction,
            "code": n.code,
            "subcode": n.subcode,
            "description": n.description,
            "session_role": n.session_role,
            "shutdown_reason": n.shutdown_reason,
            "reason": n.reason,
        }),
        proto::bgp_event::Payload::Policy(p) => json!({
            "type": "policy",
            "operation": p.operation,
            "target_type": p.target_type,
            "target": p.target,
            "peer": p.peer_address,
            "affected_peer_count": p.affected_peer_count,
            "reason": p.reason,
        }),
        proto::bgp_event::Payload::Dataplane(d) => json!({
            "type": "dataplane",
            "source": d.source,
            "installed": d.installed,
            "rejected": d.rejected,
            "failed": d.failed,
        }),
        proto::bgp_event::Payload::Evpn(e) => json!({
            "type": "evpn",
            "rd": e.rd,
            "route_type": e.route_type,
            "route_key": e.route_key,
            "peer": e.peer_address,
            "previous_peer": e.previous_peer_address,
            "reason": e.reason,
        }),
        proto::bgp_event::Payload::Bfd(b) => json!({
            "type": "bfd",
            "peer": b.peer_address,
            "old_state": b.old_state,
            "new_state": b.new_state,
            "diagnostic": b.diagnostic,
            "reason": b.reason,
        }),
        proto::bgp_event::Payload::DataplaneRoute(r) => json!({
            "type": "dataplane_route",
            "source": r.source,
            "action": r.action,
            "table_name": r.table_name,
            "table_id": r.table_id,
            "metric": r.metric,
            "prefix": r.prefix,
            "prefix_length": r.prefix_length,
            "next_hop": r.next_hop,
            "peer": r.peer_address,
            "reason": r.reason,
        }),
        proto::bgp_event::Payload::StreamLag(l) => json!({
            "type": "stream_lag",
            "source_category": l.source_category,
            "missed_count": l.missed_count,
            "reason": l.reason,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_operator_friendly_envelope_labels() {
        let event = proto::BgpEvent {
            timestamp: "1".to_string(),
            category: proto::EventCategory::Route as i32,
            event_type: proto::BgpEventType::RouteAdded as i32,
            severity: proto::EventSeverity::Info as i32,
            peer_address: "10.0.0.1".to_string(),
            prefix: "10.1.0.0".to_string(),
            prefix_length: 24,
            afi_safi: proto::AddressFamily::Ipv4Unicast as i32,
            summary: "route added 10.1.0.0/24".to_string(),
            event_id: Some(42),
            ..Default::default()
        };

        let value: Value = serde_json::from_str(&bgp_event_to_json_line(&event)).unwrap();
        assert_eq!(value["event_id"], 42);
        assert_eq!(value["category"], "route");
        assert_eq!(value["event_type"], "BGP_EVENT_TYPE_ROUTE_ADDED");
        assert_eq!(value["severity"], "info");
        assert_eq!(value["afi_safi"], "ipv4_unicast");
    }
}
