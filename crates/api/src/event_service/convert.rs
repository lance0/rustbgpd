use crate::peer_types::{
    PolicyEvent, SessionEvent, SessionLifecycleEvent, SessionLifecycleEventType,
    SessionNotificationEvent, SessionNotificationEventType,
};
use crate::proto;
use crate::rib_service::{evpn_route_to_proto, route_event_to_proto};

use super::filters::{
    route_event_type_to_bgp_event_type, route_event_type_to_evpn_bgp_event_type,
    session_lifecycle_event_type_to_bgp_event_type,
    session_notification_event_type_to_bgp_event_type,
};

#[must_use]
pub fn route_event_to_bgp_event(event: rustbgpd_rib::RouteEvent) -> proto::BgpEvent {
    let event_type = route_event_type_to_bgp_event_type(event.event_type);
    let route = route_event_to_proto(event);
    let summary = format!(
        "route {} {}/{}",
        match event_type {
            proto::BgpEventType::RouteAdded => "added",
            proto::BgpEventType::RouteWithdrawn => "withdrawn",
            proto::BgpEventType::RouteBestChanged => "best changed",
            proto::BgpEventType::RoutePolicyFiltered => "policy filtered",
            proto::BgpEventType::Unspecified
            | proto::BgpEventType::SessionStateChanged
            | proto::BgpEventType::SessionEstablished
            | proto::BgpEventType::SessionLost
            | proto::BgpEventType::PeerEnabled
            | proto::BgpEventType::PeerDisabled
            | proto::BgpEventType::PeerAdded
            | proto::BgpEventType::PeerRemoved
            | proto::BgpEventType::NotificationSent
            | proto::BgpEventType::NotificationReceived
            | proto::BgpEventType::PolicyChanged
            | proto::BgpEventType::DataplaneStatusChanged
            | proto::BgpEventType::DataplaneRouteInstalled
            | proto::BgpEventType::DataplaneRouteWithdrawn
            | proto::BgpEventType::DataplaneRouteFailed
            | proto::BgpEventType::EvpnRouteAdded
            | proto::BgpEventType::EvpnRouteWithdrawn
            | proto::BgpEventType::EvpnRouteBestChanged
            | proto::BgpEventType::BfdSessionUp
            | proto::BgpEventType::BfdSessionDown
            | proto::BgpEventType::BfdSessionStateChanged
            | proto::BgpEventType::OtcRouteBlocked
            | proto::BgpEventType::StreamLagged => "changed",
        },
        route.prefix,
        route.prefix_length
    );
    let summary = if event_type == proto::BgpEventType::RoutePolicyFiltered {
        format!(
            "{summary} target={} reason={}",
            route.target_peer_address, route.reason
        )
    } else {
        summary
    };

    proto::BgpEvent {
        timestamp: route.timestamp.clone(),
        category: proto::EventCategory::Route as i32,
        event_type: event_type as i32,
        severity: proto::EventSeverity::Info as i32,
        peer_address: route.peer_address.clone(),
        previous_peer_address: route.previous_peer_address.clone(),
        prefix: route.prefix.clone(),
        prefix_length: route.prefix_length,
        afi_safi: route.afi_safi,
        summary,
        target_peer_address: route.target_peer_address.clone(),
        // event_id is carried by the durable outbox (ADR-0072); these
        // converters build BgpEvent from the legacy in-memory rings and
        // don't have a durable id to surface. PR5+ replaces these sites
        // with EHM-fed conversions that fill the field from the
        // `CommittedEvent` envelope.
        event_id: None,
        payload: Some(proto::bgp_event::Payload::Route(route)),
    }
}

pub fn evpn_event_to_bgp_event(event: rustbgpd_rib::EvpnRouteEvent) -> proto::BgpEvent {
    let event_type = route_event_type_to_evpn_bgp_event_type(event.event_type);
    let peer_address = event.peer.map_or_else(String::new, |peer| peer.to_string());
    let previous_peer_address = event
        .previous_peer
        .map_or_else(String::new, |peer| peer.to_string());
    let rd =
        rustbgpd_rib::event::evpn_key_rd(&event.key).map_or_else(String::new, |rd| rd.to_string());
    let route_type = u32::from(event.key.route_type());
    let route_key = format_evpn_route_key(&event.key);
    let action = match event_type {
        proto::BgpEventType::EvpnRouteAdded => "added",
        proto::BgpEventType::EvpnRouteWithdrawn => "withdrawn",
        proto::BgpEventType::EvpnRouteBestChanged => "best changed",
        _ => "changed",
    };
    let summary = format!("EVPN route {action} type={route_type} key={route_key}");
    let route = event.best.as_ref().map(evpn_route_to_proto);
    let previous_route = event.previous_best.as_ref().map(evpn_route_to_proto);
    let payload = proto::EvpnRouteEvent {
        event_type: event_type as i32,
        peer_address: peer_address.clone(),
        previous_peer_address: previous_peer_address.clone(),
        timestamp: event.timestamp.clone(),
        route_type,
        rd,
        route_key,
        route,
        previous_route,
        reason: summary.clone(),
    };

    proto::BgpEvent {
        timestamp: event.timestamp,
        category: proto::EventCategory::Evpn as i32,
        event_type: event_type as i32,
        severity: proto::EventSeverity::Info as i32,
        peer_address,
        previous_peer_address,
        prefix: String::new(),
        prefix_length: 0,
        afi_safi: proto::AddressFamily::L2vpnEvpn as i32,
        summary,
        target_peer_address: String::new(),
        event_id: None,
        payload: Some(proto::bgp_event::Payload::Evpn(payload)),
    }
}

fn format_evpn_route_key(key: &rustbgpd_wire::EvpnRouteKey) -> String {
    match key {
        rustbgpd_wire::EvpnRouteKey::EadPerEs {
            rd,
            esi,
            ethernet_tag,
        } => format!("ead-per-es rd={rd} esi={esi} ethernet_tag={ethernet_tag}"),
        rustbgpd_wire::EvpnRouteKey::EadPerEvi {
            rd,
            esi,
            ethernet_tag,
        } => format!("ead-per-evi rd={rd} esi={esi} ethernet_tag={ethernet_tag}"),
        rustbgpd_wire::EvpnRouteKey::MacIp {
            rd,
            ethernet_tag,
            mac,
            ip,
        } => format!(
            "mac-ip rd={rd} ethernet_tag={ethernet_tag} mac={mac} ip={}",
            ip.map_or_else(String::new, |ip| ip.to_string())
        ),
        rustbgpd_wire::EvpnRouteKey::Imet {
            rd,
            ethernet_tag,
            originator_ip,
        } => format!("imet rd={rd} ethernet_tag={ethernet_tag} originator_ip={originator_ip}"),
        rustbgpd_wire::EvpnRouteKey::Es {
            rd,
            esi,
            originator_ip,
        } => format!("es rd={rd} esi={esi} originator_ip={originator_ip}"),
        rustbgpd_wire::EvpnRouteKey::IpPrefix {
            rd,
            ethernet_tag,
            prefix,
        } => format!("ip-prefix rd={rd} ethernet_tag={ethernet_tag} prefix={prefix}"),
        // Non-exhaustive: name the gap honestly instead of guessing fields.
        _ => "unmodeled-route-type".to_string(),
    }
}

#[must_use]
pub fn session_event_to_bgp_event(event: SessionEvent) -> proto::BgpEvent {
    match event {
        SessionEvent::Lifecycle(event) => session_lifecycle_event_to_bgp_event(event),
        SessionEvent::Notification(event) => session_notification_event_to_bgp_event(event),
    }
}

fn session_lifecycle_event_to_bgp_event(event: SessionLifecycleEvent) -> proto::BgpEvent {
    let event_type = session_lifecycle_event_type_to_bgp_event_type(event.event_type);
    let peer_address = event
        .peer_label
        .clone()
        .unwrap_or_else(|| event.peer.to_string());
    let old_state = event
        .old_state
        .map_or_else(String::new, |state| state.as_str().to_string());
    let new_state = event
        .new_state
        .map_or_else(String::new, |state| state.as_str().to_string());
    let session_role = event.session_role.unwrap_or_default();
    let session = proto::SessionEvent {
        event_type: event_type as i32,
        peer_address: peer_address.clone(),
        timestamp: event.timestamp.clone(),
        old_state,
        new_state,
        session_role,
        reason: event.reason.clone(),
    };

    let severity = match event.event_type {
        SessionLifecycleEventType::Lost => proto::EventSeverity::Warning,
        SessionLifecycleEventType::StateChanged
        | SessionLifecycleEventType::Established
        | SessionLifecycleEventType::PeerAdded
        | SessionLifecycleEventType::PeerRemoved
        | SessionLifecycleEventType::PeerEnabled
        | SessionLifecycleEventType::PeerDisabled => proto::EventSeverity::Info,
    };

    proto::BgpEvent {
        timestamp: event.timestamp,
        category: proto::EventCategory::Session as i32,
        event_type: event_type as i32,
        severity: severity as i32,
        peer_address,
        previous_peer_address: String::new(),
        prefix: String::new(),
        prefix_length: 0,
        afi_safi: proto::AddressFamily::Unspecified as i32,
        summary: event.reason,
        target_peer_address: String::new(),
        event_id: None,
        payload: Some(proto::bgp_event::Payload::Session(session)),
    }
}

fn session_notification_event_to_bgp_event(event: SessionNotificationEvent) -> proto::BgpEvent {
    let event_type = session_notification_event_type_to_bgp_event_type(event.event_type);
    let peer_address = event
        .peer_label
        .clone()
        .unwrap_or_else(|| event.peer.to_string());
    let direction = match event.event_type {
        SessionNotificationEventType::Sent => "sent",
        SessionNotificationEventType::Received => "received",
    };
    let notification = proto::NotificationEvent {
        event_type: event_type as i32,
        peer_address: peer_address.clone(),
        timestamp: event.timestamp.clone(),
        direction: direction.to_string(),
        code: u32::from(event.code),
        subcode: u32::from(event.subcode),
        description: event.description.clone(),
        session_role: event.session_role.unwrap_or_default(),
        shutdown_reason: event.shutdown_reason.unwrap_or_default(),
        reason: event.reason.clone(),
    };

    proto::BgpEvent {
        timestamp: event.timestamp,
        category: proto::EventCategory::Session as i32,
        event_type: event_type as i32,
        severity: proto::EventSeverity::Warning as i32,
        peer_address,
        previous_peer_address: String::new(),
        prefix: String::new(),
        prefix_length: 0,
        afi_safi: proto::AddressFamily::Unspecified as i32,
        summary: event.reason,
        target_peer_address: String::new(),
        event_id: None,
        payload: Some(proto::bgp_event::Payload::Notification(notification)),
    }
}

#[must_use]
pub fn policy_event_to_bgp_event(event: PolicyEvent) -> proto::BgpEvent {
    let PolicyEvent {
        operation,
        target_type,
        target,
        peer,
        peer_label,
        affected_peer_count,
        timestamp,
        reason,
    } = event;
    let peer_address =
        peer_label.unwrap_or_else(|| peer.map_or_else(String::new, |peer| peer.to_string()));
    let policy = proto::PolicyEvent {
        event_type: proto::BgpEventType::PolicyChanged as i32,
        operation: operation.to_string(),
        target_type: target_type.to_string(),
        target,
        peer_address: peer_address.clone(),
        affected_peer_count: u32::try_from(affected_peer_count).unwrap_or(u32::MAX),
        timestamp: timestamp.clone(),
        reason: reason.clone(),
    };

    proto::BgpEvent {
        timestamp,
        category: proto::EventCategory::Policy as i32,
        event_type: proto::BgpEventType::PolicyChanged as i32,
        severity: proto::EventSeverity::Info as i32,
        peer_address,
        previous_peer_address: String::new(),
        prefix: String::new(),
        prefix_length: 0,
        afi_safi: proto::AddressFamily::Unspecified as i32,
        summary: reason,
        target_peer_address: String::new(),
        event_id: None,
        payload: Some(proto::bgp_event::Payload::Policy(policy)),
    }
}

/// Convert a transport-layer [`rustbgpd_transport::OtcRouteBlockedEvent`]
/// into a proto `BgpEvent` envelope. The legacy
/// `bgp_otc_routes_blocked_total` counter and the per-`NeighborState`
/// `otc_routes_blocked` scalar are unchanged; this converter handles
/// only the structured payload path (ADR-0072 follow-up, ADR-0071
/// deferred item).
///
/// `local_role` / `remote_role` lower to the RFC 9234 §4 lowercase
/// names (`provider`, `route_server`, `route_server_client`,
/// `customer`, `peer`). The `otc_value` is `None` only on the
/// `malformed_length` path where the attribute couldn't be decoded.
#[must_use]
pub fn otc_route_blocked_event_to_bgp_event(
    event: &rustbgpd_transport::OtcRouteBlockedEvent,
) -> proto::BgpEvent {
    let peer_address = event.peer.to_string();
    let timestamp = rustbgpd_rib::event::unix_timestamp_now();
    let count = u32::try_from(event.prefixes.len()).unwrap_or(u32::MAX);
    let summary = format!(
        "OTC {} blocked {} route(s) on peer {} ({})",
        event.direction.as_str(),
        count,
        peer_address,
        event.reason,
    );
    let payload = proto::OtcRouteBlockedEvent {
        event_type: proto::BgpEventType::OtcRouteBlocked as i32,
        peer_address: peer_address.clone(),
        timestamp: timestamp.clone(),
        direction: event.direction.as_str().to_string(),
        reason: event.reason.to_string(),
        prefixes: event.prefixes.clone(),
        count,
        local_role: event.local_role.map(bgp_role_label).unwrap_or_default(),
        remote_role: event.remote_role.map(bgp_role_label).unwrap_or_default(),
        otc_value: event.otc_value,
        as_path: event.as_path.clone(),
        summary: summary.clone(),
    };

    proto::BgpEvent {
        timestamp,
        category: proto::EventCategory::Policy as i32,
        event_type: proto::BgpEventType::OtcRouteBlocked as i32,
        severity: proto::EventSeverity::Warning as i32,
        peer_address,
        previous_peer_address: String::new(),
        prefix: String::new(),
        prefix_length: 0,
        afi_safi: proto::AddressFamily::Unspecified as i32,
        summary,
        target_peer_address: String::new(),
        event_id: None,
        payload: Some(proto::bgp_event::Payload::OtcRouteBlocked(payload)),
    }
}

/// Operator-facing string form of a BGP Role (RFC 9234 §4).
/// Lowercase `snake_case` matches existing event-surface conventions.
fn bgp_role_label(role: rustbgpd_wire::BgpRole) -> String {
    match role {
        rustbgpd_wire::BgpRole::Provider => "provider",
        rustbgpd_wire::BgpRole::RouteServer => "route_server",
        rustbgpd_wire::BgpRole::RouteServerClient => "route_server_client",
        rustbgpd_wire::BgpRole::Customer => "customer",
        rustbgpd_wire::BgpRole::Peer => "peer",
        // Non-exhaustive registry enum: label future roles honestly.
        _ => "unrecognized",
    }
    .to_string()
}

pub(crate) fn stream_lag_bgp_event(
    source_category: proto::EventCategory,
    missed_count: u64,
) -> proto::BgpEvent {
    let source = match source_category {
        proto::EventCategory::Route => "route",
        proto::EventCategory::Session => "session",
        proto::EventCategory::Policy => "policy",
        proto::EventCategory::Dataplane => "dataplane",
        proto::EventCategory::Evpn => "evpn",
        proto::EventCategory::Bfd => "bfd",
        proto::EventCategory::Unspecified => "unknown",
    };
    let summary = format!("{source} event stream lagged; missed {missed_count} event(s)");
    proto::BgpEvent {
        timestamp: rustbgpd_rib::event::unix_timestamp_now(),
        category: source_category as i32,
        event_type: proto::BgpEventType::StreamLagged as i32,
        severity: proto::EventSeverity::Warning as i32,
        peer_address: String::new(),
        previous_peer_address: String::new(),
        prefix: String::new(),
        prefix_length: 0,
        afi_safi: proto::AddressFamily::Unspecified as i32,
        summary: summary.clone(),
        target_peer_address: String::new(),
        event_id: None,
        payload: Some(proto::bgp_event::Payload::StreamLag(
            proto::StreamLagEvent {
                source_category: source_category as i32,
                missed_count,
                reason: summary,
            },
        )),
    }
}

pub(super) fn dataplane_summary_to_bgp_event(
    summary: super::dataplane::DataplaneSummary,
) -> proto::BgpEvent {
    let severity = if summary.failed > 0 {
        proto::EventSeverity::Warning
    } else {
        proto::EventSeverity::Info
    };
    let payload = proto::DataplaneEvent {
        source: summary.source.to_string(),
        installed: summary.installed,
        rejected: summary.rejected,
        failed: summary.failed,
    };
    proto::BgpEvent {
        timestamp: rustbgpd_rib::event::unix_timestamp_now(),
        category: proto::EventCategory::Dataplane as i32,
        event_type: proto::BgpEventType::DataplaneStatusChanged as i32,
        severity: severity as i32,
        peer_address: String::new(),
        previous_peer_address: String::new(),
        prefix: String::new(),
        prefix_length: 0,
        afi_safi: proto::AddressFamily::Unspecified as i32,
        summary: format!(
            "dataplane {} status changed: installed={} rejected={} failed={}",
            summary.source, summary.installed, summary.rejected, summary.failed
        ),
        target_peer_address: String::new(),
        event_id: None,
        payload: Some(proto::bgp_event::Payload::Dataplane(payload)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn peer_presence_events_lower_with_exact_state_and_classification() {
        let peer = std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        for (kind, expected_type, new_state) in [
            (
                SessionLifecycleEventType::PeerAdded,
                proto::BgpEventType::PeerAdded,
                Some(rustbgpd_fsm::SessionState::Idle),
            ),
            (
                SessionLifecycleEventType::PeerRemoved,
                proto::BgpEventType::PeerRemoved,
                None,
            ),
        ] {
            let event =
                session_event_to_bgp_event(SessionEvent::Lifecycle(SessionLifecycleEvent {
                    event_type: kind,
                    peer,
                    peer_label: Some("10.0.0.2".to_string()),
                    timestamp: "123".to_string(),
                    old_state: None,
                    new_state,
                    session_role: None,
                    reason: format!(
                        "peer 10.0.0.2 {}",
                        if new_state.is_some() {
                            "added"
                        } else {
                            "removed"
                        }
                    ),
                }));
            assert_eq!(event.category, proto::EventCategory::Session as i32);
            assert_eq!(event.event_type, expected_type as i32);
            assert_eq!(event.severity, proto::EventSeverity::Info as i32);
            let Some(proto::bgp_event::Payload::Session(session)) = event.payload else {
                panic!("expected session payload");
            };
            assert!(session.old_state.is_empty());
            assert_eq!(
                session.new_state,
                if new_state.is_some() { "idle" } else { "" }
            );
            assert!(session.session_role.is_empty());
        }
    }

    #[test]
    fn otc_route_blocked_event_lowers_with_full_context() {
        let event = rustbgpd_transport::OtcRouteBlockedEvent {
            peer: std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            direction: rustbgpd_transport::OtcDirection::Ingress,
            reason: rustbgpd_telemetry::reason_labels::OtcBlockReason::IngressFromCustomerRsclient,
            prefixes: vec!["203.0.113.0/24".to_string(), "2001:db8::/32".to_string()],
            local_role: Some(rustbgpd_wire::BgpRole::Provider),
            remote_role: Some(rustbgpd_wire::BgpRole::Customer),
            otc_value: Some(65002),
            as_path: "65002 {65003 65004}".to_string(),
        };

        let bgp = otc_route_blocked_event_to_bgp_event(&event);

        assert_eq!(bgp.category, proto::EventCategory::Policy as i32);
        assert_eq!(bgp.event_type, proto::BgpEventType::OtcRouteBlocked as i32);
        assert_eq!(bgp.severity, proto::EventSeverity::Warning as i32);
        assert_eq!(bgp.peer_address, "10.0.0.2");

        let Some(proto::bgp_event::Payload::OtcRouteBlocked(payload)) = bgp.payload else {
            panic!("expected OtcRouteBlocked payload variant");
        };
        assert_eq!(payload.direction, "ingress");
        assert_eq!(payload.reason, "ingress_from_customer_rsclient");
        assert_eq!(payload.count, 2);
        assert_eq!(payload.prefixes.len(), 2);
        assert_eq!(payload.local_role, "provider");
        assert_eq!(payload.remote_role, "customer");
        assert_eq!(payload.otc_value, Some(65002));
        // Lossless: AS_SET segment survives the round-trip.
        assert_eq!(payload.as_path, "65002 {65003 65004}");
    }

    #[test]
    fn otc_route_blocked_event_omits_otc_value_on_malformed_length() {
        let event = rustbgpd_transport::OtcRouteBlockedEvent {
            peer: std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            direction: rustbgpd_transport::OtcDirection::Ingress,
            reason: rustbgpd_telemetry::reason_labels::OtcBlockReason::MalformedLength,
            prefixes: vec!["203.0.113.0/24".to_string()],
            local_role: Some(rustbgpd_wire::BgpRole::Provider),
            remote_role: None,
            otc_value: None,
            as_path: String::new(),
        };

        let bgp = otc_route_blocked_event_to_bgp_event(&event);
        let Some(proto::bgp_event::Payload::OtcRouteBlocked(payload)) = bgp.payload else {
            panic!("expected OtcRouteBlocked payload variant");
        };
        assert!(payload.otc_value.is_none());
        assert_eq!(
            payload.remote_role, "",
            "missing role lowers to empty string"
        );
    }

    #[test]
    fn otc_route_blocked_egress_lowers_direction_string() {
        let event = rustbgpd_transport::OtcRouteBlockedEvent {
            peer: std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            direction: rustbgpd_transport::OtcDirection::Egress,
            reason: rustbgpd_telemetry::reason_labels::OtcBlockReason::EgressToUpstreamViaOtc,
            prefixes: vec!["203.0.113.0/24".to_string()],
            local_role: Some(rustbgpd_wire::BgpRole::Customer),
            remote_role: Some(rustbgpd_wire::BgpRole::Provider),
            otc_value: Some(65001),
            as_path: "65001".to_string(),
        };
        let bgp = otc_route_blocked_event_to_bgp_event(&event);
        let Some(proto::bgp_event::Payload::OtcRouteBlocked(payload)) = bgp.payload else {
            panic!("expected OtcRouteBlocked payload variant");
        };
        assert_eq!(payload.direction, "egress");
    }
}
