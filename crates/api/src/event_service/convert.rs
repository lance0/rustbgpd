use crate::peer_types::{
    PolicyEvent, SessionEvent, SessionLifecycleEvent, SessionLifecycleEventType,
    SessionNotificationEvent, SessionNotificationEventType,
};
use crate::proto;
use crate::rib_service::{evpn_route_to_proto, route_event_to_proto};
use crate::route_distinguisher::format_rd;

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
            | proto::BgpEventType::MaxPrefixWarning
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
        timestamp_unix_ms: route.timestamp_unix_ms,
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
        payload: Some(proto::bgp_event::Payload::Route(route)),
    }
}

pub fn evpn_event_to_bgp_event(event: rustbgpd_rib::EvpnRouteEvent) -> proto::BgpEvent {
    let event_type = route_event_type_to_evpn_bgp_event_type(event.event_type);
    let peer_address = event.peer.map_or_else(String::new, |peer| peer.to_string());
    let previous_peer_address = event
        .previous_peer
        .map_or_else(String::new, |peer| peer.to_string());
    let rd = rustbgpd_rib::event::evpn_key_rd(&event.key).map_or_else(String::new, format_rd);
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
        timestamp_unix_ms: rustbgpd_rib::event::unix_timestamp_ms(&event.timestamp),
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
        payload: Some(proto::bgp_event::Payload::Evpn(payload)),
    }
}

fn format_evpn_route_key(key: &rustbgpd_wire::EvpnRouteKey) -> String {
    let rd = rustbgpd_rib::event::evpn_key_rd(key).map_or_else(String::new, format_rd);
    match key {
        rustbgpd_wire::EvpnRouteKey::EadPerEs {
            rd: _,
            esi,
            ethernet_tag,
        } => format!("ead-per-es rd={rd} esi={esi} ethernet_tag={ethernet_tag}"),
        rustbgpd_wire::EvpnRouteKey::EadPerEvi {
            rd: _,
            esi,
            ethernet_tag,
        } => format!("ead-per-evi rd={rd} esi={esi} ethernet_tag={ethernet_tag}"),
        rustbgpd_wire::EvpnRouteKey::MacIp {
            rd: _,
            ethernet_tag,
            mac,
            ip,
        } => format!(
            "mac-ip rd={rd} ethernet_tag={ethernet_tag} mac={mac} ip={}",
            ip.map_or_else(String::new, |ip| ip.to_string())
        ),
        rustbgpd_wire::EvpnRouteKey::Imet {
            rd: _,
            ethernet_tag,
            originator_ip,
        } => format!("imet rd={rd} ethernet_tag={ethernet_tag} originator_ip={originator_ip}"),
        rustbgpd_wire::EvpnRouteKey::Es {
            rd: _,
            esi,
            originator_ip,
        } => format!("es rd={rd} esi={esi} originator_ip={originator_ip}"),
        rustbgpd_wire::EvpnRouteKey::IpPrefix {
            rd: _,
            ethernet_tag,
            prefix,
        } => format!("ip-prefix rd={rd} ethernet_tag={ethernet_tag} prefix={prefix}"),
        rustbgpd_wire::EvpnRouteKey::Smet {
            rd: _,
            ethernet_tag,
            source_ip,
            group_ip,
            originator_ip,
        } => format!(
            "smet rd={rd} ethernet_tag={ethernet_tag} source={} group={} originator_ip={originator_ip}",
            source_ip.map_or_else(|| "*".to_string(), |ip| ip.to_string()),
            group_ip.map_or_else(|| "*".to_string(), |ip| ip.to_string())
        ),
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
        SessionLifecycleEventType::Lost | SessionLifecycleEventType::MaxPrefixWarning => {
            proto::EventSeverity::Warning
        }
        SessionLifecycleEventType::StateChanged
        | SessionLifecycleEventType::Established
        | SessionLifecycleEventType::PeerAdded
        | SessionLifecycleEventType::PeerRemoved
        | SessionLifecycleEventType::PeerEnabled
        | SessionLifecycleEventType::PeerDisabled => proto::EventSeverity::Info,
    };

    proto::BgpEvent {
        timestamp_unix_ms: rustbgpd_rib::event::unix_timestamp_ms(&event.timestamp),
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
        timestamp_unix_ms: rustbgpd_rib::event::unix_timestamp_ms(&event.timestamp),
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
        timestamp_unix_ms: rustbgpd_rib::event::unix_timestamp_ms(&timestamp),
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
        payload: Some(proto::bgp_event::Payload::Policy(policy)),
    }
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
    let timestamp = rustbgpd_rib::event::unix_timestamp_now();
    proto::BgpEvent {
        timestamp_unix_ms: rustbgpd_rib::event::unix_timestamp_ms(&timestamp),
        timestamp,
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
    let timestamp = rustbgpd_rib::event::unix_timestamp_now();
    proto::BgpEvent {
        timestamp_unix_ms: rustbgpd_rib::event::unix_timestamp_ms(&timestamp),
        timestamp,
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
        payload: Some(proto::bgp_event::Payload::Dataplane(payload)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn rd_event_output_round_trips_the_exact_event_filter() {
        use rustbgpd_rib::RouteEventType;
        use rustbgpd_wire::EvpnRoute;
        for rd in [
            rustbgpd_wire::RouteDistinguisher([0, 0, 0xfd, 0xe8, 0, 0, 0, 100]),
            rustbgpd_wire::RouteDistinguisher([0, 2, 0, 0, 0xfd, 0xe8, 0, 100]),
        ] {
            let mut event = crate::test_support::evpn_event(
                RouteEventType::Added,
                Some("192.0.2.1".parse().unwrap()),
                None,
            );
            let EvpnRoute::MacIp(route) = &mut event.best.as_mut().unwrap().route else {
                unreachable!()
            };
            route.rd = rd;
            event.key = event.best.as_ref().unwrap().key();
            let output = evpn_event_to_bgp_event(event);
            let Some(proto::bgp_event::Payload::Evpn(payload)) = output.payload else {
                unreachable!()
            };
            let expected = format_rd(rd);
            assert_eq!(payload.rd, expected);
            assert_eq!(payload.route.unwrap().rd, expected);
            assert!(payload.route_key.contains(&format!("rd={expected} ")));
            for rd_filter in [expected.clone(), expected.to_ascii_uppercase()] {
                let filter = super::super::filters::parse_list_evpn_events_filter(
                    &proto::ListEvpnEventsRequest {
                        rd_filter,
                        ..Default::default()
                    },
                )
                .unwrap();
                assert_eq!(filter.rd, Some(rd));
            }
        }
    }

    #[test]
    fn converted_events_carry_typed_millisecond_timestamps() {
        let peer = std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let mut route = crate::test_support::route_event(
            rustbgpd_wire::Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
                Ipv4Addr::new(10, 1, 0, 0),
                24,
            )),
            peer,
        );
        route.timestamp = "1783915200".to_string();
        let event = route_event_to_bgp_event(route);
        assert_eq!(event.timestamp, "1783915200");
        assert_eq!(event.timestamp_unix_ms, 1_783_915_200_000);
        let Some(proto::bgp_event::Payload::Route(payload)) = event.payload else {
            panic!("expected route payload");
        };
        assert_eq!(payload.timestamp_unix_ms, 1_783_915_200_000);

        let event = policy_event_to_bgp_event(PolicyEvent {
            operation: "set",
            target_type: "policy",
            target: "p".to_string(),
            peer: None,
            peer_label: None,
            affected_peer_count: 0,
            timestamp: "1783915201".to_string(),
            reason: String::new(),
        });
        assert_eq!(event.timestamp_unix_ms, 1_783_915_201_000);

        let event = stream_lag_bgp_event(proto::EventCategory::Route, 1);
        assert_eq!(
            event.timestamp_unix_ms,
            event.timestamp.parse::<i64>().unwrap() * 1000
        );
        assert!(event.timestamp_unix_ms > 0);
    }

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
            assert_eq!(event.timestamp_unix_ms, 123_000);
            assert_eq!(event.event_type, expected_type as i32);
            assert_eq!(event.severity, proto::EventSeverity::Info as i32);
            let Some(proto::bgp_event::Payload::Session(session)) = event.payload else {
                panic!("expected session payload");
            };
            assert_eq!(session.old_state.len(), 0);
            assert_eq!(
                session.new_state,
                if new_state.is_some() { "idle" } else { "" }
            );
            assert_eq!(session.session_role.len(), 0);
        }
    }
}
