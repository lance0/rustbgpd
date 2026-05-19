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

pub(crate) fn route_event_to_bgp_event(event: rustbgpd_rib::RouteEvent) -> proto::BgpEvent {
    let event_type = route_event_type_to_bgp_event_type(event.event_type);
    let route = route_event_to_proto(event);
    let summary = format!(
        "route {} {}/{}",
        match event_type {
            proto::BgpEventType::RouteAdded => "added",
            proto::BgpEventType::RouteWithdrawn => "withdrawn",
            proto::BgpEventType::RouteBestChanged => "best changed",
            proto::BgpEventType::Unspecified
            | proto::BgpEventType::SessionStateChanged
            | proto::BgpEventType::SessionEstablished
            | proto::BgpEventType::SessionLost
            | proto::BgpEventType::PeerEnabled
            | proto::BgpEventType::PeerDisabled
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
            | proto::BgpEventType::StreamLagged => "changed",
        },
        route.prefix,
        route.prefix_length
    );

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
        payload: Some(proto::bgp_event::Payload::Route(route)),
    }
}

pub(crate) fn evpn_event_to_bgp_event(event: rustbgpd_rib::EvpnRouteEvent) -> proto::BgpEvent {
    let event_type = route_event_type_to_evpn_bgp_event_type(event.event_type);
    let peer_address = event.peer.map_or_else(String::new, |peer| peer.to_string());
    let previous_peer_address = event
        .previous_peer
        .map_or_else(String::new, |peer| peer.to_string());
    let rd = rustbgpd_rib::event::evpn_key_rd(&event.key).to_string();
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
    }
}

pub(super) fn session_event_to_bgp_event(event: SessionEvent) -> proto::BgpEvent {
    match event {
        SessionEvent::Lifecycle(event) => session_lifecycle_event_to_bgp_event(event),
        SessionEvent::Notification(event) => session_notification_event_to_bgp_event(event),
    }
}

fn session_lifecycle_event_to_bgp_event(event: SessionLifecycleEvent) -> proto::BgpEvent {
    let event_type = session_lifecycle_event_type_to_bgp_event_type(event.event_type);
    let peer_address = event.peer.to_string();
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
        payload: Some(proto::bgp_event::Payload::Session(session)),
    }
}

fn session_notification_event_to_bgp_event(event: SessionNotificationEvent) -> proto::BgpEvent {
    let event_type = session_notification_event_type_to_bgp_event_type(event.event_type);
    let peer_address = event.peer.to_string();
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
        payload: Some(proto::bgp_event::Payload::Notification(notification)),
    }
}

pub(super) fn policy_event_to_bgp_event(event: PolicyEvent) -> proto::BgpEvent {
    let PolicyEvent {
        operation,
        target_type,
        target,
        peer,
        affected_peer_count,
        timestamp,
        reason,
    } = event;
    let peer_address = peer.map_or_else(String::new, |peer| peer.to_string());
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
        payload: Some(proto::bgp_event::Payload::Dataplane(payload)),
    }
}
