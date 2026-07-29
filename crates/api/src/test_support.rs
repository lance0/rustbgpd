use std::net::IpAddr;
use std::sync::Arc;

use prometheus::Encoder;
use rustbgpd_fsm::SessionState;
use rustbgpd_rib::{EvpnRouteEvent, RibUpdate, RouteEvent, RouteEventType};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_transport::RemovePrivateAs;
use rustbgpd_wire::{
    EthernetSegmentIdentifier, EthernetTagId, EvpnMacIp, EvpnRoute, MacAddress, MplsLabel, Origin,
    PathAttribute, Prefix, RouteDistinguisher,
};
use tokio::sync::{broadcast, mpsc};

use crate::peer_types::{
    POLICY_EVENT_HISTORY_CAPACITY, PeerInfo, PeerManagerCommand, PolicyEvent, Rfc8212PolicyStatus,
    SESSION_EVENT_HISTORY_CAPACITY, SessionEvent, SessionLifecycleEvent, SessionLifecycleEventType,
    SessionNotificationEvent, SessionNotificationEventType,
};
use crate::proto;

pub(crate) fn metrics_text(metrics: &BgpMetrics) -> String {
    let encoder = prometheus::TextEncoder::new();
    let families = metrics.registry().gather();
    let mut out = Vec::new();
    encoder.encode(&families, &mut out).unwrap();
    String::from_utf8(out).unwrap()
}

pub(crate) fn peer_info(address: IpAddr) -> PeerInfo {
    PeerInfo {
        address,
        interface: None,
        remote_asn: 65002,
        description: String::new(),
        peer_group: None,
        state: SessionState::Established,
        enabled: true,
        graceful_shutdown_advertise_intent: false,
        prefix_count: 0,
        prefix_count_ipv4: 0,
        prefix_count_ipv6: 0,
        max_prefixes_effective: None,
        max_prefixes_ipv4_effective: None,
        max_prefixes_ipv6_effective: None,
        max_prefix_headroom: None,
        max_prefix_headroom_ipv4: None,
        max_prefix_headroom_ipv6: None,
        hold_time: None,
        min_hold_time: None,
        send_hold_time: 0,
        max_prefixes: None,
        max_prefix_action: "shutdown".to_string(),
        max_prefix_restart_seconds: None,
        max_prefix_restart_remaining_millis: None,
        families: Vec::new(),
        required_families: Vec::new(),
        negotiated_session: None,
        remove_private_as: RemovePrivateAs::Disabled,
        route_server_client: false,
        per_client_best: false,
        next_hop_ownership_strict_peer: false,
        interpret_rfc1997: true,
        rs_control_communities: false,
        orr_vantage: None,
        local_role: None,
        strict_role: false,
        remote_role: None,
        role_negotiated: false,
        add_path_receive: false,
        add_path_send: false,
        add_path_send_max: 0,
        paths_limit_receive_max: 0,
        peer_paths_limits: Vec::new(),
        effective_add_path_send_limits: Vec::new(),
        updates_received: 0,
        updates_sent: 0,
        notifications_received: 0,
        notifications_sent: 0,
        messages_received: 0,
        messages_sent: 0,
        route_reflector_client: false,
        otc_routes_blocked: 0,
        import_policy_routes_permitted: 0,
        import_policy_routes_denied: 0,
        export_policy_routes_permitted: 0,
        export_policy_routes_denied: 0,
        flap_count: 0,
        uptime_secs: 0,
        last_error: String::new(),
        authentication: "plaintext".to_string(),
        tcp_ao_info: None,
        tcp_ao_rotation: rustbgpd_transport::TcpAoRotationStatus::default(),
        is_dynamic: false,
        accepted_dynamic_range: None,
        stale: false,
        slow_peer: false,
        rfc8212_import_policy: Rfc8212PolicyStatus::NotRequired,
        rfc8212_export_policy: Rfc8212PolicyStatus::NotRequired,
    }
}

pub(crate) fn route_event(prefix: Prefix, peer: IpAddr) -> RouteEvent {
    RouteEvent {
        event_id: 1,
        event_type: RouteEventType::Added,
        prefix,
        peer: Some(peer),
        previous_peer: None,
        target_peer: None,
        timestamp: "123".to_string(),
        path_id: 7,
        reason: String::new(),
    }
}

fn evpn_route(peer: IpAddr, mac_byte: u8) -> rustbgpd_rib::route::EvpnRibRoute {
    let route = EvpnRoute::MacIp(EvpnMacIp {
        rd: RouteDistinguisher::new([0, 0, 0xFD, 0xE8, 0, 0, 0, 100]),
        esi: EthernetSegmentIdentifier::ZERO,
        ethernet_tag: EthernetTagId(0),
        mac: MacAddress::new([mac_byte; 6]),
        ip: Some(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, mac_byte))),
        label1: MplsLabel::new(100),
        label2: None,
    });
    rustbgpd_rib::route::EvpnRibRoute {
        route,
        next_hop: peer,
        link_local_next_hop: None,
        peer,
        attributes: Arc::new(vec![PathAttribute::Origin(Origin::Igp)]),
        received_at: std::time::Instant::now(),
        origin_type: rustbgpd_rib::route::RouteOrigin::Ibgp,
        peer_router_id: std::net::Ipv4Addr::new(192, 0, 2, mac_byte),
        is_stale: false,
        is_llgr_stale: false,
    }
}

pub(crate) fn evpn_event(
    event_type: RouteEventType,
    peer: Option<IpAddr>,
    previous_peer: Option<IpAddr>,
) -> EvpnRouteEvent {
    let route = peer.map(|peer| evpn_route(peer, 1));
    let previous_best = previous_peer.map(|peer| evpn_route(peer, 2));
    let key = route
        .as_ref()
        .or(previous_best.as_ref())
        .expect("test event needs a route")
        .key();
    EvpnRouteEvent {
        event_type,
        key,
        best: route,
        previous_best,
        peer,
        previous_peer,
        timestamp: "123".to_string(),
    }
}

pub(crate) fn spawn_fake_rib() -> (mpsc::Sender<RibUpdate>, broadcast::Sender<RouteEvent>) {
    let (rib_tx, mut rib_rx) = mpsc::channel(16);
    let (events_tx, _) = broadcast::channel(16);
    let (evpn_events_tx, _) = broadcast::channel(16);
    let events_tx_for_task = events_tx.clone();
    let evpn_events_tx_for_task = evpn_events_tx.clone();
    tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::SubscribeRouteEvents { reply } => {
                    let _ = reply.send(events_tx_for_task.subscribe());
                }
                RibUpdate::SubscribeEvpnRouteEvents { reply } => {
                    let _ = reply.send(evpn_events_tx_for_task.subscribe());
                }
                RibUpdate::QueryEvpnRouteEventHistory { reply, .. } => {
                    let _ = reply.send(Vec::new());
                }
                _ => {}
            }
        }
    });
    (rib_tx, events_tx)
}

pub(crate) fn spawn_fake_rib_with_evpn_history(
    history: Vec<EvpnRouteEvent>,
) -> mpsc::Sender<RibUpdate> {
    let (rib_tx, mut rib_rx) = mpsc::channel(16);
    let (events_tx, _) = broadcast::channel(16);
    let history = Arc::new(history);
    tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::SubscribeRouteEvents { reply } => {
                    let _ = reply.send(events_tx.subscribe());
                }
                RibUpdate::QueryEvpnRouteEventHistory {
                    peer,
                    route_type,
                    rd,
                    event_types,
                    limit,
                    reply,
                } => {
                    let limit = if limit == 0 { 4096 } else { limit.min(4096) };
                    let mut events: Vec<_> = history
                        .iter()
                        .rev()
                        .filter(|event| {
                            route_type.is_none_or(|route_type| event.key.route_type() == route_type)
                        })
                        .filter(|event| {
                            rd.is_none_or(|rd| {
                                rustbgpd_rib::event::evpn_key_rd(&event.key) == Some(rd)
                            })
                        })
                        .filter(|event| {
                            event_types.is_empty() || event_types.contains(&event.event_type)
                        })
                        .filter(|event| match peer {
                            Some(peer) => {
                                event.peer == Some(peer) || event.previous_peer == Some(peer)
                            }
                            None => true,
                        })
                        .take(limit)
                        .cloned()
                        .collect();
                    events.reverse();
                    let _ = reply.send(events);
                }
                _ => {}
            }
        }
    });
    rib_tx
}

pub(crate) fn spawn_fake_evpn_rib() -> (mpsc::Sender<RibUpdate>, broadcast::Sender<EvpnRouteEvent>)
{
    let (rib_tx, mut rib_rx) = mpsc::channel(16);
    let (route_events_tx, _) = broadcast::channel(16);
    let (evpn_events_tx, _) = broadcast::channel(16);
    let evpn_events_tx_for_task = evpn_events_tx.clone();
    tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::SubscribeRouteEvents { reply } => {
                    let _ = reply.send(route_events_tx.subscribe());
                }
                RibUpdate::SubscribeEvpnRouteEvents { reply } => {
                    let _ = reply.send(evpn_events_tx_for_task.subscribe());
                }
                RibUpdate::QueryEvpnRouteEventHistory { reply, .. } => {
                    let _ = reply.send(Vec::new());
                }
                _ => {}
            }
        }
    });
    (rib_tx, evpn_events_tx)
}

pub(crate) fn spawn_fake_peer_manager() -> (
    mpsc::Sender<PeerManagerCommand>,
    broadcast::Sender<SessionEvent>,
    broadcast::Sender<PolicyEvent>,
) {
    let (peer_tx, mut peer_rx) = mpsc::channel(16);
    let (session_events_tx, _) = broadcast::channel(16);
    let (policy_events_tx, _) = broadcast::channel(16);
    let session_events_tx_for_task = session_events_tx.clone();
    let policy_events_tx_for_task = policy_events_tx.clone();
    tokio::spawn(async move {
        while let Some(command) = peer_rx.recv().await {
            match command {
                PeerManagerCommand::SubscribeSessionEvents { reply } => {
                    let _ = reply.send(session_events_tx_for_task.subscribe());
                }
                PeerManagerCommand::SubscribePolicyEvents { reply } => {
                    let _ = reply.send(policy_events_tx_for_task.subscribe());
                }
                PeerManagerCommand::QueryPolicyEventHistory { reply, .. } => {
                    let _ = reply.send(Vec::new());
                }
                _ => {}
            }
        }
    });
    (peer_tx, session_events_tx, policy_events_tx)
}

pub(crate) fn spawn_fake_peer_manager_with_history(
    history: Vec<SessionLifecycleEvent>,
) -> mpsc::Sender<PeerManagerCommand> {
    let (peer_tx, mut peer_rx) = mpsc::channel(16);
    let (events_tx, _) = broadcast::channel(16);
    let history = Arc::new(history);
    tokio::spawn(async move {
        while let Some(command) = peer_rx.recv().await {
            match command {
                PeerManagerCommand::SubscribeSessionEvents { reply } => {
                    let _ = reply.send(events_tx.subscribe());
                }
                PeerManagerCommand::QuerySessionEventHistory {
                    peer,
                    event_types,
                    limit,
                    reply,
                } => {
                    let limit = if limit == 0 {
                        SESSION_EVENT_HISTORY_CAPACITY
                    } else {
                        limit.min(SESSION_EVENT_HISTORY_CAPACITY)
                    };
                    let mut events: Vec<_> = history
                        .iter()
                        .rev()
                        .filter(|event| match peer {
                            Some(peer) => event.peer == peer,
                            None => true,
                        })
                        .filter(|event| {
                            event_types.is_empty() || event_types.contains(&event.event_type)
                        })
                        .take(limit)
                        .cloned()
                        .collect();
                    events.reverse();
                    let _ = reply.send(events);
                }
                _ => {}
            }
        }
    });
    peer_tx
}

pub(crate) fn spawn_fake_peer_manager_with_policy_history(
    history: Vec<PolicyEvent>,
) -> mpsc::Sender<PeerManagerCommand> {
    let (peer_tx, mut peer_rx) = mpsc::channel(16);
    let (events_tx, _) = broadcast::channel(16);
    let history = Arc::new(history);
    tokio::spawn(async move {
        while let Some(command) = peer_rx.recv().await {
            match command {
                PeerManagerCommand::SubscribePolicyEvents { reply } => {
                    let _ = reply.send(events_tx.subscribe());
                }
                PeerManagerCommand::QueryPolicyEventHistory { peer, limit, reply } => {
                    let limit = if limit == 0 {
                        POLICY_EVENT_HISTORY_CAPACITY
                    } else {
                        limit.min(POLICY_EVENT_HISTORY_CAPACITY)
                    };
                    let mut events: Vec<_> = history
                        .iter()
                        .rev()
                        .filter(|event| match peer {
                            Some(peer) => event.peer == Some(peer),
                            None => true,
                        })
                        .take(limit)
                        .cloned()
                        .collect();
                    events.reverse();
                    let _ = reply.send(events);
                }
                _ => {}
            }
        }
    });
    peer_tx
}

pub(crate) fn session_event(peer: IpAddr, event_type: SessionLifecycleEventType) -> SessionEvent {
    SessionEvent::Lifecycle(lifecycle_event(peer, event_type))
}

pub(crate) fn lifecycle_event(
    peer: IpAddr,
    event_type: SessionLifecycleEventType,
) -> SessionLifecycleEvent {
    SessionLifecycleEvent {
        event_type,
        peer,
        peer_label: None,
        timestamp: "456".to_string(),
        old_state: Some(SessionState::OpenConfirm),
        new_state: Some(SessionState::Established),
        session_role: Some("primary".to_string()),
        reason: format!("session event for peer {peer}"),
    }
}

pub(crate) fn notification_event(
    peer: IpAddr,
    event_type: SessionNotificationEventType,
) -> SessionEvent {
    SessionEvent::Notification(SessionNotificationEvent {
        event_type,
        peer,
        timestamp: "789".to_string(),
        code: 6,
        subcode: 7,
        description: "Connection Collision Resolution".to_string(),
        session_role: Some("primary".to_string()),
        shutdown_reason: None,
        reason: format!(
            "BGP NOTIFICATION sent for peer {peer}: 6/7 (Connection Collision Resolution)"
        ),
    })
}

pub(crate) fn policy_event(peer: Option<IpAddr>) -> PolicyEvent {
    PolicyEvent {
        operation: "set",
        target_type: "policy",
        target: "audit-policy".to_string(),
        peer,
        affected_peer_count: 2,
        timestamp: "789".to_string(),
        reason: "policy set policy audit-policy".to_string(),
    }
}

pub(crate) fn fib_status(state: proto::FibRouteState) -> proto::FibRouteStatus {
    proto::FibRouteStatus {
        table_name: "blue".to_string(),
        table_id: 100,
        metric: 20,
        prefix: "203.0.113.0".to_string(),
        prefix_length: 24,
        next_hop: "192.0.2.1".to_string(),
        peer_address: "10.0.0.1".to_string(),
        state: state as i32,
        reason: "test".to_string(),
        ..Default::default()
    }
}

pub(crate) fn dataplane_route_event(
    event_type: proto::BgpEventType,
    prefix: &str,
    prefix_length: u32,
    peer_address: &str,
) -> proto::BgpEvent {
    let action = match event_type {
        proto::BgpEventType::DataplaneRouteInstalled => "installed",
        proto::BgpEventType::DataplaneRouteWithdrawn => "withdrawn",
        proto::BgpEventType::DataplaneRouteFailed => "failed",
        _ => "unknown",
    };
    proto::BgpEvent {
        timestamp: "123".to_string(),
        category: proto::EventCategory::Dataplane as i32,
        event_type: event_type as i32,
        severity: proto::EventSeverity::Info as i32,
        peer_address: peer_address.to_string(),
        previous_peer_address: String::new(),
        prefix: prefix.to_string(),
        prefix_length,
        afi_safi: if prefix.contains(':') {
            proto::AddressFamily::Ipv6Unicast as i32
        } else {
            proto::AddressFamily::Ipv4Unicast as i32
        },
        summary: format!("dataplane fib route {action} {prefix}/{prefix_length}"),
        target_peer_address: String::new(),
        event_id: None,
        payload: Some(proto::bgp_event::Payload::DataplaneRoute(
            proto::DataplaneRouteEvent {
                source: "fib".to_string(),
                action: action.to_string(),
                table_name: "blue".to_string(),
                table_id: 100,
                metric: 20,
                prefix: prefix.to_string(),
                prefix_length,
                next_hop: "192.0.2.1".to_string(),
                peer_address: peer_address.to_string(),
                timestamp: "123".to_string(),
                reason: action.to_string(),
            },
        )),
    }
}

pub(crate) fn blackhole_status(state: proto::BlackholeDiscardState) -> proto::BlackholeDiscard {
    proto::BlackholeDiscard {
        prefix: "198.51.100.1".to_string(),
        prefix_length: 32,
        peer_address: "10.0.0.2".to_string(),
        state: state as i32,
        reason: "test".to_string(),
    }
}
