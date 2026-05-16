//! Unified live event stream service.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::pin::Pin;

use tokio::sync::oneshot;
use tokio_stream::Stream;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::{BroadcastStream, errors::BroadcastStreamRecvError};
use tonic::{Request, Response, Status};
use tracing::debug;

use crate::peer_types::{
    PeerManagerCommand, SessionEvent, SessionLifecycleEvent, SessionLifecycleEventType,
    SessionNotificationEvent, SessionNotificationEventType,
};
use crate::proto;
use crate::rib_service::{
    parse_route_event_prefix_filter, route_event_afi_filter, route_event_to_proto,
};
use rustbgpd_rib::{RibUpdate, RouteEventType};
use rustbgpd_wire::{Afi, Prefix};

/// gRPC service exposing a unified live daemon event stream.
#[derive(Clone)]
pub struct EventService {
    rib_tx: tokio::sync::mpsc::Sender<RibUpdate>,
    peer_mgr_tx: tokio::sync::mpsc::Sender<PeerManagerCommand>,
}

impl EventService {
    #[must_use]
    pub fn new(
        rib_tx: tokio::sync::mpsc::Sender<RibUpdate>,
        peer_mgr_tx: tokio::sync::mpsc::Sender<PeerManagerCommand>,
    ) -> Self {
        Self {
            rib_tx,
            peer_mgr_tx,
        }
    }
}

#[derive(Clone)]
struct WatchEventsFilter {
    categories: BTreeSet<i32>,
    event_types: BTreeSet<i32>,
    peer: Option<IpAddr>,
    afi: Option<Afi>,
    prefix: Option<Prefix>,
}

impl WatchEventsFilter {
    fn matches_route_event(&self, event: &rustbgpd_rib::RouteEvent) -> bool {
        if !self.wants_route_events() {
            return false;
        }

        let event_type = route_event_type_to_bgp_event_type(event.event_type);
        if !self.event_types.is_empty() && !self.event_types.contains(&(event_type as i32)) {
            return false;
        }

        if let Some(afi) = self.afi {
            match (afi, event.prefix) {
                (Afi::Ipv4, Prefix::V4(_)) | (Afi::Ipv6, Prefix::V6(_)) => {}
                _ => return false,
            }
        }

        if let Some(peer) = self.peer {
            let matches_current = event.peer == Some(peer);
            let matches_previous = event.previous_peer == Some(peer);
            if !matches_current && !matches_previous {
                return false;
            }
        }

        if let Some(prefix) = self.prefix
            && event.prefix != prefix
        {
            return false;
        }

        true
    }

    fn wants_route_events(&self) -> bool {
        (self.categories.is_empty()
            || self
                .categories
                .contains(&(proto::EventCategory::Route as i32)))
            && self.event_types_match_route_category()
    }

    fn wants_session_events(&self) -> bool {
        (self.categories.is_empty()
            || self
                .categories
                .contains(&(proto::EventCategory::Session as i32)))
            && self.afi.is_none()
            && self.prefix.is_none()
            && self.event_types_match_session_category()
    }

    fn matches_session_event(&self, event: &SessionEvent) -> bool {
        if !self.wants_session_events() {
            return false;
        }

        let (event_type, event_peer) = match event {
            SessionEvent::Lifecycle(event) => (
                session_lifecycle_event_type_to_bgp_event_type(event.event_type),
                event.peer,
            ),
            SessionEvent::Notification(event) => (
                session_notification_event_type_to_bgp_event_type(event.event_type),
                event.peer,
            ),
        };
        if !self.event_types.is_empty() && !self.event_types.contains(&(event_type as i32)) {
            return false;
        }

        if let Some(peer) = self.peer
            && event_peer != peer
        {
            return false;
        }

        true
    }

    fn event_types_match_route_category(&self) -> bool {
        self.event_types.is_empty()
            || self.event_types.iter().any(|event_type| {
                matches!(
                    proto::BgpEventType::try_from(*event_type),
                    Ok(proto::BgpEventType::RouteAdded
                        | proto::BgpEventType::RouteWithdrawn
                        | proto::BgpEventType::RouteBestChanged
                        | proto::BgpEventType::StreamLagged)
                )
            })
    }

    fn event_types_match_session_category(&self) -> bool {
        self.event_types.is_empty()
            || self.event_types.iter().any(|event_type| {
                matches!(
                    proto::BgpEventType::try_from(*event_type),
                    Ok(proto::BgpEventType::SessionStateChanged
                        | proto::BgpEventType::SessionEstablished
                        | proto::BgpEventType::SessionLost
                        | proto::BgpEventType::PeerEnabled
                        | proto::BgpEventType::PeerDisabled
                        | proto::BgpEventType::NotificationSent
                        | proto::BgpEventType::NotificationReceived
                        | proto::BgpEventType::StreamLagged)
                )
            })
    }
}

fn route_event_type_to_bgp_event_type(event_type: RouteEventType) -> proto::BgpEventType {
    match event_type {
        RouteEventType::Added => proto::BgpEventType::RouteAdded,
        RouteEventType::Withdrawn => proto::BgpEventType::RouteWithdrawn,
        RouteEventType::BestChanged => proto::BgpEventType::RouteBestChanged,
    }
}

fn parse_category_filter(categories: &[i32]) -> Result<BTreeSet<i32>, Status> {
    let mut parsed = BTreeSet::new();
    for category in categories {
        let category = proto::EventCategory::try_from(*category)
            .map_err(|_| Status::invalid_argument("unknown event category"))?;
        match category {
            proto::EventCategory::Route | proto::EventCategory::Session => {
                parsed.insert(category as i32);
            }
            proto::EventCategory::Unspecified => {
                return Err(Status::invalid_argument(
                    "EVENT_CATEGORY_UNSPECIFIED is not a valid filter",
                ));
            }
            proto::EventCategory::Policy | proto::EventCategory::Dataplane => {
                return Err(Status::invalid_argument(
                    "only EVENT_CATEGORY_ROUTE and EVENT_CATEGORY_SESSION are supported by WatchEvents in this release",
                ));
            }
        }
    }
    Ok(parsed)
}

fn parse_event_type_filter(event_types: &[i32]) -> Result<BTreeSet<i32>, Status> {
    let mut parsed = BTreeSet::new();
    for event_type in event_types {
        let event_type = proto::BgpEventType::try_from(*event_type)
            .map_err(|_| Status::invalid_argument("unknown event type"))?;
        match event_type {
            proto::BgpEventType::RouteAdded
            | proto::BgpEventType::RouteWithdrawn
            | proto::BgpEventType::RouteBestChanged
            | proto::BgpEventType::SessionStateChanged
            | proto::BgpEventType::SessionEstablished
            | proto::BgpEventType::SessionLost
            | proto::BgpEventType::PeerEnabled
            | proto::BgpEventType::PeerDisabled
            | proto::BgpEventType::NotificationSent
            | proto::BgpEventType::NotificationReceived
            | proto::BgpEventType::StreamLagged => {
                parsed.insert(event_type as i32);
            }
            proto::BgpEventType::Unspecified => {
                return Err(Status::invalid_argument(
                    "BGP_EVENT_TYPE_UNSPECIFIED is not a valid filter",
                ));
            }
        }
    }
    Ok(parsed)
}

fn session_lifecycle_event_type_to_bgp_event_type(
    event_type: SessionLifecycleEventType,
) -> proto::BgpEventType {
    match event_type {
        SessionLifecycleEventType::StateChanged => proto::BgpEventType::SessionStateChanged,
        SessionLifecycleEventType::Established => proto::BgpEventType::SessionEstablished,
        SessionLifecycleEventType::Lost => proto::BgpEventType::SessionLost,
        SessionLifecycleEventType::PeerEnabled => proto::BgpEventType::PeerEnabled,
        SessionLifecycleEventType::PeerDisabled => proto::BgpEventType::PeerDisabled,
    }
}

fn session_notification_event_type_to_bgp_event_type(
    event_type: SessionNotificationEventType,
) -> proto::BgpEventType {
    match event_type {
        SessionNotificationEventType::Sent => proto::BgpEventType::NotificationSent,
        SessionNotificationEventType::Received => proto::BgpEventType::NotificationReceived,
    }
}

fn parse_watch_events_filter(req: &proto::WatchEventsRequest) -> Result<WatchEventsFilter, Status> {
    let categories = parse_category_filter(&req.categories)?;
    let event_types = parse_event_type_filter(&req.event_types)?;
    let afi = route_event_afi_filter(req.afi_safi)?;
    let prefix = parse_route_event_prefix_filter(&req.prefix, req.prefix_length, afi)?;
    let peer = if req.neighbor_address.is_empty() {
        None
    } else {
        Some(
            req.neighbor_address
                .parse::<IpAddr>()
                .map_err(|e| Status::invalid_argument(format!("invalid address: {e}")))?,
        )
    };

    Ok(WatchEventsFilter {
        categories,
        event_types,
        peer,
        afi,
        prefix,
    })
}

fn route_event_to_bgp_event(event: rustbgpd_rib::RouteEvent) -> proto::BgpEvent {
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

fn session_event_to_bgp_event(event: SessionEvent) -> proto::BgpEvent {
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

fn stream_lag_bgp_event(
    source_category: proto::EventCategory,
    missed_count: u64,
) -> proto::BgpEvent {
    let source = match source_category {
        proto::EventCategory::Route => "route",
        proto::EventCategory::Session => "session",
        proto::EventCategory::Policy
        | proto::EventCategory::Dataplane
        | proto::EventCategory::Unspecified => "unknown",
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

#[tonic::async_trait]
impl proto::event_service_server::EventService for EventService {
    type WatchEventsStream =
        Pin<Box<dyn Stream<Item = Result<proto::BgpEvent, Status>> + Send + 'static>>;

    async fn watch_events(
        &self,
        request: Request<proto::WatchEventsRequest>,
    ) -> Result<Response<Self::WatchEventsStream>, Status> {
        let req = request.into_inner();
        let filter = parse_watch_events_filter(&req)?;

        let route_stream: Pin<Box<dyn Stream<Item = Result<proto::BgpEvent, Status>> + Send>> =
            if filter.wants_route_events() {
                let (reply_tx, reply_rx) = oneshot::channel();
                self.rib_tx
                    .send(RibUpdate::SubscribeRouteEvents { reply: reply_tx })
                    .await
                    .map_err(|_| Status::internal("RIB manager unavailable"))?;
                let broadcast_rx = reply_rx
                    .await
                    .map_err(|_| Status::internal("RIB manager dropped reply"))?;
                let route_filter = filter.clone();
                Box::pin(BroadcastStream::new(broadcast_rx).filter_map(
                    move |result| match result {
                        Ok(event) => {
                            if route_filter.matches_route_event(&event) {
                                Some(Ok(route_event_to_bgp_event(event)))
                            } else {
                                None
                            }
                        }
                        Err(BroadcastStreamRecvError::Lagged(missed)) => {
                            debug!(
                                missed,
                                "WatchEvents route subscriber lagged, emitting missed-event signal"
                            );
                            Some(Ok(stream_lag_bgp_event(
                                proto::EventCategory::Route,
                                missed,
                            )))
                        }
                    },
                ))
            } else {
                Box::pin(tokio_stream::empty())
            };

        let session_stream: Pin<Box<dyn Stream<Item = Result<proto::BgpEvent, Status>> + Send>> =
            if filter.wants_session_events() {
                let (reply_tx, reply_rx) = oneshot::channel();
                self.peer_mgr_tx
                    .send(PeerManagerCommand::SubscribeSessionEvents { reply: reply_tx })
                    .await
                    .map_err(|_| Status::internal("peer manager unavailable"))?;
                let broadcast_rx = reply_rx
                    .await
                    .map_err(|_| Status::internal("peer manager dropped reply"))?;
                let session_filter = filter.clone();
                Box::pin(BroadcastStream::new(broadcast_rx).filter_map(
                    move |result| match result {
                        Ok(event) => {
                            if session_filter.matches_session_event(&event) {
                                Some(Ok(session_event_to_bgp_event(event)))
                            } else {
                                None
                            }
                        }
                        Err(BroadcastStreamRecvError::Lagged(missed)) => {
                            debug!(
                                missed,
                                "WatchEvents session subscriber lagged, emitting missed-event signal"
                            );
                            Some(Ok(stream_lag_bgp_event(
                                proto::EventCategory::Session,
                                missed,
                            )))
                        }
                    },
                ))
            } else {
                Box::pin(tokio_stream::empty())
            };

        Ok(Response::new(Box::pin(route_stream.merge(session_stream))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::event_service_server::EventService as EventServiceTrait;
    use rustbgpd_fsm::SessionState;
    use rustbgpd_rib::RouteEvent;
    use rustbgpd_wire::{Ipv4Prefix, Ipv6Prefix};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use tokio::sync::{broadcast, mpsc};
    use tokio_stream::StreamExt;

    fn route_event(prefix: Prefix, peer: IpAddr) -> RouteEvent {
        RouteEvent {
            event_type: RouteEventType::Added,
            prefix,
            peer: Some(peer),
            previous_peer: None,
            timestamp: "123".to_string(),
            path_id: 7,
        }
    }

    fn spawn_fake_rib() -> (mpsc::Sender<RibUpdate>, broadcast::Sender<RouteEvent>) {
        let (rib_tx, mut rib_rx) = mpsc::channel(16);
        let (events_tx, _) = broadcast::channel(16);
        let events_tx_for_task = events_tx.clone();
        tokio::spawn(async move {
            while let Some(update) = rib_rx.recv().await {
                if let RibUpdate::SubscribeRouteEvents { reply } = update {
                    let _ = reply.send(events_tx_for_task.subscribe());
                }
            }
        });
        (rib_tx, events_tx)
    }

    fn spawn_fake_peer_manager() -> (
        mpsc::Sender<PeerManagerCommand>,
        broadcast::Sender<SessionEvent>,
    ) {
        let (peer_tx, mut peer_rx) = mpsc::channel(16);
        let (events_tx, _) = broadcast::channel(16);
        let events_tx_for_task = events_tx.clone();
        tokio::spawn(async move {
            while let Some(command) = peer_rx.recv().await {
                if let PeerManagerCommand::SubscribeSessionEvents { reply } = command {
                    let _ = reply.send(events_tx_for_task.subscribe());
                }
            }
        });
        (peer_tx, events_tx)
    }

    fn session_event(peer: IpAddr, event_type: SessionLifecycleEventType) -> SessionEvent {
        SessionEvent::Lifecycle(SessionLifecycleEvent {
            event_type,
            peer,
            timestamp: "456".to_string(),
            old_state: Some(SessionState::OpenConfirm),
            new_state: Some(SessionState::Established),
            session_role: Some("primary".to_string()),
            reason: format!("session event for peer {peer}"),
        })
    }

    fn notification_event(peer: IpAddr, event_type: SessionNotificationEventType) -> SessionEvent {
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

    #[tokio::test]
    async fn route_event_bridge_emits_bgp_event() {
        let (rib_tx, events_tx) = spawn_fake_rib();
        let (peer_tx, _) = spawn_fake_peer_manager();
        let service = EventService::new(rib_tx, peer_tx);
        let response = service
            .watch_events(Request::new(proto::WatchEventsRequest::default()))
            .await
            .unwrap();
        let mut stream = response.into_inner();

        events_tx
            .send(route_event(
                Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            ))
            .unwrap();

        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.category, proto::EventCategory::Route as i32);
        assert_eq!(event.event_type, proto::BgpEventType::RouteAdded as i32);
        assert_eq!(event.severity, proto::EventSeverity::Info as i32);
        assert_eq!(event.prefix, "203.0.113.0");
        assert_eq!(event.prefix_length, 24);
        assert!(matches!(
            event.payload,
            Some(proto::bgp_event::Payload::Route(_))
        ));
    }

    #[tokio::test]
    async fn filters_compose_for_route_events() {
        let (rib_tx, events_tx) = spawn_fake_rib();
        let (peer_tx, _) = spawn_fake_peer_manager();
        let service = EventService::new(rib_tx, peer_tx);
        let response = service
            .watch_events(Request::new(proto::WatchEventsRequest {
                categories: vec![proto::EventCategory::Route as i32],
                event_types: vec![proto::BgpEventType::RouteAdded as i32],
                neighbor_address: "10.0.0.1".to_string(),
                afi_safi: proto::AddressFamily::Ipv4Unicast as i32,
                prefix: "203.0.113.0".to_string(),
                prefix_length: 24,
            }))
            .await
            .unwrap();
        let mut stream = response.into_inner();

        events_tx
            .send(route_event(
                Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            ))
            .unwrap();
        events_tx
            .send(route_event(
                Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            ))
            .unwrap();
        events_tx
            .send(route_event(
                Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            ))
            .unwrap();

        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.prefix, "203.0.113.0");
        assert_eq!(event.peer_address, "10.0.0.1");
    }

    #[tokio::test]
    async fn route_and_session_category_filters_do_not_cross_match() {
        let (rib_tx, _) = spawn_fake_rib();
        let (peer_tx, session_events_tx) = spawn_fake_peer_manager();
        let service = EventService::new(rib_tx, peer_tx);
        let response = service
            .watch_events(Request::new(proto::WatchEventsRequest {
                categories: vec![proto::EventCategory::Session as i32],
                event_types: vec![proto::BgpEventType::SessionEstablished as i32],
                neighbor_address: "10.0.0.1".to_string(),
                ..Default::default()
            }))
            .await
            .unwrap();
        let mut stream = response.into_inner();

        session_events_tx
            .send(session_event(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                SessionLifecycleEventType::Established,
            ))
            .unwrap();
        session_events_tx
            .send(session_event(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                SessionLifecycleEventType::Established,
            ))
            .unwrap();

        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.category, proto::EventCategory::Session as i32);
        assert_eq!(
            event.event_type,
            proto::BgpEventType::SessionEstablished as i32
        );
        assert_eq!(event.peer_address, "10.0.0.1");
        assert!(matches!(
            event.payload,
            Some(proto::bgp_event::Payload::Session(_))
        ));
    }

    #[tokio::test]
    async fn notification_event_bridge_emits_bgp_event() {
        let (rib_tx, _) = spawn_fake_rib();
        let (peer_tx, session_events_tx) = spawn_fake_peer_manager();
        let service = EventService::new(rib_tx, peer_tx);
        let response = service
            .watch_events(Request::new(proto::WatchEventsRequest {
                categories: vec![proto::EventCategory::Session as i32],
                event_types: vec![proto::BgpEventType::NotificationSent as i32],
                neighbor_address: "10.0.0.1".to_string(),
                ..Default::default()
            }))
            .await
            .unwrap();
        let mut stream = response.into_inner();

        session_events_tx
            .send(notification_event(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                SessionNotificationEventType::Sent,
            ))
            .unwrap();
        session_events_tx
            .send(notification_event(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                SessionNotificationEventType::Sent,
            ))
            .unwrap();

        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.category, proto::EventCategory::Session as i32);
        assert_eq!(
            event.event_type,
            proto::BgpEventType::NotificationSent as i32
        );
        assert_eq!(event.severity, proto::EventSeverity::Warning as i32);
        assert_eq!(event.peer_address, "10.0.0.1");
        let Some(proto::bgp_event::Payload::Notification(notification)) = event.payload else {
            panic!("expected notification payload");
        };
        assert_eq!(notification.direction, "sent");
        assert_eq!(notification.code, 6);
        assert_eq!(notification.subcode, 7);
        assert_eq!(notification.description, "Connection Collision Resolution");
    }

    #[tokio::test]
    async fn prefix_filter_does_not_match_session_events() {
        let (rib_tx, _) = spawn_fake_rib();
        let (peer_tx, session_events_tx) = spawn_fake_peer_manager();
        let service = EventService::new(rib_tx, peer_tx);
        let response = service
            .watch_events(Request::new(proto::WatchEventsRequest {
                categories: vec![proto::EventCategory::Session as i32],
                prefix: "203.0.113.0".to_string(),
                prefix_length: 24,
                ..Default::default()
            }))
            .await
            .unwrap();
        let mut stream = response.into_inner();
        assert_eq!(session_events_tx.receiver_count(), 0);
        assert!(
            session_events_tx
                .send(session_event(
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    SessionLifecycleEventType::Established,
                ))
                .is_err()
        );
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn route_event_type_filter_does_not_subscribe_session_events() {
        let (rib_tx, events_tx) = spawn_fake_rib();
        let (peer_tx, session_events_tx) = spawn_fake_peer_manager();
        let service = EventService::new(rib_tx, peer_tx);
        let response = service
            .watch_events(Request::new(proto::WatchEventsRequest {
                event_types: vec![proto::BgpEventType::RouteAdded as i32],
                ..Default::default()
            }))
            .await
            .unwrap();

        assert_eq!(events_tx.receiver_count(), 1);
        assert_eq!(session_events_tx.receiver_count(), 0);
        drop(response);
    }

    #[tokio::test]
    async fn session_event_type_filter_does_not_subscribe_route_events() {
        let (rib_tx, events_tx) = spawn_fake_rib();
        let (peer_tx, session_events_tx) = spawn_fake_peer_manager();
        let service = EventService::new(rib_tx, peer_tx);
        let response = service
            .watch_events(Request::new(proto::WatchEventsRequest {
                event_types: vec![proto::BgpEventType::SessionEstablished as i32],
                ..Default::default()
            }))
            .await
            .unwrap();

        assert_eq!(events_tx.receiver_count(), 0);
        assert_eq!(session_events_tx.receiver_count(), 1);
        drop(response);
    }

    #[tokio::test]
    async fn rejects_unsupported_category_filter() {
        let (rib_tx, _) = spawn_fake_rib();
        let (peer_tx, _) = spawn_fake_peer_manager();
        let service = EventService::new(rib_tx, peer_tx);
        let Err(err) = service
            .watch_events(Request::new(proto::WatchEventsRequest {
                categories: vec![proto::EventCategory::Policy as i32],
                ..Default::default()
            }))
            .await
        else {
            panic!("unsupported category filter should fail");
        };
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn subscriber_drop_releases_broadcast_receiver() {
        let (rib_tx, events_tx) = spawn_fake_rib();
        let (peer_tx, _) = spawn_fake_peer_manager();
        let service = EventService::new(rib_tx, peer_tx);
        let response = service
            .watch_events(Request::new(proto::WatchEventsRequest::default()))
            .await
            .unwrap();
        assert_eq!(events_tx.receiver_count(), 1);
        drop(response);
        tokio::task::yield_now().await;
        assert_eq!(events_tx.receiver_count(), 0);
    }

    #[tokio::test]
    async fn route_lag_emits_missed_event_signal() {
        let (rib_tx, events_tx) = spawn_fake_rib();
        let (peer_tx, _) = spawn_fake_peer_manager();
        let service = EventService::new(rib_tx, peer_tx);
        let response = service
            .watch_events(Request::new(proto::WatchEventsRequest {
                categories: vec![proto::EventCategory::Route as i32],
                event_types: vec![proto::BgpEventType::RouteAdded as i32],
                ..Default::default()
            }))
            .await
            .unwrap();
        let mut stream = response.into_inner();

        for i in 0..32 {
            events_tx
                .send(route_event(
                    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, i), 32)),
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                ))
                .unwrap();
        }

        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.category, proto::EventCategory::Route as i32);
        assert_eq!(event.event_type, proto::BgpEventType::StreamLagged as i32);
        assert_eq!(event.severity, proto::EventSeverity::Warning as i32);
        let Some(proto::bgp_event::Payload::StreamLag(lag)) = event.payload else {
            panic!("expected stream lag payload");
        };
        assert_eq!(lag.source_category, proto::EventCategory::Route as i32);
        assert!(lag.missed_count > 0);
    }

    #[tokio::test]
    async fn session_lag_emits_missed_event_signal() {
        let (rib_tx, _) = spawn_fake_rib();
        let (peer_tx, session_events_tx) = spawn_fake_peer_manager();
        let service = EventService::new(rib_tx, peer_tx);
        let response = service
            .watch_events(Request::new(proto::WatchEventsRequest {
                categories: vec![proto::EventCategory::Session as i32],
                event_types: vec![proto::BgpEventType::SessionEstablished as i32],
                ..Default::default()
            }))
            .await
            .unwrap();
        let mut stream = response.into_inner();

        for _ in 0..32 {
            session_events_tx
                .send(session_event(
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    SessionLifecycleEventType::Established,
                ))
                .unwrap();
        }

        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.category, proto::EventCategory::Session as i32);
        assert_eq!(event.event_type, proto::BgpEventType::StreamLagged as i32);
        assert_eq!(event.severity, proto::EventSeverity::Warning as i32);
        let Some(proto::bgp_event::Payload::StreamLag(lag)) = event.payload else {
            panic!("expected stream lag payload");
        };
        assert_eq!(lag.source_category, proto::EventCategory::Session as i32);
        assert!(lag.missed_count > 0);
    }

    #[test]
    fn v6_prefix_filter_matches_only_v6() {
        let filter = parse_watch_events_filter(&proto::WatchEventsRequest {
            afi_safi: proto::AddressFamily::Ipv6Unicast as i32,
            prefix: "2001:db8::".to_string(),
            prefix_length: 64,
            ..Default::default()
        })
        .unwrap();
        let event = route_event(
            Prefix::V6(Ipv6Prefix::new(Ipv6Addr::LOCALHOST, 128)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        );
        assert!(!filter.matches_route_event(&event));
    }
}
