//! Unified live event stream service.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::{broadcast, oneshot};
use tokio_stream::Stream;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::{BroadcastStream, errors::BroadcastStreamRecvError};
use tonic::{Request, Response, Status};
use tracing::debug;

use crate::peer_types::{
    PeerManagerCommand, PolicyEvent, SessionEvent, SessionLifecycleEvent,
    SessionLifecycleEventType, SessionNotificationEvent, SessionNotificationEventType,
};
use crate::proto;
use crate::rib_service::{
    BlackholeDiscardSnapshotFn, FibRouteSnapshotFn, parse_route_event_prefix_filter,
    route_event_afi_filter, route_event_to_proto,
};
use rustbgpd_rib::{RibUpdate, RouteEventType};
use rustbgpd_wire::{Afi, Prefix};

#[cfg(not(test))]
const DATAPLANE_EVENT_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
#[cfg(test)]
const DATAPLANE_EVENT_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(10);

/// gRPC service exposing a unified live daemon event stream.
#[derive(Clone)]
pub struct EventService {
    rib_tx: tokio::sync::mpsc::Sender<RibUpdate>,
    peer_mgr_tx: tokio::sync::mpsc::Sender<PeerManagerCommand>,
    blackhole_discard_snapshot: BlackholeDiscardSnapshotFn,
    fib_route_snapshot: FibRouteSnapshotFn,
    dataplane_events: Arc<Mutex<Option<broadcast::Sender<proto::BgpEvent>>>>,
}

impl EventService {
    #[allow(dead_code)]
    #[must_use]
    pub fn new(
        rib_tx: tokio::sync::mpsc::Sender<RibUpdate>,
        peer_mgr_tx: tokio::sync::mpsc::Sender<PeerManagerCommand>,
    ) -> Self {
        Self::with_dataplane_snapshots(
            rib_tx,
            peer_mgr_tx,
            std::sync::Arc::new(Vec::new),
            std::sync::Arc::new(Vec::new),
        )
    }

    #[must_use]
    pub fn with_dataplane_snapshots(
        rib_tx: tokio::sync::mpsc::Sender<RibUpdate>,
        peer_mgr_tx: tokio::sync::mpsc::Sender<PeerManagerCommand>,
        blackhole_discard_snapshot: BlackholeDiscardSnapshotFn,
        fib_route_snapshot: FibRouteSnapshotFn,
    ) -> Self {
        Self {
            rib_tx,
            peer_mgr_tx,
            blackhole_discard_snapshot,
            fib_route_snapshot,
            dataplane_events: Arc::new(Mutex::new(None)),
        }
    }

    fn subscribe_dataplane_events(&self) -> broadcast::Receiver<proto::BgpEvent> {
        let mut guard = self
            .dataplane_events
            .lock()
            .expect("dataplane event broadcaster mutex poisoned");
        if let Some(tx) = guard.as_ref() {
            return tx.subscribe();
        }

        let (tx, rx) = broadcast::channel(16);
        *guard = Some(tx.clone());
        drop(guard);

        spawn_dataplane_poller(
            tx,
            self.dataplane_events.clone(),
            self.blackhole_discard_snapshot.clone(),
            self.fib_route_snapshot.clone(),
        );
        rx
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

    fn wants_policy_events(&self) -> bool {
        let policy_category_requested = self
            .categories
            .contains(&(proto::EventCategory::Policy as i32));
        let policy_type_allowed = self.event_types_match_policy_category();
        let policy_selected = policy_category_requested
            || (self.categories.is_empty() && !self.event_types.is_empty() && policy_type_allowed);
        policy_selected && self.afi.is_none() && self.prefix.is_none() && policy_type_allowed
    }

    fn wants_dataplane_events(&self) -> bool {
        let dataplane_category_requested = self
            .categories
            .contains(&(proto::EventCategory::Dataplane as i32));
        let dataplane_type_allowed = self.event_types_match_dataplane_category();
        let dataplane_selected = dataplane_category_requested
            || (self.categories.is_empty()
                && !self.event_types.is_empty()
                && dataplane_type_allowed);
        dataplane_selected
            && self.peer.is_none()
            && self.afi.is_none()
            && self.prefix.is_none()
            && dataplane_type_allowed
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

    fn matches_policy_event(&self, event: &PolicyEvent) -> bool {
        if !self.wants_policy_events() {
            return false;
        }

        if !self.event_types.is_empty()
            && !self
                .event_types
                .contains(&(proto::BgpEventType::PolicyChanged as i32))
        {
            return false;
        }

        if let Some(peer) = self.peer
            && event.peer != Some(peer)
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

    fn event_types_match_policy_category(&self) -> bool {
        self.event_types.is_empty()
            || self.event_types.iter().any(|event_type| {
                matches!(
                    proto::BgpEventType::try_from(*event_type),
                    Ok(proto::BgpEventType::PolicyChanged)
                )
            })
    }

    fn event_types_match_dataplane_category(&self) -> bool {
        self.event_types.is_empty()
            || self.event_types.iter().any(|event_type| {
                matches!(
                    proto::BgpEventType::try_from(*event_type),
                    Ok(proto::BgpEventType::DataplaneStatusChanged)
                )
            })
    }
}

struct SessionEventHistoryFilter {
    peer: Option<IpAddr>,
    event_types: BTreeSet<SessionLifecycleEventType>,
    limit: usize,
}

fn route_event_type_to_bgp_event_type(event_type: RouteEventType) -> proto::BgpEventType {
    match event_type {
        RouteEventType::Added => proto::BgpEventType::RouteAdded,
        RouteEventType::Withdrawn => proto::BgpEventType::RouteWithdrawn,
        RouteEventType::BestChanged => proto::BgpEventType::RouteBestChanged,
    }
}

fn bgp_event_type_to_session_event_type(
    event_type: proto::BgpEventType,
) -> Option<SessionLifecycleEventType> {
    match event_type {
        proto::BgpEventType::SessionStateChanged => Some(SessionLifecycleEventType::StateChanged),
        proto::BgpEventType::SessionEstablished => Some(SessionLifecycleEventType::Established),
        proto::BgpEventType::SessionLost => Some(SessionLifecycleEventType::Lost),
        proto::BgpEventType::PeerEnabled => Some(SessionLifecycleEventType::PeerEnabled),
        proto::BgpEventType::PeerDisabled => Some(SessionLifecycleEventType::PeerDisabled),
        proto::BgpEventType::Unspecified
        | proto::BgpEventType::RouteAdded
        | proto::BgpEventType::RouteWithdrawn
        | proto::BgpEventType::RouteBestChanged
        | proto::BgpEventType::NotificationSent
        | proto::BgpEventType::NotificationReceived
        | proto::BgpEventType::PolicyChanged
        | proto::BgpEventType::DataplaneStatusChanged
        | proto::BgpEventType::StreamLagged => None,
    }
}

fn parse_category_filter(categories: &[i32]) -> Result<BTreeSet<i32>, Status> {
    let mut parsed = BTreeSet::new();
    for category in categories {
        let category = proto::EventCategory::try_from(*category)
            .map_err(|_| Status::invalid_argument("unknown event category"))?;
        match category {
            proto::EventCategory::Route
            | proto::EventCategory::Session
            | proto::EventCategory::Policy
            | proto::EventCategory::Dataplane => {
                parsed.insert(category as i32);
            }
            proto::EventCategory::Unspecified => {
                return Err(Status::invalid_argument(
                    "EVENT_CATEGORY_UNSPECIFIED is not a valid filter",
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
            | proto::BgpEventType::PolicyChanged
            | proto::BgpEventType::DataplaneStatusChanged
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

fn parse_session_event_type_filter(
    event_types: &[i32],
) -> Result<BTreeSet<SessionLifecycleEventType>, Status> {
    let mut parsed = BTreeSet::new();
    for event_type in event_types {
        let event_type = proto::BgpEventType::try_from(*event_type)
            .map_err(|_| Status::invalid_argument("unknown event type"))?;
        if event_type == proto::BgpEventType::Unspecified {
            return Err(Status::invalid_argument(
                "BGP_EVENT_TYPE_UNSPECIFIED is not a valid filter",
            ));
        }
        let Some(session_type) = bgp_event_type_to_session_event_type(event_type) else {
            return Err(Status::invalid_argument(
                "ListSessionEvents only supports session event types",
            ));
        };
        parsed.insert(session_type);
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DataplaneSummary {
    source: &'static str,
    installed: u64,
    rejected: u64,
    failed: u64,
}

impl DataplaneSummary {
    fn changed_from(self, previous: Self) -> bool {
        self.installed != previous.installed
            || self.rejected != previous.rejected
            || self.failed != previous.failed
    }
}

fn count_blackhole_statuses(rows: &[proto::BlackholeDiscard]) -> DataplaneSummary {
    let mut summary = DataplaneSummary {
        source: "blackhole",
        installed: 0,
        rejected: 0,
        failed: 0,
    };
    for row in rows {
        match proto::BlackholeDiscardState::try_from(row.state) {
            Ok(proto::BlackholeDiscardState::Installed) => summary.installed += 1,
            Ok(proto::BlackholeDiscardState::Rejected) => summary.rejected += 1,
            Ok(proto::BlackholeDiscardState::Failed) => summary.failed += 1,
            Ok(proto::BlackholeDiscardState::Unspecified) | Err(_) => {}
        }
    }
    summary
}

fn count_fib_statuses(rows: &[proto::FibRouteStatus]) -> DataplaneSummary {
    let mut summary = DataplaneSummary {
        source: "fib",
        installed: 0,
        rejected: 0,
        failed: 0,
    };
    for row in rows {
        match proto::FibRouteState::try_from(row.state) {
            Ok(proto::FibRouteState::Installed) => summary.installed += 1,
            Ok(proto::FibRouteState::Rejected) => summary.rejected += 1,
            Ok(proto::FibRouteState::Failed) => summary.failed += 1,
            Ok(proto::FibRouteState::Unspecified) | Err(_) => {}
        }
    }
    summary
}

fn dataplane_summaries(
    blackholes: &[proto::BlackholeDiscard],
    fib_routes: &[proto::FibRouteStatus],
) -> Vec<DataplaneSummary> {
    vec![
        count_blackhole_statuses(blackholes),
        count_fib_statuses(fib_routes),
    ]
}

fn changed_dataplane_summaries(
    previous: &[DataplaneSummary],
    current: &[DataplaneSummary],
) -> Vec<DataplaneSummary> {
    current
        .iter()
        .copied()
        .filter(|summary| {
            previous
                .iter()
                .find(|candidate| candidate.source == summary.source)
                .is_none_or(|previous| summary.changed_from(*previous))
        })
        .collect()
}

fn dataplane_summary_to_bgp_event(summary: DataplaneSummary) -> proto::BgpEvent {
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
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_string(),
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

fn spawn_dataplane_poller(
    tx: broadcast::Sender<proto::BgpEvent>,
    shared_tx: Arc<Mutex<Option<broadcast::Sender<proto::BgpEvent>>>>,
    blackhole_snapshot: BlackholeDiscardSnapshotFn,
    fib_snapshot: FibRouteSnapshotFn,
) {
    tokio::spawn(async move {
        let mut previous = dataplane_summaries(&blackhole_snapshot(), &fib_snapshot());
        let mut interval = tokio::time::interval(DATAPLANE_EVENT_POLL_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if tx.receiver_count() == 0 {
                let mut guard = shared_tx
                    .lock()
                    .expect("dataplane event broadcaster mutex poisoned");
                if tx.receiver_count() == 0 {
                    *guard = None;
                    return;
                }
            }

            let current = dataplane_summaries(&blackhole_snapshot(), &fib_snapshot());
            for summary in changed_dataplane_summaries(&previous, &current) {
                let _ = tx.send(dataplane_summary_to_bgp_event(summary));
            }
            previous = current;
        }
    });
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

fn parse_list_session_events_filter(
    req: &proto::ListSessionEventsRequest,
) -> Result<SessionEventHistoryFilter, Status> {
    let event_types = parse_session_event_type_filter(&req.event_types)?;
    let peer = if req.neighbor_address.is_empty() {
        None
    } else {
        Some(
            req.neighbor_address
                .parse::<IpAddr>()
                .map_err(|e| Status::invalid_argument(format!("invalid address: {e}")))?,
        )
    };

    Ok(SessionEventHistoryFilter {
        peer,
        event_types,
        limit: req.limit as usize,
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
            | proto::BgpEventType::PolicyChanged
            | proto::BgpEventType::DataplaneStatusChanged
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

fn policy_event_to_bgp_event(event: PolicyEvent) -> proto::BgpEvent {
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

    #[allow(clippy::too_many_lines)]
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

        let policy_stream: Pin<Box<dyn Stream<Item = Result<proto::BgpEvent, Status>> + Send>> =
            if filter.wants_policy_events() {
                let (reply_tx, reply_rx) = oneshot::channel();
                self.peer_mgr_tx
                    .send(PeerManagerCommand::SubscribePolicyEvents { reply: reply_tx })
                    .await
                    .map_err(|_| Status::internal("peer manager unavailable"))?;
                let broadcast_rx = reply_rx
                    .await
                    .map_err(|_| Status::internal("peer manager dropped reply"))?;
                let policy_filter = filter.clone();
                Box::pin(BroadcastStream::new(broadcast_rx).filter_map(
                    move |result| match result {
                        Ok(event) => {
                            if policy_filter.matches_policy_event(&event) {
                                Some(Ok(policy_event_to_bgp_event(event)))
                            } else {
                                None
                            }
                        }
                        Err(_lagged) => {
                            debug!("WatchEvents policy subscriber lagged, skipping missed events");
                            None
                        }
                    },
                ))
            } else {
                Box::pin(tokio_stream::empty())
            };

        let dataplane_stream: Pin<Box<dyn Stream<Item = Result<proto::BgpEvent, Status>> + Send>> =
            if filter.wants_dataplane_events() {
                let broadcast_rx = self.subscribe_dataplane_events();
                Box::pin(BroadcastStream::new(broadcast_rx).filter_map(
                    move |result| match result {
                        Ok(event) => Some(Ok(event)),
                        Err(_lagged) => {
                            debug!(
                                "WatchEvents dataplane subscriber lagged, skipping missed events"
                            );
                            None
                        }
                    },
                ))
            } else {
                Box::pin(tokio_stream::empty())
            };

        Ok(Response::new(Box::pin(
            route_stream
                .merge(session_stream)
                .merge(policy_stream)
                .merge(dataplane_stream),
        )))
    }

    async fn list_session_events(
        &self,
        request: Request<proto::ListSessionEventsRequest>,
    ) -> Result<Response<proto::ListSessionEventsResponse>, Status> {
        let filter = parse_list_session_events_filter(&request.into_inner())?;
        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::QuerySessionEventHistory {
                peer: filter.peer,
                event_types: filter.event_types,
                limit: filter.limit,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;
        let events = reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?;
        Ok(Response::new(proto::ListSessionEventsResponse {
            events: events
                .into_iter()
                .map(|event| session_event_to_bgp_event(SessionEvent::Lifecycle(event)))
                .collect(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_types::SESSION_EVENT_HISTORY_CAPACITY;
    use crate::proto::event_service_server::EventService as EventServiceTrait;
    use rustbgpd_fsm::SessionState;
    use rustbgpd_rib::RouteEvent;
    use rustbgpd_wire::{Ipv4Prefix, Ipv6Prefix};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::{Arc, Mutex};
    use tokio::sync::{broadcast, mpsc};
    use tokio_stream::StreamExt;

    fn route_event(prefix: Prefix, peer: IpAddr) -> RouteEvent {
        RouteEvent {
            event_id: 1,
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
                    _ => {}
                }
            }
        });
        (peer_tx, session_events_tx, policy_events_tx)
    }

    fn spawn_fake_peer_manager_with_history(
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

    fn session_event(peer: IpAddr, event_type: SessionLifecycleEventType) -> SessionEvent {
        SessionEvent::Lifecycle(lifecycle_event(peer, event_type))
    }

    fn lifecycle_event(
        peer: IpAddr,
        event_type: SessionLifecycleEventType,
    ) -> SessionLifecycleEvent {
        SessionLifecycleEvent {
            event_type,
            peer,
            timestamp: "456".to_string(),
            old_state: Some(SessionState::OpenConfirm),
            new_state: Some(SessionState::Established),
            session_role: Some("primary".to_string()),
            reason: format!("session event for peer {peer}"),
        }
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

    fn policy_event(peer: Option<IpAddr>) -> PolicyEvent {
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

    fn fib_status(state: proto::FibRouteState) -> proto::FibRouteStatus {
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
        }
    }

    fn blackhole_status(state: proto::BlackholeDiscardState) -> proto::BlackholeDiscard {
        proto::BlackholeDiscard {
            prefix: "198.51.100.1".to_string(),
            prefix_length: 32,
            peer_address: "10.0.0.2".to_string(),
            state: state as i32,
            reason: "test".to_string(),
        }
    }

    #[tokio::test]
    async fn route_event_bridge_emits_bgp_event() {
        let (rib_tx, events_tx) = spawn_fake_rib();
        let (peer_tx, _, _) = spawn_fake_peer_manager();
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
        let Some(proto::bgp_event::Payload::Route(route)) = event.payload else {
            panic!("expected route payload");
        };
        assert_eq!(route.event_id, 1);
    }

    #[tokio::test]
    async fn dataplane_category_filter_does_not_subscribe_route_or_session_events() {
        let (rib_tx, route_events_tx) = spawn_fake_rib();
        let (peer_tx, session_events_tx, _policy_events_tx) = spawn_fake_peer_manager();
        let service = EventService::new(rib_tx, peer_tx);
        let response = service
            .watch_events(Request::new(proto::WatchEventsRequest {
                categories: vec![proto::EventCategory::Dataplane as i32],
                event_types: vec![proto::BgpEventType::DataplaneStatusChanged as i32],
                ..Default::default()
            }))
            .await
            .unwrap();

        assert_eq!(route_events_tx.receiver_count(), 0);
        assert_eq!(session_events_tx.receiver_count(), 0);
        drop(response);
    }

    #[tokio::test]
    async fn dataplane_subscriber_drop_stops_shared_poller() {
        let (rib_tx, _) = spawn_fake_rib();
        let (peer_tx, _, _) = spawn_fake_peer_manager();
        let service = EventService::new(rib_tx, peer_tx);
        let response = service
            .watch_events(Request::new(proto::WatchEventsRequest {
                categories: vec![proto::EventCategory::Dataplane as i32],
                ..Default::default()
            }))
            .await
            .unwrap();

        {
            let guard = service.dataplane_events.lock().unwrap();
            let tx = guard.as_ref().expect("dataplane poller should be active");
            assert_eq!(tx.receiver_count(), 1);
        }

        drop(response);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if service.dataplane_events.lock().unwrap().is_none() {
                    break;
                }
                tokio::time::sleep(DATAPLANE_EVENT_POLL_INTERVAL).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn dataplane_summary_event_emits_on_aggregate_change() {
        let blackholes = Arc::new(Mutex::new(Vec::<proto::BlackholeDiscard>::new()));
        let fib_routes = Arc::new(Mutex::new(Vec::<proto::FibRouteStatus>::new()));
        let blackholes_for_service = blackholes.clone();
        let fib_routes_for_service = fib_routes.clone();
        let (rib_tx, _) = spawn_fake_rib();
        let (peer_tx, _, _) = spawn_fake_peer_manager();
        let service = EventService::with_dataplane_snapshots(
            rib_tx,
            peer_tx,
            Arc::new(move || blackholes_for_service.lock().unwrap().clone()),
            Arc::new(move || fib_routes_for_service.lock().unwrap().clone()),
        );
        let response = service
            .watch_events(Request::new(proto::WatchEventsRequest {
                categories: vec![proto::EventCategory::Dataplane as i32],
                ..Default::default()
            }))
            .await
            .unwrap();
        let mut stream = response.into_inner();

        tokio::time::sleep(DATAPLANE_EVENT_POLL_INTERVAL * 2).await;
        *fib_routes.lock().unwrap() = vec![
            fib_status(proto::FibRouteState::Installed),
            fib_status(proto::FibRouteState::Failed),
        ];

        let event = tokio::time::timeout(std::time::Duration::from_secs(1), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(event.category, proto::EventCategory::Dataplane as i32);
        assert_eq!(
            event.event_type,
            proto::BgpEventType::DataplaneStatusChanged as i32
        );
        assert_eq!(event.severity, proto::EventSeverity::Warning as i32);
        assert_eq!(
            event.summary,
            "dataplane fib status changed: installed=1 rejected=0 failed=1"
        );
        let Some(proto::bgp_event::Payload::Dataplane(payload)) = event.payload else {
            panic!("expected dataplane payload");
        };
        assert_eq!(payload.source, "fib");
        assert_eq!(payload.installed, 1);
        assert_eq!(payload.failed, 1);
    }

    #[test]
    fn dataplane_summaries_count_blackhole_and_fib_states() {
        let summaries = dataplane_summaries(
            &[
                blackhole_status(proto::BlackholeDiscardState::Installed),
                blackhole_status(proto::BlackholeDiscardState::Rejected),
            ],
            &[
                fib_status(proto::FibRouteState::Installed),
                fib_status(proto::FibRouteState::Installed),
                fib_status(proto::FibRouteState::Failed),
            ],
        );

        assert_eq!(
            summaries,
            vec![
                DataplaneSummary {
                    source: "blackhole",
                    installed: 1,
                    rejected: 1,
                    failed: 0,
                },
                DataplaneSummary {
                    source: "fib",
                    installed: 2,
                    rejected: 0,
                    failed: 1,
                },
            ]
        );
    }

    #[tokio::test]
    async fn filters_compose_for_route_events() {
        let (rib_tx, events_tx) = spawn_fake_rib();
        let (peer_tx, _, _) = spawn_fake_peer_manager();
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
        let (peer_tx, session_events_tx, _) = spawn_fake_peer_manager();
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
        let (peer_tx, session_events_tx, _) = spawn_fake_peer_manager();
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
    async fn list_session_events_returns_bgp_event_history() {
        let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let peer_tx = spawn_fake_peer_manager_with_history(vec![
            lifecycle_event(peer1, SessionLifecycleEventType::PeerEnabled),
            lifecycle_event(peer2, SessionLifecycleEventType::PeerDisabled),
            lifecycle_event(peer1, SessionLifecycleEventType::PeerDisabled),
        ]);
        let (rib_tx, _) = spawn_fake_rib();
        let service = EventService::new(rib_tx, peer_tx);

        let response = service
            .list_session_events(Request::new(proto::ListSessionEventsRequest {
                neighbor_address: peer1.to_string(),
                event_types: vec![proto::BgpEventType::PeerDisabled as i32],
                limit: 10,
            }))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.events.len(), 1);
        let event = &response.events[0];
        assert_eq!(event.category, proto::EventCategory::Session as i32);
        assert_eq!(event.event_type, proto::BgpEventType::PeerDisabled as i32);
        assert_eq!(event.peer_address, peer1.to_string());
        assert!(matches!(
            event.payload,
            Some(proto::bgp_event::Payload::Session(_))
        ));
    }

    #[tokio::test]
    async fn list_session_events_rejects_route_event_type_filter() {
        let (rib_tx, _) = spawn_fake_rib();
        let peer_tx = spawn_fake_peer_manager_with_history(Vec::new());
        let service = EventService::new(rib_tx, peer_tx);

        let Err(err) = service
            .list_session_events(Request::new(proto::ListSessionEventsRequest {
                event_types: vec![proto::BgpEventType::RouteAdded as i32],
                ..Default::default()
            }))
            .await
        else {
            panic!("route event type should be rejected for session history");
        };
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn prefix_filter_does_not_match_session_events() {
        let (rib_tx, _) = spawn_fake_rib();
        let (peer_tx, session_events_tx, _) = spawn_fake_peer_manager();
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
        let (peer_tx, session_events_tx, _) = spawn_fake_peer_manager();
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
        let (peer_tx, session_events_tx, _) = spawn_fake_peer_manager();
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
    async fn policy_event_bridge_emits_bgp_event() {
        let (rib_tx, _) = spawn_fake_rib();
        let (peer_tx, _, policy_events_tx) = spawn_fake_peer_manager();
        let service = EventService::new(rib_tx, peer_tx);
        let response = service
            .watch_events(Request::new(proto::WatchEventsRequest {
                categories: vec![proto::EventCategory::Policy as i32],
                event_types: vec![proto::BgpEventType::PolicyChanged as i32],
                ..Default::default()
            }))
            .await
            .unwrap();
        let mut stream = response.into_inner();

        policy_events_tx.send(policy_event(None)).unwrap();
        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.category, proto::EventCategory::Policy as i32);
        assert_eq!(event.event_type, proto::BgpEventType::PolicyChanged as i32);
        assert_eq!(event.severity, proto::EventSeverity::Info as i32);
        assert_eq!(event.summary, "policy set policy audit-policy");
        assert!(matches!(
            event.payload,
            Some(proto::bgp_event::Payload::Policy(_))
        ));
    }

    #[tokio::test]
    async fn policy_event_type_filter_subscribes_without_policy_category() {
        let (rib_tx, _) = spawn_fake_rib();
        let (peer_tx, _, policy_events_tx) = spawn_fake_peer_manager();
        let service = EventService::new(rib_tx, peer_tx);
        let response = service
            .watch_events(Request::new(proto::WatchEventsRequest {
                event_types: vec![proto::BgpEventType::PolicyChanged as i32],
                ..Default::default()
            }))
            .await
            .unwrap();
        let mut stream = response.into_inner();

        policy_events_tx.send(policy_event(None)).unwrap();
        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.category, proto::EventCategory::Policy as i32);
        assert_eq!(event.event_type, proto::BgpEventType::PolicyChanged as i32);
    }

    #[tokio::test]
    async fn peer_filter_matches_only_peer_scoped_policy_events() {
        let (rib_tx, _) = spawn_fake_rib();
        let (peer_tx, _, policy_events_tx) = spawn_fake_peer_manager();
        let service = EventService::new(rib_tx, peer_tx);
        let response = service
            .watch_events(Request::new(proto::WatchEventsRequest {
                categories: vec![proto::EventCategory::Policy as i32],
                neighbor_address: "10.0.0.1".to_string(),
                ..Default::default()
            }))
            .await
            .unwrap();
        let mut stream = response.into_inner();

        policy_events_tx.send(policy_event(None)).unwrap();
        policy_events_tx
            .send(policy_event(Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))))
            .unwrap();
        policy_events_tx
            .send(policy_event(Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))))
            .unwrap();

        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.peer_address, "10.0.0.1");
    }

    #[tokio::test]
    async fn default_watch_does_not_subscribe_policy_events() {
        let (rib_tx, _) = spawn_fake_rib();
        let (peer_tx, _, policy_events_tx) = spawn_fake_peer_manager();
        let service = EventService::new(rib_tx, peer_tx);
        let response = service
            .watch_events(Request::new(proto::WatchEventsRequest::default()))
            .await
            .unwrap();

        assert_eq!(policy_events_tx.receiver_count(), 0);
        drop(response);
    }

    #[tokio::test]
    async fn rejects_unsupported_category_filter() {
        let (rib_tx, _) = spawn_fake_rib();
        let (peer_tx, _, _) = spawn_fake_peer_manager();
        let service = EventService::new(rib_tx, peer_tx);
        let Err(err) = service
            .watch_events(Request::new(proto::WatchEventsRequest {
                categories: vec![proto::EventCategory::Unspecified as i32],
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
        let (peer_tx, _, _) = spawn_fake_peer_manager();
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
        let (peer_tx, _, _) = spawn_fake_peer_manager();
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
        let (peer_tx, session_events_tx, _) = spawn_fake_peer_manager();
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
