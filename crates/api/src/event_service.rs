//! Unified live event stream service.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::{broadcast, oneshot};
use tokio_stream::Stream;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tonic::{Request, Response, Status};
use tracing::debug;

use crate::peer_types::{PeerManagerCommand, SessionLifecycleEvent, SessionLifecycleEventType};
use crate::proto;
use crate::rib_service::{
    BlackholeDiscardSnapshotFn, FibRouteSnapshotFn, parse_route_event_prefix_filter,
    route_event_afi_filter, route_event_to_proto,
};
use rustbgpd_rib::{RibUpdate, RouteEventType};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{Afi, Prefix};

#[cfg(not(test))]
const DATAPLANE_EVENT_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
#[cfg(test)]
const DATAPLANE_EVENT_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(10);

pub(crate) type DataplaneEventBroadcaster = Arc<Mutex<Option<broadcast::Sender<proto::BgpEvent>>>>;

#[must_use]
pub(crate) fn dataplane_event_broadcaster() -> DataplaneEventBroadcaster {
    Arc::new(Mutex::new(None))
}

/// gRPC service exposing a unified live daemon event stream.
#[derive(Clone)]
pub struct EventService {
    rib_tx: tokio::sync::mpsc::Sender<RibUpdate>,
    peer_mgr_tx: tokio::sync::mpsc::Sender<PeerManagerCommand>,
    blackhole_discard_snapshot: BlackholeDiscardSnapshotFn,
    fib_route_snapshot: FibRouteSnapshotFn,
    dataplane_events: DataplaneEventBroadcaster,
    metrics: BgpMetrics,
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
        Self::with_dataplane_snapshots_and_broadcaster(
            rib_tx,
            peer_mgr_tx,
            blackhole_discard_snapshot,
            fib_route_snapshot,
            dataplane_event_broadcaster(),
        )
    }

    #[must_use]
    pub(crate) fn with_dataplane_snapshots_and_broadcaster(
        rib_tx: tokio::sync::mpsc::Sender<RibUpdate>,
        peer_mgr_tx: tokio::sync::mpsc::Sender<PeerManagerCommand>,
        blackhole_discard_snapshot: BlackholeDiscardSnapshotFn,
        fib_route_snapshot: FibRouteSnapshotFn,
        dataplane_events: DataplaneEventBroadcaster,
    ) -> Self {
        Self::with_dataplane_snapshots_broadcaster_and_metrics(
            rib_tx,
            peer_mgr_tx,
            blackhole_discard_snapshot,
            fib_route_snapshot,
            dataplane_events,
            BgpMetrics::new(),
        )
    }

    #[must_use]
    pub(crate) fn with_dataplane_snapshots_broadcaster_and_metrics(
        rib_tx: tokio::sync::mpsc::Sender<RibUpdate>,
        peer_mgr_tx: tokio::sync::mpsc::Sender<PeerManagerCommand>,
        blackhole_discard_snapshot: BlackholeDiscardSnapshotFn,
        fib_route_snapshot: FibRouteSnapshotFn,
        dataplane_events: DataplaneEventBroadcaster,
        metrics: BgpMetrics,
    ) -> Self {
        Self {
            rib_tx,
            peer_mgr_tx,
            blackhole_discard_snapshot,
            fib_route_snapshot,
            dataplane_events,
            metrics,
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

    fn wants_dataplane_events(&self) -> bool {
        (self.categories.is_empty()
            || self
                .categories
                .contains(&(proto::EventCategory::Dataplane as i32)))
            && self.peer.is_none()
            && self.afi.is_none()
            && self.prefix.is_none()
            && self.event_types_match_dataplane_category()
    }

    fn matches_session_event(&self, event: &SessionLifecycleEvent) -> bool {
        if !self.wants_session_events() {
            return false;
        }

        let event_type = session_event_type_to_bgp_event_type(event.event_type);
        if !self.event_types.is_empty() && !self.event_types.contains(&(event_type as i32)) {
            return false;
        }

        if let Some(peer) = self.peer
            && event.peer != peer
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
                        | proto::BgpEventType::RouteBestChanged)
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
                        | proto::BgpEventType::PeerDisabled)
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
            proto::EventCategory::Route
            | proto::EventCategory::Session
            | proto::EventCategory::Dataplane => {
                parsed.insert(category as i32);
            }
            proto::EventCategory::Unspecified => {
                return Err(Status::invalid_argument(
                    "EVENT_CATEGORY_UNSPECIFIED is not a valid filter",
                ));
            }
            proto::EventCategory::Policy => {
                return Err(Status::invalid_argument(
                    "only EVENT_CATEGORY_ROUTE, EVENT_CATEGORY_SESSION, and EVENT_CATEGORY_DATAPLANE are supported by WatchEvents in this release",
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
            | proto::BgpEventType::DataplaneStatusChanged => {
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

fn session_event_type_to_bgp_event_type(
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
    shared_tx: DataplaneEventBroadcaster,
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
            | proto::BgpEventType::DataplaneStatusChanged => "changed",
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

fn session_event_to_bgp_event(event: SessionLifecycleEvent) -> proto::BgpEvent {
    let event_type = session_event_type_to_bgp_event_type(event.event_type);
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

#[tonic::async_trait]
impl proto::event_service_server::EventService for EventService {
    type WatchEventsStream =
        Pin<Box<dyn Stream<Item = Result<proto::BgpEvent, Status>> + Send + 'static>>;

    #[expect(
        clippy::too_many_lines,
        reason = "WatchEvents assembles route, session, and dataplane source streams with per-source filters and metrics"
    )]
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
                let route_metrics = self.metrics.clone();
                let route_subscriber_guard =
                    route_metrics.event_stream_subscriber_guard("watch_events", "route");
                Box::pin(BroadcastStream::new(broadcast_rx).filter_map(
                    move |result| match result {
                        Err(BroadcastStreamRecvError::Lagged(missed)) => {
                            let _subscriber_guard = &route_subscriber_guard;
                            route_metrics.record_event_stream_lagged(
                                "watch_events",
                                "route",
                                missed,
                            );
                            debug!(
                                missed,
                                "WatchEvents route subscriber lagged, skipping missed events"
                            );
                            None
                        }
                        Ok(event) => {
                            let _subscriber_guard = &route_subscriber_guard;
                            if route_filter.matches_route_event(&event) {
                                Some(Ok(route_event_to_bgp_event(event)))
                            } else {
                                None
                            }
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
                let session_metrics = self.metrics.clone();
                let session_subscriber_guard =
                    session_metrics.event_stream_subscriber_guard("watch_events", "session");
                Box::pin(BroadcastStream::new(broadcast_rx).filter_map(
                    move |result| match result {
                        Err(BroadcastStreamRecvError::Lagged(missed)) => {
                            let _subscriber_guard = &session_subscriber_guard;
                            session_metrics.record_event_stream_lagged(
                                "watch_events",
                                "session",
                                missed,
                            );
                            debug!(
                                missed,
                                "WatchEvents session subscriber lagged, skipping missed events"
                            );
                            None
                        }
                        Ok(event) => {
                            let _subscriber_guard = &session_subscriber_guard;
                            if session_filter.matches_session_event(&event) {
                                Some(Ok(session_event_to_bgp_event(event)))
                            } else {
                                None
                            }
                        }
                    },
                ))
            } else {
                Box::pin(tokio_stream::empty())
            };

        let dataplane_stream: Pin<Box<dyn Stream<Item = Result<proto::BgpEvent, Status>> + Send>> =
            if filter.wants_dataplane_events() {
                let broadcast_rx = self.subscribe_dataplane_events();
                let dataplane_metrics = self.metrics.clone();
                let dataplane_subscriber_guard =
                    dataplane_metrics.event_stream_subscriber_guard("watch_events", "dataplane");
                Box::pin(BroadcastStream::new(broadcast_rx).filter_map(
                    move |result| match result {
                        Err(BroadcastStreamRecvError::Lagged(missed)) => {
                            let _subscriber_guard = &dataplane_subscriber_guard;
                            dataplane_metrics.record_event_stream_lagged(
                                "watch_events",
                                "dataplane",
                                missed,
                            );
                            debug!(
                                missed,
                                "WatchEvents dataplane subscriber lagged, skipping missed events"
                            );
                            None
                        }
                        Ok(event) => {
                            let _subscriber_guard = &dataplane_subscriber_guard;
                            Some(Ok(event))
                        }
                    },
                ))
            } else {
                Box::pin(tokio_stream::empty())
            };

        Ok(Response::new(Box::pin(
            route_stream.merge(session_stream).merge(dataplane_stream),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::event_service_server::EventService as EventServiceTrait;
    use prometheus::Encoder;
    use rustbgpd_fsm::SessionState;
    use rustbgpd_rib::RouteEvent;
    use rustbgpd_wire::{Ipv4Prefix, Ipv6Prefix};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::{Arc, Mutex};
    use tokio::sync::{broadcast, mpsc};
    use tokio_stream::StreamExt;

    fn gather_text(metrics: &BgpMetrics) -> String {
        let encoder = prometheus::TextEncoder::new();
        let families = metrics.registry().gather();
        let mut out = Vec::new();
        encoder.encode(&families, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

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
        broadcast::Sender<SessionLifecycleEvent>,
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

    fn session_event(peer: IpAddr, event_type: SessionLifecycleEventType) -> SessionLifecycleEvent {
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

    #[test]
    fn route_bgp_event_contract_duplicates_common_fields() {
        let event = RouteEvent {
            event_type: RouteEventType::BestChanged,
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24)),
            peer: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            previous_peer: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            timestamp: "123".to_string(),
            path_id: 42,
        };

        let bgp_event = route_event_to_bgp_event(event);

        assert_eq!(bgp_event.timestamp, "123");
        assert_eq!(bgp_event.category, proto::EventCategory::Route as i32);
        assert_eq!(
            bgp_event.event_type,
            proto::BgpEventType::RouteBestChanged as i32
        );
        assert_eq!(bgp_event.severity, proto::EventSeverity::Info as i32);
        assert_eq!(bgp_event.peer_address, "10.0.0.1");
        assert_eq!(bgp_event.previous_peer_address, "10.0.0.2");
        assert_eq!(bgp_event.prefix, "203.0.113.0");
        assert_eq!(bgp_event.prefix_length, 24);
        assert_eq!(bgp_event.afi_safi, proto::AddressFamily::Ipv4Unicast as i32);
        assert_eq!(bgp_event.summary, "route best changed 203.0.113.0/24");

        let Some(proto::bgp_event::Payload::Route(route)) = bgp_event.payload else {
            panic!("expected route payload");
        };
        assert_eq!(route.peer_address, bgp_event.peer_address);
        assert_eq!(route.previous_peer_address, bgp_event.previous_peer_address);
        assert_eq!(route.path_id, 42);
    }

    #[tokio::test]
    async fn dataplane_category_filter_does_not_subscribe_route_or_session_events() {
        let (rib_tx, route_events_tx) = spawn_fake_rib();
        let (peer_tx, session_events_tx) = spawn_fake_peer_manager();
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
        let (peer_tx, _) = spawn_fake_peer_manager();
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
    async fn dataplane_broadcaster_can_be_shared_across_services() {
        let shared = dataplane_event_broadcaster();
        let (rib_tx_a, _) = spawn_fake_rib();
        let (peer_tx_a, _) = spawn_fake_peer_manager();
        let service_a = EventService::with_dataplane_snapshots_and_broadcaster(
            rib_tx_a,
            peer_tx_a,
            Arc::new(Vec::new),
            Arc::new(Vec::new),
            shared.clone(),
        );
        let (rib_tx_b, _) = spawn_fake_rib();
        let (peer_tx_b, _) = spawn_fake_peer_manager();
        let service_b = EventService::with_dataplane_snapshots_and_broadcaster(
            rib_tx_b,
            peer_tx_b,
            Arc::new(Vec::new),
            Arc::new(Vec::new),
            shared.clone(),
        );

        let response_a = service_a
            .watch_events(Request::new(proto::WatchEventsRequest {
                categories: vec![proto::EventCategory::Dataplane as i32],
                ..Default::default()
            }))
            .await
            .unwrap();
        let response_b = service_b
            .watch_events(Request::new(proto::WatchEventsRequest {
                categories: vec![proto::EventCategory::Dataplane as i32],
                ..Default::default()
            }))
            .await
            .unwrap();

        {
            let guard = shared.lock().unwrap();
            let tx = guard
                .as_ref()
                .expect("shared dataplane poller should exist");
            assert_eq!(tx.receiver_count(), 2);
        }

        drop(response_a);
        drop(response_b);
    }

    #[tokio::test]
    async fn dataplane_summary_event_emits_on_aggregate_change() {
        let blackholes = Arc::new(Mutex::new(Vec::<proto::BlackholeDiscard>::new()));
        let fib_routes = Arc::new(Mutex::new(Vec::<proto::FibRouteStatus>::new()));
        let blackholes_for_service = blackholes.clone();
        let fib_routes_for_service = fib_routes.clone();
        let (rib_tx, _) = spawn_fake_rib();
        let (peer_tx, _) = spawn_fake_peer_manager();
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
    async fn rejects_unspecified_category_and_event_type_filters() {
        let (rib_tx, _) = spawn_fake_rib();
        let (peer_tx, _) = spawn_fake_peer_manager();
        let service = EventService::new(rib_tx, peer_tx);

        let Err(err) = service
            .watch_events(Request::new(proto::WatchEventsRequest {
                categories: vec![proto::EventCategory::Unspecified as i32],
                ..Default::default()
            }))
            .await
        else {
            panic!("unspecified category filter should fail");
        };
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("EVENT_CATEGORY_UNSPECIFIED"));

        let Err(err) = service
            .watch_events(Request::new(proto::WatchEventsRequest {
                event_types: vec![proto::BgpEventType::Unspecified as i32],
                ..Default::default()
            }))
            .await
        else {
            panic!("unspecified event-type filter should fail");
        };
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("BGP_EVENT_TYPE_UNSPECIFIED"));
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
    async fn watch_events_subscriber_gauge_tracks_route_stream_lifecycle() {
        let (rib_tx, _) = spawn_fake_rib();
        let (peer_tx, _) = spawn_fake_peer_manager();
        let metrics = BgpMetrics::new();
        let service = EventService::with_dataplane_snapshots_broadcaster_and_metrics(
            rib_tx,
            peer_tx,
            Arc::new(Vec::new),
            Arc::new(Vec::new),
            dataplane_event_broadcaster(),
            metrics.clone(),
        );
        let response = service
            .watch_events(Request::new(proto::WatchEventsRequest {
                categories: vec![proto::EventCategory::Route as i32],
                ..Default::default()
            }))
            .await
            .unwrap();

        let text = gather_text(&metrics);
        assert!(
            text.contains(
                "bgp_event_stream_subscribers{service=\"watch_events\",source=\"route\"} 1"
            )
        );

        drop(response);
        tokio::task::yield_now().await;

        let text = gather_text(&metrics);
        assert!(
            text.contains(
                "bgp_event_stream_subscribers{service=\"watch_events\",source=\"route\"} 0"
            )
        );
    }

    #[tokio::test]
    async fn watch_events_lagged_route_subscriber_increments_metric() {
        let (rib_tx, events_tx) = spawn_fake_rib();
        let (peer_tx, _) = spawn_fake_peer_manager();
        let metrics = BgpMetrics::new();
        let service = EventService::with_dataplane_snapshots_broadcaster_and_metrics(
            rib_tx,
            peer_tx,
            Arc::new(Vec::new),
            Arc::new(Vec::new),
            dataplane_event_broadcaster(),
            metrics.clone(),
        );
        let response = service
            .watch_events(Request::new(proto::WatchEventsRequest {
                categories: vec![proto::EventCategory::Route as i32],
                ..Default::default()
            }))
            .await
            .unwrap();
        let mut stream = response.into_inner();

        for index in 0..20 {
            events_tx
                .send(route_event(
                    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, index), 32)),
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                ))
                .unwrap();
        }

        let event = tokio::time::timeout(std::time::Duration::from_secs(1), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(event.category, proto::EventCategory::Route as i32);

        let text = gather_text(&metrics);
        assert!(text.contains(
            "bgp_event_stream_lagged_total{service=\"watch_events\",source=\"route\"} 4"
        ));
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
