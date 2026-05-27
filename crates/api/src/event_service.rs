//! Unified live event stream service.

use std::pin::Pin;
use std::sync::{Arc, Mutex};

use tokio::sync::{broadcast, oneshot};
use tokio_stream::Stream;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::{BroadcastStream, errors::BroadcastStreamRecvError};
use tonic::{Request, Response, Status};
use tracing::debug;

pub(crate) mod convert;
mod cursor;
pub(crate) mod dataplane;
mod filters;

use convert::{evpn_event_to_bgp_event, policy_event_to_bgp_event, session_event_to_bgp_event};
pub(crate) use convert::{route_event_to_bgp_event, stream_lag_bgp_event};
use dataplane::spawn_dataplane_poller;
#[cfg(test)]
use dataplane::{DataplaneSummary, dataplane_summaries};
use filters::{
    parse_list_evpn_events_filter, parse_list_policy_events_filter,
    parse_list_session_events_filter, parse_watch_events_filter,
};

use crate::peer_types::{PeerManagerCommand, SessionEvent};
use crate::proto;
use crate::rib_service::{BlackholeDiscardSnapshotFn, FibRouteSnapshotFn};
use rustbgpd_rib::RibUpdate;
#[cfg(test)]
use rustbgpd_rib::RouteEventType;
use rustbgpd_telemetry::BgpMetrics;
#[cfg(test)]
use rustbgpd_wire::Prefix;

#[cfg(not(test))]
const DATAPLANE_EVENT_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
#[cfg(test)]
const DATAPLANE_EVENT_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(10);

pub(crate) type DataplaneEventBroadcaster = Arc<Mutex<Option<broadcast::Sender<proto::BgpEvent>>>>;
pub(crate) type DataplaneRouteEventBroadcaster = Option<broadcast::Sender<proto::BgpEvent>>;
/// Live ADR-0067 BFD session-event source for `WatchEvents`. `None` disables
/// the BFD event stream.
pub(crate) type BfdEventBroadcaster = Option<broadcast::Sender<proto::BgpEvent>>;

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
    dataplane_route_events: DataplaneRouteEventBroadcaster,
    bfd_events: BfdEventBroadcaster,
    /// Optional handle to the durable event outbox (ADR-0072). When
    /// `None`, `SubscribeFromEvent` returns
    /// `Status::failed_precondition`; the legacy `WatchEvents` /
    /// `WatchRoutes` / `List*Events` surfaces continue to work
    /// unchanged regardless of this field.
    event_history: Option<rustbgpd_event_history::EventHistoryHandle>,
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
            None,
            None,
            BgpMetrics::new(),
        )
    }

    #[must_use]
    #[expect(
        clippy::too_many_arguments,
        reason = "EventService aggregates several independent event sources + snapshots"
    )]
    pub(crate) fn with_dataplane_snapshots_broadcaster_and_metrics(
        rib_tx: tokio::sync::mpsc::Sender<RibUpdate>,
        peer_mgr_tx: tokio::sync::mpsc::Sender<PeerManagerCommand>,
        blackhole_discard_snapshot: BlackholeDiscardSnapshotFn,
        fib_route_snapshot: FibRouteSnapshotFn,
        dataplane_events: DataplaneEventBroadcaster,
        dataplane_route_events: DataplaneRouteEventBroadcaster,
        bfd_events: BfdEventBroadcaster,
        metrics: BgpMetrics,
    ) -> Self {
        Self {
            rib_tx,
            peer_mgr_tx,
            blackhole_discard_snapshot,
            fib_route_snapshot,
            dataplane_events,
            dataplane_route_events,
            bfd_events,
            event_history: None,
            metrics,
        }
    }

    /// Install the durable event-outbox handle (ADR-0072). Called
    /// once at daemon startup when `[event_history].enabled = true`.
    /// `None` means `SubscribeFromEvent` returns
    /// `Status::failed_precondition`; the rest of the live surface
    /// is unaffected.
    #[must_use]
    pub fn with_event_history(
        mut self,
        handle: Option<rustbgpd_event_history::EventHistoryHandle>,
    ) -> Self {
        self.event_history = handle;
        self
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

        // ADR-0072 PR-FU1: this lazy-spawn path runs when EHM is
        // disabled (or pre-startup-spawn). The EHM-enabled startup
        // spawn in `serve()` populates the broadcaster eagerly, so
        // we never get here in that case. Pass None / a fresh
        // metrics handle — the latter is used only for drop
        // accounting which is a no-op without an EHM handle.
        spawn_dataplane_poller(
            tx,
            self.dataplane_events.clone(),
            self.blackhole_discard_snapshot.clone(),
            self.fib_route_snapshot.clone(),
            None,
            self.metrics.clone(),
        );
        rx
    }
}

#[tonic::async_trait]
impl proto::event_service_server::EventService for EventService {
    type WatchEventsStream =
        Pin<Box<dyn Stream<Item = Result<proto::BgpEvent, Status>> + Send + 'static>>;

    #[expect(
        clippy::too_many_lines,
        reason = "WatchEvents assembles route, session, policy, and dataplane source streams with per-source filters and metrics"
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
                                "WatchEvents route subscriber lagged, emitting missed-event signal"
                            );
                            Some(Ok(stream_lag_bgp_event(
                                proto::EventCategory::Route,
                                missed,
                            )))
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
                                "WatchEvents session subscriber lagged, emitting missed-event signal"
                            );
                            Some(Ok(stream_lag_bgp_event(
                                proto::EventCategory::Session,
                                missed,
                            )))
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
                let policy_metrics = self.metrics.clone();
                let policy_subscriber_guard =
                    policy_metrics.event_stream_subscriber_guard("watch_events", "policy");
                Box::pin(BroadcastStream::new(broadcast_rx).filter_map(
                    move |result| match result {
                        Err(BroadcastStreamRecvError::Lagged(missed)) => {
                            let _subscriber_guard = &policy_subscriber_guard;
                            policy_metrics.record_event_stream_lagged(
                                "watch_events",
                                "policy",
                                missed,
                            );
                            debug!(
                                missed,
                                "WatchEvents policy subscriber lagged, skipping missed events"
                            );
                            None
                        }
                        Ok(event) => {
                            let _subscriber_guard = &policy_subscriber_guard;
                            if policy_filter.matches_policy_event(&event) {
                                Some(Ok(policy_event_to_bgp_event(event)))
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
                let dataplane_route_rx = self
                    .dataplane_route_events
                    .as_ref()
                    .map(tokio::sync::broadcast::Sender::subscribe);
                let dataplane_filter = filter.clone();
                let dataplane_metrics = self.metrics.clone();
                let dataplane_subscriber_guard =
                    dataplane_metrics.event_stream_subscriber_guard("watch_events", "dataplane");
                let aggregate_stream =
                    BroadcastStream::new(broadcast_rx).filter_map(move |result| match result {
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
                            if dataplane_filter.matches_dataplane_bgp_event(&event) {
                                Some(Ok(event))
                            } else {
                                None
                            }
                        }
                    });
                let route_stream: Pin<
                    Box<dyn Stream<Item = Result<proto::BgpEvent, Status>> + Send>,
                > = if let Some(dataplane_route_rx) = dataplane_route_rx {
                    let dataplane_filter = filter.clone();
                    let dataplane_route_metrics = self.metrics.clone();
                    let dataplane_route_subscriber_guard = dataplane_route_metrics
                        .event_stream_subscriber_guard("watch_events", "dataplane_route");
                    Box::pin(BroadcastStream::new(dataplane_route_rx).filter_map(
                        move |result| match result {
                            Err(BroadcastStreamRecvError::Lagged(missed)) => {
                                let _subscriber_guard = &dataplane_route_subscriber_guard;
                                dataplane_route_metrics.record_event_stream_lagged(
                                    "watch_events",
                                    "dataplane_route",
                                    missed,
                                );
                                debug!(
                                    missed,
                                    "WatchEvents dataplane route subscriber lagged, emitting missed-event signal"
                                );
                                Some(Ok(stream_lag_bgp_event(
                                    proto::EventCategory::Dataplane,
                                    missed,
                                )))
                            }
                            Ok(event) => {
                                let _subscriber_guard = &dataplane_route_subscriber_guard;
                                if dataplane_filter.matches_dataplane_bgp_event(&event) {
                                    Some(Ok(event))
                                } else {
                                    None
                                }
                            }
                        },
                    ))
                } else {
                    Box::pin(tokio_stream::empty())
                };
                Box::pin(aggregate_stream.merge(route_stream))
            } else {
                Box::pin(tokio_stream::empty())
            };

        let evpn_stream: Pin<Box<dyn Stream<Item = Result<proto::BgpEvent, Status>> + Send>> =
            if filter.wants_evpn_events() {
                let (reply_tx, reply_rx) = oneshot::channel();
                self.rib_tx
                    .send(RibUpdate::SubscribeEvpnRouteEvents { reply: reply_tx })
                    .await
                    .map_err(|_| Status::internal("RIB manager unavailable"))?;
                let broadcast_rx = reply_rx
                    .await
                    .map_err(|_| Status::internal("RIB manager dropped reply"))?;
                let evpn_filter = filter.clone();
                let evpn_metrics = self.metrics.clone();
                let evpn_subscriber_guard =
                    evpn_metrics.event_stream_subscriber_guard("watch_events", "evpn");
                Box::pin(BroadcastStream::new(broadcast_rx).filter_map(
                    move |result| match result {
                        Err(BroadcastStreamRecvError::Lagged(missed)) => {
                            let _subscriber_guard = &evpn_subscriber_guard;
                            evpn_metrics.record_event_stream_lagged("watch_events", "evpn", missed);
                            debug!(
                                missed,
                                "WatchEvents EVPN subscriber lagged, emitting missed-event signal"
                            );
                            Some(Ok(stream_lag_bgp_event(proto::EventCategory::Evpn, missed)))
                        }
                        Ok(event) => {
                            let _subscriber_guard = &evpn_subscriber_guard;
                            if evpn_filter.matches_evpn_event(&event) {
                                Some(Ok(evpn_event_to_bgp_event(event)))
                            } else {
                                None
                            }
                        }
                    },
                ))
            } else {
                Box::pin(tokio_stream::empty())
            };

        let bfd_stream: Pin<Box<dyn Stream<Item = Result<proto::BgpEvent, Status>> + Send>> =
            if filter.wants_bfd_events() {
                if let Some(bfd_rx) = self
                    .bfd_events
                    .as_ref()
                    .map(tokio::sync::broadcast::Sender::subscribe)
                {
                    let bfd_filter = filter.clone();
                    let bfd_metrics = self.metrics.clone();
                    let bfd_subscriber_guard =
                        bfd_metrics.event_stream_subscriber_guard("watch_events", "bfd");
                    Box::pin(BroadcastStream::new(bfd_rx).filter_map(
                        move |result| match result {
                            Err(BroadcastStreamRecvError::Lagged(missed)) => {
                                let _subscriber_guard = &bfd_subscriber_guard;
                                bfd_metrics.record_event_stream_lagged("watch_events", "bfd", missed);
                                debug!(
                                    missed,
                                    "WatchEvents BFD subscriber lagged, emitting missed-event signal"
                                );
                                Some(Ok(stream_lag_bgp_event(proto::EventCategory::Bfd, missed)))
                            }
                            Ok(event) => {
                                let _subscriber_guard = &bfd_subscriber_guard;
                                if bfd_filter.matches_bfd_event(&event) {
                                    Some(Ok(event))
                                } else {
                                    None
                                }
                            }
                        },
                    ))
                } else {
                    Box::pin(tokio_stream::empty())
                }
            } else {
                Box::pin(tokio_stream::empty())
            };

        Ok(Response::new(Box::pin(
            route_stream
                .merge(session_stream)
                .merge(policy_stream)
                .merge(dataplane_stream)
                .merge(evpn_stream)
                .merge(bfd_stream),
        )))
    }

    async fn list_evpn_events(
        &self,
        request: Request<proto::ListEvpnEventsRequest>,
    ) -> Result<Response<proto::ListEvpnEventsResponse>, Status> {
        let filter = parse_list_evpn_events_filter(&request.into_inner())?;
        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::QueryEvpnRouteEventHistory {
                peer: filter.peer,
                route_type: filter.route_type,
                rd: filter.rd,
                event_types: filter.event_types,
                limit: filter.limit,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("RIB manager unavailable"))?;
        let events = reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?;
        Ok(Response::new(proto::ListEvpnEventsResponse {
            events: events.into_iter().map(evpn_event_to_bgp_event).collect(),
        }))
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

    async fn list_policy_events(
        &self,
        request: Request<proto::ListPolicyEventsRequest>,
    ) -> Result<Response<proto::ListPolicyEventsResponse>, Status> {
        let filter = parse_list_policy_events_filter(&request.into_inner())?;
        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::QueryPolicyEventHistory {
                peer: filter.peer,
                limit: filter.limit,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;
        let events = reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?;
        Ok(Response::new(proto::ListPolicyEventsResponse {
            events: events.into_iter().map(policy_event_to_bgp_event).collect(),
        }))
    }

    type SubscribeFromEventStream =
        Pin<Box<dyn Stream<Item = Result<proto::BgpEvent, Status>> + Send + 'static>>;

    /// `SubscribeFromEvent` — durable cursor replay + live (ADR-0072).
    ///
    /// Server-side replay-then-live join of the durable event outbox.
    /// Cursor semantics on `from_event_id`:
    ///
    /// - `None` ⇒ live-only (no replay).
    /// - `Some(0)` ⇒ replay everything retained, then live.
    /// - `Some(N>0)` ⇒ replay events with `event_id > N`, then live.
    ///
    /// When the requested cursor is older than the retention floor,
    /// the server emits a single leading `StreamLagEvent` with the
    /// missed count over the **global committed stream** (not the
    /// filtered subset), then continues replay from the earliest
    /// retained event. Collectors continue moving while observing
    /// the gap.
    ///
    /// When the daemon was started with `[event_history].enabled =
    /// false`, when EHM failed to start with
    /// `required = false`, or when EHM dropped into pass-through
    /// mode at runtime, returns `Status::failed_precondition`. The
    /// legacy `WatchEvents` / `WatchRoutes` / `List*Events` surfaces
    /// continue to work in all those cases.
    async fn subscribe_from_event(
        &self,
        request: Request<proto::SubscribeFromEventRequest>,
    ) -> Result<Response<Self::SubscribeFromEventStream>, Status> {
        let req = request.into_inner();
        let handle = self.event_history.as_ref().ok_or_else(|| {
            Status::failed_precondition(
                "event history disabled or unavailable; \
                 see [event_history] config and \
                 the bgp_event_outbox_degraded gauge",
            )
        })?;
        let stream = cursor::subscribe(handle, &req, self.metrics.clone())?;
        Ok(Response::new(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_types::{
        POLICY_EVENT_HISTORY_CAPACITY, PolicyEvent, SESSION_EVENT_HISTORY_CAPACITY, SessionEvent,
        SessionLifecycleEvent, SessionLifecycleEventType, SessionNotificationEvent,
        SessionNotificationEventType,
    };
    use crate::proto::event_service_server::EventService as EventServiceTrait;
    use prometheus::Encoder;
    use rustbgpd_fsm::SessionState;
    use rustbgpd_rib::{EvpnRouteEvent, RouteEvent};
    use rustbgpd_wire::{
        EthernetSegmentIdentifier, EthernetTagId, EvpnMacIp, EvpnRoute, MacAddress, MplsLabel,
        Origin, PathAttribute, RouteDistinguisher,
    };
    use rustbgpd_wire::{Ipv4Prefix, Ipv6Prefix};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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
            ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, mac_byte))),
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
            peer_router_id: Ipv4Addr::new(192, 0, 2, mac_byte),
            is_stale: false,
            is_llgr_stale: false,
        }
    }

    fn evpn_event(
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

    fn spawn_fake_rib() -> (mpsc::Sender<RibUpdate>, broadcast::Sender<RouteEvent>) {
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

    fn spawn_fake_rib_with_evpn_history(history: Vec<EvpnRouteEvent>) -> mpsc::Sender<RibUpdate> {
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
                                route_type
                                    .is_none_or(|route_type| event.key.route_type() == route_type)
                            })
                            .filter(|event| {
                                rd.is_none_or(|rd| {
                                    rustbgpd_rib::event::evpn_key_rd(&event.key) == rd
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

    fn spawn_fake_evpn_rib() -> (mpsc::Sender<RibUpdate>, broadcast::Sender<EvpnRouteEvent>) {
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
                    PeerManagerCommand::QueryPolicyEventHistory { reply, .. } => {
                        let _ = reply.send(Vec::new());
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

    fn spawn_fake_peer_manager_with_policy_history(
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
            peer_label: None,
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
            ..Default::default()
        }
    }

    fn dataplane_route_event(
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

    #[test]
    fn route_bgp_event_contract_duplicates_common_fields() {
        let event = RouteEvent {
            event_id: 0,
            event_type: RouteEventType::BestChanged,
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24)),
            peer: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            previous_peer: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            target_peer: None,
            timestamp: "123".to_string(),
            path_id: 42,
            reason: String::new(),
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

    #[test]
    fn policy_filtered_route_event_carries_target_peer() {
        let event = RouteEvent {
            event_id: 7,
            event_type: RouteEventType::PolicyFiltered,
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24)),
            peer: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            previous_peer: None,
            target_peer: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            timestamp: "123".to_string(),
            path_id: 9,
            reason: "policy_denied".to_string(),
        };

        let bgp_event = route_event_to_bgp_event(event);

        assert_eq!(
            bgp_event.event_type,
            proto::BgpEventType::RoutePolicyFiltered as i32
        );
        assert_eq!(bgp_event.peer_address, "10.0.0.1");
        assert_eq!(bgp_event.target_peer_address, "10.0.0.2");
        assert!(bgp_event.summary.contains("policy_denied"));
        let Some(proto::bgp_event::Payload::Route(route)) = bgp_event.payload else {
            panic!("expected route payload");
        };
        assert_eq!(route.target_peer_address, "10.0.0.2");
        assert_eq!(route.reason, "policy_denied");
    }

    #[test]
    fn evpn_bgp_event_contract_uses_l2vpn_payload() {
        let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let bgp_event = evpn_event_to_bgp_event(evpn_event(
            RouteEventType::BestChanged,
            Some(peer2),
            Some(peer1),
        ));

        assert_eq!(bgp_event.timestamp, "123");
        assert_eq!(bgp_event.category, proto::EventCategory::Evpn as i32);
        assert_eq!(
            bgp_event.event_type,
            proto::BgpEventType::EvpnRouteBestChanged as i32
        );
        assert_eq!(bgp_event.peer_address, peer2.to_string());
        assert_eq!(bgp_event.previous_peer_address, peer1.to_string());
        assert_eq!(bgp_event.afi_safi, proto::AddressFamily::L2vpnEvpn as i32);
        assert!(bgp_event.summary.contains("EVPN route best changed"));
        let Some(proto::bgp_event::Payload::Evpn(evpn)) = bgp_event.payload else {
            panic!("expected EVPN payload");
        };
        assert_eq!(evpn.route_type, 2);
        assert_eq!(evpn.rd, "65000:100");
        assert!(evpn.route.is_some());
        assert!(evpn.previous_route.is_some());
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
    async fn evpn_event_bridge_emits_bgp_event() {
        let (rib_tx, evpn_events_tx) = spawn_fake_evpn_rib();
        let (peer_tx, _, _) = spawn_fake_peer_manager();
        let service = EventService::new(rib_tx, peer_tx);
        let response = service
            .watch_events(Request::new(proto::WatchEventsRequest {
                categories: vec![proto::EventCategory::Evpn as i32],
                event_types: vec![proto::BgpEventType::EvpnRouteAdded as i32],
                ..Default::default()
            }))
            .await
            .unwrap();
        let mut stream = response.into_inner();

        evpn_events_tx
            .send(evpn_event(
                RouteEventType::Added,
                Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                None,
            ))
            .unwrap();

        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.category, proto::EventCategory::Evpn as i32);
        assert_eq!(event.event_type, proto::BgpEventType::EvpnRouteAdded as i32);
        assert!(matches!(
            event.payload,
            Some(proto::bgp_event::Payload::Evpn(_))
        ));
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
    async fn dataplane_poller_with_ehm_handle_outlives_watch_events_subscribers() {
        // ADR-0072 PR-FU1: when EHM is enabled, the poller must
        // stay alive even after every WatchEvents subscriber drops
        // — `SubscribeFromEvent` collectors need durable summaries
        // regardless of who else is watching.
        let dir = tempfile::tempdir().unwrap();
        let manager = rustbgpd_event_history::EventHistoryManager::start(
            rustbgpd_event_history::EventHistoryConfig {
                path: dir.path().join("events.db"),
                max_events: 100,
                max_bytes: 1_000_000,
                synchronous: rustbgpd_event_history::SynchronousMode::Full,
                required: false,
                queue_capacity: 64,
                batch_size: 4,
                batch_interval: std::time::Duration::from_millis(20),
                broadcast_capacity: 64,
                retention_interval: std::time::Duration::from_mins(1),
                sidecar_flush_interval_batches: 100,
                metrics: None,
            },
        )
        .await
        .expect("EHM start");
        let handle = manager.handle();

        let shared = dataplane_event_broadcaster();
        let (tx, initial_rx) = broadcast::channel(16);
        {
            let mut guard = shared.lock().unwrap();
            *guard = Some(tx.clone());
        }
        dataplane::spawn_dataplane_poller(
            tx,
            shared.clone(),
            Arc::new(Vec::new),
            Arc::new(Vec::new),
            Some(handle),
            BgpMetrics::new(),
        );

        // Drop the only WatchEvents-side receiver.
        drop(initial_rx);

        // Wait for several poll intervals; the EHM-enabled poller
        // must NOT reset the shared broadcaster to None.
        for _ in 0..5 {
            tokio::time::sleep(DATAPLANE_EVENT_POLL_INTERVAL).await;
        }
        assert!(
            shared.lock().unwrap().is_some(),
            "EHM-enabled dataplane poller must outlive WatchEvents subscribers"
        );

        manager.shutdown().await;
    }

    #[tokio::test]
    async fn dataplane_summary_enqueued_to_ehm_handle_alongside_broadcast() {
        // ADR-0072 PR-FU1: every dataplane summary that the poller
        // broadcasts must also be enqueued into EHM so
        // `SubscribeFromEvent` collectors see the same event the
        // legacy `WatchEvents` consumer sees.
        let dir = tempfile::tempdir().unwrap();
        let manager = rustbgpd_event_history::EventHistoryManager::start(
            rustbgpd_event_history::EventHistoryConfig {
                path: dir.path().join("events.db"),
                max_events: 100,
                max_bytes: 1_000_000,
                synchronous: rustbgpd_event_history::SynchronousMode::Full,
                required: false,
                queue_capacity: 64,
                batch_size: 1,
                batch_interval: std::time::Duration::from_millis(10),
                broadcast_capacity: 64,
                retention_interval: std::time::Duration::from_mins(1),
                sidecar_flush_interval_batches: 100,
                metrics: None,
            },
        )
        .await
        .expect("EHM start");
        let handle = manager.handle();
        let mut ehm_live = handle.subscribe_live();

        // Empty snapshots at spawn time so the poller's initial
        // `previous` baseline is "no rows." We mutate the fib
        // snapshot AFTER spawning so the first tick diff sees a
        // non-empty current and emits a DataplaneEvent.
        let fib_routes: Arc<Mutex<Vec<proto::FibRouteStatus>>> = Arc::new(Mutex::new(Vec::new()));
        let fib_snapshot: FibRouteSnapshotFn = {
            let fib_routes = fib_routes.clone();
            Arc::new(move || fib_routes.lock().unwrap().clone())
        };

        let shared = dataplane_event_broadcaster();
        let (tx, mut watch_rx) = broadcast::channel(16);
        {
            let mut guard = shared.lock().unwrap();
            *guard = Some(tx.clone());
        }
        dataplane::spawn_dataplane_poller(
            tx,
            shared,
            Arc::new(Vec::new),
            fib_snapshot,
            Some(handle.clone()),
            BgpMetrics::new(),
        );

        // The poller's `previous` baseline is captured at the
        // start of its spawned task. Yield + wait one poll
        // interval so the baseline definitely sees the empty
        // snapshot BEFORE we mutate it; without this, the
        // baseline can race with the push below and the poller
        // initializes already in the "installed=1" steady state
        // (no diff, no event ever).
        tokio::time::sleep(DATAPLANE_EVENT_POLL_INTERVAL * 2).await;
        fib_routes.lock().unwrap().push(proto::FibRouteStatus {
            state: proto::FibRouteState::Installed as i32,
            ..Default::default()
        });

        // The poller broadcasts the summary on the WatchEvents
        // channel first — confirm we see it there so the test
        // distinguishes "diff didn't fire" from "EHM enqueue
        // didn't fire" if it ever regresses.
        let _broadcast_event =
            tokio::time::timeout(std::time::Duration::from_secs(2), watch_rx.recv())
                .await
                .expect("WatchEvents broadcast within 2s")
                .expect("WatchEvents receiver still attached");

        // EHM commits it on the next batch interval (10ms).
        let committed = tokio::time::timeout(std::time::Duration::from_secs(2), ehm_live.recv())
            .await
            .expect("committed event within 2s")
            .expect("EHM broadcast still attached");
        assert_eq!(
            committed.envelope.category,
            rustbgpd_event_history::Category::Dataplane,
            "summary must be classified under Category::Dataplane"
        );

        manager.shutdown().await;
    }

    #[tokio::test]
    async fn dataplane_broadcaster_can_be_shared_across_services() {
        let shared = dataplane_event_broadcaster();
        let (rib_tx_a, _) = spawn_fake_rib();
        let (peer_tx_a, _, _) = spawn_fake_peer_manager();
        let service_a = EventService::with_dataplane_snapshots_and_broadcaster(
            rib_tx_a,
            peer_tx_a,
            Arc::new(Vec::new),
            Arc::new(Vec::new),
            shared.clone(),
        );
        let (rib_tx_b, _) = spawn_fake_rib();
        let (peer_tx_b, _, _) = spawn_fake_peer_manager();
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

    #[tokio::test]
    async fn dataplane_route_events_filter_by_type_peer_and_prefix() {
        let (rib_tx, _) = spawn_fake_rib();
        let (peer_tx, _, _) = spawn_fake_peer_manager();
        let (route_tx, _) = broadcast::channel(16);
        let service = EventService::with_dataplane_snapshots_broadcaster_and_metrics(
            rib_tx,
            peer_tx,
            Arc::new(Vec::new),
            Arc::new(Vec::new),
            dataplane_event_broadcaster(),
            Some(route_tx.clone()),
            None,
            BgpMetrics::new(),
        );
        let response = service
            .watch_events(Request::new(proto::WatchEventsRequest {
                categories: vec![proto::EventCategory::Dataplane as i32],
                event_types: vec![proto::BgpEventType::DataplaneRouteInstalled as i32],
                neighbor_address: "10.0.0.1".to_string(),
                afi_safi: proto::AddressFamily::Ipv4Unicast as i32,
                prefix: "203.0.113.0".to_string(),
                prefix_length: 24,
            }))
            .await
            .unwrap();
        let mut stream = response.into_inner();

        route_tx
            .send(dataplane_route_event(
                proto::BgpEventType::DataplaneRouteWithdrawn,
                "203.0.113.0",
                24,
                "10.0.0.1",
            ))
            .unwrap();
        route_tx
            .send(dataplane_route_event(
                proto::BgpEventType::DataplaneRouteInstalled,
                "203.0.113.0",
                24,
                "10.0.0.2",
            ))
            .unwrap();
        route_tx
            .send(dataplane_route_event(
                proto::BgpEventType::DataplaneRouteInstalled,
                "203.0.113.0",
                24,
                "10.0.0.1",
            ))
            .unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_secs(1), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            event.event_type,
            proto::BgpEventType::DataplaneRouteInstalled as i32
        );
        assert_eq!(event.peer_address, "10.0.0.1");
        assert_eq!(event.prefix, "203.0.113.0");
        let Some(proto::bgp_event::Payload::DataplaneRoute(payload)) = event.payload else {
            panic!("expected dataplane route payload");
        };
        assert_eq!(payload.source, "fib");
        assert_eq!(payload.table_name, "blue");
    }

    fn bfd_bgp_event(event_type: proto::BgpEventType, peer: &str) -> proto::BgpEvent {
        proto::BgpEvent {
            timestamp: "0".to_string(),
            category: proto::EventCategory::Bfd as i32,
            event_type: event_type as i32,
            severity: proto::EventSeverity::Info as i32,
            peer_address: peer.to_string(),
            previous_peer_address: String::new(),
            prefix: String::new(),
            prefix_length: 0,
            afi_safi: proto::AddressFamily::Unspecified as i32,
            summary: format!("bfd {peer}"),
            target_peer_address: String::new(),
            event_id: None,
            payload: Some(proto::bgp_event::Payload::Bfd(proto::BfdSessionEvent {
                event_type: event_type as i32,
                peer_address: peer.to_string(),
                timestamp: "0".to_string(),
                old_state: proto::BfdSessionState::Down as i32,
                new_state: proto::BfdSessionState::Up as i32,
                diagnostic: "none".to_string(),
                reason: String::new(),
            })),
        }
    }

    #[tokio::test]
    async fn bfd_events_stream_filtered_by_category_and_peer() {
        let (rib_tx, _) = spawn_fake_rib();
        let (peer_tx, _, _) = spawn_fake_peer_manager();
        let (bfd_tx, _) = broadcast::channel(16);
        let service = EventService::with_dataplane_snapshots_broadcaster_and_metrics(
            rib_tx,
            peer_tx,
            Arc::new(Vec::new),
            Arc::new(Vec::new),
            dataplane_event_broadcaster(),
            None,
            Some(bfd_tx.clone()),
            BgpMetrics::new(),
        );
        let response = service
            .watch_events(Request::new(proto::WatchEventsRequest {
                categories: vec![proto::EventCategory::Bfd as i32],
                event_types: vec![],
                neighbor_address: "10.0.0.1".to_string(),
                afi_safi: proto::AddressFamily::Unspecified as i32,
                prefix: String::new(),
                prefix_length: 0,
            }))
            .await
            .unwrap();
        let mut stream = response.into_inner();

        // Wrong peer — filtered out.
        bfd_tx
            .send(bfd_bgp_event(proto::BgpEventType::BfdSessionUp, "10.0.0.2"))
            .unwrap();
        // Matching peer — delivered.
        bfd_tx
            .send(bfd_bgp_event(proto::BgpEventType::BfdSessionUp, "10.0.0.1"))
            .unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_secs(1), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(event.category, proto::EventCategory::Bfd as i32);
        assert_eq!(event.event_type, proto::BgpEventType::BfdSessionUp as i32);
        assert_eq!(event.peer_address, "10.0.0.1");
        let Some(proto::bgp_event::Payload::Bfd(payload)) = event.payload else {
            panic!("expected bfd payload");
        };
        assert_eq!(payload.new_state, proto::BfdSessionState::Up as i32);
    }

    #[tokio::test]
    async fn bfd_events_not_in_default_route_session_stream() {
        let (rib_tx, _) = spawn_fake_rib();
        let (peer_tx, _, _) = spawn_fake_peer_manager();
        let (bfd_tx, _) = broadcast::channel(16);
        let service = EventService::with_dataplane_snapshots_broadcaster_and_metrics(
            rib_tx,
            peer_tx,
            Arc::new(Vec::new),
            Arc::new(Vec::new),
            dataplane_event_broadcaster(),
            None,
            Some(bfd_tx.clone()),
            BgpMetrics::new(),
        );
        // Default request (no categories) = route + session only; BFD opt-in.
        let response = service
            .watch_events(Request::new(proto::WatchEventsRequest::default()))
            .await
            .unwrap();
        let mut stream = response.into_inner();
        // The default stream never subscribes to BFD, so `send` may report no
        // receivers — that absence is exactly the property under test.
        let _ = bfd_tx.send(bfd_bgp_event(proto::BgpEventType::BfdSessionUp, "10.0.0.1"));
        // The BFD event must not leak into the default stream.
        let result =
            tokio::time::timeout(std::time::Duration::from_millis(300), stream.next()).await;
        assert!(result.is_err(), "BFD event leaked into the default stream");
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
    async fn list_policy_events_returns_bgp_event_history() {
        let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let peer_tx = spawn_fake_peer_manager_with_policy_history(vec![
            policy_event(Some(peer1)),
            policy_event(Some(peer2)),
            PolicyEvent {
                target: "route-map-audit".to_string(),
                ..policy_event(Some(peer1))
            },
        ]);
        let (rib_tx, _) = spawn_fake_rib();
        let service = EventService::new(rib_tx, peer_tx);

        let response = service
            .list_policy_events(Request::new(proto::ListPolicyEventsRequest {
                neighbor_address: peer1.to_string(),
                event_types: vec![proto::BgpEventType::PolicyChanged as i32],
                limit: 10,
            }))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.events.len(), 2);
        assert!(
            response
                .events
                .iter()
                .all(|event| event.category == proto::EventCategory::Policy as i32)
        );
        assert_eq!(
            response.events[0].event_type,
            proto::BgpEventType::PolicyChanged as i32
        );
        assert_eq!(response.events[0].peer_address, peer1.to_string());
        let Some(proto::bgp_event::Payload::Policy(policy)) = response.events[1].payload.as_ref()
        else {
            panic!("expected policy payload");
        };
        assert_eq!(policy.target, "route-map-audit");
    }

    #[tokio::test]
    async fn list_policy_events_rejects_session_event_type_filter() {
        let (rib_tx, _) = spawn_fake_rib();
        let peer_tx = spawn_fake_peer_manager_with_policy_history(Vec::new());
        let service = EventService::new(rib_tx, peer_tx);

        let Err(err) = service
            .list_policy_events(Request::new(proto::ListPolicyEventsRequest {
                event_types: vec![proto::BgpEventType::SessionEstablished as i32],
                ..Default::default()
            }))
            .await
        else {
            panic!("session event type should be rejected for policy history");
        };
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn list_evpn_events_returns_bgp_event_history() {
        let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let rib_tx = spawn_fake_rib_with_evpn_history(vec![
            evpn_event(RouteEventType::Added, Some(peer1), None),
            evpn_event(RouteEventType::BestChanged, Some(peer2), Some(peer1)),
        ]);
        let (peer_tx, _, _) = spawn_fake_peer_manager();
        let service = EventService::new(rib_tx, peer_tx);

        let response = service
            .list_evpn_events(Request::new(proto::ListEvpnEventsRequest {
                neighbor_address: peer1.to_string(),
                event_types: vec![proto::BgpEventType::EvpnRouteBestChanged as i32],
                route_type_filter: 2,
                rd_filter: "65000:100".to_string(),
                limit: 10,
            }))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.events.len(), 1);
        let event = &response.events[0];
        assert_eq!(event.category, proto::EventCategory::Evpn as i32);
        assert_eq!(
            event.event_type,
            proto::BgpEventType::EvpnRouteBestChanged as i32
        );
        assert_eq!(event.previous_peer_address, peer1.to_string());
    }

    #[tokio::test]
    async fn list_evpn_events_rejects_route_event_type_filter() {
        let rib_tx = spawn_fake_rib_with_evpn_history(Vec::new());
        let (peer_tx, _, _) = spawn_fake_peer_manager();
        let service = EventService::new(rib_tx, peer_tx);

        let Err(err) = service
            .list_evpn_events(Request::new(proto::ListEvpnEventsRequest {
                event_types: vec![proto::BgpEventType::RouteAdded as i32],
                ..Default::default()
            }))
            .await
        else {
            panic!("route event type should be rejected for EVPN history");
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
    async fn default_watch_does_not_subscribe_evpn_events() {
        let (rib_tx, evpn_events_tx) = spawn_fake_evpn_rib();
        let (peer_tx, _, _) = spawn_fake_peer_manager();
        let service = EventService::new(rib_tx, peer_tx);
        let response = service
            .watch_events(Request::new(proto::WatchEventsRequest::default()))
            .await
            .unwrap();

        assert_eq!(evpn_events_tx.receiver_count(), 0);
        drop(response);
    }

    #[tokio::test]
    async fn evpn_event_type_filter_subscribes_without_evpn_category() {
        let (rib_tx, evpn_events_tx) = spawn_fake_evpn_rib();
        let (peer_tx, _, _) = spawn_fake_peer_manager();
        let service = EventService::new(rib_tx, peer_tx);
        let response = service
            .watch_events(Request::new(proto::WatchEventsRequest {
                event_types: vec![proto::BgpEventType::EvpnRouteAdded as i32],
                ..Default::default()
            }))
            .await
            .unwrap();

        assert_eq!(evpn_events_tx.receiver_count(), 1);
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
    async fn rejects_unspecified_category_and_event_type_filters() {
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

    #[tokio::test]
    async fn evpn_lag_emits_missed_event_signal() {
        let (rib_tx, evpn_events_tx) = spawn_fake_evpn_rib();
        let (peer_tx, _, _) = spawn_fake_peer_manager();
        let service = EventService::new(rib_tx, peer_tx);
        let response = service
            .watch_events(Request::new(proto::WatchEventsRequest {
                categories: vec![proto::EventCategory::Evpn as i32],
                event_types: vec![proto::BgpEventType::EvpnRouteAdded as i32],
                ..Default::default()
            }))
            .await
            .unwrap();
        let mut stream = response.into_inner();

        for _ in 0..32 {
            evpn_events_tx
                .send(evpn_event(
                    RouteEventType::Added,
                    Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                    None,
                ))
                .unwrap();
        }

        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.category, proto::EventCategory::Evpn as i32);
        assert_eq!(event.event_type, proto::BgpEventType::StreamLagged as i32);
        let Some(proto::bgp_event::Payload::StreamLag(lag)) = event.payload else {
            panic!("expected stream lag payload");
        };
        assert_eq!(lag.source_category, proto::EventCategory::Evpn as i32);
        assert!(lag.missed_count > 0);
    }

    #[tokio::test]
    async fn watch_events_subscriber_gauge_tracks_route_stream_lifecycle() {
        let (rib_tx, _) = spawn_fake_rib();
        let (peer_tx, _, _) = spawn_fake_peer_manager();
        let metrics = BgpMetrics::new();
        let service = EventService::with_dataplane_snapshots_broadcaster_and_metrics(
            rib_tx,
            peer_tx,
            Arc::new(Vec::new),
            Arc::new(Vec::new),
            dataplane_event_broadcaster(),
            None,
            None,
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
        let (peer_tx, _, _) = spawn_fake_peer_manager();
        let metrics = BgpMetrics::new();
        let service = EventService::with_dataplane_snapshots_broadcaster_and_metrics(
            rib_tx,
            peer_tx,
            Arc::new(Vec::new),
            Arc::new(Vec::new),
            dataplane_event_broadcaster(),
            None,
            None,
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

    // ── ADR-0072 PR5 — SubscribeFromEvent handler tests ────────

    #[tokio::test]
    async fn subscribe_from_event_unavailable_returns_failed_precondition() {
        // EventService constructed without `with_event_history` ⇒
        // handle is None ⇒ the handler returns FAILED_PRECONDITION
        // and the legacy WatchEvents surface is unaffected.
        let (rib_tx, _) = spawn_fake_rib();
        let (peer_tx, _, _) = spawn_fake_peer_manager();
        let service = EventService::new(rib_tx, peer_tx);

        match service
            .subscribe_from_event(Request::new(proto::SubscribeFromEventRequest::default()))
            .await
        {
            Ok(_) => panic!("subscribe_from_event must error when EHM is None"),
            Err(status) => assert_eq!(
                status.code(),
                tonic::Code::FailedPrecondition,
                "expected FAILED_PRECONDITION when event_history handle is None"
            ),
        }

        // Legacy WatchEvents is unaffected: it still returns a stream.
        let response = service
            .watch_events(Request::new(proto::WatchEventsRequest::default()))
            .await
            .expect("WatchEvents must still work when EHM is None");
        drop(response);
    }

    #[tokio::test]
    async fn subscribe_from_event_route_durable_id_overrides_nested_field() {
        use prost::Message;
        use rustbgpd_event_history::{
            Category, EnvelopePeers, EventEnvelope, EventHistoryConfig, EventHistoryManager,
            PayloadCodec, Severity, SynchronousMode,
        };

        // Spin up an EHM in a tempdir.
        let dir = tempfile::tempdir().unwrap();
        let ehm = EventHistoryManager::start(EventHistoryConfig {
            path: dir.path().join("events.db"),
            max_events: 100,
            max_bytes: 1_000_000,
            synchronous: SynchronousMode::Full,
            required: false,
            queue_capacity: 64,
            batch_size: 4,
            batch_interval: std::time::Duration::from_millis(20),
            broadcast_capacity: 64,
            retention_interval: std::time::Duration::from_mins(1),
            sidecar_flush_interval_batches: 100,
            metrics: None,
        })
        .await
        .expect("EHM start");
        let handle = ehm.handle();

        // Enqueue one route event with a deliberately wrong
        // process-local `event_id = 99` on the nested payload.
        // The cursor handler must overwrite it with the durable
        // id (which will be 1 since this is the first committed).
        let route_payload = proto::RouteEvent {
            event_id: 99,
            event_type: proto::BgpEventType::RouteAdded as i32,
            prefix: "10.0.0.0".to_string(),
            prefix_length: 24,
            afi_safi: proto::AddressFamily::Ipv4Unicast as i32,
            peer_address: "10.0.0.1".to_string(),
            previous_peer_address: String::new(),
            target_peer_address: String::new(),
            path_id: 0,
            timestamp: "0".to_string(),
            reason: String::new(),
        };
        let envelope_proto = proto::BgpEvent {
            timestamp: "0".to_string(),
            category: proto::EventCategory::Route as i32,
            event_type: proto::BgpEventType::RouteAdded as i32,
            severity: proto::EventSeverity::Info as i32,
            peer_address: "10.0.0.1".to_string(),
            previous_peer_address: String::new(),
            prefix: "10.0.0.0".to_string(),
            prefix_length: 24,
            afi_safi: proto::AddressFamily::Ipv4Unicast as i32,
            summary: String::new(),
            target_peer_address: String::new(),
            event_id: None,
            payload: Some(proto::bgp_event::Payload::Route(route_payload)),
        };
        handle
            .sender()
            .try_send(EventEnvelope {
                timestamp_ns: 0,
                category: Category::Route,
                event_type: "ROUTE_ADDED".to_string(),
                peers: EnvelopePeers::default(),
                afi_safi: Some("ipv4_unicast".to_string()),
                prefix: Some("10.0.0.0/24".to_string()),
                rd: None,
                evpn_route_type: None,
                severity: Severity::Info,
                payload_codec: PayloadCodec::Proto,
                payload: envelope_proto.encode_to_vec(),
            })
            .expect("try_send");

        // Wait for the commit so the cursor query sees it.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Plumb the handle into a fresh EventService and subscribe
        // from the start (cursor = Some(0)).
        let (rib_tx, _) = spawn_fake_rib();
        let (peer_tx, _, _) = spawn_fake_peer_manager();
        let service = EventService::new(rib_tx, peer_tx).with_event_history(Some(handle.clone()));

        let response = service
            .subscribe_from_event(Request::new(proto::SubscribeFromEventRequest {
                from_event_id: Some(0),
                ..Default::default()
            }))
            .await
            .expect("subscribe_from_event must succeed");
        let mut stream = response.into_inner();

        let event = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
            .await
            .expect("first event within 2s")
            .expect("stream still attached")
            .expect("no status error");

        // Envelope-level event_id is set to the durable id.
        assert_eq!(event.event_id, Some(1));
        // Nested RouteEvent.event_id is overwritten from the
        // durable id (was 99 before the handler stamped it).
        let Some(proto::bgp_event::Payload::Route(ref route)) = event.payload else {
            panic!("expected route payload");
        };
        assert_eq!(
            route.event_id, 1,
            "nested RouteEvent.event_id must mirror the durable envelope id"
        );

        ehm.shutdown().await;
    }
}
