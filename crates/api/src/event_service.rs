//! Unified live event stream service.

use std::pin::Pin;
use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;
use tokio_stream::Stream;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::{BroadcastStream, errors::BroadcastStreamRecvError};
use tonic::{Request, Response, Status};
use tracing::debug;

pub(crate) mod convert;
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

use crate::actor_read::{peer_manager_read, rib_manager_read};
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
    metrics: BgpMetrics,
    /// Published managed-peer roster for scoped neighbor selectors.
    roster: Option<crate::import_roster::ImportRosterReader>,
}

impl EventService {
    /// Minimal service for this crate's own unit tests.
    ///
    /// `cfg(test)` holds only inside this crate, so neither the daemon, nor
    /// other workspace crates, nor this crate's `tests/*.rs` integration
    /// targets can reach this constructor or the two
    /// `with_dataplane_snapshots*` ones below it, even under
    /// `cargo test --workspace`. Callers inside the crate build the service
    /// through `with_dataplane_snapshots_broadcaster_and_metrics`, as
    /// `server::serve` does; callers outside it drive the served gRPC
    /// surface rather than constructing an `EventService`.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn new(
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

    #[cfg(test)]
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

    #[cfg(test)]
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
            metrics,
            roster: None,
        }
    }

    /// Resolve scoped neighbor selectors against the managed-peer roster.
    #[must_use]
    pub(crate) fn with_peer_roster(
        mut self,
        roster: crate::import_roster::ImportRosterReader,
    ) -> Self {
        self.roster = Some(roster);
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

        spawn_dataplane_poller(
            tx,
            self.dataplane_events.clone(),
            self.blackhole_discard_snapshot.clone(),
            self.fib_route_snapshot.clone(),
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
        let filter = parse_watch_events_filter(&req, self.roster.as_ref())?;

        let route_stream: Pin<Box<dyn Stream<Item = Result<proto::BgpEvent, Status>> + Send>> =
            if filter.wants_route_events() {
                let broadcast_rx = rib_manager_read(&self.rib_tx, |reply| {
                    RibUpdate::SubscribeRouteEvents { reply }
                })
                .await?;
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
                                Some(Ok(route_event_to_bgp_event(event.as_ref().clone())))
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
                let broadcast_rx = peer_manager_read(&self.peer_mgr_tx, |reply| {
                    PeerManagerCommand::SubscribeSessionEvents { reply }
                })
                .await?;
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
                                Some(Ok(session_event_to_bgp_event(event.as_ref().clone())))
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
                let broadcast_rx = peer_manager_read(&self.peer_mgr_tx, |reply| {
                    PeerManagerCommand::SubscribePolicyEvents { reply }
                })
                .await?;
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
                                "WatchEvents policy subscriber lagged, emitting missed-event signal"
                            );
                            Some(Ok(stream_lag_bgp_event(
                                proto::EventCategory::Policy,
                                missed,
                            )))
                        }
                        Ok(event) => {
                            let _subscriber_guard = &policy_subscriber_guard;
                            if policy_filter.matches_policy_event(&event) {
                                Some(Ok(policy_event_to_bgp_event(event.as_ref().clone())))
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
                                "WatchEvents dataplane subscriber lagged, emitting missed-event signal"
                            );
                            Some(Ok(stream_lag_bgp_event(
                                proto::EventCategory::Dataplane,
                                missed,
                            )))
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
                let broadcast_rx = rib_manager_read(&self.rib_tx, |reply| {
                    RibUpdate::SubscribeEvpnRouteEvents { reply }
                })
                .await?;
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
                                Some(Ok(evpn_event_to_bgp_event(&event)))
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
        let filter = parse_list_evpn_events_filter(&request.into_inner(), self.roster.as_ref())?;
        let events = rib_manager_read(&self.rib_tx, |reply| {
            RibUpdate::QueryEvpnRouteEventHistory {
                peer: filter.peer,
                route_type: filter.route_type,
                rd: filter.rd,
                event_types: filter.event_types,
                limit: filter.limit,
                reply,
            }
        })
        .await?;
        Ok(Response::new(proto::ListEvpnEventsResponse {
            events: events.iter().map(evpn_event_to_bgp_event).collect(),
        }))
    }

    async fn list_session_events(
        &self,
        request: Request<proto::ListSessionEventsRequest>,
    ) -> Result<Response<proto::ListSessionEventsResponse>, Status> {
        let filter = parse_list_session_events_filter(&request.into_inner(), self.roster.as_ref())?;
        let events = peer_manager_read(&self.peer_mgr_tx, |reply| {
            PeerManagerCommand::QuerySessionEventHistory {
                peer: filter.peer,
                event_types: filter.event_types,
                limit: filter.limit,
                reply,
            }
        })
        .await?;
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
        let filter = parse_list_policy_events_filter(&request.into_inner(), self.roster.as_ref())?;
        let events = peer_manager_read(&self.peer_mgr_tx, |reply| {
            PeerManagerCommand::QueryPolicyEventHistory {
                peer: filter.peer,
                limit: filter.limit,
                reply,
            }
        })
        .await?;
        Ok(Response::new(proto::ListPolicyEventsResponse {
            events: events.into_iter().map(policy_event_to_bgp_event).collect(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_types::{PolicyEvent, SessionLifecycleEventType, SessionNotificationEventType};
    use crate::proto::event_service_server::EventService as EventServiceTrait;
    use crate::test_support::{
        blackhole_status, dataplane_route_event, evpn_event, fib_status, lifecycle_event,
        metrics_text as gather_text, notification_event, policy_event, route_event, session_event,
        spawn_fake_evpn_rib, spawn_fake_peer_manager, spawn_fake_peer_manager_with_history,
        spawn_fake_peer_manager_with_policy_history, spawn_fake_rib,
        spawn_fake_rib_with_evpn_history,
    };
    use rustbgpd_rib::RouteEvent;
    use rustbgpd_wire::{Ipv4Prefix, Ipv6Prefix};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::{Arc, Mutex};
    use tokio::sync::broadcast;
    use tokio_stream::StreamExt;

    #[derive(Clone, Copy, Debug)]
    enum ListEventRead {
        Evpn,
        Session,
        Policy,
    }

    const LIST_EVENT_READS: [ListEventRead; 3] = [
        ListEventRead::Evpn,
        ListEventRead::Session,
        ListEventRead::Policy,
    ];

    #[derive(Clone, Copy, Debug)]
    enum WatchEventAdmission {
        Route,
        Session,
        Policy,
        Evpn,
    }

    impl WatchEventAdmission {
        fn category(self) -> proto::EventCategory {
            match self {
                Self::Route => proto::EventCategory::Route,
                Self::Session => proto::EventCategory::Session,
                Self::Policy => proto::EventCategory::Policy,
                Self::Evpn => proto::EventCategory::Evpn,
            }
        }

        fn manager(self) -> &'static str {
            match self {
                Self::Route | Self::Evpn => "RIB",
                Self::Session | Self::Policy => "peer",
            }
        }
    }

    const WATCH_EVENT_ADMISSIONS: [WatchEventAdmission; 4] = [
        WatchEventAdmission::Route,
        WatchEventAdmission::Session,
        WatchEventAdmission::Policy,
        WatchEventAdmission::Evpn,
    ];

    fn watch_event_request(source: WatchEventAdmission) -> proto::WatchEventsRequest {
        proto::WatchEventsRequest {
            categories: vec![source.category() as i32],
            ..Default::default()
        }
    }

    async fn within_test_deadline<T>(future: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(std::time::Duration::from_secs(1), future)
            .await
            .expect("test operation timed out")
    }

    async fn invoke_watch_event_admission(
        service: &EventService,
        source: WatchEventAdmission,
    ) -> Result<(), Status> {
        within_test_deadline(service.watch_events(Request::new(watch_event_request(source))))
            .await
            .map(|_| ())
    }

    fn event_service_with_metrics(
        rib_tx: tokio::sync::mpsc::Sender<RibUpdate>,
        peer_tx: tokio::sync::mpsc::Sender<PeerManagerCommand>,
        metrics: &BgpMetrics,
    ) -> EventService {
        EventService::with_dataplane_snapshots_broadcaster_and_metrics(
            rib_tx,
            peer_tx,
            Arc::new(Vec::new),
            Arc::new(Vec::new),
            dataplane_event_broadcaster(),
            None,
            None,
            metrics.clone(),
        )
    }

    async fn invoke_list_event_read(
        service: &EventService,
        rpc: ListEventRead,
    ) -> Result<(), Status> {
        match rpc {
            ListEventRead::Evpn => service
                .list_evpn_events(Request::new(proto::ListEvpnEventsRequest::default()))
                .await
                .map(|_| ()),
            ListEventRead::Session => service
                .list_session_events(Request::new(proto::ListSessionEventsRequest::default()))
                .await
                .map(|_| ()),
            ListEventRead::Policy => service
                .list_policy_events(Request::new(proto::ListPolicyEventsRequest::default()))
                .await
                .map(|_| ()),
        }
    }

    /// Load-bearing: restoring an included list RPC's actor-send mapping to
    /// `INTERNAL` makes its row red. No watch/subscription RPC is included.
    #[tokio::test]
    async fn list_event_read_send_failures_are_unavailable() {
        for rpc in LIST_EVENT_READS {
            let (rib_tx, rib_rx) = tokio::sync::mpsc::channel(1);
            let (peer_tx, peer_rx) = tokio::sync::mpsc::channel(1);
            match rpc {
                ListEventRead::Evpn => drop(rib_rx),
                ListEventRead::Session | ListEventRead::Policy => drop(peer_rx),
            }
            let service = EventService::new(rib_tx, peer_tx);
            let error = invoke_list_event_read(&service, rpc).await.unwrap_err();
            assert_eq!(error.code(), tonic::Code::Unavailable, "{rpc:?}");
            let expected = match rpc {
                ListEventRead::Evpn => "RIB manager unavailable",
                ListEventRead::Session | ListEventRead::Policy => "peer manager unavailable",
            };
            assert_eq!(error.message(), expected, "{rpc:?}");
        }
    }

    /// Load-bearing: restoring an included list RPC's reply-await mapping to
    /// `INTERNAL` makes its accepted-then-dropped row red.
    #[tokio::test]
    async fn list_event_read_reply_drops_are_unavailable() {
        for rpc in LIST_EVENT_READS {
            let (rib_tx, mut rib_rx) = tokio::sync::mpsc::channel(1);
            let (peer_tx, mut peer_rx) = tokio::sync::mpsc::channel(1);
            let actor = match rpc {
                ListEventRead::Evpn => tokio::spawn(async move {
                    drop(rib_rx.recv().await.expect("EVPN history read"));
                }),
                ListEventRead::Session | ListEventRead::Policy => tokio::spawn(async move {
                    drop(peer_rx.recv().await.expect("peer event-history read"));
                }),
            };
            let service = EventService::new(rib_tx, peer_tx);
            let error = invoke_list_event_read(&service, rpc).await.unwrap_err();
            actor.await.unwrap();
            assert_eq!(error.code(), tonic::Code::Unavailable, "{rpc:?}");
            let expected = match rpc {
                ListEventRead::Evpn => "RIB manager dropped reply",
                ListEventRead::Session | ListEventRead::Policy => "peer manager dropped reply",
            };
            assert_eq!(error.message(), expected, "{rpc:?}");
        }
    }

    /// Load-bearing: restoring any included `WatchEvents` actor-send mapping to
    /// `INTERNAL` makes its isolated actual-handler row red.
    #[tokio::test]
    async fn watch_event_admission_send_failures_are_unavailable() {
        for source in WATCH_EVENT_ADMISSIONS {
            let (rib_tx, rib_rx) = tokio::sync::mpsc::channel(1);
            let (peer_tx, peer_rx) = tokio::sync::mpsc::channel(1);
            match source {
                WatchEventAdmission::Route | WatchEventAdmission::Evpn => drop(rib_rx),
                WatchEventAdmission::Session | WatchEventAdmission::Policy => drop(peer_rx),
            }
            let service = EventService::new(rib_tx, peer_tx);
            let error = invoke_watch_event_admission(&service, source)
                .await
                .unwrap_err();
            assert_eq!(error.code(), tonic::Code::Unavailable, "{source:?}");
            assert_eq!(
                error.message(),
                format!("{} manager unavailable", source.manager()),
                "{source:?}"
            );
        }
    }

    /// Load-bearing: restoring any included `WatchEvents` reply-await mapping to
    /// `INTERNAL` makes its accepted-then-dropped actual-handler row red.
    #[tokio::test]
    async fn watch_event_admission_reply_drops_are_unavailable() {
        for source in WATCH_EVENT_ADMISSIONS {
            let (rib_tx, mut rib_rx) = tokio::sync::mpsc::channel(1);
            let (peer_tx, mut peer_rx) = tokio::sync::mpsc::channel(1);
            let actor = match source {
                WatchEventAdmission::Route | WatchEventAdmission::Evpn => {
                    tokio::spawn(async move {
                        drop(rib_rx.recv().await.expect("RIB watch admission"));
                    })
                }
                WatchEventAdmission::Session | WatchEventAdmission::Policy => {
                    tokio::spawn(async move {
                        drop(peer_rx.recv().await.expect("peer watch admission"));
                    })
                }
            };
            let service = EventService::new(rib_tx, peer_tx);
            let error = invoke_watch_event_admission(&service, source)
                .await
                .unwrap_err();
            within_test_deadline(actor).await.unwrap();
            assert_eq!(error.code(), tonic::Code::Unavailable, "{source:?}");
            assert_eq!(
                error.message(),
                format!("{} manager dropped reply", source.manager()),
                "{source:?}"
            );
        }
    }

    /// Load-bearing: leaking the route receiver or its subscriber guard across
    /// a later session-admission error makes the zero-count assertion red;
    /// restoring the session send mapping to `INTERNAL` makes the status red.
    #[tokio::test]
    async fn watch_events_releases_route_admission_when_session_send_fails() {
        let (rib_tx, mut rib_rx) = tokio::sync::mpsc::channel(1);
        let (peer_tx, peer_rx) = tokio::sync::mpsc::channel(1);
        let (route_events_tx, _) = broadcast::channel(1);
        let route_events_for_actor = route_events_tx.clone();
        let rib_actor = tokio::spawn(async move {
            match rib_rx.recv().await.expect("route watch admission") {
                RibUpdate::SubscribeRouteEvents { reply } => {
                    let _ = reply.send(route_events_for_actor.subscribe());
                }
                _ => panic!("expected route watch admission"),
            }
        });
        drop(peer_rx);

        let metrics = BgpMetrics::new();
        let service = event_service_with_metrics(rib_tx, peer_tx, &metrics);
        let Err(error) = within_test_deadline(service.watch_events(Request::new(
            proto::WatchEventsRequest {
                categories: vec![
                    proto::EventCategory::Route as i32,
                    proto::EventCategory::Session as i32,
                ],
                ..Default::default()
            },
        )))
        .await
        else {
            panic!("session admission must fail");
        };
        within_test_deadline(rib_actor).await.unwrap();

        assert_eq!(error.code(), tonic::Code::Unavailable);
        assert_eq!(error.message(), "peer manager unavailable");
        assert_eq!(route_events_tx.receiver_count(), 0);
        assert!(
            gather_text(&metrics).contains(
                "bgp_event_stream_subscribers{service=\"watch_events\",source=\"route\"} 0"
            )
        );
    }

    /// Load-bearing: leaking any earlier receiver or subscriber guard across
    /// the later EVPN reply drop makes its zero-count assertion red; restoring
    /// the EVPN reply mapping to `INTERNAL` makes the status red.
    #[tokio::test]
    async fn watch_events_releases_earlier_admissions_when_evpn_reply_drops() {
        let (rib_tx, mut rib_rx) = tokio::sync::mpsc::channel(2);
        let (peer_tx, mut peer_rx) = tokio::sync::mpsc::channel(2);
        let (route_events_tx, _) = broadcast::channel(1);
        let (session_events_tx, _) = broadcast::channel(1);
        let (policy_events_tx, _) = broadcast::channel(1);

        let route_events_for_actor = route_events_tx.clone();
        let rib_actor = tokio::spawn(async move {
            match rib_rx.recv().await.expect("route watch admission") {
                RibUpdate::SubscribeRouteEvents { reply } => {
                    let _ = reply.send(route_events_for_actor.subscribe());
                }
                _ => panic!("expected route watch admission"),
            }
            match rib_rx.recv().await.expect("EVPN watch admission") {
                RibUpdate::SubscribeEvpnRouteEvents { reply } => drop(reply),
                _ => panic!("expected EVPN watch admission"),
            }
        });

        let session_events_for_actor = session_events_tx.clone();
        let policy_events_for_actor = policy_events_tx.clone();
        let peer_actor = tokio::spawn(async move {
            match peer_rx.recv().await.expect("session watch admission") {
                PeerManagerCommand::SubscribeSessionEvents { reply } => {
                    let _ = reply.send(session_events_for_actor.subscribe());
                }
                _ => panic!("expected session watch admission"),
            }
            match peer_rx.recv().await.expect("policy watch admission") {
                PeerManagerCommand::SubscribePolicyEvents { reply } => {
                    let _ = reply.send(policy_events_for_actor.subscribe());
                }
                _ => panic!("expected policy watch admission"),
            }
        });

        let metrics = BgpMetrics::new();
        let service = event_service_with_metrics(rib_tx, peer_tx, &metrics);
        let Err(error) = within_test_deadline(service.watch_events(Request::new(
            proto::WatchEventsRequest {
                categories: vec![
                    proto::EventCategory::Route as i32,
                    proto::EventCategory::Session as i32,
                    proto::EventCategory::Policy as i32,
                    proto::EventCategory::Evpn as i32,
                ],
                ..Default::default()
            },
        )))
        .await
        else {
            panic!("EVPN admission must fail");
        };
        within_test_deadline(rib_actor).await.unwrap();
        within_test_deadline(peer_actor).await.unwrap();

        assert_eq!(error.code(), tonic::Code::Unavailable);
        assert_eq!(error.message(), "RIB manager dropped reply");
        for (source, receivers) in [
            ("route", route_events_tx.receiver_count()),
            ("session", session_events_tx.receiver_count()),
            ("policy", policy_events_tx.receiver_count()),
        ] {
            assert_eq!(receivers, 0, "{source} receiver leaked");
            assert!(
                gather_text(&metrics).contains(&format!(
                    "bgp_event_stream_subscribers{{service=\"watch_events\",source=\"{source}\"}} 0"
                )),
                "{source} subscriber gauge did not return to zero"
            );
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
            .send(Arc::new(route_event(
                Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            )))
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
            peer_scope: rustbgpd_rib::route::AspaContextId::DEFAULT,
            previous_peer_scope: rustbgpd_rib::route::AspaContextId::DEFAULT,
            target_peer_scope: rustbgpd_rib::route::AspaContextId::DEFAULT,
            timestamp_unix_ms: 123_000,
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
            peer_scope: rustbgpd_rib::route::AspaContextId::DEFAULT,
            previous_peer_scope: rustbgpd_rib::route::AspaContextId::DEFAULT,
            target_peer_scope: rustbgpd_rib::route::AspaContextId::DEFAULT,
            timestamp_unix_ms: 123_000,
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
        let bgp_event = evpn_event_to_bgp_event(&evpn_event(
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
    async fn incompatible_live_filter_fails_before_subscribing() {
        let (rib_tx, route_events) = spawn_fake_rib();
        let (peer_tx, session_events, _) = spawn_fake_peer_manager();
        let service = EventService::new(rib_tx, peer_tx);
        let request = proto::WatchEventsRequest {
            categories: vec![proto::EventCategory::Session as i32],
            event_types: vec![proto::BgpEventType::RouteAdded as i32],
            ..Default::default()
        };
        let Err(status) = service.watch_events(Request::new(request)).await else {
            panic!("incompatible filter accepted");
        };
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert_eq!(route_events.receiver_count(), 0);
        assert_eq!(session_events.receiver_count(), 0);
    }

    #[tokio::test]
    async fn mixed_live_filter_subscribes_only_to_intersection() {
        let (rib_tx, route_events) = spawn_fake_rib();
        let (peer_tx, session_events, _) = spawn_fake_peer_manager();
        let service = EventService::new(rib_tx, peer_tx);
        let response = service
            .watch_events(Request::new(proto::WatchEventsRequest {
                categories: vec![
                    proto::EventCategory::Route as i32,
                    proto::EventCategory::Session as i32,
                ],
                event_types: vec![proto::BgpEventType::RouteAdded as i32],
                ..Default::default()
            }))
            .await
            .unwrap();
        assert_eq!(route_events.receiver_count(), 1);
        assert_eq!(session_events.receiver_count(), 0);
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
            .send(Arc::new(evpn_event(
                RouteEventType::Added,
                Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                None,
            )))
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
            timestamp_unix_ms: 0,
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

    /// LAN-1014: on a daemon whose FIB/BFD subsystem never spawns (fixed at
    /// startup — reload and CRUD both answer restart-required), the daemon
    /// wires 1-slot placeholder rings into `ServeConfig` instead of the full
    /// 4096/1024-slot rings. A subscriber arriving before (or without) the
    /// subsystem must still get an open, functional stream: pending while
    /// silent, delivering if a publisher ever sends.
    #[tokio::test]
    async fn bfd_watch_on_one_slot_placeholder_ring_stays_open_and_delivers() {
        let (rib_tx, _) = spawn_fake_rib();
        let (peer_tx, _, _) = spawn_fake_peer_manager();
        let (bfd_tx, _) = broadcast::channel(1);
        let (fib_route_tx, _) = broadcast::channel(1);
        let service = EventService::with_dataplane_snapshots_broadcaster_and_metrics(
            rib_tx,
            peer_tx,
            Arc::new(Vec::new),
            Arc::new(Vec::new),
            dataplane_event_broadcaster(),
            Some(fib_route_tx),
            Some(bfd_tx.clone()),
            BgpMetrics::new(),
        );
        let response = service
            .watch_events(Request::new(proto::WatchEventsRequest {
                categories: vec![proto::EventCategory::Bfd as i32],
                event_types: vec![],
                neighbor_address: String::new(),
                afi_safi: proto::AddressFamily::Unspecified as i32,
                prefix: String::new(),
                prefix_length: 0,
            }))
            .await
            .unwrap();
        let mut stream = response.into_inner();

        // No publisher: the stream stays open (pending), it does not end.
        let idle = tokio::time::timeout(std::time::Duration::from_millis(300), stream.next()).await;
        assert!(
            idle.is_err(),
            "BFD stream on a placeholder ring must stay pending, got {idle:?}"
        );

        // A publisher on the 1-slot ring still reaches the subscriber.
        bfd_tx
            .send(bfd_bgp_event(proto::BgpEventType::BfdSessionUp, "10.0.0.1"))
            .unwrap();
        let event = tokio::time::timeout(std::time::Duration::from_secs(1), stream.next())
            .await
            .expect("event on placeholder ring must be delivered")
            .unwrap()
            .unwrap();
        assert_eq!(event.category, proto::EventCategory::Bfd as i32);
    }

    /// LAN-1014 structural pin: tokio broadcast allocates its slot array at
    /// construction, and each slot embeds an `Option<BgpEvent>` payload
    /// (prost oneof sized by its largest variant). Shrinking the never-used
    /// FIB (4096-slot) and BFD (1024-slot) proto rings to 1-slot placeholders
    /// removes 4095 + 1023 = 5118 slots of eager payload capacity per daemon:
    /// 5118 × 968 B = 4,954,224 B of slot payload, before per-slot metadata.
    /// The boxed optional Prefix-SID and SMET views add 32 B to the earlier
    /// 944 B layout: 64 B across unused placeholders, or 163,840 B with both
    /// actors enabled. SMET adds 16 B per slot instead of 160 B unboxed.
    /// Removing the envelope `event_id` took 16 B back out of each slot, and
    /// the envelope's typed `timestamp_unix_ms` added 8 B.
    /// Populated views allocate their boxes and retained attribute data
    /// outside this payload.
    #[test]
    fn watch_events_ring_slot_payload_size_pin() {
        assert_eq!(std::mem::size_of::<Option<proto::BgpEvent>>(), 968);
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
            .send(Arc::new(route_event(
                Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            )))
            .unwrap();
        events_tx
            .send(Arc::new(route_event(
                Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            )))
            .unwrap();
        events_tx
            .send(Arc::new(route_event(
                Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            )))
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
            .send(Arc::new(session_event(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                SessionLifecycleEventType::Established,
            )))
            .unwrap();
        session_events_tx
            .send(Arc::new(session_event(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                SessionLifecycleEventType::Established,
            )))
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
            .send(Arc::new(notification_event(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                SessionNotificationEventType::Sent,
            )))
            .unwrap();
        session_events_tx
            .send(Arc::new(notification_event(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                SessionNotificationEventType::Sent,
            )))
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
                .send(Arc::new(session_event(
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    SessionLifecycleEventType::Established,
                )))
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

        policy_events_tx.send(Arc::new(policy_event(None))).unwrap();
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

        policy_events_tx.send(Arc::new(policy_event(None))).unwrap();
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

        policy_events_tx.send(Arc::new(policy_event(None))).unwrap();
        policy_events_tx
            .send(Arc::new(policy_event(Some(IpAddr::V4(Ipv4Addr::new(
                10, 0, 0, 2,
            ))))))
            .unwrap();
        policy_events_tx
            .send(Arc::new(policy_event(Some(IpAddr::V4(Ipv4Addr::new(
                10, 0, 0, 1,
            ))))))
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
                .send(Arc::new(route_event(
                    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, i), 32)),
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                )))
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
                .send(Arc::new(session_event(
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    SessionLifecycleEventType::Established,
                )))
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

    /// Cross-stream correlation: session, notification and policy events
    /// report a scoped neighbor as route events do, a bare `peer_address`
    /// plus `peer_interface`, on both the envelope and the payload.
    /// Red proof: copying the label into `peer_address` fails every row.
    #[test]
    fn session_and_policy_events_report_address_plus_interface() {
        let peer: IpAddr = "fe80::1".parse().unwrap();
        let mut lifecycle = crate::test_support::lifecycle_event(
            peer,
            crate::peer_types::SessionLifecycleEventType::Established,
        );
        lifecycle.peer_label = Some("fe80::1%eth0".to_string());
        let event = session_event_to_bgp_event(SessionEvent::Lifecycle(lifecycle));
        assert_eq!(event.peer_address, "fe80::1");
        let Some(proto::bgp_event::Payload::Session(payload)) = event.payload else {
            panic!("expected session payload");
        };
        assert_eq!(
            (
                payload.peer_address.as_str(),
                payload.peer_interface.as_str()
            ),
            ("fe80::1", "eth0")
        );

        let SessionEvent::Notification(mut notification) =
            notification_event(peer, SessionNotificationEventType::Sent)
        else {
            unreachable!()
        };
        notification.peer_label = Some("fe80::1%eth0".to_string());
        let event = session_event_to_bgp_event(SessionEvent::Notification(notification));
        assert_eq!(event.peer_address, "fe80::1");
        let Some(proto::bgp_event::Payload::Notification(payload)) = event.payload else {
            panic!("expected notification payload");
        };
        assert_eq!(
            (
                payload.peer_address.as_str(),
                payload.peer_interface.as_str()
            ),
            ("fe80::1", "eth0")
        );

        let mut policy = policy_event(Some(peer));
        policy.peer_label = Some("fe80::1%eth0".to_string());
        let event = policy_event_to_bgp_event(policy);
        assert_eq!(event.peer_address, "fe80::1");
        let Some(proto::bgp_event::Payload::Policy(payload)) = event.payload else {
            panic!("expected policy payload");
        };
        assert_eq!(
            (
                payload.peer_address.as_str(),
                payload.peer_interface.as_str()
            ),
            ("fe80::1", "eth0")
        );

        // A numbered neighbor's label carries no interface.
        let event = policy_event_to_bgp_event(policy_event(Some("192.0.2.1".parse().unwrap())));
        let Some(proto::bgp_event::Payload::Policy(payload)) = event.payload else {
            panic!("expected policy payload");
        };
        assert_eq!(
            (
                payload.peer_address.as_str(),
                payload.peer_interface.as_str()
            ),
            ("192.0.2.1", "")
        );
    }

    #[tokio::test]
    async fn policy_lag_emits_missed_event_signal() {
        let (rib_tx, _) = spawn_fake_rib();
        let (peer_tx, _, policy_events_tx) = spawn_fake_peer_manager();
        let service = EventService::new(rib_tx, peer_tx);
        let response = service
            .watch_events(Request::new(proto::WatchEventsRequest {
                categories: vec![proto::EventCategory::Policy as i32],
                ..Default::default()
            }))
            .await
            .unwrap();
        let mut stream = response.into_inner();

        for _ in 0..32 {
            policy_events_tx.send(Arc::new(policy_event(None))).unwrap();
        }

        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.category, proto::EventCategory::Policy as i32);
        assert_eq!(event.event_type, proto::BgpEventType::StreamLagged as i32);
        assert_eq!(event.severity, proto::EventSeverity::Warning as i32);
        let Some(proto::bgp_event::Payload::StreamLag(lag)) = event.payload else {
            panic!("expected stream lag payload");
        };
        assert_eq!(lag.source_category, proto::EventCategory::Policy as i32);
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
                .send(Arc::new(evpn_event(
                    RouteEventType::Added,
                    Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                    None,
                )))
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
                .send(Arc::new(route_event(
                    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, index), 32)),
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                )))
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
        let filter = parse_watch_events_filter(
            &proto::WatchEventsRequest {
                afi_safi: proto::AddressFamily::Ipv6Unicast as i32,
                prefix: "2001:db8::".to_string(),
                prefix_length: 64,
                ..Default::default()
            },
            None,
        )
        .unwrap();
        let event = route_event(
            Prefix::V6(Ipv6Prefix::new(Ipv6Addr::LOCALHOST, 128)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        );
        assert!(!filter.matches_route_event(&event));
    }
}
