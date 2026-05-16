//! Unified live event stream service.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::pin::Pin;

use tokio::sync::oneshot;
use tokio_stream::Stream;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use tonic::{Request, Response, Status};
use tracing::debug;

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
}

impl EventService {
    #[must_use]
    pub fn new(rib_tx: tokio::sync::mpsc::Sender<RibUpdate>) -> Self {
        Self { rib_tx }
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
        if !self.categories.is_empty()
            && !self
                .categories
                .contains(&(proto::EventCategory::Route as i32))
        {
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
            proto::EventCategory::Route => {
                parsed.insert(category as i32);
            }
            proto::EventCategory::Unspecified => {
                return Err(Status::invalid_argument(
                    "EVENT_CATEGORY_UNSPECIFIED is not a valid filter",
                ));
            }
            proto::EventCategory::Session
            | proto::EventCategory::Policy
            | proto::EventCategory::Dataplane => {
                return Err(Status::invalid_argument(
                    "only EVENT_CATEGORY_ROUTE is supported by WatchEvents in this release",
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
            | proto::BgpEventType::RouteBestChanged => {
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
    let route = route_event_to_proto(event);
    let event_type = match proto::RouteEventType::try_from(route.event_type) {
        Ok(proto::RouteEventType::Added) => proto::BgpEventType::RouteAdded,
        Ok(proto::RouteEventType::Withdrawn) => proto::BgpEventType::RouteWithdrawn,
        Ok(proto::RouteEventType::BestChanged) => proto::BgpEventType::RouteBestChanged,
        _ => proto::BgpEventType::Unspecified,
    };
    let summary = format!(
        "route {} {}/{}",
        match event_type {
            proto::BgpEventType::RouteAdded => "added",
            proto::BgpEventType::RouteWithdrawn => "withdrawn",
            proto::BgpEventType::RouteBestChanged => "best changed",
            proto::BgpEventType::Unspecified => "changed",
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

        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::SubscribeRouteEvents { reply: reply_tx })
            .await
            .map_err(|_| Status::internal("RIB manager unavailable"))?;
        let broadcast_rx = reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?;

        let stream = BroadcastStream::new(broadcast_rx).filter_map(move |result| match result {
            Ok(event) => {
                if filter.matches_route_event(&event) {
                    Some(Ok(route_event_to_bgp_event(event)))
                } else {
                    None
                }
            }
            Err(_lagged) => {
                debug!("WatchEvents subscriber lagged, skipping missed events");
                None
            }
        });

        Ok(Response::new(Box::pin(stream)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::event_service_server::EventService as EventServiceTrait;
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

    #[tokio::test]
    async fn route_event_bridge_emits_bgp_event() {
        let (rib_tx, events_tx) = spawn_fake_rib();
        let service = EventService::new(rib_tx);
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
        let service = EventService::new(rib_tx);
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
    async fn rejects_unsupported_category_filter() {
        let (rib_tx, _) = spawn_fake_rib();
        let service = EventService::new(rib_tx);
        let Err(err) = service
            .watch_events(Request::new(proto::WatchEventsRequest {
                categories: vec![proto::EventCategory::Session as i32],
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
        let service = EventService::new(rib_tx);
        let response = service
            .watch_events(Request::new(proto::WatchEventsRequest::default()))
            .await
            .unwrap();
        assert_eq!(events_tx.receiver_count(), 1);
        drop(response);
        tokio::task::yield_now().await;
        assert_eq!(events_tx.receiver_count(), 0);
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
