use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::commands::control::rpki_vrp_count_sum;
use crate::connection::Connection;
use crate::proto::control_service_client::ControlServiceClient;
use crate::proto::event_service_client::EventServiceClient;
use crate::proto::global_service_client::GlobalServiceClient;
use crate::proto::neighbor_service_client::NeighborServiceClient;
use crate::proto::rib_service_client::RibServiceClient;
use crate::proto::{
    BgpEvent, BgpEventType, EventCategory, GetGlobalRequest, GlobalState, HealthRequest,
    HealthResponse, ListDynamicNeighborsRequest, ListNeighborsRequest, MetricsRequest,
    NeighborState, RouteEvent, RouteEventType, WatchEventsRequest, WatchRoutesRequest, bgp_event,
};

pub struct DataSnapshot {
    pub global: Option<GlobalState>,
    pub global_freshness: Freshness,
    pub health: Option<HealthResponse>,
    pub health_fresh: bool,
    pub neighbors: Vec<NeighborState>,
    pub neighbors_freshness: Freshness,
    pub dynamic_range_count: Option<usize>,
    pub dynamic_ranges_freshness: Freshness,
    pub rpki_vrp_count: Option<u64>,
    pub metrics_freshness: Freshness,
    pub error: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Freshness {
    Fresh,
    Stale,
    Unavailable,
}

pub struct RouteEventEntry {
    pub kind: RouteEventKind,
    pub timestamp: String,
    pub event_type: String,
    pub prefix: String,
    pub peer_address: String,
    pub previous_peer_address: String,
    pub target_peer_address: String,
    pub reason: String,
    pub path_id: u32,
    pub missed_count: u64,
}

pub enum RouteEventKind {
    Route,
    StreamLag,
}

pub enum RouteEventUpdate {
    Event(RouteEventEntry),
    StreamStatus(Option<String>),
}

pub(super) struct FetcherHandle(JoinHandle<()>, JoinHandle<()>);

impl Drop for FetcherHandle {
    fn drop(&mut self) {
        self.0.abort();
        self.1.abort();
    }
}

fn format_event_type(t: BgpEventType) -> &'static str {
    match t {
        BgpEventType::RouteAdded => "added",
        BgpEventType::RouteWithdrawn => "withdrawn",
        BgpEventType::RouteBestChanged => "best_changed",
        BgpEventType::RoutePolicyFiltered => "policy_filtered",
        BgpEventType::StreamLagged => "stream_lagged",
        _ => "unknown",
    }
}

fn format_legacy_event_type(t: i32) -> &'static str {
    match RouteEventType::try_from(t) {
        Ok(RouteEventType::Added) => "added",
        Ok(RouteEventType::Withdrawn) => "withdrawn",
        Ok(RouteEventType::BestChanged) => "best_changed",
        Ok(RouteEventType::PolicyFiltered) => "policy_filtered",
        _ => "unknown",
    }
}

fn parse_vrp_count(prometheus_text: &str) -> Option<u64> {
    rpki_vrp_count_sum(prometheus_text)
}

const METRICS_POLL_INTERVAL: Duration = Duration::from_secs(60);
const DYNAMIC_RANGES_POLL_INTERVAL: Duration = Duration::from_secs(60);
const ROUTE_STREAM_RECONNECT_BACKOFF: Duration = Duration::from_secs(2);
const LEGACY_ROUTE_STREAM_WARNING: &str =
    "DEGRADED: WatchEvents unsupported; using legacy WatchRoutes; missed-event counts unavailable";

struct FetcherState {
    global: Option<GlobalState>,
    health: Option<HealthResponse>,
    neighbors: Option<Vec<NeighborState>>,
    dynamic_range_count: Option<usize>,
    dynamic_ranges_freshness: Freshness,
    next_dynamic_ranges_poll: Instant,
    rpki_vrp_count: Option<u64>,
    metrics_freshness: Freshness,
    next_metrics_poll: Instant,
}

impl FetcherState {
    fn new() -> Self {
        Self {
            global: None,
            health: None,
            neighbors: None,
            dynamic_range_count: None,
            dynamic_ranges_freshness: Freshness::Unavailable,
            next_dynamic_ranges_poll: Instant::now(),
            rpki_vrp_count: None,
            metrics_freshness: Freshness::Unavailable,
            next_metrics_poll: Instant::now(),
        }
    }
}

pub(super) fn spawn_fetcher(
    connection: Connection,
    interval: Duration,
    data_tx: mpsc::Sender<DataSnapshot>,
    event_tx: mpsc::Sender<RouteEventUpdate>,
    event_watch: watch::Receiver<bool>,
) -> FetcherHandle {
    let route_fetcher = tokio::spawn(route_event_loop(connection.clone(), event_tx, event_watch));
    let poller = tokio::spawn(async move {
        // Poll loop
        let mut state = FetcherState::new();
        loop {
            let snapshot = poll_once(&connection, &mut state).await;
            if data_tx.send(snapshot).await.is_err() {
                break;
            }
            tokio::time::sleep(interval).await;
        }
    });
    FetcherHandle(poller, route_fetcher)
}

async fn poll_once(connection: &Connection, state: &mut FetcherState) -> DataSnapshot {
    let mut error = None;

    let global_freshness = if state.global.is_some() {
        Freshness::Fresh
    } else {
        let mut client =
            GlobalServiceClient::with_interceptor(connection.channel(), connection.interceptor());
        if let Ok(response) = client.get_global(GetGlobalRequest {}).await {
            state.global = Some(response.into_inner());
        }
        if state.global.is_some() {
            Freshness::Fresh
        } else {
            Freshness::Unavailable
        }
    };

    let (health, health_fresh) = {
        let mut client =
            ControlServiceClient::with_interceptor(connection.channel(), connection.interceptor());
        match client.get_health(HealthRequest {}).await {
            Ok(r) => {
                state.health = Some(r.into_inner());
                (state.health.clone(), true)
            }
            Err(e) => {
                error = Some(e.message().to_string());
                (state.health.clone(), false)
            }
        }
    };

    let neighbors_freshness = {
        let mut client =
            NeighborServiceClient::with_interceptor(connection.channel(), connection.interceptor());
        match client.list_neighbors(ListNeighborsRequest {}).await {
            Ok(r) => {
                state.neighbors = Some(r.into_inner().neighbors);
                Freshness::Fresh
            }
            Err(e) => {
                if error.is_none() {
                    error = Some(e.message().to_string());
                }
                if state.neighbors.is_some() {
                    Freshness::Stale
                } else {
                    Freshness::Unavailable
                }
            }
        }
    };
    let neighbors = state.neighbors.clone().unwrap_or_default();

    let now = Instant::now();
    if neighbors_freshness == Freshness::Fresh {
        if neighbors.is_empty() {
            if now >= state.next_dynamic_ranges_poll {
                state.next_dynamic_ranges_poll = now + DYNAMIC_RANGES_POLL_INTERVAL;
                let mut client = NeighborServiceClient::with_interceptor(
                    connection.channel(),
                    connection.interceptor(),
                );
                match client
                    .list_dynamic_neighbors(ListDynamicNeighborsRequest {})
                    .await
                {
                    Ok(response) => {
                        state.dynamic_range_count = Some(response.into_inner().ranges.len());
                        state.dynamic_ranges_freshness = Freshness::Fresh;
                    }
                    Err(_) => {
                        state.dynamic_ranges_freshness = if state.dynamic_range_count.is_some() {
                            Freshness::Stale
                        } else {
                            Freshness::Unavailable
                        };
                    }
                }
            }
        } else {
            // A live roster does not need dormant-range inventory. Re-arm the
            // deadline so the next fresh transition to empty fetches at once.
            state.next_dynamic_ranges_poll = now;
        }
    }

    if now >= state.next_metrics_poll {
        state.next_metrics_poll = now + METRICS_POLL_INTERVAL;
        let mut client =
            ControlServiceClient::with_interceptor(connection.channel(), connection.interceptor());
        match client.get_metrics(MetricsRequest {}).await {
            Ok(response) => {
                state.rpki_vrp_count = parse_vrp_count(&response.into_inner().prometheus_text);
                state.metrics_freshness = Freshness::Fresh;
            }
            Err(_) => {
                if state.metrics_freshness != Freshness::Unavailable {
                    state.metrics_freshness = Freshness::Stale;
                }
            }
        }
    }

    DataSnapshot {
        global: state.global.clone(),
        global_freshness,
        health,
        health_fresh,
        neighbors,
        neighbors_freshness,
        dynamic_range_count: state.dynamic_range_count,
        dynamic_ranges_freshness: state.dynamic_ranges_freshness,
        rpki_vrp_count: state.rpki_vrp_count,
        metrics_freshness: state.metrics_freshness,
        error,
    }
}

async fn route_event_loop(
    connection: Connection,
    event_tx: mpsc::Sender<RouteEventUpdate>,
    mut enabled: watch::Receiver<bool>,
) {
    loop {
        while !*enabled.borrow_and_update() {
            if enabled.changed().await.is_err() {
                return;
            }
        }

        let completed = tokio::select! {
            _ = stream_route_events(&connection, &event_tx) => true,
            changed = enabled.changed() => {
                if changed.is_err() {
                    return;
                }
                false
            }
        };
        if !completed {
            continue;
        }

        tokio::select! {
            _ = tokio::time::sleep(ROUTE_STREAM_RECONNECT_BACKOFF) => {}
            changed = enabled.changed() => {
                if changed.is_err() {
                    return;
                }
            }
        }
    }
}

enum PrimaryStreamOutcome {
    Unsupported,
    Finished(Result<(), tonic::Status>),
}

async fn stream_route_events(connection: &Connection, event_tx: &mpsc::Sender<RouteEventUpdate>) {
    match stream_events(connection, event_tx).await {
        PrimaryStreamOutcome::Unsupported => {
            if send_stream_status(event_tx, LEGACY_ROUTE_STREAM_WARNING.to_string()).await
                && let Err(error) = stream_routes(connection, event_tx).await
            {
                let status = format!(
                    "{LEGACY_ROUTE_STREAM_WARNING}; legacy stream error: {}; retrying",
                    error.message()
                );
                send_stream_status(event_tx, status).await;
            }
        }
        PrimaryStreamOutcome::Finished(Err(error)) => {
            let status = format!("route event stream error: {}; retrying", error.message());
            send_stream_status(event_tx, status).await;
        }
        PrimaryStreamOutcome::Finished(Ok(())) => {}
    }
}

async fn send_stream_status(event_tx: &mpsc::Sender<RouteEventUpdate>, status: String) -> bool {
    event_tx
        .send(RouteEventUpdate::StreamStatus(Some(status)))
        .await
        .is_ok()
}

async fn stream_events(
    connection: &Connection,
    event_tx: &mpsc::Sender<RouteEventUpdate>,
) -> PrimaryStreamOutcome {
    let mut client =
        EventServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let mut stream = match client
        .watch_events(WatchEventsRequest {
            categories: vec![EventCategory::Route as i32],
            ..Default::default()
        })
        .await
    {
        Ok(response) => response.into_inner(),
        Err(error) if error.code() == tonic::Code::Unimplemented => {
            return PrimaryStreamOutcome::Unsupported;
        }
        Err(error) => return PrimaryStreamOutcome::Finished(Err(error)),
    };
    if event_tx
        .send(RouteEventUpdate::StreamStatus(None))
        .await
        .is_err()
    {
        return PrimaryStreamOutcome::Finished(Ok(()));
    }

    loop {
        match stream.message().await {
            Ok(Some(event)) => {
                if let Some(entry) = route_event_entry(event)
                    && event_tx.send(RouteEventUpdate::Event(entry)).await.is_err()
                {
                    return PrimaryStreamOutcome::Finished(Ok(()));
                }
            }
            Ok(None) => return PrimaryStreamOutcome::Finished(Ok(())),
            Err(error) => return PrimaryStreamOutcome::Finished(Err(error)),
        }
    }
}

fn route_event_entry(event: BgpEvent) -> Option<RouteEventEntry> {
    let event_type = BgpEventType::try_from(event.event_type).ok()?;
    match event.payload? {
        bgp_event::Payload::Route(route)
            if matches!(
                event_type,
                BgpEventType::RouteAdded
                    | BgpEventType::RouteWithdrawn
                    | BgpEventType::RouteBestChanged
                    | BgpEventType::RoutePolicyFiltered
            ) =>
        {
            Some(route_entry(format_event_type(event_type), route))
        }
        bgp_event::Payload::StreamLag(lag) if event_type == BgpEventType::StreamLagged => {
            Some(RouteEventEntry {
                kind: RouteEventKind::StreamLag,
                timestamp: event.timestamp,
                event_type: format_event_type(event_type).to_string(),
                prefix: String::new(),
                peer_address: String::new(),
                previous_peer_address: String::new(),
                target_peer_address: String::new(),
                reason: lag.reason,
                path_id: 0,
                missed_count: lag.missed_count,
            })
        }
        _ => None,
    }
}

fn route_entry(event_type: &str, event: RouteEvent) -> RouteEventEntry {
    RouteEventEntry {
        kind: RouteEventKind::Route,
        timestamp: event.timestamp,
        event_type: event_type.to_string(),
        prefix: format!("{}/{}", event.prefix, event.prefix_length),
        peer_address: event.peer_address,
        previous_peer_address: event.previous_peer_address,
        target_peer_address: event.target_peer_address,
        reason: event.reason,
        path_id: event.path_id,
        missed_count: 0,
    }
}

async fn stream_routes(
    connection: &Connection,
    event_tx: &mpsc::Sender<RouteEventUpdate>,
) -> Result<(), tonic::Status> {
    let mut client =
        RibServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let mut stream = client
        .watch_routes(WatchRoutesRequest {
            neighbor_address: String::new(),
            afi_safi: 0,
        })
        .await?
        .into_inner();

    while let Some(event) = stream.message().await? {
        let event_type = format_legacy_event_type(event.event_type);
        if event_tx
            .send(RouteEventUpdate::Event(route_entry(event_type, event)))
            .await
            .is_err()
        {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::connection::connect;
    use crate::test_support::spawn_mock_server;

    async fn wait_for(mut predicate: impl FnMut() -> bool) {
        for _ in 0..1_000 {
            if predicate() {
                return;
            }
            tokio::task::yield_now().await;
        }
        assert!(predicate(), "condition did not become true");
    }

    async fn settle_tasks() {
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }
    }

    fn policy_event(summary: &str) -> rustbgpd_api::proto::BgpEvent {
        rustbgpd_api::proto::BgpEvent {
            timestamp: "2026-08-03T12:00:00Z".into(),
            category: EventCategory::Route as i32,
            event_type: BgpEventType::RoutePolicyFiltered as i32,
            summary: summary.into(),
            payload: Some(rustbgpd_api::proto::bgp_event::Payload::Route(
                rustbgpd_api::proto::RouteEvent {
                    event_type: RouteEventType::PolicyFiltered as i32,
                    prefix: "203.0.113.0".into(),
                    prefix_length: 24,
                    peer_address: "192.0.2.1".into(),
                    previous_peer_address: "192.0.2.2".into(),
                    target_peer_address: "192.0.2.3".into(),
                    timestamp: "2026-08-03T12:00:00Z".into(),
                    path_id: 77,
                    reason: "policy_denied".into(),
                    ..Default::default()
                },
            )),
            ..Default::default()
        }
    }

    fn lag_event(summary: &str) -> rustbgpd_api::proto::BgpEvent {
        rustbgpd_api::proto::BgpEvent {
            timestamp: "2026-08-03T12:00:01Z".into(),
            category: EventCategory::Route as i32,
            event_type: BgpEventType::StreamLagged as i32,
            summary: summary.into(),
            payload: Some(rustbgpd_api::proto::bgp_event::Payload::StreamLag(
                rustbgpd_api::proto::StreamLagEvent {
                    source_category: EventCategory::Route as i32,
                    missed_count: 7,
                    reason: "receiver_lagged".into(),
                },
            )),
            ..Default::default()
        }
    }

    async fn next_event(event_rx: &mut mpsc::Receiver<RouteEventUpdate>) -> RouteEventEntry {
        loop {
            match event_rx.recv().await.unwrap() {
                RouteEventUpdate::Event(event) => return event,
                RouteEventUpdate::StreamStatus(_) => {}
            }
        }
    }

    fn dynamic_range_calls(server: &crate::test_support::MockServerHandle) -> usize {
        server
            .state
            .list_dynamic_neighbors_calls
            .load(Ordering::SeqCst)
    }

    async fn assert_route_reconnect_backoff(server: &crate::test_support::MockServerHandle) {
        *server.state.watch_events_admission_error.lock().await = Some((
            tonic::Code::Unimplemented,
            "WatchEvents unavailable on this daemon".into(),
        ));
        let connection = connect(&server.addr, None).await.unwrap();
        let (enabled_tx, enabled_rx) = watch::channel(true);
        let (event_tx, _event_rx) = mpsc::channel(8);
        let task = tokio::spawn(route_event_loop(connection, event_tx, enabled_rx));

        wait_for(|| server.state.watch_routes_calls.load(Ordering::SeqCst) == 1).await;
        wait_for(|| {
            server
                .state
                .watch_routes_terminations
                .load(Ordering::SeqCst)
                == 1
        })
        .await;
        settle_tasks().await;
        tokio::time::advance(ROUTE_STREAM_RECONNECT_BACKOFF - Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(server.state.watch_events_calls.load(Ordering::SeqCst), 1);
        assert_eq!(server.state.watch_routes_calls.load(Ordering::SeqCst), 1);

        tokio::time::advance(Duration::from_millis(1)).await;
        wait_for(|| server.state.watch_events_calls.load(Ordering::SeqCst) == 2).await;
        wait_for(|| server.state.watch_routes_calls.load(Ordering::SeqCst) == 2).await;

        drop(enabled_tx);
        task.abort();
        let _ = task.await;
    }

    /// Red proof: the old polling parser loses this production-shaped value.
    #[tokio::test]
    async fn rpki_vrp_count_uses_the_exported_family() {
        let server = spawn_mock_server(None).await;
        *server.state.metrics_text.lock().await = Some(
            "bgp_rpki_vrp_count{af=\"ipv4\"} 12\nbgp_rpki_vrp_count{af=\"ipv6\"} 3\n".to_string(),
        );
        let connection = connect(&server.addr, None).await.unwrap();
        let mut state = FetcherState::new();
        assert_eq!(
            poll_once(&connection, &mut state).await.rpki_vrp_count,
            Some(15)
        );
    }

    /// Red proof: putting `GetMetrics` back in every fast poll raises the
    /// pre-deadline call count from one to thirty.
    #[tokio::test(start_paused = true)]
    async fn metrics_scrape_has_an_independent_slow_cadence() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        let mut state = FetcherState::new();

        poll_once(&connection, &mut state).await;
        for _ in 0..29 {
            tokio::time::advance(Duration::from_secs(2)).await;
            poll_once(&connection, &mut state).await;
        }

        assert_eq!(server.state.metrics_calls.load(Ordering::SeqCst), 1);
        assert_eq!(server.state.health_calls.load(Ordering::SeqCst), 30);
        assert_eq!(server.state.list_neighbors_calls.load(Ordering::SeqCst), 30);

        tokio::time::advance(Duration::from_secs(2)).await;
        poll_once(&connection, &mut state).await;
        assert_eq!(server.state.metrics_calls.load(Ordering::SeqCst), 2);
    }

    /// Red proof: polling dormant inventory on the normal two-second cadence
    /// raises the pre-deadline call count from one to thirty.
    #[tokio::test(start_paused = true)]
    async fn dynamic_ranges_fetch_immediately_then_use_a_slow_empty_cadence() {
        let server = spawn_mock_server(None).await;
        *server.state.list_dynamic_neighbors_response.lock().await =
            vec![rustbgpd_api::proto::DynamicNeighborRange::default(); 2];
        let connection = connect(&server.addr, None).await.unwrap();
        let mut state = FetcherState::new();

        let first = poll_once(&connection, &mut state).await;
        assert_eq!(first.dynamic_range_count, Some(2));
        assert_eq!(first.dynamic_ranges_freshness, Freshness::Fresh);
        for _ in 0..29 {
            tokio::time::advance(Duration::from_secs(2)).await;
            poll_once(&connection, &mut state).await;
        }
        assert_eq!(dynamic_range_calls(&server), 1);

        tokio::time::advance(Duration::from_secs(2)).await;
        poll_once(&connection, &mut state).await;
        assert_eq!(dynamic_range_calls(&server), 2);
    }

    /// Red proof: querying with a live roster increments the first assertion;
    /// removing the re-arm leaves the transition-to-empty count at zero.
    #[tokio::test(start_paused = true)]
    async fn nonempty_roster_skips_dynamic_ranges_and_rearms_next_empty_fetch() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        let mut state = FetcherState::new();

        server
            .state
            .list_neighbors_failures_remaining
            .store(1, Ordering::SeqCst);
        poll_once(&connection, &mut state).await;
        assert_eq!(dynamic_range_calls(&server), 0);

        *server.state.list_neighbors_response.lock().await =
            vec![rustbgpd_api::proto::NeighborState::default()];
        poll_once(&connection, &mut state).await;
        assert_eq!(dynamic_range_calls(&server), 0);

        server.state.list_neighbors_response.lock().await.clear();
        poll_once(&connection, &mut state).await;
        assert_eq!(dynamic_range_calls(&server), 1);

        tokio::time::advance(Duration::from_secs(2)).await;
        *server.state.list_neighbors_response.lock().await =
            vec![rustbgpd_api::proto::NeighborState::default()];
        poll_once(&connection, &mut state).await;
        assert_eq!(dynamic_range_calls(&server), 1);

        server.state.list_neighbors_response.lock().await.clear();
        poll_once(&connection, &mut state).await;
        assert_eq!(dynamic_range_calls(&server), 2);
    }

    /// Red proof: folding the optional RPC into the core error path marks this
    /// otherwise healthy snapshot disconnected.
    #[tokio::test(start_paused = true)]
    async fn initial_dynamic_range_failure_is_unavailable_without_disconnect() {
        let server = spawn_mock_server(None).await;
        *server.state.list_dynamic_neighbors_error.lock().await = Some((
            tonic::Code::Unavailable,
            "range inventory unavailable".into(),
        ));
        let connection = connect(&server.addr, None).await.unwrap();
        let mut state = FetcherState::new();

        let snapshot = poll_once(&connection, &mut state).await;

        assert_eq!(snapshot.dynamic_range_count, None);
        assert_eq!(snapshot.dynamic_ranges_freshness, Freshness::Unavailable);
        assert!(snapshot.error.is_none());
        assert_eq!(dynamic_range_calls(&server), 1);

        tokio::time::advance(DYNAMIC_RANGES_POLL_INTERVAL - Duration::from_millis(1)).await;
        poll_once(&connection, &mut state).await;
        assert_eq!(dynamic_range_calls(&server), 1);

        tokio::time::advance(Duration::from_millis(1)).await;
        poll_once(&connection, &mut state).await;
        assert_eq!(dynamic_range_calls(&server), 2);
    }

    /// Red proof: clearing the last-good zero on failure makes an unknown
    /// inventory indistinguishable from a proven unconfigured daemon.
    #[tokio::test(start_paused = true)]
    async fn dynamic_range_failure_retains_last_good_zero_as_stale() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        let mut state = FetcherState::new();

        let first = poll_once(&connection, &mut state).await;
        assert_eq!(first.dynamic_range_count, Some(0));
        assert_eq!(first.dynamic_ranges_freshness, Freshness::Fresh);

        *server.state.list_dynamic_neighbors_error.lock().await = Some((
            tonic::Code::Unavailable,
            "range inventory unavailable".into(),
        ));
        tokio::time::advance(DYNAMIC_RANGES_POLL_INTERVAL).await;
        let failed = poll_once(&connection, &mut state).await;

        assert_eq!(failed.dynamic_range_count, Some(0));
        assert_eq!(failed.dynamic_ranges_freshness, Freshness::Stale);
        assert!(failed.error.is_none());
    }

    /// Red proof: restoring the one-shot startup fetch leaves the second
    /// snapshot's global metadata absent after the first RPC fails.
    #[tokio::test(start_paused = true)]
    async fn global_metadata_retries_until_success_then_stays_cached() {
        let server = spawn_mock_server(None).await;
        server
            .state
            .global_failures_remaining
            .store(1, Ordering::SeqCst);
        let connection = connect(&server.addr, None).await.unwrap();
        let mut state = FetcherState::new();

        let first = poll_once(&connection, &mut state).await;
        assert!(first.global.is_none());
        assert_eq!(first.global_freshness, Freshness::Unavailable);
        assert!(first.error.is_none());

        tokio::time::advance(Duration::from_secs(2)).await;
        let second = poll_once(&connection, &mut state).await;
        assert_eq!(second.global.as_ref().map(|global| global.asn), Some(65001));
        assert_eq!(second.global_freshness, Freshness::Fresh);

        tokio::time::advance(Duration::from_secs(2)).await;
        let third = poll_once(&connection, &mut state).await;
        assert_eq!(third.global.as_ref().map(|global| global.asn), Some(65001));
        assert_eq!(third.global_freshness, Freshness::Fresh);
        assert_eq!(server.state.global_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn initial_metrics_failure_is_unavailable_without_disconnect() {
        let server = spawn_mock_server(None).await;
        server
            .state
            .metrics_failures_remaining
            .store(1, Ordering::SeqCst);
        let connection = connect(&server.addr, None).await.unwrap();
        let mut state = FetcherState::new();

        let snapshot = poll_once(&connection, &mut state).await;

        assert_eq!(snapshot.rpki_vrp_count, None);
        assert_eq!(snapshot.metrics_freshness, Freshness::Unavailable);
        assert!(snapshot.error.is_none());
        assert_eq!(server.state.metrics_calls.load(Ordering::SeqCst), 1);
    }

    /// Red proof: clearing the cached VRP value on a failed slow scrape makes
    /// the second snapshot report `None` instead of the last-good count.
    #[tokio::test(start_paused = true)]
    async fn metrics_failure_retains_last_good_vrp_count() {
        let server = spawn_mock_server(None).await;
        *server.state.metrics_text.lock().await = Some(
            "bgp_rpki_vrp_count{af=\"ipv4\"} 12\nbgp_rpki_vrp_count{af=\"ipv6\"} 3\n".to_string(),
        );
        let connection = connect(&server.addr, None).await.unwrap();
        let mut state = FetcherState::new();

        let first = poll_once(&connection, &mut state).await;
        assert_eq!(first.rpki_vrp_count, Some(15));
        assert_eq!(first.metrics_freshness, Freshness::Fresh);

        server
            .state
            .metrics_failures_remaining
            .store(1, Ordering::SeqCst);
        tokio::time::advance(METRICS_POLL_INTERVAL).await;
        let second = poll_once(&connection, &mut state).await;

        assert_eq!(second.rpki_vrp_count, Some(15));
        assert_eq!(second.metrics_freshness, Freshness::Stale);
        assert!(second.error.is_none());
        assert_eq!(server.state.metrics_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn successful_metrics_without_rpki_family_clears_last_good_count() {
        let server = spawn_mock_server(None).await;
        *server.state.metrics_text.lock().await = Some(
            "bgp_rpki_vrp_count{af=\"ipv4\"} 12\nbgp_rpki_vrp_count{af=\"ipv6\"} 3\n".to_string(),
        );
        let connection = connect(&server.addr, None).await.unwrap();
        let mut state = FetcherState::new();

        let first = poll_once(&connection, &mut state).await;
        assert_eq!(first.rpki_vrp_count, Some(15));
        *server.state.metrics_text.lock().await = Some("# HELP other_metric 1\n".to_string());
        tokio::time::advance(METRICS_POLL_INTERVAL).await;
        let second = poll_once(&connection, &mut state).await;

        assert_eq!(second.rpki_vrp_count, None);
        assert_eq!(second.metrics_freshness, Freshness::Fresh);
        assert!(second.error.is_none());
        assert_eq!(server.state.metrics_calls.load(Ordering::SeqCst), 2);
    }

    /// Red proof: starting the primary stream while disabled or failing to
    /// cancel its response changes the zero/active assertions.
    #[tokio::test]
    async fn route_stream_is_opt_in_and_cancellable() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        let (enabled_tx, enabled_rx) = watch::channel(false);
        let (event_tx, mut event_rx) = mpsc::channel(1);
        let (data_tx, mut data_rx) = mpsc::channel(1);
        let task = spawn_fetcher(
            connection,
            Duration::from_secs(60),
            data_tx,
            event_tx,
            enabled_rx,
        );

        data_rx.recv().await.unwrap();
        settle_tasks().await;
        assert_eq!(server.state.watch_events_calls.load(Ordering::SeqCst), 0);

        enabled_tx.send(true).unwrap();
        wait_for(|| server.state.watch_events_calls.load(Ordering::SeqCst) == 1).await;
        wait_for(|| server.state.watch_events_active.load(Ordering::SeqCst) == 1).await;
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), event_rx.recv()).await,
            Ok(Some(RouteEventUpdate::StreamStatus(None)))
        ));

        enabled_tx.send(false).unwrap();
        wait_for(|| server.state.watch_events_active.load(Ordering::SeqCst) == 0).await;
        assert_eq!(server.state.watch_events_calls.load(Ordering::SeqCst), 1);

        enabled_tx.send(true).unwrap();
        wait_for(|| server.state.watch_events_active.load(Ordering::SeqCst) == 1).await;
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), event_rx.recv()).await,
            Ok(Some(RouteEventUpdate::StreamStatus(None)))
        ));
        drop(task);
        wait_for(|| server.state.watch_events_active.load(Ordering::SeqCst) == 0).await;
    }

    /// Red proof: detaching the fallback stream from the visibility select
    /// leaves its active counter nonzero after hide and handle drop.
    #[tokio::test]
    async fn legacy_fallback_is_cancellable() {
        let server = spawn_mock_server(None).await;
        *server.state.watch_events_admission_error.lock().await =
            Some((tonic::Code::Unimplemented, "old daemon".into()));
        let connection = connect(&server.addr, None).await.unwrap();
        let (enabled_tx, enabled_rx) = watch::channel(true);
        let (event_tx, _event_rx) = mpsc::channel(4);
        let task = tokio::spawn(route_event_loop(connection, event_tx, enabled_rx));

        wait_for(|| server.state.watch_routes_active.load(Ordering::SeqCst) == 1).await;
        enabled_tx.send(false).unwrap();
        wait_for(|| server.state.watch_routes_active.load(Ordering::SeqCst) == 0).await;
        enabled_tx.send(true).unwrap();
        wait_for(|| server.state.watch_routes_active.load(Ordering::SeqCst) == 1).await;
        task.abort();
        let _ = task.await;
        wait_for(|| server.state.watch_routes_active.load(Ordering::SeqCst) == 0).await;
    }

    /// Red proof: broadening fallback beyond admission UNIMPLEMENTED makes the
    /// PermissionDenied and Unavailable rows call legacy WatchRoutes.
    #[tokio::test]
    async fn only_admission_unimplemented_enters_legacy_stream() {
        for (code, expected_legacy_calls) in [
            (tonic::Code::Unimplemented, 1),
            (tonic::Code::PermissionDenied, 0),
            (tonic::Code::Unavailable, 0),
        ] {
            let server = spawn_mock_server(None).await;
            *server.state.watch_events_admission_error.lock().await =
                Some((code, "primary admission rejected".into()));
            let connection = connect(&server.addr, None).await.unwrap();
            let (_enabled_tx, enabled_rx) = watch::channel(true);
            let (event_tx, mut event_rx) = mpsc::channel(4);
            let task = tokio::spawn(route_event_loop(connection, event_tx, enabled_rx));

            wait_for(|| server.state.watch_events_calls.load(Ordering::SeqCst) == 1).await;
            settle_tasks().await;
            assert_eq!(
                server.state.watch_routes_calls.load(Ordering::SeqCst),
                expected_legacy_calls,
                "admission status {code:?}"
            );
            let RouteEventUpdate::StreamStatus(Some(status)) = event_rx.recv().await.unwrap()
            else {
                panic!("stream admission must publish visible status");
            };
            if code == tonic::Code::Unimplemented {
                assert_eq!(
                    status,
                    "DEGRADED: WatchEvents unsupported; using legacy WatchRoutes; missed-event counts unavailable"
                );
            }
            task.abort();
            let _ = task.await;
        }
    }

    /// Red proof: switching the primary RPC back to WatchRoutes, accepting a
    /// non-route event type by numeric coincidence, or reading lag from the
    /// conflicting summary breaks these assertions.
    #[tokio::test]
    async fn primary_stream_preserves_policy_context_and_exact_lag_count() {
        let server = spawn_mock_server(None).await;
        let mut non_route = policy_event("must be ignored");
        non_route.event_type = BgpEventType::SessionEstablished as i32;
        *server.state.watch_events_response.lock().await = vec![
            non_route,
            policy_event("misleading policy summary"),
            lag_event("missed 999 events"),
        ];
        let connection = connect(&server.addr, None).await.unwrap();
        let (_enabled_tx, enabled_rx) = watch::channel(true);
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let task = tokio::spawn(route_event_loop(connection, event_tx, enabled_rx));

        let policy = next_event(&mut event_rx).await;
        let lag = next_event(&mut event_rx).await;
        assert_eq!(server.state.watch_events_calls.load(Ordering::SeqCst), 1);
        assert_eq!(server.state.watch_routes_calls.load(Ordering::SeqCst), 0);
        let request = server.state.last_watch_events.lock().await.clone().unwrap();
        assert_eq!(request.categories, vec![EventCategory::Route as i32]);
        assert!(request.event_types.is_empty());
        assert_eq!(policy.event_type, "policy_filtered");
        assert_eq!(policy.peer_address, "192.0.2.1");
        assert_eq!(policy.previous_peer_address, "192.0.2.2");
        assert_eq!(policy.target_peer_address, "192.0.2.3");
        assert_eq!(policy.reason, "policy_denied");
        assert_eq!(policy.path_id, 77);
        assert_eq!(lag.event_type, "stream_lagged");
        assert_eq!(lag.missed_count, 7);
        assert_eq!(lag.reason, "receiver_lagged");
        task.abort();
        let _ = task.await;
    }

    /// Red proof: bypassing the typed legacy mapper drops one or more policy
    /// source/previous/target/reason/path fields from the fallback result.
    #[tokio::test]
    async fn legacy_fallback_preserves_policy_context_through_mock_grpc() {
        let server = spawn_mock_server(None).await;
        *server.state.watch_events_admission_error.lock().await =
            Some((tonic::Code::Unimplemented, "old daemon".into()));
        let route = match policy_event("legacy policy summary").payload.unwrap() {
            rustbgpd_api::proto::bgp_event::Payload::Route(route) => route,
            _ => unreachable!(),
        };
        *server.state.watch_routes_response.lock().await = vec![route];
        let connection = connect(&server.addr, None).await.unwrap();
        let (_enabled_tx, enabled_rx) = watch::channel(true);
        let (event_tx, mut event_rx) = mpsc::channel(4);
        let task = tokio::spawn(route_event_loop(connection, event_tx, enabled_rx));

        let policy = next_event(&mut event_rx).await;
        assert_eq!(policy.event_type, "policy_filtered");
        assert_eq!(policy.peer_address, "192.0.2.1");
        assert_eq!(policy.previous_peer_address, "192.0.2.2");
        assert_eq!(policy.target_peer_address, "192.0.2.3");
        assert_eq!(policy.reason, "policy_denied");
        assert_eq!(policy.path_id, 77);
        task.abort();
        let _ = task.await;
    }

    /// Red proof: decoding the legacy enum as BgpEventType makes the invalid
    /// legacy value inherit an unrelated BGP-event label.
    #[test]
    fn legacy_route_event_type_has_an_independent_mapping() {
        assert_eq!(
            format_legacy_event_type(RouteEventType::PolicyFiltered as i32),
            "policy_filtered"
        );
        assert_eq!(
            format_legacy_event_type(BgpEventType::SessionEstablished as i32),
            "unknown"
        );
    }

    /// Red proof: treating a post-admission UNIMPLEMENTED as legacy support
    /// increments WatchRoutes instead of surfacing the primary error.
    #[tokio::test(start_paused = true)]
    async fn post_admission_unimplemented_never_falls_back() {
        let server = spawn_mock_server(None).await;
        *server.state.watch_events_stream_error.lock().await =
            Some((tonic::Code::Unimplemented, "stream item failed".into()));
        let connection = connect(&server.addr, None).await.unwrap();
        let (_enabled_tx, enabled_rx) = watch::channel(true);
        let (event_tx, mut event_rx) = mpsc::channel(4);
        let task = tokio::spawn(route_event_loop(connection, event_tx, enabled_rx));

        let mut visible_error = None;
        while visible_error.is_none() {
            if let RouteEventUpdate::StreamStatus(status) = event_rx.recv().await.unwrap() {
                visible_error = status;
            }
        }
        assert!(visible_error.unwrap().contains("stream item failed"));
        assert_eq!(server.state.watch_routes_calls.load(Ordering::SeqCst), 0);
        tokio::time::advance(ROUTE_STREAM_RECONNECT_BACKOFF - Duration::from_millis(1)).await;
        assert_eq!(server.state.watch_events_calls.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_millis(1)).await;
        wait_for(|| server.state.watch_events_calls.load(Ordering::SeqCst) == 2).await;
        task.abort();
        let _ = task.await;
    }

    /// Red proof: removing the clean-end delay increments the second-call
    /// assertion before its exact two-second deadline.
    #[tokio::test(start_paused = true)]
    async fn primary_clean_end_reprobes_primary_after_backoff() {
        let server = spawn_mock_server(None).await;
        server
            .state
            .watch_events_clean_end
            .store(true, Ordering::SeqCst);
        let connection = connect(&server.addr, None).await.unwrap();
        let (_enabled_tx, enabled_rx) = watch::channel(true);
        let (event_tx, _event_rx) = mpsc::channel(4);
        let task = tokio::spawn(route_event_loop(connection, event_tx, enabled_rx));

        wait_for(|| server.state.watch_events_calls.load(Ordering::SeqCst) == 1).await;
        wait_for(|| {
            server
                .state
                .watch_events_terminations
                .load(Ordering::SeqCst)
                == 1
        })
        .await;
        settle_tasks().await;
        tokio::time::advance(ROUTE_STREAM_RECONNECT_BACKOFF - Duration::from_millis(1)).await;
        assert_eq!(server.state.watch_events_calls.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_millis(1)).await;
        wait_for(|| server.state.watch_events_calls.load(Ordering::SeqCst) == 2).await;
        assert_eq!(server.state.watch_routes_calls.load(Ordering::SeqCst), 0);
        task.abort();
        let _ = task.await;
    }

    /// Red proof: removing the clean-end delay reconnects before the deadline.
    #[tokio::test(start_paused = true)]
    async fn clean_route_stream_end_uses_reconnect_backoff() {
        let server = spawn_mock_server(None).await;
        server
            .state
            .watch_routes_clean_end
            .store(true, Ordering::SeqCst);
        assert_route_reconnect_backoff(&server).await;
    }

    /// Red proof: removing the error delay reconnects before the deadline.
    #[tokio::test(start_paused = true)]
    async fn route_stream_error_uses_reconnect_backoff() {
        let server = spawn_mock_server(None).await;
        server
            .state
            .watch_routes_failures_remaining
            .store(1, Ordering::SeqCst);
        assert_route_reconnect_backoff(&server).await;
    }

    /// Red proof: calling first failure stale or dropping cached values changes assertions.
    #[tokio::test]
    async fn transient_poll_failure_retains_last_good_health_and_neighbors() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        let mut state = FetcherState::new();

        server
            .state
            .list_neighbors_failures_remaining
            .store(1, Ordering::SeqCst);
        let unavailable = poll_once(&connection, &mut state).await;
        assert_eq!(unavailable.neighbors_freshness, Freshness::Unavailable);
        let first = poll_once(&connection, &mut state).await;
        assert!(first.health_fresh);
        assert_eq!(first.neighbors_freshness, Freshness::Fresh);
        assert_eq!(
            first.health.as_ref().map(|health| health.total_routes),
            Some(10)
        );
        assert!(first.neighbors.is_empty());

        server
            .state
            .health_failures_remaining
            .store(1, Ordering::SeqCst);
        server
            .state
            .list_neighbors_failures_remaining
            .store(1, Ordering::SeqCst);
        let failed = poll_once(&connection, &mut state).await;

        assert!(!failed.health_fresh);
        assert_eq!(failed.neighbors_freshness, Freshness::Stale);
        assert_eq!(
            failed.health.as_ref().map(|health| health.total_routes),
            Some(10)
        );
        assert!(failed.neighbors.is_empty());
    }
}
