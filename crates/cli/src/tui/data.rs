use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::commands::control::rpki_vrp_count_sum;
use crate::connection::Connection;
use crate::proto::control_service_client::ControlServiceClient;
use crate::proto::global_service_client::GlobalServiceClient;
use crate::proto::neighbor_service_client::NeighborServiceClient;
use crate::proto::rib_service_client::RibServiceClient;
use crate::proto::{
    GetGlobalRequest, GlobalState, HealthRequest, HealthResponse, ListNeighborsRequest,
    MetricsRequest, NeighborState, WatchRoutesRequest,
};

pub struct DataSnapshot {
    pub global: Option<GlobalState>,
    pub global_freshness: Freshness,
    pub health: Option<HealthResponse>,
    pub health_fresh: bool,
    pub neighbors: Vec<NeighborState>,
    pub neighbors_freshness: Freshness,
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
    pub timestamp: String,
    pub event_type: String,
    pub prefix: String,
    pub peer_address: String,
    pub path_id: u32,
}

pub(super) struct FetcherHandle(JoinHandle<()>, JoinHandle<()>);

impl Drop for FetcherHandle {
    fn drop(&mut self) {
        self.0.abort();
        self.1.abort();
    }
}

fn format_event_type(t: i32) -> &'static str {
    match t {
        1 => "added",
        2 => "withdrawn",
        3 => "best_changed",
        _ => "unknown",
    }
}

fn parse_vrp_count(prometheus_text: &str) -> Option<u64> {
    rpki_vrp_count_sum(prometheus_text)
}

const METRICS_POLL_INTERVAL: Duration = Duration::from_secs(60);
const ROUTE_STREAM_RECONNECT_BACKOFF: Duration = Duration::from_secs(2);

struct FetcherState {
    global: Option<GlobalState>,
    health: Option<HealthResponse>,
    neighbors: Option<Vec<NeighborState>>,
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
    event_tx: mpsc::Sender<RouteEventEntry>,
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
        rpki_vrp_count: state.rpki_vrp_count,
        metrics_freshness: state.metrics_freshness,
        error,
    }
}

async fn route_event_loop(
    connection: Connection,
    event_tx: mpsc::Sender<RouteEventEntry>,
    mut enabled: watch::Receiver<bool>,
) {
    loop {
        while !*enabled.borrow_and_update() {
            if enabled.changed().await.is_err() {
                return;
            }
        }

        let completed = tokio::select! {
            _ = stream_routes(&connection, &event_tx) => true,
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

async fn stream_routes(
    connection: &Connection,
    event_tx: &mpsc::Sender<RouteEventEntry>,
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
        let entry = RouteEventEntry {
            timestamp: event.timestamp,
            event_type: format_event_type(event.event_type).to_string(),
            prefix: format!("{}/{}", event.prefix, event.prefix_length),
            peer_address: event.peer_address,
            path_id: event.path_id,
        };
        if event_tx.send(entry).await.is_err() {
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

    async fn assert_route_reconnect_backoff(server: &crate::test_support::MockServerHandle) {
        let connection = connect(&server.addr, None).await.unwrap();
        let (enabled_tx, enabled_rx) = watch::channel(true);
        let (event_tx, _event_rx) = mpsc::channel(1);
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
        assert_eq!(server.state.watch_routes_calls.load(Ordering::SeqCst), 1);

        tokio::time::advance(Duration::from_millis(1)).await;
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

    /// Red proof: the old detached watcher starts early and survives final drop.
    #[tokio::test]
    async fn route_stream_is_opt_in_and_cancellable() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        let (enabled_tx, enabled_rx) = watch::channel(false);
        let (event_tx, _event_rx) = mpsc::channel(1);
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
        assert_eq!(server.state.watch_routes_calls.load(Ordering::SeqCst), 0);

        enabled_tx.send(true).unwrap();
        wait_for(|| server.state.watch_routes_calls.load(Ordering::SeqCst) == 1).await;
        wait_for(|| server.state.watch_routes_active.load(Ordering::SeqCst) == 1).await;

        enabled_tx.send(false).unwrap();
        wait_for(|| server.state.watch_routes_active.load(Ordering::SeqCst) == 0).await;
        assert_eq!(server.state.watch_routes_calls.load(Ordering::SeqCst), 1);

        enabled_tx.send(true).unwrap();
        wait_for(|| server.state.watch_routes_active.load(Ordering::SeqCst) == 1).await;
        drop(task);
        wait_for(|| server.state.watch_routes_active.load(Ordering::SeqCst) == 0).await;
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
