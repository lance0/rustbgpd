use std::time::Duration;

use tokio::sync::mpsc;
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
    pub health: Option<HealthResponse>,
    pub neighbors: Vec<NeighborState>,
    pub rpki_vrp_count: Option<u64>,
    pub error: Option<String>,
}

pub struct RouteEventEntry {
    pub timestamp: String,
    pub event_type: String,
    pub prefix: String,
    pub peer_address: String,
    pub path_id: u32,
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

struct FetcherState {
    global: Option<GlobalState>,
    rpki_vrp_count: Option<u64>,
    next_metrics_poll: Instant,
}

impl FetcherState {
    fn new() -> Self {
        Self {
            global: None,
            rpki_vrp_count: None,
            next_metrics_poll: Instant::now(),
        }
    }
}

pub fn spawn_fetcher(
    connection: Connection,
    interval: Duration,
    data_tx: mpsc::Sender<DataSnapshot>,
    event_tx: mpsc::Sender<RouteEventEntry>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        // Spawn WatchRoutes stream in a sub-task
        let conn2 = connection.clone();
        let event_tx2 = event_tx.clone();
        tokio::spawn(async move {
            loop {
                let result = stream_routes(&conn2, &event_tx2).await;
                if result.is_err() {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        });

        // Poll loop
        let mut state = FetcherState::new();
        loop {
            let snapshot = poll_once(&connection, &mut state).await;
            if data_tx.send(snapshot).await.is_err() {
                break;
            }
            tokio::time::sleep(interval).await;
        }
    })
}

async fn poll_once(connection: &Connection, state: &mut FetcherState) -> DataSnapshot {
    let mut error = None;

    if state.global.is_none() {
        let mut client =
            GlobalServiceClient::with_interceptor(connection.channel(), connection.interceptor());
        if let Ok(response) = client.get_global(GetGlobalRequest {}).await {
            state.global = Some(response.into_inner());
        }
    }

    let health = {
        let mut client =
            ControlServiceClient::with_interceptor(connection.channel(), connection.interceptor());
        match client.get_health(HealthRequest {}).await {
            Ok(r) => Some(r.into_inner()),
            Err(e) => {
                error = Some(e.message().to_string());
                None
            }
        }
    };

    let neighbors = {
        let mut client =
            NeighborServiceClient::with_interceptor(connection.channel(), connection.interceptor());
        match client.list_neighbors(ListNeighborsRequest {}).await {
            Ok(r) => r.into_inner().neighbors,
            Err(e) => {
                if error.is_none() {
                    error = Some(e.message().to_string());
                }
                vec![]
            }
        }
    };

    let now = Instant::now();
    if now >= state.next_metrics_poll {
        state.next_metrics_poll = now + METRICS_POLL_INTERVAL;
        let mut client =
            ControlServiceClient::with_interceptor(connection.channel(), connection.interceptor());
        if let Ok(response) = client.get_metrics(MetricsRequest {}).await {
            state.rpki_vrp_count = parse_vrp_count(&response.into_inner().prometheus_text);
        }
    }

    DataSnapshot {
        global: state.global.clone(),
        health,
        neighbors,
        rpki_vrp_count: state.rpki_vrp_count,
        error,
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

        tokio::time::advance(Duration::from_secs(2)).await;
        let second = poll_once(&connection, &mut state).await;
        assert_eq!(second.global.as_ref().map(|global| global.asn), Some(65001));

        tokio::time::advance(Duration::from_secs(2)).await;
        let third = poll_once(&connection, &mut state).await;
        assert_eq!(third.global.as_ref().map(|global| global.asn), Some(65001));
        assert_eq!(server.state.global_calls.load(Ordering::SeqCst), 2);
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

        server
            .state
            .metrics_failures_remaining
            .store(1, Ordering::SeqCst);
        tokio::time::advance(METRICS_POLL_INTERVAL).await;
        let second = poll_once(&connection, &mut state).await;

        assert_eq!(second.rpki_vrp_count, Some(15));
        assert_eq!(server.state.metrics_calls.load(Ordering::SeqCst), 2);
    }
}
