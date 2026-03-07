use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

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
    for line in prometheus_text.lines() {
        if let Some(rest) = line.strip_prefix("rpki_vrp_count ") {
            return rest.trim().parse().ok();
        }
    }
    None
}

pub fn spawn_fetcher(
    connection: Connection,
    interval: Duration,
    data_tx: mpsc::Sender<DataSnapshot>,
    event_tx: mpsc::Sender<RouteEventEntry>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        // Fetch global once
        let global = {
            let mut client = GlobalServiceClient::with_interceptor(
                connection.channel(),
                connection.interceptor(),
            );
            client
                .get_global(GetGlobalRequest {})
                .await
                .ok()
                .map(|r| r.into_inner())
        };

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
        loop {
            let snapshot = poll_once(&connection, global.clone()).await;
            if data_tx.send(snapshot).await.is_err() {
                break;
            }
            tokio::time::sleep(interval).await;
        }
    })
}

async fn poll_once(connection: &Connection, global: Option<GlobalState>) -> DataSnapshot {
    let mut error = None;

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

    let rpki_vrp_count = {
        let mut client =
            ControlServiceClient::with_interceptor(connection.channel(), connection.interceptor());
        match client.get_metrics(MetricsRequest {}).await {
            Ok(r) => parse_vrp_count(&r.into_inner().prometheus_text),
            Err(_) => None,
        }
    };

    DataSnapshot {
        global,
        health,
        neighbors,
        rpki_vrp_count,
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
