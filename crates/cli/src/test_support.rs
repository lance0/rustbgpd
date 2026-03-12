use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::net::TcpListener;
use tokio::sync::{Mutex, oneshot};
use tokio_stream::Stream;
use tokio_stream::wrappers::{TcpListenerStream, UnixListenerStream};
use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use rustbgpd_api::proto as server_proto;
use rustbgpd_api::proto::control_service_server::ControlServiceServer;
use rustbgpd_api::proto::global_service_server::GlobalServiceServer;
use rustbgpd_api::proto::neighbor_service_server::NeighborServiceServer;
use rustbgpd_api::proto::rib_service_server::RibServiceServer;

#[derive(Default)]
pub(crate) struct MockState {
    pub(crate) health_calls: AtomicUsize,
    pub(crate) global_calls: AtomicUsize,
    pub(crate) last_add_neighbor: Mutex<Option<server_proto::NeighborConfig>>,
    pub(crate) last_softreset: Mutex<Option<server_proto::SoftResetInRequest>>,
    pub(crate) last_explain_advertised: Mutex<Option<server_proto::ExplainAdvertisedRouteRequest>>,
}

pub(crate) struct MockServerHandle {
    pub(crate) addr: String,
    pub(crate) state: Arc<MockState>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    uds_path: Option<PathBuf>,
}

impl Drop for MockServerHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(path) = self.uds_path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[derive(Clone)]
struct AuthInterceptor {
    expected: Option<MetadataValue<tonic::metadata::Ascii>>,
}

impl Interceptor for AuthInterceptor {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        let Some(expected) = self.expected.as_ref() else {
            return Ok(request);
        };
        let actual = request
            .metadata()
            .get("authorization")
            .ok_or_else(|| Status::unauthenticated("missing authorization metadata"))?;
        if actual == expected {
            Ok(request)
        } else {
            Err(Status::unauthenticated("invalid bearer token"))
        }
    }
}

pub(crate) async fn spawn_mock_server(auth_token: Option<&str>) -> MockServerHandle {
    let state = Arc::new(MockState::default());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let interceptor = AuthInterceptor {
        expected: auth_token
            .map(|token| MetadataValue::try_from(format!("Bearer {token}")).unwrap()),
    };

    let global = MockGlobalService {
        state: Arc::clone(&state),
    };
    let control = MockControlService {
        state: Arc::clone(&state),
    };
    let neighbor = MockNeighborService {
        state: Arc::clone(&state),
    };
    let rib = MockRibService {
        state: Arc::clone(&state),
    };

    tokio::spawn(async move {
        Server::builder()
            .add_service(GlobalServiceServer::with_interceptor(
                global,
                interceptor.clone(),
            ))
            .add_service(ControlServiceServer::with_interceptor(
                control,
                interceptor.clone(),
            ))
            .add_service(NeighborServiceServer::with_interceptor(
                neighbor,
                interceptor.clone(),
            ))
            .add_service(RibServiceServer::with_interceptor(rib, interceptor.clone()))
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });

    MockServerHandle {
        addr: addr.to_string(),
        state,
        shutdown_tx: Some(shutdown_tx),
        uds_path: None,
    }
}

pub(crate) async fn spawn_mock_uds_server(
    path: &Path,
    auth_token: Option<&str>,
) -> MockServerHandle {
    let state = Arc::new(MockState::default());
    let _ = std::fs::remove_file(path);
    let listener = tokio::net::UnixListener::bind(path).unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let interceptor = AuthInterceptor {
        expected: auth_token
            .map(|token| MetadataValue::try_from(format!("Bearer {token}")).unwrap()),
    };

    let global = MockGlobalService {
        state: Arc::clone(&state),
    };
    let control = MockControlService {
        state: Arc::clone(&state),
    };
    let neighbor = MockNeighborService {
        state: Arc::clone(&state),
    };
    let rib = MockRibService {
        state: Arc::clone(&state),
    };

    tokio::spawn(async move {
        Server::builder()
            .add_service(GlobalServiceServer::with_interceptor(
                global,
                interceptor.clone(),
            ))
            .add_service(ControlServiceServer::with_interceptor(
                control,
                interceptor.clone(),
            ))
            .add_service(NeighborServiceServer::with_interceptor(
                neighbor,
                interceptor.clone(),
            ))
            .add_service(RibServiceServer::with_interceptor(rib, interceptor.clone()))
            .serve_with_incoming_shutdown(UnixListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });

    MockServerHandle {
        addr: format!("unix://{}", path.display()),
        state,
        shutdown_tx: Some(shutdown_tx),
        uds_path: Some(path.to_path_buf()),
    }
}

struct MockGlobalService {
    state: Arc<MockState>,
}

#[tonic::async_trait]
impl rustbgpd_api::proto::global_service_server::GlobalService for MockGlobalService {
    async fn get_global(
        &self,
        _request: Request<server_proto::GetGlobalRequest>,
    ) -> Result<Response<server_proto::GlobalState>, Status> {
        self.state.global_calls.fetch_add(1, Ordering::SeqCst);
        Ok(Response::new(server_proto::GlobalState {
            asn: 65001,
            router_id: "10.0.0.1".to_string(),
            listen_port: 179,
        }))
    }

    async fn set_global(
        &self,
        _request: Request<server_proto::SetGlobalRequest>,
    ) -> Result<Response<server_proto::SetGlobalResponse>, Status> {
        Err(Status::unimplemented("not used in CLI tests"))
    }
}

struct MockControlService {
    state: Arc<MockState>,
}

#[tonic::async_trait]
impl rustbgpd_api::proto::control_service_server::ControlService for MockControlService {
    async fn get_health(
        &self,
        _request: Request<server_proto::HealthRequest>,
    ) -> Result<Response<server_proto::HealthResponse>, Status> {
        self.state.health_calls.fetch_add(1, Ordering::SeqCst);
        Ok(Response::new(server_proto::HealthResponse {
            healthy: true,
            uptime_seconds: 42,
            active_peers: 2,
            total_routes: 10,
        }))
    }

    async fn get_metrics(
        &self,
        _request: Request<server_proto::MetricsRequest>,
    ) -> Result<Response<server_proto::MetricsResponse>, Status> {
        Ok(Response::new(server_proto::MetricsResponse {
            prometheus_text: "# HELP test 1\n".to_string(),
        }))
    }

    async fn shutdown(
        &self,
        _request: Request<server_proto::ShutdownRequest>,
    ) -> Result<Response<server_proto::ShutdownResponse>, Status> {
        Ok(Response::new(server_proto::ShutdownResponse {}))
    }

    async fn trigger_mrt_dump(
        &self,
        _request: Request<server_proto::TriggerMrtDumpRequest>,
    ) -> Result<Response<server_proto::TriggerMrtDumpResponse>, Status> {
        Ok(Response::new(server_proto::TriggerMrtDumpResponse {
            file_path: "/tmp/test.mrt".to_string(),
        }))
    }
}

struct MockNeighborService {
    state: Arc<MockState>,
}

#[tonic::async_trait]
impl rustbgpd_api::proto::neighbor_service_server::NeighborService for MockNeighborService {
    async fn add_neighbor(
        &self,
        request: Request<server_proto::AddNeighborRequest>,
    ) -> Result<Response<server_proto::AddNeighborResponse>, Status> {
        let cfg = request
            .into_inner()
            .config
            .ok_or_else(|| Status::invalid_argument("config required"))?;
        *self.state.last_add_neighbor.lock().await = Some(cfg);
        Ok(Response::new(server_proto::AddNeighborResponse {}))
    }

    async fn delete_neighbor(
        &self,
        _request: Request<server_proto::DeleteNeighborRequest>,
    ) -> Result<Response<server_proto::DeleteNeighborResponse>, Status> {
        Ok(Response::new(server_proto::DeleteNeighborResponse {}))
    }

    async fn list_neighbors(
        &self,
        _request: Request<server_proto::ListNeighborsRequest>,
    ) -> Result<Response<server_proto::ListNeighborsResponse>, Status> {
        Ok(Response::new(server_proto::ListNeighborsResponse {
            neighbors: vec![],
        }))
    }

    async fn get_neighbor_state(
        &self,
        _request: Request<server_proto::GetNeighborStateRequest>,
    ) -> Result<Response<server_proto::NeighborState>, Status> {
        Ok(Response::new(server_proto::NeighborState {
            config: Some(server_proto::NeighborConfig {
                address: "10.0.0.2".to_string(),
                remote_asn: 65002,
                description: "peer-2".to_string(),
                hold_time: 90,
                max_prefixes: 0,
                families: vec!["ipv4_unicast".to_string()],
                remove_private_as: String::new(),
                peer_group: String::new(),
                route_server_client: true,
                add_path_receive: true,
                add_path_send: true,
                add_path_send_max: 4,
            }),
            state: server_proto::SessionState::Established as i32,
            uptime_seconds: 30,
            prefixes_received: 1,
            prefixes_sent: 1,
            updates_received: 0,
            updates_sent: 0,
            notifications_received: 0,
            notifications_sent: 0,
            flap_count: 0,
            last_error: String::new(),
        }))
    }

    async fn enable_neighbor(
        &self,
        _request: Request<server_proto::EnableNeighborRequest>,
    ) -> Result<Response<server_proto::EnableNeighborResponse>, Status> {
        Ok(Response::new(server_proto::EnableNeighborResponse {}))
    }

    async fn disable_neighbor(
        &self,
        _request: Request<server_proto::DisableNeighborRequest>,
    ) -> Result<Response<server_proto::DisableNeighborResponse>, Status> {
        Ok(Response::new(server_proto::DisableNeighborResponse {}))
    }

    async fn soft_reset_in(
        &self,
        request: Request<server_proto::SoftResetInRequest>,
    ) -> Result<Response<server_proto::SoftResetInResponse>, Status> {
        *self.state.last_softreset.lock().await = Some(request.into_inner());
        Ok(Response::new(server_proto::SoftResetInResponse {}))
    }
}

struct MockRibService {
    state: Arc<MockState>,
}

#[tonic::async_trait]
impl rustbgpd_api::proto::rib_service_server::RibService for MockRibService {
    type WatchRoutesStream =
        std::pin::Pin<Box<dyn Stream<Item = Result<server_proto::RouteEvent, Status>> + Send>>;

    async fn list_received_routes(
        &self,
        _request: Request<server_proto::ListRoutesRequest>,
    ) -> Result<Response<server_proto::ListRoutesResponse>, Status> {
        Ok(Response::new(server_proto::ListRoutesResponse {
            routes: vec![],
            next_page_token: String::new(),
            total_count: 0,
        }))
    }

    async fn list_best_routes(
        &self,
        _request: Request<server_proto::ListRoutesRequest>,
    ) -> Result<Response<server_proto::ListRoutesResponse>, Status> {
        Ok(Response::new(server_proto::ListRoutesResponse {
            routes: vec![],
            next_page_token: String::new(),
            total_count: 0,
        }))
    }

    async fn list_advertised_routes(
        &self,
        _request: Request<server_proto::ListRoutesRequest>,
    ) -> Result<Response<server_proto::ListRoutesResponse>, Status> {
        Ok(Response::new(server_proto::ListRoutesResponse {
            routes: vec![],
            next_page_token: String::new(),
            total_count: 0,
        }))
    }

    async fn explain_advertised_route(
        &self,
        request: Request<server_proto::ExplainAdvertisedRouteRequest>,
    ) -> Result<Response<server_proto::ExplainAdvertisedRouteResponse>, Status> {
        *self.state.last_explain_advertised.lock().await = Some(request.into_inner());
        Ok(Response::new(
            server_proto::ExplainAdvertisedRouteResponse {
                decision: server_proto::ExplainDecision::Advertise as i32,
                peer_address: "192.0.2.1".to_string(),
                prefix: "203.0.113.0".to_string(),
                prefix_length: 24,
                next_hop: "198.51.100.1".to_string(),
                path_id: 0,
                route_peer_address: "198.51.100.2".to_string(),
                route_type: "external".to_string(),
                reasons: vec![server_proto::ExplainReason {
                    code: "policy_permitted".to_string(),
                    message: "export policy permitted this route".to_string(),
                }],
                modifications: Some(server_proto::ExplainModifications {
                    set_local_pref: Some(200),
                    set_med: None,
                    set_next_hop: String::new(),
                    communities_add: vec![],
                    communities_remove: vec![],
                    extended_communities_add: vec![],
                    extended_communities_remove: vec![],
                    large_communities_add: vec![],
                    large_communities_remove: vec![],
                    as_path_prepend_asn: None,
                    as_path_prepend_count: None,
                }),
            },
        ))
    }

    async fn watch_routes(
        &self,
        _request: Request<server_proto::WatchRoutesRequest>,
    ) -> Result<Response<Self::WatchRoutesStream>, Status> {
        Err(Status::unimplemented("not used in CLI tests"))
    }

    async fn list_flow_spec_routes(
        &self,
        _request: Request<server_proto::ListFlowSpecRequest>,
    ) -> Result<Response<server_proto::ListFlowSpecResponse>, Status> {
        Ok(Response::new(server_proto::ListFlowSpecResponse {
            routes: vec![],
        }))
    }
}
