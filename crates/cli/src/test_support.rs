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
use rustbgpd_api::proto::evpn_service_server::EvpnServiceServer;
use rustbgpd_api::proto::global_service_server::GlobalServiceServer;
use rustbgpd_api::proto::neighbor_service_server::NeighborServiceServer;
use rustbgpd_api::proto::peer_group_service_server::PeerGroupServiceServer;
use rustbgpd_api::proto::policy_service_server::PolicyServiceServer;
use rustbgpd_api::proto::rib_service_server::RibServiceServer;

#[derive(Default)]
pub(crate) struct MockState {
    pub(crate) health_calls: AtomicUsize,
    pub(crate) global_calls: AtomicUsize,
    pub(crate) last_add_neighbor: Mutex<Option<server_proto::NeighborConfig>>,
    pub(crate) last_softreset: Mutex<Option<server_proto::SoftResetInRequest>>,
    pub(crate) last_explain_advertised: Mutex<Option<server_proto::ExplainAdvertisedRouteRequest>>,
    // Policy / neighbor-set / chain captures used by the policy.rs +
    // neighbor_set.rs CLI tests.
    pub(crate) last_set_policy: Mutex<Option<server_proto::SetPolicyRequest>>,
    pub(crate) last_delete_policy: Mutex<Option<server_proto::DeletePolicyRequest>>,
    pub(crate) last_set_neighbor_set: Mutex<Option<server_proto::SetNeighborSetRequest>>,
    pub(crate) last_delete_neighbor_set: Mutex<Option<server_proto::DeleteNeighborSetRequest>>,
    pub(crate) last_set_global_import_chain:
        Mutex<Option<server_proto::SetGlobalImportChainRequest>>,
    pub(crate) last_set_global_export_chain:
        Mutex<Option<server_proto::SetGlobalExportChainRequest>>,
    pub(crate) last_set_neighbor_import_chain:
        Mutex<Option<server_proto::SetNeighborImportChainRequest>>,
    pub(crate) last_set_neighbor_export_chain:
        Mutex<Option<server_proto::SetNeighborExportChainRequest>>,
    pub(crate) last_clear_global_import_chain:
        Mutex<Option<server_proto::ClearGlobalImportChainRequest>>,
    pub(crate) last_clear_global_export_chain:
        Mutex<Option<server_proto::ClearGlobalExportChainRequest>>,
    pub(crate) last_clear_neighbor_import_chain:
        Mutex<Option<server_proto::ClearNeighborImportChainRequest>>,
    pub(crate) last_clear_neighbor_export_chain:
        Mutex<Option<server_proto::ClearNeighborExportChainRequest>>,
    // Peer-group captures used by the peer_group.rs CLI tests.
    pub(crate) last_set_peer_group: Mutex<Option<server_proto::SetPeerGroupRequest>>,
    pub(crate) last_delete_peer_group: Mutex<Option<server_proto::DeletePeerGroupRequest>>,
    pub(crate) last_set_neighbor_peer_group:
        Mutex<Option<server_proto::SetNeighborPeerGroupRequest>>,
    pub(crate) last_clear_neighbor_peer_group:
        Mutex<Option<server_proto::ClearNeighborPeerGroupRequest>>,
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
    let evpn = MockEvpnService;
    let policy = MockPolicyService {
        state: Arc::clone(&state),
    };
    let peer_group = MockPeerGroupService {
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
            .add_service(EvpnServiceServer::with_interceptor(
                evpn,
                interceptor.clone(),
            ))
            .add_service(PolicyServiceServer::with_interceptor(
                policy,
                interceptor.clone(),
            ))
            .add_service(PeerGroupServiceServer::with_interceptor(
                peer_group,
                interceptor.clone(),
            ))
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
    let evpn = MockEvpnService;
    let policy = MockPolicyService {
        state: Arc::clone(&state),
    };
    let peer_group = MockPeerGroupService {
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
            .add_service(EvpnServiceServer::with_interceptor(
                evpn,
                interceptor.clone(),
            ))
            .add_service(PolicyServiceServer::with_interceptor(
                policy,
                interceptor.clone(),
            ))
            .add_service(PeerGroupServiceServer::with_interceptor(
                peer_group,
                interceptor.clone(),
            ))
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
            prometheus_text: r#"# HELP test 1
evpn_local_originations_total{action="inject"} 1
evpn_duplicate_mac_moves_total{vni="100",mac="02:aa:bb:cc:dd:01"} 2
"#
            .to_string(),
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
            is_dynamic: false,
            stale: false,
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

    async fn list_dynamic_neighbors(
        &self,
        _request: Request<server_proto::ListDynamicNeighborsRequest>,
    ) -> Result<Response<server_proto::ListDynamicNeighborsResponse>, Status> {
        Err(Status::unimplemented("not in mock"))
    }

    async fn add_dynamic_neighbor(
        &self,
        _request: Request<server_proto::AddDynamicNeighborRequest>,
    ) -> Result<Response<server_proto::AddDynamicNeighborResponse>, Status> {
        Err(Status::unimplemented("not in mock"))
    }

    async fn delete_dynamic_neighbor(
        &self,
        _request: Request<server_proto::DeleteDynamicNeighborRequest>,
    ) -> Result<Response<server_proto::DeleteDynamicNeighborResponse>, Status> {
        Err(Status::unimplemented("not in mock"))
    }

    async fn set_graceful_shutdown(
        &self,
        _request: Request<server_proto::SetGracefulShutdownRequest>,
    ) -> Result<Response<server_proto::SetGracefulShutdownResponse>, Status> {
        Err(Status::unimplemented("not in mock"))
    }
}

struct MockRibService {
    state: Arc<MockState>,
}

struct MockEvpnService;

#[tonic::async_trait]
impl rustbgpd_api::proto::evpn_service_server::EvpnService for MockEvpnService {
    async fn list_evpn_instances(
        &self,
        _request: Request<server_proto::ListEvpnInstancesRequest>,
    ) -> Result<Response<server_proto::ListEvpnInstancesResponse>, Status> {
        Ok(Response::new(server_proto::ListEvpnInstancesResponse {
            instances: vec![server_proto::EvpnInstanceState {
                vni: 100,
                rd: "65000:100".to_string(),
                route_targets: vec!["65000:100".to_string()],
                local_vtep_ip: "10.0.0.1".to_string(),
                bridge: "br100".to_string(),
                advertise_svi_mac: false,
                originated_local_macs_count: 2,
            }],
        }))
    }

    async fn list_evpn_nexthops(
        &self,
        _request: Request<server_proto::ListEvpnNexthopsRequest>,
    ) -> Result<Response<server_proto::ListEvpnNexthopsResponse>, Status> {
        Ok(Response::new(server_proto::ListEvpnNexthopsResponse {
            groups: vec![server_proto::EvpnFdbNexthopGroup {
                vni: 100,
                esi: "03:00:00:00:00:00:00:00:00:07".to_string(),
                ethernet_tag: "0".to_string(),
                group_id: 0x4000_0001,
                members: vec![
                    server_proto::EvpnFdbNexthopMember {
                        gateway: "10.0.0.2".to_string(),
                        nexthop_id: 0x3000_0001,
                    },
                    server_proto::EvpnFdbNexthopMember {
                        gateway: "10.0.0.3".to_string(),
                        nexthop_id: 0x3000_0002,
                    },
                ],
                ref_macs: vec!["02:aa:bb:cc:dd:01".to_string()],
            }],
            orphan_nexthops_count: 1,
            pending_delete_count: 0,
            drift_recovery_disabled: false,
        }))
    }

    async fn list_ip_vrfs(
        &self,
        _request: Request<server_proto::ListIpVrfsRequest>,
    ) -> Result<Response<server_proto::ListIpVrfsResponse>, Status> {
        Ok(Response::new(server_proto::ListIpVrfsResponse {
            ip_vrfs: Vec::new(),
        }))
    }

    async fn get_ip_vrf(
        &self,
        request: Request<server_proto::GetIpVrfRequest>,
    ) -> Result<Response<server_proto::IpVrfState>, Status> {
        let name = request.into_inner().name;
        Err(Status::not_found(format!("no IP-VRF named {name:?}")))
    }
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

    async fn explain_best_path(
        &self,
        request: Request<server_proto::ExplainBestPathRequest>,
    ) -> Result<Response<server_proto::ExplainBestPathResponse>, Status> {
        let req = request.into_inner();
        Ok(Response::new(server_proto::ExplainBestPathResponse {
            prefix: "203.0.113.0".to_string(),
            prefix_length: 24,
            best_route: None,
            candidates: vec![],
            peer_address: req.peer_address,
            add_path_send_max: 0,
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

    async fn list_blackhole_discards(
        &self,
        _request: Request<server_proto::ListBlackholeDiscardsRequest>,
    ) -> Result<Response<server_proto::ListBlackholeDiscardsResponse>, Status> {
        Ok(Response::new(server_proto::ListBlackholeDiscardsResponse {
            discards: vec![],
        }))
    }

    async fn list_fib_routes(
        &self,
        _request: Request<server_proto::ListFibRoutesRequest>,
    ) -> Result<Response<server_proto::ListFibRoutesResponse>, Status> {
        Ok(Response::new(server_proto::ListFibRoutesResponse {
            routes: vec![],
        }))
    }

    async fn list_route_events(
        &self,
        _request: Request<server_proto::ListRouteEventsRequest>,
    ) -> Result<Response<server_proto::ListRouteEventsResponse>, Status> {
        Ok(Response::new(server_proto::ListRouteEventsResponse {
            events: vec![],
        }))
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

    async fn list_evpn_routes(
        &self,
        request: Request<server_proto::ListEvpnRequest>,
    ) -> Result<Response<server_proto::ListEvpnResponse>, Status> {
        let filter = request.into_inner().route_type_filter;
        let mut routes = Vec::new();
        if filter == 0 || filter == 2 {
            routes.push(mock_evpn_route(2));
        }
        if filter == 0 || filter == 3 {
            routes.push(mock_evpn_route(3));
        }
        Ok(Response::new(server_proto::ListEvpnResponse { routes }))
    }
}

fn mock_evpn_route(route_type: u32) -> server_proto::EvpnRouteEntry {
    server_proto::EvpnRouteEntry {
        route_type,
        rd: "65000:100".to_string(),
        esi: String::new(),
        ethernet_tag: "0".to_string(),
        mac: if route_type == 2 {
            "02:aa:bb:cc:dd:01".to_string()
        } else {
            String::new()
        },
        ip: if route_type == 3 {
            "10.0.0.1".to_string()
        } else {
            String::new()
        },
        prefix: String::new(),
        gateway: String::new(),
        label: 100,
        label2: 0,
        next_hop: "10.0.0.1".to_string(),
        peer_address: "10.0.0.2".to_string(),
        as_path: vec![],
        communities: vec![],
        extended_communities: vec![],
        tunnel_type: 8,
    }
}

struct MockPolicyService {
    state: Arc<MockState>,
}

#[tonic::async_trait]
impl rustbgpd_api::proto::policy_service_server::PolicyService for MockPolicyService {
    async fn list_policies(
        &self,
        _request: Request<server_proto::ListPoliciesRequest>,
    ) -> Result<Response<server_proto::ListPoliciesResponse>, Status> {
        Ok(Response::new(server_proto::ListPoliciesResponse {
            policies: vec![],
        }))
    }

    async fn get_policy(
        &self,
        request: Request<server_proto::GetPolicyRequest>,
    ) -> Result<Response<server_proto::GetPolicyResponse>, Status> {
        Ok(Response::new(server_proto::GetPolicyResponse {
            name: request.into_inner().name,
            definition: Some(server_proto::PolicyDefinition::default()),
        }))
    }

    async fn set_policy(
        &self,
        request: Request<server_proto::SetPolicyRequest>,
    ) -> Result<Response<server_proto::SetPolicyResponse>, Status> {
        *self.state.last_set_policy.lock().await = Some(request.into_inner());
        Ok(Response::new(server_proto::SetPolicyResponse {}))
    }

    async fn delete_policy(
        &self,
        request: Request<server_proto::DeletePolicyRequest>,
    ) -> Result<Response<server_proto::DeletePolicyResponse>, Status> {
        *self.state.last_delete_policy.lock().await = Some(request.into_inner());
        Ok(Response::new(server_proto::DeletePolicyResponse {}))
    }

    async fn list_neighbor_sets(
        &self,
        _request: Request<server_proto::ListNeighborSetsRequest>,
    ) -> Result<Response<server_proto::ListNeighborSetsResponse>, Status> {
        Ok(Response::new(server_proto::ListNeighborSetsResponse {
            neighbor_sets: vec![],
        }))
    }

    async fn get_neighbor_set(
        &self,
        request: Request<server_proto::GetNeighborSetRequest>,
    ) -> Result<Response<server_proto::GetNeighborSetResponse>, Status> {
        Ok(Response::new(server_proto::GetNeighborSetResponse {
            name: request.into_inner().name,
            definition: Some(server_proto::NeighborSetDefinition::default()),
        }))
    }

    async fn set_neighbor_set(
        &self,
        request: Request<server_proto::SetNeighborSetRequest>,
    ) -> Result<Response<server_proto::SetNeighborSetResponse>, Status> {
        *self.state.last_set_neighbor_set.lock().await = Some(request.into_inner());
        Ok(Response::new(server_proto::SetNeighborSetResponse {}))
    }

    async fn delete_neighbor_set(
        &self,
        request: Request<server_proto::DeleteNeighborSetRequest>,
    ) -> Result<Response<server_proto::DeleteNeighborSetResponse>, Status> {
        *self.state.last_delete_neighbor_set.lock().await = Some(request.into_inner());
        Ok(Response::new(server_proto::DeleteNeighborSetResponse {}))
    }

    async fn get_global_policy_chains(
        &self,
        _request: Request<server_proto::GetGlobalPolicyChainsRequest>,
    ) -> Result<Response<server_proto::GlobalPolicyChains>, Status> {
        Ok(Response::new(server_proto::GlobalPolicyChains {
            import_policy_names: vec!["g-import".to_string()],
            export_policy_names: vec!["g-export".to_string()],
        }))
    }

    async fn set_global_import_chain(
        &self,
        request: Request<server_proto::SetGlobalImportChainRequest>,
    ) -> Result<Response<server_proto::SetGlobalImportChainResponse>, Status> {
        *self.state.last_set_global_import_chain.lock().await = Some(request.into_inner());
        Ok(Response::new(server_proto::SetGlobalImportChainResponse {}))
    }

    async fn set_global_export_chain(
        &self,
        request: Request<server_proto::SetGlobalExportChainRequest>,
    ) -> Result<Response<server_proto::SetGlobalExportChainResponse>, Status> {
        *self.state.last_set_global_export_chain.lock().await = Some(request.into_inner());
        Ok(Response::new(server_proto::SetGlobalExportChainResponse {}))
    }

    async fn clear_global_import_chain(
        &self,
        request: Request<server_proto::ClearGlobalImportChainRequest>,
    ) -> Result<Response<server_proto::ClearGlobalImportChainResponse>, Status> {
        *self.state.last_clear_global_import_chain.lock().await = Some(request.into_inner());
        Ok(Response::new(
            server_proto::ClearGlobalImportChainResponse {},
        ))
    }

    async fn clear_global_export_chain(
        &self,
        request: Request<server_proto::ClearGlobalExportChainRequest>,
    ) -> Result<Response<server_proto::ClearGlobalExportChainResponse>, Status> {
        *self.state.last_clear_global_export_chain.lock().await = Some(request.into_inner());
        Ok(Response::new(
            server_proto::ClearGlobalExportChainResponse {},
        ))
    }

    async fn get_neighbor_policy_chains(
        &self,
        request: Request<server_proto::GetNeighborPolicyChainsRequest>,
    ) -> Result<Response<server_proto::NeighborPolicyChains>, Status> {
        Ok(Response::new(server_proto::NeighborPolicyChains {
            address: request.into_inner().address,
            import_policy_names: vec!["n-import".to_string()],
            export_policy_names: vec!["n-export".to_string()],
        }))
    }

    async fn set_neighbor_import_chain(
        &self,
        request: Request<server_proto::SetNeighborImportChainRequest>,
    ) -> Result<Response<server_proto::SetNeighborImportChainResponse>, Status> {
        *self.state.last_set_neighbor_import_chain.lock().await = Some(request.into_inner());
        Ok(Response::new(
            server_proto::SetNeighborImportChainResponse {},
        ))
    }

    async fn set_neighbor_export_chain(
        &self,
        request: Request<server_proto::SetNeighborExportChainRequest>,
    ) -> Result<Response<server_proto::SetNeighborExportChainResponse>, Status> {
        *self.state.last_set_neighbor_export_chain.lock().await = Some(request.into_inner());
        Ok(Response::new(
            server_proto::SetNeighborExportChainResponse {},
        ))
    }

    async fn clear_neighbor_import_chain(
        &self,
        request: Request<server_proto::ClearNeighborImportChainRequest>,
    ) -> Result<Response<server_proto::ClearNeighborImportChainResponse>, Status> {
        *self.state.last_clear_neighbor_import_chain.lock().await = Some(request.into_inner());
        Ok(Response::new(
            server_proto::ClearNeighborImportChainResponse {},
        ))
    }

    async fn clear_neighbor_export_chain(
        &self,
        request: Request<server_proto::ClearNeighborExportChainRequest>,
    ) -> Result<Response<server_proto::ClearNeighborExportChainResponse>, Status> {
        *self.state.last_clear_neighbor_export_chain.lock().await = Some(request.into_inner());
        Ok(Response::new(
            server_proto::ClearNeighborExportChainResponse {},
        ))
    }
}

struct MockPeerGroupService {
    state: Arc<MockState>,
}

#[tonic::async_trait]
impl rustbgpd_api::proto::peer_group_service_server::PeerGroupService for MockPeerGroupService {
    async fn list_peer_groups(
        &self,
        _request: Request<server_proto::ListPeerGroupsRequest>,
    ) -> Result<Response<server_proto::ListPeerGroupsResponse>, Status> {
        Ok(Response::new(server_proto::ListPeerGroupsResponse {
            peer_groups: vec![],
        }))
    }

    async fn get_peer_group(
        &self,
        request: Request<server_proto::GetPeerGroupRequest>,
    ) -> Result<Response<server_proto::GetPeerGroupResponse>, Status> {
        Ok(Response::new(server_proto::GetPeerGroupResponse {
            name: request.into_inner().name,
            definition: Some(server_proto::PeerGroupDefinition::default()),
        }))
    }

    async fn set_peer_group(
        &self,
        request: Request<server_proto::SetPeerGroupRequest>,
    ) -> Result<Response<server_proto::SetPeerGroupResponse>, Status> {
        *self.state.last_set_peer_group.lock().await = Some(request.into_inner());
        Ok(Response::new(server_proto::SetPeerGroupResponse {}))
    }

    async fn delete_peer_group(
        &self,
        request: Request<server_proto::DeletePeerGroupRequest>,
    ) -> Result<Response<server_proto::DeletePeerGroupResponse>, Status> {
        *self.state.last_delete_peer_group.lock().await = Some(request.into_inner());
        Ok(Response::new(server_proto::DeletePeerGroupResponse {}))
    }

    async fn set_neighbor_peer_group(
        &self,
        request: Request<server_proto::SetNeighborPeerGroupRequest>,
    ) -> Result<Response<server_proto::SetNeighborPeerGroupResponse>, Status> {
        *self.state.last_set_neighbor_peer_group.lock().await = Some(request.into_inner());
        Ok(Response::new(server_proto::SetNeighborPeerGroupResponse {}))
    }

    async fn clear_neighbor_peer_group(
        &self,
        request: Request<server_proto::ClearNeighborPeerGroupRequest>,
    ) -> Result<Response<server_proto::ClearNeighborPeerGroupResponse>, Status> {
        *self.state.last_clear_neighbor_peer_group.lock().await = Some(request.into_inner());
        Ok(Response::new(
            server_proto::ClearNeighborPeerGroupResponse {},
        ))
    }
}
