use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use tokio::net::TcpListener;
use tokio::sync::{Mutex, oneshot};
use tokio_stream::Stream;
use tokio_stream::wrappers::{TcpListenerStream, UnixListenerStream};
use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::transport::Server;
use tonic::{Code, Request, Response, Status};

use rustbgpd_api::proto as server_proto;
use rustbgpd_api::proto::bfd_service_server::BfdServiceServer;
use rustbgpd_api::proto::config_service_server::ConfigServiceServer;
use rustbgpd_api::proto::control_service_server::ControlServiceServer;
use rustbgpd_api::proto::event_service_server::EventServiceServer;
use rustbgpd_api::proto::evpn_service_server::EvpnServiceServer;
use rustbgpd_api::proto::global_service_server::GlobalServiceServer;
use rustbgpd_api::proto::neighbor_service_server::NeighborServiceServer;
use rustbgpd_api::proto::peer_group_service_server::PeerGroupServiceServer;
use rustbgpd_api::proto::policy_service_server::PolicyServiceServer;
use rustbgpd_api::proto::rib_service_server::RibServiceServer;

#[derive(Default)]
pub(crate) struct MockState {
    pub(crate) bfd_calls: AtomicUsize,
    pub(crate) health_calls: AtomicUsize,
    pub(crate) metrics_calls: AtomicUsize,
    pub(crate) global_calls: AtomicUsize,
    pub(crate) list_neighbors_calls: AtomicUsize,
    pub(crate) list_session_events_calls: AtomicUsize,
    pub(crate) list_policy_events_calls: AtomicUsize,
    pub(crate) config_diff_calls: AtomicUsize,
    pub(crate) config_plan_calls: AtomicUsize,
    pub(crate) config_apply_calls: AtomicUsize,
    pub(crate) config_confirm_calls: AtomicUsize,
    pub(crate) config_abort_calls: AtomicUsize,
    pub(crate) config_status_calls: AtomicUsize,
    pub(crate) config_effective_calls: AtomicUsize,
    pub(crate) config_effective_error: Mutex<Option<(Code, String)>>,
    // Doctor-bundle overrides: canned effective-config TOML, metrics
    // text, and session events so redaction/layout tests can seed
    // secret-looking material through every collection path.
    pub(crate) config_effective_toml: Mutex<Option<String>>,
    pub(crate) metrics_text: Mutex<Option<String>>,
    pub(crate) session_events: Mutex<Vec<server_proto::BgpEvent>>,
    pub(crate) config_confirm_error: Mutex<Option<(Code, String)>>,
    pub(crate) config_abort_error: Mutex<Option<(Code, String)>>,
    pub(crate) config_status_error: Mutex<Option<(Code, String)>>,
    pub(crate) config_diff_error: Mutex<Option<(Code, String)>>,
    // Serve a "candidate matches runtime" diff / noop plan so the CLI
    // detailed exit-code contract (0 = no changes) can be pinned.
    pub(crate) config_diff_no_changes: AtomicBool,
    pub(crate) config_plan_noop: AtomicBool,
    pub(crate) bfd_error: Mutex<Option<(Code, String)>>,
    pub(crate) bfd_sessions: Mutex<Vec<server_proto::BfdSession>>,
    pub(crate) last_bfd_request: Mutex<Option<server_proto::GetBfdSessionsRequest>>,
    pub(crate) last_config_diff: Mutex<Option<String>>,
    pub(crate) last_config_plan: Mutex<Option<server_proto::PlanConfigTransactionRequest>>,
    pub(crate) last_config_apply: Mutex<Option<server_proto::ApplyConfigTransactionRequest>>,
    pub(crate) last_config_confirm: Mutex<Option<server_proto::ConfirmConfigTransactionRequest>>,
    pub(crate) last_config_abort: Mutex<Option<server_proto::AbortConfigTransactionRequest>>,
    pub(crate) last_add_neighbor: Mutex<Option<server_proto::NeighborConfig>>,
    pub(crate) last_softreset: Mutex<Option<server_proto::SoftResetInRequest>>,
    pub(crate) last_explain_advertised: Mutex<Option<server_proto::ExplainAdvertisedRouteRequest>>,
    pub(crate) last_explain_best_path: Mutex<Option<server_proto::ExplainBestPathRequest>>,
    // Canned pages served in order by the unicast route-listing RPCs
    // (received/best/advertised) — drives the CLI pagination loop.
    // Empty = every call returns an empty final page.
    pub(crate) list_route_pages: Mutex<Vec<server_proto::ListRoutesResponse>>,
    pub(crate) list_route_requests: Mutex<Vec<server_proto::ListRoutesRequest>>,
    // Canned ListNeighbors response — drives `rbgp diff` peer-availability
    // gating. Empty = no neighbors configured on the daemon.
    pub(crate) list_neighbors_response: Mutex<Vec<server_proto::NeighborState>>,
    pub(crate) last_list_bgpls: Mutex<Option<server_proto::ListBgpLsRequest>>,
    pub(crate) last_list_vpn: Mutex<Option<server_proto::ListVpnRoutesRequest>>,
    pub(crate) last_list_labeled: Mutex<Option<server_proto::ListLabeledRoutesRequest>>,
    pub(crate) last_list_rtc: Mutex<Option<server_proto::ListRtcRoutesRequest>>,
    pub(crate) last_list_topology_nodes: Mutex<Option<server_proto::ListTopologyNodesRequest>>,
    pub(crate) last_list_topology_links: Mutex<Option<server_proto::ListTopologyLinksRequest>>,
    pub(crate) last_list_orr_status: Mutex<Option<server_proto::ListOrrStatusRequest>>,
    // Policy / neighbor-set / chain captures used by the policy.rs +
    // neighbor_set.rs CLI tests.
    pub(crate) last_set_policy: Mutex<Option<server_proto::SetPolicyRequest>>,
    pub(crate) last_delete_policy: Mutex<Option<server_proto::DeletePolicyRequest>>,
    pub(crate) last_explain_import: Mutex<Option<server_proto::ExplainImportPolicyRequest>>,
    // LAN-320: when set, `explain_import_policy` answers with one
    // synthetic match carrying this outcome (empty decision fields)
    // instead of the canned permit/deny fixtures — drives the
    // not_seen / cache_disabled / no_session CLI pins.
    pub(crate) explain_import_synthetic_outcome: Mutex<Option<server_proto::ImportExplainOutcome>>,
    pub(crate) last_test_policy: Mutex<Option<server_proto::TestPolicyRequest>>,
    pub(crate) last_set_neighbor_set: Mutex<Option<server_proto::SetNeighborSetRequest>>,
    pub(crate) last_delete_neighbor_set: Mutex<Option<server_proto::DeleteNeighborSetRequest>>,
    pub(crate) last_add_dynamic_neighbor: Mutex<Option<server_proto::AddDynamicNeighborRequest>>,
    pub(crate) last_delete_dynamic_neighbor:
        Mutex<Option<server_proto::DeleteDynamicNeighborRequest>>,
    pub(crate) last_set_fib_table: Mutex<Option<server_proto::SetFibTableRequest>>,
    pub(crate) last_delete_fib_table: Mutex<Option<server_proto::DeleteFibTableRequest>>,
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
    let config = MockConfigService {
        state: Arc::clone(&state),
    };
    let control = MockControlService {
        state: Arc::clone(&state),
    };
    let bfd = MockBfdService {
        state: Arc::clone(&state),
    };
    let neighbor = MockNeighborService {
        state: Arc::clone(&state),
    };
    let rib = MockRibService {
        state: Arc::clone(&state),
    };
    let evpn = MockEvpnService;
    let event = MockEventService {
        state: Arc::clone(&state),
    };
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
            .add_service(ConfigServiceServer::with_interceptor(
                config,
                interceptor.clone(),
            ))
            .add_service(ControlServiceServer::with_interceptor(
                control,
                interceptor.clone(),
            ))
            .add_service(BfdServiceServer::with_interceptor(bfd, interceptor.clone()))
            .add_service(NeighborServiceServer::with_interceptor(
                neighbor,
                interceptor.clone(),
            ))
            .add_service(RibServiceServer::with_interceptor(rib, interceptor.clone()))
            .add_service(EvpnServiceServer::with_interceptor(
                evpn,
                interceptor.clone(),
            ))
            .add_service(EventServiceServer::with_interceptor(
                event,
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
    let config = MockConfigService {
        state: Arc::clone(&state),
    };
    let control = MockControlService {
        state: Arc::clone(&state),
    };
    let bfd = MockBfdService {
        state: Arc::clone(&state),
    };
    let neighbor = MockNeighborService {
        state: Arc::clone(&state),
    };
    let rib = MockRibService {
        state: Arc::clone(&state),
    };
    let evpn = MockEvpnService;
    let event = MockEventService {
        state: Arc::clone(&state),
    };
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
            .add_service(ConfigServiceServer::with_interceptor(
                config,
                interceptor.clone(),
            ))
            .add_service(ControlServiceServer::with_interceptor(
                control,
                interceptor.clone(),
            ))
            .add_service(BfdServiceServer::with_interceptor(bfd, interceptor.clone()))
            .add_service(NeighborServiceServer::with_interceptor(
                neighbor,
                interceptor.clone(),
            ))
            .add_service(RibServiceServer::with_interceptor(rib, interceptor.clone()))
            .add_service(EvpnServiceServer::with_interceptor(
                evpn,
                interceptor.clone(),
            ))
            .add_service(EventServiceServer::with_interceptor(
                event,
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

struct MockConfigService {
    state: Arc<MockState>,
}

#[tonic::async_trait]
impl rustbgpd_api::proto::config_service_server::ConfigService for MockConfigService {
    async fn diff_runtime_config(
        &self,
        request: Request<server_proto::DiffRuntimeConfigRequest>,
    ) -> Result<Response<server_proto::DiffRuntimeConfigResponse>, Status> {
        self.state.config_diff_calls.fetch_add(1, Ordering::SeqCst);
        *self.state.last_config_diff.lock().await = Some(request.into_inner().candidate_toml);
        if let Some((code, message)) = self.state.config_diff_error.lock().await.clone() {
            return Err(Status::new(code, message));
        }
        if self.state.config_diff_no_changes.load(Ordering::SeqCst) {
            return Ok(Response::new(server_proto::DiffRuntimeConfigResponse {
                has_actionable_changes: false,
                has_reload_applied_changes: false,
                has_restart_required_changes: false,
                has_informational_changes: false,
                has_any_changes: false,
                human_text: "No changes.\n".to_string(),
                diff_json: "{\"has_any_changes\":false}".to_string(),
            }));
        }
        Ok(Response::new(server_proto::DiffRuntimeConfigResponse {
            has_actionable_changes: true,
            has_reload_applied_changes: false,
            has_restart_required_changes: true,
            has_informational_changes: false,
            has_any_changes: true,
            human_text: "Restart-required changes:\n".to_string(),
            diff_json: "{\"has_any_changes\":true}".to_string(),
        }))
    }

    async fn plan_config_transaction(
        &self,
        request: Request<server_proto::PlanConfigTransactionRequest>,
    ) -> Result<Response<server_proto::ConfigTransactionPlanResponse>, Status> {
        self.state.config_plan_calls.fetch_add(1, Ordering::SeqCst);
        *self.state.last_config_plan.lock().await = Some(request.into_inner());
        if self.state.config_plan_noop.load(Ordering::SeqCst) {
            return Ok(Response::new(server_proto::ConfigTransactionPlanResponse {
                status: server_proto::ConfigTransactionPlanStatus::Noop as i32,
                runtime_snapshot_token: "kv1:planned:1".to_string(),
                diff: None,
                supported_sections: Vec::new(),
                unsupported_sections: Vec::new(),
                restart_required_sections: Vec::new(),
                human_text: "Config transaction is a noop.\n".to_string(),
            }));
        }
        Ok(Response::new(server_proto::ConfigTransactionPlanResponse {
            status: server_proto::ConfigTransactionPlanStatus::Committable as i32,
            runtime_snapshot_token: "kv1:planned:1".to_string(),
            diff: Some(server_proto::DiffRuntimeConfigResponse {
                has_actionable_changes: true,
                has_reload_applied_changes: true,
                has_restart_required_changes: false,
                has_informational_changes: false,
                has_any_changes: true,
                human_text: "Reload-applied changes:\n".to_string(),
                diff_json: "{\"has_any_changes\":true}".to_string(),
            }),
            supported_sections: vec!["[[fib_tables]]".to_string()],
            unsupported_sections: Vec::new(),
            restart_required_sections: Vec::new(),
            human_text: "Config transaction is committable by v1.\n".to_string(),
        }))
    }

    async fn apply_config_transaction(
        &self,
        request: Request<server_proto::ApplyConfigTransactionRequest>,
    ) -> Result<Response<server_proto::ConfigTransactionApplyResponse>, Status> {
        self.state.config_apply_calls.fetch_add(1, Ordering::SeqCst);
        *self.state.last_config_apply.lock().await = Some(request.into_inner());
        Ok(Response::new(
            server_proto::ConfigTransactionApplyResponse {
                status: server_proto::ConfigTransactionPlanStatus::Committable as i32,
                runtime_snapshot_token: "kv1:committed:2".to_string(),
                committed_sections: vec!["[[fib_tables]]".to_string()],
                human_text: "Committed [[fib_tables]] transaction.\n".to_string(),
                confirmation: None,
            },
        ))
    }

    async fn confirm_config_transaction(
        &self,
        request: Request<server_proto::ConfirmConfigTransactionRequest>,
    ) -> Result<Response<server_proto::ConfirmConfigTransactionResponse>, Status> {
        self.state
            .config_confirm_calls
            .fetch_add(1, Ordering::SeqCst);
        let request = request.into_inner();
        *self.state.last_config_confirm.lock().await = Some(request.clone());
        if let Some((code, message)) = self.state.config_confirm_error.lock().await.clone() {
            return Err(Status::new(code, message));
        }
        Ok(Response::new(
            server_proto::ConfirmConfigTransactionResponse {
                confirmation: Some(server_proto::ConfigTransactionConfirmation {
                    status: server_proto::ConfigTransactionConfirmationStatus::Confirmed as i32,
                    confirm_id: request.confirm_id,
                    timeout_seconds: 120,
                    deadline_unix_seconds: 0,
                    committed_sections: vec!["[[fib_tables]]".to_string()],
                    runtime_snapshot_token: "kv1:committed:2".to_string(),
                    human_text: "Confirmed config transaction committed permanently.".to_string(),
                }),
                human_text: "Confirmed config transaction committed permanently.\n".to_string(),
            },
        ))
    }

    async fn abort_config_transaction(
        &self,
        request: Request<server_proto::AbortConfigTransactionRequest>,
    ) -> Result<Response<server_proto::AbortConfigTransactionResponse>, Status> {
        self.state.config_abort_calls.fetch_add(1, Ordering::SeqCst);
        let request = request.into_inner();
        *self.state.last_config_abort.lock().await = Some(request.clone());
        if let Some((code, message)) = self.state.config_abort_error.lock().await.clone() {
            return Err(Status::new(code, message));
        }
        Ok(Response::new(
            server_proto::AbortConfigTransactionResponse {
                confirmation: Some(server_proto::ConfigTransactionConfirmation {
                    status: server_proto::ConfigTransactionConfirmationStatus::Aborted as i32,
                    confirm_id: request.confirm_id,
                    timeout_seconds: 120,
                    deadline_unix_seconds: 0,
                    committed_sections: vec!["[[fib_tables]]".to_string()],
                    runtime_snapshot_token: "kv1:rollback:3".to_string(),
                    human_text: "Aborted confirmed config transaction.".to_string(),
                }),
                runtime_snapshot_token: "kv1:rollback:3".to_string(),
                human_text: "Aborted confirmed config transaction.\n".to_string(),
            },
        ))
    }

    async fn get_config_transaction_status(
        &self,
        _request: Request<server_proto::GetConfigTransactionStatusRequest>,
    ) -> Result<Response<server_proto::ConfigTransactionStatusResponse>, Status> {
        self.state
            .config_status_calls
            .fetch_add(1, Ordering::SeqCst);
        if let Some((code, message)) = self.state.config_status_error.lock().await.clone() {
            return Err(Status::new(code, message));
        }
        Ok(Response::new(
            server_proto::ConfigTransactionStatusResponse {
                confirmation: Some(server_proto::ConfigTransactionConfirmation {
                    status: server_proto::ConfigTransactionConfirmationStatus::None as i32,
                    confirm_id: String::new(),
                    timeout_seconds: 0,
                    deadline_unix_seconds: 0,
                    committed_sections: Vec::new(),
                    runtime_snapshot_token: String::new(),
                    human_text: "No confirmed config transaction is pending.".to_string(),
                }),
                human_text: "No confirmed config transaction is pending.\n".to_string(),
            },
        ))
    }

    async fn get_effective_config(
        &self,
        _request: Request<server_proto::GetEffectiveConfigRequest>,
    ) -> Result<Response<server_proto::GetEffectiveConfigResponse>, Status> {
        self.state
            .config_effective_calls
            .fetch_add(1, Ordering::SeqCst);
        if let Some((code, message)) = self.state.config_effective_error.lock().await.clone() {
            return Err(Status::new(code, message));
        }
        let toml = self.state.config_effective_toml.lock().await.clone().unwrap_or_else(|| {
            "[global]\nasn = 65000\nrouter_id = \"192.0.2.1\"\n\n[[neighbors]]\naddress = \"192.0.2.2\"\nhold_time = 90\nremote_asn = 65000\n".to_string()
        });
        Ok(Response::new(server_proto::GetEffectiveConfigResponse {
            toml,
        }))
    }
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
            tcp_ao_support: server_proto::TcpAoSupport::Supported as i32,
            tcp_ao_detail: String::new(),
        }))
    }
}

struct MockControlService {
    state: Arc<MockState>,
}

struct MockBfdService {
    state: Arc<MockState>,
}

#[tonic::async_trait]
impl rustbgpd_api::proto::bfd_service_server::BfdService for MockBfdService {
    async fn get_bfd_sessions(
        &self,
        request: Request<server_proto::GetBfdSessionsRequest>,
    ) -> Result<Response<server_proto::GetBfdSessionsResponse>, Status> {
        self.state.bfd_calls.fetch_add(1, Ordering::SeqCst);
        let request = request.into_inner();
        *self.state.last_bfd_request.lock().await = Some(request.clone());
        if let Some((code, message)) = self.state.bfd_error.lock().await.clone() {
            return Err(Status::new(code, message));
        }
        let mut sessions = self.state.bfd_sessions.lock().await.clone();
        if !request.peer_address.is_empty() {
            sessions.retain(|session| session.peer_address == request.peer_address);
        }
        Ok(Response::new(server_proto::GetBfdSessionsResponse {
            sessions,
        }))
    }
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
            daemon_version: "0.0.0-mock".to_string(),
        }))
    }

    async fn get_metrics(
        &self,
        _request: Request<server_proto::MetricsRequest>,
    ) -> Result<Response<server_proto::MetricsResponse>, Status> {
        self.state.metrics_calls.fetch_add(1, Ordering::SeqCst);
        let prometheus_text = self
            .state
            .metrics_text
            .lock()
            .await
            .clone()
            .unwrap_or_else(|| {
                r#"# HELP test 1
evpn_local_originations_total{action="inject"} 1
evpn_duplicate_mac_moves_total{vni="100",mac="02:aa:bb:cc:dd:01"} 2
"#
                .to_string()
            });
        Ok(Response::new(server_proto::MetricsResponse {
            prometheus_text,
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
        self.state
            .list_neighbors_calls
            .fetch_add(1, Ordering::SeqCst);
        Ok(Response::new(server_proto::ListNeighborsResponse {
            neighbors: self.state.list_neighbors_response.lock().await.clone(),
        }))
    }

    async fn get_neighbor_state(
        &self,
        _request: Request<server_proto::GetNeighborStateRequest>,
    ) -> Result<Response<server_proto::NeighborState>, Status> {
        Ok(Response::new(server_proto::NeighborState {
            config: Some(server_proto::NeighborConfig {
                address: "10.0.0.2".to_string(),
                interface: String::new(),
                remote_asn: 65002,
                description: "peer-2".to_string(),
                hold_time: 90,
                send_hold_time: Some(480),
                per_client_best: false,
                max_prefixes: 0,
                families: vec!["ipv4_unicast".to_string()],
                remove_private_as: String::new(),
                peer_group: String::new(),
                route_server_client: true,
                role: "rs".to_string(),
                strict_role: true,
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
            local_role: "rs".to_string(),
            remote_role: "rs-client".to_string(),
            role_negotiated: true,
            otc_routes_blocked: 0,
            import_policy_routes_permitted: 0,
            import_policy_routes_denied: 0,
            export_policy_routes_permitted: 0,
            export_policy_routes_denied: 0,
            update_group: "group:0".to_string(),
            messages_received: 9,
            messages_sent: 8,
            route_reflector_client: false,
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
        Ok(Response::new(server_proto::ListDynamicNeighborsResponse {
            ranges: Vec::new(),
        }))
    }

    async fn add_dynamic_neighbor(
        &self,
        request: Request<server_proto::AddDynamicNeighborRequest>,
    ) -> Result<Response<server_proto::AddDynamicNeighborResponse>, Status> {
        *self.state.last_add_dynamic_neighbor.lock().await = Some(request.into_inner());
        Ok(Response::new(server_proto::AddDynamicNeighborResponse {}))
    }

    async fn delete_dynamic_neighbor(
        &self,
        request: Request<server_proto::DeleteDynamicNeighborRequest>,
    ) -> Result<Response<server_proto::DeleteDynamicNeighborResponse>, Status> {
        *self.state.last_delete_dynamic_neighbor.lock().await = Some(request.into_inner());
        Ok(Response::new(
            server_proto::DeleteDynamicNeighborResponse {},
        ))
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

impl MockRibService {
    /// Record the request and serve the next canned route page (an
    /// empty final page when none are queued).
    async fn next_route_page(
        &self,
        request: server_proto::ListRoutesRequest,
    ) -> server_proto::ListRoutesResponse {
        self.state.list_route_requests.lock().await.push(request);
        let mut pages = self.state.list_route_pages.lock().await;
        if pages.is_empty() {
            server_proto::ListRoutesResponse {
                routes: vec![],
                next_page_token: String::new(),
                total_count: 0,
            }
        } else {
            pages.remove(0)
        }
    }
}

struct MockEvpnService;

#[tonic::async_trait]
impl rustbgpd_api::proto::evpn_service_server::EvpnService for MockEvpnService {
    async fn get_evpn_runtime(
        &self,
        _request: Request<server_proto::GetEvpnRuntimeRequest>,
    ) -> Result<Response<server_proto::EvpnRuntimeState>, Status> {
        Ok(Response::new(server_proto::EvpnRuntimeState {
            generation: 1,
            lifecycle: server_proto::EvpnRuntimeLifecycle::Active as i32,
            mutation_state: server_proto::EvpnRuntimeMutationState::EvpnRuntimeMutationDisabled
                as i32,
            evpn_instances_count: 1,
            evpn_ip_vrfs_count: 0,
            ethernet_segments_count: 0,
            ethernet_segment_member_vnis_count: 0,
            message: "startup snapshot active; runtime EVPN mutation disabled".to_string(),
        }))
    }

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
                bridge_vlan: Some(10),
                advertise_svi_mac: false,
                originated_local_macs_count: 2,
                readiness_state:
                    server_proto::EvpnInstanceReadinessState::EvpnInstanceReadinessReady as i32,
                not_ready_reason: String::new(),
            }],
        }))
    }

    async fn list_managed_netdevs(
        &self,
        _request: Request<server_proto::ListManagedNetdevsRequest>,
    ) -> Result<Response<server_proto::ListManagedNetdevsResponse>, Status> {
        Ok(Response::new(server_proto::ListManagedNetdevsResponse {
            netdevs: vec![server_proto::ManagedNetdevState {
                class: server_proto::ManagedNetdevClass::Bridge as i32,
                name: "br100".to_string(),
                desired: true,
                ownership_stamp: "rustbgpd:bridge:leaf-1:br100".to_string(),
                state: server_proto::ManagedNetdevLifecycleState::ManagedNetdevStateOwnedSafe
                    as i32,
                reason: String::new(),
                ifindex: Some(10),
                observed_vlan_filtering: Some(true),
                observed_stamps: vec!["rustbgpd:bridge:leaf-1:br100".to_string()],
                observed_vni: None,
                observed_vlan: None,
                observed_local: None,
                observed_dstport: None,
                observed_learning_disabled: None,
                observed_collect_metadata: None,
                observed_vnifilter: None,
                observed_bridge: None,
                observed_table_id: None,
                observed_up: None,
                observed_master: None,
                observed_router_mac: None,
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

    async fn list_ethernet_segments(
        &self,
        request: Request<server_proto::ListEthernetSegmentsRequest>,
    ) -> Result<Response<server_proto::ListEthernetSegmentsResponse>, Status> {
        let filter = request.into_inner().esi;
        let esi = "03:00:00:00:00:00:00:00:00:07";
        let segments = if filter.is_empty() || filter == esi {
            vec![server_proto::EthernetSegmentState {
                esi: esi.to_string(),
                member_vnis: vec![100],
                redundancy_mode: "single-active".to_string(),
                df_algorithm: "highest-preference".to_string(),
                df_preference: 500,
                df_dont_preempt: true,
                originator_ip: "10.0.0.1".to_string(),
                drained: true,
                drain_reasons: vec!["operator".to_string()],
                members: vec![server_proto::EthernetSegmentMemberState {
                    vni: 100,
                    df_role: "nondf".to_string(),
                    bum_forwarding_action: "suppress".to_string(),
                    bridge: "br100".to_string(),
                    same_esi_bias_eligible: false,
                }],
                ac_gate_state: "blocked".to_string(),
                ac_gate_interface: "eth1".to_string(),
                fdb_nexthop_groups_count: 1,
                fdb_nexthop_ref_macs_count: 1,
            }]
        } else {
            Vec::new()
        };
        Ok(Response::new(server_proto::ListEthernetSegmentsResponse {
            segments,
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

    async fn clear_duplicate_mac_quarantine(
        &self,
        _request: Request<server_proto::ClearDuplicateMacQuarantineRequest>,
    ) -> Result<Response<server_proto::ClearDuplicateMacQuarantineResponse>, Status> {
        Ok(Response::new(
            server_proto::ClearDuplicateMacQuarantineResponse {
                cleared: true,
                message: "duplicate-MAC quarantine cleared".to_string(),
            },
        ))
    }

    async fn set_ethernet_segment_drain(
        &self,
        request: Request<server_proto::SetEthernetSegmentDrainRequest>,
    ) -> Result<Response<server_proto::SetEthernetSegmentDrainResponse>, Status> {
        let req = request.into_inner();
        Ok(Response::new(
            server_proto::SetEthernetSegmentDrainResponse {
                drained: req.drained,
                changed: true,
                member_vni_count: 1,
                message: if req.drained {
                    format!("Ethernet Segment {} drained", req.esi)
                } else {
                    format!("Ethernet Segment {} undrained", req.esi)
                },
                reasons: if req.drained {
                    vec!["operator".to_string()]
                } else {
                    Vec::new()
                },
            },
        ))
    }

    async fn apply_evpn_runtime(
        &self,
        _request: Request<server_proto::ApplyEvpnRuntimeRequest>,
    ) -> Result<Response<server_proto::ApplyEvpnRuntimeResponse>, Status> {
        Err(Status::unimplemented("not in mock"))
    }
}

struct MockEventService {
    state: Arc<MockState>,
}

#[tonic::async_trait]
impl rustbgpd_api::proto::event_service_server::EventService for MockEventService {
    type WatchEventsStream =
        std::pin::Pin<Box<dyn Stream<Item = Result<server_proto::BgpEvent, Status>> + Send>>;
    type SubscribeFromEventStream =
        std::pin::Pin<Box<dyn Stream<Item = Result<server_proto::BgpEvent, Status>> + Send>>;

    async fn watch_events(
        &self,
        _request: Request<server_proto::WatchEventsRequest>,
    ) -> Result<Response<Self::WatchEventsStream>, Status> {
        Err(Status::unimplemented("not used in CLI tests"))
    }

    async fn subscribe_from_event(
        &self,
        _request: Request<server_proto::SubscribeFromEventRequest>,
    ) -> Result<Response<Self::SubscribeFromEventStream>, Status> {
        Err(Status::unimplemented("not used in CLI tests"))
    }

    async fn list_evpn_events(
        &self,
        _request: Request<server_proto::ListEvpnEventsRequest>,
    ) -> Result<Response<server_proto::ListEvpnEventsResponse>, Status> {
        Ok(Response::new(server_proto::ListEvpnEventsResponse {
            events: vec![],
        }))
    }

    async fn list_session_events(
        &self,
        _request: Request<server_proto::ListSessionEventsRequest>,
    ) -> Result<Response<server_proto::ListSessionEventsResponse>, Status> {
        self.state
            .list_session_events_calls
            .fetch_add(1, Ordering::SeqCst);
        Ok(Response::new(server_proto::ListSessionEventsResponse {
            events: self.state.session_events.lock().await.clone(),
        }))
    }

    async fn list_policy_events(
        &self,
        _request: Request<server_proto::ListPolicyEventsRequest>,
    ) -> Result<Response<server_proto::ListPolicyEventsResponse>, Status> {
        self.state
            .list_policy_events_calls
            .fetch_add(1, Ordering::SeqCst);
        Ok(Response::new(server_proto::ListPolicyEventsResponse {
            events: vec![],
        }))
    }
}

#[tonic::async_trait]
impl rustbgpd_api::proto::rib_service_server::RibService for MockRibService {
    type WatchRoutesStream =
        std::pin::Pin<Box<dyn Stream<Item = Result<server_proto::RouteEvent, Status>> + Send>>;
    type WatchRouteEventsStream =
        std::pin::Pin<Box<dyn Stream<Item = Result<server_proto::BgpEvent, Status>> + Send>>;

    async fn list_received_routes(
        &self,
        request: Request<server_proto::ListRoutesRequest>,
    ) -> Result<Response<server_proto::ListRoutesResponse>, Status> {
        Ok(Response::new(
            self.next_route_page(request.into_inner()).await,
        ))
    }

    async fn list_best_routes(
        &self,
        request: Request<server_proto::ListRoutesRequest>,
    ) -> Result<Response<server_proto::ListRoutesResponse>, Status> {
        Ok(Response::new(
            self.next_route_page(request.into_inner()).await,
        ))
    }

    async fn list_advertised_routes(
        &self,
        request: Request<server_proto::ListRoutesRequest>,
    ) -> Result<Response<server_proto::ListRoutesResponse>, Status> {
        Ok(Response::new(
            self.next_route_page(request.into_inner()).await,
        ))
    }

    async fn explain_best_path(
        &self,
        request: Request<server_proto::ExplainBestPathRequest>,
    ) -> Result<Response<server_proto::ExplainBestPathResponse>, Status> {
        let req = request.into_inner();
        *self.state.last_explain_best_path.lock().await = Some(req.clone());
        Ok(Response::new(server_proto::ExplainBestPathResponse {
            prefix: "203.0.113.0".to_string(),
            prefix_length: 24,
            best_route: Some(server_proto::Route {
                prefix: "203.0.113.0".to_string(),
                prefix_length: 24,
                next_hop: "198.51.100.1".to_string(),
                peer_address: "198.51.100.1".to_string(),
                ..Default::default()
            }),
            candidates: vec![server_proto::BestPathCandidate {
                route: Some(server_proto::Route {
                    prefix: "203.0.113.0".to_string(),
                    prefix_length: 24,
                    next_hop: "198.51.100.2".to_string(),
                    peer_address: "198.51.100.2".to_string(),
                    ..Default::default()
                }),
                vs_best_reason: "higher_local_pref".to_string(),
                vs_best_ordering: "worse".to_string(),
                advertised_path_id: 0,
                vs_best_detail: "local_pref 100 < 200".to_string(),
                multipath: "none".to_string(),
            }],
            peer_address: req.peer_address,
            add_path_send_max: 0,
            best_reason: "higher_local_pref".to_string(),
            best_reason_detail: "local_pref 200 > 100".to_string(),
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
                orr_vantage: String::new(),
                orr_candidates: vec![],
                gates: vec![
                    server_proto::ExportGateStep {
                        gate: "best_route".to_string(),
                        code: "ebgp_route".to_string(),
                        verdict: server_proto::ExportGateVerdict::Pass as i32,
                        detail: "best route was learned from an eBGP peer (Loc-RIB best \
                                 from 198.51.100.2)"
                            .to_string(),
                    },
                    server_proto::ExportGateStep {
                        gate: "export_policy".to_string(),
                        code: "policy_permitted".to_string(),
                        verdict: server_proto::ExportGateVerdict::Pass as i32,
                        detail: "export policy \"lp200\" permitted this route".to_string(),
                    },
                    server_proto::ExportGateStep {
                        gate: "adj_rib_out".to_string(),
                        code: "already_advertised".to_string(),
                        verdict: server_proto::ExportGateVerdict::Pass as i32,
                        detail: "identical route already advertised - peer is in sync, no \
                                 re-announcement"
                            .to_string(),
                    },
                ],
                update_group_id: Some(1),
                already_advertised: true,
                rd: String::new(),
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
            next_page_token: String::new(),
            total_count: 0,
        }))
    }

    async fn list_bgp_ls_routes(
        &self,
        request: Request<server_proto::ListBgpLsRequest>,
    ) -> Result<Response<server_proto::ListBgpLsResponse>, Status> {
        *self.state.last_list_bgpls.lock().await = Some(request.into_inner());
        Ok(Response::new(server_proto::ListBgpLsResponse {
            routes: vec![server_proto::BgpLsRouteEntry {
                afi_safi: server_proto::AddressFamily::BgpLs as i32,
                family: "bgp_ls".to_string(),
                nlri_type: 1,
                nlri_type_name: "node".to_string(),
                route_distinguisher: vec![],
                payload: vec![0x01, 0x02, 0x03],
                descriptor: vec![0x04, 0x05],
                next_hop: "192.0.2.1".to_string(),
                peer_address: "198.51.100.1".to_string(),
                as_path: vec![64512],
                communities: vec![],
                extended_communities: vec![],
                stale: false,
                llgr_stale: false,
                path_id: 0,
                bgp_ls_attribute: vec![0xaa, 0xbb],
            }],
        }))
    }

    async fn list_vpn_routes(
        &self,
        request: Request<server_proto::ListVpnRoutesRequest>,
    ) -> Result<Response<server_proto::ListVpnRoutesResponse>, Status> {
        *self.state.last_list_vpn.lock().await = Some(request.into_inner());
        Ok(Response::new(server_proto::ListVpnRoutesResponse {
            routes: vec![server_proto::VpnRouteEntry {
                afi_safi: "l3vpn_ipv4_unicast".to_string(),
                route_distinguisher: vec![0, 0, 0xfd, 0xe8, 0, 0, 0, 1],
                route_distinguisher_str: "65000:1".to_string(),
                prefix: "10.1.0.0/24".to_string(),
                labels: vec![24017],
                next_hop: "192.0.2.1".to_string(),
                peer_address: "198.51.100.1".to_string(),
                as_path: vec![64512],
                communities: vec![],
                extended_communities: vec!["RT:65000:1".to_string()],
                stale: false,
                llgr_stale: false,
                path_id: 0,
            }],
        }))
    }

    async fn list_labeled_routes(
        &self,
        request: Request<server_proto::ListLabeledRoutesRequest>,
    ) -> Result<Response<server_proto::ListLabeledRoutesResponse>, Status> {
        *self.state.last_list_labeled.lock().await = Some(request.into_inner());
        Ok(Response::new(server_proto::ListLabeledRoutesResponse {
            routes: vec![server_proto::LabeledRouteEntry {
                afi_safi: "ipv4_labeled_unicast".to_string(),
                prefix: "10.1.0.0/24".to_string(),
                labels: vec![100],
                next_hop: "192.0.2.1".to_string(),
                peer_address: "198.51.100.1".to_string(),
                as_path: vec![64512],
                communities: vec![],
                extended_communities: vec![],
                stale: false,
                llgr_stale: false,
                path_id: 0,
            }],
        }))
    }

    async fn list_rtc_routes(
        &self,
        request: Request<server_proto::ListRtcRoutesRequest>,
    ) -> Result<Response<server_proto::ListRtcRoutesResponse>, Status> {
        *self.state.last_list_rtc.lock().await = Some(request.into_inner());
        Ok(Response::new(server_proto::ListRtcRoutesResponse {
            routes: vec![
                server_proto::RtcRouteEntry {
                    is_default: true,
                    origin_as: 0,
                    route_target: String::new(),
                    prefix_len: 0,
                    next_hop: "0.0.0.0".to_string(),
                    peer_address: "0.0.0.0".to_string(),
                    as_path: vec![],
                    communities: vec![],
                    stale: false,
                    llgr_stale: false,
                    path_id: 0,
                },
                server_proto::RtcRouteEntry {
                    is_default: false,
                    origin_as: 65001,
                    route_target: "RT:65001:100".to_string(),
                    prefix_len: 96,
                    next_hop: "192.0.2.1".to_string(),
                    peer_address: "198.51.100.1".to_string(),
                    as_path: vec![64512],
                    communities: vec![],
                    stale: false,
                    llgr_stale: false,
                    path_id: 0,
                },
            ],
        }))
    }

    async fn list_topology_nodes(
        &self,
        request: Request<server_proto::ListTopologyNodesRequest>,
    ) -> Result<Response<server_proto::ListTopologyNodesResponse>, Status> {
        *self.state.last_list_topology_nodes.lock().await = Some(request.into_inner());
        Ok(Response::new(server_proto::ListTopologyNodesResponse {
            nodes: vec![server_proto::TopologyNodeEntry {
                key: "02aabb".to_string(),
                asn: 64512,
                bgp_ls_id: 0,
                router_id: "000000000001".to_string(),
                link_count: 2,
            }],
        }))
    }

    async fn list_topology_links(
        &self,
        request: Request<server_proto::ListTopologyLinksRequest>,
    ) -> Result<Response<server_proto::ListTopologyLinksResponse>, Status> {
        *self.state.last_list_topology_links.lock().await = Some(request.into_inner());
        Ok(Response::new(server_proto::ListTopologyLinksResponse {
            links: vec![server_proto::TopologyLinkEntry {
                local_key: "02aabb".to_string(),
                local_router_id: "000000000001".to_string(),
                remote_key: "02ccdd".to_string(),
                remote_router_id: "000000000002".to_string(),
                cost: 10,
                addresses: vec!["10.0.8.1".to_string()],
            }],
        }))
    }

    async fn list_orr_status(
        &self,
        request: Request<server_proto::ListOrrStatusRequest>,
    ) -> Result<Response<server_proto::ListOrrStatusResponse>, Status> {
        *self.state.last_list_orr_status.lock().await = Some(request.into_inner());
        Ok(Response::new(server_proto::ListOrrStatusResponse {
            vantages: vec![server_proto::OrrVantageStatusEntry {
                vantage: "10.0.8.1".to_string(),
                resolved: true,
                node_key: "02aabb".to_string(),
                asn: 64512,
                bgp_ls_id: 0,
                router_id: "000000000001".to_string(),
                reachable_nodes: 4,
                peers: vec!["192.0.2.1".to_string()],
            }],
            topology_nodes: 4,
            topology_links: 4,
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

    async fn watch_route_events(
        &self,
        _request: Request<server_proto::WatchRoutesRequest>,
    ) -> Result<Response<Self::WatchRouteEventsStream>, Status> {
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

    async fn set_fib_table(
        &self,
        request: Request<server_proto::SetFibTableRequest>,
    ) -> Result<Response<server_proto::ListFibTablesResponse>, Status> {
        let request = request.into_inner();
        let table = request.table.clone().unwrap_or_default();
        *self.state.last_set_fib_table.lock().await = Some(request);
        Ok(Response::new(server_proto::ListFibTablesResponse {
            tables: vec![table],
            runtime_available: true,
        }))
    }

    async fn delete_fib_table(
        &self,
        request: Request<server_proto::DeleteFibTableRequest>,
    ) -> Result<Response<server_proto::ListFibTablesResponse>, Status> {
        *self.state.last_delete_fib_table.lock().await = Some(request.into_inner());
        Ok(Response::new(server_proto::ListFibTablesResponse {
            tables: vec![],
            runtime_available: true,
        }))
    }

    async fn list_fib_tables(
        &self,
        _request: Request<server_proto::ListFibTablesRequest>,
    ) -> Result<Response<server_proto::ListFibTablesResponse>, Status> {
        Ok(Response::new(server_proto::ListFibTablesResponse {
            tables: vec![mock_fib_table()],
            runtime_available: true,
        }))
    }
}

fn mock_fib_table() -> server_proto::FibTableConfig {
    server_proto::FibTableConfig {
        name: "edge".to_string(),
        table_id: 1000,
        metric: 200,
        families: vec!["ipv4_unicast".to_string()],
        allowed_peer_groups: vec![],
        allowed_neighbors: vec![],
        max_routes: None,
        maximum_paths: None,
        maximum_paths_ebgp: None,
        maximum_paths_ibgp: None,
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

    async fn explain_import_policy(
        &self,
        request: Request<server_proto::ExplainImportPolicyRequest>,
    ) -> Result<Response<server_proto::ExplainImportPolicyResponse>, Status> {
        let req = request.into_inner();
        *self.state.last_explain_import.lock().await = Some(req.clone());

        if let Some(outcome) = *self.state.explain_import_synthetic_outcome.lock().await {
            return Ok(Response::new(server_proto::ExplainImportPolicyResponse {
                peer_address: req.peer_address.clone(),
                prefix: req.prefix.clone(),
                prefix_length: req.prefix_length,
                afi_safi: req.afi_safi,
                current_policy_generation: 0,
                matches: vec![server_proto::ImportExplainMatch {
                    outcome: outcome as i32,
                    peer_address: req.peer_address,
                    prefix: req.prefix,
                    prefix_length: req.prefix_length,
                    path_id: req.path_id.unwrap_or(0),
                    afi_safi: req.afi_safi,
                    ..Default::default()
                }],
            }));
        }

        let modifications = Some(server_proto::ExplainModifications {
            set_local_pref: Some(200),
            set_med: None,
            set_next_hop: String::new(),
            communities_add: vec![65001 << 16 | 100],
            communities_remove: vec![],
            extended_communities_add: vec![0x0002_fde8_0000_0064],
            extended_communities_remove: vec![],
            large_communities_add: vec![],
            large_communities_remove: vec![],
            as_path_prepend_asn: None,
            as_path_prepend_count: None,
        });
        let permit = |path_id: u32| server_proto::ImportExplainMatch {
            outcome: server_proto::ImportExplainOutcome::Permit as i32,
            peer_address: req.peer_address.clone(),
            prefix: req.prefix.clone(),
            prefix_length: req.prefix_length,
            path_id,
            afi_safi: req.afi_safi,
            matched_policy: "from-transit".to_string(),
            rpki_validation: "valid".to_string(),
            aspa_validation: "unknown".to_string(),
            modifications: modifications.clone(),
            evaluated_at_unix_ns: 1_700_000_000_000_000_000,
            policy_generation: 3,
            statements: vec![server_proto::ImportExplainStatementStep {
                policy_index: 0,
                policy_name: "from-transit".to_string(),
                default_action: false,
                statement_index: 1,
                action: "permit".to_string(),
                matched_conditions: vec!["community 65001:100".to_string()],
                modifications: vec!["local_pref 100 -> 200".to_string()],
                term: String::new(),
                term_traces: vec![],
            }],
        };
        // When the caller pins a path_id, return exactly that path;
        // otherwise return two paths so the Add-Path "all matches"
        // rendering is exercised (one permit, one deny).
        let matches = match req.path_id {
            Some(path_id) => vec![permit(path_id)],
            None => vec![
                permit(1),
                server_proto::ImportExplainMatch {
                    outcome: server_proto::ImportExplainOutcome::Deny as i32,
                    peer_address: req.peer_address.clone(),
                    prefix: req.prefix.clone(),
                    prefix_length: req.prefix_length,
                    path_id: 2,
                    afi_safi: req.afi_safi,
                    matched_policy: "block-bogons".to_string(),
                    rpki_validation: "invalid".to_string(),
                    aspa_validation: "unknown".to_string(),
                    modifications: None,
                    evaluated_at_unix_ns: 1_700_000_000_000_000_000,
                    policy_generation: 3,
                    statements: vec![server_proto::ImportExplainStatementStep {
                        policy_index: 0,
                        policy_name: "block-bogons".to_string(),
                        default_action: true,
                        statement_index: 0,
                        action: "deny".to_string(),
                        matched_conditions: vec![],
                        modifications: vec![],
                        term: String::new(),
                        term_traces: vec![],
                    }],
                },
            ],
        };
        Ok(Response::new(server_proto::ExplainImportPolicyResponse {
            peer_address: req.peer_address,
            prefix: req.prefix,
            prefix_length: req.prefix_length,
            afi_safi: req.afi_safi,
            current_policy_generation: 3,
            matches,
        }))
    }

    async fn get_policy_stats(
        &self,
        request: Request<server_proto::GetPolicyStatsRequest>,
    ) -> Result<Response<server_proto::GetPolicyStatsResponse>, Status> {
        let req = request.into_inner();
        let export_chain = server_proto::PolicyChainStats {
            peer_address: "10.0.0.2".to_string(),
            direction: "export".to_string(),
            routes_evaluated: 7,
            policy_generation: 0,
            eval_errors: 2,
            last_error: "overflow in policy customer-in(200) term customer-routes".to_string(),
            terms: vec![
                server_proto::PolicyTermStat {
                    policy_index: 0,
                    policy: "customer-in(200)".to_string(),
                    term_index: 0,
                    term: "customer-routes".to_string(),
                    hits: 5,
                },
                server_proto::PolicyTermStat {
                    policy_index: 0,
                    policy: "customer-in(200)".to_string(),
                    term_index: 1,
                    term: String::new(),
                    hits: 2,
                },
            ],
        };
        let import_chain = server_proto::PolicyChainStats {
            peer_address: "10.0.0.2".to_string(),
            direction: "import".to_string(),
            routes_evaluated: 11,
            policy_generation: 3,
            eval_errors: 0,
            last_error: String::new(),
            terms: vec![server_proto::PolicyTermStat {
                policy_index: 0,
                policy: "customer-in(200)".to_string(),
                term_index: 0,
                term: "customer-routes".to_string(),
                hits: 9,
            }],
        };
        let chains = match req.direction.as_str() {
            "" | "export" => vec![export_chain],
            "import" => vec![import_chain],
            "both" => vec![export_chain, import_chain],
            other => {
                return Err(Status::invalid_argument(format!(
                    "unexpected direction {other:?}"
                )));
            }
        };
        Ok(Response::new(server_proto::GetPolicyStatsResponse {
            chains,
            datasets: vec![server_proto::PolicyDatasetStatus {
                name: "customers".to_string(),
                kind: "asn-set".to_string(),
                generation: 7,
                records: 42,
                path: "/var/lib/rustbgpd/datasets/customers.list".to_string(),
                last_error: "line 3: bad".to_string(),
            }],
        }))
    }

    async fn test_policy(
        &self,
        request: Request<server_proto::TestPolicyRequest>,
    ) -> Result<Response<server_proto::TestPolicyResponse>, Status> {
        *self.state.last_test_policy.lock().await = Some(request.into_inner());
        Ok(Response::new(server_proto::TestPolicyResponse {
            compiled: true,
            diagnostics: String::new(),
            routes_evaluated: 3,
            accepted: 2,
            rejected: 1,
            modified: 1,
            term_hits: vec![server_proto::TestPolicyTermHits {
                term: "customer-routes".to_string(),
                hits: 2,
            }],
            diffs: vec![server_proto::TestPolicyDiff {
                prefix: "10.10.1.0".to_string(),
                prefix_length: 24,
                peer: "10.0.0.9".to_string(),
                changes: vec!["local_pref unset -> 200".to_string()],
            }],
        }))
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
