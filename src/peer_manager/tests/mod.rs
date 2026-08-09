use super::*;

use bytes::BytesMut;

use rustbgpd_api::peer_types::{
    CatalogMutationError, DynamicRangeTarget, ImportValidationDependency, PeerKey,
    SessionLifecycleEventType,
};

use rustbgpd_fsm::SessionState;

use rustbgpd_transport::handle::MaxPrefixState;

use rustbgpd_transport::{
    PeerCommand, PeerSessionState, TcpAoRotationStatus, WarmCheckpointSessionState,
};

use rustbgpd_wire::{
    Capability, Message, OpenMessage, decode_message, encode_message, peek_message_length,
};

use std::collections::BTreeSet;

use std::net::Ipv6Addr;

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
};

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use tokio::net::TcpListener;

use tokio::net::TcpStream;

use tokio::sync::{Notify, broadcast, mpsc, oneshot};

use crate::test_support::{assert_tier_authorized_test_config, tier_authorized_uds_test_config};

fn key(addr: IpAddr) -> PeerKey {
    PeerKey::new(addr, None)
}

fn scoped_key(addr: IpAddr, interface: &str) -> PeerKey {
    PeerKey::new(addr, Some(interface.to_string()))
}

fn sock(addr: IpAddr) -> SocketAddr {
    SocketAddr::new(addr, 179)
}

fn make_config(addr: IpAddr, asn: u32) -> PeerManagerNeighborConfig {
    PeerManagerNeighborConfig {
        min_hold_time: None,
        address: addr,
        interface: None,
        scope_id: None,
        remote_asn: asn,
        description: format!("test-peer-{addr}"),
        peer_group: None,
        hold_time: None,
        send_hold_time: None,
        slow_peer_threshold_pct: rustbgpd_transport::DEFAULT_SLOW_PEER_THRESHOLD_PCT,
        slow_peer_duration: rustbgpd_transport::DEFAULT_SLOW_PEER_DURATION_SECS,
        slow_peer_isolation: false,
        max_prefixes: None,
        max_prefixes_ipv4: None,
        max_prefixes_ipv6: None,
        max_prefix_restart_seconds: None,
        md5_password: None,
        tcp_ao: None,
        ttl_security: false,
        families: vec![(Afi::Ipv4, Safi::Unicast)],
        required_families: Vec::new(),
        graceful_restart: true,
        gr_restart_time: 120,
        gr_peer_restart_time_max: 4095,
        gr_stale_routes_time: 360,
        llgr_stale_time: 0,
        gr_restart_eligible: false,
        local_ipv6_nexthop: None,
        route_reflector_client: false,
        orr_vantage: None,
        route_server_client: false,
        per_client_best: false,
        next_hop_ownership_strict_peer: false,
        interpret_rfc1997: true,
        rs_control_communities: false,
        remove_private_as: rustbgpd_transport::RemovePrivateAs::Disabled,
        add_path_receive: false,
        add_path_send: false,
        add_path_send_max: 0,
        paths_limit_receive_max: 0,
        local_role: None,
        strict_role: false,
        prefix_orf_receive: false,
        disable_ipv4_unicast: false,
        import_policy: None,
        export_policy: None,
    }
}

async fn subscribe_session_events(
    tx: &mpsc::Sender<PeerManagerCommand>,
) -> broadcast::Receiver<SessionEvent> {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::SubscribeSessionEvents { reply: reply_tx })
        .await
        .unwrap();
    reply_rx.await.unwrap()
}

/// The export-only cohort transaction opens with a best-effort destination
/// preparation; scripted RIB dialogues answer it with a skip so the cohort
/// proceeds on its ordinary staging path.
async fn skip_destination_prestage(rib_rx: &mut mpsc::Receiver<RibUpdate>) {
    let RibUpdate::PrepareExportPolicyDestination { reply, .. } = rib_rx.recv().await.unwrap()
    else {
        panic!("expected destination preparation to open the cohort dialogue");
    };
    let _ = reply.send(Err("test: prestage skipped".to_string()));
}

async fn wait_for_session_event(
    rx: &mut broadcast::Receiver<SessionEvent>,
    event_type: SessionLifecycleEventType,
) -> SessionLifecycleEvent {
    for _ in 0..20 {
        let event = tokio::time::timeout(Duration::from_millis(250), rx.recv())
            .await
            .expect("session event timeout")
            .expect("session event channel closed");
        if let SessionEvent::Lifecycle(event) = event
            && event.event_type == event_type
        {
            return event;
        }
    }
    panic!("session event {event_type:?} did not arrive");
}

fn test_peer_manager() -> PeerManager {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    )
}

async fn query_session_event_history(
    mgr: &PeerManager,
    peer: Option<IpAddr>,
    event_types: BTreeSet<SessionLifecycleEventType>,
    limit: usize,
) -> Vec<SessionLifecycleEvent> {
    let (reply_tx, reply_rx) = oneshot::channel();
    mgr.handle_query_session_event_history(peer, &event_types, limit, reply_tx);
    reply_rx.await.unwrap()
}

async fn query_policy_event_history(
    mgr: &PeerManager,
    peer: Option<IpAddr>,
    limit: usize,
) -> Vec<PolicyEvent> {
    let (reply_tx, reply_rx) = oneshot::channel();
    mgr.handle_query_policy_event_history(peer, limit, reply_tx);
    reply_rx.await.unwrap()
}

fn make_dynamic_manager_config() -> Config {
    let mut peer_groups = HashMap::new();
    peer_groups.insert(
        "ix-members".to_string(),
        crate::config::PeerGroupConfig {
            families: vec!["ipv4_unicast".to_string()],
            ..Default::default()
        },
    );

    let config = Config {
        config_epoch: None,
        global: crate::config::Global {
            asn: 65001,
            router_id: "10.0.0.1".to_string(),
            listen_port: BGP_PORT,
            cluster_id: None,
            runtime_state_dir: "/tmp/rustbgpd-tests".to_string(),
            telemetry: crate::config::TelemetryConfig {
                prometheus_addr: Some("127.0.0.1:9179".to_string()),
                log_format: "json".to_string(),
                grpc_tcp: None,
                grpc_uds: Some(crate::config::GrpcUdsListenerConfig {
                    enabled: true,
                    path: Some("/tmp/rustbgpd-test.sock".to_string()),
                    mode: 0o600,
                    access_mode: None,
                    max_tier: None,
                    token_file: None,
                    principal: Some("rustbgpd://operator/test-only".to_string()),
                }),
            },
            dynamic_neighbor_limit: Some(100),
            worker_threads: None,
            honor_graceful_shutdown: false,
            honor_blackhole: false,
            multipath_relax: false,
            link_bandwidth_weighted: false,
            install_blackhole_discard: false,
            allow_blackhole_broad_prefixes: false,
            ebgp_requires_policy: None,
            warm_cache_checkpoint_on_shutdown: false,
        },
        security: crate::config::SecurityConfig {
            grpc: crate::config::GrpcSecurityConfig {
                enforcement: crate::config::GrpcEnforcementConfig::Tier,
                roles: HashMap::from([(
                    "rustbgpd://operator/test-only".to_string(),
                    crate::config::GrpcRoleConfig::Operator,
                )]),
            },
        },
        neighbors: Vec::new(),
        peer_groups,
        policy: crate::config::PolicyConfig::default(),
        dynamic_neighbors: vec![crate::config::DynamicNeighborConfig {
            prefix: "127.0.0.0/8".to_string(),
            peer_group: "ix-members".to_string(),
            remote_asn: 0,
            description: Some("ix-auto".to_string()),
            tcp_ao: None,
        }],
        rpki: None,
        bmp: None,
        gnmi_dialout: None,
        mrt: None,
        file_path: None,
        evpn_instances: Vec::new(),
        ethernet_segments: Vec::new(),
        evpn_ip_vrfs: Vec::new(),
        managed_netdevs: crate::config::ManagedNetdevsConfig::default(),
        fib_tables: Vec::new(),
        bfd_profiles: Vec::new(),
        apply_bum_enforcement: false,
        event_history: crate::config::EventHistoryConfig::default(),
        inbound_admission: crate::config::InboundAdmissionConfig::default(),
    };
    assert_tier_authorized_test_config(&config);
    config
}

fn load_test_config(toml: &str) -> Config {
    Config::load_toml_with_diagnostics(&tier_authorized_uds_test_config(toml), "test config")
        .unwrap()
}

fn dynamic_test_manager() -> PeerManager {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    PeerManager::new_with_config(
        rx,
        mpsc::unbounded_channel().1,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
        None,
        make_dynamic_manager_config(),
    )
}

fn test_tcp_ao() -> crate::config::TcpAoConfig {
    crate::config::TcpAoConfig {
        key: "secret".to_string(),
        send_id: 1,
        recv_id: 1,
        algorithm: "hmac(sha256)".to_string(),
        preferred: false,
        deprecated: false,
    }
}

fn deny_policy_chain() -> PolicyChain {
    use rustbgpd_policy::{Policy, PolicyAction};

    PolicyChain::new(vec![Policy {
        entries: Vec::new(),
        default_action: PolicyAction::Deny,
    }])
}

/// A deny chain padded to `depth + 1` copies of the deny policy —
/// content-distinct per depth. Per-peer distinct export targets keep a
/// snapshot off the import-tolerant export cohort (LAN-462 relaxed its
/// import-equality requirement, so a uniform import+export move now
/// partitions) and on the per-peer authoritative path these regressions pin.
fn distinct_deny_policy_chain(depth: usize) -> PolicyChain {
    use rustbgpd_policy::{Policy, PolicyAction};

    PolicyChain::new(
        (0..=depth)
            .map(|_| Policy {
                entries: Vec::new(),
                default_action: PolicyAction::Deny,
            })
            .collect(),
    )
}

fn validation_policy_chain(dependency: ImportValidationDependency) -> PolicyChain {
    use rustbgpd_policy::{Policy, PolicyAction, PolicyStatement, RouteModifications};
    use rustbgpd_wire::{AspaValidation, RpkiValidation};

    let mut statement = PolicyStatement {
        prefix: None,
        ge: None,
        le: None,
        action: PolicyAction::Deny,
        match_community: vec![],
        match_as_path: None,
        match_neighbor_set: None,
        match_route_type: None,
        match_evpn_route_type: None,
        match_rpki_validation: None,
        match_aspa_validation: None,
        match_as_path_length_ge: None,
        match_as_path_length_le: None,
        match_local_pref_ge: None,
        match_local_pref_le: None,
        match_med_ge: None,
        match_med_le: None,
        match_next_hop: None,
        modifications: RouteModifications::default(),
    };
    match dependency {
        ImportValidationDependency::Rpki => {
            statement.match_rpki_validation = Some(RpkiValidation::Invalid);
        }
        ImportValidationDependency::Aspa => {
            statement.match_aspa_validation = Some(AspaValidation::Invalid);
        }
    }

    PolicyChain::new(vec![Policy {
        entries: vec![statement],
        default_action: PolicyAction::Permit,
    }])
}

fn insert_test_managed_peer(
    mgr: &mut PeerManager,
    addr: IpAddr,
    handle: PeerHandle,
    pending_refresh: bool,
) {
    insert_test_managed_peer_with_asn(mgr, addr, 65002, handle, pending_refresh);
}

fn insert_test_managed_peer_with_asn(
    mgr: &mut PeerManager,
    addr: IpAddr,
    remote_asn: u32,
    handle: PeerHandle,
    pending_refresh: bool,
) {
    let peer_config = make_config(addr, remote_asn);
    let transport = mgr.build_transport_config(&peer_config);
    let hold = transport.peer.hold_time;
    let peer_key = key(addr);
    mgr.peers.insert(
        peer_key.clone(),
        ManagedPeer {
            handle,
            session_id: 1,
            remote_asn,
            description: "test".to_string(),
            peer_group: None,
            enabled: true,
            hold_time: Some(hold),
            max_prefixes: None,
            max_prefix_restart_seconds: None,
            transport_config: transport,
            import_policy: None,
            export_policy: None,
            pending_inbound: None,
            is_dynamic: false,
            rfc8212_external: false,
            tcp_ao_protected: false,
            accepted_dynamic_range: None,
            pending_refresh,
            pending_export_apply: false,
            tcp_ao_rotation: TcpAoRotationStatus::default(),
            advertise_graceful_shutdown: false,
        },
    );
    mgr.register_session(1, &peer_key);
}

fn stalled_policy_query_handle() -> PeerHandle {
    let (commands, mut command_rx) = mpsc::channel(4);
    let task = tokio::spawn(async move {
        let mut held_queries = Vec::new();
        while let Some(command) = command_rx.recv().await {
            if matches!(command, rustbgpd_transport::PeerCommand::Shutdown) {
                break;
            }
            held_queries.push(command);
        }
        Ok(())
    });
    PeerHandle::from_parts(commands, task)
}

fn recording_runtime_config_handle() -> (PeerHandle, mpsc::UnboundedReceiver<u16>) {
    use rustbgpd_transport::PeerCommand;

    let (commands, mut command_rx) = mpsc::channel(16);
    let (seen_tx, seen_rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        while let Some(command) = command_rx.recv().await {
            match command {
                PeerCommand::UpdateRuntimeConfig {
                    gr_peer_restart_time_max,
                    reply,
                    ..
                } => {
                    let _ = seen_tx.send(gr_peer_restart_time_max);
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::Shutdown => break,
                _ => {}
            }
        }
        Ok(())
    });
    (PeerHandle::from_parts(commands, task), seen_rx)
}

fn established_export_policy_test_session(
    addr: IpAddr,
    attempts: Arc<AtomicUsize>,
    fail_on_attempt: Option<usize>,
) -> PeerHandle {
    established_export_policy_test_session_with_queries(addr, attempts, fail_on_attempt).0
}

fn established_export_policy_test_session_with_queries(
    addr: IpAddr,
    attempts: Arc<AtomicUsize>,
    fail_on_attempt: Option<usize>,
) -> (PeerHandle, Arc<AtomicUsize>) {
    use rustbgpd_transport::PeerCommand;

    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(16);
    let queries = Arc::new(AtomicUsize::new(0));
    let task_queries = Arc::clone(&queries);
    let task = tokio::spawn(async move {
        while let Some(command) = session_rx.recv().await {
            match command {
                PeerCommand::UpdateExportPolicy { reply, .. } => {
                    let attempt = attempts.fetch_add(1, Ordering::SeqCst) + 1;
                    let result = if fail_on_attempt == Some(attempt) {
                        Err(rustbgpd_transport::PeerCommandError::CommandFailed(
                            "injected export-policy apply failure".to_string(),
                        ))
                    } else {
                        Ok(())
                    };
                    let _ = reply.send(result);
                }
                PeerCommand::QueryState { reply } => {
                    task_queries.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(PeerSessionState {
                        fsm_state: SessionState::Established,
                        peer_ip: addr,
                        peer_asn: Some(65002),
                        prefix_count: 0,
                        max_prefix: MaxPrefixState::default(),
                        negotiated_hold_time: Some(90),
                        four_octet_as: Some(true),
                        remote_router_id: None,
                        negotiated_session: None,
                        local_role: None,
                        remote_role: None,
                        role_negotiated: false,
                        peer_paths_limits: Vec::new(),
                        effective_add_path_send_limits: Vec::new(),
                        updates_received: 0,
                        updates_sent: 0,
                        notifications_received: 0,
                        notifications_sent: 0,
                        messages_received: 0,
                        messages_sent: 0,
                        otc_routes_blocked: 0,
                        import_policy_routes_permitted: 0,
                        import_policy_routes_denied: 0,
                        flap_count: 0,
                        uptime_secs: 1,
                        last_error: String::new(),
                        tcp_ao_info: None,
                        tcp_ao_protected: false,
                        slow_peer: false,
                    });
                }
                PeerCommand::Shutdown => break,
                _ => {}
            }
        }
        Ok(())
    });
    (PeerHandle::from_parts(session_tx, task), queries)
}

fn rollback_ordering_policy_session(
    addr: IpAddr,
    rib_tx: mpsc::Sender<RibUpdate>,
    fail_first_export: bool,
    rollback_export_delay: Option<Duration>,
) -> PeerHandle {
    use rustbgpd_transport::{PeerCommand, PeerCommandError};

    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(16);
    let task = tokio::spawn(async move {
        let mut export_attempts = 0;
        let mut refresh_attempts = 0;
        while let Some(command) = session_rx.recv().await {
            match command {
                PeerCommand::UpdateImportPolicy { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::UpdateExportPolicy { reply, .. } => {
                    export_attempts += 1;
                    let result = if fail_first_export && export_attempts == 1 {
                        Err(PeerCommandError::CommandFailed(
                            "injected final session failure".to_string(),
                        ))
                    } else {
                        if export_attempts > 1
                            && let Some(delay) = rollback_export_delay
                        {
                            tokio::time::sleep(delay).await;
                        }
                        Ok(())
                    };
                    let _ = reply.send(result);
                }
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(PeerSessionState {
                        fsm_state: SessionState::Established,
                        peer_ip: addr,
                        peer_asn: Some(65002),
                        prefix_count: 0,
                        max_prefix: MaxPrefixState::default(),
                        negotiated_hold_time: Some(90),
                        four_octet_as: Some(true),
                        remote_router_id: None,
                        negotiated_session: None,
                        local_role: None,
                        remote_role: None,
                        role_negotiated: false,
                        peer_paths_limits: Vec::new(),
                        effective_add_path_send_limits: Vec::new(),
                        updates_received: 0,
                        updates_sent: 0,
                        notifications_received: 0,
                        notifications_sent: 0,
                        messages_received: 0,
                        messages_sent: 0,
                        otc_routes_blocked: 0,
                        import_policy_routes_permitted: 0,
                        import_policy_routes_denied: 0,
                        flap_count: 0,
                        uptime_secs: 1,
                        last_error: String::new(),
                        tcp_ao_info: None,
                        tcp_ao_protected: false,
                        slow_peer: false,
                    });
                }
                PeerCommand::SendRouteRefresh { reply, .. } => {
                    refresh_attempts += 1;
                    if refresh_attempts > 1 {
                        let (marker_tx, marker_rx) = oneshot::channel();
                        let _ = rib_tx
                            .send(RibUpdate::QueryLocRibCount { reply: marker_tx })
                            .await;
                        let _ = marker_rx.await;
                    }
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::Shutdown => break,
                _ => {}
            }
        }
        Ok(())
    });
    PeerHandle::from_parts(session_tx, task)
}

fn stalled_export_policy_test_session(
    addr: IpAddr,
) -> (
    PeerHandle,
    oneshot::Receiver<()>,
    Arc<tokio::sync::Notify>,
    Arc<AtomicUsize>,
) {
    use rustbgpd_transport::PeerCommand;

    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(16);
    let (entered_tx, entered_rx) = oneshot::channel();
    let release = Arc::new(tokio::sync::Notify::new());
    let task_release = Arc::clone(&release);
    let state_queries = Arc::new(AtomicUsize::new(0));
    let task_state_queries = Arc::clone(&state_queries);
    let task = tokio::spawn(async move {
        let mut entered_tx = Some(entered_tx);
        while let Some(command) = session_rx.recv().await {
            match command {
                PeerCommand::UpdateExportPolicy { reply, .. } => {
                    if let Some(entered) = entered_tx.take() {
                        let _ = entered.send(());
                    }
                    task_release.notified().await;
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::QueryState { reply } => {
                    task_state_queries.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(PeerSessionState {
                        fsm_state: SessionState::Established,
                        peer_ip: addr,
                        peer_asn: Some(65002),
                        prefix_count: 0,
                        max_prefix: MaxPrefixState::default(),
                        negotiated_hold_time: Some(90),
                        four_octet_as: Some(true),
                        remote_router_id: None,
                        negotiated_session: None,
                        local_role: None,
                        remote_role: None,
                        role_negotiated: false,
                        peer_paths_limits: Vec::new(),
                        effective_add_path_send_limits: Vec::new(),
                        updates_received: 0,
                        updates_sent: 0,
                        notifications_received: 0,
                        notifications_sent: 0,
                        messages_received: 0,
                        messages_sent: 0,
                        otc_routes_blocked: 0,
                        import_policy_routes_permitted: 0,
                        import_policy_routes_denied: 0,
                        flap_count: 0,
                        uptime_secs: 1,
                        last_error: String::new(),
                        tcp_ao_info: None,
                        tcp_ao_protected: false,
                        slow_peer: false,
                    });
                }
                PeerCommand::Shutdown => break,
                _ => {}
            }
        }
        Ok(())
    });
    (
        PeerHandle::from_parts(session_tx, task),
        entered_rx,
        release,
        state_queries,
    )
}

fn insert_test_scoped_managed_peer(
    mgr: &mut PeerManager,
    addr: IpAddr,
    interface: &str,
    scope_id: u32,
    session_id: u64,
    handle: PeerHandle,
) {
    let mut peer_config = make_config(addr, 65002);
    peer_config.interface = Some(interface.to_string());
    peer_config.scope_id = Some(scope_id);
    let transport = mgr.build_transport_config(&peer_config);
    let hold = transport.peer.hold_time;
    let peer_key = scoped_key(addr, interface);
    mgr.peers.insert(
        peer_key.clone(),
        ManagedPeer {
            handle,
            session_id,
            remote_asn: 65002,
            description: interface.to_string(),
            peer_group: None,
            enabled: true,
            hold_time: Some(hold),
            max_prefixes: None,
            max_prefix_restart_seconds: None,
            transport_config: transport,
            import_policy: None,
            export_policy: None,
            pending_inbound: None,
            is_dynamic: false,
            rfc8212_external: false,
            tcp_ao_protected: false,
            accepted_dynamic_range: None,
            pending_refresh: false,
            pending_export_apply: false,
            tcp_ao_rotation: TcpAoRotationStatus::default(),
            advertise_graceful_shutdown: false,
        },
    );
    mgr.register_session(session_id, &peer_key);
}

#[derive(Default)]
struct FakePeerCounters {
    start: AtomicU32,
    collision_dump: AtomicU32,
    query_state: AtomicU32,
    route_refresh: AtomicU32,
    activate_max_prefix_metrics: AtomicU32,
    shutdown: AtomicU32,
    stop: AtomicU32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MaxPrefixTrigger {
    Start,
    StartTwice,
    CollisionDump,
    Shutdown,
}

fn max_prefix_on_command_peer_handle(
    peer_addr: IpAddr,
    session_id: u64,
    role: rustbgpd_transport::SessionRole,
    trigger: MaxPrefixTrigger,
    notify_tx: mpsc::UnboundedSender<SessionNotification>,
    counters: Arc<FakePeerCounters>,
) -> PeerHandle {
    use rustbgpd_transport::PeerCommand;

    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let task = tokio::spawn(async move {
        let mut emitted = 0;
        while let Some(command) = session_rx.recv().await {
            let terminal = matches!(&command, PeerCommand::CollisionDump | PeerCommand::Shutdown);
            let should_emit = match command {
                PeerCommand::Start => {
                    counters.start.fetch_add(1, Ordering::SeqCst);
                    matches!(
                        trigger,
                        MaxPrefixTrigger::Start | MaxPrefixTrigger::StartTwice
                    )
                }
                PeerCommand::CollisionDump => {
                    counters.collision_dump.fetch_add(1, Ordering::SeqCst);
                    trigger == MaxPrefixTrigger::CollisionDump
                }
                PeerCommand::Shutdown => {
                    counters.shutdown.fetch_add(1, Ordering::SeqCst);
                    trigger == MaxPrefixTrigger::Shutdown
                }
                PeerCommand::Stop { .. } => {
                    counters.stop.fetch_add(1, Ordering::SeqCst);
                    false
                }
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(PeerSessionState {
                        fsm_state: SessionState::Idle,
                        peer_ip: peer_addr,
                        peer_asn: Some(65002),
                        prefix_count: 0,
                        max_prefix: MaxPrefixState::default(),
                        negotiated_hold_time: None,
                        four_octet_as: None,
                        remote_router_id: None,
                        negotiated_session: None,
                        local_role: None,
                        remote_role: None,
                        role_negotiated: false,
                        peer_paths_limits: Vec::new(),
                        effective_add_path_send_limits: Vec::new(),
                        updates_received: 0,
                        updates_sent: 0,
                        notifications_received: 0,
                        notifications_sent: 0,
                        messages_received: 0,
                        messages_sent: 0,
                        otc_routes_blocked: 0,
                        import_policy_routes_permitted: 0,
                        import_policy_routes_denied: 0,
                        flap_count: 0,
                        uptime_secs: 0,
                        last_error: String::new(),
                        tcp_ao_info: None,
                        tcp_ao_protected: false,
                        slow_peer: false,
                    });
                    false
                }
                _ => false,
            };
            let emission_limit = if trigger == MaxPrefixTrigger::StartTwice {
                2
            } else {
                1
            };
            if should_emit && emitted < emission_limit {
                emitted += 1;
                notify_tx
                    .send(SessionNotification::MaxPrefixExceeded {
                        session_id,
                        role,
                        peer_addr,
                        count: 501,
                        bound: 500,
                        family: None,
                    })
                    .unwrap();
            }
            if terminal {
                break;
            }
        }
        Ok(())
    });
    PeerHandle::from_parts(session_tx, task)
}

struct TaskDropCounter {
    dropped: Arc<AtomicU32>,
    notify: Option<Arc<Notify>>,
}

impl Drop for TaskDropCounter {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
        if let Some(notify) = &self.notify {
            notify.notify_one();
        }
    }
}

async fn stalled_shutdown_peer_handle(dropped: Arc<AtomicU32>) -> PeerHandle {
    stalled_shutdown_peer_handle_with_notify(dropped, None).await
}

async fn stalled_shutdown_peer_handle_with_notify(
    dropped: Arc<AtomicU32>,
    notify: Option<Arc<Notify>>,
) -> PeerHandle {
    let (commands, receiver) = mpsc::channel(1);
    commands
        .send(rustbgpd_transport::PeerCommand::Start)
        .await
        .expect("seed the deliberately full command channel");
    let task = tokio::spawn(async move {
        let _receiver = receiver;
        let _drop_counter = TaskDropCounter { dropped, notify };
        std::future::pending::<Result<(), rustbgpd_transport::TransportError>>().await
    });
    PeerHandle::from_parts(commands, task)
}

fn fake_peer_handle(
    peer_addr: IpAddr,
    state: SessionState,
    remote_router_id: Option<Ipv4Addr>,
    counters: Arc<FakePeerCounters>,
) -> PeerHandle {
    fake_peer_handle_with_route_refresh_reply(peer_addr, state, remote_router_id, counters, true)
}

fn fake_peer_handle_with_route_refresh_reply(
    peer_addr: IpAddr,
    state: SessionState,
    remote_router_id: Option<Ipv4Addr>,
    counters: Arc<FakePeerCounters>,
    reply_to_route_refresh: bool,
) -> PeerHandle {
    use rustbgpd_transport::PeerCommand;

    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let task = tokio::spawn(async move {
        let mut pending_route_refresh_replies = Vec::new();
        while let Some(cmd) = session_rx.recv().await {
            match cmd {
                PeerCommand::Start => {
                    counters.start.fetch_add(1, Ordering::SeqCst);
                }
                PeerCommand::QueryState { reply } => {
                    counters.query_state.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(PeerSessionState {
                        fsm_state: state,
                        peer_ip: peer_addr,
                        peer_asn: None,
                        prefix_count: 0,
                        max_prefix: MaxPrefixState::default(),
                        negotiated_hold_time: None,
                        four_octet_as: None,
                        remote_router_id,
                        negotiated_session: None,
                        local_role: None,
                        remote_role: None,
                        role_negotiated: false,
                        peer_paths_limits: Vec::new(),
                        effective_add_path_send_limits: Vec::new(),
                        updates_received: 0,
                        updates_sent: 0,
                        notifications_received: 0,
                        notifications_sent: 0,
                        messages_received: 0,
                        messages_sent: 0,
                        otc_routes_blocked: 0,
                        import_policy_routes_permitted: 0,
                        import_policy_routes_denied: 0,
                        flap_count: 0,
                        uptime_secs: 0,
                        last_error: String::new(),
                        tcp_ao_info: None,
                        tcp_ao_protected: false,
                        slow_peer: false,
                    });
                }
                PeerCommand::SendRouteRefresh { reply, .. } => {
                    counters.route_refresh.fetch_add(1, Ordering::SeqCst);
                    if reply_to_route_refresh {
                        let _ = reply.send(Ok(()));
                    } else {
                        pending_route_refresh_replies.push(reply);
                    }
                }
                PeerCommand::ActivateMaxPrefixMetrics { reply } => {
                    counters
                        .activate_max_prefix_metrics
                        .fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(());
                }
                PeerCommand::CollisionDump => {
                    counters.collision_dump.fetch_add(1, Ordering::SeqCst);
                    break;
                }
                PeerCommand::Shutdown => {
                    counters.shutdown.fetch_add(1, Ordering::SeqCst);
                    break;
                }
                PeerCommand::Stop { .. } => {
                    counters.stop.fetch_add(1, Ordering::SeqCst);
                    break;
                }
                _ => {}
            }
        }
        Ok(())
    });
    PeerHandle::from_parts(session_tx, task)
}

fn eligible_warm_checkpoint_state() -> WarmCheckpointSessionState {
    WarmCheckpointSessionState {
        fsm_state: SessionState::Established,
        peer_asn: Some(65002),
        peer_router_id: Some(Ipv4Addr::new(10, 0, 0, 2)),
        negotiated_families: vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)],
        peer_gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_gr_capable: true,
        peer_gr_restart_time: 120,
        add_path_receive_families: vec![(Afi::Ipv4, Safi::Unicast)],
    }
}

fn attach_test_pending_inbound(
    mgr: &mut PeerManager,
    peer_addr: IpAddr,
    handle: PeerHandle,
    session_id: u64,
) {
    mgr.peers
        .get_mut(&key(peer_addr))
        .expect("managed peer")
        .pending_inbound = Some(PendingInbound { handle, session_id });
    mgr.register_session(session_id, &key(peer_addr));
}

async fn wait_counter(counter: &AtomicU32, expected: u32) {
    for _ in 0..20 {
        if counter.load(Ordering::SeqCst) == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(counter.load(Ordering::SeqCst), expected);
}

fn config_neighbor(addr: IpAddr, remote_asn: u32) -> crate::config::Neighbor {
    crate::config::Neighbor {
        min_hold_time: None,
        address: addr.to_string(),
        interface: None,
        remote_asn,
        description: None,
        peer_group: None,
        hold_time: None,
        send_hold_time: None,
        slow_peer_threshold_pct: None,
        slow_peer_duration: None,
        slow_peer_isolation: None,
        max_prefixes: None,
        max_prefixes_ipv4: None,
        max_prefixes_ipv6: None,
        max_prefixes_out_ipv4: None,
        max_prefixes_out_ipv6: None,
        max_prefix_restart_seconds: None,
        md5_password: None,
        tcp_ao: None,
        bfd: None,
        ttl_security: None,
        families: Vec::new(),
        required_families: Vec::new(),
        graceful_restart: None,
        gr_restart_time: None,
        gr_peer_restart_time_max: None,
        gr_stale_routes_time: None,
        llgr_stale_time: None,
        local_ipv6_nexthop: None,
        route_reflector_client: None,
        orr_vantage: None,
        route_server_client: None,
        per_client_best: None,
        next_hop_ownership: None,
        interpret_rfc1997: None,
        rs_control_communities: None,
        role: None,
        strict_role: None,
        prefix_orf_receive: None,
        disable_ipv4_unicast: None,
        remove_private_as: None,
        add_path: None,
        log_level: None,
        import_policy: Vec::new(),
        export_policy: Vec::new(),
        import_policy_chain: Vec::new(),
        export_policy_chain: Vec::new(),
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "test fixture mirrors ManagedPeer fields"
)]
fn insert_test_dynamic_managed_peer(
    mgr: &mut PeerManager,
    addr: IpAddr,
    session_id: u64,
    handle: PeerHandle,
    enabled: bool,
    range_addr: IpAddr,
    range_prefix_len: u8,
    range_peer_group: &str,
) {
    let peer_config = make_config(addr, 65030);
    let transport = mgr.build_transport_config(&peer_config);
    let hold = transport.peer.hold_time;
    let peer_key = key(addr);
    mgr.peers.insert(
        peer_key.clone(),
        ManagedPeer {
            handle,
            session_id,
            remote_asn: 65030,
            description: format!("dynamic:{range_peer_group}"),
            peer_group: Some(range_peer_group.to_string()),
            enabled,
            hold_time: Some(hold),
            max_prefixes: None,
            max_prefix_restart_seconds: None,
            transport_config: transport,
            import_policy: None,
            export_policy: None,
            pending_inbound: None,
            is_dynamic: true,
            rfc8212_external: false,
            tcp_ao_protected: false,
            accepted_dynamic_range: Some(AcceptedDynamicRange {
                addr: range_addr,
                prefix_len: range_prefix_len,
                peer_group: range_peer_group.to_string(),
            }),
            pending_refresh: false,
            pending_export_apply: false,
            tcp_ao_rotation: TcpAoRotationStatus::default(),
            advertise_graceful_shutdown: false,
        },
    );
    mgr.register_session(session_id, &peer_key);
    mgr.dynamic_peer_count += 1;
    mgr.refresh_dynamic_neighbor_capacity_metrics();
}

fn process_global_metric(metrics: &BgpMetrics, family_name: &str) -> Option<f64> {
    metrics
        .registry()
        .gather()
        .into_iter()
        .find(|family| family.name() == family_name)
        .map(|family| {
            assert_eq!(family.get_metric().len(), 1, "{family_name} series count");
            let metric = &family.get_metric()[0];
            assert!(
                metric.get_label().is_empty(),
                "{family_name} must remain label-free"
            );
            if family_name.ends_with("_total") {
                metric.get_counter().value()
            } else {
                metric.get_gauge().value()
            }
        })
}

fn assert_dynamic_neighbor_capacity(
    metrics: &BgpMetrics,
    used: f64,
    limit: f64,
    headroom: f64,
    rejections: f64,
) {
    assert_eq!(
        (
            process_global_metric(metrics, "bgp_dynamic_neighbor_slots_used"),
            process_global_metric(metrics, "bgp_dynamic_neighbor_slots_limit"),
            process_global_metric(metrics, "bgp_dynamic_neighbor_slots_headroom"),
            process_global_metric(metrics, "bgp_dynamic_neighbor_limit_rejections_total"),
        ),
        (Some(used), Some(limit), Some(headroom), Some(rejections))
    );
}

/// `None` when the reason's series does not exist yet — a reason never
/// recorded has no child, so `None` doubles as "never dropped".
fn inbound_drop_metric(metrics: &BgpMetrics, reason: &str) -> Option<f64> {
    metrics
        .registry()
        .gather()
        .into_iter()
        .find(|family| family.name() == "bgp_inbound_connections_dropped_total")
        .and_then(|family| {
            family.get_metric().iter().find_map(|metric| {
                metric
                    .get_label()
                    .iter()
                    .any(|label| label.name() == "reason" && label.value() == reason)
                    .then(|| metric.get_counter().value())
            })
        })
}

fn peer_identity_gauge(
    metrics: &BgpMetrics,
    family_name: &str,
    peer: &str,
    interface: &str,
) -> Option<f64> {
    metrics
        .registry()
        .gather()
        .into_iter()
        .find(|family| family.name() == family_name)
        .and_then(|family| {
            family.get_metric().iter().find_map(|metric| {
                let has_peer = metric
                    .get_label()
                    .iter()
                    .any(|label| label.name() == "peer" && label.value() == peer);
                let has_interface = metric
                    .get_label()
                    .iter()
                    .any(|label| label.name() == "interface" && label.value() == interface);
                (has_peer && has_interface).then(|| metric.get_gauge().value())
            })
        })
}

/// The Established-only negotiated projection a stub session reports.
///
/// Keep it coherent with how the same stub answers `SendRouteRefresh`: a
/// session that acks a refresh advertises the capability, and one that rejects
/// it does not. ADR-0112's import-presence gate reads exactly this field, so an
/// incoherent stub would let a test pass against a peer no real session could be.
fn test_negotiated_session(route_refresh: bool) -> rustbgpd_transport::NegotiatedSessionState {
    rustbgpd_transport::NegotiatedSessionState {
        hold_time: 90,
        remote_router_id: Ipv4Addr::new(192, 0, 2, 1),
        four_octet_as: true,
        families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_route_refresh: route_refresh,
        peer_enhanced_route_refresh: false,
        peer_extended_message: false,
        outbound_max_message_bytes: rustbgpd_wire::MAX_MESSAGE_LEN,
        graceful_restart: None,
    }
}

/// Like `acking_policy_handle`, but counting `QueryState` and Route Refresh
/// sends so policy fan-out coverage can be asserted per peer.
fn acking_counted_policy_handle(peer_addr: IpAddr, counters: Arc<FakePeerCounters>) -> PeerHandle {
    use rustbgpd_transport::PeerCommand;
    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let task = tokio::spawn(async move {
        while let Some(cmd) = session_rx.recv().await {
            match cmd {
                PeerCommand::QueryState { reply } => {
                    counters.query_state.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(PeerSessionState {
                        fsm_state: SessionState::Established,
                        peer_ip: peer_addr,
                        peer_asn: None,
                        prefix_count: 0,
                        max_prefix: MaxPrefixState::default(),
                        negotiated_hold_time: None,
                        four_octet_as: None,
                        remote_router_id: None,
                        negotiated_session: Some(test_negotiated_session(true)),
                        local_role: None,
                        remote_role: None,
                        role_negotiated: false,
                        peer_paths_limits: Vec::new(),
                        effective_add_path_send_limits: Vec::new(),
                        updates_received: 0,
                        updates_sent: 0,
                        notifications_received: 0,
                        notifications_sent: 0,
                        messages_received: 0,
                        messages_sent: 0,
                        otc_routes_blocked: 0,
                        import_policy_routes_permitted: 0,
                        import_policy_routes_denied: 0,
                        flap_count: 0,
                        uptime_secs: 0,
                        last_error: String::new(),
                        tcp_ao_info: None,
                        tcp_ao_protected: false,
                        slow_peer: false,
                    });
                }
                PeerCommand::SendRouteRefresh { reply, .. } => {
                    counters.route_refresh.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::UpdateImportPolicy { reply, .. }
                | PeerCommand::UpdateExportPolicy { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::Shutdown | PeerCommand::Stop { .. } | PeerCommand::CollisionDump => {
                    break;
                }
                _ => {}
            }
        }
        Ok(())
    });
    PeerHandle::from_parts(session_tx, task)
}

/// Minimal state snapshot shared by policy-command session models.
fn policy_test_peer_state(peer_addr: IpAddr, state: SessionState) -> PeerSessionState {
    PeerSessionState {
        fsm_state: state,
        peer_ip: peer_addr,
        peer_asn: None,
        prefix_count: 0,
        max_prefix: MaxPrefixState::default(),
        negotiated_hold_time: None,
        four_octet_as: None,
        remote_router_id: None,
        negotiated_session: None,
        local_role: None,
        remote_role: None,
        role_negotiated: false,
        peer_paths_limits: Vec::new(),
        effective_add_path_send_limits: Vec::new(),
        updates_received: 0,
        updates_sent: 0,
        notifications_received: 0,
        notifications_sent: 0,
        messages_received: 0,
        messages_sent: 0,
        otc_routes_blocked: 0,
        import_policy_routes_permitted: 0,
        import_policy_routes_denied: 0,
        flap_count: 0,
        uptime_secs: 0,
        last_error: String::new(),
        tcp_ao_info: None,
        tcp_ao_protected: false,
        slow_peer: false,
    }
}

/// A peer handle that acknowledges policy hot-applies (and route refreshes), so
/// `update_runtime_policies_for_peer_key` succeeds and advances bookkeeping.
/// `fake_peer_handle`'s catch-all never replies to UpdateImport/ExportPolicy, so
/// it would time out — this one is for the resolved-policy-snapshot apply tests.
fn acking_policy_handle(peer_addr: IpAddr, state: SessionState) -> PeerHandle {
    use rustbgpd_transport::PeerCommand;
    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let task = tokio::spawn(async move {
        while let Some(cmd) = session_rx.recv().await {
            match cmd {
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(PeerSessionState {
                        fsm_state: state,
                        peer_ip: peer_addr,
                        peer_asn: None,
                        prefix_count: 0,
                        max_prefix: MaxPrefixState::default(),
                        negotiated_hold_time: None,
                        four_octet_as: None,
                        remote_router_id: None,
                        negotiated_session: (state == SessionState::Established)
                            .then(|| test_negotiated_session(true)),
                        local_role: None,
                        remote_role: None,
                        role_negotiated: false,
                        peer_paths_limits: Vec::new(),
                        effective_add_path_send_limits: Vec::new(),
                        updates_received: 0,
                        updates_sent: 0,
                        notifications_received: 0,
                        notifications_sent: 0,
                        messages_received: 0,
                        messages_sent: 0,
                        otc_routes_blocked: 0,
                        import_policy_routes_permitted: 0,
                        import_policy_routes_denied: 0,
                        flap_count: 0,
                        uptime_secs: 0,
                        last_error: String::new(),
                        tcp_ao_info: None,
                        tcp_ao_protected: false,
                        slow_peer: false,
                    });
                }
                PeerCommand::UpdateImportPolicy { reply, .. }
                | PeerCommand::UpdateExportPolicy { reply, .. }
                | PeerCommand::SendRouteRefresh { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::Shutdown | PeerCommand::Stop { .. } | PeerCommand::CollisionDump => {
                    break;
                }
                _ => {}
            }
        }
        Ok(())
    });
    PeerHandle::from_parts(session_tx, task)
}

/// A peer handle whose session receiver is dropped, so every command send fails
/// — forces a per-peer policy hot-apply failure.
fn closed_peer_handle() -> PeerHandle {
    use rustbgpd_transport::PeerCommand;
    let (session_tx, session_rx) = mpsc::channel::<PeerCommand>(1);
    drop(session_rx);
    let task = tokio::spawn(async { Ok(()) });
    PeerHandle::from_parts(session_tx, task)
}

fn live_policy_test_manager() -> PeerManager {
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
    // Leak the RIB receiver so soft-reset / RIB sends during apply never fail.
    Box::leak(Box::new(rib_rx));
    PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    )
}

fn down(peer: IpAddr) -> crate::bfd_runtime::BfdStateChange {
    crate::bfd_runtime::BfdStateChange {
        peer,
        state: rustbgpd_bfd::SessionState::Down,
        diagnostic: rustbgpd_bfd::Diagnostic::ControlDetectionTimeExpired,
        remote_admin_down: false,
        resync: false,
    }
}

/// A Down caused by the remote signaling `AdminDown` (RFC 5882 §4.1).
fn remote_admin_down(peer: IpAddr) -> crate::bfd_runtime::BfdStateChange {
    crate::bfd_runtime::BfdStateChange {
        peer,
        state: rustbgpd_bfd::SessionState::Down,
        diagnostic: rustbgpd_bfd::Diagnostic::NeighborSignaledDown,
        remote_admin_down: true,
        resync: false,
    }
}

fn up(peer: IpAddr) -> crate::bfd_runtime::BfdStateChange {
    crate::bfd_runtime::BfdStateChange {
        peer,
        state: rustbgpd_bfd::SessionState::Up,
        diagnostic: rustbgpd_bfd::Diagnostic::None,
        remote_admin_down: false,
        resync: false,
    }
}

/// ADR-0112 step 5 helper: a manager whose peers are governed by RFC 8212
/// enforcement, with the running config additionally claiming a global
/// explicit policy chain in both directions.
fn rfc8212_status_manager() -> (PeerManager, mpsc::Receiver<RibUpdate>) {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, rib_rx) = mpsc::channel(64);
    let mut mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let mut config = make_dynamic_manager_config();
    config.global.ebgp_requires_policy = Some(true);
    // The running config says every neighbor inherits an explicit operator
    // chain. Nothing in the status derivation may consult it.
    config.policy.import_chain = vec!["operator-import".to_string()];
    config.policy.export_chain = vec!["operator-export".to_string()];
    mgr.current_config = config;
    (mgr, rib_rx)
}

/// Answer every RIB command the policy snapshot can emit, reporting a fixed
/// retained GR/LLGR stale count for `QueryPeerRetainedStale`.
fn spawn_rfc8212_rib_stub(
    mut rib_rx: mpsc::Receiver<RibUpdate>,
    retained_stale: usize,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::QueryPeerRetainedStale { reply, .. } => {
                    let _ = reply.send(retained_stale);
                }
                RibUpdate::ReplacePeerExportPolicy { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                _ => {}
            }
        }
    })
}

mod bfd;
mod cohort_budgets;
mod cohort_handoff;
mod collision;
mod config_mutation;
mod config_transaction;
mod dynamic_ranges;
mod events;
mod export_cohorts;
mod inbound_admission;
mod lifecycle;
mod max_prefix;
mod metrics;
mod peer_groups;
mod persistence;
mod policy;
mod policy_apply;
mod policy_failures;
mod policy_stats;
mod queries;
mod rfc8212;
mod snapshots;
mod transport_config;
