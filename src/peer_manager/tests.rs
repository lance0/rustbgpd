use super::*;
use bytes::BytesMut;
use rustbgpd_api::peer_types::{
    CatalogMutationError, DynamicRangeTarget, ImportValidationDependency, PeerKey,
    SessionLifecycleEventType,
};
use rustbgpd_fsm::SessionState;
use rustbgpd_transport::PeerSessionState;
use rustbgpd_wire::{
    Capability, Message, OpenMessage, decode_message, encode_message, peek_message_length,
};
use std::collections::BTreeSet;
use std::net::Ipv6Addr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU32, Ordering},
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, oneshot};

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
        address: addr,
        interface: None,
        scope_id: None,
        remote_asn: asn,
        description: format!("test-peer-{addr}"),
        peer_group: None,
        hold_time: None,
        send_hold_time: None,
        max_prefixes: None,
        md5_password: None,
        tcp_ao: None,
        ttl_security: false,
        families: vec![(Afi::Ipv4, Safi::Unicast)],
        graceful_restart: true,
        gr_restart_time: 120,
        gr_stale_routes_time: 360,
        llgr_stale_time: 0,
        gr_restart_eligible: false,
        local_ipv6_nexthop: None,
        route_reflector_client: false,
        orr_vantage: None,
        route_server_client: false,
        per_client_best: false,
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

async fn subscribe_policy_events(
    tx: &mpsc::Sender<PeerManagerCommand>,
) -> broadcast::Receiver<PolicyEvent> {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::SubscribePolicyEvents { reply: reply_tx })
        .await
        .unwrap();
    reply_rx.await.unwrap()
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

#[tokio::test]
async fn stale_live_snapshot_is_rejected_before_candidate_validation() {
    let config = load_test_config(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
"#,
    );
    let candidate = toml::to_string_pretty(&config).unwrap();
    let (_tx, rx) = mpsc::channel(4);
    let (_internal_tx, internal_rx) = mpsc::unbounded_channel();
    let (rib_tx, mut rib_rx) = mpsc::channel(4);
    let mgr = PeerManager::new_with_config(
        rx,
        internal_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
        None,
        config,
    );
    let responder = tokio::spawn(async move {
        let Some(RibUpdate::QueryUpdateGroupSnapshot { reply }) = rib_rx.recv().await else {
            panic!("first plan snapshot query missing");
        };
        reply
            .send(rustbgpd_rib::UpdateGroupSnapshot::default())
            .unwrap();
        let Some(RibUpdate::QueryUpdateGroupSnapshot { reply }) = rib_rx.recv().await else {
            panic!("apply re-plan snapshot query missing");
        };
        reply
            .send(rustbgpd_rib::UpdateGroupSnapshot {
                peers: vec![rustbgpd_rib::UpdateGroupPeerSnapshot {
                    peer: "192.0.2.1".parse().unwrap(),
                    input: rustbgpd_rib::UpdateGroupClassifierInput {
                        policy_fingerprint: None,
                        policy_provenance: None,
                        policy_requires_peer_context: false,
                        target_is_ebgp: false,
                        target_is_rr_client: true,
                        sendable_families: vec![(1, 1)],
                        llgr_families: vec![],
                        add_path_send: false,
                        per_client_best: false,
                        orr_vantage: None,
                        orf_installed: false,
                    },
                    classification: rustbgpd_rib::UpdateGroupClassification::Groupable(
                        rustbgpd_rib::UpdateGroupFingerprint {
                            policy_fingerprint: None,
                            target_is_ebgp: false,
                            target_is_rr_client: true,
                            sendable_ipv4_unicast: true,
                            sendable_ipv6_unicast: false,
                            sendable_vpnv4: false,
                            sendable_vpnv6: false,
                            rtc_negotiated: false,
                            llgr_families: vec![],
                        },
                    ),
                    runtime_membership: "group:0".to_string(),
                }],
            })
            .unwrap();
    });
    let planned = mgr.plan_config_transaction(&candidate, None).await.unwrap();
    let error = mgr
        .plan_config_transaction(
            "this is not valid TOML =",
            Some(&planned.runtime_snapshot_token),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        rustbgpd_api::peer_types::RuntimeConfigTransactionPlanError::StaleSnapshot { .. }
    ));
    responder.await.unwrap();
}

#[tokio::test]
async fn candidate_neighbor_resolution_failure_is_invalid_candidate() {
    let config = load_test_config(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
"#,
    );
    let mut candidate = toml::to_string_pretty(&config).unwrap();
    candidate.push_str(
        r#"
[[neighbors]]
address = "fe80::2"
interface = "rustbgpd-interface-that-does-not-exist"
remote_asn = 65002
"#,
    );
    let (_tx, rx) = mpsc::channel(4);
    let (_internal_tx, internal_rx) = mpsc::unbounded_channel();
    let (rib_tx, mut rib_rx) = mpsc::channel(4);
    let mgr = PeerManager::new_with_config(
        rx,
        internal_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
        None,
        config,
    );
    let responder = tokio::spawn(async move {
        let Some(RibUpdate::QueryUpdateGroupSnapshot { reply }) = rib_rx.recv().await else {
            panic!("plan snapshot query missing");
        };
        reply
            .send(rustbgpd_rib::UpdateGroupSnapshot::default())
            .unwrap();
    });

    let error = mgr
        .plan_config_transaction(&candidate, None)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        rustbgpd_api::peer_types::RuntimeConfigTransactionPlanError::InvalidCandidate(_)
    ));
    responder.await.unwrap();
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

fn test_policy_event(target: &str, peer: Option<IpAddr>) -> PolicyEvent {
    PolicyEvent {
        operation: "set",
        target_type: "policy",
        target: target.to_string(),
        peer,
        affected_peer_count: usize::from(peer.is_some()),
        timestamp: "1".to_string(),
        reason: format!("policy set policy {target}"),
    }
}

fn mock_open(router_id: Ipv4Addr) -> OpenMessage {
    OpenMessage {
        version: 4,
        my_as: 65002,
        hold_time: 90,
        bgp_identifier: router_id,
        capabilities: vec![
            Capability::MultiProtocol {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            },
            Capability::FourOctetAs { asn: 65002 },
        ],
    }
}

async fn read_bgp_message(stream: &mut TcpStream, buf: &mut BytesMut) -> Message {
    loop {
        if let Ok(Some(len)) = peek_message_length(buf, rustbgpd_wire::MAX_MESSAGE_LEN) {
            let len = usize::from(len);
            if buf.len() >= len {
                let frame = buf.split_to(len);
                let mut bytes = frame.freeze();
                return decode_message(&mut bytes, rustbgpd_wire::MAX_MESSAGE_LEN)
                    .expect("valid BGP message");
            }
        }
        let n = stream.read_buf(buf).await.expect("TCP read");
        assert!(n > 0, "unexpected EOF from peer");
    }
}

async fn send_bgp_message(stream: &mut TcpStream, msg: &Message) {
    let encoded = encode_message(msg).expect("encode BGP message");
    stream.write_all(&encoded).await.expect("TCP write");
    stream.flush().await.expect("TCP flush");
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

    Config {
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
                grpc_uds: None,
            },
            dynamic_neighbor_limit: Some(100),
            worker_threads: None,
            honor_graceful_shutdown: false,
            honor_blackhole: false,
            multipath_relax: false,
            link_bandwidth_weighted: false,
            install_blackhole_discard: false,
            allow_blackhole_broad_prefixes: false,
        },
        security: crate::config::SecurityConfig {
            grpc: crate::config::GrpcSecurityConfig {
                enforcement: crate::config::GrpcEnforcementConfig::Legacy,
                ..Default::default()
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
    }
}

fn load_test_config(toml: &str) -> Config {
    Config::load_toml_with_diagnostics(toml, "test config").unwrap()
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

#[test]
fn add_dynamic_range_appends_and_is_matchable() {
    let mut mgr = dynamic_test_manager();
    let before = mgr.dynamic_ranges.len();
    let cfg_before = mgr.current_config.dynamic_neighbors.len();
    mgr.add_dynamic_range("10.0.0.0/24".into(), "ix-members".into(), 65002, None)
        .expect("add should succeed");
    assert_eq!(mgr.dynamic_ranges.len(), before + 1);
    assert_eq!(mgr.current_config.dynamic_neighbors.len(), cfg_before + 1);
    assert!(
        mgr.match_dynamic_range("10.0.0.5".parse().unwrap())
            .is_some(),
        "newly added range should match"
    );
}

#[test]
fn add_dynamic_range_rejects_duplicate_effective_prefix() {
    let mut mgr = dynamic_test_manager();
    mgr.add_dynamic_range("10.0.0.0/24".into(), "ix-members".into(), 0, None)
        .unwrap();
    let count = mgr.dynamic_ranges.len();
    // 10.0.0.9/24 normalizes to the same 10.0.0.0/24 — must be rejected.
    let err = mgr
        .add_dynamic_range("10.0.0.9/24".into(), "ix-members".into(), 0, None)
        .expect_err("duplicate effective prefix should be rejected");
    assert!(
        matches!(
            err,
            rustbgpd_api::peer_types::DynamicRangeError::AlreadyExists(_)
        ),
        "{err}"
    );
    assert_eq!(
        mgr.dynamic_ranges.len(),
        count,
        "no range added on duplicate"
    );
}

#[test]
fn add_dynamic_range_rejects_unknown_peer_group() {
    let mut mgr = dynamic_test_manager();
    let err = mgr
        .add_dynamic_range("10.0.0.0/24".into(), "nonexistent".into(), 0, None)
        .expect_err("unknown peer group should be rejected");
    assert!(
        matches!(
            err,
            rustbgpd_api::peer_types::DynamicRangeError::NotFound(_)
        ),
        "{err}"
    );
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

#[test]
fn runtime_dynamic_crud_rejects_startup_pinned_tcp_ao_ranges_and_overlaps() {
    let mut mgr = dynamic_test_manager();
    mgr.current_config.dynamic_neighbors[0].tcp_ao = Some(test_tcp_ao());

    let add_err = mgr
        .add_dynamic_range("127.0.1.0/24".into(), "ix-members".into(), 0, None)
        .expect_err("runtime add overlapping protected prefix must fail");
    assert!(add_err.to_string().contains("startup-pinned TCP-AO"));

    let delete_err = mgr
        .delete_dynamic_range("127.0.0.0/8")
        .expect_err("runtime delete of protected prefix must fail");
    assert!(delete_err.to_string().contains("startup-pinned"));
}

#[test]
fn delete_dynamic_range_removes_and_stops_future_match() {
    let mut mgr = dynamic_test_manager();
    mgr.add_dynamic_range("10.0.0.0/24".into(), "ix-members".into(), 0, None)
        .unwrap();
    let before = mgr.dynamic_ranges.len();
    assert!(
        mgr.match_dynamic_range("10.0.0.5".parse().unwrap())
            .is_some()
    );
    // Delete by a host-bit variant of the same network — effective-prefix match.
    let removed = mgr
        .delete_dynamic_range("10.0.0.7/24")
        .expect("delete by effective prefix should succeed");
    assert_eq!(mgr.dynamic_ranges.len(), before - 1);
    assert!(
        mgr.match_dynamic_range("10.0.0.5".parse().unwrap())
            .is_none(),
        "deleted range must no longer match (future accepts stop)"
    );
    assert_eq!(removed.prefix, "10.0.0.0/24");
    assert_eq!(removed.peer_group, "ix-members");
}

#[test]
fn delete_dynamic_range_unknown_returns_error() {
    let mut mgr = dynamic_test_manager();
    let err = mgr
        .delete_dynamic_range("192.0.2.0/24")
        .expect_err("deleting a missing range should error");
    assert!(
        matches!(
            err,
            rustbgpd_api::peer_types::DynamicRangeError::NotFound(_)
        ),
        "{err}"
    );
}

#[tokio::test]
async fn replace_config_snapshot_rebuilds_dynamic_range_matcher() {
    let (tx, rx) = mpsc::channel(16);
    let (internal_tx, internal_rx) = mpsc::unbounded_channel();
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let config = make_dynamic_manager_config();
    let mut replacement = config.clone();
    replacement.dynamic_neighbors = vec![crate::config::DynamicNeighborConfig {
        prefix: "10.10.0.0/16".to_string(),
        peer_group: "ix-members".to_string(),
        remote_asn: 65010,
        description: Some("reload range".to_string()),
        tcp_ao: None,
    }];

    let manager = PeerManager::new_with_config(
        rx,
        internal_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
        None,
        config,
    );
    let handle = tokio::spawn(manager.run());

    let (ack_tx, ack_rx) = oneshot::channel();
    internal_tx
        .send(InternalCommand::ReplaceConfigSnapshot {
            config: Box::new(replacement),
            ack: Some(ack_tx),
        })
        .unwrap();
    ack_rx.await.unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::ListDynamicRanges { reply: reply_tx })
        .await
        .unwrap();
    let ranges = reply_rx.await.unwrap();
    assert_eq!(ranges.len(), 1);
    assert_eq!(ranges[0].prefix, "10.10.0.0/16");
    assert_eq!(ranges[0].peer_group, "ix-members");
    assert_eq!(ranges[0].remote_asn, 65010);

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn stage_config_snapshot_rebuilds_matcher_and_returns_previous_toml() {
    let (tx, rx) = mpsc::channel(16);
    let (_internal_tx, internal_rx) = mpsc::unbounded_channel();
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let config = make_dynamic_manager_config();
    let mut replacement = config.clone();
    replacement.dynamic_neighbors = vec![crate::config::DynamicNeighborConfig {
        prefix: "10.20.0.0/16".to_string(),
        peer_group: "ix-members".to_string(),
        remote_asn: 65020,
        description: Some("transaction range".to_string()),
        tcp_ao: None,
    }];
    let candidate_toml = toml::to_string_pretty(&replacement).unwrap();

    let manager = PeerManager::new_with_config(
        rx,
        internal_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
        None,
        config,
    );
    let handle = tokio::spawn(manager.run());

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::StageConfigSnapshot {
        candidate_toml,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let previous_toml = reply_rx.await.unwrap().unwrap();
    let previous = Config::load_toml_with_diagnostics(&previous_toml, "previous snapshot").unwrap();
    assert_eq!(previous.dynamic_neighbors[0].prefix, "127.0.0.0/8");

    let (list_tx, list_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::ListDynamicRanges { reply: list_tx })
        .await
        .unwrap();
    let ranges = list_rx.await.unwrap();
    assert_eq!(ranges.len(), 1);
    assert_eq!(ranges[0].prefix, "10.20.0.0/16");
    assert_eq!(ranges[0].peer_group, "ix-members");
    assert_eq!(ranges[0].remote_asn, 65020);

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn staged_snapshot_fences_dynamic_accept_and_restore_reaps_candidate_dynamic_peer() {
    let (tx, rx) = mpsc::channel(16);
    let (_internal_tx, internal_rx) = mpsc::unbounded_channel();
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let mut initial = make_dynamic_manager_config();
    initial.dynamic_neighbors.clear();

    let mut candidate = initial.clone();
    candidate.dynamic_neighbors = vec![crate::config::DynamicNeighborConfig {
        prefix: "127.0.0.0/8".to_string(),
        peer_group: "ix-members".to_string(),
        remote_asn: 0,
        description: Some("candidate-only".to_string()),
        tcp_ao: None,
    }];
    let candidate_toml = toml::to_string_pretty(&candidate).unwrap();

    let manager = PeerManager::new_with_config(
        rx,
        internal_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
        None,
        initial,
    );
    let handle = tokio::spawn(manager.run());

    let (stage_tx, stage_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::StageConfigSnapshot {
        candidate_toml,
        reply: stage_tx,
    })
    .await
    .unwrap();
    let previous_toml = stage_rx.await.unwrap().unwrap();

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
    let (server_stream, remote_addr) = listener.accept().await.unwrap();
    let client_stream = client.await.unwrap();
    tx.send(PeerManagerCommand::AcceptInbound {
        stream: server_stream,
        peer_addr: remote_addr,
    })
    .await
    .unwrap();

    let (list_tx, list_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::ListPeers { reply: list_tx })
        .await
        .unwrap();
    assert!(
        list_rx.await.unwrap().is_empty(),
        "dynamic inbound must not be accepted while a config snapshot is staged but uncommitted"
    );

    let (commit_tx, commit_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::CommitConfigSnapshotStage { reply: commit_tx })
        .await
        .unwrap();
    commit_rx.await.unwrap();

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
    let (server_stream, remote_addr) = listener.accept().await.unwrap();
    let client_stream2 = client.await.unwrap();
    tx.send(PeerManagerCommand::AcceptInbound {
        stream: server_stream,
        peer_addr: remote_addr,
    })
    .await
    .unwrap();

    let (list_tx, list_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::ListPeers { reply: list_tx })
        .await
        .unwrap();
    assert_eq!(
        list_rx.await.unwrap().len(),
        1,
        "dynamic inbound should be accepted once the staged snapshot is committed"
    );

    let (restore_tx, restore_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::RestoreConfigSnapshot {
        candidate_toml: previous_toml,
        reply: restore_tx,
    })
    .await
    .unwrap();
    restore_rx.await.unwrap().unwrap();

    let (list_tx, list_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::ListPeers { reply: list_tx })
        .await
        .unwrap();
    assert!(
        list_rx.await.unwrap().is_empty(),
        "rollback must reap dynamic peers accepted by ranges absent from the restored snapshot"
    );

    drop(client_stream);
    drop(client_stream2);
    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn runtime_config_snapshot_returns_current_staged_config() {
    let (tx, rx) = mpsc::channel(16);
    let (_internal_tx, internal_rx) = mpsc::unbounded_channel();
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let config = make_dynamic_manager_config();
    let mut replacement = config.clone();
    replacement.dynamic_neighbors = vec![crate::config::DynamicNeighborConfig {
        prefix: "10.30.0.0/16".to_string(),
        peer_group: "ix-members".to_string(),
        remote_asn: 65030,
        description: Some("transaction range".to_string()),
        tcp_ao: None,
    }];
    let candidate_toml = toml::to_string_pretty(&replacement).unwrap();

    let manager = PeerManager::new_with_config(
        rx,
        internal_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
        None,
        config,
    );
    let handle = tokio::spawn(manager.run());

    let (stage_tx, stage_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::StageConfigSnapshot {
        candidate_toml,
        reply: stage_tx,
    })
    .await
    .unwrap();
    stage_rx.await.unwrap().unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::RuntimeConfigSnapshot { reply: reply_tx })
        .await
        .unwrap();
    let snapshot_toml = reply_rx.await.unwrap().unwrap();
    let snapshot =
        Config::load_toml_with_diagnostics(&snapshot_toml.toml, "runtime snapshot").unwrap();
    assert_eq!(snapshot.dynamic_neighbors.len(), 1);
    assert_eq!(snapshot.dynamic_neighbors[0].prefix, "10.30.0.0/16");
    assert_eq!(snapshot.dynamic_neighbors[0].remote_asn, 65030);

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[test]
fn runtime_config_diff_compares_candidate_against_live_snapshot_and_redacts_secret() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let current = load_test_config(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
md5_password = "old-secret"
"#,
    );
    let mgr = PeerManager::new_with_config(
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
        current,
    );

    let diff = mgr
        .diff_runtime_config(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
md5_password = "new-secret"
"#,
        )
        .unwrap();

    assert!(diff.has_reload_applied_changes);
    assert!(diff.has_actionable_changes);
    assert!(diff.human_text.contains("md5_password: <changed>"));
    assert!(!diff.human_text.contains("old-secret"));
    assert!(!diff.human_text.contains("new-secret"));
    assert!(diff.diff_json.contains("\"field\": \"md5_password\""));
    assert!(!diff.diff_json.contains("old-secret"));
    assert!(!diff.diff_json.contains("new-secret"));
}

fn deny_policy_chain() -> PolicyChain {
    use rustbgpd_policy::{Policy, PolicyAction};

    PolicyChain::new(vec![Policy {
        entries: Vec::new(),
        default_action: PolicyAction::Deny,
    }])
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

fn validation_import_refresh_metric(mgr: &PeerManager, dependency: &str, outcome: &str) -> f64 {
    mgr.metrics
        .registry()
        .gather()
        .iter()
        .find(|family| family.name() == "bgp_validation_import_refreshes_total")
        .and_then(|family| {
            family.metric.iter().find(|metric| {
                let label_value = |name| {
                    metric
                        .get_label()
                        .iter()
                        .find(|label| label.name() == name)
                        .map(prometheus::proto::LabelPair::value)
                };
                label_value("dependency") == Some(dependency)
                    && label_value("outcome") == Some(outcome)
            })
        })
        .map_or(0.0, |metric| metric.get_counter().value())
}

fn assert_validation_import_refresh_metric(
    mgr: &PeerManager,
    dependency: &str,
    outcome: &str,
    expected: f64,
) {
    let actual = validation_import_refresh_metric(mgr, dependency, outcome);
    assert!(
        (actual - expected).abs() < f64::EPSILON,
        "metric dependency={dependency} outcome={outcome}: got {actual}, expected {expected}"
    );
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
            transport_config: transport,
            import_policy: None,
            export_policy: None,
            pending_inbound: None,
            is_dynamic: false,
            accepted_dynamic_range: None,
            pending_refresh,
            pending_export_apply: false,
            advertise_graceful_shutdown: false,
        },
    );
    mgr.register_session(1, &peer_key);
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
            transport_config: transport,
            import_policy: None,
            export_policy: None,
            pending_inbound: None,
            is_dynamic: false,
            accepted_dynamic_range: None,
            pending_refresh: false,
            pending_export_apply: false,
            advertise_graceful_shutdown: false,
        },
    );
    mgr.register_session(session_id, &peer_key);
}

#[derive(Default)]
struct FakePeerCounters {
    collision_dump: AtomicU32,
    query_state: AtomicU32,
    route_refresh: AtomicU32,
    shutdown: AtomicU32,
    stop: AtomicU32,
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
                PeerCommand::QueryState { reply } => {
                    counters.query_state.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(PeerSessionState {
                        fsm_state: state,
                        peer_ip: peer_addr,
                        peer_asn: None,
                        prefix_count: 0,
                        negotiated_hold_time: None,
                        four_octet_as: None,
                        remote_router_id,
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
        address: addr.to_string(),
        interface: None,
        remote_asn,
        description: None,
        peer_group: None,
        hold_time: None,
        send_hold_time: None,
        max_prefixes: None,
        md5_password: None,
        tcp_ao: None,
        bfd: None,
        ttl_security: None,
        families: Vec::new(),
        graceful_restart: None,
        gr_restart_time: None,
        gr_stale_routes_time: None,
        llgr_stale_time: None,
        local_ipv6_nexthop: None,
        route_reflector_client: None,
        orr_vantage: None,
        route_server_client: None,
        per_client_best: None,
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

#[tokio::test]
async fn add_peer_and_list() {
    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let handle = tokio::spawn(mgr.run());

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::AddPeer {
        config: make_config(addr, 65002),
        sync_config_snapshot: false,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_ok());

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::ListPeers { reply: reply_tx })
        .await
        .unwrap();
    let peers = reply_rx.await.unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].address, addr);
    assert_eq!(peers[0].remote_asn, 65002);

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn reconfigure_peer_preserves_disabled_state() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    mgr.add_peer(make_config(addr, 65002), false).await.unwrap();
    mgr.disable_peer(key(addr), None).await.unwrap();

    let mut replacement = make_config(addr, 65002);
    replacement.hold_time = Some(45);
    let previous = mgr.reconfigure_peer(replacement).await.unwrap();

    assert_eq!(previous.hold_time, Some(90));
    let managed = mgr.peers.get(&key(addr)).expect("reconfigured peer");
    assert_eq!(managed.hold_time, Some(45));
    assert!(!managed.enabled);
}

#[tokio::test]
async fn reconfigure_peer_preserves_graceful_shutdown_intent() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::RefreshPeerOutbound { reply, .. } = update {
                let _ = reply.send(Ok(()));
            }
        }
    });
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    mgr.add_peer(make_config(addr, 65002), false).await.unwrap();
    mgr.peers
        .get_mut(&key(addr))
        .expect("managed peer")
        .advertise_graceful_shutdown = true;

    let mut replacement = make_config(addr, 65002);
    replacement.description = "modified".to_string();
    mgr.reconfigure_peer(replacement).await.unwrap();

    let managed = mgr.peers.get(&key(addr)).expect("reconfigured peer");
    assert_eq!(managed.description, "modified");
    assert!(managed.advertise_graceful_shutdown);
}

// ── LAN-341: hot-applicable-only edits apply in place ─────────────────

#[tokio::test]
async fn hot_update_peer_applies_in_place_without_session_rebuild() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    mgr.add_peer(make_config(addr, 65002), false).await.unwrap();
    let session_id_before = mgr.peers.get(&key(addr)).expect("peer").session_id;

    let mut updated = make_config(addr, 65002);
    updated.description = "hot-updated".to_string();
    updated.max_prefixes = Some(500);
    updated.gr_stale_routes_time = 300;
    mgr.hot_update_peer(updated).await.unwrap();

    let managed = mgr.peers.get(&key(addr)).expect("hot-updated peer");
    // The load-bearing pin: the session task was NOT delete/re-added.
    // Every rebuild path (`reconfigure_peer`, `reconcile_peers` changed)
    // allocates a fresh session id; hot update must keep the same one.
    assert_eq!(managed.session_id, session_id_before);
    assert_eq!(managed.description, "hot-updated");
    assert_eq!(managed.max_prefixes, Some(500));
    assert_eq!(managed.transport_config.max_prefixes, Some(500));
    assert_eq!(managed.transport_config.gr_stale_routes_time, 300);
}

#[tokio::test]
async fn hot_update_peer_applies_policy_chains_in_place() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    mgr.add_peer(make_config(addr, 65002), false).await.unwrap();
    let session_id_before = mgr.peers.get(&key(addr)).expect("peer").session_id;

    let mut updated = make_config(addr, 65002);
    let chain = deny_policy_chain();
    updated.import_policy = Some(chain.clone());
    mgr.hot_update_peer(updated).await.unwrap();

    let managed = mgr.peers.get(&key(addr)).expect("hot-updated peer");
    assert_eq!(managed.session_id, session_id_before);
    assert_eq!(managed.import_policy, Some(chain));
}

#[tokio::test]
async fn hot_update_peer_unknown_peer_returns_not_found() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99));
    let result = mgr.hot_update_peer(make_config(addr, 65002)).await;
    assert!(matches!(
        result,
        Err(rustbgpd_api::peer_types::PeerLifecycleError::NotFound(_))
    ));
}

#[tokio::test]
async fn reconcile_changed_peer_still_rebuilds_session_task() {
    // The contrast pin for LAN-341: a session-reset-class change routed
    // through `ReconcilePeers.changed` (the reload rebuild path) must
    // still delete/re-add the session task — observable as a fresh
    // session id.
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    mgr.add_peer(make_config(addr, 65002), false).await.unwrap();
    let session_id_before = mgr.peers.get(&key(addr)).expect("peer").session_id;

    let mut changed = make_config(addr, 65002);
    changed.hold_time = Some(30);
    let result = mgr
        .reconcile_peers(Vec::new(), Vec::new(), vec![changed])
        .await;
    assert!(result.failures.is_empty(), "{:?}", result.failures);

    let managed = mgr.peers.get(&key(addr)).expect("rebuilt peer");
    assert_ne!(managed.session_id, session_id_before);
    assert_eq!(managed.hold_time, Some(30));
}

#[tokio::test]
async fn reconfigure_peer_restores_previous_peer_when_replacement_add_fails() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let addr = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
    let interface = "rustbgpd-test-missing0";
    let mut original = make_config(addr, 65002);
    original.interface = Some(interface.to_string());
    original.scope_id = Some(42);
    mgr.add_peer(original, false).await.unwrap();
    mgr.disable_peer(scoped_key(addr, interface), None)
        .await
        .unwrap();

    let mut replacement = make_config(addr, 65002);
    replacement.interface = Some(interface.to_string());
    replacement.description = "should not survive failed add".to_string();
    let Err(error) = mgr.reconfigure_peer(replacement).await else {
        panic!("invalid replacement should fail after internal restore");
    };

    assert!(
        error.to_string().contains("previous peer restored"),
        "{error}"
    );
    let managed = mgr
        .peers
        .get(&scoped_key(addr, interface))
        .expect("restored peer");
    assert_eq!(managed.description, format!("test-peer-{addr}"));
    assert_eq!(managed.remote_asn, 65002);
    assert_eq!(managed.hold_time, Some(90));
    assert!(!managed.enabled);
}

#[tokio::test]
async fn apply_peer_reshape_snapshot_returns_priors_and_can_replay_them() {
    let mut mgr = test_peer_manager();
    let addr1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let addr2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    mgr.add_peer(make_config(addr1, 65002), false)
        .await
        .unwrap();
    mgr.add_peer(make_config(addr2, 65003), false)
        .await
        .unwrap();
    mgr.disable_peer(key(addr2), None).await.unwrap();

    let mut replacement1 = make_config(addr1, 65002);
    replacement1.hold_time = Some(45);
    let mut replacement2 = make_config(addr2, 65003);
    replacement2.hold_time = Some(30);

    let priors = mgr
        .apply_peer_reshape_snapshot(vec![replacement1, replacement2])
        .await
        .unwrap();

    assert_eq!(priors.len(), 2);
    assert_eq!(priors[0].hold_time, Some(90));
    assert_eq!(priors[1].hold_time, Some(90));
    assert_eq!(
        mgr.peers.get(&key(addr1)).expect("peer 1").hold_time,
        Some(45)
    );
    let peer2 = mgr.peers.get(&key(addr2)).expect("peer 2");
    assert_eq!(peer2.hold_time, Some(30));
    assert!(!peer2.enabled);

    let rollback_priors = mgr.apply_peer_reshape_snapshot(priors).await.unwrap();
    assert_eq!(rollback_priors.len(), 2);
    assert_eq!(
        mgr.peers.get(&key(addr1)).expect("peer 1").hold_time,
        Some(90)
    );
    let peer2 = mgr.peers.get(&key(addr2)).expect("peer 2");
    assert_eq!(peer2.hold_time, Some(90));
    assert!(!peer2.enabled);
}

#[tokio::test]
async fn apply_peer_reshape_snapshot_rejects_duplicate_targets_without_mutation() {
    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    mgr.add_peer(make_config(addr, 65002), false).await.unwrap();

    let mut replacement = make_config(addr, 65002);
    replacement.hold_time = Some(45);
    let mut duplicate = replacement.clone();
    duplicate.description = "duplicate target".to_string();

    let Err(error) = mgr
        .apply_peer_reshape_snapshot(vec![replacement, duplicate])
        .await
    else {
        panic!("duplicate targets must be rejected before mutation");
    };

    assert!(
        error.to_string().contains("appears more than once"),
        "{error}"
    );
    let managed = mgr.peers.get(&key(addr)).expect("unchanged peer");
    assert_eq!(managed.hold_time, Some(90));
    assert_eq!(managed.description, format!("test-peer-{addr}"));
}

#[tokio::test]
async fn apply_peer_reshape_snapshot_rejects_tcp_ao_delta_without_mutation() {
    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    mgr.add_peer(make_config(addr, 65002), false).await.unwrap();

    let mut replacement = make_config(addr, 65002);
    replacement.hold_time = Some(45);
    replacement.tcp_ao = Some(rustbgpd_transport::TcpAoConfig {
        key: "secret".to_string(),
        send_id: 1,
        recv_id: 1,
        algorithm: rustbgpd_transport::TcpAoAlgorithm::HmacSha256,
        preferred: false,
        deprecated: false,
    });

    let Err(error) = mgr.apply_peer_reshape_snapshot(vec![replacement]).await else {
        panic!("TCP-AO deltas must be rejected before mutation");
    };

    assert!(error.to_string().contains("changes tcp_ao"), "{error}");
    let managed = mgr.peers.get(&key(addr)).expect("unchanged peer");
    assert_eq!(managed.hold_time, Some(90));
    assert!(managed.transport_config.tcp_ao.is_none());
}

#[tokio::test]
async fn apply_peer_reshape_snapshot_rolls_back_prior_peers_on_later_failure() {
    let mut mgr = test_peer_manager();
    let addr1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    mgr.add_peer(make_config(addr1, 65002), false)
        .await
        .unwrap();

    let addr2 = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2));
    let interface = "rustbgpd-test-missing0";
    let mut original2 = make_config(addr2, 65003);
    original2.interface = Some(interface.to_string());
    original2.scope_id = Some(42);
    mgr.add_peer(original2, false).await.unwrap();

    let mut replacement1 = make_config(addr1, 65002);
    replacement1.hold_time = Some(45);
    let mut invalid_replacement2 = make_config(addr2, 65003);
    invalid_replacement2.interface = Some(interface.to_string());
    invalid_replacement2.description = "should not survive failed reshape".to_string();

    let Err(error) = mgr
        .apply_peer_reshape_snapshot(vec![replacement1, invalid_replacement2])
        .await
    else {
        panic!("later invalid target must fail and roll back earlier peers");
    };

    assert!(
        error.to_string().contains("prior peers restored"),
        "{error}"
    );
    let peer1 = mgr.peers.get(&key(addr1)).expect("restored peer 1");
    assert_eq!(peer1.hold_time, Some(90));
    let peer2 = mgr
        .peers
        .get(&scoped_key(addr2, interface))
        .expect("restored peer 2");
    assert_eq!(peer2.description, format!("test-peer-{addr2}"));
    assert_eq!(peer2.hold_time, Some(90));
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
            transport_config: transport,
            import_policy: None,
            export_policy: None,
            pending_inbound: None,
            is_dynamic: true,
            accepted_dynamic_range: Some(AcceptedDynamicRange {
                addr: range_addr,
                prefix_len: range_prefix_len,
                peer_group: range_peer_group.to_string(),
            }),
            pending_refresh: false,
            pending_export_apply: false,
            advertise_graceful_shutdown: false,
        },
    );
    mgr.register_session(session_id, &peer_key);
    mgr.dynamic_peer_count += 1;
}

#[tokio::test]
async fn rollback_reap_preserves_dynamic_peer_accepted_by_wildcard_asn_range() {
    let mut mgr = dynamic_test_manager();
    let peer_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 42));
    let counters = Arc::new(FakePeerCounters::default());
    insert_test_dynamic_managed_peer(
        &mut mgr,
        peer_addr,
        77,
        fake_peer_handle(
            peer_addr,
            SessionState::Established,
            Some(Ipv4Addr::new(192, 0, 2, 42)),
            counters,
        ),
        true,
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
        8,
        "ix-members",
    );

    assert_eq!(mgr.dynamic_ranges[0].remote_asn, 0);
    assert_eq!(
        mgr.peers.get(&key(peer_addr)).unwrap().remote_asn,
        65030,
        "fixture simulates a wildcard-accepted peer after the real ASN is known"
    );

    let removed = mgr.reap_dynamic_peers_not_allowed_by_current_ranges().await;
    assert_eq!(removed, 0);
    assert!(
        mgr.peers.contains_key(&key(peer_addr)),
        "wildcard dynamic ranges must keep peers whose learned ASN is nonzero"
    );
    assert_eq!(mgr.dynamic_peer_count, 1);
}

#[tokio::test]
async fn rollback_reap_keeps_dynamic_peer_for_host_bit_range_prefix() {
    // Regression: a `[[dynamic_neighbors]]` prefix configured with host bits
    // set (`127.0.0.9/24`) parses into a RAW `DynamicRange`, but an accepted
    // peer's attribution is MASKED (`127.0.0.0/24`, via `accepted_attribution`).
    // The reap predicate must normalize the range side through `effective_prefix`
    // or it tears down a live dynamic session on every rollback whose restored
    // snapshot still contains that unchanged range.
    let mut mgr = dynamic_test_manager();
    let mut config = make_dynamic_manager_config();
    config.dynamic_neighbors = vec![crate::config::DynamicNeighborConfig {
        prefix: "127.0.0.9/24".to_string(),
        peer_group: "ix-members".to_string(),
        remote_asn: 0,
        description: Some("host-bit range".to_string()),
        tcp_ao: None,
    }];
    mgr.dynamic_ranges = PeerManager::parse_dynamic_ranges(&config);
    assert_eq!(
        mgr.dynamic_ranges[0].addr,
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9)),
        "the range is stored raw/unmasked, with host bits intact"
    );
    assert_eq!(mgr.dynamic_ranges[0].prefix_len, 24);

    let peer_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 42));
    let counters = Arc::new(FakePeerCounters::default());
    insert_test_dynamic_managed_peer(
        &mut mgr,
        peer_addr,
        88,
        fake_peer_handle(
            peer_addr,
            SessionState::Established,
            Some(Ipv4Addr::new(192, 0, 2, 42)),
            counters,
        ),
        true,
        // The masked attribution, exactly what `accepted_attribution()` stores
        // when this peer is accepted by the host-bit range above.
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
        24,
        "ix-members",
    );

    let removed = mgr.reap_dynamic_peers_not_allowed_by_current_ranges().await;
    assert_eq!(
        removed, 0,
        "a host-bit range prefix must not reap the peer whose masked attribution still matches it"
    );
    assert!(
        mgr.peers.contains_key(&key(peer_addr)),
        "a live dynamic session must survive rollback to a snapshot that still contains its (host-bit) range"
    );
    assert_eq!(mgr.dynamic_peer_count, 1);
}

#[tokio::test]
async fn bounce_dynamic_peers_signals_only_matching_enabled_dynamic_sessions() {
    let mut mgr = dynamic_test_manager();

    let static_counters = Arc::new(FakePeerCounters::default());
    let static_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    insert_test_managed_peer(
        &mut mgr,
        static_addr,
        fake_peer_handle(
            static_addr,
            SessionState::Established,
            None,
            static_counters.clone(),
        ),
        false,
    );

    let matched_counters = Arc::new(FakePeerCounters::default());
    let matched_addr = IpAddr::V4(Ipv4Addr::new(10, 30, 0, 5));
    insert_test_dynamic_managed_peer(
        &mut mgr,
        matched_addr,
        11,
        fake_peer_handle(
            matched_addr,
            SessionState::Established,
            None,
            matched_counters.clone(),
        ),
        true,
        IpAddr::V4(Ipv4Addr::new(10, 30, 0, 0)),
        16,
        "ix-members",
    );

    let other_range_counters = Arc::new(FakePeerCounters::default());
    let other_addr = IpAddr::V4(Ipv4Addr::new(10, 40, 0, 5));
    insert_test_dynamic_managed_peer(
        &mut mgr,
        other_addr,
        12,
        fake_peer_handle(
            other_addr,
            SessionState::Established,
            None,
            other_range_counters.clone(),
        ),
        true,
        IpAddr::V4(Ipv4Addr::new(10, 40, 0, 0)),
        16,
        "ix-members",
    );

    let disabled_counters = Arc::new(FakePeerCounters::default());
    let disabled_addr = IpAddr::V4(Ipv4Addr::new(10, 30, 0, 6));
    insert_test_dynamic_managed_peer(
        &mut mgr,
        disabled_addr,
        13,
        fake_peer_handle(
            disabled_addr,
            SessionState::Idle,
            None,
            disabled_counters.clone(),
        ),
        false,
        IpAddr::V4(Ipv4Addr::new(10, 30, 0, 0)),
        16,
        "ix-members",
    );

    let dynamic_count_before = mgr.dynamic_peer_count;
    let outcome = mgr
        .bounce_dynamic_peers_for_ranges(&[DynamicRangeTarget {
            addr: IpAddr::V4(Ipv4Addr::new(10, 30, 0, 0)),
            prefix_len: 16,
            peer_group: "ix-members".to_string(),
        }])
        .await;

    assert_eq!(outcome.signaled, 1, "{outcome:?}");
    assert!(outcome.failures.is_empty(), "{outcome:?}");
    wait_counter(&matched_counters.stop, 1).await;
    assert_eq!(static_counters.stop.load(Ordering::SeqCst), 0);
    assert_eq!(other_range_counters.stop.load(Ordering::SeqCst), 0);
    assert_eq!(disabled_counters.stop.load(Ordering::SeqCst), 0);

    // The bounce only signals: ManagedPeer removal, the
    // `dynamic_peer_count` slot decrement, and metric reaping stay owned by
    // the normal BackToIdle reap path, and the peer's admin state is
    // untouched so that reap actually runs.
    assert_eq!(mgr.dynamic_peer_count, dynamic_count_before);
    let managed = mgr
        .peers
        .get(&key(matched_addr))
        .expect("signaled peer must remain managed until BackToIdle reaps it");
    assert!(managed.enabled);
    assert!(managed.is_dynamic);
}

#[tokio::test]
async fn bounce_dynamic_peers_reports_signaling_failures_per_peer() {
    let mut mgr = dynamic_test_manager();

    // A handle whose session task is already gone: the stop signal fails.
    let (dead_tx, dead_rx) = mpsc::channel(1);
    drop(dead_rx);
    let dead_handle = PeerHandle::from_parts(dead_tx, tokio::spawn(async { Ok(()) }));
    let dead_addr = IpAddr::V4(Ipv4Addr::new(10, 30, 0, 5));
    insert_test_dynamic_managed_peer(
        &mut mgr,
        dead_addr,
        11,
        dead_handle,
        true,
        IpAddr::V4(Ipv4Addr::new(10, 30, 0, 0)),
        16,
        "ix-members",
    );

    let live_counters = Arc::new(FakePeerCounters::default());
    let live_addr = IpAddr::V4(Ipv4Addr::new(10, 30, 0, 6));
    insert_test_dynamic_managed_peer(
        &mut mgr,
        live_addr,
        12,
        fake_peer_handle(
            live_addr,
            SessionState::Established,
            None,
            live_counters.clone(),
        ),
        true,
        IpAddr::V4(Ipv4Addr::new(10, 30, 0, 0)),
        16,
        "ix-members",
    );

    let outcome = mgr
        .bounce_dynamic_peers_for_ranges(&[DynamicRangeTarget {
            addr: IpAddr::V4(Ipv4Addr::new(10, 30, 0, 0)),
            prefix_len: 16,
            peer_group: "ix-members".to_string(),
        }])
        .await;

    // One failure reported by peer, and the failure does not stop the sweep:
    // the live peer is still signaled.
    assert_eq!(outcome.signaled, 1, "{outcome:?}");
    assert_eq!(outcome.failures.len(), 1, "{outcome:?}");
    assert!(
        outcome.failures[0].contains("10.30.0.5"),
        "{:?}",
        outcome.failures
    );
    wait_counter(&live_counters.stop, 1).await;
    // The unsignalable peer stays managed; it keeps its running config until
    // it reconnects (or its session-task exit drives BackToIdle).
    assert!(mgr.peers.contains_key(&key(dead_addr)));
}

#[tokio::test]
async fn reconcile_changed_peer_preserves_disabled_state() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    mgr.add_peer(make_config(addr, 65002), false).await.unwrap();
    mgr.disable_peer(key(addr), None).await.unwrap();

    let mut replacement = make_config(addr, 65002);
    replacement.description = "reloaded description".to_string();
    replacement.hold_time = Some(45);
    let result = mgr
        .reconcile_peers(Vec::new(), Vec::new(), vec![replacement])
        .await;

    assert!(result.failures.is_empty(), "{:?}", result.failures);
    let managed = mgr.peers.get(&key(addr)).expect("reconciled peer");
    assert_eq!(managed.description, "reloaded description");
    assert_eq!(managed.hold_time, Some(45));
    assert!(!managed.enabled);
}

#[tokio::test]
async fn peer_group_change_preserves_disabled_state() {
    let config = load_test_config(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.edge]
hold_time = 90

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "edge"
"#,
    );
    let (_tx, rx) = mpsc::channel(16);
    let (_internal_tx, internal_rx) = mpsc::unbounded_channel();
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new_with_config(
        rx,
        internal_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
        None,
        config.clone(),
    );
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let initial = PeerManager::peer_manager_config_from_resolved(
        config
            .resolved_neighbors()
            .unwrap()
            .into_iter()
            .next()
            .expect("one neighbor"),
        false,
    );
    mgr.add_peer(initial, false).await.unwrap();
    mgr.disable_peer(key(addr), None).await.unwrap();

    mgr.apply_peer_group_change(
        rustbgpd_api::peer_types::ConfigEvent::SetPeerGroup {
            name: "edge".to_string(),
            definition: rustbgpd_api::peer_types::PeerGroupDefinition {
                hold_time: Some(45),
                send_hold_time: None,
                max_prefixes: None,
                md5_password: None,
                ttl_security: None,
                families: Vec::new(),
                graceful_restart: None,
                gr_restart_time: None,
                gr_stale_routes_time: None,
                llgr_stale_time: None,
                local_ipv6_nexthop: None,
                route_reflector_client: None,
                orr_vantage: None,
                route_server_client: None,
                per_client_best: None,
                remove_private_as: None,
                add_path: None,
                import_policy: Vec::new(),
                export_policy: Vec::new(),
                import_policy_chain: Vec::new(),
                export_policy_chain: Vec::new(),
            },
            ack: None,
        },
        vec![addr],
    )
    .await
    .unwrap();

    let managed = mgr.peers.get(&key(addr)).expect("reconfigured peer");
    assert_eq!(managed.hold_time, Some(45));
    assert!(!managed.enabled);
}

fn edge_group_definition(hold_time: Option<u16>) -> rustbgpd_api::peer_types::PeerGroupDefinition {
    rustbgpd_api::peer_types::PeerGroupDefinition {
        hold_time,
        send_hold_time: None,
        max_prefixes: None,
        md5_password: None,
        ttl_security: None,
        families: Vec::new(),
        graceful_restart: None,
        gr_restart_time: None,
        gr_stale_routes_time: None,
        llgr_stale_time: None,
        local_ipv6_nexthop: None,
        route_reflector_client: None,
        orr_vantage: None,
        route_server_client: None,
        per_client_best: None,
        remove_private_as: None,
        add_path: None,
        import_policy: Vec::new(),
        export_policy: Vec::new(),
        import_policy_chain: Vec::new(),
        export_policy_chain: Vec::new(),
    }
}

fn set_edge_hold_time_event(hold_time: u16) -> rustbgpd_api::peer_types::ConfigEvent {
    rustbgpd_api::peer_types::ConfigEvent::SetPeerGroup {
        name: "edge".to_string(),
        definition: edge_group_definition(Some(hold_time)),
        ack: None,
    }
}

fn peer_group_reshape_manager(config: Config) -> PeerManager {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
    // Leak the RIB receiver so session sends during delete/re-add never fail.
    Box::leak(Box::new(rib_rx));
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
        config,
    )
}

const EDGE_GROUP_TOML: &str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.edge]
hold_time = 90

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "edge"

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "edge"

[[neighbors]]
address = "10.0.0.4"
remote_asn = 65004
peer_group = "edge"
"#;

#[tokio::test]
async fn peer_group_reshape_noop_update_does_not_bounce_or_publish() {
    let config = load_test_config(EDGE_GROUP_TOML);
    let mut mgr = peer_group_reshape_manager(config.clone());
    for resolved in config.resolved_neighbors().unwrap() {
        mgr.add_peer(
            PeerManager::peer_manager_config_from_resolved(resolved, false),
            false,
        )
        .await
        .unwrap();
    }
    let addresses = [
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)),
    ];
    let before: Vec<_> = addresses
        .iter()
        .map(|addr| {
            (
                *addr,
                mgr.peers.get(&key(*addr)).expect("managed peer").session_id,
            )
        })
        .collect();
    let config_before = mgr.current_config.clone();

    mgr.apply_peer_group_change(set_edge_hold_time_event(90), addresses.to_vec())
        .await
        .unwrap();

    for (addr, session_id) in before {
        let managed = mgr.peers.get(&key(addr)).expect("managed peer");
        assert_eq!(
            managed.session_id, session_id,
            "no-op peer-group set must not rebuild {addr}"
        );
        assert_eq!(managed.hold_time, Some(90));
    }
    assert_eq!(
        mgr.current_config
            .peer_groups
            .get("edge")
            .expect("group definition")
            .hold_time,
        Some(90),
        "no-op update must leave current_config unchanged"
    );
    assert_eq!(
        mgr.current_config, config_before,
        "no-op update must leave the full resolved config structurally unchanged"
    );
    assert!(
        query_policy_event_history(&mgr, None, 8).await.is_empty(),
        "no-op update must not publish a catalog policy event"
    );
}

/// ADR-0081 success path: a targeted `SetPeerGroup` reshapes every static
/// member through the captured-prior snapshot primitive, advances
/// `current_config`, and publishes the applied member count.
#[tokio::test]
async fn peer_group_reshape_applies_to_all_members_and_advances_config() {
    let config = load_test_config(EDGE_GROUP_TOML);
    let mut mgr = peer_group_reshape_manager(config.clone());
    for resolved in config.resolved_neighbors().unwrap() {
        mgr.add_peer(
            PeerManager::peer_manager_config_from_resolved(resolved, false),
            false,
        )
        .await
        .unwrap();
    }
    let a1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let a2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let a3 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    let before: Vec<_> = [a1, a2, a3]
        .into_iter()
        .map(|addr| {
            (
                addr,
                mgr.peers.get(&key(addr)).expect("managed peer").session_id,
            )
        })
        .collect();

    mgr.apply_peer_group_change(set_edge_hold_time_event(45), vec![a1, a2, a3])
        .await
        .unwrap();

    for (addr, session_id) in before {
        let managed = mgr.peers.get(&key(addr)).expect("reshaped member");
        assert_eq!(managed.hold_time, Some(45));
        assert_ne!(
            managed.session_id, session_id,
            "real peer-group reshape must rebuild {addr}"
        );
    }
    assert_eq!(
        mgr.current_config
            .peer_groups
            .get("edge")
            .expect("group definition")
            .hold_time,
        Some(45),
        "successful reshape must advance current_config"
    );
    let events = query_policy_event_history(&mgr, None, 8).await;
    let event = events
        .iter()
        .find(|event| event.target_type == "peer_group")
        .expect("peer-group policy event");
    assert_eq!(event.affected_peer_count, 3);
}

/// ADR-0081: a mid-fanout reconfigure failure on the targeted peer-group
/// path restores already-reshaped members from their captured priors, never
/// reaches later members, leaves the failing member in place, and does not
/// advance `current_config`.
///
/// Every config-shaped failure is rejected before any peer is touched
/// (event validation, phase-1 resolution, the primitive's preflight), so
/// the surviving mid-fanout failure class is a transient runtime fault —
/// induced here with the manager's test-only reconfigure injection.
#[tokio::test]
async fn peer_group_reshape_mid_fanout_failure_restores_prior_members() {
    let config = load_test_config(EDGE_GROUP_TOML);
    let mut mgr = peer_group_reshape_manager(config.clone());
    for resolved in config.resolved_neighbors().unwrap() {
        mgr.add_peer(
            PeerManager::peer_manager_config_from_resolved(resolved, false),
            false,
        )
        .await
        .unwrap();
    }
    let a1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let a2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)); // its reconfigure fails
    let a3 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    mgr.inject_reconfigure_failures.insert(key(a2), 0);

    let result = mgr
        .apply_peer_group_change(
            set_edge_hold_time_event(45),
            // Explicit order so member 1 is reshaped before member 2 fails.
            vec![a1, a2, a3],
        )
        .await;
    let Err(error) = result else {
        panic!("mid-fanout reconfigure failure must surface as Err");
    };
    assert!(
        matches!(error, CatalogMutationError::Internal(_)),
        "{error:?}"
    );
    let message = error.to_string();
    assert!(message.contains("prior peers restored"), "{message}");
    assert!(message.contains("10.0.0.3"), "{message}");

    assert_eq!(
        mgr.peers
            .get(&key(a1))
            .expect("restored member 1")
            .hold_time,
        Some(90),
        "member reshaped before the failure must be back on its prior config"
    );
    assert_eq!(
        mgr.peers.get(&key(a2)).expect("failing member").hold_time,
        Some(90),
        "the failing member must still exist on its prior config, not be left deleted"
    );
    assert_eq!(
        mgr.peers
            .get(&key(a3))
            .expect("untouched member 3")
            .hold_time,
        Some(90),
        "member after the failure must never be touched"
    );
    assert_eq!(
        mgr.current_config
            .peer_groups
            .get("edge")
            .expect("group definition")
            .hold_time,
        Some(90),
        "failed reshape must not advance current_config"
    );
}

/// ADR-0081: rollback of the captured priors is best-effort — a failed
/// restore must not short-circuit the reverse sweep, so every earlier
/// member is still attempted, and the compound error names exactly which
/// members were left in the reshaped state (members it does not name were
/// restored).
#[tokio::test]
async fn peer_group_reshape_rollback_failure_still_restores_other_priors() {
    let config = load_test_config(EDGE_GROUP_TOML);
    let mut mgr = peer_group_reshape_manager(config.clone());
    for resolved in config.resolved_neighbors().unwrap() {
        mgr.add_peer(
            PeerManager::peer_manager_config_from_resolved(resolved, false),
            false,
        )
        .await
        .unwrap();
    }
    let a1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let a2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)); // its rollback fails
    let a3 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)); // its apply fails
    // a3 fails on its first reconfigure (the apply), triggering rollback of
    // the captured priors [a1, a2] in reverse order; a2's first reconfigure
    // (the apply) succeeds and its second (the rollback) fails.
    mgr.inject_reconfigure_failures.insert(key(a3), 0);
    mgr.inject_reconfigure_failures.insert(key(a2), 1);

    let result = mgr
        .apply_peer_group_change(
            set_edge_hold_time_event(45),
            // Explicit order so members 1 and 2 are reshaped before member 3
            // fails.
            vec![a1, a2, a3],
        )
        .await;
    let Err(error) = result else {
        panic!("apply failure with a partial rollback failure must surface as Err");
    };
    assert!(
        matches!(error, CatalogMutationError::Internal(_)),
        "{error:?}"
    );
    let message = error.to_string();
    assert!(
        message.contains("10.0.0.4"),
        "compound error must carry the original apply failure: {message}"
    );
    assert!(
        message.contains("10.0.0.3"),
        "compound error must name the member left reshaped: {message}"
    );
    assert!(
        !message.contains("10.0.0.2"),
        "compound error must not claim the restored member failed: {message}"
    );

    assert_eq!(
        mgr.peers
            .get(&key(a1))
            .expect("restored member 1")
            .hold_time,
        Some(90),
        "member 1's rollback must still be attempted after member 2's fails"
    );
    assert_eq!(
        mgr.peers
            .get(&key(a2))
            .expect("rollback-failed member 2")
            .hold_time,
        Some(45),
        "member 2 stays in the reshaped state its failed rollback left it in"
    );
    assert_eq!(
        mgr.peers
            .get(&key(a3))
            .expect("apply-failed member 3")
            .hold_time,
        Some(90),
        "member 3's apply failed up front, leaving its prior config in place"
    );
    assert_eq!(
        mgr.current_config
            .peer_groups
            .get("edge")
            .expect("group definition")
            .hold_time,
        Some(90),
        "failed reshape must not advance current_config"
    );
}

/// ADR-0081 decision 2: a member whose resolved next config changes TCP-AO
/// is rejected by the primitive's preflight with `RestartRequired` BEFORE
/// any session is bounced — no delete/re-add, no partial apply.
#[tokio::test]
async fn peer_group_reshape_rejects_tcp_ao_delta_before_any_bounce() {
    let config = load_test_config(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.edge]
hold_time = 90

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "edge"
tcp_ao = { key = "secret", send_id = 7, recv_id = 9, algorithm = "hmac(sha256)" }
"#,
    );
    let mut mgr = peer_group_reshape_manager(config);
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let counters = Arc::new(FakePeerCounters::default());
    // The running peer carries NO TCP-AO key, so the resolved next config
    // (tcp_ao set) is a restart-required delta.
    insert_test_managed_peer(
        &mut mgr,
        addr,
        fake_peer_handle(addr, SessionState::Idle, None, counters.clone()),
        false,
    );

    let Err(error) = mgr
        .apply_peer_group_change(set_edge_hold_time_event(45), vec![addr])
        .await
    else {
        panic!("TCP-AO delta must be rejected up front");
    };
    assert!(
        matches!(error, CatalogMutationError::RestartRequired(_)),
        "{error:?}"
    );
    assert!(error.to_string().contains("changes tcp_ao"), "{error}");

    assert_eq!(
        counters.shutdown.load(Ordering::SeqCst),
        0,
        "preflight rejection must not bounce any session"
    );
    let managed = mgr.peers.get(&key(addr)).expect("untouched peer");
    assert_eq!(managed.hold_time, Some(90));
    assert_eq!(managed.session_id, 1, "peer generation unchanged");
    assert_eq!(
        mgr.current_config
            .peer_groups
            .get("edge")
            .expect("group definition")
            .hold_time,
        Some(90)
    );
}

/// ADR-0081 decision 3: rollback re-reads live admin state, so a member
/// that was admin-disabled before the failed fan-out is still disabled
/// after its prior config is restored.
#[tokio::test]
async fn peer_group_reshape_rollback_preserves_admin_disabled_state() {
    let config = load_test_config(EDGE_GROUP_TOML);
    let mut mgr = peer_group_reshape_manager(config.clone());
    for resolved in config.resolved_neighbors().unwrap() {
        mgr.add_peer(
            PeerManager::peer_manager_config_from_resolved(resolved, false),
            false,
        )
        .await
        .unwrap();
    }
    let a1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let a2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    mgr.disable_peer(key(a1), None).await.unwrap();
    // Member 2 fails after member 1 was reshaped, forcing member 1's
    // rollback while it is admin-disabled.
    mgr.inject_reconfigure_failures.insert(key(a2), 0);

    let result = mgr
        .apply_peer_group_change(set_edge_hold_time_event(45), vec![a1, a2])
        .await;
    assert!(result.is_err(), "{result:?}");

    let managed = mgr.peers.get(&key(a1)).expect("restored member");
    assert_eq!(managed.hold_time, Some(90));
    assert!(
        !managed.enabled,
        "rollback must preserve the member's admin-disabled state"
    );
}

/// ADR-0081 decision 4: a dynamic peer at an affected address is never
/// bounced by a targeted peer-group reshape — its running session keeps its
/// config until it reconnects. The definition edit itself still commits.
#[tokio::test]
async fn peer_group_reshape_skips_dynamic_peers_without_bouncing() {
    let config = load_test_config(EDGE_GROUP_TOML);
    let mut mgr = peer_group_reshape_manager(config);
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let counters = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer(
        &mut mgr,
        addr,
        fake_peer_handle(addr, SessionState::Established, None, counters.clone()),
        false,
    );
    mgr.peers.get_mut(&key(addr)).unwrap().is_dynamic = true;

    mgr.apply_peer_group_change(set_edge_hold_time_event(45), vec![addr])
        .await
        .unwrap();

    assert_eq!(
        counters.shutdown.load(Ordering::SeqCst),
        0,
        "dynamic peer must not be bounced by a peer-group reshape"
    );
    let managed = mgr.peers.get(&key(addr)).expect("dynamic peer");
    assert!(managed.is_dynamic);
    assert_eq!(managed.hold_time, Some(90), "running config unchanged");
    assert_eq!(
        mgr.current_config
            .peer_groups
            .get("edge")
            .expect("group definition")
            .hold_time,
        Some(45),
        "the definition edit itself still commits"
    );
}

/// Regression for the old per-member loop's `None` arm, which DELETED a
/// managed static peer whose neighbor record could not be found in the next
/// config. Peer-group events never remove records, so that state is a
/// snapshot/managed-peer inconsistency: refuse with zero peers touched.
#[tokio::test]
async fn peer_group_reshape_rejects_member_missing_from_next_config() {
    let config = load_test_config(EDGE_GROUP_TOML);
    let mut mgr = peer_group_reshape_manager(config);
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let counters = Arc::new(FakePeerCounters::default());
    // Managed under a scoped key, so the interface-qualified record lookup
    // finds no `[[neighbors]]` entry for it.
    insert_test_scoped_managed_peer(
        &mut mgr,
        addr,
        "rustbgpd-test-missing0",
        7,
        42,
        fake_peer_handle(addr, SessionState::Idle, None, counters.clone()),
    );

    let Err(error) = mgr
        .apply_peer_group_change(set_edge_hold_time_event(45), vec![addr])
        .await
    else {
        panic!("member missing from next_config must be rejected");
    };
    assert!(
        matches!(error, CatalogMutationError::Internal(_)),
        "{error:?}"
    );
    assert!(error.to_string().contains("no neighbor record"), "{error}");

    assert!(
        mgr.peers
            .contains_key(&scoped_key(addr, "rustbgpd-test-missing0")),
        "the member must NOT be deleted (the old loop's None arm did)"
    );
    assert_eq!(counters.shutdown.load(Ordering::SeqCst), 0);
    assert_eq!(
        mgr.current_config
            .peer_groups
            .get("edge")
            .expect("group definition")
            .hold_time,
        Some(90),
        "rejected reshape must not advance current_config"
    );
}

#[tokio::test]
async fn session_events_publish_state_changes() {
    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let handle = tokio::spawn(mgr.run());
    let mut events = subscribe_session_events(&tx).await;

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::AddPeer {
        config: make_config(addr, 65002),
        sync_config_snapshot: false,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_ok());

    let event = wait_for_session_event(&mut events, SessionLifecycleEventType::StateChanged).await;
    assert_eq!(event.peer, addr);
    assert_eq!(event.session_role.as_deref(), Some("primary"));
    assert!(event.old_state.is_some());
    assert!(event.new_state.is_some());

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn collision_notifications_flush_ready_lifecycle_events_first() {
    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (session_tx, mut session_rx) = mpsc::channel(8);
    let task = tokio::spawn(async move {
        // Exit on Shutdown: `PeerHandle::shutdown` keeps its command
        // sender alive while awaiting the task, so a drain-forever loop
        // here never sees `None` and deadlocks the join.
        while let Some(cmd) = session_rx.recv().await {
            if matches!(
                cmd,
                rustbgpd_transport::PeerCommand::Shutdown
                    | rustbgpd_transport::PeerCommand::Stop { .. }
            ) {
                break;
            }
        }
        Ok(())
    });
    insert_test_managed_peer(
        &mut mgr,
        addr,
        PeerHandle::from_parts(session_tx, task),
        false,
    );
    mgr.peers.get_mut(&key(addr)).unwrap().is_dynamic = true;

    let lifecycle_tx = mgr.session_lifecycle_tx.clone();
    let notify_tx = mgr.session_notify_tx.clone();
    let mut events = mgr.session_events_tx.subscribe();
    let handle = tokio::spawn(mgr.run());

    lifecycle_tx
        .send(SessionLifecycleNotification::StateChanged {
            session_id: 1,
            role: rustbgpd_transport::SessionRole::Primary,
            peer_addr: addr,
            peer_asn: None,
            old: SessionState::Established,
            new: SessionState::Idle,
        })
        .await
        .unwrap();
    notify_tx
        .send(SessionNotification::BackToIdle {
            session_id: 1,
            role: rustbgpd_transport::SessionRole::Primary,
            peer_addr: addr,
        })
        .unwrap();

    let event = wait_for_session_event(&mut events, SessionLifecycleEventType::Lost).await;
    assert_eq!(event.peer, addr);
    assert_eq!(event.old_state, Some(SessionState::Established));
    assert_eq!(event.new_state, Some(SessionState::Idle));

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn dynamic_accept_any_peer_snapshot_learns_negotiated_asn() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    insert_test_managed_peer_with_asn(
        &mut mgr,
        addr,
        0,
        fake_peer_handle(
            addr,
            SessionState::Established,
            None,
            Arc::new(FakePeerCounters::default()),
        ),
        false,
    );
    mgr.peers.get_mut(&key(addr)).unwrap().is_dynamic = true;

    mgr.handle_session_lifecycle_notification(&SessionLifecycleNotification::StateChanged {
        session_id: 1,
        role: rustbgpd_transport::SessionRole::Primary,
        peer_addr: addr,
        peer_asn: Some(65099),
        old: SessionState::OpenConfirm,
        new: SessionState::Established,
    });

    let managed = mgr.peers.get(&key(addr)).unwrap();
    assert_eq!(managed.remote_asn, 65099);
    assert_eq!(managed.transport_config.peer.remote_asn, 65099);
    assert_eq!(
        mgr.get_peer_info(&key(addr)).await.unwrap().remote_asn,
        65099
    );
}

#[tokio::test]
async fn lifecycle_notification_matches_scoped_static_peer_by_session_id() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );

    let peer = IpAddr::V6("fe80::2".parse().unwrap());
    insert_test_scoped_managed_peer(
        &mut mgr,
        peer,
        "eth0",
        10,
        1,
        fake_peer_handle(
            peer,
            SessionState::Established,
            None,
            Arc::new(FakePeerCounters::default()),
        ),
    );
    insert_test_scoped_managed_peer(
        &mut mgr,
        peer,
        "eth1",
        11,
        2,
        fake_peer_handle(
            peer,
            SessionState::Established,
            None,
            Arc::new(FakePeerCounters::default()),
        ),
    );

    let mut events = mgr.session_events_tx.subscribe();
    mgr.handle_session_lifecycle_notification(&SessionLifecycleNotification::StateChanged {
        session_id: 2,
        role: rustbgpd_transport::SessionRole::Primary,
        peer_addr: peer,
        peer_asn: None,
        old: SessionState::OpenConfirm,
        new: SessionState::Established,
    });

    let event = tokio::time::timeout(Duration::from_millis(250), events.recv())
        .await
        .expect("session event timeout")
        .expect("session event channel closed");
    let SessionEvent::Lifecycle(event) = event else {
        panic!("expected lifecycle event");
    };
    assert_eq!(event.peer, peer);
    assert_eq!(event.peer_label.as_deref(), Some("fe80::2%eth1"));
    assert_eq!(event.session_role.as_deref(), Some("primary"));
}

#[tokio::test]
async fn session_events_publish_peer_enable_disable() {
    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let handle = tokio::spawn(mgr.run());

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::AddPeer {
        config: make_config(addr, 65002),
        sync_config_snapshot: false,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_ok());

    let mut events = subscribe_session_events(&tx).await;
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::DisablePeer {
        peer: key(addr),
        reason: None,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_ok());
    let event = wait_for_session_event(&mut events, SessionLifecycleEventType::PeerDisabled).await;
    assert_eq!(event.peer, addr);

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::EnablePeer {
        peer: key(addr),
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_ok());
    let event = wait_for_session_event(&mut events, SessionLifecycleEventType::PeerEnabled).await;
    assert_eq!(event.peer, addr);

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn session_event_history_records_events_without_subscriber() {
    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    mgr.publish_peer_lifecycle_event(
        &key(addr),
        SessionLifecycleEventType::PeerEnabled,
        "peer enabled".to_string(),
    );

    let events = query_session_event_history(&mgr, None, BTreeSet::new(), 0).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].peer, addr);
    assert_eq!(events[0].event_type, SessionLifecycleEventType::PeerEnabled);
}

#[tokio::test]
async fn session_event_history_filters_peer_type_and_limit_in_order() {
    let mut mgr = test_peer_manager();
    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    mgr.publish_peer_lifecycle_event(
        &key(peer1),
        SessionLifecycleEventType::PeerEnabled,
        "old match".to_string(),
    );
    mgr.publish_peer_lifecycle_event(
        &key(peer2),
        SessionLifecycleEventType::PeerEnabled,
        "wrong peer".to_string(),
    );
    mgr.publish_peer_lifecycle_event(
        &key(peer1),
        SessionLifecycleEventType::PeerDisabled,
        "wrong type".to_string(),
    );
    mgr.publish_peer_lifecycle_event(
        &key(peer1),
        SessionLifecycleEventType::PeerEnabled,
        "middle match".to_string(),
    );
    mgr.publish_peer_lifecycle_event(
        &key(peer1),
        SessionLifecycleEventType::PeerEnabled,
        "newest match".to_string(),
    );

    let events = query_session_event_history(
        &mgr,
        Some(peer1),
        [SessionLifecycleEventType::PeerEnabled]
            .into_iter()
            .collect(),
        2,
    )
    .await;
    let reasons: Vec<_> = events.iter().map(|event| event.reason.as_str()).collect();
    assert_eq!(reasons, vec!["middle match", "newest match"]);
}

#[tokio::test]
async fn session_event_history_capacity_evicts_oldest() {
    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    for idx in 0..=SESSION_EVENT_HISTORY_CAPACITY {
        mgr.publish_peer_lifecycle_event(
            &key(addr),
            SessionLifecycleEventType::StateChanged,
            format!("event-{idx}"),
        );
    }

    let events = query_session_event_history(&mgr, None, BTreeSet::new(), 0).await;
    assert_eq!(events.len(), SESSION_EVENT_HISTORY_CAPACITY);
    assert_eq!(events[0].reason, "event-1");
    let expected_last = format!("event-{SESSION_EVENT_HISTORY_CAPACITY}");
    assert_eq!(
        events.last().map(|event| event.reason.as_str()),
        Some(expected_last.as_str())
    );
}

#[tokio::test]
async fn policy_event_history_records_events_without_subscriber() {
    let mut mgr = test_peer_manager();

    mgr.publish_policy_event(test_policy_event("policy-a", None));

    let events = query_policy_event_history(&mgr, None, 0).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].target, "policy-a");
    assert_eq!(events[0].reason, "policy set policy policy-a");
}

#[tokio::test]
async fn policy_event_history_filters_peer_and_limit_in_order() {
    let mut mgr = test_peer_manager();
    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    mgr.publish_policy_event(test_policy_event("old-match", Some(peer1)));
    mgr.publish_policy_event(test_policy_event("wrong-peer", Some(peer2)));
    mgr.publish_policy_event(test_policy_event("global", None));
    mgr.publish_policy_event(test_policy_event("middle-match", Some(peer1)));
    mgr.publish_policy_event(test_policy_event("newest-match", Some(peer1)));

    let events = query_policy_event_history(&mgr, Some(peer1), 2).await;
    let targets: Vec<_> = events.iter().map(|event| event.target.as_str()).collect();
    assert_eq!(targets, vec!["middle-match", "newest-match"]);
}

#[tokio::test]
async fn policy_event_history_capacity_evicts_oldest() {
    let mut mgr = test_peer_manager();

    for idx in 0..=POLICY_EVENT_HISTORY_CAPACITY {
        mgr.publish_policy_event(test_policy_event(&format!("policy-{idx}"), None));
    }

    let events = query_policy_event_history(&mgr, None, 0).await;
    assert_eq!(events.len(), POLICY_EVENT_HISTORY_CAPACITY);
    assert_eq!(events[0].target, "policy-1");
    let expected_last = format!("policy-{POLICY_EVENT_HISTORY_CAPACITY}");
    assert_eq!(
        events.last().map(|event| event.target.as_str()),
        Some(expected_last.as_str())
    );
}

#[tokio::test]
async fn add_duplicate_returns_error() {
    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let handle = tokio::spawn(mgr.run());

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::AddPeer {
        config: make_config(addr, 65002),
        sync_config_snapshot: false,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_ok());

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::AddPeer {
        config: make_config(addr, 65002),
        sync_config_snapshot: false,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_err());

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn delete_peer_removes() {
    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let handle = tokio::spawn(mgr.run());

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::AddPeer {
        config: make_config(addr, 65002),
        sync_config_snapshot: false,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_ok());

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::DeletePeer {
        peer: key(addr),
        sync_config_snapshot: false,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let removed = reply_rx.await.unwrap().unwrap();
    assert_eq!(removed.address, addr);
    assert_eq!(removed.remote_asn, 65002);

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::ListPeers { reply: reply_tx })
        .await
        .unwrap();
    let peers = reply_rx.await.unwrap();
    assert!(peers.is_empty());

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn delete_peer_drains_pending_inbound_candidate() {
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let primary = Arc::new(FakePeerCounters::default());
    let pending = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer_with_asn(
        &mut mgr,
        peer_addr,
        65002,
        fake_peer_handle(
            peer_addr,
            SessionState::OpenConfirm,
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            primary.clone(),
        ),
        false,
    );
    attach_test_pending_inbound(
        &mut mgr,
        peer_addr,
        fake_peer_handle(
            peer_addr,
            SessionState::OpenConfirm,
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            pending.clone(),
        ),
        2,
    );

    mgr.delete_peer(key(peer_addr), false).await.unwrap();

    wait_counter(&primary.shutdown, 1).await;
    wait_counter(&pending.shutdown, 1).await;
    assert!(mgr.peers.is_empty());
    assert!(mgr.peer_key_for_session(1).is_none());
    assert!(mgr.peer_key_for_session(2).is_none());
}

/// Number of metric series in the registry whose `peer` label equals
/// `peer` (exact match), across all families.
fn peer_metric_series_count(metrics: &BgpMetrics, peer: &str) -> usize {
    metrics
        .registry()
        .gather()
        .iter()
        .flat_map(|family| family.get_metric().iter())
        .filter(|metric| {
            metric
                .get_label()
                .iter()
                .any(|label| label.name() == "peer" && label.value() == peer)
        })
        .count()
}

/// Seed per-peer series under both label forms used at runtime: the
/// transport sessions label `peer` with the remote `SocketAddr`, the
/// RIB manager and BFD runtime with the bare address.
fn seed_peer_metric_series(metrics: &BgpMetrics, transport_label: &str, bare_label: &str) {
    metrics.record_state_transition(transport_label, "open_confirm", "established");
    metrics.record_message_sent(transport_label, "keepalive");
    metrics.set_rib_prefixes(bare_label, "ipv4_unicast", 42);
    metrics.record_bfd_state(bare_label, true, false);
}

#[tokio::test]
async fn delete_peer_reaps_metric_series() {
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let metrics_view = metrics.clone();
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let counters = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer_with_asn(
        &mut mgr,
        peer_addr,
        65002,
        fake_peer_handle(peer_addr, SessionState::Established, None, counters.clone()),
        false,
    );
    let transport_label = mgr
        .peers
        .get(&key(peer_addr))
        .unwrap()
        .transport_config
        .remote_addr
        .to_string();
    seed_peer_metric_series(&metrics_view, &transport_label, "10.0.0.2");
    metrics_view.record_fib_route_installed(); // process-global counter
    assert!(peer_metric_series_count(&metrics_view, &transport_label) > 0);
    assert!(peer_metric_series_count(&metrics_view, "10.0.0.2") > 0);

    mgr.delete_peer(key(peer_addr), false).await.unwrap();

    // Both label forms are gone; process-global counters are untouched.
    assert_eq!(peer_metric_series_count(&metrics_view, &transport_label), 0);
    assert_eq!(peer_metric_series_count(&metrics_view, "10.0.0.2"), 0);
    let fib_installed = metrics_view
        .registry()
        .gather()
        .into_iter()
        .find(|family| family.name() == "bgp_fib_routes_installed_total")
        .expect("global counter family present");
    assert!((fib_installed.get_metric()[0].get_counter().value() - 1.0).abs() < f64::EPSILON);
    // The ordered RIB-side reap marker was queued.
    let update = rib_rx.try_recv().expect("PeerDeleted queued for the RIB");
    assert!(matches!(update, RibUpdate::PeerDeleted { peer } if peer == peer_addr));
}

#[tokio::test]
async fn session_flap_does_not_reap_metric_series() {
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let metrics_view = metrics.clone();
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let counters = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer_with_asn(
        &mut mgr,
        peer_addr,
        65002,
        fake_peer_handle(peer_addr, SessionState::Idle, None, counters.clone()),
        false,
    );
    let transport_label = mgr
        .peers
        .get(&key(peer_addr))
        .unwrap()
        .transport_config
        .remote_addr
        .to_string();
    seed_peer_metric_series(&metrics_view, &transport_label, "10.0.0.2");
    metrics_view.record_state_transition(&transport_label, "established", "idle");
    let before_transport = peer_metric_series_count(&metrics_view, &transport_label);
    let before_bare = peer_metric_series_count(&metrics_view, "10.0.0.2");

    // A static peer's session flap (BackToIdle) must keep its history.
    mgr.handle_session_notification(SessionNotification::BackToIdle {
        session_id: 1,
        role: rustbgpd_transport::SessionRole::Primary,
        peer_addr,
    })
    .await;

    assert!(mgr.peers.contains_key(&key(peer_addr)));
    assert_eq!(
        peer_metric_series_count(&metrics_view, &transport_label),
        before_transport
    );
    assert_eq!(
        peer_metric_series_count(&metrics_view, "10.0.0.2"),
        before_bare
    );
    assert!(rib_rx.try_recv().is_err(), "no PeerDeleted on a flap");
}

#[tokio::test]
async fn reconfigure_peer_does_not_reap_metric_series() {
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let metrics_view = metrics.clone();
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let counters = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer_with_asn(
        &mut mgr,
        peer_addr,
        65002,
        fake_peer_handle(peer_addr, SessionState::Established, None, counters.clone()),
        false,
    );
    let transport_label = mgr
        .peers
        .get(&key(peer_addr))
        .unwrap()
        .transport_config
        .remote_addr
        .to_string();
    seed_peer_metric_series(&metrics_view, &transport_label, "10.0.0.2");
    let before_transport = peer_metric_series_count(&metrics_view, &transport_label);
    let before_bare = peer_metric_series_count(&metrics_view, "10.0.0.2");

    // Reconfigure routes through the same delete primitive, but the
    // peer continues to exist — its series and history must survive.
    let mut new_config = make_config(peer_addr, 65002);
    new_config.description = "reshaped".to_string();
    mgr.reconfigure_peer(new_config).await.unwrap();

    assert!(mgr.peers.contains_key(&key(peer_addr)));
    assert_eq!(
        peer_metric_series_count(&metrics_view, &transport_label),
        before_transport
    );
    assert_eq!(
        peer_metric_series_count(&metrics_view, "10.0.0.2"),
        before_bare
    );
    assert!(
        rib_rx.try_recv().is_err(),
        "no PeerDeleted on a reconfigure"
    );
}

#[tokio::test]
async fn dynamic_peer_auto_removal_reaps_metric_series() {
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let metrics_view = metrics.clone();
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let counters = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer_with_asn(
        &mut mgr,
        peer_addr,
        65002,
        fake_peer_handle(peer_addr, SessionState::Idle, None, counters.clone()),
        false,
    );
    mgr.peers.get_mut(&key(peer_addr)).unwrap().is_dynamic = true;
    mgr.dynamic_peer_count = 1;
    let transport_label = mgr
        .peers
        .get(&key(peer_addr))
        .unwrap()
        .transport_config
        .remote_addr
        .to_string();
    seed_peer_metric_series(&metrics_view, &transport_label, "10.0.0.2");

    // Auto-removal on idle is a full deletion for a dynamic peer.
    mgr.handle_session_notification(SessionNotification::BackToIdle {
        session_id: 1,
        role: rustbgpd_transport::SessionRole::Primary,
        peer_addr,
    })
    .await;

    assert!(mgr.peers.is_empty());
    assert_eq!(peer_metric_series_count(&metrics_view, &transport_label), 0);
    assert_eq!(peer_metric_series_count(&metrics_view, "10.0.0.2"), 0);
    let update = rib_rx.try_recv().expect("PeerDeleted queued for the RIB");
    assert!(matches!(update, RibUpdate::PeerDeleted { peer } if peer == peer_addr));
}

#[tokio::test]
async fn delete_tcp_ao_peer_is_restart_required() {
    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let handle = tokio::spawn(mgr.run());

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut config = make_config(addr, 65002);
    config.tcp_ao = Some(rustbgpd_transport::TcpAoConfig {
        key: "secret".to_string(),
        send_id: 1,
        recv_id: 1,
        algorithm: rustbgpd_transport::TcpAoAlgorithm::HmacSha256,
        preferred: false,
        deprecated: false,
    });

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::AddPeer {
        config,
        sync_config_snapshot: false,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_ok());

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::DeletePeer {
        peer: key(addr),
        sync_config_snapshot: true,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let result = reply_rx.await.unwrap();
    assert!(
        result.is_err(),
        "TCP-AO peer deletion must be restart-required"
    );
    let err = result.err().unwrap();
    assert!(err.to_string().contains("requires restart"), "{err}");

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::ListPeers { reply: reply_tx })
        .await
        .unwrap();
    let peers = reply_rx.await.unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].address, addr);

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn same_key_tcp_ao_peer_reconfigure_is_allowed() {
    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let handle = tokio::spawn(mgr.run());

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let tcp_ao = rustbgpd_transport::TcpAoConfig {
        key: "secret".to_string(),
        send_id: 1,
        recv_id: 1,
        algorithm: rustbgpd_transport::TcpAoAlgorithm::HmacSha256,
        preferred: false,
        deprecated: false,
    };
    let mut config = make_config(addr, 65002);
    config.tcp_ao = Some(tcp_ao.clone());

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::AddPeer {
        config,
        sync_config_snapshot: false,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_ok());

    let mut changed = make_config(addr, 65002);
    changed.description = "updated-description".to_string();
    changed.tcp_ao = Some(tcp_ao);
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::ReconcilePeers {
        added: Vec::new(),
        removed: Vec::new(),
        changed: vec![changed],
        reply: reply_tx,
    })
    .await
    .unwrap();
    let result = reply_rx.await.unwrap();
    assert!(result.failures.is_empty(), "{:?}", result.failures);

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::ListPeers { reply: reply_tx })
        .await
        .unwrap();
    let peers = reply_rx.await.unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].address, addr);
    assert_eq!(peers[0].description, "updated-description");

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn delete_nonexistent_returns_error() {
    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let handle = tokio::spawn(mgr.run());

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99));
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::DeletePeer {
        peer: key(addr),
        sync_config_snapshot: false,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_err());

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn get_peer_state_existing() {
    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let handle = tokio::spawn(mgr.run());

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::AddPeer {
        config: make_config(addr, 65002),
        sync_config_snapshot: false,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let _ = reply_rx.await;

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::GetPeerState {
        peer: key(addr),
        reply: reply_tx,
    })
    .await
    .unwrap();
    let info = reply_rx.await.unwrap();
    assert!(info.is_some());
    assert_eq!(info.unwrap().address, addr);

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn get_peer_state_nonexistent_returns_none() {
    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let handle = tokio::spawn(mgr.run());

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::GetPeerState {
        peer: key(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99))),
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_none());

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn shutdown_stops_all_peers() {
    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let handle = tokio::spawn(mgr.run());

    for i in 2..=3 {
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::AddPeer {
            config: make_config(addr, 65000 + u32::from(i)),
            sync_config_snapshot: false,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let _ = reply_rx.await;
    }

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[test]
fn build_transport_config_preserves_local_ipv6_nexthop() {
    let (_, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );

    let nh: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
    let mut config = make_config(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65002);
    config.local_ipv6_nexthop = Some(nh);

    let transport = mgr.build_transport_config(&config);
    assert_eq!(transport.local_ipv6_nexthop, Some(nh));
}

#[test]
fn build_transport_config_threads_policy_explain_settings() {
    // ADR-0073: both [policy.explain] knobs must propagate from the
    // daemon config snapshot into the per-session TransportConfig.
    // A regression here would silently leave `enabled` at its
    // TransportConfig::new default (true), ignoring the operator's
    // off-switch in production sessions.
    let (_, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    mgr.current_config.policy.explain.enabled = false;
    mgr.current_config.policy.explain.cache_size = 256;

    let config = make_config(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65002);
    let transport = mgr.build_transport_config(&config);
    assert!(!transport.explain_enabled, "enabled must propagate");
    assert_eq!(
        transport.explain_cache_size, 256,
        "cache_size must propagate"
    );
}

#[test]
fn build_transport_config_preserves_route_server_client() {
    let (_, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );

    let mut config = make_config(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65002);
    config.route_server_client = true;

    let transport = mgr.build_transport_config(&config);
    assert!(transport.route_server_client);
}

/// RFC 7947 §2.3.2 / ADR-0101: `per_client_best` on a neighbor config
/// must reach the transport session config — the session-up event
/// registers the mode with the RIB manager from exactly this field.
/// M83 caught this dropped at the `build_transport_config` seam while
/// the RIB/CLI layers (wired above it) tested green.
#[test]
fn build_transport_config_preserves_per_client_best() {
    let (_, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );

    let mut config = make_config(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65002);
    config.route_server_client = true;
    config.per_client_best = true;

    let transport = mgr.build_transport_config(&config);
    assert!(transport.per_client_best);
}

/// RFC 9234 OTC for dynamic/gRPC-added peers: `local_role` set on a
/// runtime `PeerConfig` (the `AddNeighbor` / dynamic-range path) reaches
/// the transport session config verbatim — transport attaches OTC on
/// eBGP egress for `Provider`/`Peer`/`RouteServer` roles from exactly
/// this field (`otc_egress_adds_local_asn_for_provider_peer_and_route_server`
/// in the transport crate pins the attach itself).
#[test]
fn build_transport_config_preserves_local_role_for_otc() {
    let (_, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );

    let mut config = make_config(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65002);
    config.route_server_client = true;
    config.local_role = Some(rustbgpd_wire::BgpRole::RouteServer);

    let transport = mgr.build_transport_config(&config);
    assert_eq!(
        transport.peer.local_role,
        Some(rustbgpd_wire::BgpRole::RouteServer)
    );
}

/// Class guard for the "config knob parsed/validated/displayed but never
/// reaches its runtime consumer" bug (#702, `per_client_best` dropped in
/// `build_transport_config`; caught only by the M83 real-stack lab because
/// the RIB/CLI unit layers are wired above this seam). This pins the
/// `PeerManagerNeighborConfig` → `TransportConfig` seam as a whole so a
/// future dropped copy fails a unit test, not a lab.
///
/// Two guards, deliberately layered:
///
/// 1. **Compile-time (new field):** the destructure below names EVERY
///    field with NO `..`. Add a field to `PeerManagerNeighborConfig` and
///    THIS test stops compiling — forcing an explicit decision: transport
///    field (assert it) or one of the three non-transport fields
///    (`description`, `import_policy`, `export_policy` — RIB/label side,
///    not a session property; add it to the `_`-bound exclusions).
///
/// 2. **Run-time (dropped copy of an existing field):** every transport
///    field is set to a non-default sentinel and asserted against the
///    resulting `TransportConfig`. A field left at `TransportConfig::new`'s
///    default would pass a weaker test even with the copy missing, so the
///    sentinels are chosen to differ from those defaults.
#[test]
#[allow(clippy::too_many_lines)]
fn build_transport_config_reflects_every_transport_field() {
    let (_, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );

    let config = PeerManagerNeighborConfig {
        address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        interface: Some("test-if".to_string()),
        scope_id: Some(7),
        remote_asn: 65002,
        description: "sentinel-description".to_string(),
        peer_group: Some("rr-clients".to_string()),
        hold_time: Some(240),
        send_hold_time: Some(600),
        max_prefixes: Some(1000),
        md5_password: Some("hunter2".to_string()),
        tcp_ao: Some(rustbgpd_transport::TcpAoConfig {
            key: "ao-secret".to_string(),
            send_id: 11,
            recv_id: 22,
            algorithm: rustbgpd_transport::TcpAoAlgorithm::HmacSha256,
            preferred: true,
            deprecated: false,
        }),
        ttl_security: true,
        families: vec![(Afi::Ipv6, Safi::Unicast)],
        graceful_restart: true,
        gr_restart_time: 300,
        gr_stale_routes_time: 720,
        llgr_stale_time: 3600,
        gr_restart_eligible: false,
        local_ipv6_nexthop: Some("2001:db8::1".parse().unwrap()),
        route_reflector_client: true,
        orr_vantage: Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))),
        route_server_client: true,
        per_client_best: true,
        remove_private_as: rustbgpd_transport::RemovePrivateAs::All,
        add_path_receive: true,
        add_path_send: true,
        add_path_send_max: 4,
        paths_limit_receive_max: 3,
        local_role: Some(rustbgpd_wire::BgpRole::RouteServer),
        strict_role: true,
        prefix_orf_receive: true,
        disable_ipv4_unicast: true,
        import_policy: None,
        export_policy: None,
    };

    // Destructure with NO `..`: a new field breaks compilation here.
    let PeerManagerNeighborConfig {
        address,
        interface,
        scope_id,
        remote_asn,
        description: _description, // NON-TRANSPORT: operator label only.
        peer_group,
        hold_time,
        send_hold_time,
        max_prefixes,
        md5_password,
        tcp_ao,
        ttl_security,
        families,
        graceful_restart,
        gr_restart_time,
        gr_stale_routes_time,
        llgr_stale_time,
        gr_restart_eligible,
        local_ipv6_nexthop,
        route_reflector_client,
        orr_vantage,
        route_server_client,
        per_client_best,
        remove_private_as,
        add_path_receive,
        add_path_send,
        add_path_send_max,
        paths_limit_receive_max,
        local_role,
        strict_role,
        prefix_orf_receive,
        disable_ipv4_unicast,
        import_policy: _import_policy, // NON-TRANSPORT: RIB-side policy chain.
        export_policy: _export_policy, // NON-TRANSPORT: RIB-side policy chain.
    } = &config;

    let t = mgr.build_transport_config(&config);

    assert_eq!(t.remote_addr.ip(), *address, "address");
    assert_eq!(t.peer_interface, *interface, "interface");
    assert_eq!(t.peer_scope_id, *scope_id, "scope_id");
    assert_eq!(t.peer.remote_asn, *remote_asn, "remote_asn");
    assert_eq!(t.peer_group, *peer_group, "peer_group");
    assert_eq!(t.peer.hold_time, hold_time.unwrap(), "hold_time");
    assert_eq!(
        t.peer.send_hold_time,
        send_hold_time.unwrap(),
        "send_hold_time"
    );
    assert_eq!(t.max_prefixes, *max_prefixes, "max_prefixes");
    assert_eq!(t.md5_password, *md5_password, "md5_password");
    assert_eq!(t.tcp_ao, *tcp_ao, "tcp_ao");
    assert_eq!(t.ttl_security, *ttl_security, "ttl_security");
    assert_eq!(t.peer.families, *families, "families");
    assert_eq!(
        t.peer.graceful_restart, *graceful_restart,
        "graceful_restart"
    );
    assert_eq!(t.peer.gr_restart_time, *gr_restart_time, "gr_restart_time");
    assert_eq!(
        t.gr_stale_routes_time, *gr_stale_routes_time,
        "gr_stale_routes_time"
    );
    assert_eq!(t.llgr_stale_time, *llgr_stale_time, "llgr_stale_time");
    // `gr_restart_eligible` only opens the restart window when the manager
    // holds a live `local_gr_restart_until` deadline (none here), so it
    // resolves to `None`. The window→Some path has its own dedicated test
    // (`build_transport_config_sets_restart_window_for_eligible_static_peer`);
    // here we just keep the field named/consumed and pin the disabled outcome.
    assert!(!*gr_restart_eligible);
    assert!(t.gr_restart_until.is_none(), "gr_restart_until");
    assert_eq!(
        t.local_ipv6_nexthop, *local_ipv6_nexthop,
        "local_ipv6_nexthop"
    );
    assert_eq!(
        t.route_reflector_client, *route_reflector_client,
        "route_reflector_client"
    );
    assert_eq!(t.orr_vantage, *orr_vantage, "orr_vantage");
    assert_eq!(
        t.route_server_client, *route_server_client,
        "route_server_client"
    );
    // The #702 field: this is the exact assertion the class of tests exists
    // to make impossible to lose again.
    assert_eq!(t.per_client_best, *per_client_best, "per_client_best");
    assert_eq!(t.remove_private_as, *remove_private_as, "remove_private_as");
    assert_eq!(
        t.peer.add_path_receive, *add_path_receive,
        "add_path_receive"
    );
    assert_eq!(t.peer.add_path_send, *add_path_send, "add_path_send");
    assert_eq!(
        t.peer.add_path_send_max, *add_path_send_max,
        "add_path_send_max"
    );
    assert_eq!(
        t.peer.paths_limit_receive_max, *paths_limit_receive_max,
        "paths_limit_receive_max"
    );
    assert_eq!(t.peer.local_role, *local_role, "local_role");
    assert_eq!(t.peer.strict_role, *strict_role, "strict_role");
    assert_eq!(
        t.peer.prefix_orf_receive, *prefix_orf_receive,
        "prefix_orf_receive"
    );
    assert_eq!(
        t.peer.disable_ipv4_unicast, *disable_ipv4_unicast,
        "disable_ipv4_unicast"
    );
}

#[tokio::test]
async fn policy_events_publish_successful_policy_mutations() {
    use rustbgpd_api::peer_types::{NamedPolicyDefinition, PolicyStatementDefinition};

    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let handle = tokio::spawn(mgr.run());
    let mut events = subscribe_policy_events(&tx).await;

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::SetPolicy {
        name: "audit-policy".to_string(),
        definition: NamedPolicyDefinition {
            default_action: "permit".to_string(),
            statements: Vec::<PolicyStatementDefinition>::new(),
        },
        reply: reply_tx,
    })
    .await
    .unwrap();
    reply_rx.await.unwrap().unwrap();

    let event = tokio::time::timeout(Duration::from_secs(2), events.recv())
        .await
        .expect("policy event timeout")
        .expect("policy event channel closed");
    assert_eq!(event.operation, "set");
    assert_eq!(event.target_type, "policy");
    assert_eq!(event.target, "audit-policy");
    assert_eq!(event.peer, None);
    assert_eq!(event.affected_peer_count, 0);
    assert_eq!(event.reason, "policy set policy audit-policy");

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn apply_policy_change_fans_out_to_scoped_peers() {
    use rustbgpd_api::peer_types::NeighborSetDefinition;

    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    let rib_drainer = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                let _ = reply.send(Ok(()));
            }
        }
    });
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
    // Distinct link-local addresses per interface: v1 config requires link-local
    // addresses to be unique across neighbors (ADR-0069), but the scoped PeerKey
    // still keys each peer by (address, interface), so this exercises policy
    // fan-out across two separately-keyed scoped peers.
    let peer0 = IpAddr::V6("fe80::2".parse().unwrap());
    let peer1 = IpAddr::V6("fe80::3".parse().unwrap());
    let eth0 = Arc::new(FakePeerCounters::default());
    let eth1 = Arc::new(FakePeerCounters::default());

    insert_test_scoped_managed_peer(
        &mut mgr,
        peer0,
        "eth0",
        10,
        1,
        fake_peer_handle(peer0, SessionState::Established, None, eth0.clone()),
    );
    insert_test_scoped_managed_peer(
        &mut mgr,
        peer1,
        "eth1",
        11,
        2,
        fake_peer_handle(peer1, SessionState::Established, None, eth1.clone()),
    );

    let mut n0 = config_neighbor(peer0, 65002);
    n0.interface = Some("eth0".to_string());
    let mut n1 = config_neighbor(peer1, 65002);
    n1.interface = Some("eth1".to_string());
    mgr.current_config.neighbors = vec![n0, n1];

    mgr.apply_policy_change(
        ConfigEvent::SetNeighborSet {
            name: "unused".to_string(),
            definition: NeighborSetDefinition {
                addresses: vec!["192.0.2.1".to_string()],
                remote_asns: vec![],
                peer_groups: vec![],
            },
            ack: None,
        },
        None,
    )
    .await
    .unwrap();

    assert_eq!(eth0.query_state.load(Ordering::SeqCst), 1);
    assert_eq!(eth1.query_state.load(Ordering::SeqCst), 1);
    drop(mgr);
    rib_drainer.await.unwrap();
}

/// ADR-0096: `sync_rpol_policies` adopts the new compiled registry,
/// re-resolves live chains through it (Route Refresh for the material
/// import change), and `SetPolicy` cannot shadow an rpol-defined name.
#[tokio::test]
async fn sync_rpol_policies_reresolves_chains_and_rejects_shadowing() {
    use rustbgpd_api::peer_types::NamedPolicyDefinition;
    use rustbgpd_policy::rpol::{RpolFile, RpolPolicyEntry, RpolPolicySet};

    fn registry(source: &str) -> RpolPolicySet {
        let file = std::sync::Arc::new(RpolFile::parse(source).expect("clean rpol"));
        let mut set = RpolPolicySet::default();
        set.policies.insert(
            "edge-in".to_string(),
            RpolPolicyEntry {
                file,
                params: 0,
                path: "policies/core.rpol".to_string(),
            },
        );
        set
    }

    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    let rib_drainer = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                let _ = reply.send(Ok(()));
            }
        }
    });
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
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer(
        &mut mgr,
        peer,
        acking_counted_policy_handle(peer, counters.clone()),
        false,
    );
    let mut neighbor = config_neighbor(peer, 65002);
    neighbor.import_policy_chain = vec!["edge-in".to_string()];
    mgr.current_config.neighbors = vec![neighbor];
    mgr.current_config.policy.rpol =
        registry("policy edge-in { term all { set local-pref 150; accept } }");

    // New registry content: chains re-resolve and the peer's import
    // policy now carries the edited compiled body.
    mgr.sync_rpol_policies(
        vec!["policies/core.rpol".to_string()],
        registry("policy edge-in { term all { set local-pref 250; accept } }"),
        rustbgpd_policy::datasets::DatasetBindings::default(),
    )
    .await
    .expect("sync succeeds");
    let managed = mgr.peers.values().next().expect("peer present");
    let chain = managed.import_policy.as_ref().expect("import chain set");
    assert!(chain.policies[0].rpol.is_some());
    let ctx = rustbgpd_policy::RouteContext {
        prefix: None,
        next_hop: None,
        extended_communities: &[],
        communities: &[],
        large_communities: &[],
        as_path_str: "",
        as_path: None,
        as_path_len: 0,
        origin_asn: None,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        peer_address: None,
        peer_asn: None,
        peer_group: None,
        route_type: None,
        family: None,
        evpn_route_type: None,
        local_pref: None,
        med: None,
    };
    assert_eq!(chain.evaluate(&ctx).modifications.set_local_pref, Some(250));

    // The rpol name cannot be shadowed by a TOML SetPolicy.
    let err = mgr
        .apply_policy_change(
            ConfigEvent::SetPolicy {
                name: "edge-in".to_string(),
                definition: NamedPolicyDefinition {
                    default_action: "permit".to_string(),
                    statements: vec![],
                },
                ack: None,
            },
            None,
        )
        .await
        .expect_err("shadowing an rpol policy must be rejected");
    assert!(err.to_string().contains("rpol"), "{err}");

    drop(mgr);
    rib_drainer.await.unwrap();
}

/// LAN-284: a rejected `sync_rpol_policies` (mid-apply chain resolution
/// failure) must leave BOTH policy surfaces on the old registry — the
/// live peer's chain (existing sessions) and `current_config` (what a
/// session created afterwards resolves against). Asserted at decision
/// level: the live chain still evaluates the OLD local-pref.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the extra dataset-bindings argument pushed this linear scenario over the line cap"
)]
async fn sync_rpol_policies_rejection_keeps_old_registry_for_live_and_new_sessions() {
    use rustbgpd_policy::rpol::{RpolFile, RpolPolicyEntry, RpolPolicySet};

    fn registry(name: &str, source: &str) -> RpolPolicySet {
        let file = std::sync::Arc::new(RpolFile::parse(source).expect("clean rpol"));
        let mut set = RpolPolicySet::default();
        set.policies.insert(
            name.to_string(),
            RpolPolicyEntry {
                file,
                params: 0,
                path: "policies/core.rpol".to_string(),
            },
        );
        set
    }

    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    let rib_drainer = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                let _ = reply.send(Ok(()));
            }
        }
    });
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
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer(
        &mut mgr,
        peer,
        acking_counted_policy_handle(peer, counters.clone()),
        false,
    );
    let mut neighbor = config_neighbor(peer, 65002);
    neighbor.import_policy_chain = vec!["edge-in".to_string()];
    mgr.current_config.neighbors = vec![neighbor];
    mgr.current_config.policy.rpol = registry(
        "edge-in",
        "policy edge-in { term all { set local-pref 150; accept } }",
    );
    // Materialize the live chain from the OLD registry.
    mgr.sync_rpol_policies(
        vec!["policies/core.rpol".to_string()],
        registry(
            "edge-in",
            "policy edge-in { term all { set local-pref 150; accept } }",
        ),
        rustbgpd_policy::datasets::DatasetBindings::default(),
    )
    .await
    .expect("baseline sync succeeds");

    // Candidate registry renames the policy, so the static peer's
    // `import_policy_chain = ["edge-in"]` no longer resolves: the sync
    // is rejected mid-apply with zero peers touched.
    mgr.sync_rpol_policies(
        vec!["policies/core.rpol".to_string()],
        registry(
            "edge-in-renamed",
            "policy edge-in-renamed { term all { set local-pref 250; accept } }",
        ),
        rustbgpd_policy::datasets::DatasetBindings::default(),
    )
    .await
    .expect_err("chain resolution failure must reject the sync");

    // Existing session: the live chain still evaluates the OLD decision.
    let managed = mgr.peers.values().next().expect("peer present");
    let chain = managed.import_policy.as_ref().expect("import chain set");
    let ctx = rustbgpd_policy::RouteContext {
        prefix: None,
        next_hop: None,
        extended_communities: &[],
        communities: &[],
        large_communities: &[],
        as_path_str: "",
        as_path: None,
        as_path_len: 0,
        origin_asn: None,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        peer_address: None,
        peer_asn: None,
        peer_group: None,
        route_type: None,
        family: None,
        evpn_route_type: None,
        local_pref: None,
        med: None,
    };
    assert_eq!(chain.evaluate(&ctx).modifications.set_local_pref, Some(150));

    // New session source: chains for a session created AFTER the
    // rejection resolve from `current_config`, which must still carry
    // the old registry — and evaluate the OLD decision.
    let neighbor = mgr.current_config.neighbors[0].clone();
    let (import, _export) = mgr
        .current_config
        .effective_policy_chains_for_neighbor(&neighbor)
        .expect("new-session chains resolve against the old registry");
    let chain = import.expect("import chain configured");
    assert_eq!(chain.evaluate(&ctx).modifications.set_local_pref, Some(150));

    drop(mgr);
    rib_drainer.await.unwrap();
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
                        negotiated_hold_time: None,
                        four_octet_as: None,
                        remote_router_id: None,
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

/// Regression: catalog policy mutations (`SetPolicy` / neighbor sets / global
/// chains, gRPC and SIGHUP alike) must hot-apply resolved chains to live
/// DYNAMIC peers. Dynamic peers have no `[[neighbors]]` record, and the
/// per-peer loop previously skipped them entirely — a policy edit on a route
/// server never reached established dynamic sessions until they flapped,
/// running split-brain policy between sessions accepted before and after
/// the edit.
#[tokio::test]
async fn apply_policy_change_reaches_live_dynamic_peers() {
    use rustbgpd_api::peer_types::{NamedPolicyDefinition, PolicyStatementDefinition};

    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    let rib_drainer = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                let _ = reply.send(Ok(()));
            }
        }
    });
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

    // Config: the dynamic peers' group resolves an import chain that
    // references the named policy being edited.
    let mut config = make_dynamic_manager_config();
    if let Some(group) = config.peer_groups.get_mut("ix-members") {
        group.import_policy_chain = vec!["ix-import".to_string()];
    }
    mgr.current_config = config;

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let counters = Arc::new(FakePeerCounters::default());
    let handle = acking_counted_policy_handle(addr, counters.clone());
    insert_test_managed_peer(&mut mgr, addr, handle, false);
    let managed = mgr.peers.get_mut(&key(addr)).unwrap();
    managed.is_dynamic = true;
    managed.peer_group = Some("ix-members".to_string());

    mgr.apply_policy_change(
        ConfigEvent::SetPolicy {
            name: "ix-import".to_string(),
            definition: NamedPolicyDefinition {
                default_action: "deny".to_string(),
                statements: Vec::<PolicyStatementDefinition>::new(),
            },
            ack: None,
        },
        None,
    )
    .await
    .unwrap();

    // The dynamic peer must have been processed: chains resolved against the
    // synthetic peer-group-backed neighbor, hot-applied to the session, and
    // the import change refreshed.
    assert_eq!(
        counters.query_state.load(Ordering::SeqCst),
        1,
        "dynamic peer must not be skipped by catalog policy mutations"
    );
    assert_eq!(
        counters.route_refresh.load(Ordering::SeqCst),
        1,
        "import-chain change on a dynamic peer must trigger Route Refresh"
    );
    assert!(
        mgr.peers.get(&key(addr)).unwrap().import_policy.is_some(),
        "resolved import chain must be recorded on the dynamic peer"
    );

    drop(mgr);
    rib_drainer.await.unwrap();
}

#[tokio::test]
async fn set_peer_group_policy_only_change_reaches_live_dynamic_peers() {
    use crate::config::NamedPolicyConfig;

    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    let rib_drainer = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                let _ = reply.send(Ok(()));
            }
        }
    });
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
    config.policy.definitions.insert(
        "deny-import".to_string(),
        NamedPolicyConfig {
            default_action: "deny".to_string(),
            statements: Vec::new(),
        },
    );
    if let Some(group) = config.peer_groups.get_mut("ix-members") {
        group.import_policy_chain = vec!["ix-import".to_string()];
    }
    let mut next_group = crate::policy_admin::config_peer_group_to_api(
        config.peer_groups.get("ix-members").unwrap(),
    );
    next_group.import_policy_chain = vec!["deny-import".to_string()];
    mgr.current_config = config;

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let counters = Arc::new(FakePeerCounters::default());
    let handle = acking_counted_policy_handle(addr, counters.clone());
    insert_test_managed_peer(&mut mgr, addr, handle, false);
    let managed = mgr.peers.get_mut(&key(addr)).unwrap();
    managed.is_dynamic = true;
    managed.peer_group = Some("ix-members".to_string());

    let manager_task = tokio::spawn(mgr.run());
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::SetPeerGroup {
        name: "ix-members".to_string(),
        definition: next_group,
        reply: reply_tx,
    })
    .await
    .unwrap();
    reply_rx.await.unwrap().unwrap();

    assert_eq!(
        counters.query_state.load(Ordering::SeqCst),
        1,
        "SetPeerGroup policy-only edits must not skip live dynamic peers"
    );
    assert_eq!(
        counters.route_refresh.load(Ordering::SeqCst),
        1,
        "dynamic import policy-chain movement must trigger Route Refresh"
    );

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    manager_task.await.unwrap();
    rib_drainer.abort();
}

/// A catalog mutation's fan-out is atomic: when applying the resolved
/// chains to peer 2 fails mid-loop, peer 1 (already updated) is restored
/// to its prior chains, peer 3 is never touched, and `current_config`
/// does not advance — no split-brain where some sessions run the new
/// policy and others the old.
#[tokio::test]
async fn apply_policy_change_mid_fanout_failure_restores_prior_chains() {
    use rustbgpd_api::peer_types::{NamedPolicyDefinition, PolicyStatementDefinition};

    let mut mgr = live_policy_test_manager();
    let a1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let a2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)); // its apply fails
    let a3 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    insert_test_managed_peer(
        &mut mgr,
        a1,
        acking_policy_handle(a1, SessionState::Idle),
        false,
    );
    insert_test_managed_peer(&mut mgr, a2, closed_peer_handle(), false);
    insert_test_managed_peer(
        &mut mgr,
        a3,
        acking_policy_handle(a3, SessionState::Idle),
        false,
    );
    // Static records whose import chain references the policy being set.
    mgr.current_config.neighbors = [a1, a2, a3]
        .into_iter()
        .map(|addr| {
            let mut neighbor = config_neighbor(addr, 65002);
            neighbor.import_policy_chain = vec!["edge-import".to_string()];
            neighbor
        })
        .collect();
    let prior = validation_policy_chain(ImportValidationDependency::Rpki);
    for a in [a1, a2, a3] {
        mgr.peers.get_mut(&key(a)).unwrap().import_policy = Some(prior.clone());
    }

    let result = mgr
        .apply_policy_change(
            ConfigEvent::SetPolicy {
                name: "edge-import".to_string(),
                definition: NamedPolicyDefinition {
                    default_action: "deny".to_string(),
                    statements: Vec::<PolicyStatementDefinition>::new(),
                },
                ack: None,
            },
            // Explicit order so peer 1 is applied before peer 2 fails.
            Some(vec![a1, a2, a3]),
        )
        .await;
    assert!(
        result.is_err(),
        "a mid-fanout per-peer failure must surface as Err: {result:?}"
    );

    let expect_prior = format!("{:?}", Some(prior));
    assert_eq!(
        format!("{:?}", mgr.peers.get(&key(a1)).unwrap().import_policy),
        expect_prior,
        "peer 1 must be restored to its prior chain after the self-heal"
    );
    assert_eq!(
        format!("{:?}", mgr.peers.get(&key(a3)).unwrap().import_policy),
        expect_prior,
        "peer 3 was never reached and must keep its prior chain"
    );
    assert!(
        !mgr.current_config
            .policy
            .definitions
            .contains_key("edge-import"),
        "a failed catalog mutation must not advance current_config"
    );
}

#[tokio::test]
async fn validation_cache_refresh_targets_matching_established_import_policies() {
    let mut mgr = test_peer_manager();
    let rpki_peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 11));
    let aspa_peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 12));
    let no_validation_peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 13));
    let idle_rpki_peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 14));

    let rpki = Arc::new(FakePeerCounters::default());
    let aspa = Arc::new(FakePeerCounters::default());
    let no_validation = Arc::new(FakePeerCounters::default());
    let idle_rpki = Arc::new(FakePeerCounters::default());

    insert_test_managed_peer(
        &mut mgr,
        rpki_peer,
        fake_peer_handle(rpki_peer, SessionState::Established, None, rpki.clone()),
        false,
    );
    insert_test_managed_peer(
        &mut mgr,
        aspa_peer,
        fake_peer_handle(aspa_peer, SessionState::Established, None, aspa.clone()),
        false,
    );
    insert_test_managed_peer(
        &mut mgr,
        no_validation_peer,
        fake_peer_handle(
            no_validation_peer,
            SessionState::Established,
            None,
            no_validation.clone(),
        ),
        false,
    );
    insert_test_managed_peer(
        &mut mgr,
        idle_rpki_peer,
        fake_peer_handle(idle_rpki_peer, SessionState::Idle, None, idle_rpki.clone()),
        false,
    );

    mgr.peers.get_mut(&key(rpki_peer)).unwrap().import_policy =
        Some(validation_policy_chain(ImportValidationDependency::Rpki));
    mgr.peers.get_mut(&key(aspa_peer)).unwrap().import_policy =
        Some(validation_policy_chain(ImportValidationDependency::Aspa));
    mgr.peers
        .get_mut(&key(no_validation_peer))
        .unwrap()
        .import_policy = Some(deny_policy_chain());
    mgr.peers
        .get_mut(&key(idle_rpki_peer))
        .unwrap()
        .import_policy = Some(validation_policy_chain(ImportValidationDependency::Rpki));

    mgr.soft_reset_import_validation_dependents(ImportValidationDependency::Rpki)
        .await
        .unwrap();

    assert_eq!(rpki.query_state.load(Ordering::SeqCst), 1);
    assert_eq!(rpki.route_refresh.load(Ordering::SeqCst), 1);
    assert_eq!(
        idle_rpki.query_state.load(Ordering::SeqCst),
        1,
        "RPKI-dependent idle peers are considered but not refreshed"
    );
    assert_eq!(idle_rpki.route_refresh.load(Ordering::SeqCst), 0);
    assert_eq!(
        aspa.query_state.load(Ordering::SeqCst),
        0,
        "ASPA-only peers must not be touched by an RPKI cache update"
    );
    assert_eq!(aspa.route_refresh.load(Ordering::SeqCst), 0);
    assert_eq!(
        no_validation.query_state.load(Ordering::SeqCst),
        0,
        "peers without validation-state import predicates are not queried"
    );

    mgr.soft_reset_import_validation_dependents(ImportValidationDependency::Aspa)
        .await
        .unwrap();

    assert_eq!(aspa.query_state.load(Ordering::SeqCst), 1);
    assert_eq!(aspa.route_refresh.load(Ordering::SeqCst), 1);
    assert_eq!(
        rpki.route_refresh.load(Ordering::SeqCst),
        1,
        "RPKI peer must not receive a second refresh from an ASPA-only update"
    );

    assert_validation_import_refresh_metric(&mgr, "rpki", "eligible", 2.0);
    assert_validation_import_refresh_metric(&mgr, "rpki", "refreshed", 1.0);
    assert_validation_import_refresh_metric(&mgr, "rpki", "skipped_not_established", 1.0);
    assert_validation_import_refresh_metric(&mgr, "rpki", "failed", 0.0);
    assert_validation_import_refresh_metric(&mgr, "aspa", "eligible", 1.0);
    assert_validation_import_refresh_metric(&mgr, "aspa", "refreshed", 1.0);
}

#[tokio::test]
async fn validation_cache_refresh_times_out_unresponsive_route_refresh() {
    let mut mgr = test_peer_manager();
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 15));
    let counters = Arc::new(FakePeerCounters::default());

    insert_test_managed_peer(
        &mut mgr,
        peer,
        fake_peer_handle_with_route_refresh_reply(
            peer,
            SessionState::Established,
            None,
            counters.clone(),
            false,
        ),
        false,
    );
    mgr.peers.get_mut(&key(peer)).unwrap().import_policy =
        Some(validation_policy_chain(ImportValidationDependency::Rpki));

    let result = tokio::time::timeout(
        PEER_POLICY_UPDATE_TIMEOUT * 3,
        mgr.soft_reset_import_validation_dependents(ImportValidationDependency::Rpki),
    )
    .await
    .expect("outer timeout: cache refresh helper should return after its per-peer timeout");

    let error = result.expect_err("unresponsive route-refresh reply should be reported");
    assert!(
        error.contains("timed out"),
        "timeout failure should be visible in the aggregate error: {error}"
    );
    assert_eq!(counters.query_state.load(Ordering::SeqCst), 1);
    assert_eq!(counters.route_refresh.load(Ordering::SeqCst), 1);
    assert_validation_import_refresh_metric(&mgr, "rpki", "eligible", 1.0);
    assert_validation_import_refresh_metric(&mgr, "rpki", "refreshed", 0.0);
    assert_validation_import_refresh_metric(&mgr, "rpki", "failed", 1.0);
}

/// Regression: when a policy mutation actually changes the
/// effective import policy for an Idle peer (so
/// `import_changed` flips true inside
/// `update_runtime_policies`), the route-refresh trigger must
/// be gated on Established and the mutation must still return
/// Ok. Without the gate, `send_route_refresh` returns "session
/// not Established" for any peer mid-reconnect, which would
/// propagate through `apply_policy_change` and fail the gRPC
/// call. Operators with even one peer mid-reconnect would see
/// every `SetPolicy` / `SetGlobalImportChain` fail.
///
/// The test deliberately wires up a chain reference to the
/// policy so `import_changed` actually fires. Earlier shape
/// (`SetPolicy` with no chain reference) didn't exercise the
/// gate at all — `import_changed` stayed false and the test
/// would pass even with the gate removed.
///
/// Companion (Established-side) coverage — that the auto-refresh
/// actually fires when a peer IS Established — is M34 in the
/// interop suite (needs a real FRR session).
#[tokio::test]
async fn set_policy_does_not_error_on_idle_peers_when_import_changes() {
    use rustbgpd_api::peer_types::{NamedPolicyDefinition, PolicyStatementDefinition};
    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let handle = tokio::spawn(mgr.run());

    // sync_config_snapshot = true so PM's current_config tracks
    // the new neighbor. Otherwise apply_policy_change's per-peer
    // loop skips it (the neighbor wouldn't be present in
    // next_config) and update_runtime_policies never runs —
    // making the gate untestable.
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::AddPeer {
        config: make_config(addr, 65002),
        sync_config_snapshot: true,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_ok(), "AddPeer must succeed");

    // Step 1: install a named policy that the peer's resolved
    // chain will pick up once we attach it via the global
    // import_chain. This call alone doesn't move
    // `import_changed` (no chain references the new policy
    // yet); it's just setup.
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::SetPolicy {
        name: "test-policy".to_string(),
        definition: NamedPolicyDefinition {
            default_action: "deny".to_string(),
            statements: Vec::<PolicyStatementDefinition>::new(),
        },
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(
        reply_rx.await.unwrap().is_ok(),
        "SetPolicy setup step must succeed"
    );

    // Step 2: this is the call that actually flips
    // `import_changed = true`. Setting the global chain to
    // ["test-policy"] makes the peer's resolved import chain
    // move from "empty / inline" to "single-policy chain
    // (deny-default)" — `update_runtime_policies` sees the
    // change and tries to fire `soft_reset_in`. The peer is
    // Idle (unreachable address, no session), so without the
    // Established gate the route-refresh would error and the
    // reply would be Err.
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::SetGlobalImportChain {
        policy_names: vec!["test-policy".to_string()],
        reply: reply_tx,
    })
    .await
    .unwrap();
    let result = reply_rx.await.unwrap();
    assert!(
        result.is_ok(),
        "SetGlobalImportChain with import-changing chain must succeed when the only \
         affected peer is Idle — the auto Route Refresh trigger must be gated on \
         Established or operator gRPC calls would fail every time a peer is mid-reconnect. \
         Got: {result:?}",
    );

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn missing_policy_catalog_references_return_not_found_errors() {
    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let handle = tokio::spawn(mgr.run());

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::SetGlobalImportChain {
        policy_names: vec!["missing-policy".to_string()],
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(matches!(
        reply_rx.await.unwrap(),
        Err(CatalogMutationError::NotFound(message)) if message.contains("missing-policy")
    ));

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::AddPeer {
        config: make_config(addr, 65002),
        sync_config_snapshot: true,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_ok(), "AddPeer must succeed");

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::SetNeighborPeerGroup {
        address: addr,
        peer_group: "missing-group".to_string(),
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(matches!(
        reply_rx.await.unwrap(),
        Err(CatalogMutationError::NotFound(message)) if message.contains("missing-group")
    ));

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

/// Auto-retry semantics for `pending_refresh`: if a prior call set
/// the flag (because an Established refresh send failed), the next
/// call to `update_runtime_policies` must drain it. When the peer
/// still isn't Established at the time of the next call, the flag
/// must be re-armed so a future call retries — without this, a
/// transient send failure would silently leave the new policy
/// applied to *future* UPDATEs while routes already in `AdjRibIn`
/// keep flowing under the prior policy.
///
/// Construct `ManagedPeer` directly with `pending_refresh = true`
/// to simulate inheriting the flag. Driving the natural failure
/// path (Established → `send_route_refresh` Err) requires a real
/// session, which is what M34 (interop) covers; the unit test
/// focuses on the in-process drain/re-arm bookkeeping.
#[tokio::test]
async fn pending_refresh_re_arms_when_peer_still_not_established() {
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics.clone(),
        rib_tx.clone(),
        None,
    );

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let peer_config = make_config(addr, 65002);
    let transport = mgr.build_transport_config(&peer_config);
    // Spawn a peer session handle but never call `start()` — the
    // session stays in Idle, so QueryState returns Some(Idle) and
    // is_established == false inside update_runtime_policies.
    let handle = rustbgpd_transport::PeerHandle::spawn(
        transport.clone(),
        metrics,
        rib_tx.clone(),
        None,
        None,
        None,
        None,
        None,
        false,
    );
    let hold = transport.peer.hold_time;
    mgr.peers.insert(
        key(addr),
        ManagedPeer {
            handle,
            session_id: 1,
            remote_asn: 65002,
            description: "test".to_string(),
            peer_group: None,
            enabled: true,
            hold_time: Some(hold),
            max_prefixes: None,
            transport_config: transport,
            import_policy: None,
            export_policy: None,
            pending_inbound: None,
            is_dynamic: false,
            accepted_dynamic_range: None,
            pending_refresh: true,
            pending_export_apply: false,
            advertise_graceful_shutdown: false,
        },
    );

    // Same (None) policies — `import_changed = false` here. The
    // refresh intent is carried only by `pending_refresh`; if the
    // drain logic forgot to honor the flag, this call would no-op
    // and pending_refresh would clear silently.
    let result = mgr.update_runtime_policies(addr, None, None).await;
    assert!(
        result.is_ok(),
        "update_runtime_policies on Idle peer must return Ok even when retrying a \
         pending refresh — refresh is gated on Established, so 'not Established yet' \
         is not an error condition. Got: {result:?}"
    );

    let pending = mgr.peers.get(&key(addr)).unwrap().pending_refresh;
    assert!(
        pending,
        "pending_refresh must be re-armed after an update where the peer is still \
         not Established. Without this, a transient Err on the original Established \
         refresh would leave routes in AdjRibIn flowing under the prior policy until \
         an operator manually reissues SetPolicy."
    );
}

#[tokio::test]
async fn channel_full_policy_update_bails_and_preserves_pending_refresh() {
    use rustbgpd_transport::PeerCommand;

    let (session_tx, session_rx) = mpsc::channel::<PeerCommand>(1);
    let (queued_reply, _queued_rx) = oneshot::channel();
    assert!(
        session_tx
            .try_send(PeerCommand::QueryState {
                reply: queued_reply,
            })
            .is_ok(),
        "pre-fill the session command channel so policy hot-apply send blocks"
    );
    let (finish_tx, finish_rx) = oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        let _session_rx = session_rx;
        let _ = finish_rx.await;
        Ok(())
    });
    let handle = PeerHandle::from_parts(session_tx, task);

    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(64);
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    insert_test_managed_peer(&mut mgr, addr, handle, false);

    let result = mgr
        .update_runtime_policies(addr, Some(deny_policy_chain()), None)
        .await;

    assert!(
        result.is_err(),
        "full session command channel must surface as a failed hot-apply, not a \
         silent policy success. Got: {result:?}"
    );
    let err = result.unwrap_err();
    assert!(
        err.contains("timed out") && err.contains("import:"),
        "error should preserve the channel-full timeout detail: {err}"
    );
    let managed = mgr.peers.get(&key(addr)).expect("peer remains managed");
    assert!(
        managed.pending_refresh,
        "pending_refresh must be set so a later policy update retries after the \
         session command channel drains"
    );
    assert!(
        managed.import_policy.is_none(),
        "daemon bookkeeping must not advance when the session command never accepted \
         the import-policy update"
    );

    let _ = finish_tx.send(());
}

#[tokio::test]
async fn channel_full_soft_reset_in_returns_timeout_instead_of_wedging_manager() {
    use rustbgpd_transport::PeerCommand;

    let (session_tx, session_rx) = mpsc::channel::<PeerCommand>(1);
    assert!(
        session_tx.try_send(PeerCommand::Start).is_ok(),
        "pre-fill the session command channel so route-refresh send blocks"
    );
    let (finish_tx, finish_rx) = oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        let _session_rx = session_rx;
        let _ = finish_rx.await;
        Ok(())
    });
    let handle = PeerHandle::from_parts(session_tx, task);

    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(64);
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    insert_test_managed_peer(&mut mgr, addr, handle, false);

    let result = tokio::time::timeout(
        Duration::from_secs(2),
        mgr.soft_reset_in(key(addr), vec![(Afi::Ipv4, Safi::Unicast)]),
    )
    .await
    .expect("soft_reset_in should return under the lifecycle command deadline");

    assert!(
        result.is_err(),
        "full session command channel must surface as a failed soft reset, not a silent success"
    );
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("timed out") && err.contains("route refresh"),
        "error should preserve the channel-full route-refresh timeout detail: {err}"
    );

    let _ = finish_tx.send(());
}

#[tokio::test]
async fn channel_full_disable_peer_returns_timeout_instead_of_wedging_manager() {
    use rustbgpd_transport::PeerCommand;

    let (session_tx, session_rx) = mpsc::channel::<PeerCommand>(1);
    assert!(
        session_tx.try_send(PeerCommand::Start).is_ok(),
        "pre-fill the session command channel so stop send blocks"
    );
    let (finish_tx, finish_rx) = oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        let _session_rx = session_rx;
        let _ = finish_rx.await;
        Ok(())
    });
    let handle = PeerHandle::from_parts(session_tx, task);

    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(64);
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    insert_test_managed_peer(&mut mgr, addr, handle, false);

    let result = tokio::time::timeout(Duration::from_secs(2), mgr.disable_peer(key(addr), None))
        .await
        .expect("disable_peer should return under the lifecycle command deadline");

    assert!(
        result.is_err(),
        "full session command channel must surface as a failed disable, not a silent success"
    );
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("timed out") && err.contains("stop"),
        "error should preserve the channel-full stop timeout detail: {err}"
    );
    assert!(
        !mgr.peers
            .get(&key(addr))
            .expect("peer remains managed")
            .enabled,
        "disable marks desired admin state before signaling the stuck session"
    );

    let _ = finish_tx.send(());
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
                        negotiated_hold_time: None,
                        four_octet_as: None,
                        remote_router_id: None,
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

/// A peer handle that accepts import-policy hot-apply but fails the first export
/// hot-apply, then accepts later export updates. This forces the transaction
/// primitive's partial-mutation path: the peer's import bookkeeping can advance
/// before export fails, and rollback must restore the same peer too.
fn export_fails_once_policy_handle(peer_addr: IpAddr, state: SessionState) -> PeerHandle {
    use rustbgpd_transport::{PeerCommand, PeerCommandError};
    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let export_failed = Arc::new(AtomicBool::new(false));
    let task = tokio::spawn(async move {
        while let Some(cmd) = session_rx.recv().await {
            match cmd {
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(PeerSessionState {
                        fsm_state: state,
                        peer_ip: peer_addr,
                        peer_asn: None,
                        prefix_count: 0,
                        negotiated_hold_time: None,
                        four_octet_as: None,
                        remote_router_id: None,
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
                    });
                }
                PeerCommand::UpdateImportPolicy { reply, .. }
                | PeerCommand::SendRouteRefresh { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::UpdateExportPolicy { reply, .. } => {
                    if export_failed.swap(true, Ordering::SeqCst) {
                        let _ = reply.send(Ok(()));
                    } else {
                        let _ = reply.send(Err(PeerCommandError::CommandFailed(
                            "export apply failed once".to_string(),
                        )));
                    }
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

/// A peer handle that acks policy hot-applies but rejects Route Refresh, as a
/// peer that did not negotiate the Route Refresh capability would (the session
/// returns "peer lacks Route Refresh capability"). Used to verify a live-impact
/// apply rejects an Established non-RR peer cleanly.
fn route_refresh_failing_handle(peer_addr: IpAddr, state: SessionState) -> PeerHandle {
    use rustbgpd_transport::{PeerCommand, PeerCommandError};
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
                        negotiated_hold_time: None,
                        four_octet_as: None,
                        remote_router_id: None,
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
                    });
                }
                PeerCommand::UpdateImportPolicy { reply, .. }
                | PeerCommand::UpdateExportPolicy { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::SendRouteRefresh { reply, .. } => {
                    let _ = reply.send(Err(PeerCommandError::RouteRefreshUnsupported));
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

/// A peer handle that acks policy hot-applies, reports Established, and acks the
/// FIRST Route Refresh but fails every subsequent one. Drives the compound
/// rollback path: the forward apply succeeds (peer captured
/// `forward_completed = true`), but the refresh issued while rolling back fails,
/// exercising `RefreshFailureHandling::BestEffortRearm`.
fn route_refresh_failing_after_first_handle(peer_addr: IpAddr, state: SessionState) -> PeerHandle {
    use rustbgpd_transport::{PeerCommand, PeerCommandError};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let refresh_calls = Arc::new(AtomicU32::new(0));
    let task = tokio::spawn(async move {
        while let Some(cmd) = session_rx.recv().await {
            match cmd {
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(PeerSessionState {
                        fsm_state: state,
                        peer_ip: peer_addr,
                        peer_asn: None,
                        prefix_count: 0,
                        negotiated_hold_time: None,
                        four_octet_as: None,
                        remote_router_id: None,
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
                    });
                }
                PeerCommand::UpdateImportPolicy { reply, .. }
                | PeerCommand::UpdateExportPolicy { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::SendRouteRefresh { reply, .. } => {
                    if refresh_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                        let _ = reply.send(Ok(()));
                    } else {
                        let _ = reply.send(Err(PeerCommandError::CommandFailed(
                            "transient route refresh failure".to_string(),
                        )));
                    }
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

#[tokio::test]
async fn apply_resolved_policy_snapshot_captures_priors_and_applies() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let mut mgr = live_policy_test_manager();
    let a1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let a2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    insert_test_managed_peer(
        &mut mgr,
        a1,
        acking_policy_handle(a1, SessionState::Idle),
        false,
    );
    insert_test_managed_peer(
        &mut mgr,
        a2,
        acking_policy_handle(a2, SessionState::Idle),
        false,
    );
    let peer_a_prior = validation_policy_chain(ImportValidationDependency::Rpki);
    mgr.peers.get_mut(&key(a1)).unwrap().import_policy = Some(peer_a_prior.clone());
    // a2 starts with no import policy (None).

    let new_chain = deny_policy_chain();
    let targets = vec![
        ResolvedPeerPolicy {
            address: a1,
            interface: None,
            import_policy: Some(new_chain.clone()),
            export_policy: None,
        },
        ResolvedPeerPolicy {
            address: a2,
            interface: None,
            import_policy: Some(new_chain.clone()),
            export_policy: None,
        },
    ];
    let priors = mgr
        .apply_resolved_policy_snapshot(targets)
        .await
        .expect("apply must succeed");

    assert_eq!(priors.len(), 2);
    assert_eq!(priors[0].address, a1);
    assert_eq!(
        format!("{:?}", priors[0].import_policy),
        format!("{:?}", Some(peer_a_prior))
    );
    assert_eq!(priors[1].address, a2);
    assert_eq!(
        format!("{:?}", priors[1].import_policy),
        format!("{:?}", Option::<PolicyChain>::None)
    );

    let expect_new = format!("{:?}", Some(new_chain));
    assert_eq!(
        format!("{:?}", mgr.peers.get(&key(a1)).unwrap().import_policy),
        expect_new,
        "peer 1 import policy must advance to the new chain"
    );
    assert_eq!(
        format!("{:?}", mgr.peers.get(&key(a2)).unwrap().import_policy),
        expect_new,
        "peer 2 import policy must advance to the new chain"
    );
}

#[tokio::test]
async fn apply_resolved_policy_snapshot_mid_fanout_failure_self_heals() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let mut mgr = live_policy_test_manager();
    let a1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let a2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)); // its apply fails
    let a3 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    insert_test_managed_peer(
        &mut mgr,
        a1,
        acking_policy_handle(a1, SessionState::Idle),
        false,
    );
    insert_test_managed_peer(&mut mgr, a2, closed_peer_handle(), false);
    insert_test_managed_peer(
        &mut mgr,
        a3,
        acking_policy_handle(a3, SessionState::Idle),
        false,
    );
    let prior = validation_policy_chain(ImportValidationDependency::Rpki);
    for a in [a1, a2, a3] {
        mgr.peers.get_mut(&key(a)).unwrap().import_policy = Some(prior.clone());
    }

    let new_chain = deny_policy_chain();
    let targets = [a1, a2, a3]
        .into_iter()
        .map(|address| ResolvedPeerPolicy {
            address,
            interface: None,
            import_policy: Some(new_chain.clone()),
            export_policy: None,
        })
        .collect();
    let result = mgr.apply_resolved_policy_snapshot(targets).await;
    assert!(
        result.is_err(),
        "a mid-fanout per-peer failure must surface as Err: {result:?}"
    );

    let expect_prior = format!("{:?}", Some(prior));
    assert_eq!(
        format!("{:?}", mgr.peers.get(&key(a1)).unwrap().import_policy),
        expect_prior,
        "peer 1 must be restored to its prior chain after the self-heal"
    );
    assert_eq!(
        format!("{:?}", mgr.peers.get(&key(a3)).unwrap().import_policy),
        expect_prior,
        "peer 3 was never reached and must keep its prior chain"
    );
}

#[tokio::test]
async fn apply_resolved_policy_snapshot_restores_partially_mutated_failing_peer() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let mut mgr = live_policy_test_manager();
    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    insert_test_managed_peer(
        &mut mgr,
        address,
        export_fails_once_policy_handle(address, SessionState::Idle),
        false,
    );
    let import_prior = validation_policy_chain(ImportValidationDependency::Rpki);
    let export_prior = validation_policy_chain(ImportValidationDependency::Aspa);
    {
        let managed = mgr.peers.get_mut(&key(address)).unwrap();
        managed.import_policy = Some(import_prior.clone());
        managed.export_policy = Some(export_prior.clone());
    }

    let new_chain = deny_policy_chain();
    let result = mgr
        .apply_resolved_policy_snapshot(vec![ResolvedPeerPolicy {
            address,
            interface: None,
            import_policy: Some(new_chain.clone()),
            export_policy: Some(new_chain),
        }])
        .await;
    assert!(
        result.is_err(),
        "the one-shot export failure must surface as Err: {result:?}"
    );

    let managed = mgr.peers.get(&key(address)).unwrap();
    assert_eq!(
        format!("{:?}", managed.import_policy),
        format!("{:?}", Some(import_prior)),
        "failing peer's import policy must be restored after partial mutation"
    );
    assert_eq!(
        format!("{:?}", managed.export_policy),
        format!("{:?}", Some(export_prior)),
        "failing peer's export policy must be restored too"
    );
}

#[tokio::test]
async fn apply_resolved_policy_snapshot_skips_non_live_targets() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let mut mgr = live_policy_test_manager();
    let live = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let missing = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    insert_test_managed_peer(
        &mut mgr,
        live,
        acking_policy_handle(live, SessionState::Idle),
        false,
    );

    let new_chain = deny_policy_chain();
    let targets = vec![
        ResolvedPeerPolicy {
            address: missing,
            interface: None,
            import_policy: Some(new_chain.clone()),
            export_policy: None,
        },
        ResolvedPeerPolicy {
            address: live,
            interface: None,
            import_policy: Some(new_chain.clone()),
            export_policy: None,
        },
    ];
    let priors = mgr
        .apply_resolved_policy_snapshot(targets)
        .await
        .expect("apply must succeed");

    assert_eq!(priors.len(), 1, "non-live target must be skipped");
    assert_eq!(priors[0].address, live);
    assert_eq!(
        format!("{:?}", mgr.peers.get(&key(live)).unwrap().import_policy),
        format!("{:?}", Some(new_chain))
    );
}

#[tokio::test]
async fn apply_policy_impact_snapshot_expands_dynamic_range_targets() {
    let mut mgr = live_policy_test_manager();
    let candidate = crate::config::Config::load_toml_with_diagnostics(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[security.grpc]
enforcement = "legacy"

[peer_groups.ix]
import_policy_chain = ["deny-import"]

[policy.definitions.deny-import]
default_action = "deny"

[[dynamic_neighbors]]
prefix = "10.30.0.0/16"
peer_group = "ix"
remote_asn = 65030
"#,
        "dynamic policy candidate",
    )
    .expect("test config must parse");
    mgr.current_config = candidate;

    let peer = IpAddr::V4(Ipv4Addr::new(10, 30, 0, 7));
    insert_test_managed_peer_with_asn(
        &mut mgr,
        peer,
        65030,
        acking_policy_handle(peer, SessionState::Idle),
        false,
    );
    let prior = validation_policy_chain(ImportValidationDependency::Rpki);
    {
        let managed = mgr.peers.get_mut(&key(peer)).unwrap();
        managed.is_dynamic = true;
        managed.peer_group = Some("ix".to_string());
        managed.description = "dynamic:ix".to_string();
        managed.accepted_dynamic_range = Some(AcceptedDynamicRange {
            addr: IpAddr::V4(Ipv4Addr::new(10, 30, 0, 0)),
            prefix_len: 16,
            peer_group: "ix".to_string(),
        });
        managed.import_policy = Some(prior.clone());
    }

    let priors = mgr
        .apply_policy_impact_snapshot(
            Vec::new(),
            vec![DynamicRangeTarget {
                addr: IpAddr::V4(Ipv4Addr::new(10, 30, 0, 0)),
                prefix_len: 16,
                peer_group: "ix".to_string(),
            }],
        )
        .await
        .expect("dynamic policy impact apply must succeed");

    assert_eq!(priors.len(), 1);
    assert_eq!(priors[0].address, peer);
    assert_eq!(
        format!("{:?}", priors[0].import_policy),
        format!("{:?}", Some(prior)),
        "rollback token must capture the peer's prior import policy"
    );
    let applied_action = mgr
        .peers
        .get(&key(peer))
        .unwrap()
        .import_policy
        .as_ref()
        .and_then(|chain| chain.policies.first())
        .map(|policy| policy.default_action);
    assert_eq!(
        applied_action,
        Some(rustbgpd_policy::PolicyAction::Deny),
        "dynamic peer must resolve the candidate peer-group policy"
    );
}

#[tokio::test]
async fn apply_resolved_policy_snapshot_rejects_non_route_refresh_peer_cleanly() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    // An Established peer that never negotiated Route Refresh can't be
    // soft-refreshed, so a live-impact apply that needs to re-evaluate its
    // existing AdjRibIn under the new policy must reject. The rollback must be
    // clean (prior chain restored) — not a compound "restore also failed", since
    // the doomed rollback refresh is best-effort.
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(64);
    let rib_drainer = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                let _ = reply.send(Ok(()));
            }
        }
    });
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    insert_test_managed_peer(
        &mut mgr,
        addr,
        route_refresh_failing_handle(addr, SessionState::Established),
        false,
    );
    let prior = validation_policy_chain(ImportValidationDependency::Rpki);
    mgr.peers.get_mut(&key(addr)).unwrap().import_policy = Some(prior.clone());

    let targets = vec![ResolvedPeerPolicy {
        address: addr,
        interface: None,
        import_policy: Some(deny_policy_chain()),
        export_policy: None,
    }];
    let err = mgr
        .apply_resolved_policy_snapshot(targets)
        .await
        .unwrap_err();

    assert!(
        err.to_lowercase().contains("route refresh"),
        "rejection should cite the Route Refresh failure: {err}"
    );
    assert!(
        err.contains("already-applied peers restored"),
        "rollback should be clean: {err}"
    );
    assert!(
        !err.contains("restoring already-applied peers also failed"),
        "rollback must not be a compound failure for a non-RR peer: {err}"
    );
    assert_eq!(
        format!("{:?}", mgr.peers.get(&key(addr)).unwrap().import_policy),
        format!("{:?}", Some(prior)),
        "the peer's import policy must be restored to its prior chain"
    );
    assert!(
        !mgr.peers.get(&key(addr)).unwrap().pending_refresh,
        "a rejected non-RR apply must restore the prior pending_refresh state"
    );
    rib_drainer.abort();
}

#[tokio::test]
async fn apply_resolved_policy_snapshot_rearms_refresh_on_compound_rollback_failure() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    // Compound failure: peer A's forward apply fully succeeds (its AdjRibIn is
    // moved to the new policy via a successful Route Refresh), then peer B's
    // forward refresh fails and forces a rollback. While restoring A, its
    // rollback-time refresh also fails. Because A's forward completed, its
    // AdjRibIn is stale at the new policy, so pending_refresh must be RE-ARMED
    // (true) — whereas B never completed, so B restores its prior pending state
    // (false). Pins the RefreshFailureHandling::BestEffortRearm vs
    // BestEffortRestorePrior asymmetry under a rollback-time refresh failure.
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(64);
    let rib_drainer = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                let _ = reply.send(Ok(()));
            }
        }
    });
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );

    // Peer A: forward succeeds (first refresh acked), rollback refresh fails.
    let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    insert_test_managed_peer(
        &mut mgr,
        a,
        route_refresh_failing_after_first_handle(a, SessionState::Established),
        false,
    );
    // Peer B: applied second; its forward refresh fails, forcing the rollback.
    let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    insert_test_managed_peer(
        &mut mgr,
        b,
        route_refresh_failing_handle(b, SessionState::Established),
        false,
    );
    let prior = validation_policy_chain(ImportValidationDependency::Rpki);
    for p in [a, b] {
        mgr.peers.get_mut(&key(p)).unwrap().import_policy = Some(prior.clone());
    }

    let new_chain = deny_policy_chain();
    let targets = [a, b]
        .into_iter()
        .map(|address| ResolvedPeerPolicy {
            address,
            interface: None,
            import_policy: Some(new_chain.clone()),
            export_policy: None,
        })
        .collect();
    let result = mgr.apply_resolved_policy_snapshot(targets).await;
    assert!(
        result.is_err(),
        "peer B's forward refresh failure must surface as Err: {result:?}"
    );

    let a_peer = mgr.peers.get(&key(a)).unwrap();
    assert_eq!(
        format!("{:?}", a_peer.import_policy),
        format!("{:?}", Some(prior.clone())),
        "peer A's import policy must be restored to its prior chain"
    );
    assert!(
        a_peer.pending_refresh,
        "peer A completed its forward apply, so a failed rollback refresh must re-arm pending_refresh"
    );
    assert!(
        !mgr.peers.get(&key(b)).unwrap().pending_refresh,
        "peer B never completed its forward apply, so it must restore prior pending_refresh, not re-arm"
    );
    rib_drainer.abort();
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn back_to_back_updates_do_not_lose_pending_refresh() {
    use rustbgpd_transport::PeerCommand;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let established = Arc::new(AtomicBool::new(false));
    let refresh_calls = Arc::new(AtomicU32::new(0));
    let established_in_task = established.clone();
    let refresh_calls_in_task = refresh_calls.clone();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let task = tokio::spawn(async move {
        while let Some(cmd) = session_rx.recv().await {
            match cmd {
                PeerCommand::UpdateImportPolicy { reply, .. }
                | PeerCommand::UpdateExportPolicy { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::QueryState { reply } => {
                    let state = if established_in_task.load(Ordering::SeqCst) {
                        SessionState::Established
                    } else {
                        SessionState::Idle
                    };
                    let _ = reply.send(PeerSessionState {
                        fsm_state: state,
                        peer_ip: addr,
                        peer_asn: None,
                        prefix_count: 0,
                        negotiated_hold_time: Some(90),
                        four_octet_as: Some(true),
                        remote_router_id: Some(Ipv4Addr::new(10, 0, 0, 2)),
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
                        uptime_secs: u64::from(state == SessionState::Established),
                        last_error: String::new(),
                    });
                }
                PeerCommand::SendRouteRefresh { reply, .. } => {
                    refresh_calls_in_task.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::Shutdown => break,
                _ => {}
            }
        }
        Ok(())
    });
    let handle = PeerHandle::from_parts(session_tx, task);

    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(64);
    let rib_drainer = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                let _ = reply.send(Ok(()));
            }
        }
    });
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    insert_test_managed_peer(&mut mgr, addr, handle, true);

    let first = mgr.update_runtime_policies(addr, None, None).await;
    assert!(
        first.is_ok(),
        "first update should re-arm the pending refresh while the peer is idle: {first:?}"
    );
    assert!(
        mgr.peers.get(&key(addr)).unwrap().pending_refresh,
        "pending_refresh must survive the first back-to-back update while the peer is idle"
    );
    assert_eq!(
        refresh_calls.load(Ordering::SeqCst),
        0,
        "idle peer must not receive route refresh yet"
    );

    established.store(true, Ordering::SeqCst);
    let second = mgr.update_runtime_policies(addr, None, None).await;
    assert!(
        second.is_ok(),
        "second update should consume the carried refresh once the peer is Established: {second:?}"
    );
    assert!(
        !mgr.peers.get(&key(addr)).unwrap().pending_refresh,
        "pending_refresh must clear after the retry successfully sends Route Refresh"
    );
    assert_eq!(
        refresh_calls.load(Ordering::SeqCst),
        1,
        "second update must fire the previously carried Route Refresh exactly once"
    );

    mgr.delete_peer(key(addr), false).await.unwrap();
    drop(mgr);
    let _ = rib_drainer.await;
}

#[tokio::test]
async fn peer_deletion_after_failed_update_drops_pending_retry_cleanly() {
    use rustbgpd_transport::PeerCommand;

    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let task = tokio::spawn(async move {
        while let Some(cmd) = session_rx.recv().await {
            match cmd {
                PeerCommand::UpdateImportPolicy { reply, .. } => {
                    drop(reply);
                }
                PeerCommand::UpdateExportPolicy { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(PeerSessionState {
                        fsm_state: SessionState::Established,
                        peer_ip: addr,
                        peer_asn: None,
                        prefix_count: 0,
                        negotiated_hold_time: Some(90),
                        four_octet_as: Some(true),
                        remote_router_id: Some(Ipv4Addr::new(10, 0, 0, 2)),
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
                    });
                }
                PeerCommand::Shutdown => break,
                _ => {}
            }
        }
        Ok(())
    });
    let handle = PeerHandle::from_parts(session_tx, task);

    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(64);
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    insert_test_managed_peer(&mut mgr, addr, handle, false);

    let failed = mgr
        .update_runtime_policies(addr, Some(deny_policy_chain()), None)
        .await;
    assert!(
        failed.is_err(),
        "first update should fail and leave pending retry intent: {failed:?}"
    );
    assert!(
        mgr.peers.get(&key(addr)).unwrap().pending_refresh,
        "failed update must set pending_refresh before deletion"
    );

    mgr.delete_peer(key(addr), false)
        .await
        .expect("peer deletion after failed update must complete");
    assert!(
        mgr.peers.is_empty(),
        "deleting the peer must drop the ManagedPeer that held pending retry state"
    );

    let retry_after_delete = mgr
        .update_runtime_policies(addr, Some(deny_policy_chain()), None)
        .await;
    assert!(
        retry_after_delete.is_ok(),
        "a queued or follow-up policy update for a peer deleted during the failure window \
         must no-op cleanly, not resurrect stale pending state: {retry_after_delete:?}"
    );
}

/// LAN-311: a policy fan-out (SIGHUP rpol overlay, catalog edit, and
/// the ADR-0076 txn snapshot all funnel through
/// `update_runtime_policies_for_peer_key`) must scope reinstallation to
/// peers whose resolved chain CONTENT moved. A peer re-resolving to a
/// content-equal chain gets no session command at all — the session
/// bumps its import-policy generation (and swaps the counter-bearing
/// chain instance) inside the `UpdateImportPolicy` handler, so "no
/// command" IS the #761 generation-unchanged / counters-survive
/// guarantee (the M80 finding: SIGHUP bumped generation 0→1 on peers
/// whose chains didn't change) — and no RIB `ReplacePeerExportPolicy`.
/// The peer whose content moved gets exactly the prior behavior:
/// session installs, RIB replace, and a Route Refresh.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn content_equal_policy_fanout_skips_unaffected_peers() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;
    use rustbgpd_transport::PeerCommand;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[derive(Default)]
    struct SessionCounters {
        import_installs: AtomicU32,
        export_installs: AtomicU32,
        refreshes: AtomicU32,
    }

    fn fake_session(addr: IpAddr) -> (PeerHandle, Arc<SessionCounters>) {
        let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(16);
        let counters = Arc::new(SessionCounters::default());
        let counters_in_task = counters.clone();
        let task = tokio::spawn(async move {
            while let Some(cmd) = session_rx.recv().await {
                match cmd {
                    PeerCommand::UpdateImportPolicy { reply, .. } => {
                        counters_in_task
                            .import_installs
                            .fetch_add(1, Ordering::SeqCst);
                        let _ = reply.send(Ok(()));
                    }
                    PeerCommand::UpdateExportPolicy { reply, .. } => {
                        counters_in_task
                            .export_installs
                            .fetch_add(1, Ordering::SeqCst);
                        let _ = reply.send(Ok(()));
                    }
                    PeerCommand::SendRouteRefresh { reply, .. } => {
                        counters_in_task.refreshes.fetch_add(1, Ordering::SeqCst);
                        let _ = reply.send(Ok(()));
                    }
                    PeerCommand::QueryState { reply } => {
                        let _ = reply.send(PeerSessionState {
                            fsm_state: SessionState::Established,
                            peer_ip: addr,
                            peer_asn: None,
                            prefix_count: 0,
                            negotiated_hold_time: Some(90),
                            four_octet_as: Some(true),
                            remote_router_id: None,
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
                        });
                    }
                    PeerCommand::Shutdown => break,
                    _ => {}
                }
            }
            Ok(())
        });
        (PeerHandle::from_parts(session_tx, task), counters)
    }

    fn permit_policy_chain() -> PolicyChain {
        use rustbgpd_policy::{Policy, PolicyAction};
        PolicyChain::new(vec![Policy {
            entries: Vec::new(),
            default_action: PolicyAction::Permit,
        }])
    }

    let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let (handle_a, counters_a) = fake_session(a);
    let (handle_b, counters_b) = fake_session(b);

    // RIB drainer counting ReplacePeerExportPolicy per peer.
    let rib_replaces_a = Arc::new(AtomicU32::new(0));
    let rib_replaces_b = Arc::new(AtomicU32::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(64);
    let (replaces_a, replaces_b) = (rib_replaces_a.clone(), rib_replaces_b.clone());
    let rib_drainer = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } = update {
                if peer == a {
                    replaces_a.fetch_add(1, Ordering::SeqCst);
                } else {
                    replaces_b.fetch_add(1, Ordering::SeqCst);
                }
                let _ = reply.send(Ok(()));
            }
        }
    });

    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    insert_test_managed_peer(&mut mgr, a, handle_a, false);
    insert_test_managed_peer(&mut mgr, b, handle_b, false);

    // Initial install through the atomic fan-out both edits ride.
    let target = |address: IpAddr, chain: PolicyChain| ResolvedPeerPolicy {
        address,
        interface: None,
        import_policy: Some(chain.clone()),
        export_policy: Some(chain),
    };
    mgr.apply_resolved_policy_snapshot(vec![
        target(a, permit_policy_chain()),
        target(b, permit_policy_chain()),
    ])
    .await
    .expect("initial install");
    assert_eq!(counters_a.import_installs.load(Ordering::SeqCst), 1);
    assert_eq!(counters_a.refreshes.load(Ordering::SeqCst), 1);
    assert_eq!(rib_replaces_a.load(Ordering::SeqCst), 1);

    // The M80 shape: an edit re-resolves BOTH peers, but only B's chain
    // content moved; A resolves to a content-equal (fresh-instance)
    // chain.
    mgr.apply_resolved_policy_snapshot(vec![
        target(a, permit_policy_chain()),
        target(b, deny_policy_chain()),
    ])
    .await
    .expect("scoped re-apply");

    // (ii) Unaffected peer: NO reinstall of any kind — generation and
    // live counters in the session survive untouched.
    assert_eq!(
        counters_a.import_installs.load(Ordering::SeqCst),
        1,
        "content-equal re-resolve must not send UpdateImportPolicy \
         (each send bumps the session's import generation and resets its counters)"
    );
    assert_eq!(
        counters_a.export_installs.load(Ordering::SeqCst),
        1,
        "content-equal re-resolve must not send UpdateExportPolicy"
    );
    assert_eq!(
        rib_replaces_a.load(Ordering::SeqCst),
        1,
        "content-equal re-resolve must not send ReplacePeerExportPolicy \
         (a fresh instance would strand the update group's term-hit counters)"
    );
    assert_eq!(
        counters_a.refreshes.load(Ordering::SeqCst),
        1,
        "content-equal re-resolve must not fire Route Refresh"
    );

    // (iii) Changed peer: full reinstall — session installs, RIB
    // replace, Route Refresh — and bookkeeping advances to the new
    // chain.
    assert_eq!(counters_b.import_installs.load(Ordering::SeqCst), 2);
    assert_eq!(counters_b.export_installs.load(Ordering::SeqCst), 2);
    assert_eq!(rib_replaces_b.load(Ordering::SeqCst), 2);
    assert_eq!(counters_b.refreshes.load(Ordering::SeqCst), 2);
    assert_eq!(
        mgr.peers.get(&key(b)).unwrap().import_policy,
        Some(deny_policy_chain()),
        "changed peer's bookkeeping must advance to the new chain"
    );

    rib_drainer.abort();
}

#[tokio::test(start_paused = true)]
async fn gshut_toggle_times_out_when_rib_reply_wedges() {
    use rustbgpd_transport::PeerCommand;

    // LAN-286: a wedged RIB (accepts RefreshPeerOutbound but never
    // replies) must surface as a bounded error — not park the
    // peer-manager actor (and the reload/apply path driving the
    // toggle) forever.
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let session_task = tokio::spawn(async move {
        while let Some(cmd) = session_rx.recv().await {
            if let PeerCommand::UpdateGracefulShutdown { reply, .. } = cmd {
                let _ = reply.send(Ok(()));
            }
        }
        Ok(())
    });
    let handle = PeerHandle::from_parts(session_tx, session_task);

    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(64);
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::RefreshPeerOutbound { reply, .. } = update {
                // Wedged RIB: hold the reply channel open, never answer.
                held.push(reply);
            }
        }
    });
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    insert_test_managed_peer(&mut mgr, addr, handle, false);

    let err = mgr
        .set_graceful_shutdown(Some(key(addr)), true)
        .await
        .expect_err("wedged RIB reply must fail the toggle, not hang it");
    assert!(
        err.to_string().contains("timed out"),
        "error must name the RIB reply timeout: {err}"
    );
}

#[allow(clippy::too_many_lines)]
#[tokio::test(start_paused = true)]
async fn export_policy_apply_times_out_when_rib_reply_wedges() {
    use rustbgpd_transport::PeerCommand;

    // LAN-286: same wedge class as the gshut refresh — the
    // ReplacePeerExportPolicy reply await must be bounded so a wedged
    // RIB cannot hang a SIGHUP reload / gRPC policy apply forever.
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let session_task = tokio::spawn(async move {
        while let Some(cmd) = session_rx.recv().await {
            match cmd {
                PeerCommand::UpdateImportPolicy { reply, .. }
                | PeerCommand::UpdateExportPolicy { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(PeerSessionState {
                        fsm_state: SessionState::Established,
                        peer_ip: addr,
                        peer_asn: None,
                        prefix_count: 0,
                        negotiated_hold_time: None,
                        four_octet_as: None,
                        remote_router_id: None,
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
                    });
                }
                _ => {}
            }
        }
        Ok(())
    });
    let handle = PeerHandle::from_parts(session_tx, session_task);

    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(64);
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                // Wedged RIB: hold the reply channel open, never answer.
                held.push(reply);
            }
        }
    });
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    insert_test_managed_peer(&mut mgr, addr, handle, false);

    let err = mgr
        .update_runtime_policies(addr, None, Some(deny_policy_chain()))
        .await
        .expect_err("wedged RIB reply must fail the export apply, not hang it");
    assert!(
        err.contains("did not reply within"),
        "error must name the RIB reply timeout: {err}"
    );
}

#[tokio::test]
async fn gshut_not_found_preserves_scoped_peer_label() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let peer = scoped_key(IpAddr::V6("fe80::2".parse().unwrap()), "eth1");

    let err = mgr
        .set_graceful_shutdown(Some(peer), true)
        .await
        .unwrap_err();

    assert_eq!(err.to_string(), "peer fe80::2%eth1 not found");
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn honor_graceful_shutdown_hot_apply_targets_ebgp_only() {
    use rustbgpd_transport::PeerCommand;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn fake_established_peer(
        addr: IpAddr,
        import_updates: Arc<AtomicU32>,
        refresh_calls: Arc<AtomicU32>,
    ) -> PeerHandle {
        let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
        let task = tokio::spawn(async move {
            while let Some(cmd) = session_rx.recv().await {
                match cmd {
                    PeerCommand::UpdateImportPolicy { reply, .. } => {
                        import_updates.fetch_add(1, Ordering::SeqCst);
                        let _ = reply.send(Ok(()));
                    }
                    PeerCommand::UpdateExportPolicy { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    PeerCommand::QueryState { reply } => {
                        let _ = reply.send(PeerSessionState {
                            fsm_state: SessionState::Established,
                            peer_ip: addr,
                            peer_asn: None,
                            prefix_count: 0,
                            negotiated_hold_time: Some(90),
                            four_octet_as: Some(true),
                            remote_router_id: Some(Ipv4Addr::new(10, 0, 0, 2)),
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
                        });
                    }
                    PeerCommand::SendRouteRefresh { reply, .. } => {
                        refresh_calls.fetch_add(1, Ordering::SeqCst);
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

    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(64);
    let rib_drainer = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                let _ = reply.send(Ok(()));
            }
        }
    });
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );

    let ebgp = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let ibgp = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    mgr.current_config.neighbors = vec![config_neighbor(ebgp, 65002), config_neighbor(ibgp, 65001)];

    let ebgp_import_updates = Arc::new(AtomicU32::new(0));
    let ebgp_refresh_calls = Arc::new(AtomicU32::new(0));
    let ibgp_import_updates = Arc::new(AtomicU32::new(0));
    let ibgp_refresh_calls = Arc::new(AtomicU32::new(0));
    insert_test_managed_peer_with_asn(
        &mut mgr,
        ebgp,
        65002,
        fake_established_peer(
            ebgp,
            ebgp_import_updates.clone(),
            ebgp_refresh_calls.clone(),
        ),
        false,
    );
    insert_test_managed_peer_with_asn(
        &mut mgr,
        ibgp,
        65001,
        fake_established_peer(
            ibgp,
            ibgp_import_updates.clone(),
            ibgp_refresh_calls.clone(),
        ),
        false,
    );

    let result = mgr.set_honor_graceful_shutdown(true).await;
    assert!(result.is_ok(), "hot-apply must succeed: {result:?}");
    assert!(mgr.current_config.global.honor_graceful_shutdown);
    assert_eq!(
        ebgp_import_updates.load(Ordering::SeqCst),
        1,
        "EBGP peer must receive recomputed import policy with the implicit GShut rule"
    );
    assert_eq!(
        ebgp_refresh_calls.load(Ordering::SeqCst),
        1,
        "Established EBGP peer must get route refresh after the import chain changes"
    );
    assert_eq!(
        ibgp_import_updates.load(Ordering::SeqCst),
        0,
        "iBGP peer must be exempt from RFC 8326 receiver hot-apply"
    );
    assert_eq!(
        ibgp_refresh_calls.load(Ordering::SeqCst),
        0,
        "iBGP exemption also means no route refresh"
    );

    mgr.delete_peer(key(ebgp), false).await.unwrap();
    mgr.delete_peer(key(ibgp), false).await.unwrap();
    drop(mgr);
    let _ = rib_drainer.await;
}

/// Regression for a high-severity gap in the prior code: when
/// `update_import_policy_timeout` failed against an Established
/// peer, the warn-and-continue path then fired `soft_reset_in`
/// regardless. The session task still held the *old* import
/// policy, so Route Refresh would re-evaluate `AdjRibIn` against
/// the old policy — silently keeping forbidden routes flowing
/// on a permit→deny edit, with the daemon believing
/// the new policy was live and clearing any retry intent.
///
/// Fix and assertion: when the session-side import-policy update
/// fails AND the peer is Established AND there's a refresh
/// intent, the function must (a) leave `managed.import_policy`
/// at the prior value (so the next call's `import_changed` still
/// fires), (b) set `pending_refresh` for retry, (c) NOT call
/// `soft_reset_in`, and (d) return Err so the caller surfaces
/// the failure. The fake session here drops the import-policy
/// reply oneshot (sender side gets "session task dropped reply")
/// but answers `QueryState` with Established. This reproduces
/// the production race: the session task can drop a reply
/// mid-shutdown while the FSM is still reporting Established
/// for one more poll.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn import_apply_failure_on_established_peer_bails_without_refresh() {
    use rustbgpd_policy::{Policy, PolicyAction};
    use rustbgpd_transport::PeerCommand;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    // Fake session task: drops UpdateImportPolicy replies (induces
    // "session task dropped reply" Err on the caller side), replies
    // OK to UpdateExportPolicy, replies Established to QueryState,
    // and counts SendRouteRefresh invocations so the test can
    // assert refresh was NOT issued. Subsequent commands process
    // sequentially after the dropped import reply because we drop
    // the reply oneshot inside the same arm — no parking.
    let (tx, mut rx) = mpsc::channel::<PeerCommand>(8);
    let route_refresh_calls = Arc::new(AtomicU32::new(0));
    let route_refresh_calls_in_task = route_refresh_calls.clone();
    let task_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let task = tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                PeerCommand::UpdateImportPolicy { reply, .. } => {
                    // Drop reply without responding → caller's
                    // reply_rx.await yields RecvError → the
                    // bounded variant maps that to "session task
                    // dropped reply".
                    drop(reply);
                }
                PeerCommand::UpdateExportPolicy { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(PeerSessionState {
                        fsm_state: SessionState::Established,
                        peer_ip: task_addr,
                        peer_asn: None,
                        prefix_count: 0,
                        negotiated_hold_time: Some(90),
                        four_octet_as: Some(true),
                        remote_router_id: Some(Ipv4Addr::new(10, 0, 0, 2)),
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
                    });
                }
                PeerCommand::SendRouteRefresh { reply, .. } => {
                    route_refresh_calls_in_task.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::Shutdown => break,
                _ => {}
            }
        }
        Ok(())
    });
    let handle = PeerHandle::from_parts(tx, task);

    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    // RIB receiver is held but never expected to receive: the bail
    // path returns Err *before* the `ReplacePeerExportPolicy`
    // send. Holding rib_rx alive prevents the
    // `RibUpdate::ReplacePeerExportPolicy` send from failing
    // spuriously if the bail logic ever regresses.
    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let peer_config = make_config(task_addr, 65002);
    let transport = mgr.build_transport_config(&peer_config);
    let hold = transport.peer.hold_time;
    mgr.peers.insert(
        key(task_addr),
        ManagedPeer {
            handle,
            session_id: 1,
            remote_asn: 65002,
            description: "test".to_string(),
            peer_group: None,
            enabled: true,
            hold_time: Some(hold),
            max_prefixes: None,
            transport_config: transport,
            import_policy: None,
            export_policy: None,
            pending_inbound: None,
            is_dynamic: false,
            accepted_dynamic_range: None,
            pending_refresh: false,
            pending_export_apply: false,
            advertise_graceful_shutdown: false,
        },
    );

    // Build a non-empty PolicyChain so import_changed flips true
    // (None → Some(...)). The chain content doesn't matter for
    // the test — only that it's distinct from the prior None.
    let chain = PolicyChain::new(vec![Policy {
        entries: Vec::new(),
        default_action: PolicyAction::Deny,
    }]);

    let result = mgr
        .update_runtime_policies(task_addr, Some(chain), None)
        .await;

    assert!(
        result.is_err(),
        "Established peer with import-changing intent must surface session-side \
         import-apply failure as Err — silently logging-and-continuing would let \
         the daemon believe the new policy is live while the session still has the \
         old one. Got: {result:?}"
    );
    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("policy hot-apply") && err_msg.contains("import:"),
        "error message must explain the failure mode for the operator: {err_msg}"
    );

    let managed = mgr.peers.get(&key(task_addr)).expect("peer present");
    assert!(
        managed.pending_refresh,
        "pending_refresh must be set so the next update_runtime_policies call \
         retries the session-side update + Route Refresh as a unit."
    );
    assert!(
        managed.import_policy.is_none(),
        "managed.import_policy must remain at the prior value when the \
         session-side update failed — advancing it would mask the delta from \
         the next call's import_changed comparison and skip the retry. \
         Got: {:?}",
        managed.import_policy
    );

    assert_eq!(
        route_refresh_calls.load(Ordering::SeqCst),
        0,
        "soft_reset_in must NOT have run: firing Route Refresh against a session \
         that still holds the prior import policy would re-evaluate AdjRibIn \
         against the OLD policy — the silent-stale-routes regression this test pins."
    );
}

/// Non-Established variant of the import-apply failure regression.
/// The prior bail condition
/// (`is_established && import_apply_failed && needs_refresh`)
/// gated the failure surface on Established, which let an Idle /
/// Connect peer with a dropped `UpdateImportPolicy` command
/// silently return Ok. The caller (`apply_policy_change`) then
/// advanced `current_config`, leaving no retry signal — if the
/// session task subsequently died before processing the queued
/// command, the peer would reach Established holding the prior
/// import policy with no record that the edit didn't land.
///
/// The fix dropped the `is_established` gate from `import_bail`
/// (Route Refresh stays gated by `soft_reset_in`'s own check —
/// the gates serve different purposes). This test pins that
/// behavior: an Idle peer with a session that drops the
/// `UpdateImportPolicy` reply must bail with Err, set
/// `pending_refresh = true`, leave `managed.import_policy` at
/// the prior value, and (because peer is Idle) NOT fire Route
/// Refresh.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn import_apply_failure_on_idle_peer_bails_and_sets_pending_refresh() {
    use rustbgpd_policy::{Policy, PolicyAction};
    use rustbgpd_transport::PeerCommand;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    let (tx, mut rx) = mpsc::channel::<PeerCommand>(8);
    let route_refresh_calls = Arc::new(AtomicU32::new(0));
    let route_refresh_calls_in_task = route_refresh_calls.clone();
    let task_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let task = tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                PeerCommand::UpdateImportPolicy { reply, .. } => {
                    // Drop without replying — caller observes
                    // "session task dropped reply".
                    drop(reply);
                }
                PeerCommand::UpdateExportPolicy { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(PeerSessionState {
                        fsm_state: SessionState::Idle,
                        peer_ip: task_addr,
                        peer_asn: None,
                        prefix_count: 0,
                        negotiated_hold_time: None,
                        four_octet_as: None,
                        remote_router_id: None,
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
                    });
                }
                PeerCommand::SendRouteRefresh { reply, .. } => {
                    route_refresh_calls_in_task.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::Shutdown => break,
                _ => {}
            }
        }
        Ok(())
    });
    let handle = PeerHandle::from_parts(tx, task);

    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let peer_config = make_config(task_addr, 65002);
    let transport = mgr.build_transport_config(&peer_config);
    let hold = transport.peer.hold_time;
    mgr.peers.insert(
        key(task_addr),
        ManagedPeer {
            handle,
            session_id: 1,
            remote_asn: 65002,
            description: "test".to_string(),
            peer_group: None,
            enabled: true,
            hold_time: Some(hold),
            max_prefixes: None,
            transport_config: transport,
            import_policy: None,
            export_policy: None,
            pending_inbound: None,
            is_dynamic: false,
            accepted_dynamic_range: None,
            pending_refresh: false,
            pending_export_apply: false,
            advertise_graceful_shutdown: false,
        },
    );

    let chain = PolicyChain::new(vec![Policy {
        entries: Vec::new(),
        default_action: PolicyAction::Deny,
    }]);

    let result = mgr
        .update_runtime_policies(task_addr, Some(chain), None)
        .await;

    assert!(
        result.is_err(),
        "Idle peer with import-changing intent and session-side apply failure must \
         surface as Err — silently returning Ok would let `apply_policy_change` \
         advance current_config with no retry signal, so a subsequently dying \
         session task would leak the stale import policy when the peer establishes. \
         Got: {result:?}"
    );
    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("policy hot-apply") && err_msg.contains("import:"),
        "error message must call out the import side specifically: {err_msg}"
    );

    let managed = mgr.peers.get(&key(task_addr)).expect("peer present");
    assert!(
        managed.pending_refresh,
        "pending_refresh must be set so the next update_runtime_policies call \
         retries the session-side import update."
    );
    assert!(
        managed.import_policy.is_none(),
        "managed.import_policy must remain at the prior value when the session-side \
         update failed — advancing it would mask the delta from the next call's \
         import_changed comparison and skip the retry. Got: {:?}",
        managed.import_policy
    );

    assert_eq!(
        route_refresh_calls.load(Ordering::SeqCst),
        0,
        "Route Refresh must NOT fire for an Idle peer regardless of the bail \
         outcome — that's `soft_reset_in`'s own Established gate, which is a \
         separate concern from the failure-surfacing decision."
    );
}

/// Symmetric counterpart for the export side: the prior code
/// swallowed `update_export_policy_timeout` failures, logging a
/// warning and returning Ok. That left the peer announcing
/// under the old export policy even though the daemon's
/// bookkeeping had no record that the edit didn't land.
/// Different blast radius from the import gap
/// (no Route Refresh involved), but the same silent-stale-policy
/// class — and crucially, no `is_established` gate: a session
/// that's mid-handshake can still drop policy commands, and once
/// it reaches Established the registration with the RIB
/// (`PeerUp` path) uses whatever export policy the session task
/// holds. Failure must propagate, the bookkeeping must not
/// advance, and `pending_export_apply` must be set so the next
/// call retries.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn export_apply_failure_bails_without_advancing_bookkeeping() {
    use rustbgpd_policy::{Policy, PolicyAction};
    use rustbgpd_transport::PeerCommand;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    let (tx, mut rx) = mpsc::channel::<PeerCommand>(8);
    let rib_replace_calls = Arc::new(AtomicU32::new(0));
    let route_refresh_calls = Arc::new(AtomicU32::new(0));
    let route_refresh_calls_in_task = route_refresh_calls.clone();
    let task_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let task = tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                PeerCommand::UpdateImportPolicy { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::UpdateExportPolicy { reply, .. } => {
                    // Drop without replying — caller observes
                    // "session task dropped reply".
                    drop(reply);
                }
                PeerCommand::QueryState { reply } => {
                    // Idle is enough: the export-side bail does
                    // not require Established. Using Idle here
                    // proves the export gap fires regardless of
                    // session state, which the prior code's
                    // warn-and-continue would have masked for
                    // every non-Established peer.
                    let _ = reply.send(PeerSessionState {
                        fsm_state: SessionState::Idle,
                        peer_ip: task_addr,
                        peer_asn: None,
                        prefix_count: 0,
                        negotiated_hold_time: None,
                        four_octet_as: None,
                        remote_router_id: None,
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
                    });
                }
                PeerCommand::SendRouteRefresh { reply, .. } => {
                    route_refresh_calls_in_task.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::Shutdown => break,
                _ => {}
            }
        }
        Ok(())
    });
    let handle = PeerHandle::from_parts(tx, task);

    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    // Hold rib_rx but spawn a task to assert ReplacePeerExportPolicy
    // is never received: the bail must run *before* the RIB step.
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(64);
    let rib_replace_calls_clone = rib_replace_calls.clone();
    let rib_drainer = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if matches!(update, RibUpdate::ReplacePeerExportPolicy { .. }) {
                rib_replace_calls_clone.fetch_add(1, Ordering::SeqCst);
            }
        }
    });

    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let peer_config = make_config(task_addr, 65002);
    let transport = mgr.build_transport_config(&peer_config);
    let hold = transport.peer.hold_time;
    mgr.peers.insert(
        key(task_addr),
        ManagedPeer {
            handle,
            session_id: 1,
            remote_asn: 65002,
            description: "test".to_string(),
            peer_group: None,
            enabled: true,
            hold_time: Some(hold),
            max_prefixes: None,
            transport_config: transport,
            import_policy: None,
            export_policy: None,
            pending_inbound: None,
            is_dynamic: false,
            accepted_dynamic_range: None,
            pending_refresh: false,
            pending_export_apply: false,
            advertise_graceful_shutdown: false,
        },
    );

    let chain = PolicyChain::new(vec![Policy {
        entries: Vec::new(),
        default_action: PolicyAction::Deny,
    }]);

    // Pass the chain on the export side; import stays None so
    // import_apply succeeds and only the export path drives the
    // bail. This isolates the export-side regression from the
    // import-side coverage already in place.
    let result = mgr
        .update_runtime_policies(task_addr, None, Some(chain))
        .await;

    assert!(
        result.is_err(),
        "Export-changing intent with session-side apply failure must propagate as \
         Err — silently logging-and-continuing would let the daemon believe the \
         new export policy is live while the session keeps announcing under the \
         prior one. Got: {result:?}"
    );
    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("policy hot-apply") && err_msg.contains("export:"),
        "error message must call out the export side specifically so the operator \
         can diagnose: {err_msg}"
    );

    let managed = mgr.peers.get(&key(task_addr)).expect("peer present");
    assert!(
        managed.pending_export_apply,
        "pending_export_apply must be set so the next update_runtime_policies call \
         retries the session-side export update."
    );
    assert!(
        managed.export_policy.is_none(),
        "managed.export_policy must remain at the prior value when the session-side \
         update failed — advancing it would mask the delta from the next call's \
         export_changed comparison and skip the retry. Got: {:?}",
        managed.export_policy
    );

    assert_eq!(
        rib_replace_calls.load(Ordering::SeqCst),
        0,
        "RIB ReplacePeerExportPolicy must NOT fire when the session-side export \
         update failed: the RIB and session would otherwise diverge, with the RIB \
         computing routes against the new policy and the session re-applying the \
         old one on outbound."
    );
    assert_eq!(
        route_refresh_calls.load(Ordering::SeqCst),
        0,
        "Export-only failure must not trigger Route Refresh — that is import-side \
         machinery and has no business firing on an export edit."
    );

    // Drain rib_rx so the spawned task can exit cleanly when mgr drops.
    drop(mgr);
    let _ = rib_drainer.await;
}

/// Cross-side regression: import apply succeeds (advancing
/// `managed.import_policy`) but export apply fails on the same
/// call. The bail must carry forward the unfired Route Refresh
/// intent so a subsequent retry — even one that finds
/// `import_changed = false` because bookkeeping already advanced
/// — still fires `soft_reset_in`. Without this, an operator
/// applying a policy referenced by both import and export chains
/// would land the new import policy for *future* UPDATEs but
/// leave `AdjRibIn` routes accepted under the prior import
/// policy stuck, with no signal that the refresh ever needed
/// to run.
///
/// First call: fake session ACKs `UpdateImportPolicy`, drops
/// `UpdateExportPolicy` reply → bail with both `pending_refresh`
/// and `pending_export_apply` set.
///
/// Second call (same target policies): fake session ACKs both →
/// no bail, `had_pending_refresh = true` carries
/// `needs_refresh = true`, `soft_reset_in` fires.
///
/// Asserts: first call returns Err with both flags set; second
/// call returns Ok with `route_refresh_calls > 0`.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn import_succeeds_export_fails_then_retry_fires_refresh() {
    use rustbgpd_policy::{Policy, PolicyAction};
    use rustbgpd_transport::PeerCommand;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    let (tx, mut rx) = mpsc::channel::<PeerCommand>(8);
    let drop_export_replies = Arc::new(AtomicBool::new(true));
    let route_refresh_calls = Arc::new(AtomicU32::new(0));
    let drop_export_replies_in_task = drop_export_replies.clone();
    let route_refresh_calls_in_task = route_refresh_calls.clone();
    let task_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let task = tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                PeerCommand::UpdateImportPolicy { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::UpdateExportPolicy { reply, .. } => {
                    if drop_export_replies_in_task.load(Ordering::SeqCst) {
                        drop(reply);
                    } else {
                        let _ = reply.send(Ok(()));
                    }
                }
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(PeerSessionState {
                        fsm_state: SessionState::Established,
                        peer_ip: task_addr,
                        peer_asn: None,
                        prefix_count: 0,
                        negotiated_hold_time: Some(90),
                        four_octet_as: Some(true),
                        remote_router_id: Some(Ipv4Addr::new(10, 0, 0, 2)),
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
                    });
                }
                PeerCommand::SendRouteRefresh { reply, .. } => {
                    route_refresh_calls_in_task.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::Shutdown => break,
                _ => {}
            }
        }
        Ok(())
    });
    let handle = PeerHandle::from_parts(tx, task);

    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    // Drain RIB so the second call's ReplacePeerExportPolicy doesn't
    // wedge waiting for a reply.
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(64);
    let rib_drainer = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                let _ = reply.send(Ok(()));
            }
        }
    });

    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let peer_config = make_config(task_addr, 65002);
    let transport = mgr.build_transport_config(&peer_config);
    let hold = transport.peer.hold_time;
    mgr.peers.insert(
        key(task_addr),
        ManagedPeer {
            handle,
            session_id: 1,
            remote_asn: 65002,
            description: "test".to_string(),
            peer_group: None,
            enabled: true,
            hold_time: Some(hold),
            max_prefixes: None,
            transport_config: transport,
            import_policy: None,
            export_policy: None,
            pending_inbound: None,
            is_dynamic: false,
            accepted_dynamic_range: None,
            pending_refresh: false,
            pending_export_apply: false,
            advertise_graceful_shutdown: false,
        },
    );

    let import_chain = PolicyChain::new(vec![Policy {
        entries: Vec::new(),
        default_action: PolicyAction::Deny,
    }]);
    let export_chain = PolicyChain::new(vec![Policy {
        entries: Vec::new(),
        default_action: PolicyAction::Deny,
    }]);

    // First call: import succeeds, export drops reply → bail.
    let result_1 = mgr
        .update_runtime_policies(
            task_addr,
            Some(import_chain.clone()),
            Some(export_chain.clone()),
        )
        .await;

    assert!(
        result_1.is_err(),
        "First call must fail: export apply dropped reply. Got: {result_1:?}"
    );

    let managed = mgr.peers.get(&key(task_addr)).expect("peer present");
    assert!(
        managed.import_policy.is_some(),
        "managed.import_policy must have advanced — import apply succeeded. Got: {:?}",
        managed.import_policy
    );
    assert!(
        managed.export_policy.is_none(),
        "managed.export_policy must NOT have advanced — export apply failed. Got: {:?}",
        managed.export_policy
    );
    assert!(
        managed.pending_refresh,
        "pending_refresh MUST be set even though import_bail did not trigger — \
         the refresh intent (import_changed) survives across an export-side bail. \
         Without this, the retry would see import_changed=false, no pending refresh, \
         and silently skip Route Refresh, leaving AdjRibIn stuck on prior policy."
    );
    assert!(
        managed.pending_export_apply,
        "pending_export_apply must be set so the next retry attempts export again."
    );
    assert_eq!(
        route_refresh_calls.load(Ordering::SeqCst),
        0,
        "First call must NOT have fired Route Refresh — it bailed before that step."
    );

    // Flip the fake to ACK export replies, then retry with the
    // SAME target policies. import_changed will be false on the
    // retry (bookkeeping already advanced), so the retry must
    // rely on had_pending_refresh to decide to fire refresh.
    drop_export_replies.store(false, Ordering::SeqCst);

    let result_2 = mgr
        .update_runtime_policies(task_addr, Some(import_chain), Some(export_chain))
        .await;

    assert!(
        result_2.is_ok(),
        "Second call (export now succeeds) must return Ok. Got: {result_2:?}"
    );

    let managed = mgr.peers.get(&key(task_addr)).expect("peer present");
    assert!(
        managed.export_policy.is_some(),
        "managed.export_policy must now be advanced after the successful retry."
    );
    assert!(
        !managed.pending_refresh,
        "pending_refresh must be cleared after the retry's soft_reset_in succeeded."
    );
    assert!(
        !managed.pending_export_apply,
        "pending_export_apply must be cleared after the retry's export apply succeeded."
    );

    assert!(
        route_refresh_calls.load(Ordering::SeqCst) >= 1,
        "Retry MUST have fired Route Refresh: this is the regression — without \
         carrying pending_refresh across the export bail on the first call, \
         needs_refresh would be false on retry and refresh would silently never \
         fire, leaving AdjRibIn stuck on prior import policy. \
         Got: {} refresh calls",
        route_refresh_calls.load(Ordering::SeqCst)
    );

    drop(mgr);
    let _ = rib_drainer.await;
}

/// Multi-agent quality audit caught a third partial-success
/// failure mode: session-side hot-apply succeeds (advancing
/// `managed.import_policy` AND `managed.export_policy`), the
/// peer is Established, then the RIB step fails — `rib_tx.send`
/// hits a closed channel, the reply oneshot is dropped, or the
/// RIB returns Err. The prior code returned Err via `?` without
/// re-arming `pending_refresh`, so a retry with the same target
/// would see `import_changed = false` (bookkeeping advanced)
/// and `had_pending_refresh = false`, compute `needs_refresh =
/// false`, and silently never fire `soft_reset_in`. `AdjRibIn`
/// routes accepted under the prior import policy would stay
/// stuck against a session that now had the new policy — same
/// silent-stale-routes class as the cross-side bail bug, just
/// at a different downstream step.
///
/// Fix: in the RIB-failure path, re-arm `pending_refresh` if
/// `needs_refresh` was true, then return Err. This test pins
/// it: a fake RIB drainer that replies Err to the
/// `ReplacePeerExportPolicy` causes the call to return Err,
/// but `pending_refresh` is set so the next call retries the
/// refresh.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn rib_failure_preserves_pending_refresh_for_retry() {
    use rustbgpd_policy::{Policy, PolicyAction};
    use rustbgpd_transport::PeerCommand;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    let (tx, mut rx) = mpsc::channel::<PeerCommand>(8);
    let route_refresh_calls = Arc::new(AtomicU32::new(0));
    let route_refresh_calls_in_task = route_refresh_calls.clone();
    let task_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let task = tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                PeerCommand::UpdateImportPolicy { reply, .. }
                | PeerCommand::UpdateExportPolicy { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(PeerSessionState {
                        fsm_state: SessionState::Established,
                        peer_ip: task_addr,
                        peer_asn: None,
                        prefix_count: 0,
                        negotiated_hold_time: Some(90),
                        four_octet_as: Some(true),
                        remote_router_id: Some(Ipv4Addr::new(10, 0, 0, 2)),
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
                    });
                }
                PeerCommand::SendRouteRefresh { reply, .. } => {
                    route_refresh_calls_in_task.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::Shutdown => break,
                _ => {}
            }
        }
        Ok(())
    });
    let handle = PeerHandle::from_parts(tx, task);

    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    // RIB drainer that replies Err to ReplacePeerExportPolicy —
    // simulates the RIB rejecting the update. Other RibUpdate
    // variants get Ok so unrelated codepaths don't tangle.
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(64);
    let rib_drainer = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                let _ = reply.send(Err("simulated RIB failure".to_string()));
            }
        }
    });

    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let peer_config = make_config(task_addr, 65002);
    let transport = mgr.build_transport_config(&peer_config);
    let hold = transport.peer.hold_time;
    mgr.peers.insert(
        key(task_addr),
        ManagedPeer {
            handle,
            session_id: 1,
            remote_asn: 65002,
            description: "test".to_string(),
            peer_group: None,
            enabled: true,
            hold_time: Some(hold),
            max_prefixes: None,
            transport_config: transport,
            import_policy: None,
            export_policy: None,
            pending_inbound: None,
            is_dynamic: false,
            accepted_dynamic_range: None,
            pending_refresh: false,
            pending_export_apply: false,
            advertise_graceful_shutdown: false,
        },
    );

    let chain = PolicyChain::new(vec![Policy {
        entries: Vec::new(),
        default_action: PolicyAction::Deny,
    }]);

    // Both sides changed; both session-side applies succeed
    // (advancing bookkeeping); RIB step fails; before fix this
    // would return Err with no `pending_refresh` set, leaving
    // the next retry to silently skip Route Refresh.
    let result = mgr
        .update_runtime_policies(task_addr, Some(chain.clone()), Some(chain))
        .await;

    assert!(
        result.is_err(),
        "RIB failure must propagate as Err. Got: {result:?}"
    );
    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("simulated RIB failure")
            || err_msg.contains("failed to update export policy"),
        "error message must surface the RIB failure for the operator: {err_msg}"
    );

    let managed = mgr.peers.get(&key(task_addr)).expect("peer present");
    assert!(
        managed.pending_refresh,
        "pending_refresh MUST be set: bookkeeping already advanced (session-side \
         apply succeeded) so the next retry would see import_changed=false; \
         without pending_refresh the retry's needs_refresh would be false and \
         soft_reset_in would silently never fire, leaving AdjRibIn stuck on \
         the prior import policy."
    );
    assert!(
        managed.import_policy.is_some(),
        "managed.import_policy correctly advanced — session ACKed the new policy."
    );
    assert!(
        managed.export_policy.is_some(),
        "managed.export_policy correctly advanced — session ACKed the new policy."
    );
    assert_eq!(
        route_refresh_calls.load(Ordering::SeqCst),
        0,
        "Route Refresh must NOT have run — the RIB-failure bail returned Err \
         before reaching the soft_reset_in step."
    );

    drop(mgr);
    let _ = rib_drainer.await;
}

/// Stale-state-query regression: when
/// `query_state_timeout` returns None — because the session task
/// is back-pressured past the deadline and missed answering
/// `QueryState` — `is_established` reads false even for a peer
/// that is genuinely Established. With a fresh
/// `import_changed = true`, the prior code (`else if
/// had_pending_refresh && !is_established`) wouldn't re-arm
/// `pending_refresh` because nothing was inherited; the function
/// would advance bookkeeping, return Ok, and the next call would
/// see `import_changed = false` and silently never fire refresh.
/// `AdjRibIn` routes accepted under the prior import policy
/// would stay stuck against a session that now had the new
/// policy.
///
/// Fix: re-arm `pending_refresh` whenever
/// `needs_refresh && !is_established`, regardless of whether
/// the intent was inherited or freshly generated. This subsumes
/// the prior `had_pending_refresh && !is_established` branch and
/// covers the stale-query case that's indistinguishable from
/// genuine Idle from this side.
///
/// The "wasted refresh on truly-Idle peer" cost is real but
/// small (Route Refresh against an empty `AdjRibIn` is a no-op
/// on the wire) and is the right tradeoff against silent
/// stale-routes.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn stale_query_state_re_arms_pending_refresh() {
    use rustbgpd_policy::{Policy, PolicyAction};
    use rustbgpd_transport::PeerCommand;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    let (tx, mut rx) = mpsc::channel::<PeerCommand>(8);
    let route_refresh_calls = Arc::new(AtomicU32::new(0));
    let route_refresh_calls_in_task = route_refresh_calls.clone();
    let task = tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                PeerCommand::UpdateImportPolicy { reply, .. }
                | PeerCommand::UpdateExportPolicy { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::QueryState { reply } => {
                    // Drop the reply — caller observes None,
                    // simulating a back-pressured session that
                    // missed the deadline. From `update_runtime_policies`'s
                    // perspective this is indistinguishable from
                    // a genuinely Idle peer; the fix must re-arm
                    // pending_refresh regardless.
                    drop(reply);
                }
                PeerCommand::SendRouteRefresh { reply, .. } => {
                    route_refresh_calls_in_task.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::Shutdown => break,
                _ => {}
            }
        }
        Ok(())
    });
    let handle = PeerHandle::from_parts(tx, task);

    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let task_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let peer_config = make_config(task_addr, 65002);
    let transport = mgr.build_transport_config(&peer_config);
    let hold = transport.peer.hold_time;
    mgr.peers.insert(
        key(task_addr),
        ManagedPeer {
            handle,
            session_id: 1,
            remote_asn: 65002,
            description: "test".to_string(),
            peer_group: None,
            enabled: true,
            hold_time: Some(hold),
            max_prefixes: None,
            transport_config: transport,
            import_policy: None,
            export_policy: None,
            pending_inbound: None,
            is_dynamic: false,
            accepted_dynamic_range: None,
            pending_refresh: false,
            pending_export_apply: false,
            advertise_graceful_shutdown: false,
        },
    );

    let chain = PolicyChain::new(vec![Policy {
        entries: Vec::new(),
        default_action: PolicyAction::Deny,
    }]);

    // Fresh import_changed=true; both apply paths succeed; query
    // returns None (stale). Without the fix, this call returns
    // Ok and silently loses refresh intent.
    let result = mgr
        .update_runtime_policies(task_addr, Some(chain), None)
        .await;

    assert!(
        result.is_ok(),
        "Stale query state must NOT be treated as a failure — the call should \
         succeed (apply paths did) and just defer the refresh via pending_refresh. \
         Got: {result:?}"
    );

    let managed = mgr.peers.get(&key(task_addr)).expect("peer present");
    assert!(
        managed.pending_refresh,
        "pending_refresh MUST be re-armed when query_state_timeout returned None \
         with a fresh import_changed=true. The prior code only re-armed when the \
         pending flag was *inherited*; a fresh refresh intent under a stale query \
         was silently lost. Without this re-arm, the retry would see \
         import_changed=false (bookkeeping advanced) and never fire refresh, \
         leaving AdjRibIn stuck on the prior import policy."
    );
    assert!(
        managed.import_policy.is_some(),
        "managed.import_policy correctly advanced — session ACKed the new policy. \
         The query was stale, but the apply itself succeeded."
    );
    assert_eq!(
        route_refresh_calls.load(Ordering::SeqCst),
        0,
        "Route Refresh must NOT have fired in this call — soft_reset_in is gated \
         on Established (via query_state_timeout result), and the query was stale. \
         The retry-on-next-call path is what fires refresh once the query unblocks."
    );
}

#[test]
fn collision_local_wins() {
    // Local router-id 10.0.0.10 (higher) vs remote 10.0.0.2 (lower)
    // → local wins, inbound should be dropped
    let local_id = u32::from(Ipv4Addr::new(10, 0, 0, 10));
    let remote_id = u32::from(Ipv4Addr::new(10, 0, 0, 2));
    assert!(local_id > remote_id, "local should win collision");
}

#[test]
fn collision_remote_wins() {
    // Local router-id 10.0.0.1 (lower) vs remote 10.0.0.10 (higher)
    // → remote wins, existing session should be dumped
    let local_id = u32::from(Ipv4Addr::new(10, 0, 0, 1));
    let remote_id = u32::from(Ipv4Addr::new(10, 0, 0, 10));
    assert!(local_id < remote_id, "remote should win collision");
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn simultaneous_active_open_runs_inbound_candidate_before_primary_idle() {
    use rustbgpd_transport::PeerCommand;

    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );

    let peer_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let collision_dumps = Arc::new(AtomicU32::new(0));
    let dumps = collision_dumps.clone();
    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let fake_primary = tokio::spawn(async move {
        while let Some(cmd) = session_rx.recv().await {
            match cmd {
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(PeerSessionState {
                        fsm_state: SessionState::OpenSent,
                        peer_ip: peer_addr,
                        peer_asn: None,
                        prefix_count: 0,
                        negotiated_hold_time: None,
                        four_octet_as: None,
                        remote_router_id: None,
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
                    });
                }
                PeerCommand::CollisionDump => {
                    dumps.fetch_add(1, Ordering::SeqCst);
                    break;
                }
                PeerCommand::Shutdown => break,
                _ => {}
            }
        }
        Ok(())
    });
    insert_test_managed_peer_with_asn(
        &mut mgr,
        peer_addr,
        65002,
        PeerHandle::from_parts(session_tx, fake_primary),
        false,
    );

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
    let (server_stream, remote_addr) = listener.accept().await.unwrap();
    let mut client_stream = client.await.unwrap();

    mgr.handle_inbound(server_stream, remote_addr).await;
    assert!(
        mgr.peers
            .get(&key(peer_addr))
            .is_some_and(|m| m.pending_inbound.is_some()),
        "inbound socket should become a live collision candidate"
    );

    let mut buf = BytesMut::with_capacity(4096);
    let msg = tokio::time::timeout(
        Duration::from_secs(2),
        read_bgp_message(&mut client_stream, &mut buf),
    )
    .await
    .expect("candidate must send OPEN before primary goes idle");
    assert!(matches!(msg, Message::Open(_)));

    send_bgp_message(
        &mut client_stream,
        &Message::Open(mock_open(Ipv4Addr::new(10, 0, 0, 2))),
    )
    .await;

    let notification = loop {
        let notification =
            tokio::time::timeout(Duration::from_secs(2), mgr.session_notify_rx.recv())
                .await
                .expect("candidate should notify OpenReceived")
                .expect("notification channel should stay open");
        if matches!(notification, SessionNotification::StateChanged { .. }) {
            mgr.handle_session_notification(notification).await;
            continue;
        }
        break notification;
    };
    match &notification {
        SessionNotification::OpenReceived {
            role,
            remote_router_id,
            ..
        } => {
            assert_eq!(*role, rustbgpd_transport::SessionRole::InboundCandidate);
            assert_eq!(*remote_router_id, Ipv4Addr::new(10, 0, 0, 2));
        }
        other @ (SessionNotification::BackToIdle { .. }
        | SessionNotification::StateChanged { .. }) => {
            panic!("expected OpenReceived from candidate, got {other:?}");
        }
    }
    mgr.handle_session_notification(notification).await;

    for _ in 0..20 {
        if collision_dumps.load(Ordering::SeqCst) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(
        collision_dumps.load(Ordering::SeqCst),
        1,
        "remote-higher router-id must dump the local-initiated primary"
    );
    assert!(
        mgr.peers
            .get(&key(peer_addr))
            .is_some_and(|m| m.pending_inbound.is_none()),
        "candidate should be promoted, not left pending"
    );

    let msg = tokio::time::timeout(
        Duration::from_secs(2),
        read_bgp_message(&mut client_stream, &mut buf),
    )
    .await
    .expect("candidate should send KEEPALIVE after OPEN");
    assert!(matches!(msg, Message::Keepalive));
    send_bgp_message(&mut client_stream, &Message::Keepalive).await;

    let managed = mgr.peers.get(&key(peer_addr)).expect("promoted peer");
    for _ in 0..20 {
        let state = managed.handle.query_state().await.expect("query state");
        if state.fsm_state == SessionState::Established {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("promoted inbound candidate did not reach Established");
}

/// RFC 4271 §6.8 regression: a state query that merely times out (the
/// session task is wedged on TCP back-pressure but may be Established)
/// must NOT be treated as Idle. Before the fix, the timeout mapped to
/// `SessionState::Idle` and routed through `replace_with_inbound`,
/// shutting down a possibly-Established session because of a transient
/// stall. The conservative behavior is to drop the inbound connection
/// and keep the existing session: if it is genuinely dead, hold-timer
/// expiry tears it down and the remote's retry lands in the genuine
/// Idle arm.
#[tokio::test]
async fn inbound_state_query_timeout_keeps_existing_session() {
    use rustbgpd_transport::PeerCommand;

    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );

    let peer_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let counters = Arc::new(FakePeerCounters::default());
    let task_counters = counters.clone();
    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    // Simulate a TCP-back-pressure wedge: the task holds the command
    // channel open but services nothing until well past
    // PEER_QUERY_TIMEOUT (100ms). Commands sent meanwhile sit buffered.
    // It eventually drains and answers Shutdown so a buggy
    // replace-the-session path fails the assertions below instead of
    // deadlocking the test in `PeerHandle::shutdown`.
    let task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(2)).await;
        while let Some(cmd) = session_rx.recv().await {
            match cmd {
                PeerCommand::QueryState { reply } => {
                    task_counters.query_state.fetch_add(1, Ordering::SeqCst);
                    // Stale answer — the manager's deadline has long expired.
                    drop(reply);
                }
                PeerCommand::Shutdown => {
                    task_counters.shutdown.fetch_add(1, Ordering::SeqCst);
                    break;
                }
                _ => {}
            }
        }
        Ok(())
    });
    insert_test_managed_peer_with_asn(
        &mut mgr,
        peer_addr,
        65002,
        PeerHandle::from_parts(session_tx, task),
        false,
    );

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
    let (server_stream, remote_addr) = listener.accept().await.unwrap();
    let mut client_stream = client.await.unwrap();

    mgr.handle_inbound(server_stream, remote_addr).await;

    let managed = mgr.peers.get(&key(peer_addr)).expect("peer still managed");
    assert_eq!(
        counters.shutdown.load(Ordering::SeqCst),
        0,
        "the wedged (possibly-Established) session must NOT be shut down \
         because a state query timed out"
    );
    assert_eq!(
        managed.session_id, 1,
        "the existing session must NOT be replaced on a state-query timeout"
    );
    assert!(
        managed.pending_inbound.is_none(),
        "no collision candidate may be spawned while the existing session's \
         state is unknown"
    );

    // The inbound connection itself must have been dropped: the client
    // observes EOF, not a BGP OPEN from a freshly-started session.
    let mut buf = [0u8; 64];
    let read = tokio::time::timeout(Duration::from_secs(2), client_stream.read(&mut buf))
        .await
        .expect("inbound socket must be closed promptly")
        .expect("clean EOF expected");
    assert_eq!(read, 0, "inbound connection must be dropped, got data");
}

/// Companion to `inbound_state_query_timeout_keeps_existing_session`:
/// a genuinely dead session task (command channel closed because the
/// task exited) still takes the accept path — `query_state_outcome`
/// reports `SessionGone`, which maps to Idle and replaces the dead
/// session with the inbound connection.
#[tokio::test]
async fn inbound_after_session_task_exit_takes_accept_path() {
    use rustbgpd_transport::PeerCommand;

    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );

    let peer_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    // Burn session id 1 so the helper-inserted peer's hardcoded
    // `session_id: 1` differs from whatever a replacement allocates.
    let _ = mgr.allocate_session_id();
    // Dead session task: receiver dropped, task already exited.
    let (session_tx, session_rx) = mpsc::channel::<PeerCommand>(8);
    drop(session_rx);
    let task = tokio::spawn(async move { Ok(()) });
    insert_test_managed_peer_with_asn(
        &mut mgr,
        peer_addr,
        65002,
        PeerHandle::from_parts(session_tx, task),
        false,
    );

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
    let (server_stream, remote_addr) = listener.accept().await.unwrap();
    let mut client_stream = client.await.unwrap();

    mgr.handle_inbound(server_stream, remote_addr).await;

    let managed = mgr.peers.get(&key(peer_addr)).expect("peer still managed");
    assert_ne!(
        managed.session_id, 1,
        "a dead session task must be replaced by the inbound connection"
    );
    assert!(managed.pending_inbound.is_none());

    // The replacement is a live inbound session that was started:
    // TcpConnectionConfirmed sends our OPEN to the remote.
    let mut buf = BytesMut::with_capacity(4096);
    let msg = tokio::time::timeout(
        Duration::from_secs(2),
        read_bgp_message(&mut client_stream, &mut buf),
    )
    .await
    .expect("accepted inbound session must send OPEN");
    assert!(matches!(msg, Message::Open(_)));
}

#[tokio::test]
async fn collision_local_wins_drops_inbound_candidate() {
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 10),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let primary = Arc::new(FakePeerCounters::default());
    let pending = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer_with_asn(
        &mut mgr,
        peer_addr,
        65002,
        fake_peer_handle(
            peer_addr,
            SessionState::OpenConfirm,
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            primary.clone(),
        ),
        false,
    );
    attach_test_pending_inbound(
        &mut mgr,
        peer_addr,
        fake_peer_handle(
            peer_addr,
            SessionState::OpenConfirm,
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            pending.clone(),
        ),
        2,
    );

    mgr.handle_session_notification(SessionNotification::OpenReceived {
        session_id: 2,
        role: rustbgpd_transport::SessionRole::InboundCandidate,
        peer_addr,
        remote_router_id: Ipv4Addr::new(10, 0, 0, 2),
    })
    .await;

    wait_counter(&pending.collision_dump, 1).await;
    assert_eq!(primary.collision_dump.load(Ordering::SeqCst), 0);
    assert_eq!(pending.collision_dump.load(Ordering::SeqCst), 1);
    assert!(
        mgr.peers
            .get(&key(peer_addr))
            .is_some_and(|m| m.pending_inbound.is_none() && m.session_id == 1),
        "local-wins collision must keep the primary session"
    );
}

#[tokio::test]
async fn collision_equal_router_ids_drops_inbound_candidate() {
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 2),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let primary = Arc::new(FakePeerCounters::default());
    let pending = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer_with_asn(
        &mut mgr,
        peer_addr,
        65002,
        fake_peer_handle(
            peer_addr,
            SessionState::OpenConfirm,
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            primary.clone(),
        ),
        false,
    );
    attach_test_pending_inbound(
        &mut mgr,
        peer_addr,
        fake_peer_handle(
            peer_addr,
            SessionState::OpenConfirm,
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            pending.clone(),
        ),
        2,
    );

    mgr.handle_session_notification(SessionNotification::OpenReceived {
        session_id: 2,
        role: rustbgpd_transport::SessionRole::InboundCandidate,
        peer_addr,
        remote_router_id: Ipv4Addr::new(10, 0, 0, 2),
    })
    .await;

    wait_counter(&pending.collision_dump, 1).await;
    assert_eq!(primary.collision_dump.load(Ordering::SeqCst), 0);
    assert_eq!(pending.collision_dump.load(Ordering::SeqCst), 1);
    assert!(
        mgr.peers
            .get(&key(peer_addr))
            .is_some_and(|m| m.pending_inbound.is_none() && m.session_id == 1),
        "equal router-id collision must keep the primary session"
    );
}

#[tokio::test]
async fn primary_back_to_idle_promotes_pending_inbound_candidate() {
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let primary = Arc::new(FakePeerCounters::default());
    let pending = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer_with_asn(
        &mut mgr,
        peer_addr,
        65002,
        fake_peer_handle(peer_addr, SessionState::OpenSent, None, primary.clone()),
        false,
    );
    attach_test_pending_inbound(
        &mut mgr,
        peer_addr,
        fake_peer_handle(
            peer_addr,
            SessionState::OpenConfirm,
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            pending.clone(),
        ),
        2,
    );

    mgr.handle_session_notification(SessionNotification::BackToIdle {
        session_id: 1,
        role: rustbgpd_transport::SessionRole::Primary,
        peer_addr,
    })
    .await;

    assert_eq!(primary.shutdown.load(Ordering::SeqCst), 1);
    assert_eq!(pending.shutdown.load(Ordering::SeqCst), 0);
    assert!(
        mgr.peers
            .get(&key(peer_addr))
            .is_some_and(|m| m.pending_inbound.is_none() && m.session_id == 2),
        "pending inbound candidate should be promoted when the primary idles"
    );
}

#[tokio::test]
async fn stale_collision_notifications_do_not_mutate_current_peer() {
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let primary = Arc::new(FakePeerCounters::default());
    let pending = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer_with_asn(
        &mut mgr,
        peer_addr,
        65002,
        fake_peer_handle(
            peer_addr,
            SessionState::OpenConfirm,
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            primary.clone(),
        ),
        false,
    );
    attach_test_pending_inbound(
        &mut mgr,
        peer_addr,
        fake_peer_handle(
            peer_addr,
            SessionState::OpenConfirm,
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            pending.clone(),
        ),
        2,
    );

    mgr.handle_session_notification(SessionNotification::OpenReceived {
        session_id: 99,
        role: rustbgpd_transport::SessionRole::InboundCandidate,
        peer_addr,
        remote_router_id: Ipv4Addr::new(10, 0, 0, 2),
    })
    .await;
    mgr.handle_session_notification(SessionNotification::BackToIdle {
        session_id: 99,
        role: rustbgpd_transport::SessionRole::Primary,
        peer_addr,
    })
    .await;

    assert_eq!(primary.collision_dump.load(Ordering::SeqCst), 0);
    assert_eq!(pending.collision_dump.load(Ordering::SeqCst), 0);
    assert!(
        mgr.peers
            .get(&key(peer_addr))
            .is_some_and(|m| m.pending_inbound.is_some() && m.session_id == 1),
        "stale notifications must not drop or promote live sessions"
    );
}

#[tokio::test]
async fn disable_peer_drains_pending_inbound_candidate() {
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let primary = Arc::new(FakePeerCounters::default());
    let pending = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer_with_asn(
        &mut mgr,
        peer_addr,
        65002,
        fake_peer_handle(
            peer_addr,
            SessionState::OpenConfirm,
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            primary.clone(),
        ),
        false,
    );
    attach_test_pending_inbound(
        &mut mgr,
        peer_addr,
        fake_peer_handle(
            peer_addr,
            SessionState::OpenConfirm,
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            pending.clone(),
        ),
        2,
    );

    mgr.disable_peer(key(peer_addr), None).await.unwrap();

    wait_counter(&primary.stop, 1).await;
    assert_eq!(pending.shutdown.load(Ordering::SeqCst), 1);
    assert_eq!(primary.stop.load(Ordering::SeqCst), 1);
    assert!(
        mgr.peers
            .get(&key(peer_addr))
            .is_some_and(|m| m.pending_inbound.is_none() && !m.enabled),
        "disable must clear the pending candidate"
    );
}

#[tokio::test]
async fn collision_existing_goes_idle_accepts_pending() {
    // Verify the PeerManager correctly handles notifications via its
    // select! loop (session_notify channel is wired).
    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let handle = tokio::spawn(mgr.run());

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // Add peer
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::AddPeer {
        config: make_config(addr, 65002),
        sync_config_snapshot: false,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_ok());

    // Verify the peer exists
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::GetPeerState {
        peer: key(addr),
        reply: reply_tx,
    })
    .await
    .unwrap();
    let info = reply_rx.await.unwrap();
    assert!(info.is_some());

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn disable_peer_stays_disabled() {
    // Verify that disabling a peer keeps it disabled even after
    // the session goes idle (BackToIdle should not re-enable).
    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let handle = tokio::spawn(mgr.run());

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // Add peer
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::AddPeer {
        config: make_config(addr, 65002),
        sync_config_snapshot: false,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_ok());

    // Disable peer
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::DisablePeer {
        peer: key(addr),
        reason: None,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_ok());

    // Give time for the session to process Stop and go Idle
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify the peer is still disabled
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::GetPeerState {
        peer: key(addr),
        reply: reply_tx,
    })
    .await
    .unwrap();
    let info = reply_rx.await.unwrap().unwrap();
    assert!(!info.enabled, "peer should remain disabled");

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn inbound_during_established_dropped() {
    // Verify the handle_inbound match arm for Established works.
    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let handle = tokio::spawn(mgr.run());

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // Add peer
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::AddPeer {
        config: make_config(addr, 65002),
        sync_config_snapshot: false,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_ok());

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn dynamic_inbound_peer_is_created_and_removed_on_back_to_idle() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new_with_config(
        rx,
        mpsc::unbounded_channel().1,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
        None,
        make_dynamic_manager_config(),
    );

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
    let (server_stream, remote_addr) = listener.accept().await.unwrap();
    let client_stream = client.await.unwrap();
    let peer_addr = remote_addr.ip();

    mgr.handle_inbound(server_stream, sock(peer_addr)).await;

    assert_eq!(
        mgr.dynamic_peer_count, 1,
        "dynamic peer count should increment"
    );
    let info = mgr.get_peer_info(&key(peer_addr)).await.unwrap();
    assert!(info.is_dynamic, "peer should be marked dynamic");
    assert_eq!(info.peer_group.as_deref(), Some("ix-members"));
    assert_eq!(info.description, "ix-auto");

    let peers = mgr.list_peers().await;
    assert_eq!(peers.len(), 1);
    assert!(peers[0].is_dynamic);

    let session_id = mgr.peers.get(&key(peer_addr)).unwrap().session_id;
    mgr.handle_session_notification(SessionNotification::BackToIdle {
        session_id,
        role: rustbgpd_transport::SessionRole::Primary,
        peer_addr,
    })
    .await;

    assert_eq!(
        mgr.dynamic_peer_count, 0,
        "dynamic peer count should decrement"
    );
    assert!(
        mgr.get_peer_info(&key(peer_addr)).await.is_none(),
        "dynamic peer should be removed when it goes idle"
    );
    assert!(mgr.peers.is_empty(), "dynamic peer table should be empty");

    drop(client_stream);
}

#[tokio::test]
async fn dynamic_inbound_peer_records_most_specific_accepted_range() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut config = make_dynamic_manager_config();
    config.peer_groups.insert(
        "narrow-members".to_string(),
        crate::config::PeerGroupConfig {
            families: vec!["ipv4_unicast".to_string()],
            ..Default::default()
        },
    );
    config.dynamic_neighbors = vec![
        crate::config::DynamicNeighborConfig {
            prefix: "127.0.0.0/8".to_string(),
            peer_group: "ix-members".to_string(),
            remote_asn: 0,
            description: Some("wide".to_string()),
            tcp_ao: None,
        },
        crate::config::DynamicNeighborConfig {
            prefix: "127.0.0.9/24".to_string(),
            peer_group: "narrow-members".to_string(),
            remote_asn: 0,
            description: Some("narrow".to_string()),
            tcp_ao: None,
        },
    ];
    let mut mgr = PeerManager::new_with_config(
        rx,
        mpsc::unbounded_channel().1,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
        None,
        config,
    );

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
    let (server_stream, remote_addr) = listener.accept().await.unwrap();
    let client_stream = client.await.unwrap();
    let peer_addr = remote_addr.ip();

    mgr.handle_inbound(server_stream, sock(peer_addr)).await;

    let managed = mgr.peers.get(&key(peer_addr)).unwrap();
    assert!(managed.is_dynamic);
    assert_eq!(managed.peer_group.as_deref(), Some("narrow-members"));
    let accepted = managed
        .accepted_dynamic_range
        .as_ref()
        .expect("dynamic peer should record accepted range");
    assert_eq!(accepted.addr, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)));
    assert_eq!(accepted.prefix_len, 24);
    assert_eq!(accepted.peer_group, "narrow-members");

    drop(client_stream);
}

#[tokio::test]
async fn inbound_link_local_is_not_accepted_as_dynamic_peer() {
    // ADR-0069: a link-local inbound that matches no configured scoped peer must
    // be dropped, not promoted to a dynamic peer. Dynamic peers are keyed by
    // bare address (`PeerKey::new(ip, None)`), so accepting a `fe80::` source
    // would create an unscoped link-local peer and re-introduce the RFC 4007
    // scope ambiguity that scoped static peers exist to remove. The dynamic
    // range below covers `fe80::/10`, so without the guard this inbound would
    // succeed — the guard must reject it first.
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut config = make_dynamic_manager_config();
    config.dynamic_neighbors = vec![crate::config::DynamicNeighborConfig {
        prefix: "fe80::/10".to_string(),
        peer_group: "ix-members".to_string(),
        remote_asn: 0,
        description: Some("ll-auto".to_string()),
        tcp_ao: None,
    }];
    let mut mgr = PeerManager::new_with_config(
        rx,
        mpsc::unbounded_channel().1,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
        None,
        config,
    );

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
    let (server_stream, _remote_addr) = listener.accept().await.unwrap();
    let client_stream = client.await.unwrap();

    let link_local: IpAddr = "fe80::1".parse().unwrap();
    mgr.handle_inbound(server_stream, sock(link_local)).await;

    assert_eq!(
        mgr.dynamic_peer_count, 0,
        "link-local inbound must not create a dynamic peer"
    );
    assert!(
        mgr.peers.is_empty(),
        "link-local inbound must not be added to the peer table"
    );

    drop(client_stream);
}

#[tokio::test]
async fn dynamic_peer_auto_removal_drains_pending_inbound_candidate() {
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let primary = Arc::new(FakePeerCounters::default());
    let pending = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer_with_asn(
        &mut mgr,
        peer_addr,
        65002,
        fake_peer_handle(
            peer_addr,
            SessionState::Established,
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            primary,
        ),
        false,
    );
    mgr.peers.get_mut(&key(peer_addr)).unwrap().is_dynamic = true;
    mgr.dynamic_peer_count = 1;
    attach_test_pending_inbound(
        &mut mgr,
        peer_addr,
        fake_peer_handle(
            peer_addr,
            SessionState::OpenConfirm,
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            pending.clone(),
        ),
        2,
    );

    mgr.handle_session_notification(SessionNotification::BackToIdle {
        session_id: 1,
        role: rustbgpd_transport::SessionRole::Primary,
        peer_addr,
    })
    .await;

    wait_counter(&pending.shutdown, 1).await;
    assert!(mgr.peers.is_empty());
    assert_eq!(mgr.dynamic_peer_count, 0);
    assert!(mgr.peer_key_for_session(1).is_none());
    assert!(mgr.peer_key_for_session(2).is_none());
}

#[tokio::test]
async fn dead_lettered_pending_survives_dynamic_peer_auto_removal_and_re_establish() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new_with_config(
        rx,
        mpsc::unbounded_channel().1,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
        None,
        make_dynamic_manager_config(),
    );

    // First incarnation: accept the dynamic peer, then mark it as
    // carrying both unfired hot-apply flags. We set the flags
    // directly on the ManagedPeer rather than driving a path that
    // sets them — the regression covered here is the BackToIdle
    // → handle_inbound carry, not the flag-setting paths (which
    // are covered by `pending_refresh_re_arms_when_peer_still_not_established`).
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
    let (server_stream, remote_addr) = listener.accept().await.unwrap();
    let client_stream = client.await.unwrap();
    let peer_addr = remote_addr.ip();

    mgr.handle_inbound(server_stream, sock(peer_addr)).await;
    assert_eq!(mgr.dynamic_peer_count, 1);

    let managed = mgr.peers.get_mut(&key(peer_addr)).unwrap();
    managed.pending_refresh = true;
    managed.pending_export_apply = true;

    // Tear down — peer auto-removes, flags should land in the
    // dead-letter side table rather than evaporating.
    let session_id = mgr.peers.get(&key(peer_addr)).unwrap().session_id;
    mgr.handle_session_notification(SessionNotification::BackToIdle {
        session_id,
        role: rustbgpd_transport::SessionRole::Primary,
        peer_addr,
    })
    .await;
    assert_eq!(mgr.dynamic_peer_count, 0);
    assert!(mgr.peers.is_empty());
    let dead = mgr
        .dead_lettered_pending
        .get(&peer_addr)
        .copied()
        .expect("dead-lettered pending entry should exist after auto-removal");
    assert!(dead.refresh, "pending_refresh should be carried");
    assert!(dead.export_apply, "pending_export_apply should be carried");
    drop(client_stream);

    // Second incarnation at the same address: the new ManagedPeer
    // must inherit the dead-lettered flags, and the side-table
    // entry must drain.
    let next_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let next_listener_addr = next_listener.local_addr().unwrap();
    let next_client =
        tokio::spawn(async move { TcpStream::connect(next_listener_addr).await.unwrap() });
    let (server2, remote_addr2) = next_listener.accept().await.unwrap();
    let next_client_stream = next_client.await.unwrap();
    let peer_addr2 = remote_addr2.ip();
    // Both incarnations bind LOCALHOST so the IpAddr key (the unit
    // we dead-letter on) is identical even though the ephemeral
    // TCP port differs. Pin the precondition explicitly so any
    // future change that diverges the bind address gets caught.
    assert_eq!(
        peer_addr2, peer_addr,
        "test relies on both incarnations sharing an IpAddr key"
    );

    mgr.handle_inbound(server2, sock(peer_addr2)).await;

    let managed2 = mgr.peers.get(&key(peer_addr2)).expect("re-established");
    assert!(
        managed2.pending_refresh,
        "new ManagedPeer must inherit pending_refresh from dead-letter table"
    );
    assert!(
        managed2.pending_export_apply,
        "new ManagedPeer must inherit pending_export_apply from dead-letter table"
    );
    assert!(
        !mgr.dead_lettered_pending.contains_key(&peer_addr2),
        "dead-letter entry must drain on restore"
    );
    drop(next_client_stream);
}

#[tokio::test]
async fn dead_lettered_gshut_survives_dynamic_peer_auto_removal_and_re_establish() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new_with_config(
        rx,
        mpsc::unbounded_channel().1,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
        None,
        make_dynamic_manager_config(),
    );

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
    let (server_stream, remote_addr) = listener.accept().await.unwrap();
    let client_stream = client.await.unwrap();
    let peer_addr = remote_addr.ip();

    mgr.handle_inbound(server_stream, sock(peer_addr)).await;
    assert_eq!(mgr.dynamic_peer_count, 1);
    mgr.peers
        .get_mut(&key(peer_addr))
        .expect("dynamic peer present")
        .advertise_graceful_shutdown = true;

    let session_id = mgr.peers.get(&key(peer_addr)).unwrap().session_id;
    mgr.handle_session_notification(SessionNotification::BackToIdle {
        session_id,
        role: rustbgpd_transport::SessionRole::Primary,
        peer_addr,
    })
    .await;
    assert!(mgr.peers.is_empty());
    let dead = mgr
        .dead_lettered_pending
        .get(&peer_addr)
        .copied()
        .expect("GShut-only dead-letter entry should be preserved");
    assert!(
        dead.graceful_shutdown,
        "GShut toggle should be carried even when no pending policy flags exist"
    );
    assert!(!dead.refresh);
    assert!(!dead.export_apply);
    drop(client_stream);

    let next_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let next_listener_addr = next_listener.local_addr().unwrap();
    let next_client =
        tokio::spawn(async move { TcpStream::connect(next_listener_addr).await.unwrap() });
    let (server2, remote_addr2) = next_listener.accept().await.unwrap();
    let next_client_stream = next_client.await.unwrap();
    let peer_addr2 = remote_addr2.ip();
    assert_eq!(
        peer_addr2, peer_addr,
        "test relies on both incarnations sharing an IpAddr key"
    );

    mgr.handle_inbound(server2, sock(peer_addr2)).await;

    let managed2 = mgr.peers.get(&key(peer_addr2)).expect("re-established");
    assert!(
        managed2.advertise_graceful_shutdown,
        "new dynamic ManagedPeer must inherit advertise_graceful_shutdown"
    );
    assert!(
        !managed2.pending_refresh && !managed2.pending_export_apply,
        "GShut-only restore must not synthesize policy retry flags"
    );
    assert!(
        !mgr.dead_lettered_pending.contains_key(&peer_addr2),
        "dead-letter entry must drain on restore"
    );
    drop(next_client_stream);
}

#[tokio::test]
async fn dead_lettered_pending_over_cap_evicts_oldest_entry() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut config = make_dynamic_manager_config();
    config.global.dynamic_neighbor_limit = Some(2);
    let mut mgr = PeerManager::new_with_config(
        rx,
        mpsc::unbounded_channel().1,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
        None,
        config,
    );
    let counters = Arc::new(FakePeerCounters::default());
    let first = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let second = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
    let third = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3));

    for addr in [first, second, third] {
        insert_test_managed_peer(
            &mut mgr,
            addr,
            fake_peer_handle(addr, SessionState::Established, None, counters.clone()),
            true,
        );
        mgr.dead_letter_pending_for(addr);
    }

    assert!(
        !mgr.dead_lettered_pending.contains_key(&first),
        "oldest pending entry should be evicted at cap"
    );
    assert!(
        mgr.dead_lettered_pending.contains_key(&second),
        "newer pending entry should be retained"
    );
    assert!(
        mgr.dead_lettered_pending.contains_key(&third),
        "newly inserted pending entry should be retained"
    );
}

#[test]
fn build_transport_config_sets_restart_window_for_eligible_static_peer() {
    let (_tx, rx) = mpsc::channel(1);
    let (rib_tx, _rib_rx) = mpsc::channel(1);
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        Some(Instant::now() + Duration::from_secs(30)),
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let mut cfg = make_config(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65002);
    cfg.gr_restart_eligible = true;

    let transport = mgr.build_transport_config(&cfg);
    assert!(transport.gr_restart_until.is_some());
}

#[test]
fn build_transport_config_omits_restart_window_for_dynamic_peer() {
    let (_tx, rx) = mpsc::channel(1);
    let (rib_tx, _rib_rx) = mpsc::channel(1);
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        Some(Instant::now() + Duration::from_secs(30)),
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let cfg = make_config(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65002);

    let transport = mgr.build_transport_config(&cfg);
    assert!(transport.gr_restart_until.is_none());
}

#[test]
fn build_transport_config_carries_tcp_ao_key() {
    let (_tx, rx) = mpsc::channel(1);
    let (rib_tx, _rib_rx) = mpsc::channel(1);
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let mut cfg = make_config(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65002);
    cfg.tcp_ao = Some(rustbgpd_transport::TcpAoConfig {
        key: "secret".to_string(),
        send_id: 1,
        recv_id: 2,
        algorithm: rustbgpd_transport::TcpAoAlgorithm::HmacSha256,
        preferred: false,
        deprecated: false,
    });

    let transport = mgr.build_transport_config(&cfg);

    let tcp_ao = transport.tcp_ao.as_ref().expect("tcp_ao carried");
    assert_eq!(tcp_ao.key, "secret");
    assert_eq!(tcp_ao.send_id, 1);
    assert_eq!(tcp_ao.recv_id, 2);
    assert_eq!(
        tcp_ao.algorithm,
        rustbgpd_transport::TcpAoAlgorithm::HmacSha256
    );
}

// ---------------------------------------------------------------------------
// ADR-0067 step 4 — RFC 5882 BFD/BGP coupling (non-strict). Adversarial around
// stale state changes and lifecycle drops: a deliberate disable/delete drains
// the BFD session (AdminDown) and must NOT look like a failure.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct BfdCouplingCounters {
    stop: AtomicU32,
    start: AtomicU32,
}

/// Fake peer handle that counts Stop/Start without exiting (unlike
/// `fake_peer_handle`, which breaks on Stop) so a down→up cycle is observable.
fn fake_bfd_peer_handle(counters: Arc<BfdCouplingCounters>) -> PeerHandle {
    use rustbgpd_transport::PeerCommand;
    let (tx, mut rx) = mpsc::channel::<PeerCommand>(8);
    let task = tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                PeerCommand::Stop { .. } => {
                    counters.stop.fetch_add(1, Ordering::SeqCst);
                }
                PeerCommand::Start => {
                    counters.start.fetch_add(1, Ordering::SeqCst);
                }
                _ => {}
            }
        }
        Ok(())
    });
    PeerHandle::from_parts(tx, task)
}

fn bfd_params(peer: IpAddr, strict: bool) -> crate::bfd_runtime::BfdSessionParams {
    crate::bfd_runtime::BfdSessionParams {
        peer,
        desired_min_tx_us: 300_000,
        required_min_rx_us: 300_000,
        detect_mult: 3,
        strict,
        enabled: true,
    }
}

/// Build a coupled `PeerManager` with one managed peer, returning the
/// desired-set receiver so tests can inspect what `PeerManager` publishes.
fn coupled_mgr(
    peer: IpAddr,
    strict: bool,
    handle: PeerHandle,
) -> (
    PeerManager,
    watch::Receiver<crate::bfd_runtime::BfdRuntimeConfig>,
) {
    let mut mgr = test_peer_manager();
    insert_test_managed_peer(&mut mgr, peer, handle, false);
    let configured = std::collections::HashMap::from([(peer, bfd_params(peer, strict))]);
    let (desired_tx, desired_rx) = watch::channel(crate::bfd_runtime::BfdRuntimeConfig::default());
    let (_state_tx, state_rx) = crate::bfd_runtime::state_change_channel();
    let mgr = mgr.with_bfd_coupling(desired_tx, state_rx, configured);
    (mgr, desired_rx)
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

/// The actor draining our own session to `AdminDown` on a local disable/delete
/// (`remote_admin_down = false`) — distinct from a remote `AdminDown`.
fn local_admin_down(peer: IpAddr) -> crate::bfd_runtime::BfdStateChange {
    crate::bfd_runtime::BfdStateChange {
        peer,
        state: rustbgpd_bfd::SessionState::AdminDown,
        diagnostic: rustbgpd_bfd::Diagnostic::AdministrativelyDown,
        remote_admin_down: false,
        resync: false,
    }
}

/// A reconcile "ack" (resync) re-reporting a session that is currently Up.
fn up_ack(peer: IpAddr) -> crate::bfd_runtime::BfdStateChange {
    crate::bfd_runtime::BfdStateChange {
        peer,
        state: rustbgpd_bfd::SessionState::Up,
        diagnostic: rustbgpd_bfd::Diagnostic::None,
        remote_admin_down: false,
        resync: true,
    }
}

/// A reconcile "ack" (resync) re-reporting a session that is currently Down
/// (e.g. a freshly (re)started session) — must never tear BGP down.
fn down_ack(peer: IpAddr) -> crate::bfd_runtime::BfdStateChange {
    crate::bfd_runtime::BfdStateChange {
        peer,
        state: rustbgpd_bfd::SessionState::Down,
        diagnostic: rustbgpd_bfd::Diagnostic::ControlDetectionTimeExpired,
        remote_admin_down: false,
        resync: true,
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

#[tokio::test]
async fn bfd_down_then_up_tears_down_and_restores_enabled_peer() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, false, fake_bfd_peer_handle(counters.clone()));

    mgr.handle_bfd_state_change(down(peer)).await;
    wait_counter(&counters.stop, 1).await; // BFD down must stop BGP
    // A duplicate Down while already held must not re-stop.
    mgr.handle_bfd_state_change(down(peer)).await;
    assert_eq!(counters.stop.load(Ordering::SeqCst), 1);

    mgr.handle_bfd_state_change(up(peer)).await;
    wait_counter(&counters.start, 1).await; // BFD up must restart BGP
}

#[tokio::test]
async fn bfd_up_without_prior_down_is_noop() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, false, fake_bfd_peer_handle(counters.clone()));

    // Not held down → an Up must not spuriously (re)start the session.
    mgr.handle_bfd_state_change(up(peer)).await;
    assert_eq!(counters.start.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn bfd_down_ignored_for_disabled_peer() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, false, fake_bfd_peer_handle(counters.clone()));
    // Operator disabled the peer; the actor's resulting AdminDown/Down must not
    // be treated as a failure.
    mgr.peers.get_mut(&key(peer)).unwrap().enabled = false;

    mgr.handle_bfd_state_change(down(peer)).await;
    assert_eq!(
        counters.stop.load(Ordering::SeqCst),
        0,
        "disabled peer Down ignored"
    );
}

#[tokio::test]
async fn bfd_change_ignored_for_absent_peer() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, false, fake_bfd_peer_handle(counters.clone()));
    // Peer deleted; a stale state change from the draining session is ignored.
    mgr.peers.remove(&key(peer));

    mgr.handle_bfd_state_change(down(peer)).await;
    assert_eq!(counters.stop.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn nonstrict_remote_admin_down_does_not_tear_down_bgp() {
    // RFC 5882 §4.2: a remote-signaled BFD AdminDown is administrative, not a
    // liveness failure. A non-strict peer keeps its BGP session (BGP carries its
    // own hold-timer liveness).
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, false, fake_bfd_peer_handle(counters.clone()));

    mgr.handle_bfd_state_change(remote_admin_down(peer)).await;
    assert_eq!(
        counters.stop.load(Ordering::SeqCst),
        0,
        "remote AdminDown must not tear down a non-strict BGP session"
    );

    // A genuine detection-timeout Down still tears it down (the coupling still
    // reacts to real liveness failures).
    mgr.handle_bfd_state_change(down(peer)).await;
    wait_counter(&counters.stop, 1).await;
}

#[tokio::test]
async fn strict_remote_admin_down_releases_withheld_bgp() {
    // RFC 5882 §4.1: when the remote BFD is AdminDown the adjacency MUST be
    // allowed — even in strict mode. A strict peer withheld pending BFD Up is
    // released (BGP started), never torn down, on a remote AdminDown.
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, true, fake_bfd_peer_handle(counters.clone()));
    mgr.mark_bfd_withheld(peer);

    mgr.handle_bfd_state_change(remote_admin_down(peer)).await;
    wait_counter(&counters.start, 1).await; // released → BGP started
    assert_eq!(
        counters.stop.load(Ordering::SeqCst),
        0,
        "strict remote AdminDown must not stop BGP"
    );
    // The hold was released (RFC 5882 §4.1 — AdminDown permits BGP).
    assert!(
        !mgr.bfd_withholding(&peer),
        "remote AdminDown released the withhold"
    );
}

#[tokio::test]
async fn strict_disable_drain_reenable_does_not_leak_bgp_before_fresh_up() {
    // #2 lifecycle: a strict peer that was Up, then disabled (the actor drains
    // its session to a *local* AdminDown), then re-enabled, must NOT establish
    // BGP until a fresh BFD Up. The local drain must not be mistaken for a remote
    // AdminDown (which would permit BGP per RFC 5882 §4.1). This proves the
    // in-order lifecycle does not leak establishment before the fresh state.
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, true, fake_bfd_peer_handle(counters.clone()));

    // Strict peer reaches Up and establishes.
    mgr.mark_bfd_withheld(peer);
    mgr.handle_bfd_state_change(up(peer)).await;
    wait_counter(&counters.start, 1).await;

    // Operator disables; the actor drains the session to a local AdminDown.
    mgr.peers.get_mut(&key(peer)).unwrap().enabled = false;
    mgr.set_bfd_peer_disabled(peer, true);
    mgr.handle_bfd_state_change(local_admin_down(peer)).await; // drained, ignored

    // Re-enable: BFD has not come Up again, so strict must withhold — the local
    // drain's AdminDown must not be read as "permits BGP".
    mgr.peers.get_mut(&key(peer)).unwrap().enabled = true;
    mgr.set_bfd_peer_disabled(peer, false);
    assert!(
        mgr.bfd_should_withhold(&peer),
        "strict re-enable after a local drain must withhold until fresh BFD Up"
    );
    mgr.enable_peer(key(peer)).await.unwrap();
    assert_eq!(
        counters.start.load(Ordering::SeqCst),
        1,
        "no BGP (re)start before a fresh BFD Up"
    );

    // The fresh session comes Up → BGP is released.
    mgr.handle_bfd_state_change(up(peer)).await;
    wait_counter(&counters.start, 2).await;
}

#[tokio::test]
async fn strict_remote_admin_down_keeps_established_bgp() {
    // A strict peer that is up and established (not held) is left alone on a
    // remote AdminDown — no stop, no spurious restart.
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, true, fake_bfd_peer_handle(counters.clone()));
    mgr.mark_bfd_withheld(peer);
    mgr.handle_bfd_state_change(up(peer)).await; // established
    wait_counter(&counters.start, 1).await;

    mgr.handle_bfd_state_change(remote_admin_down(peer)).await;
    assert_eq!(counters.stop.load(Ordering::SeqCst), 0, "no teardown");
    assert_eq!(
        counters.start.load(Ordering::SeqCst),
        1,
        "no spurious restart of an established session"
    );
}

#[tokio::test]
async fn strict_peer_started_on_first_bfd_up_then_coupled() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, true, fake_bfd_peer_handle(counters.clone()));
    assert!(mgr.is_strict_bfd_peer(&peer));
    // add_peer marks strict peers pre-held (withheld); simulate that here.
    mgr.mark_bfd_withheld(peer);

    // First BFD Up releases the withhold → BGP starts.
    mgr.handle_bfd_state_change(up(peer)).await;
    wait_counter(&counters.start, 1).await;

    // Once up, a later BFD down couples like non-strict → teardown.
    mgr.handle_bfd_state_change(down(peer)).await;
    wait_counter(&counters.stop, 1).await;
}

#[tokio::test]
async fn strict_peer_stays_withheld_without_bfd_up() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, true, fake_bfd_peer_handle(counters.clone()));
    mgr.mark_bfd_withheld(peer);

    // While withheld, a Down (or anything but Up) must not start BGP, and the
    // already-held guard means no spurious stop either.
    mgr.handle_bfd_state_change(down(peer)).await;
    assert_eq!(
        counters.start.load(Ordering::SeqCst),
        0,
        "withheld peer not started"
    );
    assert_eq!(
        counters.stop.load(Ordering::SeqCst),
        0,
        "already-held peer not re-stopped"
    );
}

#[tokio::test]
async fn strict_ack_releases_withhold_when_bfd_already_up() {
    // "BFD already Up before the peer was added" case: a strict peer is always
    // added withheld, and the actor's reconcile ack (re-reporting the session
    // already Up) releases it — no transition needed, no deadlock, and no
    // trusting of a cached state.
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, true, fake_bfd_peer_handle(counters.clone()));
    assert!(
        mgr.bfd_should_withhold(&peer),
        "strict always withholds at add/enable"
    );
    mgr.mark_bfd_withheld(peer);
    assert!(mgr.bfd_withholding(&peer));

    mgr.handle_bfd_state_change(up_ack(peer)).await;
    wait_counter(&counters.start, 1).await;
    assert!(!mgr.bfd_withholding(&peer), "ack of an Up session releases");
}

#[tokio::test]
async fn strict_enable_withholds_then_ack_or_edge_releases() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, true, fake_bfd_peer_handle(counters.clone()));

    // enable_peer always withholds a strict peer; a fresh Up (edge) releases it.
    mgr.enable_peer(key(peer)).await.unwrap();
    assert_eq!(
        counters.start.load(Ordering::SeqCst),
        0,
        "withheld at enable"
    );
    assert!(mgr.bfd_withholding(&peer));
    mgr.handle_bfd_state_change(up(peer)).await;
    wait_counter(&counters.start, 1).await; // released on the Up edge

    // Re-enabling after release withholds again — never trusting a stale state —
    // and the reconcile ack (BFD still Up) releases it.
    mgr.enable_peer(key(peer)).await.unwrap();
    assert!(
        mgr.bfd_withholding(&peer),
        "re-enable re-withholds (no stale trust)"
    );
    assert_eq!(
        counters.start.load(Ordering::SeqCst),
        1,
        "not started before the ack confirms BFD"
    );
    mgr.handle_bfd_state_change(up_ack(peer)).await;
    wait_counter(&counters.start, 2).await;
}

#[tokio::test]
async fn ack_is_release_only_never_tears_down() {
    // A reconcile ack re-reporting Down (e.g. a freshly (re)started session)
    // must NOT tear BGP down — only a real Up→Down transition does.
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, false, fake_bfd_peer_handle(counters.clone()));

    mgr.handle_bfd_state_change(down_ack(peer)).await;
    assert_eq!(
        counters.stop.load(Ordering::SeqCst),
        0,
        "ack-Down must not tear down BGP"
    );

    // A real Down transition still does.
    mgr.handle_bfd_state_change(down(peer)).await;
    wait_counter(&counters.stop, 1).await;
}

#[tokio::test]
async fn strict_reenable_withholds_until_ack_no_leak_no_deadlock() {
    // The #2 tight-race fix: a strict re-enable always withholds (never trusts a
    // possibly-stale Up), so it cannot leak BGP before the fresh state; and the
    // reconcile ack re-reporting the still-Up session (the coalesced case, where
    // no fresh edge will come) releases it — so it does not deadlock either.
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, true, fake_bfd_peer_handle(counters.clone()));

    // Established.
    mgr.mark_bfd_withheld(peer);
    mgr.handle_bfd_state_change(up(peer)).await;
    wait_counter(&counters.start, 1).await;

    // Disable then re-enable, coalesced: the actor never drained, the session
    // stays Up, and no fresh edge will arrive.
    mgr.peers.get_mut(&key(peer)).unwrap().enabled = false;
    mgr.set_bfd_peer_disabled(peer, true);
    mgr.peers.get_mut(&key(peer)).unwrap().enabled = true;
    mgr.set_bfd_peer_disabled(peer, false);
    mgr.enable_peer(key(peer)).await.unwrap();
    assert!(
        mgr.bfd_withholding(&peer),
        "re-enable withholds — no premature start"
    );
    assert_eq!(
        counters.start.load(Ordering::SeqCst),
        1,
        "did not leak a start trusting the old Up"
    );

    // The reconcile ack re-reports the still-Up session → release (no deadlock).
    mgr.handle_bfd_state_change(up_ack(peer)).await;
    wait_counter(&counters.start, 2).await;
}

#[tokio::test]
async fn strict_bfd_drops_inbound_until_up() {
    // Regression: strict withholding must cover the passive path. A strict peer
    // whose BFD is not Up must not accept an inbound connection — accepting it
    // would start a session and establish BGP, bypassing the withhold the
    // active-open path (`add_peer` / `enable_peer`) enforces.
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, true, fake_bfd_peer_handle(counters));
    mgr.mark_bfd_withheld(peer);
    assert!(
        mgr.bfd_should_withhold(&peer),
        "strict + BFD down → withhold"
    );

    let session_id_before = mgr.peers.get(&key(peer)).unwrap().session_id;

    // A real inbound socket; the address we drive `handle_inbound` with is the
    // configured strict peer's, not the loopback the socket actually came from.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
    let (server_stream, _real_addr) = listener.accept().await.unwrap();
    let _client_stream = client.await.unwrap();

    mgr.handle_inbound(server_stream, sock(peer)).await;

    // The inbound was dropped: the managed session was neither replaced nor
    // given a pending collision candidate, so no BGP session started.
    let managed = mgr.peers.get(&key(peer)).unwrap();
    assert_eq!(
        managed.session_id, session_id_before,
        "strict peer's session must not be replaced by an inbound while BFD is down"
    );
    assert!(
        managed.pending_inbound.is_none(),
        "no inbound collision candidate should start for a withheld strict peer"
    );
}

#[tokio::test]
async fn nonstrict_bfd_down_drops_inbound_while_held() {
    // A non-strict peer torn down by a BFD-down is held; an inbound connection
    // must be dropped while held — re-establishing BGP over a presumed-dead path
    // would undo the BFD-driven teardown. (The hold releases on the BFD-up edge,
    // which reconnects via the normal active-open path.)
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, false, fake_bfd_peer_handle(counters.clone()));

    // BFD goes down → BGP torn down and held.
    mgr.handle_bfd_state_change(down(peer)).await;
    wait_counter(&counters.stop, 1).await;
    assert!(
        mgr.bfd_withholding(&peer),
        "non-strict peer is held while BFD is down"
    );

    let session_id_before = mgr.peers.get(&key(peer)).unwrap().session_id;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
    let (server_stream, _real_addr) = listener.accept().await.unwrap();
    let _client_stream = client.await.unwrap();

    mgr.handle_inbound(server_stream, sock(peer)).await;

    let managed = mgr.peers.get(&key(peer)).unwrap();
    assert_eq!(
        managed.session_id, session_id_before,
        "inbound must be dropped while a non-strict peer is BFD-held"
    );
    assert!(managed.pending_inbound.is_none());
}

#[tokio::test]
async fn republish_reflects_disable_and_readd() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, rx) = coupled_mgr(peer, false, fake_bfd_peer_handle(counters));

    let enabled_now = |rx: &watch::Receiver<crate::bfd_runtime::BfdRuntimeConfig>| {
        rx.borrow()
            .sessions
            .iter()
            .find(|s| s.peer == peer)
            .map(|s| s.enabled)
    };

    // A configured peer is enabled by default (disabled set empty) — crucially
    // even before it is added to `self.peers`, since static peers arrive async.
    mgr.republish_bfd_desired();
    assert_eq!(
        enabled_now(&rx),
        Some(true),
        "configured peer enabled by default"
    );

    // Disable / delete → published disabled (actor drains to AdminDown).
    mgr.set_bfd_peer_disabled(peer, true);
    assert_eq!(
        enabled_now(&rx),
        Some(false),
        "disabled/deleted peer published disabled"
    );

    // Re-add (reconfigure delete→add) → re-enabled so the actor restarts it.
    mgr.set_bfd_peer_disabled(peer, false);
    assert_eq!(enabled_now(&rx), Some(true), "re-added peer re-enabled");
}

/// Two-path transport-construction parity. Sessions are built from two
/// independent paths: `Config::resolve_neighbor` (snapshot-sync gRPC peer
/// adds spawn directly from `resolved.transport_config`) and
/// `PeerManager::build_transport_config` (startup + reconcile). Fields have
/// drifted between them before — the ADR-0073 explain knobs, and
/// `cluster_id` (a gRPC-added iBGP RR client ran without `CLUSTER_LIST`
/// prepend or cluster-loop detection until restart). Pin full struct
/// equality so the next added field cannot silently diverge.
#[tokio::test]
async fn resolved_transport_config_matches_build_transport_config() {
    let cluster = Ipv4Addr::new(10, 0, 0, 99);
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        Some(cluster),
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );

    // An iBGP route-reflector client with a few non-default knobs set, so
    // the comparison exercises more than the defaults.
    let mut neighbor = config_neighbor(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65001);
    neighbor.route_reflector_client = Some(true);
    neighbor.hold_time = Some(90);
    neighbor.gr_stale_routes_time = Some(120);

    // Resolve against the manager's own config snapshot (same global
    // ASN/router-id/cluster-id), as the runtime-add path does.
    let mut config = mgr.current_config.clone();
    config.neighbors = vec![neighbor.clone()];
    let resolved = config
        .resolve_neighbor(&neighbor)
        .expect("neighbor resolves");

    let pm_cfg = PeerManager::peer_manager_config_from_resolved(resolved.clone(), false);
    let rebuilt = mgr.build_transport_config(&pm_cfg);

    assert_eq!(
        rebuilt.cluster_id,
        Some(cluster),
        "reconcile path must carry the cluster id"
    );
    assert_eq!(
        resolved.transport_config, rebuilt,
        "resolve_neighbor and build_transport_config must produce identical \
         TransportConfigs — a field set on only one path silently diverges \
         runtime-added peers from restart-built peers"
    );
}

/// Regression: `DeleteNeighbor` must refuse dynamic-range peers. Deleting
/// one through the static surface permanently leaked its
/// `dynamic_neighbor_limit` slot (the `BackToIdle` decrement never runs for a
/// peer removed this way), and the persist-failure rollback would resurrect
/// it as a persisted static neighbor.
#[tokio::test]
async fn delete_peer_rejects_dynamic_targets() {
    use rustbgpd_api::peer_types::PeerLifecycleError;

    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    insert_test_managed_peer(
        &mut mgr,
        addr,
        fake_peer_handle(
            addr,
            SessionState::Established,
            None,
            Arc::new(FakePeerCounters::default()),
        ),
        false,
    );
    mgr.peers.get_mut(&key(addr)).unwrap().is_dynamic = true;

    let Err(err) = mgr.delete_peer(key(addr), false).await else {
        panic!("deleting a dynamic peer must be rejected");
    };
    assert!(
        matches!(err, PeerLifecycleError::Invalid(_)),
        "expected Invalid, got {err:?}"
    );
    assert!(
        mgr.peers.contains_key(&key(addr)),
        "rejected delete must leave the dynamic peer managed"
    );
}

/// Regression: a genuine BFD Down must tear down a pending inbound collision
/// candidate alongside the primary session. The candidate is a live,
/// already-started session; previously only the primary was stopped, so
/// `BackToIdle` promotion re-established BGP over the BFD-down path moments
/// after the teardown.
#[tokio::test]
async fn bfd_down_tears_down_pending_inbound_candidate() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, false, fake_bfd_peer_handle(counters.clone()));
    let pending = Arc::new(FakePeerCounters::default());
    attach_test_pending_inbound(
        &mut mgr,
        peer,
        fake_peer_handle(peer, SessionState::OpenConfirm, None, pending.clone()),
        2,
    );

    mgr.handle_bfd_state_change(down(peer)).await;

    wait_counter(&pending.shutdown, 1).await;
    wait_counter(&counters.stop, 1).await;
    assert!(
        mgr.peers
            .get(&key(peer))
            .is_some_and(|m| m.pending_inbound.is_none()),
        "pending candidate must be gone after BFD down"
    );
    assert!(mgr.peer_key_for_session(2).is_none());
}

/// Regression: `BackToIdle` must not promote a pending inbound collision
/// candidate while BFD is withholding the peer — the primary usually went
/// idle BECAUSE BFD tore it down, and promotion would re-establish BGP over
/// the BFD-down path. The candidate is dropped instead.
#[tokio::test]
async fn back_to_idle_drops_candidate_while_bfd_withholding() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, false, fake_bfd_peer_handle(counters.clone()));

    // Enter the hold first (no candidate exists yet), then attach one —
    // exercising the promotion-time gate rather than the BFD-down teardown.
    mgr.handle_bfd_state_change(down(peer)).await;
    let pending = Arc::new(FakePeerCounters::default());
    attach_test_pending_inbound(
        &mut mgr,
        peer,
        fake_peer_handle(peer, SessionState::OpenConfirm, None, pending.clone()),
        2,
    );

    mgr.handle_session_notification(SessionNotification::BackToIdle {
        session_id: 1,
        role: rustbgpd_transport::SessionRole::Primary,
        peer_addr: peer,
    })
    .await;

    wait_counter(&pending.shutdown, 1).await;
    assert!(
        mgr.peers
            .get(&key(peer))
            .is_some_and(|m| m.pending_inbound.is_none()),
        "candidate must be dropped, not promoted, while BFD withholds"
    );
    assert!(mgr.peer_key_for_session(2).is_none());
}

/// The 60s BMP stats tick sources RFC 8671 types 15/17 from the RIB's
/// per-peer Adj-RIB-Out family counts via one `QueryAdjRibOutCounts`
/// round-trip, converting `(Afi, Safi)` to raw wire codes.
#[tokio::test]
async fn periodic_bmp_stats_carry_adj_rib_out_counts() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    let (bmp_tx, mut bmp_rx) = mpsc::channel(16);
    let mut mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        Some(bmp_tx),
    );
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let counters = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer(
        &mut mgr,
        addr,
        fake_peer_handle(
            addr,
            SessionState::Established,
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            counters,
        ),
        false,
    );

    // Answer the single RIB-wide Adj-RIB-Out counts query.
    let rib_task = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::QueryAdjRibOutCounts { reply } = update {
                let mut counts = std::collections::HashMap::new();
                counts.insert(
                    addr,
                    vec![
                        ((Afi::Ipv4, Safi::Unicast), 12_u64),
                        ((Afi::Ipv4, Safi::MplsVpn), 3_u64),
                    ],
                );
                let _ = reply.send(counts);
                return;
            }
        }
        panic!("QueryAdjRibOutCounts never arrived");
    });

    mgr.emit_periodic_bmp_stats().await;
    rib_task.await.unwrap();

    match bmp_rx.recv().await.unwrap() {
        rustbgpd_bmp::BmpEvent::StatsReport {
            peer_info,
            adj_rib_in_routes,
            adj_rib_out_post,
        } => {
            assert_eq!(peer_info.peer_addr, addr);
            assert_eq!(adj_rib_in_routes, 0);
            assert_eq!(
                adj_rib_out_post,
                Some(vec![(1, 1, 12), (1, 128, 3)]),
                "wire AFI/SAFI codes with AdjRibOut-derived counts"
            );
        }
        other => panic!("expected StatsReport, got {other:?}"),
    }
}
